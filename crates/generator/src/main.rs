//! zkFHE Generator CLI
//!
//! Command-line tool for generating zkFHE circuit parameters and TOML files.
//!
//! This binary provides a user-friendly interface for generating cryptographic
//! parameters and TOML files for zkFHE circuits. It supports multiple circuits
//! and preset configurations for different security levels.
//!
//! - **Circuit Registry**: Easy registration and management of circuit implementations
//! - **Preset System**: Pre-configured security levels (dev, test, prod)
//! - **Validation**: Comprehensive parameter validation and error handling
//! - **Beautiful Output**: Emoji-rich progress indicators and user feedback
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

use crypto_params::bfv::{BfvSearchConfig, bfv_search};
use crypto_params::pvw::{PvwSearchConfig, pvw_search};
use crypto_params::utils::{approx_bits_from_log2, log2_big};
use fhe::bfv::BfvParametersBuilder;
use shared::{Circuit, SupportedParameterType};

/// Main CLI structure using clap for argument parsing
///
/// This structure defines the command-line interface using clap's derive macros.
/// It provides a clean, type-safe way to handle command-line arguments and
/// subcommands.
#[derive(Parser)]
#[command(name = "zkfhe-generator")]
#[command(about = "Generate zkFHE circuit parameters and TOML files")]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available CLI commands
///
/// This enum defines all the available commands that the CLI supports.
/// Each command has its own set of arguments and options.
#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Generate parameters for a specific circuit
    ///
    /// This command generates cryptographic parameters and TOML files
    /// for the specified circuit. You can either use a preset configuration
    /// or specify custom BFV parameters directly.
    Generate {
        /// Circuit name to generate parameters for
        ///
        /// This should match the name returned by the circuit's `name()` method.
        /// Available circuits can be listed using the `list` command.
        #[arg(long, short)]
        circuit: String,

        /// Preset configuration (dev, test, prod)
        ///
        /// The preset determines the security level and cryptographic parameters
        /// used for generation. If not specified, defaults to "dev".
        /// Custom parameters (--bfv-*) will override preset values.
        #[arg(long, short)]
        preset: Option<String>,

        /// BFV-specific parameters
        ///
        /// Use these flags to specify BFV (Brakerski-Fan-Vercauteren) parameters.
        /// This is the default parameter type for most circuits.
        #[command(flatten)]
        bfv: Option<BfvParams>,

        /// PVW-specific parameters (future)
        ///
        /// Use these flags to specify PVW parameters.
        /// This will be available in future versions.
        #[command(flatten)]
        pvw: Option<PvwParams>,

        /// Verbose output showing detailed parameter search process
        #[arg(long, short)]
        verbose: bool,

        /// Output directory for generated files
        ///
        /// The directory where the generated TOML file will be placed.
        /// If not specified, defaults to the current directory.
        #[arg(long, short, default_value = ".")]
        output: PathBuf,
    },

    /// List available circuits and presets
    ///
    /// This command displays information about available circuits and
    /// preset configurations.
    List {
        /// List available circuits
        #[arg(long)]
        circuits: bool,

        /// List available presets
        #[arg(long)]
        presets: bool,
    },
}

/// BFV-specific parameters
#[derive(Args, Debug, Clone)]
pub struct BfvParams {
    /// Number of parties n (e.g. ciphernodes)
    ///
    /// This parameter affects the security analysis and noise bounds.
    /// If not specified, uses the preset default or 1000.
    #[arg(long)]
    bfv_n: Option<u128>,

    /// Number of fresh ciphertext additions z (number of votes)
    ///
    /// Note that the BFV plaintext modulus k will be defined as k = z.
    /// If not specified, uses the preset default or 1000.
    #[arg(long)]
    z: Option<u128>,

    /// Statistical Security parameter λ (negl(λ)=2^{-λ})
    ///
    /// Higher values provide stronger security guarantees but may require
    /// larger parameters. If not specified, uses the preset default or 80.
    #[arg(long)]
    lambda: Option<u32>,

    /// Bound B on the error distribution ψ
    ///
    /// Used to generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    /// If not specified, uses the preset default or 20.
    #[arg(long)]
    b: Option<u128>,
}

/// Propose PVW parameter sets, **starting with q_PVW = q_BFV**:
/// 1) Compute q_BFV from the provided CRT primes (default or override)
/// 2) First evaluate PVW with q_PVW = q_BFV (no extra primes)
/// 3) If needed, grow q_PVW by multiplying primes from a size-aware pool:
///      - target_bits = min bit-length among BFV CRT primes
///      - try more primes of bit-length == target_bits, then escalate to larger bit-lengths
#[derive(Args, Debug, Clone)]
pub struct PvwParams {
    /// Number of parties n (e.g. ciphernodes) - if not provided, uses BFV n value
    #[arg(long)]
    pvw_n: Option<usize>,

    /// Start ell (power of two, ≥ 2), where ell is the redundency parameter.
    #[arg(long)]
    ell_start: Option<usize>,

    /// Maximum ell (doubling schedule stops here)
    #[arg(long)]
    ell_max: Option<usize>,

    /// k start (doubling schedule), k here is the LWE dimension
    #[arg(long)]
    k_start: Option<usize>,

    /// k max (inclusive). Default = 32768
    #[arg(long)]
    k_max: Option<usize>,

    /// α in Δ = floor(q_PVW^(α/ℓ)). Common choices: 1 or 2
    #[arg(long)]
    delta_power_num: Option<u32>,

    /// Override q_BFV primes (comma-separated). Accepts hex (0x...) or decimal.
    /// Examples:
    ///   --qbfv-primes "0x00800000022a0001,0x00800000021a0001"
    ///   --qbfv-primes "562949951979521,562949951881217,562949951619073"
    #[arg(long)]
    qbfv_primes: Option<String>,

    /// Limit how many extra PVW primes to enumerate (growth steps) beyond the initial q_BFV.
    /// Default: 4 (tweak as needed).
    #[arg(long)]
    max_pvw_growth: Option<usize>,
}

/// Circuit registry - maps circuit names to their implementations
///
/// This function provides a centralized registry of all available circuit
/// implementations. To add a new circuit, simply add a new match arm here.
///
/// # Arguments
///
/// * `circuit_name` - The name of the circuit to load
///
/// # Returns
///
/// Returns a boxed circuit implementation or an error if the circuit is not found.
fn get_circuit(circuit_name: &str) -> anyhow::Result<Box<dyn Circuit>> {
    match circuit_name.to_lowercase().as_str() {
        "greco" => {
            let circuit = greco::circuit::GrecoCircuit;
            Ok(Box::new(circuit))
        }
        _ => anyhow::bail!("Unknown circuit: {}", circuit_name),
    }
}

/// Get BFV configuration based on preset
///
/// This function maps preset names to their corresponding BFV configurations.
/// Each preset provides different security levels and performance characteristics.
///
/// # Arguments
///
/// * `preset` - The preset name (dev, test, prod)
///
/// # Returns
///
/// Parameter configuration that can handle both BFV and PVW
#[derive(Debug, Clone)]
pub struct ParameterConfig {
    pub bfv_config: BfvSearchConfig,
    pub pvw_config: Option<PvwSearchConfig>,
}

impl ParameterConfig {
    /// Create parameter configuration from CLI arguments
    pub fn from_cli_args(
        preset: Option<&str>,
        bfv: Option<BfvParams>,
        pvw: Option<PvwParams>,
        verbose: bool,
    ) -> anyhow::Result<Self> {
        // Always create BFV config first (needed as base for PVW)
        let bfv_config = create_bfv_config(preset, bfv, verbose)?;

        // If PVW params provided, create PVW config that derives from BFV
        let pvw_config = if pvw.is_some() {
            // Step 1: Create initial PVW config from preset + CLI args (like BFV)
            let mut pvw_config = create_pvw_config(preset, pvw, verbose)?;
            // Step 2: Update it with BFV computation results
            pvw_config = update_pvw_config_with_bfv(pvw_config, &bfv_config, verbose)?;
            Some(pvw_config)
        } else {
            None
        };

        Ok(ParameterConfig {
            bfv_config,
            pvw_config,
        })
    }
}

/// Create BFV search configuration from CLI arguments
fn create_bfv_config(
    preset: Option<&str>,
    bfv_params: Option<BfvParams>,
    verbose: bool,
) -> anyhow::Result<BfvSearchConfig> {
    // Start with preset defaults
    let mut config = match preset.unwrap_or("dev") {
        // TODO: there's currently no difference between dev, test and prod.
        "dev" => BfvSearchConfig {
            n: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            verbose,
        },
        "test" => BfvSearchConfig {
            n: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            verbose,
        },
        "prod" => BfvSearchConfig {
            n: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            verbose,
        },
        _ => anyhow::bail!("Unknown preset: {}", preset.unwrap()),
    };

    // Override with custom values if provided
    if let Some(bfv_params) = bfv_params {
        if let Some(n_val) = bfv_params.bfv_n {
            config.n = n_val;
        }
        if let Some(z_val) = bfv_params.z {
            config.z = z_val;
        }
        if let Some(lambda_val) = bfv_params.lambda {
            config.lambda = lambda_val;
        }
        if let Some(b_val) = bfv_params.b {
            config.b = b_val;
        }
    }

    Ok(config)
}

/// Create PVW search configuration from preset and CLI arguments (similar to BFV pattern)
fn create_pvw_config(
    preset: Option<&str>,
    pvw_params: Option<PvwParams>,
    verbose: bool,
) -> anyhow::Result<PvwSearchConfig> {
    // Start with preset defaults (similar to BFV)
    let mut config = match preset.unwrap_or("dev") {
        "dev" => PvwSearchConfig {
            n: 1000, // Default, can be overridden by BFV result or PVW param
            ell_start: 2,
            ell_max: 64,
            k_start: 1024,
            k_max: 32768,
            delta_power_num: 1,
            qbfv_primes: None, // Will be set from BFV computation
            max_pvw_growth: None,
            verbose,
        },
        "test" => PvwSearchConfig {
            n: 1000,
            ell_start: 2,
            ell_max: 64,
            k_start: 1024,
            k_max: 32768,
            delta_power_num: 1,
            qbfv_primes: None,
            max_pvw_growth: None,
            verbose,
        },
        "prod" => PvwSearchConfig {
            n: 1000,
            ell_start: 2,
            ell_max: 64,
            k_start: 1024,
            k_max: 32768,
            delta_power_num: 1,
            qbfv_primes: None,
            max_pvw_growth: None,
            verbose,
        },
        _ => anyhow::bail!("Unknown preset: {}", preset.unwrap()),
    };

    // Override with custom PVW values if provided
    if let Some(pvw_params) = pvw_params {
        if let Some(n_val) = pvw_params.pvw_n {
            config.n = n_val as u128;
        }
        if let Some(ell_start_val) = pvw_params.ell_start {
            config.ell_start = ell_start_val;
        }
        if let Some(ell_max_val) = pvw_params.ell_max {
            config.ell_max = ell_max_val;
        }
        if let Some(k_start_val) = pvw_params.k_start {
            config.k_start = k_start_val;
        }
        if let Some(k_max_val) = pvw_params.k_max {
            config.k_max = k_max_val;
        }
        if let Some(delta_power_num_val) = pvw_params.delta_power_num {
            config.delta_power_num = delta_power_num_val;
        }
        if let Some(qbfv_primes_val) = pvw_params.qbfv_primes {
            config.qbfv_primes = Some(qbfv_primes_val);
        }
        if let Some(max_pvw_growth_val) = pvw_params.max_pvw_growth {
            config.max_pvw_growth = Some(max_pvw_growth_val);
        }
    }

    Ok(config)
}

/// Update PVW config with BFV computation results
fn update_pvw_config_with_bfv(
    mut pvw_config: PvwSearchConfig,
    bfv_config: &BfvSearchConfig,
    verbose: bool,
) -> anyhow::Result<PvwSearchConfig> {
    // Run BFV search to get the modulus that PVW will start from
    println!("⚙️  Computing BFV parameters for PVW derivation...");
    let bfv_result = bfv_search(bfv_config)?;

    if verbose {
        println!("🔐 BFV Result for PVW: q_bfv={}", bfv_result.q_bfv);
    }

    // If no explicit PVW n was provided, use BFV n
    if pvw_config.n == 1000 {
        // This is the default, so likely wasn't explicitly set
        pvw_config.n = bfv_config.n;
    }

    // If no explicit qbfv_primes provided, use computed BFV modulus
    if pvw_config.qbfv_primes.is_none() {
        pvw_config.qbfv_primes = Some(bfv_result.q_bfv.to_string());
    }

    Ok(pvw_config)
}

/// Validate that the provided parameters are compatible with the circuit
fn validate_parameter_compatibility(
    circuit: &dyn Circuit,
    param_config: &ParameterConfig,
) -> anyhow::Result<()> {
    let supported_types = circuit.supported_parameter_types();
    let has_pvw = param_config.pvw_config.is_some();

    match supported_types {
        SupportedParameterType::Bfv => {
            if has_pvw {
                println!(
                    "⚠️  Warning: Circuit '{}' only supports BFV parameters, but PVW parameters were provided.",
                    circuit.name()
                );
                println!("   PVW parameters will be ignored for this circuit.");
                println!("   To suppress this warning, use only --bfv-* flags with this circuit.");
            }
        }
        SupportedParameterType::Pvw => {
            if !has_pvw {
                anyhow::bail!(
                    "Circuit '{}' requires PVW parameters, but none were provided. \
                     Please provide PVW parameters using --pvw-* flags.",
                    circuit.name()
                );
            }
        }
        SupportedParameterType::Both => {
            // Both parameter types are supported, no validation needed
        }
    }

    Ok(())
}

/// Generate parameters for a circuit
///
/// This function orchestrates the entire parameter generation process:
/// 1. Loads the specified circuit implementation
/// 2. Creates the BFV configuration from the preset
/// 3. Generates circuit parameters
/// 4. Creates the TOML file
///
/// # Arguments
///
/// * `circuit_name` - The name of the circuit to generate parameters for
/// * `preset` - The preset configuration to use
/// * `output_dir` - The directory where output files should be placed
///
/// # Returns
///
/// Returns `Ok(())` if generation was successful, or an error otherwise.
fn generate_circuit_params(
    circuit_name: &str,
    preset: Option<&str>,
    bfv: Option<BfvParams>,
    pvw: Option<PvwParams>,
    verbose: bool,
    output_dir: &Path,
) -> anyhow::Result<()> {
    println!("🔧 Generating parameters for circuit: {circuit_name}");

    // Create parameter configuration
    let param_config = ParameterConfig::from_cli_args(preset, bfv, pvw, verbose)?;

    if let Some(preset_name) = preset {
        println!("📋 Using preset: {preset_name}");
    }

    // Get circuit implementation
    let circuit = get_circuit(circuit_name)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    // Validate parameter compatibility
    validate_parameter_compatibility(circuit.as_ref(), &param_config)?;

    // Generate BFV parameters (always needed)
    println!(
        "🔐 BFV Parameters: n={}, z={}, λ={}, B={}",
        param_config.bfv_config.n,
        param_config.bfv_config.z,
        param_config.bfv_config.lambda,
        param_config.bfv_config.b
    );
    println!("⚙️  Searching for optimal BFV parameters...");

    let bfv_result = bfv_search(&param_config.bfv_config)?;

    println!(
        "🔐 BFV Result: qi_values={:?}",
        bfv_result.qi_values().as_slice()
    );

    // Generate PVW parameters if requested
    if let Some(pvw_config) = &param_config.pvw_config {
        println!(
            "🔐 PVW Parameters: n={}, ell_start={}, ell_max={}, k_start={}, k_max={}, delta_power_num={}",
            pvw_config.n,
            pvw_config.ell_start,
            pvw_config.ell_max,
            pvw_config.k_start,
            pvw_config.k_max,
            pvw_config.delta_power_num
        );
        println!("⚙️  PVW parameters computed using BFV result as starting point");

        println!("⚙️  Computing PVW parameters...");
        let pvw_result = pvw_search(pvw_config, &bfv_result.selected_primes)?;

        if verbose {
            println!("\n=== PVW Result (summary) ===");
            println!("ell (redundancy parameter)     = {}", pvw_result.ell);
            println!("k (LWE dimension)              = {}", pvw_result.k);
            println!("sigma_e1 (error bound 1)       = {}", pvw_result.sigma1);
            println!("sigma_e2 (error bound 2)       = {}", pvw_result.sigma2);
            println!(
                "delta_log2                     = {:.6}",
                pvw_result.delta_log2
            );
            println!("q_PVW bits                     = {}", pvw_result.q_pvw_bits);
            println!(
                "PVW primes used                = {}",
                pvw_result.pvw_primes_used
            );
            println!(
                "log2(LHS)                      = {:.6}",
                pvw_result.lhs_log2
            );
            println!(
                "log2(RHS)                      = {:.6}",
                pvw_result.rhs_log2
            );
            println!(
                "PVW primes used ({}): {}",
                pvw_result.used_pvw_list.len(),
                pvw_result
                    .used_pvw_list
                    .iter()
                    .map(|p| format!(
                        "0x{} ({} bits)",
                        p.to_str_radix(16),
                        approx_bits_from_log2(log2_big(p))
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!("✅ PVW parameters computed successfully");
    }

    // Build BFV parameters for circuit use
    let bfv_params = BfvParametersBuilder::new()
        .set_degree(bfv_result.d as usize)
        .set_plaintext_modulus(bfv_result.k_plain_eff as u64)
        .set_moduli(bfv_result.qi_values().as_slice())
        .build_arc()
        .unwrap();

    println!(
        "🔐 BFV Configuration: degree={}, plaintext_modulus={}",
        bfv_params.degree(),
        bfv_params.plaintext()
    );

    // Generate parameters
    println!("⚙️  Generating circuit parameters...");
    circuit
        .generate_params(&bfv_params)
        .map_err(|e| anyhow::anyhow!("Failed to generate parameters: {}", e))?;
    println!("✅ Parameters generated successfully");

    // Generate TOML file
    println!("📄 Generating TOML file...");
    circuit
        .generate_toml(&bfv_params, output_dir)
        .map_err(|e| anyhow::anyhow!("Failed to generate TOML: {}", e))?;
    println!("✅ TOML file generated successfully");

    println!("\n🎉 Generation complete!");
    println!("📁 Output directory: {}", output_dir.display());

    Ok(())
}

/// Main entry point for the CLI application
///
/// This function parses command-line arguments and executes the appropriate
/// command. It provides a clean, user-friendly interface with progress
/// indicators and helpful error messages.
///
/// # Returns
///
/// Returns `Ok(())` if the command executed successfully, or an error otherwise.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("🚀 zkFHE Generator");
    println!("Generating cryptographic parameters...\n");

    match cli.command {
        Commands::Generate {
            circuit,
            preset,
            bfv,
            pvw,
            verbose,
            output,
        } => {
            // Ensure output directory exists
            std::fs::create_dir_all(&output)?;

            generate_circuit_params(&circuit, preset.as_deref(), bfv, pvw, verbose, &output)?;
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("📋 Available circuits:");
                println!("  • greco - Greco circuit implementation (BFV only)");
            }
            if presets {
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
            }
            if !circuits && !presets {
                println!("📋 Available circuits:");
                println!("  • greco - Greco circuit implementation (BFV only)");
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 128");
                println!("\n⚠️  Note: greco circuit only supports BFV parameters");
            }
        }
    }

    Ok(())
}
