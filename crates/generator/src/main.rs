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

use bfv_params::search::{BfvSearchConfig, bfv_search};
use fhe::bfv::BfvParametersBuilder;
use shared::circuit::Circuit;

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
    n: Option<u128>,

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

/// PVW-specific parameters (future)
#[derive(Args, Debug, Clone)]
pub struct PvwParams {
    /// PVW-specific parameter 1 (placeholder)
    #[arg(long)]
    param1: Option<u128>,

    /// PVW-specific parameter 2 (placeholder)
    #[arg(long)]
    param2: Option<u32>,
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
/// Parameter type enumeration for different FHE schemes
#[derive(Debug, Clone)]
pub enum ParameterType {
    Bfv(BfvSearchConfig),
    Pvw, // TODO: PVW implementation
}

impl ParameterType {
    /// Resolve parameter type and configuration from CLI arguments
    pub     fn from_cli_args(
        preset: Option<&str>,
        bfv: Option<BfvParams>,
        pvw: Option<PvwParams>,
        verbose: bool,
    ) -> anyhow::Result<Self> {
        // Determine which parameter type to use
        match (bfv, pvw) {
            (Some(bfv_params), None) => {
                let config = create_bfv_config(preset, bfv_params, verbose)?;
                Ok(ParameterType::Bfv(config))
            }
            (None, Some(_pvw_params)) => {
                // TODO: PVW implementation
                anyhow::bail!("PVW parameters not yet implemented")
            }
            (None, None) => {
                // Default to BFV with preset
                let config = create_bfv_config(preset, BfvParams {
                    n: None,
                    z: None,
                    lambda: None,
                    b: None,
                }, verbose)?;
                Ok(ParameterType::Bfv(config))
            }
            _ => {
                anyhow::bail!("Only one parameter type can be specified at a time")
            }
        }
    }
}

/// Create BFV search configuration from CLI arguments
fn create_bfv_config(
    preset: Option<&str>,
    bfv_params: BfvParams,
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
    if let Some(n_val) = bfv_params.n {
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

    Ok(config)
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

    // Resolve parameter type and configuration
    let param_type = ParameterType::from_cli_args(preset, bfv, pvw, verbose)?;

    if let Some(preset_name) = preset {
        println!("📋 Using preset: {preset_name}");
    }

    // Get circuit implementation
    let circuit = get_circuit(circuit_name)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    // Generate parameters based on type
    let bfv_config = match param_type {
        ParameterType::Bfv(config) => {
            println!(
                "🔐 BFV Parameters: n={}, z={}, λ={}, B={}",
                config.n, config.z, config.lambda, config.b
            );
            println!("⚙️  Searching for optimal BFV parameters...");

            let result = bfv_search(&config)?;

            println!("🔐 BFV Parameters: qi_values={:?}", result.qi_values().as_slice());
            BfvParametersBuilder::new()
                .set_degree(result.d as usize)
                .set_plaintext_modulus(result.k_plain_eff as u64)
                .set_moduli(result.qi_values().as_slice())
                .build_arc()
                .unwrap()
        }
        ParameterType::Pvw => {
            anyhow::bail!("PVW parameters not yet implemented")
        }
    };

    println!(
        "🔐 BFV Configuration: degree={}, plaintext_modulus={}",
        bfv_config.degree(),
        bfv_config.plaintext()
    );

    // Generate parameters
    println!("⚙️  Generating circuit parameters...");
    circuit
        .generate_params(&bfv_config)
        .map_err(|e| anyhow::anyhow!("Failed to generate parameters: {}", e))?;
    println!("✅ Parameters generated successfully");

    // Generate TOML file
    println!("📄 Generating TOML file...");
    circuit
        .generate_toml(&bfv_config, output_dir)
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
                println!("  • greco - Greco circuit implementation");
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
                println!("  • greco - Greco circuit implementation");
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 128");
            }
        }
    }

    Ok(())
}
