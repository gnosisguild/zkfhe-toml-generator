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
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use shared::bfv::BfvConfig;
use shared::circuit::{Circuit, CircuitConfig, CircuitMetadata};

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
enum Commands {
    /// Generate parameters for a specific circuit
    ///
    /// This command generates cryptographic parameters and TOML files
    /// for the specified circuit using the given preset configuration.
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
        #[arg(long, short)]
        preset: Option<String>,

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
            let circuit = greco::GrecoCircuit;
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
/// Returns the BFV configuration for the specified preset or an error if the preset is unknown.
fn get_bfv_config(preset: &str) -> anyhow::Result<BfvConfig> {
    let config = match preset.to_lowercase().as_str() {
        // TODO: need to clearly define the parameters for prod.
        "dev" => BfvConfig {
            degree: 1024,
            plaintext_modulus: 1032193,
            moduli: vec![0x3FFFFFFF000001],
        },
        "test" => BfvConfig {
            degree: 2048,
            plaintext_modulus: 1032193,
            moduli: vec![0x3FFFFFFF000001],
        },
        "prod" => BfvConfig {
            degree: 2048,
            plaintext_modulus: 1032193,
            moduli: vec![0x3FFFFFFF000001],
        },
        _ => anyhow::bail!("Unknown preset: {}", preset),
    };

    // Validate the configuration
    shared::validation::validate_degree_bounds(config.degree)
        .map_err(|e| anyhow::anyhow!("Invalid degree: {}", e))?;
    shared::validation::validate_plaintext_modulus(config.plaintext_modulus)
        .map_err(|e| anyhow::anyhow!("Invalid plaintext modulus: {}", e))?;
    shared::validation::validate_ciphertext_moduli(&config.moduli)
        .map_err(|e| anyhow::anyhow!("Invalid ciphertext moduli: {}", e))?;

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
    preset: &str,
    output_dir: &PathBuf,
) -> anyhow::Result<()> {
    println!("🔧 Generating parameters for circuit: {}", circuit_name);
    println!("📋 Using preset: {}", preset);

    // Get circuit implementation
    let circuit = get_circuit(circuit_name)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    // Get BFV configuration for preset
    let bfv_config = get_bfv_config(preset)?;
    println!(
        "🔐 BFV Configuration: degree={}, plaintext_modulus={}",
        bfv_config.degree, bfv_config.plaintext_modulus
    );

    // Create circuit configuration
    let circuit_config = CircuitConfig {
        bfv_config,
        custom_params: None,
        metadata: CircuitMetadata {
            version: "1.0.0".to_string(),
            description: format!(
                "Generated for {} circuit with {} preset",
                circuit_name, preset
            ),
            created_at: chrono::Utc::now(),
        },
    };

    // Generate parameters
    println!("⚙️  Generating circuit parameters...");
    let params = circuit
        .generate_params(&circuit_config)
        .map_err(|e| anyhow::anyhow!("Failed to generate parameters: {}", e))?;
    println!("✅ Parameters generated successfully");

    // Generate TOML file
    println!("📄 Generating TOML file...");
    circuit
        .generate_toml(&params, output_dir)
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
            output,
        } => {
            let preset = preset.unwrap_or_else(|| "dev".to_string());

            // Ensure output directory exists
            std::fs::create_dir_all(&output)?;

            generate_circuit_params(&circuit, &preset, &output)?;
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("📋 Available circuits:");
                println!("  • greco - Greco circuit implementation");
            }
            if presets {
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (degree=1024)");
                println!("  • test  - Testing (degree=2048)");
                println!("  • prod  - Production (128-bit security, degree=?)");
            }
            if !circuits && !presets {
                println!("📋 Available circuits:");
                println!("  • greco - Greco circuit implementation");
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (degree=1024)");
                println!("  • test  - Testing (degree=2048)");
                println!("  • prod  - Production (128-bit security, degree=?)");
            }
        }
    }

    Ok(())
}
