//! zkFHE Generator CLI
//!
//! Command-line tool for generating zkFHE circuit parameters and TOML files.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use shared::bfv::BfvConfig;
use shared::circuit::{Circuit, CircuitConfig, CircuitMetadata};

#[derive(Parser)]
#[command(name = "zkfhe-generator")]
#[command(about = "Generate zkFHE circuit parameters and TOML files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate parameters for a specific circuit
    Generate {
        /// Circuit name to generate parameters for
        #[arg(long, short)]
        circuit: String,

        /// Preset configuration (dev, test, prod)
        #[arg(long, short)]
        preset: Option<String>,

        /// Output directory for generated files
        #[arg(long, short, default_value = ".")]
        output: PathBuf,
    },

    /// List available circuits
    List {
        /// List circuits
        #[arg(long)]
        circuits: bool,

        /// List presets
        #[arg(long)]
        presets: bool,
    },
}

/// Circuit registry - maps circuit names to their implementations
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
fn get_bfv_config(preset: &str) -> anyhow::Result<BfvConfig> {
    let config = match preset.to_lowercase().as_str() {
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
                println!("  • example - Example circuit (placeholder)");
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (degree=1024)");
                println!("  • test  - Testing (degree=2048)");
                println!("  • prod  - Production (128-bit security, degree=?)");
            }
        }
    }

    Ok(())
}
