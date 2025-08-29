//! zkFHE Generator CLI
//!
//! Command-line tool for generating zkFHE circuit parameters and TOML files.

use clap::{Parser, Subcommand};

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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("zkFHE Generator");
    println!("Generating cryptographic parameters...\n");

    match cli.command {
        Commands::Generate { circuit, preset } => {
            println!("Generating parameters for circuit: {circuit}");
            if let Some(p) = preset {
                println!("Using preset: {p}");
            }
            // TODO: Implement generation logic
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("Available circuits:");
                println!("  - greco");
            }
            if presets {
                println!("Available presets:");
                println!("  - dev (expected 32-bit security)");
                println!("  - test (expected 64-bit security)");
                println!("  - prod (expected 128-bit security)");
            }
        }
    }

    Ok(())
}
