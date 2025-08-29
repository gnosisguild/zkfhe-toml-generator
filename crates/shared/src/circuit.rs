//! Circuit trait definition for zkFHE circuit implementations

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Trait that all zkFHE circuits must implement
pub trait Circuit {
    /// Returns the name of the circuit
    fn name(&self) -> &str;

    /// Returns a description of the circuit
    fn description(&self) -> &str;

    /// Generate parameters for the circuit
    fn generate_params(&self, config: &CircuitConfig) -> Result<CircuitParams>;

    /// Generate TOML file for the circuit
    fn generate_toml(&self, params: &CircuitParams, output_dir: &Path) -> Result<PathBuf>;

    /// Validate configuration for the circuit
    fn validate_config(&self, config: &CircuitConfig) -> Result<()>;
}

/// Configuration for circuit generation
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    pub circuit_type: String,
    pub preset: Option<String>,
    pub output_dir: PathBuf,
    pub custom_params: Option<CustomParams>,
}

/// Custom parameters for circuit generation
#[derive(Debug, Clone)]
pub struct CustomParams {
    pub degree: usize,
    pub plaintext_modulus: u64,
    pub moduli: Vec<u64>,
}

/// Generated circuit parameters
#[derive(Debug)]
pub struct CircuitParams {
    pub bounds: Vec<String>,
    pub vectors: Vec<String>,
    pub metadata: CircuitMetadata,
}

/// Metadata about the generated circuit
#[derive(Debug)]
pub struct CircuitMetadata {
    pub circuit_name: String,
    pub security_level: String,
    pub generation_timestamp: String,
}
