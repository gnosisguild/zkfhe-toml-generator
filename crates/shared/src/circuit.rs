//! Circuit trait definition for zkFHE circuit implementations

use std::path::Path;

use crate::bfv::BfvConfig;

/// Circuit trait that all circuit implementations must implement
pub trait Circuit {
    /// The name of the circuit
    fn name(&self) -> &'static str;

    /// A description of the circuit
    fn description(&self) -> &'static str;

    /// Generate parameters for the circuit
    fn generate_params(
        &self,
        config: &CircuitConfig,
    ) -> Result<CircuitParams, Box<dyn std::error::Error>>;

    /// Generate TOML file for the circuit
    fn generate_toml(
        &self,
        params: &CircuitParams,
        output_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Validate circuit configuration
    fn validate_config(&self, config: &CircuitConfig) -> Result<(), Box<dyn std::error::Error>>;
}

/// Trait for circuit parameters that can provide dimensions
pub trait CircuitDimensions {
    /// Get the number of moduli
    fn num_moduli(&self) -> usize;

    /// Get the polynomial degree
    fn degree(&self) -> usize;

    /// Get the encryption level
    fn level(&self) -> usize;
}

/// Enhanced trait for circuit vectors with derived dimensions
pub trait CircuitVectors: CircuitDimensions {
    /// Create new vectors with dimensions derived from circuit parameters
    fn new_from_params<P>(params: &P, level: usize) -> Self
    where
        P: CircuitDimensions;

    /// Convert to standard form (reduced modulo ZKP modulus)
    fn standard_form(&self, zkp_modulus: &num_bigint::BigInt) -> Self;

    /// Convert to JSON representation
    fn to_json(&self) -> serde_json::Value;

    /// Validate vector dimensions using derived parameters
    fn validate_dimensions(&self) -> bool {
        self.check_correct_lengths(self.num_moduli(), self.degree())
    }

    /// Check correct lengths (internal method)
    fn check_correct_lengths(&self, num_moduli: usize, degree: usize) -> bool;
}

/// Enhanced trait for circuit bounds with derived dimensions
pub trait CircuitBounds: CircuitDimensions {
    /// Convert to JSON representation
    fn to_json(&self) -> serde_json::Value;

    /// Validate that vectors satisfy these bounds
    fn validate_vectors<V: CircuitVectors>(
        &self,
        vectors: &V,
        zkp_modulus: &num_bigint::BigInt,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Configuration for circuit generation
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    pub bfv_config: BfvConfig,
    pub custom_params: Option<CustomParams>,
    pub metadata: CircuitMetadata,
}

/// Custom parameters that can be overridden
#[derive(Clone, Debug)]
pub struct CustomParams {
    pub security_level: Option<u32>,
    pub environment: Option<String>,
    // Add more custom parameters as needed
}

/// Circuit parameters
#[derive(Clone, Debug)]
pub struct CircuitParams {
    pub metadata: CircuitMetadata,
}

/// Metadata about the circuit
#[derive(Clone, Debug)]
pub struct CircuitMetadata {
    pub version: String,
    pub description: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
