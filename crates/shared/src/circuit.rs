//! Circuit trait definition for zkFHE circuit implementations
//!
//! This module defines the core traits and configuration structures that all
//! zkFHE circuit implementations must use. It provides a unified interface
//! for parameter generation, TOML file creation, and configuration validation.
//!
//! - **`Circuit`**: The main trait that all circuit implementations must implement
//! - **`CircuitDimensions`**: Trait for objects that can provide dimensional information
//! - **`CircuitVectors`**: Trait for circuit-specific vector operations
//! - **`CircuitBounds`**: Trait for circuit-specific bounds validation
//! - **Configuration structures**: `CircuitConfig`, `CircuitParams`, `CircuitMetadata`
use std::path::Path;

use fhe::bfv::BfvParameters;
use std::sync::Arc;
use crate::errors::ZkfheResult;

/// Circuit trait that all circuit implementations must implement
///
/// This trait defines the contract that every zkFHE circuit implementation
/// must fulfill. It provides methods for parameter generation, TOML file
/// creation, and configuration validation.
pub trait Circuit {
    /// The name of the circuit
    ///
    /// This should be a short, unique identifier for the circuit.
    /// It's used in CLI commands and error messages.
    fn name(&self) -> &'static str;

    /// A description of the circuit
    ///
    /// This should provide a brief description of what the circuit does
    /// and its intended use case.
    fn description(&self) -> &'static str;

    /// Generate parameters for the circuit
    ///
    /// This method should generate all the circuit-specific parameters
    /// needed for the zero-knowledge proof, including bounds, vectors,
    /// and any other circuit-specific data.
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters and metadata
    ///
    /// # Returns
    ///
    /// Returns the generated circuit parameters or an error if generation fails.
    fn generate_params(&self, config: &CircuitConfig) -> ZkfheResult<CircuitParams>;

    /// Generate TOML file for the circuit
    ///
    /// This method should create a TOML file containing all the parameters
    /// needed for the Noir circuit to function correctly.
    ///
    /// * `params` - The generated circuit parameters
    /// * `output_dir` - The directory where the TOML file should be created
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the TOML file was created successfully, or an error otherwise.
    fn generate_toml(&self, params: &CircuitParams, output_dir: &Path) -> ZkfheResult<()>;
}

/// Trait for circuit parameters that can provide dimensions
///
/// Objects implementing this trait can provide dimensional information
/// about the circuit, such as the number of moduli, polynomial degree,
/// and encryption level.
pub trait CircuitDimensions {
    /// Get the number of moduli
    fn num_moduli(&self) -> usize;

    /// Get the polynomial degree
    fn degree(&self) -> usize;

    /// Get the encryption level
    fn level(&self) -> usize;
}

/// Enhanced trait for circuit vectors with derived dimensions
///
/// This trait extends `CircuitDimensions` with methods for working with
/// circuit-specific vector data. It provides functionality for creating
/// vectors from parameters, converting to standard form, and validation.
pub trait CircuitVectors: CircuitDimensions {
    /// Create new vectors with dimensions derived from circuit parameters
    ///
    /// # Arguments
    ///
    /// * `params` - The circuit parameters to derive dimensions from
    /// * `level` - The encryption level
    ///
    /// # Returns
    ///
    /// Returns a new instance of the vectors with the specified dimensions.
    fn new_from_params<P>(params: &P, level: usize) -> Self
    where
        P: CircuitDimensions;

    /// Convert to standard form (reduced modulo ZKP modulus)
    ///
    /// This method should reduce all coefficients modulo the ZKP modulus
    /// to ensure they are within the valid range for Noir circuits.
    ///
    /// # Returns
    ///
    /// Returns a new instance with all coefficients in standard form.
    fn standard_form(&self) -> Self;

    /// Convert to JSON representation
    ///
    /// # Returns
    ///
    /// Returns a JSON representation of the vectors.
    fn to_json(&self) -> serde_json::Value;

    /// Validate vector dimensions using derived parameters
    ///
    /// This method should validate that the vector dimensions are consistent
    /// with the circuit parameters.
    ///
    /// # Returns
    ///
    /// Returns `true` if the dimensions are valid, `false` otherwise.
    fn validate_dimensions(&self) -> bool;
}

/// Enhanced trait for circuit bounds with derived dimensions
///
/// This trait extends `CircuitDimensions` with methods for validating
/// that vectors satisfy the circuit's bounds constraints.
pub trait CircuitBounds: CircuitDimensions {
    /// Convert to JSON representation
    ///
    /// # Returns
    ///
    /// Returns a JSON representation of the bounds.
    fn to_json(&self) -> serde_json::Value;

    /// Validate that vectors satisfy these bounds
    ///
    /// This method should check that the provided vectors satisfy
    /// all the bounds constraints defined by this object.
    ///
    /// # Arguments
    ///
    /// * `vectors` - The vectors to validate against these bounds
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the vectors satisfy the bounds, or an error otherwise.
    fn validate_vectors<V: CircuitVectors>(&self, vectors: &V) -> ZkfheResult<()>;
}

/// Configuration for circuit generation
///
/// This structure contains all the configuration needed to generate
/// circuit parameters, including BFV parameters, custom parameters,
/// and metadata.
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    /// BFV homomorphic encryption parameters
    pub bfv_parameters: Arc<BfvParameters>,
    /// Optional custom parameters that can be overridden
    pub custom_params: Option<CustomParams>,
    /// Metadata about the circuit generation
    pub metadata: CircuitMetadata,
}

/// Custom parameters that can be overridden
///
/// This structure allows for circuit-specific parameter overrides
/// beyond the standard BFV configuration.
#[derive(Clone, Debug)]
pub struct CustomParams {
    /// Optional security level override
    pub security_level: Option<u32>,
    /// Optional environment specification
    pub environment: Option<String>,
    // Add more custom parameters as needed
}

/// Circuit parameters
///
/// This structure contains the generated circuit parameters
/// and metadata about the generation process.
#[derive(Clone, Debug)]
pub struct CircuitParams {
    /// The configuration used to generate these parameters
    pub config: CircuitConfig,
    /// Metadata about the circuit generation
    pub metadata: CircuitMetadata,
}

/// Metadata about the circuit
///
/// This structure contains metadata about the circuit generation,
/// including version information, description, and creation timestamp.
#[derive(Clone, Debug)]
pub struct CircuitMetadata {
    /// Version of the circuit implementation
    pub version: String,
    /// Description of the circuit
    pub description: String,
    /// When the circuit was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}
