//! Greco circuit parameter generation in Rust
//!
//! This crate provides the Greco circuit parameter generation in Rust.
//! The Greco circuit is a zero-knowledge proof circuit for BFV homomorphic
//! encryption that enables proving correct encryption without revealing
//! the secret key or plaintext.
//!
//! - **Bounds Calculation**: Computes valid ranges for polynomial coefficients
//! - **Vector Generation**: Creates input validation vectors for zero-knowledge proofs
//! - **TOML Generation**: Produces Noir-compatible TOML files
//! - **Configuration Validation**: Ensures cryptographic parameters are secure
pub mod bounds;
pub mod sample;
pub mod toml;
pub mod vectors;

use crate::sample::generate_sample_encryption;
use shared::Circuit;
use shared::circuit::CircuitVectors;
use shared::toml::TomlGenerator;
use std::path::Path;

/// Greco circuit implementation
///
/// This struct implements the `Circuit` trait for the Greco zero-knowledge
/// proof circuit. It provides methods for parameter generation, TOML file
/// creation, and configuration validation.
///
/// The Greco circuit is designed to prove the correctness of BFV homomorphic
/// encryption without revealing the secret key or plaintext. It achieves this
/// by generating bounds and validation vectors that can be used in zero-knowledge
/// proofs.
pub struct GrecoCircuit;

impl GrecoCircuit {
    /// Get sample encryption data for vector computation
    ///
    /// This method generates sample encryption data that is used to compute
    /// the input validation vectors for zero-knowledge proofs.
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters
    ///
    /// # Returns
    ///
    /// Returns the sample encryption data or an error if generation fails.
    pub fn get_sample_encryption_data(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<sample::EncryptionData, shared::errors::ZkFheError> {
        generate_sample_encryption(&config.bfv_parameters)
            .map_err(|e| shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            })
            .map_err(|e| shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            })
    }

    /// Get computed bounds directly
    ///
    /// This method computes the bounds for polynomial coefficients that
    /// are used in zero-knowledge proof validation.
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters
    ///
    /// # Returns
    ///
    /// Returns the computed bounds or an error if computation fails.
    pub fn get_bounds(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<bounds::GrecoBounds, shared::errors::ZkFheError> {
        bounds::GrecoBounds::compute(&config.bfv_parameters, 0)
    }

    /// Get computed vectors directly
    ///
    /// This method computes the input validation vectors that are used
    /// in zero-knowledge proofs to validate encryption correctness.
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters
    ///
    /// # Returns
    ///
    /// Returns the computed vectors or an error if computation fails.
    pub fn get_vectors(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<vectors::GrecoVectors, shared::errors::ZkFheError> {
        let encryption_data = self.get_sample_encryption_data(config)?;

        vectors::GrecoVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            &config.bfv_parameters,
        )
    }

    /// Get vectors in standard form (reduced modulo ZKP modulus)
    ///
    /// This method returns the vectors reduced modulo the ZKP modulus,
    /// which is the format required for zero-knowledge proof circuits.
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters
    ///
    /// # Returns
    ///
    /// Returns the vectors in standard form or an error if computation fails.
    pub fn get_vectors_standard_form(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<vectors::GrecoVectors, shared::errors::ZkFheError> {
        let vectors = self.get_vectors(config)?;
        Ok(vectors.standard_form())
    }
}

impl Circuit for GrecoCircuit {
    /// Returns the name of the Greco circuit
    ///
    /// This name is used in CLI commands and error messages to identify
    /// the circuit implementation.
    fn name(&self) -> &'static str {
        "greco"
    }

    /// Returns a description of the Greco circuit
    ///
    /// This description provides information about what the circuit does
    /// and its intended use case.
    fn description(&self) -> &'static str {
        "Greco zero-knowledge proof circuit for BFV homomorphic encryption"
    }

    /// Generate parameters for the Greco circuit
    ///
    /// This method orchestrates the entire parameter generation process:
    /// 1. Creates a BFV helper from the provided configuration
    /// 2. Generates sample encryption data
    /// 3. Computes bounds from BFV parameters
    /// 4. Computes vectors from encryption data
    /// 5. Converts vectors to standard form (reduced modulo ZKP modulus)
    /// 6. Creates TOML generator and validates TOML generation
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters and metadata
    ///
    /// # Returns
    ///
    /// Returns the generated circuit parameters or an error if generation fails.
    fn generate_params(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<shared::circuit::CircuitParams, shared::errors::ZkFheError> {
        // Validate that we can compute everything using our public methods
        let _bounds = self.get_bounds(config)?;
        let _vectors = self.get_vectors(config)?;
        let _vectors_standard = self.get_vectors_standard_form(config)?;

        Ok(shared::circuit::CircuitParams {
            config: config.clone(),
            metadata: config.metadata.clone(),
        })
    }

    /// Generate TOML file for the Greco circuit
    ///
    /// This method creates a TOML file containing all the parameters needed
    /// for the Noir Greco circuit to function correctly. The TOML file includes:
    ///
    /// - Cryptographic parameters (moduli, bounds)
    /// - Input validation vectors
    /// - Metadata about the generation process
    ///
    /// # Arguments
    ///
    /// * `_params` - The generated circuit parameters (unused in this implementation)
    /// * `output_dir` - The directory where the TOML file should be created
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the TOML file was created successfully, or an error otherwise.
    fn generate_toml(
        &self,
        params: &shared::circuit::CircuitParams,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Use the config from the params to get the data
        let bounds = self.get_bounds(&params.config)?;
        let vectors_standard = self.get_vectors_standard_form(&params.config)?;

        // Create TOML generator and generate file
        let toml_generator = toml::GrecoTomlGenerator::new(bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
