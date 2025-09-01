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
pub mod toml;
pub mod vectors;

use shared::Circuit;
use shared::bfv::BfvHelper;
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
    /// Get BFV helper with computed parameters
    ///
    /// This method creates a BFV helper from the provided configuration,
    /// which can be used for encryption operations and parameter access.
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration containing BFV parameters
    ///
    /// # Returns
    ///
    /// Returns the BFV helper or an error if creation fails.
    pub fn get_bfv_helper(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<shared::bfv::BfvHelper, shared::errors::ZkfheError> {
        shared::bfv::BfvHelper::new(config.bfv_config.clone()).map_err(|e| {
            shared::errors::ZkfheError::Bfv {
                message: e.to_string(),
            }
        })
    }

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
    ) -> Result<shared::bfv::EncryptionData, shared::errors::ZkfheError> {
        let bfv_helper = self.get_bfv_helper(config)?;
        bfv_helper
            .generate_sample_encryption()
            .map_err(|e| shared::errors::ZkfheError::Bfv {
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
    ) -> Result<bounds::GrecoBounds, shared::errors::ZkfheError> {
        let bfv_helper = self.get_bfv_helper(config)?;
        bounds::GrecoBounds::compute(&bfv_helper.params, 0)
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
    ) -> Result<vectors::GrecoVectors, shared::errors::ZkfheError> {
        let encryption_data = self.get_sample_encryption_data(config)?;
        let bfv_helper = self.get_bfv_helper(config)?;

        vectors::GrecoVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            &bfv_helper.params,
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
    ) -> Result<vectors::GrecoVectors, shared::errors::ZkfheError> {
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
    ) -> Result<shared::circuit::CircuitParams, shared::errors::ZkfheError> {
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
    ) -> Result<(), shared::errors::ZkfheError> {
        // Use the config from the params to get the data
        let bounds = self.get_bounds(&params.config)?;
        let vectors_standard = self.get_vectors_standard_form(&params.config)?;

        // Create TOML generator and generate file
        let toml_generator = toml::GrecoTomlGenerator::new(bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }

    /// Validate Greco circuit configuration
    ///
    /// This method validates that the provided configuration is suitable
    /// for the Greco circuit implementation. It checks:
    ///
    /// - Degree bounds (must be between 1024-8192)
    /// - Plaintext modulus (must be non-zero)
    /// - Ciphertext moduli (must be non-empty and non-zero)
    /// - BFV helper creation (ensures parameters are valid)
    ///
    /// # Arguments
    ///
    /// * `config` - The circuit configuration to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the configuration is valid, or an error otherwise.
    fn validate_config(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<(), shared::errors::ZkfheError> {
        // Validate BFV configuration using shared validation utilities
        shared::validation::validate_degree_bounds(config.bfv_config.degree)?;
        shared::validation::validate_plaintext_modulus(config.bfv_config.plaintext_modulus)?;
        shared::validation::validate_ciphertext_moduli(&config.bfv_config.moduli)?;

        // Test that we can actually create a BFV helper with this config
        let _bfv_helper = BfvHelper::new(config.bfv_config.clone())?;

        Ok(())
    }
}
