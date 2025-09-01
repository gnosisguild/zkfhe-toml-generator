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
        // Create BFV helper from configuration
        let bfv_helper = BfvHelper::new(config.bfv_config.clone())?;

        // Generate sample encryption data
        let encryption_data = bfv_helper.generate_sample_encryption()?;

        // Create bounds from BFV parameters
        let bounds = bounds::GrecoBounds::compute(&bfv_helper.params, 0)?;

        // Create vectors from the encryption data
        let vectors = vectors::GrecoVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            &bfv_helper.params,
        )?;

        // Convert vectors to standard form (reduced modulo ZKP modulus)
        let vectors_standard_form = vectors.standard_form();

        // Create TOML generator
        let toml_generator = toml::GrecoTomlGenerator::new(bounds, vectors_standard_form);

        // Generate TOML file (we'll handle output directory in the generate_toml method)
        // For now, just create the TOML string to validate it works
        let _toml_string = toml_generator.to_toml_string()?;

        Ok(shared::circuit::CircuitParams {
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
        _params: &shared::circuit::CircuitParams,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkfheError> {
        // Create BFV helper and generate data
        let bfv_helper = BfvHelper::new(shared::bfv::BfvConfig::default())?;
        let encryption_data = bfv_helper.generate_sample_encryption()?;

        // Create bounds and vectors
        let bounds = bounds::GrecoBounds::compute(&bfv_helper.params, 0)?;
        let vectors = vectors::GrecoVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            &bfv_helper.params,
        )?;

        // Convert vectors to standard form (reduced modulo ZKP modulus)
        let vectors_standard_form = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = toml::GrecoTomlGenerator::new(bounds, vectors_standard_form);
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
