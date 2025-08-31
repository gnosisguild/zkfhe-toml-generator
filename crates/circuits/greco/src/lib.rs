//! Greco circuit parameter generation in Rust
//!
//! This crate provides the Greco circuit parameter generation in Rust.

pub mod bounds;
pub mod toml;
pub mod vectors;

use shared::Circuit;
use shared::bfv::BfvHelper;
use shared::circuit::CircuitVectors;
use shared::toml::TomlGenerator;
use std::path::Path;

pub struct GrecoCircuit;

impl Circuit for GrecoCircuit {
    fn name(&self) -> &'static str {
        "greco"
    }

    fn description(&self) -> &'static str {
        "Greco zero-knowledge proof circuit for BFV homomorphic encryption"
    }

    fn generate_params(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<shared::circuit::CircuitParams, Box<dyn std::error::Error>> {
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

    fn generate_toml(
        &self,
        _params: &shared::circuit::CircuitParams,
        output_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    fn validate_config(
        &self,
        config: &shared::circuit::CircuitConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Validate BFV configuration using shared validation utilities
        shared::validation::validate_degree_bounds(config.bfv_config.degree)?;
        shared::validation::validate_plaintext_modulus(config.bfv_config.plaintext_modulus)?;
        shared::validation::validate_ciphertext_moduli(&config.bfv_config.moduli)?;

        // Test that we can actually create a BFV helper with this config
        let _bfv_helper = BfvHelper::new(config.bfv_config.clone())?;

        Ok(())
    }
}
