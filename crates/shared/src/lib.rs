//! Shared utilities and traits for zkFHE circuit generation
//!
//! This crate provides common functionality used across all circuit implementations.

// Core modules
pub mod bfv;
pub mod circuit;
pub mod constants;
pub mod toml;
pub mod utils;

// Re-export commonly used items for convenience
pub use bfv::{BfvConfig, BfvHelper, EncryptionData};
pub use circuit::{Circuit, CircuitConfig, CircuitMetadata, CircuitParams, CustomParams};
pub use constants::{ZKP_MODULUS, get_zkp_modulus};
pub use toml::TomlGenerator;

/// Validation utilities for common parameters
pub mod validation {
    use std::error::Error;

    /// Validate that a degree is a valid power of 2
    pub fn validate_degree(degree: usize) -> Result<(), Box<dyn Error>> {
        if !degree.is_power_of_two() {
            return Err("Degree must be a power of 2".into());
        }
        Ok(())
    }

    /// Validate that a degree is within reasonable bounds
    pub fn validate_degree_bounds(degree: usize) -> Result<(), Box<dyn Error>> {
        validate_degree(degree)?;

        if degree < 1024 || degree > 8192 {
            return Err("Degree must be between 1024 and 8192".into());
        }
        Ok(())
    }

    /// Validate plaintext modulus
    pub fn validate_plaintext_modulus(modulus: u64) -> Result<(), Box<dyn Error>> {
        if modulus == 0 {
            return Err("Plaintext modulus cannot be zero".into());
        }
        Ok(())
    }

    /// Validate ciphertext moduli
    pub fn validate_ciphertext_moduli(moduli: &[u64]) -> Result<(), Box<dyn Error>> {
        if moduli.is_empty() {
            return Err("At least one ciphertext modulus must be provided".into());
        }

        for (i, modulus) in moduli.iter().enumerate() {
            if *modulus == 0 {
                return Err(format!("Ciphertext modulus at index {} cannot be zero", i).into());
            }
        }
        Ok(())
    }
}
