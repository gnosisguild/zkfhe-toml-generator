//! Shared utilities and traits for zkFHE circuit generation
//!
//! This crate provides common functionality used across all circuit implementations.
//! It defines the core traits, configuration structures, and validation utilities
//! that enable a modular approach to zkFHE circuit parameter generation.
//!
//! - **`bfv`**: BFV (Brakerski-Fan-Vercauteren) homomorphic encryption configuration and helpers
//! - **`circuit`**: Core traits and configuration structures for circuit implementations
//! - **`constants`**: Cryptographic constants used across all circuits
//! - **`toml`**: TOML file generation traits and utilities
//! - **`utils`**: General utility functions for string conversion and serialization
//! - **`validation`**: Parameter validation utilities for ensuring correct configurations

// Core modules
pub mod bfv;
pub mod circuit;
pub mod constants;
pub mod errors;
pub mod toml;
pub mod utils;

// Re-export commonly used items for convenience
pub use bfv::{BfvConfig, BfvHelper, EncryptionData};
pub use circuit::{Circuit, CircuitConfig, CircuitMetadata, CircuitParams, CustomParams};
pub use constants::{ZKP_MODULUS, get_zkp_modulus};
pub use errors::{BfvError, CircuitError, TomlError, ValidationError, ZkfheError, ZkfheResult};
pub use toml::TomlGenerator;

/// Validation utilities for common parameters
///
/// This module provides functions to validate cryptographic parameters
/// and ensure they meet security requirements.
pub mod validation {
    use crate::errors::{ValidationError, ZkfheResult};

    /// Validate that a degree is a valid power of 2
    ///
    /// # Arguments
    ///
    /// * `degree` - The polynomial degree to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the degree is a valid power of 2, or an error otherwise.
    pub fn validate_degree(degree: usize) -> ZkfheResult<()> {
        if !degree.is_power_of_two() {
            return Err(ValidationError::Degree {
                degree,
                reason: "must be a power of 2".to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Validate that a degree is within reasonable bounds
    ///
    /// This function ensures that the degree is both a valid power of 2
    /// and within the acceptable range for cryptographic security.
    ///
    /// # Arguments
    ///
    /// * `degree` - The polynomial degree to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the degree is valid, or an error otherwise.
    pub fn validate_degree_bounds(degree: usize) -> ZkfheResult<()> {
        validate_degree(degree)?;

        if degree % 2 != 0 {
            return Err(ValidationError::Degree {
                degree,
                reason: "must be even".to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Validate plaintext modulus
    ///
    /// Ensures that the plaintext modulus is non-zero and valid.
    ///
    /// # Arguments
    ///
    /// * `modulus` - The plaintext modulus to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the modulus is valid, or an error otherwise.
    pub fn validate_plaintext_modulus(modulus: u64) -> ZkfheResult<()> {
        if modulus == 0 {
            return Err(ValidationError::PlaintextModulus {
                modulus,
                reason: "cannot be zero".to_string(),
            }
            .into());
        }
        Ok(())
    }

    /// Validate ciphertext moduli
    ///
    /// Ensures that the ciphertext moduli array is non-empty and all values are valid.
    ///
    /// # Arguments
    ///
    /// * `moduli` - The ciphertext moduli to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all moduli are valid, or an error otherwise.
    pub fn validate_ciphertext_moduli(moduli: &[u64]) -> ZkfheResult<()> {
        if moduli.is_empty() {
            return Err(ValidationError::CiphertextModuli {
                reason: "at least one ciphertext modulus must be provided".to_string(),
            }
            .into());
        }

        for (i, modulus) in moduli.iter().enumerate() {
            if *modulus == 0 {
                return Err(ValidationError::CiphertextModuli {
                    reason: format!("ciphertext modulus at index {i} cannot be zero"),
                }
                .into());
            }
        }
        Ok(())
    }
}
