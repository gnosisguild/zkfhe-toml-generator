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
pub mod toml;
pub mod utils;

// Re-export commonly used items for convenience
pub use bfv::{BfvConfig, BfvHelper, EncryptionData};
pub use circuit::{Circuit, CircuitConfig, CircuitMetadata, CircuitParams, CustomParams};
pub use constants::{ZKP_MODULUS, get_zkp_modulus};
pub use toml::TomlGenerator;

/// Validation utilities for common parameters
///
/// This module provides functions to validate cryptographic parameters
/// and ensure they meet security requirements.
pub mod validation {
    use std::error::Error;

    /// Validate that a degree is a valid power of 2
    ///
    /// # Arguments
    ///
    /// * `degree` - The polynomial degree to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the degree is a valid power of 2, or an error otherwise.
    pub fn validate_degree(degree: usize) -> Result<(), Box<dyn Error>> {
        if !degree.is_power_of_two() {
            return Err("Degree must be a power of 2".into());
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
    pub fn validate_degree_bounds(degree: usize) -> Result<(), Box<dyn Error>> {
        validate_degree(degree)?;

        if degree < 1024 || degree > 8192 {
            return Err("Degree must be between 1024 and 8192".into());
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
    pub fn validate_plaintext_modulus(modulus: u64) -> Result<(), Box<dyn Error>> {
        if modulus == 0 {
            return Err("Plaintext modulus cannot be zero".into());
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
