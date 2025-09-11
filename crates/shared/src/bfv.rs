//! BFV parameter utilities and encryption helpers.
//!
//! This module provides utilities for working with BFV encryption parameters,
//! generating sample encryptions, and managing encryption contexts.

use crate::constants::get_zkp_modulus;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Plaintext, PublicKey, SecretKey};
use fhe_math::rq::Poly;
use num_bigint::BigInt;
use std::sync::Arc;

/// Configuration for BFV parameters
#[derive(Clone, Debug)]
pub struct BfvConfig {
    pub degree: usize,
    pub plaintext_modulus: u64,
    pub moduli: Vec<u64>,
}

impl Default for BfvConfig {
    fn default() -> Self {
        Self {
            degree: 2048,
            plaintext_modulus: 1032193,
            moduli: vec![18014398492704769],
        }
    }
}

/// Data from a sample BFV encryption
pub struct EncryptionData {
    pub plaintext: Plaintext,
    pub ciphertext: Ciphertext,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub u_rns: Poly,
    pub e0_rns: Poly,
    pub e1_rns: Poly,
}

/// Helper for working with BFV parameters and operations
pub struct BfvHelper {
    pub params: Arc<BfvParameters>,
}

impl BfvHelper {
    /// Create a new BFV helper from configuration
    pub fn new(config: BfvConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let params = BfvParametersBuilder::new()
            .set_degree(config.degree)
            .set_plaintext_modulus(config.plaintext_modulus)
            .set_moduli(&config.moduli)
            .build_arc()?;

        Ok(BfvHelper { params })
    }

    /// Get the default ZKP modulus
    pub fn default_zkp_modulus() -> BigInt {
        get_zkp_modulus()
    }
}
