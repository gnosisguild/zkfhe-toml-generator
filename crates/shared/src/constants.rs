//! Constants 
//!
//! This module contains constants that are shared,
//! such as ZKP moduli and other cryptographic constants.

use num_bigint::BigInt;
use std::str::FromStr;

/// ZKP modulus (BN254 scalar field)
pub const ZKP_MODULUS: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Get the ZKP modulus as a BigInt
pub fn get_zkp_modulus() -> BigInt {
    BigInt::from_str(ZKP_MODULUS).expect("Invalid ZKP modulus")
}
