//! Shared utilities and traits for zkFHE circuit generation
//!
//! This crate provides common functionality used across all circuit implementations.

pub mod bfv;
pub mod circuit;
pub mod constants;
pub mod utils;

pub use bfv::{BfvConfig, BfvHelper, EncryptionData};
pub use constants::{ZKP_MODULUS, get_zkp_modulus};
pub use circuit::Circuit;
