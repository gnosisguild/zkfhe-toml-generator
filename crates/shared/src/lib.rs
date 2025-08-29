//! Shared utilities and traits for zkFHE circuit generation
//!
//! This crate provides common functionality used across all circuit implementations.

pub mod bfv;
pub mod circuit;
pub mod utils;

pub use bfv::{BfvConfig, BfvHelper, EncryptionData};
pub use circuit::Circuit;
