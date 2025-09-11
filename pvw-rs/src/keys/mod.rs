//! Key generation and management for the PVW library
//!
//! This module handles the generation, storage, and management of cryptographic keys
//! including public keys, secret keys, and global public keys.

pub mod public_key;
pub mod secret_key;

pub use public_key::{GlobalPublicKey, Party, PublicKey};
pub use secret_key::SecretKey;

/// Re-export key-related types and functions
pub mod prelude {
    pub use super::*;
}
