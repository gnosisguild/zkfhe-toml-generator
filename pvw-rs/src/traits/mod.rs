//! Common traits for the PVW library
//!
//! This module provides the foundational traits that define the interface
//! for serialization, encoding, and validation across all PVW types.

use crate::errors::PvwError;

/// Trait for serializing types to and from bytes
pub trait Serialize {
    /// Serialize the type to a byte vector
    fn to_bytes(&self) -> Result<Vec<u8>, PvwError>;

    /// Deserialize the type from a byte slice
    fn from_bytes(bytes: &[u8]) -> Result<Self, PvwError>
    where
        Self: Sized;
}

/// Trait for encoding types to and from bytes with specific format
pub trait Encode {
    /// Encode the type to a byte vector
    fn encode(&self) -> Result<Vec<u8>, PvwError>;

    /// Decode the type from a byte slice
    fn decode(bytes: &[u8]) -> Result<Self, PvwError>
    where
        Self: Sized;
}

/// Trait for validating types
pub trait Validate {
    /// Validate the type and return a result
    fn validate(&self) -> Result<(), PvwError>;

    /// Check if the type is valid
    fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

/// Re-export all traits for easy importing
pub mod prelude {
    pub use super::{Encode, Serialize, Validate};
}
