//! PVW Multi-Receiver LWE Encryption Scheme
//!
//! A pure-Rust implementation of the PVW (Peikert-Vaikuntanathan-Waters)
//! multi-receiver LWE encryption scheme designed for use in threshold schemes,
//! PVSS (Publicly Verifiable Secret Sharing), and lattice-based cryptography.
//!
//! ## Modules
//! - `keys`: Key generation and management
//! - `params`: Scheme parameters and CRS
//! - `traits`: Common interfaces for serialization, encoding, and validation
//! - `crypto`: Core encryption and decryption operations
//! - `sampling`: Mathematical sampling utilities

pub mod crypto;
pub mod errors;
pub mod keys;
pub mod params;
pub mod sampling;
pub mod traits;

// Re-export main types for convenience
pub use crypto::*;
pub use keys::*;
pub use params::*;
pub use sampling::*;

// Re-export traits
pub use traits::{Encode, Serialize, Validate};

// Module preludes for easy importing
pub mod prelude {
    // Re-export key types
    pub use crate::keys::{GlobalPublicKey, Party, PublicKey, SecretKey};

    // Re-export parameter types
    pub use crate::params::{PvwCrs, PvwParameters, PvwParametersBuilder, Result};

    // Re-export error types
    pub use crate::errors::{PvwError, PvwResult};

    // Re-export crypto types
    pub use crate::crypto::{
        PvwCiphertext, decrypt_party_shares, decrypt_party_value, decrypt_threshold_party_shares,
        encrypt,
    };

    // Re-export sampling functions
    pub use crate::sampling::normal::{sample_bigint_normal_vec, sample_discrete_gaussian_vec};

    // Re-export traits
    pub use crate::traits::{Encode, Serialize, Validate};
}

// Re-export commonly used types at the top level for backward compatibility
pub use errors::{PvwError, PvwResult};
pub use keys::{GlobalPublicKey, Party, PublicKey, SecretKey};
pub use params::PvwCrs;
pub use params::{PvwParameters, PvwParametersBuilder, Result};
