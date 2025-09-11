//! Parameters and Common Reference String (CRS) for the PVW library
//!
//! This module manages the various parameters required for the PVW scheme
//! and the Common Reference String used in cryptographic protocols.

pub mod crs;
pub mod parameters;
pub use crate::errors::{PvwError, PvwResult};
pub use crs::PvwCrs;
pub use parameters::{PvwParameters, PvwParametersBuilder, Result};

/// Re-export parameter-related types and functions
pub mod prelude {
    pub use super::*;
}
