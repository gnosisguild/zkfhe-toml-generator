//! Utility functions for zkFHE circuit generation

use num_bigint::BigInt;

/// Convert a 1D vector of BigInt to a vector of strings
pub fn to_string_1d_vec(vec: &[BigInt]) -> Vec<String> {
    vec.iter().map(|x| x.to_string()).collect()
}
