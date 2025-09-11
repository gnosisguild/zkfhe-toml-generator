//! BFV Parameter Search Library
//!
//! This library provides functionality to search for optimal BFV (Brakerski-Fan-Vercauteren)
//! parameters using NTT-friendly primes. It implements exact arithmetic for security analysis
//! and parameter validation.

pub mod constants;
pub mod errors;
pub mod prime;
pub mod search;
pub mod utils;
