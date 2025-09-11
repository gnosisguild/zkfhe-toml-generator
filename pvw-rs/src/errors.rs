//! Error handling for the PVW library
//!
//! This module provides a comprehensive error handling system based on `thiserror`
//! that covers all error cases across the library.
use thiserror::Error;

/// PVW library error types
#[derive(Error, Debug)]
pub enum PvwError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Sampling error: {0}")]
    SamplingError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    #[error("CRS error: {0}")]
    CrsError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Polynomial error: {0}")]
    PolynomialError(String),

    #[error("Matrix error: {0}")]
    MatrixError(String),

    #[error("Dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    #[error("Index out of bounds: {index} >= {bound}")]
    IndexOutOfBounds { index: usize, bound: usize },

    #[error("Insufficient data: expected {expected} bytes, got {actual}")]
    InsufficientData { expected: usize, actual: usize },

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type alias for PVW operations
pub type PvwResult<T> = std::result::Result<T, PvwError>;
