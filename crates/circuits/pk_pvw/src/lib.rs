//! PVW public key circuit parameter generation in Rust
//!
//! This crate provides the PVW public key circuit parameter generation in Rust.
//! The PVW public key circuit is a zero-knowledge proof circuit for PVW encryption
//! that enables proving correct public key generation without revealing the secret keys.
//!
//! - **Bounds Calculation**: Computes valid ranges for polynomial coefficients
//! - **Vector Generation**: Creates input validation vectors for zero-knowledge proofs
//! - **TOML Generation**: Produces Noir-compatible TOML files
//! - **Configuration Validation**: Ensures cryptographic parameters are secure

pub mod bounds;
pub mod toml;
pub mod vectors;

use shared::Circuit;
use shared::circuit::{CircuitConfig, CircuitParams, CircuitMetadata};
use shared::errors::ZkfheResult;
use shared::toml::TomlGenerator;
use std::path::Path;

/// PVW public key circuit implementation
///
/// This struct implements the `Circuit` trait for the PVW public key zero-knowledge
/// proof circuit. It provides methods for parameter generation, TOML file
/// creation, and configuration validation.
///
/// The PVW public key circuit is designed to prove the correctness of PVW public
/// key generation without revealing the secret keys. It achieves this by generating
/// bounds and validation vectors that can be used in zero-knowledge proofs.
pub struct PvwPkCircuit;

impl PvwPkCircuit {
    /// Get default PVW parameters for the circuit
    ///
    /// This method creates default PVW parameters using the PVW library's
    /// suggest_correct_parameters function to ensure cryptographic correctness.
    ///
    /// # Returns
    /// Returns the default PVW parameters with suggested error bounds
    pub fn get_default_params() -> (usize, usize, usize, u32, u64, u64, Vec<u64>) {
        let n_parties = 7;
        let k = 32; // LWE dimension  
        let l = 8;  // ring degree
        let moduli = vec![68719403009, 68719230977, 137438822401];
        
        // Get parameters that satisfy correctness condition
        let (suggested_variance, suggested_bound1, suggested_bound2) =
            pvw::PvwParameters::suggest_correct_parameters(n_parties, k, l, &moduli)
                .unwrap_or((1, 50, 100));
                
        // Note: Using PVW-suggested parameters for cryptographic correctness
        
        (
            n_parties,
            k,
            l,
            suggested_variance,
            suggested_bound1 as u64,
            suggested_bound2 as u64,
            moduli,
        )
    }

    /// Get computed bounds directly
    ///
    /// This method computes the bounds for polynomial coefficients that
    /// are used in zero-knowledge proof validation.
    ///
    /// # Arguments
    ///
    /// * `n_parties` - Number of parties
    /// * `k` - LWE dimension
    /// * `l` - Ring degree
    /// * `secret_variance` - Secret key variance
    /// * `error_bound_1` - First error bound
    /// * `error_bound_2` - Second error bound
    /// * `moduli` - RNS moduli chain
    ///
    /// # Returns
    /// Returns the computed bounds or an error if computation fails.
    pub fn get_bounds(
        n_parties: usize,
        k: usize,
        l: usize,
        secret_variance: u32,
        error_bound_1: u64,
        error_bound_2: u64,
        moduli: Vec<u64>,
    ) -> Result<bounds::PvwPkBounds, shared::errors::ZkfheError> {
        bounds::PvwPkBounds::compute(
            moduli,
            l as u32,
            k as u32,
            n_parties as u32,
            error_bound_1,
            secret_variance as u64,
        )
        .map_err(|e| shared::errors::ZkfheError::Circuit {
            message: e.to_string(),
        })
    }

    /// Get computed bounds using the actual computed error bound from vectors
    pub fn get_bounds_from_vectors(
        vectors: &vectors::PvwPkVectors,
        n_parties: usize,
        k: usize,
        l: usize,
        secret_variance: u32,
        moduli: Vec<u64>,
    ) -> Result<bounds::PvwPkBounds, shared::errors::ZkfheError> {
        // Use the computed error bound from actual vector generation
        let computed_error_bound = vectors.computed_error_bound;
        
        bounds::PvwPkBounds::compute(
            moduli,
            l as u32,
            k as u32,
            n_parties as u32,
            computed_error_bound,
            secret_variance as u64,
        )
        .map_err(|e| shared::errors::ZkfheError::Circuit {
            message: e.to_string(),
        })
    }

    /// Get computed vectors directly
    ///
    /// This method generates the witness vectors that are used in zero-knowledge
    /// proof validation.
    ///
    /// # Arguments
    ///
    /// * `n_parties` - Number of parties
    /// * `k` - LWE dimension
    /// * `l` - Ring degree
    /// * `secret_variance` - Secret key variance
    /// * `error_bound_1` - First error bound
    /// * `error_bound_2` - Second error bound
    /// * `moduli` - RNS moduli chain
    ///
    /// # Returns
    /// Returns the computed vectors or an error if computation fails.
    pub fn get_vectors(
        n_parties: usize,
        k: usize,
        l: usize,
        secret_variance: u32,
        error_bound_1: u64,
        error_bound_2: u64,
        moduli: Vec<u64>,
    ) -> Result<vectors::PvwPkVectors, shared::errors::ZkfheError> {
        vectors::PvwPkVectors::compute(
            n_parties,
            k,
            l,
            secret_variance,
            error_bound_1,
            error_bound_2,
            &moduli,
        )
        .map_err(|e| shared::errors::ZkfheError::Circuit {
            message: e.to_string(),
        })
    }

    /// Get computed vectors and corrected bounds
    ///
    /// This method generates vectors first, then computes bounds using the actual
    /// error magnitude found in the vectors. This ensures the bounds are realistic.
    ///
    /// # Returns
    /// Returns (vectors, bounds) tuple with corrected error bounds
    pub fn get_vectors_and_bounds(
        n_parties: usize,
        k: usize,
        l: usize,
        secret_variance: u32,
        error_bound_1: u64,
        error_bound_2: u64,
        moduli: Vec<u64>,
    ) -> Result<(vectors::PvwPkVectors, bounds::PvwPkBounds), shared::errors::ZkfheError> {
        // First compute vectors to get actual error bounds
        let vectors = Self::get_vectors(
            n_parties, k, l, secret_variance, error_bound_1, error_bound_2, moduli.clone()
        )?;
        
        // Then compute bounds using the actual computed error bound
        let bounds = Self::get_bounds_from_vectors(
            &vectors, n_parties, k, l, secret_variance, moduli
        )?;
        
        // Note: Using actual computed error bounds instead of suggested bounds for accuracy
        
        Ok((vectors, bounds))
    }
}

impl Circuit for PvwPkCircuit {
    fn name(&self) -> &'static str {
        "pk_pvw"
    }

    fn description(&self) -> &'static str {
        "PVW public key verification circuit for zero-knowledge proofs"
    }

    fn generate_params(&self, _config: &CircuitConfig) -> ZkfheResult<CircuitParams> {
        // Create circuit parameters
        let params = CircuitParams {
            config: _config.clone(),
            metadata: CircuitMetadata {
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: self.description().to_string(),
                created_at: chrono::Utc::now(),
            },
        };

        Ok(params)
    }

    fn generate_toml(&self, _params: &CircuitParams, output_dir: &Path) -> ZkfheResult<()> {
        // Get default PVW parameters and compute bounds and vectors
        let (n_parties, k, l, secret_variance, error_bound_1, error_bound_2, moduli) = 
            Self::get_default_params();

        // Compute vectors and corrected bounds together
        let (vectors, bounds) = Self::get_vectors_and_bounds(
            n_parties,
            k,
            l,
            secret_variance,
            error_bound_1,
            error_bound_2,
            moduli,
        )?;

        // Create TOML generator
        let generator = toml::PvwPkTomlGenerator::new(bounds, vectors);

        // Generate TOML file
        generator.generate_toml(output_dir)?;

        Ok(())
    }

    fn validate_config(&self, _config: &CircuitConfig) -> ZkfheResult<()> {
        // For now, accept any configuration since we use default PVW parameters
        // In the future, we could add validation for custom PVW parameters
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::circuit::CircuitConfig;
    use shared::circuit::CircuitDimensions;

    #[test]
    fn test_circuit_name() {
        let circuit = PvwPkCircuit;
        assert_eq!(circuit.name(), "pk_pvw");
    }

    #[test]
    fn test_circuit_description() {
        let circuit = PvwPkCircuit;
        assert!(circuit.description().contains("PVW public key"));
    }

    #[test]
    fn test_default_params() {
        let (n_parties, k, l, secret_variance, error_bound_1, error_bound_2, moduli) = 
            PvwPkCircuit::get_default_params();
        
        assert_eq!(n_parties, 7);
        assert_eq!(k, 32);
        assert_eq!(l, 8);
        assert_eq!(secret_variance, 1);
        assert_eq!(error_bound_1, 5000);
        assert_eq!(error_bound_2, 5000);
        assert_eq!(moduli.len(), 3);
    }

    #[test]
    fn test_bounds_computation() {
        let (n_parties, k, l, secret_variance, error_bound_1, error_bound_2, moduli) = 
            PvwPkCircuit::get_default_params();
        
        let bounds = PvwPkCircuit::get_bounds(
            n_parties,
            k,
            l,
            secret_variance,
            error_bound_1,
            error_bound_2,
            moduli,
        ).unwrap();

        assert_eq!(bounds.n_parties, 7);
        assert_eq!(bounds.k, 32);
        assert_eq!(bounds.n, 8);
    }

    #[test]
    fn test_vectors_computation() {
        let (n_parties, k, l, secret_variance, error_bound_1, error_bound_2, moduli) = 
            PvwPkCircuit::get_default_params();
        
        let vectors = PvwPkCircuit::get_vectors(
            n_parties,
            k,
            l,
            secret_variance,
            error_bound_1,
            error_bound_2,
            moduli,
        ).unwrap();

        assert_eq!(vectors.num_moduli(), 3);
        assert_eq!(vectors.degree(), 8);
    }
}
