use crate::errors::PvwError;
use crate::params::parameters::{PvwParameters, Result};
use fhe_math::rq::{Poly, Representation};
use fhe_util::sample_vec_cbd;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PVW Secret Key using coefficient representation
///
/// Stores secret key coefficients directly from CBD sampling for efficiency.
/// Polynomials are created on-demand for cryptographic operations.
#[derive(Debug, Clone)]
pub struct SecretKey {
    pub params: Arc<PvwParameters>,
    /// Secret key coefficients directly from sampling (k × l matrix)
    pub secret_coeffs: Vec<Vec<i64>>,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        // Zero out coefficient data
        for row in &mut self.secret_coeffs {
            row.zeroize();
        }
        self.secret_coeffs.clear();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Generate random secret key using CBD distribution
    ///
    /// Uses the variance specified in the PVW parameters to sample coefficients
    /// from a centered binomial distribution. Stores coefficients directly
    /// to avoid conversion overhead during frequent operations.
    ///
    /// # Arguments
    /// * `params` - PVW parameters specifying dimensions and variance
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// A new SecretKey with randomly sampled coefficients
    pub fn random<R: RngCore + CryptoRng>(
        params: &Arc<PvwParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        let mut secret_coeffs = Vec::with_capacity(params.k);

        for _ in 0..params.k {
            // Sample coefficients using CBD with configured variance
            let coeffs = sample_vec_cbd(params.l, params.secret_variance as usize, rng)
                .map_err(|e| PvwError::SamplingError(format!("CBD sampling failed: {e}")))?;

            secret_coeffs.push(coeffs);
        }

        Ok(Self {
            params: params.clone(),
            secret_coeffs,
        })
    }

    /// Convert coefficients to polynomials when needed for crypto operations
    ///
    /// Creates polynomials in NTT form for efficient ring operations.
    /// This is done on-demand to avoid storing redundant representations.
    ///
    /// # Returns
    /// Vector of polynomials in NTT representation
    pub fn to_polynomials(&self) -> Result<Vec<Poly>> {
        let mut polys = Vec::with_capacity(self.params.k);

        for coeffs in &self.secret_coeffs {
            let mut poly = Poly::from_coefficients(coeffs, &self.params.context).map_err(|e| {
                PvwError::SamplingError(format!("Failed to create polynomial: {e:?}"))
            })?;

            poly.change_representation(Representation::Ntt);
            polys.push(poly);
        }

        Ok(polys)
    }

    /// Get a single polynomial at index for crypto operations
    ///
    /// Converts the coefficient vector at the specified index into a polynomial
    /// in NTT representation. More efficient than converting all polynomials
    /// when only one is needed.
    ///
    /// # Arguments
    /// * `index` - Index of the polynomial to convert (0 <= index < k)
    ///
    /// # Returns
    /// Polynomial in NTT representation, or error if index is out of bounds
    pub fn get_polynomial(&self, index: usize) -> Result<Poly> {
        if index >= self.secret_coeffs.len() {
            return Err(PvwError::InvalidParameters(format!(
                "Index {} out of bounds for {} polynomials",
                index,
                self.secret_coeffs.len()
            )));
        }

        let mut poly = Poly::from_coefficients(&self.secret_coeffs[index], &self.params.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create polynomial: {e:?}")))?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Direct access to coefficient matrix
    ///
    /// Provides access to the raw coefficient representation without
    /// polynomial conversion overhead. Useful for operations that work
    /// directly with coefficient vectors.
    ///
    /// # Returns
    /// Reference to the k × l coefficient matrix
    pub fn coefficients(&self) -> &[Vec<i64>] {
        &self.secret_coeffs
    }

    /// Mutable access to coefficient matrix
    ///
    /// Allows direct modification of secret key coefficients.
    /// Use with caution as this bypasses validation.
    ///
    /// # Returns
    /// Mutable reference to the k × l coefficient matrix
    pub fn coefficients_mut(&mut self) -> &mut [Vec<i64>] {
        &mut self.secret_coeffs
    }

    /// Get coefficients for a specific polynomial
    ///
    /// # Arguments
    /// * `index` - Index of the polynomial (0 <= index < k)
    ///
    /// # Returns
    /// Reference to coefficient vector, or None if index is out of bounds
    pub fn get_coefficients(&self, index: usize) -> Option<&[i64]> {
        self.secret_coeffs.get(index).map(|v| v.as_slice())
    }

    /// Get mutable coefficients for a specific polynomial
    ///
    /// # Arguments
    /// * `index` - Index of the polynomial (0 <= index < k)
    ///
    /// # Returns
    /// Mutable reference to coefficient vector, or None if index is out of bounds
    pub fn get_coefficients_mut(&mut self, index: usize) -> Option<&mut Vec<i64>> {
        self.secret_coeffs.get_mut(index)
    }

    /// Legacy methods for backward compatibility
    pub fn to_coefficient_matrix(&self) -> Result<Vec<Vec<i64>>> {
        Ok(self.secret_coeffs.clone())
    }

    pub fn as_matrix(&self) -> Result<Vec<Vec<i64>>> {
        self.to_coefficient_matrix()
    }

    pub fn as_matrix_mut(&mut self) -> Result<Vec<Vec<i64>>> {
        Ok(self.secret_coeffs.clone())
    }

    /// Legacy polynomial access (creates polynomials on demand)
    pub fn as_poly_vector(&self) -> Result<Vec<Poly>> {
        self.to_polynomials()
    }

    /// Get the number of secret polynomials (should equal k)
    pub fn len(&self) -> usize {
        self.secret_coeffs.len()
    }

    /// Check if secret key is empty
    pub fn is_empty(&self) -> bool {
        self.secret_coeffs.is_empty()
    }

    /// Validate secret key structure against parameters
    ///
    /// Ensures the secret key dimensions match the PVW parameters
    /// and that all coefficient vectors have the correct length.
    ///
    /// # Returns
    /// Ok(()) if structure is valid, Err with details if invalid
    pub fn validate(&self) -> Result<()> {
        if self.secret_coeffs.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Secret key has {} polynomials but k={}",
                self.secret_coeffs.len(),
                self.params.k
            )));
        }

        // Verify all coefficient vectors have correct length
        for (i, coeffs) in self.secret_coeffs.iter().enumerate() {
            if coeffs.len() != self.params.l {
                return Err(PvwError::InvalidParameters(format!(
                    "Secret key polynomial {} has {} coefficients but l={}",
                    i,
                    coeffs.len(),
                    self.params.l
                )));
            }
        }

        Ok(())
    }

    /// Check if coefficients are within expected CBD bounds
    ///
    /// Validates that all coefficients fall within the expected range
    /// for the configured CBD variance. This helps detect incorrect parameter usage.
    ///
    /// # Returns
    /// Ok(()) if all coefficients are within bounds, Err with details if not
    pub fn validate_coefficient_bounds(&self) -> Result<()> {
        let max_bound = 2 * self.params.secret_variance as i64;

        for (poly_idx, coeffs) in self.secret_coeffs.iter().enumerate() {
            for (coeff_idx, &coeff) in coeffs.iter().enumerate() {
                if coeff.abs() > max_bound {
                    return Err(PvwError::InvalidParameters(format!(
                        "Coefficient at polynomial {} index {} is {} but should be in [-{}, {}] for variance {}",
                        poly_idx,
                        coeff_idx,
                        coeff,
                        max_bound,
                        max_bound,
                        self.params.secret_variance
                    )));
                }
            }
        }

        Ok(())
    }

    /// Create secret key from existing coefficients
    ///
    /// Used for testing, deserialization, or when coefficients are
    /// generated externally. Validates the coefficient structure.
    ///
    /// # Arguments
    /// * `params` - PVW parameters that match the coefficient dimensions
    /// * `coefficients` - Pre-generated k × l coefficient matrix
    ///
    /// # Returns
    /// SecretKey with the provided coefficients, or error if invalid
    pub fn from_coefficients(
        params: Arc<PvwParameters>,
        coefficients: Vec<Vec<i64>>,
    ) -> Result<Self> {
        let sk = Self {
            params,
            secret_coeffs: coefficients,
        };

        sk.validate()?;
        Ok(sk)
    }

    /// Serialize coefficients for storage or transmission
    ///
    /// Creates a copy of the coefficient matrix suitable for serialization.
    /// The result can be used with `from_coefficients` to reconstruct the key.
    ///
    /// # Returns
    /// Cloned coefficient matrix
    pub fn serialize_coefficients(&self) -> Vec<Vec<i64>> {
        self.secret_coeffs.clone()
    }

    /// Get coefficient statistics for debugging and analysis
    ///
    /// Computes basic statistics over all coefficients in the secret key.
    /// Useful for verifying the distribution properties and detecting anomalies.
    ///
    /// # Returns
    /// Tuple of (minimum, maximum, mean) coefficient values
    pub fn coefficient_stats(&self) -> (i64, i64, f64) {
        let all_coeffs: Vec<i64> = self.secret_coeffs.iter().flatten().copied().collect();

        if all_coeffs.is_empty() {
            return (0, 0, 0.0);
        }

        // Safe to unwrap here since we've checked that all_coeffs is not empty
        let min = *all_coeffs.iter().min().expect("all_coeffs is not empty");
        let max = *all_coeffs.iter().max().expect("all_coeffs is not empty");
        let mean = all_coeffs.iter().sum::<i64>() as f64 / all_coeffs.len() as f64;

        (min, max, mean)
    }
}
