use super::parameters::{PvwParameters, Result};
use crate::errors::PvwError;
use fhe_math::rq::{Poly, Representation};
use fhe_traits::Serialize;
use ndarray::Array2;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;

/// Common Reference String for PVW encryption
/// Contains a k × k matrix of polynomials in R_q used for multi-party encryption
#[derive(Debug, Clone)]
pub struct PvwCrs {
    /// k × k matrix of polynomials in R_q
    pub matrix: Array2<Poly>,
    /// PVW parameters used to generate this CRS
    pub params: Arc<PvwParameters>,
}

impl PvwCrs {
    /// Generate a new random CRS matrix
    ///
    /// Creates a k×k matrix of random polynomials for use in PVW encryption.
    /// All polynomials are generated in NTT representation for efficiency.
    pub fn new<R: RngCore + CryptoRng>(params: &Arc<PvwParameters>, rng: &mut R) -> Result<Self> {
        let mut matrix = Array2::from_elem(
            (params.k, params.k),
            Poly::zero(&params.context, Representation::Ntt),
        );

        // Generate each matrix element with independent randomness
        for elem in matrix.iter_mut() {
            *elem = Poly::random(&params.context, Representation::Ntt, rng);
        }

        Ok(Self {
            matrix,
            params: params.clone(),
        })
    }

    /// Generate CRS deterministically from a master seed
    ///
    /// Creates a CRS that can be reproduced by all parties using the same seed.
    /// Essential for PVSS where all participants need the same reference string.
    pub fn new_deterministic(
        params: &Arc<PvwParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let mut matrix = Array2::from_elem(
            (params.k, params.k),
            Poly::zero(&params.context, Representation::Ntt),
        );

        // Create master RNG from the seed
        let mut master_rng = ChaCha8Rng::from_seed(seed);

        // Generate each matrix element with independent randomness
        for elem in matrix.iter_mut() {
            let element_seed = master_rng.r#gen::<[u8; 32]>();
            *elem = Poly::random_from_seed(&params.context, Representation::Ntt, element_seed);
        }

        Ok(Self {
            matrix,
            params: params.clone(),
        })
    }

    /// Generate CRS deterministically from a string tag
    ///
    /// Creates a deterministic CRS that all parties can derive from a known string.
    /// Useful for PVSS where all participants need the same reference string.
    /// TODO: operate over bytes instead of strings when hashing
    pub fn new_from_tag(params: &Arc<PvwParameters>, tag: &str) -> Result<Self> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Create deterministic seed from tag
        let mut hasher = DefaultHasher::new();
        (tag.to_string() + "CRS").hash(&mut hasher);
        let seed_u64 = hasher.finish();

        // Expand to 32-byte seed
        let mut seed = [0u8; 32];
        for (i, chunk) in seed_u64.to_le_bytes().iter().cycle().take(32).enumerate() {
            seed[i] = *chunk;
        }

        Self::new_deterministic(params, seed)
    }

    /// Get the polynomial at position (i, j) in the CRS matrix
    pub fn get(&self, i: usize, j: usize) -> Option<&Poly> {
        self.matrix.get((i, j))
    }

    /// Get a mutable reference to the polynomial at position (i, j)
    pub fn get_mut(&mut self, i: usize, j: usize) -> Option<&mut Poly> {
        self.matrix.get_mut((i, j))
    }

    /// Get the dimensions of the CRS matrix
    pub fn dimensions(&self) -> (usize, usize) {
        (self.params.k, self.params.k)
    }

    /// Validate that the CRS matrix has the correct dimensions and structure
    pub fn validate(&self) -> Result<()> {
        let (rows, cols) = self.matrix.dim();
        if rows != self.params.k || cols != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "CRS matrix dimensions {}×{} don't match parameter k={}",
                rows, cols, self.params.k
            )));
        }

        // Verify all polynomials use the correct context and are in NTT form
        for poly in self.matrix.iter() {
            if !Arc::ptr_eq(&poly.ctx, &self.params.context) {
                return Err(PvwError::InvalidParameters(
                    "CRS polynomial context mismatch".to_string(),
                ));
            }
            if *poly.representation() != Representation::Ntt {
                return Err(PvwError::InvalidParameters(
                    "CRS polynomial not in NTT representation".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Matrix-vector multiplication: A * secret_key
    ///
    /// Computes the product of the CRS matrix with a secret key vector.
    /// Used in PVW public key generation: pk = sk * A + noise.
    pub fn multiply_by_secret_key(
        &self,
        secret_key: &crate::secret_key::SecretKey,
    ) -> Result<Vec<Poly>> {
        if secret_key.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Secret key length {} doesn't match CRS dimension k={}",
                secret_key.len(),
                self.params.k
            )));
        }

        let mut result = Vec::with_capacity(self.params.k);

        // Compute result[i] = sum_j(secret_key[j] * A[j][i])
        for i in 0..self.params.k {
            let mut sum = Poly::zero(&self.params.context, Representation::Ntt);

            for j in 0..self.params.k {
                let sk_poly = secret_key.get_polynomial(j)?;
                let crs_poly = self.get(j, i).ok_or_else(|| PvwError::IndexOutOfBounds {
                    index: j,
                    bound: self.params.k,
                })?;

                let product = &sk_poly * crs_poly;
                sum = &sum + &product;
            }

            result.push(sum);
        }

        Ok(result)
    }

    /// Matrix-vector multiplication: A * randomness_vector
    ///
    /// Computes the product of the CRS matrix with a randomness vector.
    /// Used in PVW encryption: c1 = A * r + e1.
    pub fn multiply_by_randomness(&self, randomness: &[Poly]) -> Result<Vec<Poly>> {
        if randomness.len() != self.params.k {
            return Err(PvwError::DimensionMismatch {
                expected: self.params.k,
                actual: randomness.len(),
            });
        }

        let mut result = Vec::with_capacity(self.params.k);

        // Compute result[i] = sum_j(A[i][j] * randomness[j])
        for i in 0..self.params.k {
            let mut sum = Poly::zero(&self.params.context, Representation::Ntt);

            for (j, randomness_poly) in randomness.iter().enumerate().take(self.params.k) {
                let crs_poly = self.get(i, j).ok_or_else(|| PvwError::IndexOutOfBounds {
                    index: i,
                    bound: self.params.k,
                })?;

                let product = crs_poly * randomness_poly;
                sum = &sum + &product;
            }

            result.push(sum);
        }

        Ok(result)
    }

    /// Get an iterator over all polynomials in the matrix
    pub fn iter(&self) -> impl Iterator<Item = &Poly> {
        self.matrix.iter()
    }

    /// Get a mutable iterator over all polynomials in the matrix
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Poly> {
        self.matrix.iter_mut()
    }

    /// Get the total number of polynomials in the CRS (k²)
    pub fn len(&self) -> usize {
        self.params.k * self.params.k
    }

    /// Check if the CRS is empty (k = 0)
    pub fn is_empty(&self) -> bool {
        self.params.k == 0
    }
}

impl Serialize for PvwCrs {
    /// Serialize the CRS to bytes
    ///
    /// Serializes the entire k×k matrix of polynomials in row-major order.
    /// The format includes dimension information for validation during deserialization.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize matrix dimensions first for validation during deserialization
        bytes.extend_from_slice(&(self.params.k as u32).to_le_bytes());

        // Serialize each polynomial in row-major order
        for poly in self.matrix.iter() {
            let poly_bytes = poly.to_bytes();
            // Store length prefix for each polynomial
            bytes.extend_from_slice(&(poly_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&poly_bytes);
        }

        bytes
    }
}
