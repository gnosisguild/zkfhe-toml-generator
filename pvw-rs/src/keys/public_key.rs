use super::secret_key::SecretKey;
use crate::errors::PvwError;
use crate::params::crs::PvwCrs;
use crate::params::parameters::{PvwParameters, Result};
use fhe_math::rq::{Poly, Representation};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::sync::Arc;

/// Individual party in the PVSS protocol
///
/// Each party manages their own secret key and has a unique index.
/// Parties generate public keys using the common reference string
/// and participate in the multi-party encryption protocol.
#[derive(Debug, Clone)]
pub struct Party {
    /// Unique index for this party (0 to n-1)
    pub index: usize,
    /// This party's secret key
    pub secret_key: SecretKey,
}

/// Individual public key for a single party
///
/// Stores the result of b_i = s_i * A + e_i computation where s_i is the secret key,
/// A is the CRS matrix, and e_i is the error vector. Polynomials are kept in RNS form
/// for efficient cryptographic operations.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The public key polynomials in RNS form (k polynomials)
    pub key_polynomials: Vec<Poly>,
    /// Parameters used to generate this key
    pub params: Arc<PvwParameters>,
}

/// Global public key containing all parties' public keys
///
/// Maintains an n × k matrix where each element is a polynomial in RNS form.
/// This matrix B is used for encryption operations where each row corresponds
/// to one party's public key.
#[derive(Debug, Clone)]
pub struct GlobalPublicKey {
    /// n × k matrix where each element is a polynomial in RNS form
    pub matrix: Array2<Poly>,
    /// Common Reference String used for key generation
    pub crs: PvwCrs,
    /// Number of public keys currently stored
    pub num_keys: usize,
    /// Parameters used for this global key
    pub params: Arc<PvwParameters>,
}

impl Party {
    /// Create a new party with a randomly generated secret key
    ///
    /// Validates that the party index is within the valid range [0, n).
    /// The secret key is generated using the CBD distribution with the
    /// variance specified in the parameters.
    pub fn new<R: RngCore + CryptoRng>(
        index: usize,
        params: &Arc<PvwParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        // Validate index
        if index >= params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Party index {} exceeds maximum {}",
                index,
                params.n - 1
            )));
        }

        let secret_key = SecretKey::random(params, rng)?;

        Ok(Self { index, secret_key })
    }

    /// Generate this party's public key using the provided CRS
    ///
    /// Computes the public key as b_i = s_i * A + e_i where A is the CRS matrix.
    /// The result is stored in efficient RNS representation for cryptographic operations.
    pub fn generate_public_key<R: RngCore + CryptoRng>(
        &self,
        crs: &PvwCrs,
        rng: &mut R,
    ) -> Result<PublicKey> {
        PublicKey::generate(&self.secret_key, crs, rng)
    }

    /// Get this party's index
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get a reference to this party's secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl PublicKey {
    /// Generate a public key for a given secret key
    ///
    /// Implements the PVW public key generation: b_i = s_i * A + e_i
    /// where s_i is the secret key, A is the CRS matrix, and e_i is sampled error.
    /// All polynomials are maintained in RNS form for efficiency.
    pub fn generate<R: RngCore + CryptoRng>(
        secret_key: &SecretKey,
        crs: &PvwCrs,
        rng: &mut R,
    ) -> Result<Self> {
        // Validate dimensions
        if secret_key.params.k != crs.params.k {
            return Err(PvwError::DimensionMismatch {
                expected: crs.params.k,
                actual: secret_key.params.k,
            });
        }

        // Compute A * secret_key using CRS matrix multiplication
        let sk_a_result = crs.multiply_by_secret_key(secret_key)?;

        // Generate error polynomials using the configured error bound
        let mut error_polys = Vec::with_capacity(secret_key.params.k);
        for _ in 0..secret_key.params.k {
            let error_poly = secret_key.params.sample_error_1(rng)?;
            error_polys.push(error_poly);
        }

        // Compute b_i = s_i * A + e_i
        let mut key_polynomials = Vec::with_capacity(secret_key.params.k);
        for (sk_a_poly, error_poly) in sk_a_result.into_iter().zip(error_polys.into_iter()) {
            let result = &sk_a_poly + &error_poly;
            key_polynomials.push(result);
        }

        Ok(Self {
            key_polynomials,
            params: secret_key.params.clone(),
        })
    }

    /// Get the dimension of the public key (should equal k)
    pub fn dimension(&self) -> usize {
        self.key_polynomials.len()
    }

    /// Get a reference to the polynomial at position i
    pub fn get_polynomial(&self, i: usize) -> Option<&Poly> {
        self.key_polynomials.get(i)
    }

    /// Get all polynomials as a slice
    pub fn polynomials(&self) -> &[Poly] {
        &self.key_polynomials
    }

    /// Validate that the public key has the correct structure
    ///
    /// Ensures the public key has the expected number of polynomials
    /// and that all polynomials use the correct fhe.rs context.
    pub fn validate(&self) -> Result<()> {
        if self.key_polynomials.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Public key dimension {} doesn't match parameter k={}",
                self.key_polynomials.len(),
                self.params.k
            )));
        }

        // Verify all polynomials use the correct context
        for (i, poly) in self.key_polynomials.iter().enumerate() {
            if !Arc::ptr_eq(&poly.ctx, &self.params.context) {
                return Err(PvwError::InvalidParameters(format!(
                    "Public key polynomial {i} context mismatch"
                )));
            }
        }

        Ok(())
    }
}

impl GlobalPublicKey {
    /// Create a new global public key with the given CRS
    ///
    /// Initializes an empty n × k matrix to store public keys for all parties.
    /// The matrix is pre-allocated with zero polynomials using the correct
    /// fhe.rs context and representation.
    pub fn new(crs: PvwCrs) -> Self {
        // Initialize matrix with zero polynomials
        let zero_poly = Poly::zero(&crs.params.context, Representation::Ntt);
        let matrix = Array2::from_elem((crs.params.n, crs.params.k), zero_poly);

        Self {
            matrix,
            params: crs.params.clone(),
            crs,
            num_keys: 0,
        }
    }

    /// Add a public key for party at given index
    ///
    /// Validates the public key structure and stores it in the global matrix.
    /// Updates the count of stored keys if this is a new party.
    pub fn add_public_key(&mut self, index: usize, public_key: PublicKey) -> Result<()> {
        // Validate index bounds
        if index >= self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Party index {} exceeds maximum {}",
                index,
                self.params.n - 1
            )));
        }

        // Validate public key structure
        public_key.validate()?;
        if public_key.params.k != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Public key dimension {} doesn't match global key dimension {}",
                public_key.params.k, self.params.k
            )));
        }

        // Copy polynomials to the matrix
        for (j, poly) in public_key.key_polynomials.iter().enumerate() {
            if let Some(matrix_entry) = self.matrix.get_mut((index, j)) {
                *matrix_entry = poly.clone();
            } else {
                return Err(PvwError::InvalidParameters(format!(
                    "Matrix access failed at ({index}, {j})"
                )));
            }
        }

        // Update counter if this is a new key
        if index >= self.num_keys {
            self.num_keys = index + 1;
        }

        Ok(())
    }

    /// Generate and add a public key for the given party
    ///
    /// Convenience method that generates a public key for a party and
    /// immediately adds it to the global matrix.
    pub fn generate_and_add_party<R: RngCore + CryptoRng>(
        &mut self,
        party: &Party,
        rng: &mut R,
    ) -> Result<()> {
        let public_key = party.generate_public_key(&self.crs, rng)?;
        self.add_public_key(party.index, public_key)
    }

    /// Generate and add a public key for the given secret key at the specified index
    ///
    /// Alternative method for generating public keys when working directly
    /// with secret keys rather than Party objects.
    pub fn generate_and_add<R: RngCore + CryptoRng>(
        &mut self,
        index: usize,
        secret_key: &SecretKey,
        rng: &mut R,
    ) -> Result<()> {
        let public_key = PublicKey::generate(secret_key, &self.crs, rng)?;
        self.add_public_key(index, public_key)
    }

    /// Get the public key for party at given index
    ///
    /// Reconstructs a PublicKey object from the stored polynomials.
    /// Returns None if the party index is invalid or no key is stored.
    pub fn get_public_key(&self, index: usize) -> Option<PublicKey> {
        if index >= self.num_keys {
            return None;
        }

        let mut key_polynomials = Vec::with_capacity(self.params.k);
        for j in 0..self.params.k {
            if let Some(poly) = self.matrix.get((index, j)) {
                key_polynomials.push(poly.clone());
            } else {
                return None;
            }
        }

        Some(PublicKey {
            key_polynomials,
            params: self.params.clone(),
        })
    }

    /// Get a reference to the polynomial at position (i, j) in the global matrix
    ///
    /// Direct access to matrix elements without reconstructing PublicKey objects.
    /// Useful for encryption operations that need specific polynomials.
    pub fn get_polynomial(&self, i: usize, j: usize) -> Option<&Poly> {
        self.matrix.get((i, j))
    }

    /// Get the dimensions of the global public key matrix
    pub fn dimensions(&self) -> (usize, usize) {
        (self.params.n, self.params.k)
    }

    /// Get the number of public keys currently stored
    pub fn num_public_keys(&self) -> usize {
        self.num_keys
    }

    /// Check if the global public key is full (all n parties have keys)
    pub fn is_full(&self) -> bool {
        self.num_keys >= self.params.n
    }

    /// Get a reference to the CRS
    pub fn crs(&self) -> &PvwCrs {
        &self.crs
    }

    /// Validate the global public key structure
    ///
    /// Ensures the matrix has the correct dimensions according to the parameters.
    pub fn validate(&self) -> Result<()> {
        let (rows, cols) = self.matrix.dim();
        if rows != self.params.n || cols != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Global public key matrix dimensions {}×{} don't match parameters n={}, k={}",
                rows, cols, self.params.n, self.params.k
            )));
        }
        Ok(())
    }

    /// Generate keys for all provided parties
    ///
    /// Batch operation to generate public keys for multiple parties at once.
    /// Useful for setup phases where all parties are known in advance.
    pub fn generate_all_party_keys(&mut self, parties: &[Party]) -> Result<()> {
        if parties.len() > self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Too many parties: {} > {}",
                parties.len(),
                self.params.n
            )));
        }

        // Generate all public keys in parallel
        let public_keys: Result<Vec<(usize, PublicKey)>> = parties
            .par_iter()
            .map(|party| {
                let mut local_rng = rand::thread_rng();
                let public_key = party.generate_public_key(&self.crs, &mut local_rng)?;
                Ok((party.index, public_key))
            })
            .collect();

        // Add all public keys to the global key
        for (index, public_key) in public_keys? {
            self.add_public_key(index, public_key)?;
        }

        Ok(())
    }

    /// Generate keys for all parties using provided secret keys
    ///
    /// Alternative batch operation when working with secret keys directly.
    /// Keys are assigned to party indices in order (0, 1, 2, ...).
    pub fn generate_all_keys(&mut self, secret_keys: &[SecretKey]) -> Result<()> {
        if secret_keys.len() > self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Too many secret keys: {} > {}",
                secret_keys.len(),
                self.params.n
            )));
        }

        // Generate all public keys in parallel
        let public_keys: Result<Vec<(usize, PublicKey)>> = secret_keys
            .par_iter()
            .enumerate()
            .map(|(index, secret_key)| {
                let mut local_rng = rand::thread_rng();
                let public_key = PublicKey::generate(secret_key, &self.crs, &mut local_rng)?;
                Ok((index, public_key))
            })
            .collect();

        // Add all public keys to the global key
        for (index, public_key) in public_keys? {
            self.add_public_key(index, public_key)?;
        }

        Ok(())
    }

    /// Get public key polynomials for a specific party (for encryption)
    ///
    /// Returns a cloned vector of polynomials for the specified party.
    /// This is used during encryption to access the recipient's public key.
    pub fn get_party_polynomials(&self, party_index: usize) -> Result<Vec<Poly>> {
        if party_index >= self.num_keys {
            return Err(PvwError::InvalidParameters(format!(
                "Party index {party_index} not found"
            )));
        }

        let mut polys = Vec::with_capacity(self.params.k);
        for j in 0..self.params.k {
            if let Some(poly) = self.get_polynomial(party_index, j) {
                polys.push(poly.clone());
            } else {
                return Err(PvwError::InvalidParameters(
                    "Matrix access failed".to_string(),
                ));
            }
        }

        Ok(polys)
    }
}
