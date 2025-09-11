//! Bounds calculation for PVW public key circuit.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! and validation that input vectors stay within these bounds.

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use shared::circuit::{CircuitBounds, CircuitDimensions, CircuitVectors};

use shared::errors::ZkfheResult;

/// Bounds for PVW public key circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct PvwPkBounds {
    // Cryptographic parameters
    pub qis: Vec<u64>,
    
    // Circuit parameters
    pub n: u32,           // Ring dimension (polynomial degree)
    pub k: u32,           // Security dimension
    pub n_parties: u32,   // Number of parties
    
    // Bounds for different polynomial types
    pub e_bound: u64,     // Bound for error polynomials (E)
    pub sk_bound: u64,    // Bound for secret key polynomials (s_i)
    
    // Bounds for quotients (per modulus)
    pub r1_low_bounds: Vec<i64>,   // Lower bounds for r1 polynomials
    pub r1_up_bounds: Vec<u64>,    // Upper bounds for r1 polynomials
    pub r2_bounds: Vec<u64>,       // Bounds for r2 polynomials
    
    // Bounds for CRS and public keys (per modulus)
    pub a_bounds: Vec<u64>,        // Bounds for CRS matrices a_l
    pub b_bounds: Vec<u64>,        // Bounds for public key vectors b_{l,i}
}

impl PvwPkBounds {
    /// Compute bounds from PVW parameters and circuit dimensions
    pub fn compute(
        qis: Vec<u64>,
        n: u32,
        k: u32,
        n_parties: u32,
        e_bound: u64,
        sk_bound: u64,
    ) -> ZkfheResult<Self> {                
        // Calculate bounds for each modulus
        let mut r1_low_bounds: Vec<i64> = Vec::new();
        let mut r1_up_bounds: Vec<u64> = Vec::new();
        let mut r2_bounds: Vec<u64> = Vec::new();
        let mut a_bounds: Vec<u64> = Vec::new();
        let mut b_bounds: Vec<u64> = Vec::new();
        
        for qi in &qis {
            let qi_bigint = BigInt::from(*qi);
            
            // a_l → [-(q_l-1)/2, (q_l-1)/2]
            let a_bound = (qi_bigint.clone() - BigInt::from(1)) / BigInt::from(2);
            a_bounds.push(a_bound.to_u64().unwrap());
            
            // b_{l,i} → [-(q_l-1)/2, (q_l-1)/2]
            let b_bound = (qi_bigint.clone() - BigInt::from(1)) / BigInt::from(2);
            b_bounds.push(b_bound.to_u64().unwrap());
            
            // r2_{l,i} → [-(q_l-1)/2, (q_l-1)/2]
            let r2_bound = (qi_bigint.clone() - BigInt::from(1)) / BigInt::from(2);
            r2_bounds.push(r2_bound.to_u64().unwrap());
            
            // r1_{l,i} → [-(N*B_s + 2)*(q_l-1)/2 + B)/q_l, ((N*B_s + 2)*(q_l-1)/2 + B)/q_l]
            let n_bigint = BigInt::from(n);
            let b_s_bigint = BigInt::from(sk_bound);
            let e_bound_bigint = BigInt::from(e_bound);
            
            let numerator_low = -(&n_bigint * &b_s_bigint + BigInt::from(2)) * &a_bound - &e_bound_bigint;
            let numerator_up = (&n_bigint * &b_s_bigint + BigInt::from(2)) * &a_bound + &e_bound_bigint;
            
            let r1_low = numerator_low / &qi_bigint;
            let r1_up = numerator_up / &qi_bigint;
            
            r1_low_bounds.push(r1_low.to_i64().unwrap());
            r1_up_bounds.push(r1_up.to_u64().unwrap());
        }
        
        Ok(PvwPkBounds {
            qis,
            n,
            k,
            n_parties,
            e_bound,
            sk_bound,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
            a_bounds,
            b_bounds,
        })
    }
}

impl CircuitDimensions for PvwPkBounds {
    fn num_moduli(&self) -> usize {
        self.qis.len()
    }

    fn degree(&self) -> usize {
        self.n as usize
    }

    fn level(&self) -> usize {
        0 // Default level, can be overridden if needed
    }
}

impl CircuitBounds for PvwPkBounds {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "qis": self.qis,
            "n": self.n,
            "k": self.k,
            "n_parties": self.n_parties,
            "e_bound": self.e_bound,
            "sk_bound": self.sk_bound,
            "r1_low_bounds": self.r1_low_bounds,
            "r1_up_bounds": self.r1_up_bounds,
            "r2_bounds": self.r2_bounds,
            "a_bounds": self.a_bounds,
            "b_bounds": self.b_bounds,
        })
    }

    fn validate_vectors<V: CircuitVectors>(&self, vectors: &V) -> ZkfheResult<()> {
        // Basic validation - ensure dimensions match
        if vectors.num_moduli() != self.num_moduli() {
            return Err(shared::errors::ValidationError::General {
                message: "Vector and bounds have different number of moduli".to_string(),
            }
            .into());
        }

        if vectors.degree() != self.degree() {
            return Err(shared::errors::ValidationError::General {
                message: "Vector and bounds have different degrees".to_string(),
            }
            .into());
        }

        // Additional validation can be added here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounds_computation() {
        let qis = vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];
        let bounds = PvwPkBounds::compute(qis, 8, 32, 7, 5000, 1).unwrap();

        assert_eq!(bounds.qis.len(), 3);
        assert_eq!(bounds.n, 8);
        assert_eq!(bounds.k, 32);
        assert_eq!(bounds.n_parties, 7);
        assert_eq!(bounds.e_bound, 5000);
        assert_eq!(bounds.sk_bound, 1);
        assert_eq!(bounds.r1_low_bounds.len(), 3);
        assert_eq!(bounds.r1_up_bounds.len(), 3);
        assert_eq!(bounds.r2_bounds.len(), 3);
        assert_eq!(bounds.a_bounds.len(), 3);
        assert_eq!(bounds.b_bounds.len(), 3);
    }
}
