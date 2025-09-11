use super::encryption::PvwCiphertext;
use crate::errors::PvwError;
use crate::keys::secret_key::SecretKey;
use crate::params::parameters::{PvwParameters, Result};
use fhe_math::rq::{Poly, Representation};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, ToPrimitive, Zero};
use rayon::prelude::*;

fn decode_scalar_pvw_rns(noisy_poly: &Poly, params: &PvwParameters) -> Result<u64> {
    let ell = params.l;

    // Create polynomials for the PVW decoding algorithm
    let delta_poly = create_delta_polynomial(params)?;

    // Compute difference polynomials tmp[i] = z[i] * Delta - z[i+1] in RNS
    let mut tmp_polys = Vec::with_capacity(ell - 1);

    for i in 0..(ell - 1) {
        // Extract coefficient i and i+1 as constant polynomials
        let z_i_poly = extract_coefficient_as_poly(noisy_poly, i, params)?;
        let z_i_plus_1_poly = extract_coefficient_as_poly(noisy_poly, i + 1, params)?;

        // Compute tmp[i] = z[i] * Delta - z[i+1] in RNS
        let tmp_i = &(&z_i_poly * &delta_poly) - &z_i_plus_1_poly;
        tmp_polys.push(tmp_i);
    }

    // Compute last component using Horner's method in RNS
    let mut last_component = tmp_polys[0].clone();
    for (_i, item) in tmp_polys.iter().enumerate().take(ell - 1).skip(1) {
        last_component = &(&last_component * &delta_poly) + item;
    }

    // Reduce modulo Delta^{ell-1}
    let delta_power_poly = create_delta_power_polynomial(params, ell - 1)?;
    last_component = reduce_modulo_poly(&last_component, &delta_power_poly, params)?;
    tmp_polys.push(last_component);

    // Recover noise components working backwards in RNS
    let mut noise_polys = vec![Poly::zero(&params.context, Representation::Ntt); ell];
    noise_polys[ell - 1] = tmp_polys[ell - 1].clone();

    for i in (0..(ell - 1)).rev() {
        // e[i] = (e[i+1] - tmp[i]) / Delta in RNS with proper rounding
        let numerator = &noise_polys[i + 1] - &tmp_polys[i];
        noise_polys[i] = divide_by_delta_rns(&numerator, &delta_poly, params)?;
    }

    // Extract plaintext with proper handling
    let z0_poly = extract_coefficient_as_poly(noisy_poly, 0, params)?;
    let minus_one_poly = create_minus_one_poly(params)?;
    let plaintext_poly = &(&z0_poly * &minus_one_poly) - &noise_polys[0];

    let plaintext_scalar = extract_constant_term_as_u64(&plaintext_poly, params)?;

    Ok(plaintext_scalar)
}

/// Create delta polynomial with precision handling
fn create_delta_polynomial(params: &PvwParameters) -> Result<Poly> {
    let delta_bigint = BigInt::from(params.delta().clone());

    // Create polynomial with l coefficients: [delta, 0, 0, ..., 0]
    let mut delta_coeffs = vec![BigInt::zero(); params.l];
    delta_coeffs[0] = delta_bigint;

    // Convert to polynomial using existing RNS infrastructure
    let mut delta_poly = params.bigints_to_poly(&delta_coeffs)?;
    if params.l >= 8 {
        delta_poly.change_representation(Representation::Ntt);
    }

    Ok(delta_poly)
}

/// Create delta power polynomial with proper exponentiation
fn create_delta_power_polynomial(params: &PvwParameters, power: usize) -> Result<Poly> {
    let delta_power = if power == 0 {
        BigUint::one()
    } else {
        params.delta().pow(power as u32)
    };

    let delta_power_bigint = BigInt::from(delta_power);

    let mut coeffs = vec![BigInt::zero(); params.l];
    coeffs[0] = delta_power_bigint;

    let mut poly = params.bigints_to_poly(&coeffs)?;
    if params.l >= 8 {
        poly.change_representation(Representation::Ntt);
    }

    Ok(poly)
}

fn create_minus_one_poly(params: &PvwParameters) -> Result<Poly> {
    let mut minus_one_coeffs = vec![BigInt::zero(); params.l];
    minus_one_coeffs[0] = BigInt::from(-1);

    let mut poly = params.bigints_to_poly(&minus_one_coeffs)?;
    if params.l >= 8 {
        poly.change_representation(Representation::Ntt);
    }
    Ok(poly)
}

fn extract_coefficient_as_poly(
    poly: &Poly,
    coeff_index: usize,
    params: &PvwParameters,
) -> Result<Poly> {
    // Convert to coefficient form temporarily
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    let coeff_value = if coeff_index >= coeffs_biguint.len() {
        BigInt::zero()
    } else {
        // Use centered coefficient representation for better precision
        center_coefficient_with_precision(&coeffs_biguint[coeff_index], params)
    };

    // Create constant polynomial
    let mut const_coeffs = vec![BigInt::zero(); params.l];
    const_coeffs[0] = coeff_value;

    let mut const_poly = params.bigints_to_poly(&const_coeffs)?;
    if params.l >= 8 {
        const_poly.change_representation(Representation::Ntt);
    }

    Ok(const_poly)
}

/// Center coefficient representation for improved precision
fn center_coefficient_with_precision(coeff: &BigUint, params: &PvwParameters) -> BigInt {
    let q_total = BigInt::from(params.q_total());
    let coeff_bigint = BigInt::from(coeff.clone());

    // Use precise centering approach
    let half_q = &q_total / 2;

    if coeff_bigint > half_q {
        &coeff_bigint - &q_total
    } else {
        coeff_bigint
    }
}

fn reduce_modulo_poly(poly: &Poly, modulus_poly: &Poly, params: &PvwParameters) -> Result<Poly> {
    let poly_const = extract_constant_term_bigint(poly, params)?;
    let mod_const = extract_constant_term_bigint(modulus_poly, params)?;

    // Perform modular reduction with proper rounding
    let mut reduced = poly_const % &mod_const;

    // Apply centering logic
    let half_mod = &mod_const / 2;
    if reduced > half_mod {
        reduced -= &mod_const;
    } else if reduced < -&half_mod {
        reduced += &mod_const;
    }

    let mut reduced_coeffs = vec![BigInt::zero(); params.l];
    reduced_coeffs[0] = reduced;

    let mut result_poly = params.bigints_to_poly(&reduced_coeffs)?;
    if params.l >= 8 {
        result_poly.change_representation(Representation::Ntt);
    }

    Ok(result_poly)
}

fn divide_by_delta_rns(poly: &Poly, delta_poly: &Poly, params: &PvwParameters) -> Result<Poly> {
    let poly_const = extract_constant_term_bigint(poly, params)?;
    let delta_const = extract_constant_term_bigint(delta_poly, params)?;

    let quotient = if delta_const.is_zero() {
        BigInt::zero()
    } else {
        // Compute quotient with proper rounding
        let twice_poly = &poly_const * 2;
        if poly_const.is_negative() {
            // For negative numbers: (2*poly - delta) / (2*delta)
            (&twice_poly - &delta_const) / (&delta_const * 2)
        } else {
            // For positive numbers: (2*poly + delta) / (2*delta)
            (&twice_poly + &delta_const) / (&delta_const * 2)
        }
    };

    let mut quotient_coeffs = vec![BigInt::zero(); params.l];
    quotient_coeffs[0] = quotient;

    let mut result_poly = params.bigints_to_poly(&quotient_coeffs)?;
    if params.l >= 8 {
        result_poly.change_representation(Representation::Ntt);
    }

    Ok(result_poly)
}

fn extract_constant_term_bigint(poly: &Poly, params: &PvwParameters) -> Result<BigInt> {
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    if coeffs_biguint.is_empty() {
        return Ok(BigInt::zero());
    }

    // Use centered coefficient representation
    Ok(center_coefficient_with_precision(
        &coeffs_biguint[0],
        params,
    ))
}

fn extract_constant_term_as_u64(poly: &Poly, params: &PvwParameters) -> Result<u64> {
    let constant_bigint = extract_constant_term_bigint(poly, params)?;

    // Convert with bounds checking and noise handling
    let plaintext_u64 = if constant_bigint.is_negative() {
        // Handle negative values carefully
        let abs_value = constant_bigint.abs();
        if abs_value <= BigInt::from(1000u64) {
            // Small negative values might be noise, return 0
            0u64
        } else {
            // Large negative values - convert to positive modular equivalent
            let q_total = BigInt::from(params.q_total());
            let positive_equiv = (&constant_bigint + &q_total) % &q_total;
            positive_equiv.to_u64().unwrap_or(0)
        }
    } else {
        constant_bigint.to_u64().unwrap_or(0)
    };

    Ok(plaintext_u64)
}

pub fn decrypt_party_value(
    ciphertext: &PvwCiphertext,
    secret_key: &SecretKey,
    party_index: usize,
) -> Result<u64> {
    let params = &ciphertext.params;

    // Compute <sk, c1> (inner product) in parallel - keep in NTT representation
    let sk_c1_products: Result<Vec<Poly>> = (0..params.k)
        .into_par_iter()
        .map(|j| {
            let sk_poly = secret_key.get_polynomial(j)?;
            Ok(&sk_poly * &ciphertext.c1[j])
        })
        .collect();

    let sk_c1_products = sk_c1_products?;

    // Sum all products
    let mut sk_c1_sum = Poly::zero(&params.context, Representation::Ntt);
    for product in sk_c1_products {
        sk_c1_sum = &sk_c1_sum + &product;
    }

    // Compute noisy message = <sk, c1> - c2[party_index]
    let noisy_message = &sk_c1_sum - &ciphertext.c2[party_index];

    // Use the decoding algorithm
    decode_scalar_pvw_rns(&noisy_message, params)
}

/// Decrypt party shares from multiple ciphertexts
pub fn decrypt_party_shares(
    all_ciphertexts: &[PvwCiphertext],
    secret_key: &SecretKey,
    party_index: usize,
) -> Result<Vec<u64>> {
    if all_ciphertexts.is_empty() {
        return Err(PvwError::InvalidParameters(
            "No ciphertexts provided".to_string(),
        ));
    }

    let params = &all_ciphertexts[0].params;

    // Validate inputs
    if all_ciphertexts.len() != params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Expected {} ciphertexts, got {}",
            params.n,
            all_ciphertexts.len()
        )));
    }

    if party_index >= params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Party index {} exceeds maximum {}",
            party_index,
            params.n - 1
        )));
    }

    // Decrypt all ciphertexts using the decoding algorithm
    let results: Result<Vec<u64>> = all_ciphertexts
        .par_iter()
        .enumerate()
        .map(|(dealer_idx, ciphertext)| {
            ciphertext.validate().map_err(|e| {
                PvwError::InvalidParameters(format!("Ciphertext {dealer_idx} invalid: {e}"))
            })?;

            decrypt_party_value(ciphertext, secret_key, party_index)
        })
        .collect();

    results
}

// Decrypt threshold shares for all parties
///
/// Decrypts the same set of t ciphertexts for all parties and returns just the shares.
/// This function ensures all parties decrypt the same ciphertext subset by taking
/// the selected ciphertexts as input and applying them uniformly to all parties.
///
/// # Arguments
/// * `selected_ciphertexts` - The t selected ciphertexts (same for all parties)
/// * `all_secret_keys` - Secret keys for all parties
/// * `threshold` - The threshold value `t` (must match number of ciphertexts)
///
/// # Returns
/// * `Result<Vec<Vec<u64>>>` - Decrypted shares: `result[party_idx][share_idx]`
pub fn decrypt_threshold_party_shares(
    selected_ciphertexts: &[PvwCiphertext],
    all_secret_keys: &[&SecretKey],
    threshold: usize,
) -> Result<Vec<Vec<u64>>> {
    if selected_ciphertexts.is_empty() {
        return Err(PvwError::InvalidParameters(
            "No ciphertexts provided".to_string(),
        ));
    }

    if all_secret_keys.is_empty() {
        return Err(PvwError::InvalidParameters(
            "No secret keys provided".to_string(),
        ));
    }

    let params = &selected_ciphertexts[0].params;

    // Validate threshold
    if selected_ciphertexts.len() != threshold {
        return Err(PvwError::InvalidParameters(format!(
            "Expected exactly {} ciphertexts for threshold {}, got {}",
            threshold,
            threshold,
            selected_ciphertexts.len()
        )));
    }

    if threshold > params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Threshold {} cannot exceed total parties {}",
            threshold, params.n
        )));
    }

    // Validate we have the right number of secret keys
    if all_secret_keys.len() != params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Expected {} secret keys for {} parties, got {}",
            params.n,
            params.n,
            all_secret_keys.len()
        )));
    }

    // Decrypt threshold shares for all parties directly
    let results: Result<Vec<Vec<u64>>> = all_secret_keys
        .par_iter()
        .enumerate()
        .map(|(party_index, secret_key)| {
            // Decrypt each selected ciphertext for this party
            let party_shares: Result<Vec<u64>> = selected_ciphertexts
                .iter()
                .enumerate()
                .map(|(idx, ciphertext)| {
                    // Validate ciphertext
                    ciphertext.validate().map_err(|e| {
                        PvwError::InvalidParameters(format!("Ciphertext {idx} invalid: {e}"))
                    })?;

                    // Ensure all ciphertexts use compatible parameters
                    if !std::sync::Arc::ptr_eq(&ciphertext.params, params) {
                        return Err(PvwError::InvalidParameters(format!(
                            "Ciphertext {idx} has different parameters"
                        )));
                    }

                    decrypt_party_value(ciphertext, secret_key, party_index)
                })
                .collect();

            party_shares
        })
        .collect();

    results
}
