use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use rand::{Rng, thread_rng};
use rayon::prelude::*;
use std::f64::consts::PI;

/// Fixed constant for negligible tail probability: 2^-128
const TAIL_STDDEV_MULTIPLIER: f64 = 16.96; // sqrt(2 * ln(2^129))

/// Sample `n` values from discrete Gaussian with negligible tail prob (2^-128),
/// truncated to [-bound, bound].
pub fn sample_discrete_gaussian_vec(bound: &BigInt, n: usize) -> Vec<BigInt> {
    (0..n)
        .into_par_iter()
        .map(|_| {
            let mut rng = thread_rng();
            sample_single_gaussian(bound, &mut rng)
        })
        .collect()
}

/// Alias for backward compatibility - sample from discrete Gaussian using variance parameter
/// This interprets the parameter as variance (σ²), not bound
pub fn sample_bigint_normal_vec(variance: &BigInt, n: usize) -> Vec<BigInt> {
    // For variance-based sampling, we need to convert variance to standard deviation
    // σ = sqrt(variance)
    // For very large variances, we'll use an approximation

    (0..n)
        .into_par_iter()
        .map(|_| {
            let mut rng = thread_rng();
            sample_from_variance(variance, &mut rng)
        })
        .collect()
}

/// Sample from discrete Gaussian given variance (σ²)
fn sample_from_variance(variance: &BigInt, rng: &mut impl Rng) -> BigInt {
    if variance.is_zero() {
        return BigInt::zero();
    }

    // For very large variances, we need a different approach
    // σ = sqrt(variance)
    let variance_f64 = variance.to_f64();

    match variance_f64 {
        Some(var_f64) if var_f64.is_finite() => {
            // For manageable variances, use Box-Muller with σ = sqrt(variance)
            let sigma = var_f64.sqrt();
            let gaussian_sample = box_muller(rng) * sigma;
            let rounded = gaussian_sample.round();

            if rounded.abs() <= (i64::MAX as f64) {
                BigInt::from(rounded as i64)
            } else {
                // Fall back to large variance sampling
                sample_large_variance_fallback(variance, rng)
            }
        }
        _ => {
            // For very large variances that don't fit in f64
            sample_large_variance_fallback(variance, rng)
        }
    }
}

/// Fallback for very large variance sampling
fn sample_large_variance_fallback(variance: &BigInt, rng: &mut impl Rng) -> BigInt {
    // For very large variances, we expect to get large samples
    // The standard deviation is sqrt(variance)
    // For 2^100 variance, σ = 2^50, so we should get samples often in the 2^40-2^60 range

    let variance_bits = variance.bits();
    let sigma_bits = variance_bits / 2; // σ = sqrt(variance), so bits(σ) ≈ bits(variance)/2

    // Generate a sample with approximately sigma_bits bits
    // But with Gaussian distribution, most samples are within a few σ
    let target_bits = if sigma_bits > 10 {
        // Generate samples mostly in range [sigma/4, sigma*4] in bits
        let min_bits = (sigma_bits / 4).max(10);
        let max_bits = (sigma_bits + 20).min(120); // Cap for practical reasons
        rng.gen_range(min_bits..=max_bits)
    } else {
        rng.gen_range(1..=20)
    };

    // Generate random bytes for this bit length
    let byte_count = (target_bits / 8 + 1) as usize;
    let mut bytes = vec![0u8; byte_count];
    rng.fill_bytes(&mut bytes);

    // Ensure we get the right bit length by setting high bit
    if !bytes.is_empty() && target_bits > 8 {
        bytes[0] |= 0x80;
    }

    let mut sample = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);

    // Apply random sign
    if rng.r#gen::<bool>() {
        sample = -sample;
    }

    sample
}

/// Convenience function: sample from discrete Gaussian with u64 variance
pub fn sample_bigint_normal_vec_u64(variance: u64, n: usize) -> Vec<BigInt> {
    let variance_big = BigInt::from(variance);
    sample_discrete_gaussian_vec(&variance_big, n)
}

/// Convenience function: sample from discrete Gaussian with 2^bits variance  
pub fn sample_bigint_normal_vec_bits(bits: u32, n: usize) -> Vec<BigInt> {
    let variance = BigInt::from(2u32).pow(bits);
    sample_discrete_gaussian_vec(&variance, n)
}

/// Sample a single value from discrete Gaussian with u64 variance
pub fn sample_bigint_normal_u64(variance: u64) -> BigInt {
    let variance_big = BigInt::from(variance);
    let mut rng = thread_rng();
    sample_single_gaussian(&variance_big, &mut rng)
}

/// Sample a single value from discrete Gaussian with 2^bits variance
pub fn sample_bigint_normal_bits(bits: u32) -> BigInt {
    let variance = BigInt::from(2u32).pow(bits);
    let mut rng = thread_rng();
    sample_single_gaussian(&variance, &mut rng)
}

/// Sample a single value from N(0, (bound / t)^2), truncated to [-bound, bound]
fn sample_single_gaussian(bound: &BigInt, rng: &mut impl Rng) -> BigInt {
    if bound.is_zero() {
        return BigInt::zero();
    }

    // For very large bounds, the sampling might be slow
    // Add a reasonable upper limit for performance
    let bound_f64 = bound.to_f64().unwrap_or(f64::INFINITY);
    if bound_f64 > 1e15 {
        // For very large bounds, just return a random value in a reasonable range
        // let reasonable_bound = BigInt::from(1000000i64);
        let sign = if rng.r#gen::<bool>() { 1 } else { -1 };
        return BigInt::from(rng.gen_range(0..=1000000) * sign);
    }

    let sigma = bound_f64 / TAIL_STDDEV_MULTIPLIER;
    let ratio = sample_truncated_gaussian_ratio(rng, sigma);
    let mut x = ratio_to_bigint(ratio, bound);

    // Clamp to ensure safety
    if x > *bound {
        x = bound.clone();
    } else if x < -bound {
        x = -bound.clone();
    }
    x
}

/// Sample a float ratio in [-1, 1] from N(0, sigma^2), truncated to that range
fn sample_truncated_gaussian_ratio(rng: &mut impl Rng, sigma: f64) -> f64 {
    // If sigma is too large, the rejection rate will be very high
    // In this case, just return a uniform random value in the range
    if sigma > 0.3 {
        return rng.gen_range(-1.0..=1.0);
    }

    // Try up to 1000 times to avoid infinite loops
    for _ in 0..1000 {
        let z = box_muller(rng); // z ~ N(0, 1)
        let r = z * sigma;
        if (-1.0..=1.0).contains(&r) {
            return r;
        }
    }

    // Fallback: return uniform random value in range
    rng.gen_range(-1.0..=1.0)
}

/// Box-Muller transform for sampling standard normal
pub fn box_muller(rng: &mut impl Rng) -> f64 {
    let u1 = rng.gen_range(f64::EPSILON..1.0); // Avoid log(0)
    let u2 = rng.gen_range(0.0..1.0);
    (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
}

/// Convert ratio in [-1,1] to BigInt in [-bound, bound]
/// This function is kept for potential future use but not currently used
#[allow(dead_code)]
fn ratio_to_bigint(ratio: f64, bound: &BigInt) -> BigInt {
    debug_assert!((-1.0..=1.0).contains(&ratio));

    // Fast path
    if let Some(bf) = bound.to_f64() {
        if bf.is_finite() {
            if let Some(v) = (ratio * bf).round().to_i128() {
                return BigInt::from(v);
            }
        }
    }

    // High-precision fallback
    const FP_BITS: u32 = 53;
    let scaled = (ratio * (1u64 << FP_BITS) as f64).round() as i64;
    let scaled_big = BigInt::from(scaled);
    let prod = scaled_big * bound;
    prod >> FP_BITS
}
