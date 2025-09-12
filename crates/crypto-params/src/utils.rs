use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::cmp::Ordering;

pub fn parse_hex_big(s: &str) -> BigUint {
    let t = s.trim_start_matches("0x");
    BigUint::parse_bytes(t.as_bytes(), 16).expect("invalid hex prime")
}

pub fn product(xs: &[BigUint]) -> BigUint {
    let mut acc = BigUint::one();
    for x in xs {
        acc *= x;
    }
    acc
}

pub fn log2_big(x: &BigUint) -> f64 {
    if x.is_zero() {
        return f64::NEG_INFINITY;
    }
    let bytes = x.to_bytes_be();
    let leading = bytes[0];
    let lead_bits = 8 - leading.leading_zeros() as usize;
    let bits = (bytes.len() - 1) * 8 + lead_bits;

    // refine with up to 8 bytes
    let take = bytes.len().min(8);
    let mut top: u64 = 0;
    for &byte in bytes.iter().take(take) {
        top = (top << 8) | byte as u64;
    }
    let frac = (top as f64).log2();
    let adjust = (take * 8) as f64;
    (bits as f64 - adjust) + frac
}

pub fn approx_bits_from_log2(log2x: f64) -> u64 {
    if log2x <= 0.0 {
        1
    } else {
        log2x.floor() as u64 + 1
    }
}

pub fn fmt_big_summary(x: &BigUint) -> String {
    let bits = approx_bits_from_log2(log2_big(x));
    format!("≈ 2^{bits} ({bits} bits)")
}

pub fn big_shift_pow2(exp: u32) -> BigUint {
    BigUint::one() << exp
}

pub fn ceil_to_u128(x: f64) -> u128 {
    x.ceil() as u128
}

pub fn big_pow(base: &BigUint, exp: u64) -> BigUint {
    let mut res = BigUint::one();
    for _ in 0..exp {
        res *= base;
    }
    res
}

pub fn nth_root_floor(a: &BigUint, n: u32) -> BigUint {
    if n <= 1 {
        return a.clone();
    }
    if a.is_zero() {
        return BigUint::zero();
    }
    let bits: usize = a.bits() as usize;
    let n_usize: usize = n as usize;
    let ub = BigUint::one() << bits.div_ceil(n_usize);
    let mut lo = BigUint::one();
    let mut hi = ub;
    while lo < hi {
        let mid = (&lo + &hi + BigUint::one()) >> 1;
        let mid_pow = big_pow(&mid, n as u64);
        match mid_pow.cmp(a) {
            Ordering::Less | Ordering::Equal => lo = mid,
            Ordering::Greater => hi = mid - BigUint::one(),
        }
    }
    lo
}
