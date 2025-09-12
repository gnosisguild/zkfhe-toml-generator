/// Configuration for PVW parameter search
#[derive(Debug, Clone)]
pub struct PvwSearchConfig {
    /// Number of parties n (e.g. ciphernodes)
    pub n: u128,
    /// Number of fresh ciphertext additions z (number of votes) - equal to k_plain_eff.
    pub ell_start: usize,
    /// Maximum ell (doubling schedule stops here)
    pub ell_max: usize,
    /// k start (doubling schedule), k here is the LWE dimension
    pub k_start: usize,
    /// k max (inclusive). Default = 32768
    pub k_max: usize,
    /// α in Δ = floor(q_PVW^(α/ℓ)). Common choices: 1 or 2
    pub delta_power_num: u32,
    /// Override q_BFV primes (comma-separated). Accepts hex (0x...) or decimal.
    pub qbfv_primes: Option<String>,
    /// Limit how many extra PVW primes to enumerate (growth steps) beyond the initial q_BFV.
    pub max_pvw_growth: Option<usize>,
    /// Verbose output showing detailed parameter search process
    pub verbose: bool,
}

pub struct PvwParametersBuilder {
    degree: usize,
    ell_start: usize,
    ell_max: usize,
    k_start: usize,
    k_max: usize,
    delta_power_num: u32,
    qbfv_primes: Option<String>,
    max_pvw_growth: Option<usize>,
}

impl PvwParametersBuilder {
    /// Creates a new instance of the builder
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            degree: Default::default(),
            ell_start: Default::default(),
            ell_max: Default::default(),
            k_start: Default::default(),
            k_max: Default::default(),
            delta_power_num: Default::default(),
            qbfv_primes: Default::default(),
            max_pvw_growth: Default::default(),
        }
    }

    /// Sets the polynomial degree. Returns an error if the degree is not
    /// a power of two larger or equal to 8.
    pub fn set_degree(&mut self, degree: usize) -> &mut Self {
        self.degree = degree;
        self
    }

    /// Sets the plaintext modulus. Returns an error if the plaintext is not
    /// between 2 and 2^62 - 1.
    pub fn set_ell_start(&mut self, ell_start: usize) -> &mut Self {
        self.ell_start = ell_start;
        self
    }

    /// Sets the sizes of the ciphertext moduli.
    /// Only one of `set_moduli_sizes` and `set_moduli`
    /// can be specified.
    pub fn set_ell_max(&mut self, ell_max: usize) -> &mut Self {
        self.ell_max = ell_max;
        self
    }

    /// Sets the ciphertext moduli to use.
    /// Only one of `set_moduli_sizes` and `set_moduli`
    /// can be specified.
    pub fn set_k_start(&mut self, k_start: usize) -> &mut Self {
        self.k_start = k_start;
        self
    }

    /// Sets the error variance. Returns an error if the variance is not between
    /// one and sixteen.
    pub fn set_k_max(&mut self, k_max: usize) -> &mut Self {
        self.k_max = k_max;
        self
    }

    /// Sets the error variance. Returns an error if the variance is not between
    /// one and sixteen.
    pub fn set_delta_power_num(&mut self, delta_power_num: u32) -> &mut Self {
        self.delta_power_num = delta_power_num;
        self
    }

    /// Sets the error variance. Returns an error if the variance is not between
    /// one and sixteen.
    pub fn set_qbfv_primes(&mut self, qbfv_primes: Option<String>) -> &mut Self {
        self.qbfv_primes = qbfv_primes;
        self
    }

    /// Sets the error variance. Returns an error if the variance is not between
    /// one and sixteen.
    pub fn set_max_pvw_growth(&mut self, max_pvw_growth: Option<usize>) -> &mut Self {
        self.max_pvw_growth = max_pvw_growth;
        self
    }
}
