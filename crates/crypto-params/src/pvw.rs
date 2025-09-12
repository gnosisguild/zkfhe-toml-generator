/// Configuration for PVW (Peikert-Vaikuntanathan-Waters) parameter search
///
/// This structure contains all the parameters needed to search for optimal PVW lattice
/// parameters for zero-knowledge proofs. PVW parameters are typically constructed from
/// BFV computation results and define the search space for LWE-based cryptographic
/// parameters including redundancy factors, LWE dimensions, and modulus growth strategies.
#[derive(Debug, Clone)]
pub struct PvwSearchConfig {
    /// Number of parties (e.g., ciphernodes) in the protocol
    pub n: u128,
    /// Starting redundancy parameter ell (power of two, ≥ 2)
    /// The search uses a doubling schedule: ell_start, 2*ell_start, 4*ell_start, ...
    pub ell_start: usize,
    /// Maximum redundancy parameter ell (doubling schedule stops here)
    /// Should be a power of two and ≥ ell_start
    pub ell_max: usize,
    /// Starting LWE dimension k (doubling schedule)
    /// Higher values provide more security but require larger parameters
    pub k_start: usize,
    /// Maximum LWE dimension k (inclusive, typically 32768)
    /// The doubling schedule for k will stop at this value
    pub k_max: usize,
    /// Alpha parameter in Δ = floor(q_PVW^(α/ℓ))
    /// Common choices are 1 or 2, affecting the delta computation for noise analysis
    pub delta_power_num: u32,
    /// Override BFV primes (comma-separated hex or decimal)
    /// If provided, these primes override the computed q_BFV modulus
    /// Example: "0x00800000022a0001,0x00800000021a0001"
    pub qbfv_primes: Option<String>,
    /// Limit for extra PVW prime enumeration beyond q_BFV
    /// Controls how many growth steps to attempt when expanding the modulus
    pub max_pvw_growth: Option<usize>,
    /// Enable verbose output showing detailed parameter search process
    pub verbose: bool,
}

/// Builder for PVW (Peikert-Vaikuntanathan-Waters) parameters
///
/// This builder provides a fluent interface for constructing PVW parameter sets
/// used in zero-knowledge proofs for lattice-based cryptography. PVW parameters
/// are typically derived from BFV computations and specify the search space for
/// optimal lattice parameters.
pub struct PvwParametersBuilder {
    /// Polynomial degree (power of two, typically from BFV parameters)
    degree: usize,
    /// Starting redundancy parameter ell (power of two, ≥ 2)
    ell_start: usize,
    /// Maximum redundancy parameter ell (doubling schedule stops here)
    ell_max: usize,
    /// Starting LWE dimension k (doubling schedule)
    k_start: usize,
    /// Maximum LWE dimension k (inclusive, default 32768)
    k_max: usize,
    /// Alpha parameter in Δ = floor(q_PVW^(α/ℓ)), common choices: 1 or 2
    delta_power_num: u32,
    /// Override BFV primes (comma-separated hex or decimal)
    qbfv_primes: Option<String>,
    /// Limit for extra PVW prime enumeration beyond q_BFV
    max_pvw_growth: Option<usize>,
}

impl PvwParametersBuilder {
    /// Creates a new instance of the PVW parameters builder
    ///
    /// All parameters are initialized to default values and should be
    /// configured using the setter methods before building.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            degree: Default::default(),
            ell_start: 2,       // Default minimum redundancy parameter
            ell_max: 64,        // Default maximum redundancy parameter
            k_start: 1024,      // Default starting LWE dimension
            k_max: 32768,       // Default maximum LWE dimension
            delta_power_num: 1, // Default alpha parameter
            qbfv_primes: Default::default(),
            max_pvw_growth: Default::default(),
        }
    }

    /// Sets the polynomial degree
    ///
    /// The degree should match the BFV polynomial degree and be a power of two.
    /// This is typically derived from BFV parameter search results.
    pub fn set_degree(&mut self, degree: usize) -> &mut Self {
        self.degree = degree;
        self
    }

    /// Sets the starting redundancy parameter ell
    ///
    /// The redundancy parameter ell should be a power of two ≥ 2.
    /// The search will start from this value and double until ell_max.
    pub fn set_ell_start(&mut self, ell_start: usize) -> &mut Self {
        self.ell_start = ell_start;
        self
    }

    /// Sets the maximum redundancy parameter ell
    ///
    /// The doubling schedule for ell will stop at this value.
    /// Should be a power of two and ≥ ell_start.
    pub fn set_ell_max(&mut self, ell_max: usize) -> &mut Self {
        self.ell_max = ell_max;
        self
    }

    /// Sets the starting LWE dimension k
    ///
    /// The LWE dimension k determines the security level.
    /// The search will start from this value and double until k_max.
    pub fn set_k_start(&mut self, k_start: usize) -> &mut Self {
        self.k_start = k_start;
        self
    }

    /// Sets the maximum LWE dimension k (inclusive)
    ///
    /// The doubling schedule for k will stop at this value.
    /// Higher values provide more security but require larger parameters.
    pub fn set_k_max(&mut self, k_max: usize) -> &mut Self {
        self.k_max = k_max;
        self
    }

    /// Sets the alpha parameter for delta computation
    ///
    /// Alpha is used in the formula Δ = floor(q_PVW^(α/ℓ)).
    /// Common choices are 1 or 2, affecting the noise analysis.
    pub fn set_delta_power_num(&mut self, delta_power_num: u32) -> &mut Self {
        self.delta_power_num = delta_power_num;
        self
    }

    /// Sets the BFV primes override string
    ///
    /// If provided, these primes will be used instead of the computed BFV modulus.
    /// Format: comma-separated values accepting hex (0x...) or decimal.
    /// Example: "0x00800000022a0001,0x00800000021a0001"
    pub fn set_qbfv_primes(&mut self, qbfv_primes: Option<String>) -> &mut Self {
        self.qbfv_primes = qbfv_primes;
        self
    }

    /// Sets the maximum PVW growth parameter
    ///
    /// Limits how many extra PVW primes to enumerate (growth steps) beyond
    /// the initial q_BFV. This controls the search space expansion.
    pub fn set_max_pvw_growth(&mut self, max_pvw_growth: Option<usize>) -> &mut Self {
        self.max_pvw_growth = max_pvw_growth;
        self
    }
}
