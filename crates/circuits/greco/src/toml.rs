//! TOML generation for Greco circuit
//!
//! This module contains the TOML generation logic specific to the Greco circuit.

use crate::bounds::GrecoBounds;
use crate::vectors::GrecoVectors;
use serde::Serialize;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for Greco circuit TOML files
pub struct GrecoTomlGenerator {
    bounds: GrecoBounds,
    vectors: GrecoVectors,
}

impl GrecoTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(bounds: GrecoBounds, vectors: GrecoVectors) -> Self {
        Self { bounds, vectors }
    }
}

/// Cryptographic parameters section in TOML
#[derive(Serialize)]
struct ProverCryptoTable {
    q_mod_t: String,
    qis: Vec<String>,
    k0is: Vec<String>,
}

/// Bound parameters section in TOML
#[derive(Serialize)]
struct ProverBoundsTable {
    e_bound: String,
    u_bound: String,
    k1_low_bound: String,
    k1_up_bound: String,
    p1_bounds: Vec<String>,
    p2_bounds: Vec<String>,
    pk_bounds: Vec<String>,
    r1_low_bounds: Vec<String>,
    r1_up_bounds: Vec<String>,
    r2_bounds: Vec<String>,
}

/// Parameter bounds to include in the TOML
#[derive(Serialize)]
struct ProverParamsTable {
    crypto: ProverCryptoTable,
    bounds: ProverBoundsTable,
}

/// Structure for individual vector tables in TOML
#[derive(Serialize)]
struct ProverVectorsTable {
    coefficients: Vec<String>,
}

/// Complete `Prover.toml` format including params and vectors
#[derive(Serialize)]
struct ProverTomlFormat {
    params: ProverParamsTable,
    ct0is: Vec<ProverVectorsTable>,
    ct1is: Vec<ProverVectorsTable>,
    pk0is: Vec<ProverVectorsTable>,
    pk1is: Vec<ProverVectorsTable>,
    r1is: Vec<ProverVectorsTable>,
    r2is: Vec<ProverVectorsTable>,
    p1is: Vec<ProverVectorsTable>,
    p2is: Vec<ProverVectorsTable>,
    u: ProverVectorsTable,
    e0: ProverVectorsTable,
    e1: ProverVectorsTable,
    k1: ProverVectorsTable,
}

impl TomlGenerator for GrecoTomlGenerator {
    fn to_toml_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        let toml_data = ProverTomlFormat {
            params: ProverParamsTable {
                crypto: ProverCryptoTable {
                    q_mod_t: self.bounds.q_mod_t.to_string(),
                    qis: self.bounds.moduli.iter().map(|b| b.to_string()).collect(),
                    k0is: self.bounds.k0is.iter().map(|b| b.to_string()).collect(),
                },
                bounds: ProverBoundsTable {
                    e_bound: self.bounds.e_bound.to_string(),
                    u_bound: self.bounds.u_bound.to_string(),
                    k1_low_bound: self.bounds.k1_low_bound.to_string(),
                    k1_up_bound: self.bounds.k1_up_bound.to_string(),
                    p1_bounds: self
                        .bounds
                        .p1_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    p2_bounds: self
                        .bounds
                        .p2_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    pk_bounds: self
                        .bounds
                        .pk_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    r1_low_bounds: self
                        .bounds
                        .r1_low_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    r1_up_bounds: self
                        .bounds
                        .r1_up_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    r2_bounds: self
                        .bounds
                        .r2_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                },
            },
            ct0is: self
                .vectors
                .ct0is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            ct1is: self
                .vectors
                .ct1is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            pk0is: self
                .vectors
                .pk0is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            pk1is: self
                .vectors
                .pk1is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            r1is: self
                .vectors
                .r1is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            r2is: self
                .vectors
                .r2is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            p1is: self
                .vectors
                .p1is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            p2is: self
                .vectors
                .p2is
                .iter()
                .map(|v| ProverVectorsTable {
                    coefficients: to_string_1d_vec(v),
                })
                .collect(),
            u: ProverVectorsTable {
                coefficients: to_string_1d_vec(&self.vectors.u),
            },
            e0: ProverVectorsTable {
                coefficients: to_string_1d_vec(&self.vectors.e0),
            },
            e1: ProverVectorsTable {
                coefficients: to_string_1d_vec(&self.vectors.e1),
            },
            k1: ProverVectorsTable {
                coefficients: to_string_1d_vec(&self.vectors.k1),
            },
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::GrecoBounds;
    use crate::vectors::GrecoVectors;
    use fhe::bfv::BfvParametersBuilder;

    use tempfile::TempDir;

    fn setup_test_data() -> (GrecoBounds, GrecoVectors) {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[0x3FFFFFFF000001])
            .build_arc()
            .unwrap();

        let bounds = GrecoBounds::compute(&params, 0).unwrap();
        let vectors = GrecoVectors::new(1, 2048);

        (bounds, vectors)
    }

    #[test]
    fn test_toml_generation() {
        let (bounds, vectors) = setup_test_data();
        let generator = GrecoTomlGenerator::new(bounds, vectors);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();
        println!("Generated TOML:\n{}", content);
        // Check that the file contains the expected sections
        assert!(content.contains("params.crypto"));
        assert!(content.contains("params.bounds"));
        assert!(content.contains("crypto"));
        assert!(content.contains("bounds"));
        assert!(content.contains("ct0is"));
        assert!(content.contains("ct1is"));
        assert!(content.contains("pk0is"));
        assert!(content.contains("pk1is"));
        assert!(content.contains("r1is"));
        assert!(content.contains("r2is"));
        assert!(content.contains("p1is"));
        assert!(content.contains("p2is"));
        assert!(content.contains("u"));
        assert!(content.contains("e0"));
        assert!(content.contains("e1"));
        assert!(content.contains("k1"));
    }

    #[test]
    fn test_toml_format_structure() {
        let (bounds, vectors) = setup_test_data();
        let generator = GrecoTomlGenerator::new(bounds, vectors);

        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("[[ct0is]]"));
        assert!(toml_string.contains("[[ct1is]]"));
        assert!(toml_string.contains("[[pk0is]]"));
        assert!(toml_string.contains("[[pk1is]]"));
        assert!(toml_string.contains("[[r1is]]"));
        assert!(toml_string.contains("[[r2is]]"));
        assert!(toml_string.contains("[[p1is]]"));
        assert!(toml_string.contains("[[p2is]]"));
        assert!(toml_string.contains("[u]"));
        assert!(toml_string.contains("[e0]"));
        assert!(toml_string.contains("[e1]"));
        assert!(toml_string.contains("[k1]"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
