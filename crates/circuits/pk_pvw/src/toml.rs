//! TOML generation for PVW public key circuit
//!
//! This module contains the TOML generation logic specific to the PVW public key circuit.

use crate::bounds::PvwPkBounds;
use crate::vectors::PvwPkVectors;
use serde::Serialize;
use shared::circuit::CircuitVectors;
use shared::errors::ZkfheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for PVW public key circuit TOML files
pub struct PvwPkTomlGenerator {
    bounds: PvwPkBounds,
    vectors: PvwPkVectors,
}

impl PvwPkTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(bounds: PvwPkBounds, vectors: PvwPkVectors) -> Self {
        Self { bounds, vectors }
    }
}

/// Cryptographic parameters section in TOML
#[derive(Serialize)]
struct ProverCryptoTable {
    qis: Vec<String>,
}

/// Bound parameters section in TOML
#[derive(Serialize)]
struct ProverBoundsTable {
    e_bound: String,
    sk_bound: String,
    r1_low_bounds: Vec<String>,
    r1_up_bounds: Vec<String>,
    r2_bounds: Vec<String>,
    a_bounds: Vec<String>,
    b_bounds: Vec<String>,
}

/// Circuit parameters section in TOML
#[derive(Serialize)]
struct ProverCircuitTable {
    n: String,
    k: String,
    n_parties: String,
}

/// Parameter bounds to include in the TOML
#[derive(Serialize)]
struct ProverParamsTable {
    crypto: ProverCryptoTable,
    bounds: ProverBoundsTable,
    circuit: ProverCircuitTable,
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
    a: Vec<Vec<Vec<ProverVectorsTable>>>,      // [L][K][K] matrices
    e: Vec<Vec<ProverVectorsTable>>,            // [N_PARTIES][K] vectors
    sk: Vec<Vec<ProverVectorsTable>>,           // [N_PARTIES][K] vectors
    b: Vec<Vec<Vec<ProverVectorsTable>>>,       // [L][N_PARTIES][K] vectors
    r1: Vec<Vec<Vec<ProverVectorsTable>>>,      // [L][N_PARTIES][K] vectors
    r2: Vec<Vec<Vec<ProverVectorsTable>>>,      // [L][N_PARTIES][K] vectors
}

impl TomlGenerator for PvwPkTomlGenerator {
    fn to_toml_string(&self) -> ZkfheResult<String> {
        // Apply field reduction to ensure all coefficients are in the BN254 field
        let reduced_vectors = self.vectors.standard_form();
        
        // Convert 4D vectors to TOML format: [L][K][K] for a, [L][N_PARTIES][K] for others
        let a_toml = reduced_vectors.a.iter()
            .map(|l| {
                l.iter()
                    .map(|k| {
                        k.iter()
                            .map(|poly| ProverVectorsTable {
                                coefficients: to_string_1d_vec(poly),
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let e_toml = reduced_vectors.e.iter()
            .map(|party| {
                party.iter()
                    .map(|poly| ProverVectorsTable {
                        coefficients: to_string_1d_vec(poly),
                    })
                    .collect()
            })
            .collect();

        let sk_toml = reduced_vectors.sk.iter()
            .map(|party| {
                party.iter()
                    .map(|poly| ProverVectorsTable {
                        coefficients: to_string_1d_vec(poly),
                    })
                    .collect()
            })
            .collect();

        let b_toml = reduced_vectors.b.iter()
            .map(|l| {
                l.iter()
                    .map(|party| {
                        party.iter()
                            .map(|poly| ProverVectorsTable {
                                coefficients: to_string_1d_vec(poly),
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let r1_toml = reduced_vectors.r1.iter()
            .map(|l| {
                l.iter()
                    .map(|party| {
                        party.iter()
                            .map(|poly| ProverVectorsTable {
                                coefficients: to_string_1d_vec(poly),
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let r2_toml = reduced_vectors.r2.iter()
            .map(|l| {
                l.iter()
                    .map(|party| {
                        party.iter()
                            .map(|poly| ProverVectorsTable {
                                coefficients: to_string_1d_vec(poly),
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let toml_data = ProverTomlFormat {
            params: ProverParamsTable {
                crypto: ProverCryptoTable {
                    qis: self.bounds.qis.iter().map(|b| b.to_string()).collect(),
                },
                bounds: ProverBoundsTable {
                    e_bound: self.bounds.e_bound.to_string(),
                    sk_bound: self.bounds.sk_bound.to_string(),
                    r1_low_bounds: self.bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect(),
                    r1_up_bounds: self.bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect(),
                    r2_bounds: self.bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
                    a_bounds: self.bounds.a_bounds.iter().map(|b| b.to_string()).collect(),
                    b_bounds: self.bounds.b_bounds.iter().map(|b| b.to_string()).collect(),
                },
                circuit: ProverCircuitTable {
                    n: self.bounds.n.to_string(),
                    k: self.bounds.k.to_string(),
                    n_parties: self.bounds.n_parties.to_string(),
                },
            },
            a: a_toml,
            e: e_toml,
            sk: sk_toml,
            b: b_toml,
            r1: r1_toml,
            r2: r2_toml,
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::PvwPkBounds;
    use crate::vectors::PvwPkVectors;

    use tempfile::TempDir;

    fn setup_test_data() -> (PvwPkBounds, PvwPkVectors) {
        let qis = vec![68719403009, 68719230977, 137438822401];
        let bounds = PvwPkBounds::compute(qis, 8, 32, 7, 5000, 1).unwrap();
        let vectors = PvwPkVectors::new(3, 7, 32, 8);

        (bounds, vectors)
    }

    #[test]
    fn test_toml_generation() {
        let (bounds, vectors) = setup_test_data();
        let generator = PvwPkTomlGenerator::new(bounds, vectors);

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
        assert!(content.contains("params.circuit"));
        assert!(content.contains("a"));
        assert!(content.contains("e"));
        assert!(content.contains("sk"));
        assert!(content.contains("b"));
        assert!(content.contains("r1"));
        assert!(content.contains("r2"));
    }

    #[test]
    fn test_toml_format_structure() {
        let (bounds, vectors) = setup_test_data();
        let generator = PvwPkTomlGenerator::new(bounds, vectors);

        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("a"));
        assert!(toml_string.contains("e"));
        assert!(toml_string.contains("sk"));
        assert!(toml_string.contains("b"));
        assert!(toml_string.contains("r1"));
        assert!(toml_string.contains("r2"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
        assert!(toml_string.contains("[params.circuit]"));
    }
}
