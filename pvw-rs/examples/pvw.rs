//! Multi-Party Vector Encryption Example
//!
//! Demonstrates PVW encryption system where:
//! 1. Multiple parties each encrypt their own vector of values
//! 2. Each party can decrypt only the values intended for them
//! 3. Privacy is preserved: parties only see their designated shares

use console::style;
use pvw::{
    crypto::{decrypt_party_shares, encrypt_all_party_shares},
    keys::{GlobalPublicKey, Party},
    params::{PvwCrs, PvwParameters, PvwParametersBuilder},
};
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        style("=== Multi-Party Vector Encryption Demo ===")
            .cyan()
            .bold()
    );
    println!();

    // Configuration
    let num_parties = 7;
    let ring_degree = 8; // Must be a power of two
    let dimension = 32;

    //let moduli = vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];
    let moduli = vec![0xffffc4001u64, 0x1ffffe0001u64];
    //let moduli = vec![0x1ffffffe88001, 0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];

    // Get parameters that satisfy correctness condition
    let (suggested_variance, suggested_bound1, suggested_bound2) =
        PvwParameters::suggest_correct_parameters(num_parties, dimension, ring_degree, &moduli)
            .unwrap_or((1, 50, 100));
    println!("Suggested variance: {suggested_variance}, Suggested bound1: {suggested_bound1}, Suggested bound2: {suggested_bound2}");
    // Build PVW parameters
    let params = PvwParametersBuilder::new()
        .set_parties(num_parties)
        .set_dimension(dimension)
        .set_l(ring_degree)
        .set_moduli(&moduli)
        .set_secret_variance(suggested_variance)
        .set_error_bounds_u32(suggested_bound1, suggested_bound2)
        .build_arc()?;

    println!("{:?}", params);
    // Display parameters
    println!("⚙️  {}", style("PVW Parameters:").blue().bold());
    println!(
        "  • Parties: {}, Dimension: {}, Ring degree: {}",
        params.n, params.k, params.l
    );
    println!(
        "  • Delta (Δ): {}, Modulus bits: {}",
        params.delta(),
        params.q_total().bits()
    );
    println!(
        "  • Error bounds: ({suggested_bound1}, {suggested_bound2}), Secret variance: {suggested_variance}"
    );
    println!(
        "  • Correctness condition: {}",
        if params.verify_correctness_condition() {
            "✓ Satisfied"
        } else {
            "✗ Not satisfied"
        }
    );
    println!();

    let mut rng = OsRng;

    // Generate parties and global public key
    let crs = PvwCrs::new(&params, &mut rng)?;
    let mut global_pk = GlobalPublicKey::new(crs);

    let mut parties = Vec::new();
    for i in 0..num_parties {
        let party = Party::new(i, &params, &mut rng)?;
        global_pk.generate_and_add_party(&party, &mut rng)?;
        parties.push(party);
    }

    // Each party creates their vector of values to distribute
    let mut all_party_vectors = Vec::new();
    for party_id in 0..num_parties {
        let party_vector: Vec<u64> = (1..=num_parties)
            .map(|j| (party_id * 1000 + j) as u64)
            .collect();
        all_party_vectors.push(party_vector);
    }

    // Display the values being encrypted
    println!(
        "📊 {}",
        style("Share Distribution Matrix (what each dealer encrypts):")
            .blue()
            .bold()
    );
    println!("    Rows = Dealers, Columns = Values for each recipient");
    println!();
    print!("Dealer ");
    for i in 0..num_parties {
        print!("{:>8}", format!("→P{i}"));
    }
    println!();
    println!("{}", "-".repeat(7 + num_parties * 8));

    for (dealer_id, vector) in all_party_vectors.iter().enumerate() {
        print!("{dealer_id:>6} ");
        for &value in vector {
            print!("{value:>8}");
        }
        println!();
    }
    println!();

    // Encrypt all party vectors (creates n ciphertexts, one per dealer)
    let start_time = std::time::Instant::now();
    let all_ciphertexts = encrypt_all_party_shares(&all_party_vectors, &global_pk)?;
    let encryption_time = start_time.elapsed();

    // Decrypt shares using the new efficient function
    let start_decrypt = std::time::Instant::now();

    // Decrypt all party shares in parallel
    let decryption_results: Result<Vec<Vec<u64>>, pvw::params::PvwError> = parties
        .par_iter()
        .enumerate()
        .take(num_parties)
        .map(|(recipient_party_index, recipient_party)| {
            // Use the new function to decrypt all shares intended for this party
            decrypt_party_shares(
                &all_ciphertexts,
                &recipient_party.secret_key,
                recipient_party_index,
            )
        })
        .collect();

    let decryption_results = decryption_results?;
    let decryption_time = start_decrypt.elapsed();

    // Count correct decryptions
    let mut total_correct = 0;
    let mut total_values = 0;
    for (recipient_party_index, party_shares) in decryption_results.iter().enumerate() {
        for (dealer_idx, &decrypted_value) in party_shares.iter().enumerate() {
            let expected_value = all_party_vectors[dealer_idx][recipient_party_index];
            if decrypted_value == expected_value {
                total_correct += 1;
            }
            total_values += 1;
        }
    }

    // Display received shares matrix
    println!(
        "📊 {}",
        style("Received Shares Matrix (what each party decrypted):")
            .blue()
            .bold()
    );
    println!("    Rows = Recipients, Columns = Shares from each dealer");
    println!();
    print!("Recip ");
    for i in 0..num_parties {
        print!("{:>8}", format!("←D{i}"));
    }
    println!();
    println!("{}", "-".repeat(6 + num_parties * 8));

    for (recipient_id, shares) in decryption_results.iter().enumerate() {
        print!("{recipient_id:>5} ");
        for &share in shares {
            print!("{share:>8}");
        }
        println!();
    }
    println!();

    // Verify the shares match the original distribution
    println!("🔍 {}", style("Verification:").blue().bold());
    let mut verification_details = Vec::new();
    for (recipient_party_index, _recipient_party) in
        all_party_vectors.iter().enumerate().take(num_parties)
    {
        for (dealer_party_index, _dealer_party) in
            all_party_vectors.iter().enumerate().take(num_parties)
        {
            let expected = all_party_vectors[dealer_party_index][recipient_party_index];
            let received = decryption_results[recipient_party_index][dealer_party_index];
            let matches = expected == received;
            verification_details.push((
                dealer_party_index,
                recipient_party_index,
                expected,
                received,
                matches,
            ));
        }
    }

    // Show any mismatches
    let mismatches: Vec<_> = verification_details
        .iter()
        .filter(|(_, _, _, _, matches)| !matches)
        .collect();

    if !mismatches.is_empty() {
        println!("  Mismatches found:");
        for (dealer, recipient, expected, received, _) in mismatches {
            println!("    D{dealer} → P{recipient}: expected {expected}, got {received}");
        }
    } else {
        println!("  ✓ All shares correctly transmitted and decrypted!");
    }

    // Results summary
    let success_rate = (total_correct as f64 / total_values as f64) * 100.0;
    println!("📈 {}", style("Results Summary:").blue().bold());
    println!("  • Success rate: {total_correct}/{total_values} ({success_rate:.1}%)");
    println!("  • Operations: {num_parties} encrypt calls, {num_parties} decrypt calls");
    println!();

    // Performance metrics
    println!("⚡ {}", style("Performance:").blue().bold());
    println!(
        "  • Encryption time: {encryption_time:?} ({:?} avg per dealer)",
        encryption_time / num_parties as u32
    );
    println!(
        "  • Decryption time: {decryption_time:?} ({:?} avg per party)",
        decryption_time / num_parties as u32
    );
    println!(
        "  • Efficiency: {total_values} individual decrypt operations in {num_parties} function calls"
    );
    println!();

    // Final status
    if success_rate == 100.0 {
        println!(
            "🎉 {}",
            style("SUCCESS: PVSS working perfectly!").green().bold()
        );
        println!("    Each party received exactly the shares intended for them.");
    } else if success_rate >= 80.0 {
        println!(
            "✅ {}",
            style("MOSTLY SUCCESSFUL: Minor decryption issues detected")
                .yellow()
                .bold()
        );
    } else {
        println!(
            "⚠️  {}",
            style("NEEDS ATTENTION: Low success rate").red().bold()
        );
    }

    Ok(())
}
