//! Threshold Multi-Party Vector Encryption Example
//!
//! Demonstrates PVW encryption system with threshold decryption where:
//! 1. Multiple parties each encrypt their own vector of values (n dealers)
//! 2. Each party only needs to decrypt t < n ciphertexts (threshold subset)
//! 3. Dealer indices are preserved for later reconstruction
//! 4. Privacy is preserved: parties only see their designated shares from selected dealers

use console::style;
use pvw::{
    crypto::PvwCiphertext,
    crypto::{decrypt_party_shares, decrypt_threshold_party_shares, encrypt_all_party_shares},
    keys::{GlobalPublicKey, Party},
    params::{PvwCrs, PvwParameters, PvwParametersBuilder},
};
use rand::{rngs::OsRng, seq::SliceRandom};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        style("=== Threshold Multi-Party Vector Encryption Demo ===")
            .cyan()
            .bold()
    );
    println!();

    // Configuration
    let num_parties = 7;
    let threshold = 5; // Only need 5 out of 7 parties
    let ring_degree = 8; // Must be a power of two
    let dimension = 32;

    let moduli = vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];

    // Get parameters that satisfy correctness condition
    let (suggested_variance, suggested_bound1, suggested_bound2) =
        PvwParameters::suggest_correct_parameters(num_parties, dimension, ring_degree, &moduli)
            .unwrap_or((1, 50, 100));

    // Build PVW parameters
    let params = PvwParametersBuilder::new()
        .set_parties(num_parties)
        .set_dimension(dimension)
        .set_l(ring_degree)
        .set_moduli(&moduli)
        .set_secret_variance(suggested_variance)
        .set_error_bounds_u32(suggested_bound1, suggested_bound2)
        .build_arc()?;

    // Display parameters
    println!("⚙️  {}", style("PVW Parameters:").blue().bold());
    println!(
        "  • Parties: {}, Threshold: {}, Dimension: {}, Ring degree: {}",
        params.n, threshold, params.k, params.l
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
        let party: Party = Party::new(i, &params, &mut rng)?;
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

    // ALL parties will decrypt the same t ciphertexts (same subset of dealers)
    let mut dealer_indices: Vec<usize> = (0..num_parties).collect();
    dealer_indices.shuffle(&mut rng);
    let selected_dealers: Vec<usize> = dealer_indices.into_iter().take(threshold).collect();

    println!(
        "🎯 {}",
        style("Selected dealers for threshold decryption (same for all parties):")
            .blue()
            .bold()
    );
    println!("    Using {threshold} out of {num_parties} dealers: {selected_dealers:?}");
    println!("    All parties will decrypt from these same dealers");
    println!();

    // Select the ciphertexts (same set for all parties)
    let selected_ciphertexts: Vec<PvwCiphertext> = selected_dealers
        .iter()
        .map(|&dealer_idx| all_ciphertexts[dealer_idx].clone())
        .collect();

    // Decrypt threshold shares using the clean new function
    let start_decrypt = std::time::Instant::now();

    // Collect all secret keys
    let all_keys: Vec<&pvw::secret_key::SecretKey> =
        parties.iter().map(|party| &party.secret_key).collect();

    // All parties decrypt the same set of t ciphertexts
    let threshold_shares_only =
        decrypt_threshold_party_shares(&selected_ciphertexts, &all_keys, threshold)?;

    let decryption_time = start_decrypt.elapsed();

    println!(
        "✅ {}",
        style("Threshold decryption completed successfully!")
            .green()
            .bold()
    );
    println!("    All parties decrypted the same {threshold} ciphertexts");
    println!();

    // Count correct threshold decryptions using the shares-only data
    let mut threshold_correct = 0;
    let mut threshold_total = 0;
    for (recipient_party_index, party_threshold_shares) in threshold_shares_only.iter().enumerate()
    {
        for (share_idx, &decrypted_value) in party_threshold_shares.iter().enumerate() {
            let dealer_idx = selected_dealers[share_idx]; // Map back to dealer using selected_dealers order
            let expected_value = all_party_vectors[dealer_idx][recipient_party_index];
            if decrypted_value == expected_value {
                threshold_correct += 1;
            }
            threshold_total += 1;
        }
    }

    // Display threshold decryption results (shares only, no dealer IDs)
    println!(
        "📊 {}",
        style("Threshold Decryption Results (decrypted shares only):")
            .blue()
            .bold()
    );
    println!("    Each party's {threshold} shares from dealers {selected_dealers:?}");
    println!();

    for (recipient_id, shares) in threshold_shares_only.iter().enumerate() {
        print!("P{recipient_id}: ");
        for &share in shares {
            print!("{share:>6} ");
        }
        println!();
    }
    println!();

    // Verify threshold shares using shares-only data
    println!(
        "🔍 {}",
        style("Threshold Share Verification:").blue().bold()
    );
    let mut threshold_verification_details = Vec::new();
    for (recipient_party_index, threshold_shares) in threshold_shares_only.iter().enumerate() {
        for (share_idx, &decrypted_value) in threshold_shares.iter().enumerate() {
            let dealer_idx = selected_dealers[share_idx];
            let expected = all_party_vectors[dealer_idx][recipient_party_index];
            let matches = expected == decrypted_value;
            threshold_verification_details.push((
                dealer_idx,
                recipient_party_index,
                expected,
                decrypted_value,
                matches,
            ));
        }
    }

    // Show any threshold mismatches
    let threshold_mismatches: Vec<_> = threshold_verification_details
        .iter()
        .filter(|(_, _, _, _, matches)| !matches)
        .collect();

    if !threshold_mismatches.is_empty() {
        println!("  Threshold mismatches found:");
        for (dealer, recipient, expected, received, _) in threshold_mismatches {
            println!("    D{dealer} → P{recipient}: expected {expected}, got {received}");
        }
    } else {
        println!("  ✓ All threshold shares correctly transmitted and decrypted!");
    }

    // Results summary
    let threshold_success_rate = (threshold_correct as f64 / threshold_total as f64) * 100.0;
    println!("📈 {}", style("Threshold Results Summary:").blue().bold());
    println!(
        "  • Threshold success rate: {threshold_correct}/{threshold_total} ({threshold_success_rate:.1}%)"
    );
    println!("  • Operations: {num_parties} encrypt calls, 1 threshold decrypt call (all parties)");
    println!("  • Each party decrypted {threshold} shares (instead of all {num_parties})");
    println!();

    // Performance metrics
    println!("⚡ {}", style("Performance:").blue().bold());
    println!(
        "  • Encryption time: {encryption_time:?} ({:?} avg per dealer)",
        encryption_time / num_parties as u32
    );
    println!("  • Threshold decryption time: {decryption_time:?} (single call for all parties)",);
    println!(
        "  • Efficiency: {threshold_total} threshold decrypt operations vs {} full operations",
        num_parties * num_parties
    );
    println!(
        "  • Savings: {:.1}% fewer decryptions needed",
        (1.0 - threshold_total as f64 / (num_parties * num_parties) as f64) * 100.0
    );
    println!();

    // Demonstration: Show what full decryption would have given us
    println!(
        "🔄 {}",
        style("Comparison with Full Decryption:").blue().bold()
    );

    // For comparison, also do full decryption on one party
    let comparison_party_idx = 0;
    let full_shares = decrypt_party_shares(
        &all_ciphertexts,
        &parties[comparison_party_idx].secret_key,
        comparison_party_idx,
    )?;
    let threshold_shares = &threshold_shares_only[comparison_party_idx];

    println!("  Party {comparison_party_idx} comparison:");
    print!("    Full decryption ({num_parties} shares):      ");
    for &share in &full_shares {
        print!("{share:>6} ");
    }
    println!();

    print!("    Threshold decryption ({threshold} shares): ");
    for &share in threshold_shares {
        print!("{share:>6} ");
    }
    println!();
    println!("    (Threshold shares are from dealers: {selected_dealers:?})");
    println!();

    // Final status
    if threshold_success_rate == 100.0 {
        println!(
            "🎉 {}",
            style("SUCCESS: Threshold PVSS working perfectly!")
                .green()
                .bold()
        );
        println!("    Each party received exactly their shares from {threshold} selected dealers.");
        println!("    Dealer indices are preserved for later reconstruction.");
    } else if threshold_success_rate >= 80.0 {
        println!(
            "✅ {}",
            style("MOSTLY SUCCESSFUL: Minor threshold decryption issues detected")
                .yellow()
                .bold()
        );
    } else {
        println!(
            "⚠️  {}",
            style("NEEDS ATTENTION: Low threshold success rate")
                .red()
                .bold()
        );
    }

    Ok(())
}
