//! End-to-end tests for the coin commitment opening circuit.
//!
//! Run with `cargo test -p opencsv-pcd -- --nocapture` to see timings.

use std::time::Instant;

use opencsv_core::{Coin, Digest, OwnerSecret};
use opencsv_pcd::{prove_opening, prove_opening_raw, verify_opening, CoinWitness, OpeningError};

/// A coin with plausible but arbitrary contents (`value` distinguishes
/// coins in tests).
fn sample_coin(value: u64) -> Coin {
    Coin {
        asset_id: Digest::from_bytes([0x11; 32]),
        value,
        owner: OwnerSecret::from_bytes([0x22; 32]).owner(),
        randomness: Digest::from_bytes([0x33; 32]),
    }
}

/// Positive end-to-end test: build a coin with opencsv-core, compute the
/// commitment off-circuit, prove the opening in-circuit, verify the proof.
#[test]
fn prove_and_verify_opening() {
    let coin = sample_coin(12_345_678);

    let t = Instant::now();
    let opening = prove_opening(&coin).expect("proving should succeed");
    let prove_time = t.elapsed();
    println!("prove_opening: {prove_time:?}");

    assert_eq!(opening.commitment, coin.commitment().to_elems());

    let t = Instant::now();
    verify_opening(&coin.commitment(), &opening).expect("verification should succeed");
    println!("verify_opening: {:?}", t.elapsed());
}

/// Negative test: a witness that does not hash to the claimed commitment
/// must fail (at witness generation / constraint checking).
#[test]
fn wrong_opening_fails() {
    let coin = sample_coin(1);
    let other = sample_coin(2);
    let commitment = coin.commitment();
    let wrong_witness = CoinWitness::from_coin(&other);

    let err = match prove_opening_raw(&commitment.to_elems(), &wrong_witness) {
        Ok(_) => panic!("proving with an inconsistent opening must fail"),
        Err(e) => e,
    };
    println!("wrong opening rejected with: {err}");
    assert!(matches!(err, OpeningError::Circuit(_)));
}

/// Negative test: a valid proof must not verify against a different
/// commitment.
#[test]
fn wrong_commitment_fails_verification() {
    let coin = sample_coin(3);
    let opening = prove_opening(&coin).expect("proving should succeed");

    let other_commitment = sample_coin(4).commitment();
    let err = verify_opening(&other_commitment, &opening)
        .expect_err("verification against a different commitment must fail");
    assert!(matches!(err, OpeningError::CommitmentMismatch));
}
