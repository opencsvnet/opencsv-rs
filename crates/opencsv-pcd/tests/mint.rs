//! End-to-end tests for the mint predicate circuit (paper §4.4).
//!
//! Run with `cargo test -p opencsv-pcd --test mint -- --nocapture` to see
//! timings.

use std::time::Instant;

use opencsv_core::{mint_commit, Coin, Digest, OwnerSecret};
use opencsv_pcd::{prove_mint, prove_mint_raw, verify_mint, MintError, MintStatement};

/// Test asset id (arbitrary but fixed).
fn asset_id() -> Digest {
    Digest::from_bytes([0x11; 32])
}

/// A coin in the test asset with the given value/owner/randomness.
fn coin(value: u64, owner_tag: u8, r_tag: u8) -> Coin {
    Coin {
        asset_id: asset_id(),
        value,
        owner: OwnerSecret::from_bytes([owner_tag; 32]).owner(),
        randomness: Digest::from_bytes([r_tag; 32]),
    }
}

fn mint_nonce() -> Digest {
    Digest::from_bytes([0x99; 32])
}

/// Raw proving entry point computing the honest `mint_commit` for
/// `(asset_id, value, mint_nonce)`.
fn prove_raw(
    asset_id: &Digest,
    value: u64,
    nonce: &Digest,
    outputs: &[Coin; 2],
) -> Result<opencsv_pcd::MintProof, MintError> {
    let mc = mint_commit(asset_id, value, nonce);
    prove_mint_raw(asset_id, value, &mc, nonce, outputs)
}

/// Positive end-to-end test, covering the value edge cases `v = 0` and
/// `v = u64::MAX` (the top limb's 16-bit range-check boundary).
#[test]
fn prove_and_verify_mint() {
    let outputs = [coin(u64::MAX, 0x22, 0x33), coin(0, 0x44, 0x55)];

    let t = Instant::now();
    let mint = prove_mint(&asset_id(), &mint_nonce(), &outputs).expect("proving should succeed");
    let prove_time = t.elapsed();
    println!("prove_mint: {prove_time:?}");

    assert_eq!(mint.statement.value, u64::MAX);
    assert_eq!(
        mint.statement.mint_commit,
        mint_commit(&asset_id(), u64::MAX, &mint_nonce())
    );
    assert_eq!(
        mint.output_commitments,
        [outputs[0].commitment(), outputs[1].commitment()]
    );

    let t = Instant::now();
    let statement = mint.statement.clone();
    verify_mint(&statement, &mint).expect("verification should succeed");
    println!("verify_mint: {:?}", t.elapsed());
}

/// Negative test: output values that do not sum to the public total must
/// fail proving (at witness generation, on the carry constraints).
#[test]
fn unbalanced_mint_fails() {
    let outputs = [coin(10, 0x22, 0x33), coin(20, 0x44, 0x55)];
    // 10 + 20 = 30, but claim V = 31.
    let err = match prove_raw(&asset_id(), 31, &mint_nonce(), &outputs) {
        Ok(_) => panic!("proving an unbalanced mint must fail"),
        Err(e) => e,
    };
    println!("unbalanced mint rejected with: {err}");
    assert!(matches!(err, MintError::Circuit(_)));
}

/// Negative test: a minted total that would overflow u64 must fail — both
/// the checked front door (`MintError::ValueOverflow`) and the in-circuit
/// carry constraints (wrapping V = 0 fails at witness generation).
#[test]
fn overflowing_mint_fails() {
    let outputs = [coin(u64::MAX, 0x22, 0x33), coin(1, 0x44, 0x55)];

    let err = match prove_mint(&asset_id(), &mint_nonce(), &outputs) {
        Ok(_) => panic!("u64-overflowing outputs must be rejected up front"),
        Err(e) => e,
    };
    assert!(matches!(err, MintError::ValueOverflow));

    // A prover bypassing the checked sum and claiming the wrapped V = 0 must
    // still fail in-circuit (final carry pinned to zero).
    let err = match prove_raw(&asset_id(), 0, &mint_nonce(), &outputs) {
        Ok(_) => panic!("proving an overflowing mint must fail"),
        Err(e) => e,
    };
    println!("overflowing mint rejected with: {err}");
    assert!(matches!(err, MintError::Circuit(_)));
}

/// Negative test: a `mint_commit` that does not match
/// `H("mint" ∥ asset_id ∥ V ∥ mint_nonce)` for the witness nonce must fail.
#[test]
fn wrong_mint_commit_fails() {
    let outputs = [coin(7, 0x22, 0x33), coin(8, 0x44, 0x55)];
    // mint_commit binds a different nonce than the witness nonce.
    let other_nonce = Digest::from_bytes([0x77; 32]);
    let wrong_commit = mint_commit(&asset_id(), 15, &other_nonce);
    let err = match prove_mint_raw(&asset_id(), 15, &wrong_commit, &mint_nonce(), &outputs) {
        Ok(_) => panic!("proving with a mismatched mint_commit must fail"),
        Err(e) => e,
    };
    println!("wrong-mint_commit rejected with: {err}");
    assert!(matches!(err, MintError::Circuit(_)));
}

/// Negative test: a valid proof must not verify against tampered public
/// data.
#[test]
fn tampered_statement_fails_verification() {
    let outputs = [coin(5, 0x22, 0x33), coin(6, 0x44, 0x55)];
    let mint = prove_mint(&asset_id(), &mint_nonce(), &outputs).expect("proving should succeed");

    let mut tampered: MintStatement = mint.statement.clone();
    tampered.value += 1;
    let err =
        verify_mint(&tampered, &mint).expect_err("verification against tampered value must fail");
    assert!(matches!(err, MintError::StatementMismatch));

    let mut tampered = mint.statement.clone();
    tampered.mint_commit = Digest::from_bytes([0xee; 32]);
    let err = verify_mint(&tampered, &mint)
        .expect_err("verification against tampered mint_commit must fail");
    assert!(matches!(err, MintError::StatementMismatch));
}
