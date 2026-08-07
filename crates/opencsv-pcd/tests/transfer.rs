//! End-to-end tests for the transfer predicate circuit (paper §4.5,
//! single-asset restriction).
//!
//! Run with `cargo test -p opencsv-pcd --test transfer -- --nocapture` to
//! see timings.

use std::time::Instant;

use opencsv_core::{Coin, Digest, OwnerSecret};
use opencsv_pcd::{prove_transfer, verify_transfer, TransferError, TransferStatement};

/// Test asset id (arbitrary but fixed).
fn asset_id() -> Digest {
    Digest::from_bytes([0x11; 32])
}

fn osk(tag: u8) -> OwnerSecret {
    OwnerSecret::from_bytes([tag; 32])
}

/// A coin in the test asset owned by `osk(owner_tag)`.
fn coin(value: u64, owner_tag: u8, r_tag: u8) -> Coin {
    Coin {
        asset_id: asset_id(),
        value,
        owner: osk(owner_tag).owner(),
        randomness: Digest::from_bytes([r_tag; 32]),
    }
}

/// Positive end-to-end test, covering the value edge cases `v = 0` and
/// `v = u64::MAX` and two distinct owner secrets.
#[test]
fn prove_and_verify_transfer() {
    let inputs = [
        (coin(u64::MAX, 0x22, 0x33), osk(0x22)),
        (coin(0, 0x44, 0x55), osk(0x44)),
    ];
    let outputs = [coin(u64::MAX, 0x66, 0x77), coin(0, 0x88, 0x99)];

    let t = Instant::now();
    let transfer = prove_transfer(&asset_id(), &inputs, &outputs).expect("proving should succeed");
    let prove_time = t.elapsed();
    println!("prove_transfer: {prove_time:?}");

    assert_eq!(
        transfer.statement.nullifiers,
        [
            opencsv_core::coin::nullifier(&osk(0x22), &inputs[0].0.commitment()),
            opencsv_core::coin::nullifier(&osk(0x44), &inputs[1].0.commitment()),
        ]
    );
    assert_eq!(
        transfer.output_commitments,
        [outputs[0].commitment(), outputs[1].commitment()]
    );

    let t = Instant::now();
    let statement = transfer.statement.clone();
    verify_transfer(&statement, &transfer).expect("verification should succeed");
    println!("verify_transfer: {:?}", t.elapsed());
}

/// A valid split may borrow across the 24-bit limb boundary. In BabyBear,
/// the first carry for 25_000_000 = 10_000_000 + 15_000_000 is `-1`.
#[test]
fn transfer_split_with_negative_limb_carry_verifies() {
    let inputs = [
        (coin(25_000_000, 0x22, 0x33), osk(0x22)),
        (coin(0, 0x44, 0x55), osk(0x44)),
    ];
    let outputs = [coin(10_000_000, 0x66, 0x77), coin(15_000_000, 0x88, 0x99)];

    let transfer = prove_transfer(&asset_id(), &inputs, &outputs)
        .expect("a balanced split with a negative limb carry must prove");
    verify_transfer(&transfer.statement, &transfer).expect("negative-carry split proof verifies");
}

/// Negative test: Σ v_in ≠ Σ v_out must fail proving (at witness generation,
/// on the carry constraints).
#[test]
fn unbalanced_transfer_fails() {
    let inputs = [
        (coin(10, 0x22, 0x33), osk(0x22)),
        (coin(20, 0x44, 0x55), osk(0x44)),
    ];
    // 10 + 20 = 30 in, but only 29 out.
    let outputs = [coin(15, 0x66, 0x77), coin(14, 0x88, 0x99)];

    let err = match prove_transfer(&asset_id(), &inputs, &outputs) {
        Ok(_) => panic!("proving an unbalanced transfer must fail"),
        Err(e) => e,
    };
    println!("unbalanced transfer rejected with: {err}");
    assert!(matches!(err, TransferError::Circuit(_)));
}

/// Negative test: spending with the wrong owner secret must fail (the
/// ownership constraint `owner_i = H(osk_i)`).
#[test]
fn wrong_osk_fails() {
    let inputs = [
        (coin(10, 0x22, 0x33), osk(0x22)),
        // coin owned by osk(0x44), spent with osk(0xee).
        (coin(20, 0x44, 0x55), osk(0xee)),
    ];
    let outputs = [coin(15, 0x66, 0x77), coin(15, 0x88, 0x99)];

    let err = match prove_transfer(&asset_id(), &inputs, &outputs) {
        Ok(_) => panic!("proving with a wrong owner secret must fail"),
        Err(e) => e,
    };
    println!("wrong-osk transfer rejected with: {err}");
    assert!(matches!(err, TransferError::Circuit(_)));
}

/// A fixed-width circuit must never count one coin twice as two inputs.
#[test]
fn duplicate_input_fails_before_proving() {
    let input = (coin(10, 0x22, 0x33), osk(0x22));
    let inputs = [input, input];
    let outputs = [coin(10, 0x66, 0x77), coin(10, 0x88, 0x99)];

    let err = match prove_transfer(&asset_id(), &inputs, &outputs) {
        Ok(_) => panic!("duplicating one input coin must fail"),
        Err(error) => error,
    };
    assert!(matches!(err, TransferError::DuplicateInput));
}

/// Negative test: a valid proof must not verify against tampered public
/// data.
#[test]
fn tampered_statement_fails_verification() {
    let inputs = [
        (coin(7, 0x22, 0x33), osk(0x22)),
        (coin(8, 0x44, 0x55), osk(0x44)),
    ];
    let outputs = [coin(9, 0x66, 0x77), coin(6, 0x88, 0x99)];
    let transfer = prove_transfer(&asset_id(), &inputs, &outputs).expect("proving should succeed");

    let mut tampered: TransferStatement = transfer.statement.clone();
    tampered.nullifiers[0] = Digest::from_bytes([0xee; 32]);
    let err = verify_transfer(&tampered, &transfer)
        .expect_err("verification against a tampered nullifier must fail");
    assert!(matches!(err, TransferError::StatementMismatch));

    let mut tampered = transfer.statement.clone();
    tampered.asset_id = Digest::from_bytes([0xee; 32]);
    let err = verify_transfer(&tampered, &transfer)
        .expect_err("verification against a tampered asset id must fail");
    assert!(matches!(err, TransferError::StatementMismatch));
}
