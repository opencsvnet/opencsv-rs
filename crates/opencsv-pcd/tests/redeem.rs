//! End-to-end tests for stage 4: the redeem circuit (paper §4.6).
//!
//! Run with `cargo test -p opencsv-pcd --test redeem -- --nocapture` to see
//! timings and proof sizes. Slow tests are marked `#[ignore]`; run them with
//! `cargo test -p opencsv-pcd --test redeem -- --ignored --nocapture`.

use std::time::Instant;

use opencsv_core::{Coin, Digest, OwnerSecret};
use opencsv_pcd::{
    prove_coin_transfer, prove_genesis_mint, prove_redeem, verify_redeem, CoinProof, NodeError,
    NodeMode,
};

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

fn proof_size(proof: &CoinProof) -> usize {
    postcard::to_allocvec(&proof.proof)
        .expect("proof serializes")
        .len()
}

/// Mint two coins (values 60 and 40) and their genesis proof.
fn genesis() -> (CoinProof, [Coin; 2]) {
    let coins = [coin(60, 0x22, 0x33), coin(40, 0x44, 0x55)];
    let nonce = Digest::from_bytes([0xaa; 32]);
    let proof = prove_genesis_mint(&asset_id(), &nonce, &coins).expect("mint proving");
    (proof, coins)
}

/// (a) Mint → redeem round trip: burning the first mint output produces a
/// proof whose statement exposes `(asset_id, V = 60, nf)`, which verifies;
/// a wrong claimed `V` or otherwise tampered expected statement is rejected.
#[test]
fn mint_to_redeem_round_trip() {
    let (mint, coins) = genesis();

    let t = Instant::now();
    let redeem =
        prove_redeem(&asset_id(), &(coins[0], osk(0x22)), &mint, 0).expect("redeem proving");
    let prove_time = t.elapsed();
    println!("prove_redeem (mint predecessor): {prove_time:?}");
    println!("redeem proof size: {} bytes", proof_size(&redeem));

    assert_eq!(redeem.mode, NodeMode::Redeem);
    assert_eq!(redeem.statement.asset_id, asset_id());
    assert_eq!(redeem.statement.value, 60);
    assert_eq!(
        redeem.statement.nullifiers[0],
        coins[0].nullifier(&osk(0x22))
    );
    assert_eq!(
        redeem.statement.nullifiers[1],
        Digest::from_bytes([0u8; 32])
    );
    assert_eq!(
        redeem.statement.output_commitments,
        [Digest::from_bytes([0u8; 32]); 2]
    );

    let t = Instant::now();
    verify_redeem(&redeem.statement, &redeem).expect("redeem verification");
    println!("verify_redeem: {:?}", t.elapsed());

    // Wrong burn amount: the statement binds V to the coin's committed
    // value, so claiming any other V is a statement mismatch.
    let mut wrong_v = redeem.statement.clone();
    wrong_v.value = 61;
    let err = verify_redeem(&wrong_v, &redeem)
        .expect_err("verification against a wrong burn amount must fail");
    assert!(matches!(err, NodeError::StatementMismatch));

    // Tampered statement: wrong nullifier, wrong asset, wrong mode — all
    // rejected before STARK verification (the bound values are compared).
    let mut wrong_nf = redeem.statement.clone();
    wrong_nf.nullifiers[0] = Digest::from_bytes([0xee; 32]);
    let err = verify_redeem(&wrong_nf, &redeem)
        .expect_err("verification against a tampered nullifier must fail");
    assert!(matches!(err, NodeError::StatementMismatch));

    let mut wrong_asset = redeem.statement.clone();
    wrong_asset.asset_id = Digest::from_bytes([0xee; 32]);
    let err = verify_redeem(&wrong_asset, &redeem)
        .expect_err("verification against a tampered asset id must fail");
    assert!(matches!(err, NodeError::StatementMismatch));

    // A redeem proof must not verify as a plain coin proof of another mode.
    let as_mint = CoinProof {
        mode: NodeMode::Mint,
        statement: redeem.statement.clone(),
        proof: redeem.proof,
    };
    let err = verify_redeem(&redeem.statement, &as_mint)
        .expect_err("verification with the wrong mode must fail");
    assert!(matches!(err, NodeError::StatementMismatch));
}

/// (b) Negative: redeeming with the wrong owner secret fails at proving
/// time (the ownership constraint `owner = H(osk)` conflicts in-circuit).
#[test]
fn wrong_osk_fails() {
    let (mint, coins) = genesis();
    // coins[0] is owned by osk(0x22); osk(0x44) owns coins[1].
    let err = match prove_redeem(&asset_id(), &(coins[0], osk(0x44)), &mint, 0) {
        Ok(_) => panic!("redeeming someone else's coin must fail"),
        Err(e) => e,
    };
    println!("wrong osk rejected with: {err}");
    assert!(matches!(err, NodeError::Circuit(_)));
}

/// (c) Mint → transfer → redeem: the redeem's in-circuit predecessor
/// verification handles a node (transfer) predecessor, not just a mint.
///
/// Slow (~2 min in debug); excluded from the default run. Run with:
/// `cargo test -p opencsv-pcd --test redeem -- --ignored --nocapture`.
#[test]
#[ignore = "slow: a full recursive transfer proof plus a redeem (~2 min in debug)"]
fn transfer_then_redeem() {
    let (mint, coins) = genesis();

    let inputs = [(coins[0], osk(0x22)), (coins[1], osk(0x44))];
    let outputs = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];
    let t = Instant::now();
    let transfer = prove_coin_transfer(&asset_id(), &inputs, &outputs, [&mint, &mint], [0, 1])
        .expect("transfer proving");
    println!("prove_coin_transfer: {:?}", t.elapsed());

    let t = Instant::now();
    let redeem =
        prove_redeem(&asset_id(), &(outputs[1], osk(0x88)), &transfer, 1).expect("redeem proving");
    println!("prove_redeem (transfer predecessor): {:?}", t.elapsed());
    println!("redeem proof size: {} bytes", proof_size(&redeem));

    assert_eq!(redeem.statement.value, 30);
    assert_eq!(
        redeem.statement.nullifiers[0],
        outputs[1].nullifier(&osk(0x88))
    );

    let t = Instant::now();
    verify_redeem(&redeem.statement, &redeem).expect("redeem verification");
    println!("verify_redeem: {:?}", t.elapsed());
}
