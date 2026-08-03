//! Benchmarks (stage 4): prove time, verify time, and proof size for the
//! coin-proof circuits. Excluded from the default run; run with:
//!
//! ```text
//! cargo test -p opencsv-pcd --test bench -- --ignored --nocapture          # debug
//! cargo test -p opencsv-pcd --release --test bench -- --ignored --nocapture # release
//! ```
//!
//! Numbers are printed as a markdown table and transcribed into
//! `BENCHMARKS.md` (with the machine specs and build profile).

use std::time::Instant;

use opencsv_core::{AssetGenesis, Coin, Digest, OwnerSecret, PoseidonIssuerAuthorization};
use opencsv_pcd::{
    proof_security_report, prove_coin_transfer, prove_genesis_mint, prove_redeem,
    verify_coin_proof, verify_redeem, CoinProof, COIN_PROOF_PROFILE_ID,
};

const ISSUER_SECRET: [u8; 32] = [0x42; 32];

fn asset_genesis() -> AssetGenesis {
    AssetGenesis {
        issuer_pk: PoseidonIssuerAuthorization::public_key(&ISSUER_SECRET),
        currency_code: *b"USD",
        terms_hash: Digest::from_bytes([0x74; 32]),
        nonce: 1,
    }
}

fn asset_id() -> Digest {
    asset_genesis().asset_id()
}

fn osk(tag: u8) -> OwnerSecret {
    OwnerSecret::from_bytes([tag; 32])
}

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

struct Row {
    name: &'static str,
    prove: std::time::Duration,
    verify: std::time::Duration,
    size: usize,
    proven_bits: usize,
    adjusted_bits: usize,
    degree_bits: Vec<usize>,
}

fn report(rows: &[Row]) {
    println!("\nprofile: `{COIN_PROOF_PROFILE_ID}`");
    println!("\n| circuit | prove | verify | proof size | proven bits | union-adjusted bits | degree bits |");
    println!("|---|---|---|---|---|---|---|");
    for r in rows {
        println!(
            "| {} | {:.2?} | {:.2?} | {} B | {} | {} | `{:?}` |",
            r.name, r.prove, r.verify, r.size, r.proven_bits, r.adjusted_bits, r.degree_bits,
        );
    }
}

fn row(
    name: &'static str,
    prove: std::time::Duration,
    verify: std::time::Duration,
    proof: &CoinProof,
) -> Row {
    let security = proof_security_report(proof);
    Row {
        name,
        prove,
        verify,
        size: proof_size(proof),
        proven_bits: security.proven_bits,
        adjusted_bits: security.union_adjusted_bits,
        degree_bits: security.degree_bits,
    }
}

/// Cold and warm setup measurements for every production circuit shape.
#[test]
#[ignore = "benchmark: several full recursive proofs (minutes in debug)"]
fn coin_proof_benchmarks() {
    let mut rows = Vec::new();

    // Genesis mint (no predecessors).
    let coins = [coin(60, 0x22, 0x33), coin(40, 0x44, 0x55)];
    let nonce = Digest::from_bytes([0xaa; 32]);
    let t = Instant::now();
    let mint =
        prove_genesis_mint(&asset_genesis(), &ISSUER_SECRET, &nonce, &coins).expect("mint proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&mint.statement, &mint).expect("mint verification");
    rows.push(row("genesis mint (cold)", prove, t.elapsed(), &mint));

    let t = Instant::now();
    let warm_mint = prove_genesis_mint(&asset_genesis(), &ISSUER_SECRET, &nonce, &coins)
        .expect("warm mint proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&warm_mint.statement, &warm_mint).expect("warm mint verification");
    rows.push(row("genesis mint (warm)", prove, t.elapsed(), &warm_mint));

    // Transfer, hop 1 (2 in-circuit verifications of mint proofs).
    let inputs1 = [(coins[0], osk(0x22)), (coins[1], osk(0x44))];
    let outputs1 = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];
    let t = Instant::now();
    let t1 = prove_coin_transfer(&asset_id(), &inputs1, &outputs1, [&mint, &mint], [0, 1])
        .expect("hop-1 transfer proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&t1.statement, &t1).expect("hop-1 verification");
    rows.push(row(
        "transfer / mint predecessors (cold)",
        prove,
        t.elapsed(),
        &t1,
    ));

    let t = Instant::now();
    let warm_t1 = prove_coin_transfer(&asset_id(), &inputs1, &outputs1, [&mint, &mint], [0, 1])
        .expect("warm hop-1 transfer proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&warm_t1.statement, &warm_t1).expect("warm hop-1 verification");
    rows.push(row(
        "transfer / mint predecessors (warm)",
        prove,
        t.elapsed(),
        &warm_t1,
    ));

    // Transfer, hop 2 (2 in-circuit verifications of node proofs — one
    // recursion level deeper).
    let inputs2 = [(outputs1[0], osk(0x66)), (outputs1[1], osk(0x88))];
    let outputs2 = [coin(50, 0x11, 0x12), coin(50, 0x13, 0x14)];
    let t = Instant::now();
    let t2 = prove_coin_transfer(&asset_id(), &inputs2, &outputs2, [&t1, &t1], [0, 1])
        .expect("hop-2 transfer proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&t2.statement, &t2).expect("hop-2 verification");
    rows.push(row(
        "transfer / node predecessors (cold)",
        prove,
        t.elapsed(),
        &t2,
    ));

    let t = Instant::now();
    let warm_t2 = prove_coin_transfer(&asset_id(), &inputs2, &outputs2, [&t1, &t1], [0, 1])
        .expect("warm hop-2 transfer proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&warm_t2.statement, &warm_t2).expect("warm hop-2 verification");
    rows.push(row(
        "transfer / node predecessors (warm)",
        prove,
        t.elapsed(),
        &warm_t2,
    ));

    // Redeem (1 in-circuit verification of a node predecessor).
    let t = Instant::now();
    let redeem =
        prove_redeem(&asset_id(), &(outputs2[0], osk(0x11)), &t2, 0).expect("redeem proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_redeem(&redeem.statement, &redeem).expect("redeem verification");
    rows.push(row("redeem (cold)", prove, t.elapsed(), &redeem));

    let t = Instant::now();
    let warm_redeem =
        prove_redeem(&asset_id(), &(outputs2[0], osk(0x11)), &t2, 0).expect("warm redeem proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_redeem(&warm_redeem.statement, &warm_redeem).expect("warm redeem verification");
    rows.push(row("redeem (warm)", prove, t.elapsed(), &warm_redeem));

    report(&rows);
}
