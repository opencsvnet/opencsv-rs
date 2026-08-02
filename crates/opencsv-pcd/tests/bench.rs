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
    prove_coin_transfer, prove_genesis_mint, prove_redeem, verify_coin_proof, verify_redeem,
    CoinProof,
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
}

fn report(rows: &[Row]) {
    println!("\n| circuit | prove | verify | proof size |");
    println!("|---|---|---|---|");
    for r in rows {
        println!(
            "| {} | {:.2?} | {:.2?} | {} B |",
            r.name, r.prove, r.verify, r.size
        );
    }
}

/// One measurement per circuit, single-shot (each row costs a full
/// recursive proof; warm-up effects are dwarfed by proving time).
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
    rows.push(Row {
        name: "genesis mint",
        prove,
        verify: t.elapsed(),
        size: proof_size(&mint),
    });

    // Transfer, hop 1 (2 in-circuit verifications of mint proofs).
    let inputs1 = [(coins[0], osk(0x22)), (coins[1], osk(0x44))];
    let outputs1 = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];
    let t = Instant::now();
    let t1 = prove_coin_transfer(&asset_id(), &inputs1, &outputs1, [&mint, &mint], [0, 1])
        .expect("hop-1 transfer proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&t1.statement, &t1).expect("hop-1 verification");
    rows.push(Row {
        name: "transfer (2 mint predecessors)",
        prove,
        verify: t.elapsed(),
        size: proof_size(&t1),
    });

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
    rows.push(Row {
        name: "2-hop transfer (2 node predecessors)",
        prove,
        verify: t.elapsed(),
        size: proof_size(&t2),
    });

    // Redeem (1 in-circuit verification of a node predecessor).
    let t = Instant::now();
    let redeem =
        prove_redeem(&asset_id(), &(outputs2[0], osk(0x11)), &t2, 0).expect("redeem proving");
    let prove = t.elapsed();
    let t = Instant::now();
    verify_redeem(&redeem.statement, &redeem).expect("redeem verification");
    rows.push(Row {
        name: "redeem (1 node predecessor)",
        prove,
        verify: t.elapsed(),
        size: proof_size(&redeem),
    });

    report(&rows);
}
