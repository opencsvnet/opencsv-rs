//! End-to-end CLI-wallet flow with **real recursive proofs**, across three
//! wallet dirs (issuer+alice, bob, carol) sharing one `FileAnchorChain` file:
//!
//! keygen → issuer init → mint to alice → alice receive (VERIFIED) →
//! alice send to bob → bob receive (VERIFIED) → bob redeem → audit →
//! double-spend of alice's spent coins to carol → REJECTED NullifierConflict.
//!
//! Driven through the library API (what a transport crate would call); the
//! proving is real, so this is **slow in debug (~4 min)** and excluded from
//! the default test run. Run it (fast, ~15 s) in release with:
//!
//! ```text
//! cargo test --release -p opencsv-cli --test e2e -- --ignored --nocapture
//! ```

use std::time::Instant;

use opencsv_cli::chain::FileAnchorChain;
use opencsv_cli::ops::{self, ReceiveReport, COIN_VK};
use opencsv_cli::store::Wallet;
use opencsv_core::accept::{public_input, ProofVerifier};
use opencsv_core::chain::AnchorChain;
use opencsv_core::{AssetId, Owner, RejectReason};
use opencsv_pcd::CoinProofVerifier;

fn timed<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    println!("{what}: {:?}", start.elapsed());
    out
}

fn verified(report: ReceiveReport) -> Vec<(AssetId, u64)> {
    match report {
        ReceiveReport::Verified { credits, .. } => credits,
        other => panic!("expected VERIFIED, got {other:?}"),
    }
}

#[test]
#[ignore = "real recursive proofs: ~4 min in debug; run in release (see header)"]
fn full_cli_flow_with_real_proofs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut chain = FileAnchorChain::open(tmp.path().join("shared-chain.log")).unwrap();
    let mut alice = Wallet::open(tmp.path().join("alice")).unwrap();
    let mut bob = Wallet::open(tmp.path().join("bob")).unwrap();
    let mut carol = Wallet::open(tmp.path().join("carol")).unwrap();

    // keygen + issuer init.
    let owner_a = ops::keygen(&mut alice).unwrap();
    let owner_b = ops::keygen(&mut bob).unwrap();
    let owner_c: Owner = ops::keygen(&mut carol).unwrap();
    let asset_id = ops::issuer_init(&mut alice, *b"USD").unwrap();
    println!(
        "asset {}",
        opencsv_cli::hexutil::to_hex(asset_id.as_bytes())
    );

    // --- mint 60+40 to alice; alice receives.
    let mint = timed("prove mint (60+40)", || {
        ops::mint(&mut alice, &mut chain, &asset_id, owner_a, &[60, 40]).unwrap()
    });
    chain.advance_blocks(6).unwrap();
    let report = timed("verify mint", || {
        ops::receive(
            &mut alice,
            &chain,
            &CoinProofVerifier,
            &mint.consignment.to_bytes(),
            6,
        )
        .unwrap()
    });
    assert_eq!(verified(report), vec![(asset_id, 100)]);
    assert_eq!(ops::balance(&alice, None), vec![(asset_id, 100)]);

    // --- alice sends 70+30 to bob; bob receives.
    let input_ids: Vec<String> = alice.coins().iter().map(|c| c.id()).collect();
    let transfer = timed("prove transfer (70+30)", || {
        ops::send(
            &mut alice,
            &mut chain,
            &input_ids,
            owner_b,
            &[70, 30],
            false,
        )
        .unwrap()
    });
    chain.advance_blocks(6).unwrap();
    let report = timed("verify transfer", || {
        ops::receive(
            &mut bob,
            &chain,
            &CoinProofVerifier,
            &transfer.consignment.to_bytes(),
            6,
        )
        .unwrap()
    });
    assert_eq!(verified(report), vec![(asset_id, 100)]);
    assert_eq!(ops::balance(&alice, None), vec![]);
    assert_eq!(ops::balance(&bob, None), vec![(asset_id, 100)]);
    // The spent inputs are marked spent locally.
    assert!(alice
        .coins()
        .iter()
        .all(|c| c.status == opencsv_cli::store::CoinStatus::Spent));

    // --- bob redeems the 70 coin; the issuer-side check uses the same
    // CoinProofVerifier adapter over the (openings-less) redeem blob.
    let coin_b1 = bob
        .coins()
        .iter()
        .find(|c| c.coin.value == 70)
        .unwrap()
        .id();
    let redeem = timed("prove redeem (70)", || {
        ops::redeem(&mut bob, &mut chain, &coin_b1).unwrap()
    });
    chain.advance_blocks(6).unwrap();
    let record = chain.anchor_at(&redeem.anchor).unwrap();
    let ctx = chain.ctx_at(&redeem.anchor).unwrap();
    let x = public_input(&record, &ctx, &[]);
    assert!(timed("verify redeem (issuer side)", || {
        CoinProofVerifier.verify(COIN_VK, &x, &redeem.consignment.proof)
    }));
    assert_eq!(ops::balance(&bob, None), vec![(asset_id, 30)]);

    // --- audit: supply is mint − redeem at every height.
    assert_eq!(ops::audit(&chain, &asset_id, Some(0)).unwrap(), 100);
    assert_eq!(ops::audit(&chain, &asset_id, None).unwrap(), 30);

    // --- double-spend: alice re-spends her (spent) mint coins to carol.
    // Proving succeeds (the circuit cannot see the chain); receive rejects.
    let double = timed("prove double-spend (99+1)", || {
        ops::send(&mut alice, &mut chain, &input_ids, owner_c, &[99, 1], true).unwrap()
    });
    chain.advance_blocks(6).unwrap();
    let report = timed("verify double-spend (rejected)", || {
        ops::receive(
            &mut carol,
            &chain,
            &CoinProofVerifier,
            &double.consignment.to_bytes(),
            6,
        )
        .unwrap()
    });
    match report {
        ReceiveReport::Rejected(RejectReason::NullifierConflict { first, .. }) => {
            assert_eq!(first, transfer.anchor.location);
        }
        other => panic!("expected NullifierConflict, got {other:?}"),
    }
    assert_eq!(ops::balance(&carol, None), vec![]);

    // The authoritative spend is unaffected.
    let report = timed("re-verify bob's transfer", || {
        ops::receive(
            &mut bob,
            &chain,
            &CoinProofVerifier,
            &transfer.consignment.to_bytes(),
            6,
        )
        .unwrap()
    });
    assert_eq!(verified(report), vec![(asset_id, 100)]);

    println!("e2e ok: mint 100 → send 70+30 → redeem 70 → supply 30; double-spend rejected");
}
