//! Fast scripted flow (no proving): the full wallet state machine — keygen,
//! issuer init, mint/transfer/redeem consignments, receive + storage,
//! balance, audit, and double-spend rejection — driven with consignments
//! whose opaque proof bytes come from `opencsv_core::MockVerifier`.
//!
//! This exercises everything except real proof generation/verification; the
//! real-proof twin of this test is `tests/e2e.rs` (ignored by default — run
//! it in release, see that file).

use opencsv_cli::chain::FileAnchorChain;
use opencsv_cli::hexutil::to_hex;
use opencsv_cli::ops::{self, ReceiveReport, COIN_VK};
use opencsv_cli::store::{CoinStatus, Wallet};
use opencsv_core::accept::{public_input, MockVerifier};
use opencsv_core::chain::AnchorChain;
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::{
    mint_commit, nullifier_commit, AnchorRecord, AssetGenesis, AssetId, Coin, Digest, OwnerSecret,
    RejectReason,
};

fn opening(coin: &Coin) -> CoinOpening {
    CoinOpening {
        asset_id: coin.asset_id,
        value: coin.value,
        owner: coin.owner,
        randomness: coin.randomness,
    }
}

fn coin(asset_id: AssetId, value: u64, osk: &OwnerSecret) -> Coin {
    Coin {
        asset_id,
        value,
        owner: osk.owner(),
        randomness: ops::random_digest(),
    }
}

/// Build a mock-proved consignment over an anchor record: append, then
/// `MockVerifier::prove` the reconstructed public input.
fn anchor_and_consignment(
    chain: &mut FileAnchorChain,
    record: AnchorRecord,
    openings: Vec<CoinOpening>,
    aux: Option<AssetGenesis>,
) -> (Consignment, opencsv_core::AnchorRef) {
    let anchor_ref = chain.append(record).unwrap();
    let x = public_input(&record, &openings);
    let consignment = Consignment {
        coin_openings: openings,
        proof: MockVerifier::prove(COIN_VK, &x),
        anchor_ref,
        aux,
    };
    (consignment, anchor_ref)
}

fn receive(
    wallet: &mut Wallet,
    chain: &FileAnchorChain,
    consignment: &Consignment,
    confirmations: u64,
) -> ReceiveReport {
    ops::receive(
        wallet,
        chain,
        &MockVerifier,
        &consignment.to_bytes(),
        confirmations,
    )
    .unwrap()
}

#[test]
fn scripted_flow_with_mock_proofs() {
    let tmp = tempfile::tempdir().unwrap();
    let chain_path = tmp.path().join("shared-chain.log");
    let mut chain = FileAnchorChain::open(&chain_path).unwrap();

    // --- issuer+alice wallet: keygen, issuer init.
    let mut alice = Wallet::open(tmp.path().join("alice")).unwrap();
    let owner_a = ops::keygen(&mut alice).unwrap();
    let osk_a = alice.secret_for(&owner_a).unwrap();
    let asset_id = ops::issuer_init(&mut alice, *b"USD").unwrap();
    let genesis = alice.find_genesis(&asset_id).unwrap().clone();

    // --- mint 60 + 40 to alice; anchor; advance 6.
    let coins_a = [coin(asset_id, 60, &osk_a), coin(asset_id, 40, &osk_a)];
    let nonce = ops::random_digest();
    let (mint_consignment, _) = anchor_and_consignment(
        &mut chain,
        AnchorRecord::Mint {
            asset_id: asset_id.to_anchor(),
            value: 100,
            mint_commit: mint_commit(&asset_id, 100, &nonce).to_anchor(),
        },
        coins_a.iter().map(opening).collect(),
        Some(genesis.clone()),
    );
    chain.advance_blocks(6).unwrap();

    // Alice receives: VERIFIED, coins stored unspent, balance 100.
    match receive(&mut alice, &chain, &mint_consignment, 6) {
        ReceiveReport::Verified { credits, coins, .. } => {
            assert_eq!(credits, vec![(asset_id, 100)]);
            assert_eq!(coins.len(), 2);
        }
        other => panic!("mint receive failed: {other:?}"),
    }
    assert_eq!(ops::balance(&alice, None), vec![(asset_id, 100)]);
    assert!(alice
        .coins()
        .iter()
        .all(|c| c.status == CoinStatus::Unspent));

    // Too few confirmations → rejected (proof is fine, depth is not).
    match receive(&mut alice, &chain, &mint_consignment, 100) {
        ReceiveReport::Rejected(RejectReason::InsufficientConfirmations { have, required }) => {
            assert_eq!((have, required), (7, 100));
        }
        other => panic!("expected InsufficientConfirmations, got {other:?}"),
    }

    // --- alice → bob transfer 70 + 30 (mock proof); mark alice spent.
    let mut bob = Wallet::open(tmp.path().join("bob")).unwrap();
    let owner_b = ops::keygen(&mut bob).unwrap();
    let osk_b = bob.secret_for(&owner_b).unwrap();
    let coins_b = [coin(asset_id, 70, &osk_b), coin(asset_id, 30, &osk_b)];
    let nullifiers: Vec<Digest> = coins_a.iter().map(|c| c.nullifier(&osk_a)).collect();
    let (transfer_consignment, transfer_ref) = anchor_and_consignment(
        &mut chain,
        AnchorRecord::XferCompressed {
            nullifier_commit: nullifier_commit(&nullifiers).to_anchor(),
        },
        coins_b.iter().map(opening).collect(),
        Some(genesis.clone()),
    );
    chain.advance_blocks(6).unwrap();
    for c in alice.coins().iter().map(|c| c.id()).collect::<Vec<_>>() {
        alice.mark_spent(&c).unwrap();
    }
    assert_eq!(ops::balance(&alice, None), vec![]);

    // Bob (fresh wallet, asset arrives via aux) receives: VERIFIED.
    match receive(&mut bob, &chain, &transfer_consignment, 6) {
        ReceiveReport::Verified { credits, coins, .. } => {
            assert_eq!(credits, vec![(asset_id, 100)]);
            assert_eq!(coins.len(), 2);
        }
        other => panic!("transfer receive failed: {other:?}"),
    }
    assert!(bob.find_genesis(&asset_id).is_some());
    assert_eq!(ops::balance(&bob, Some(&asset_id)), vec![(asset_id, 100)]);

    // --- bob redeems the 70 coin; audit shows 100 − 70 = 30.
    let coin_b1 = bob
        .coins()
        .iter()
        .find(|c| c.coin.value == 70)
        .unwrap()
        .clone();
    let nf_b1 = coin_b1.coin.nullifier(&osk_b);
    let _redeem_ref = chain
        .append(AnchorRecord::Redeem {
            asset_id: asset_id.to_anchor(),
            value: 70,
            nullifier: nf_b1.to_anchor(),
        })
        .unwrap();
    chain.advance_blocks(6).unwrap();
    bob.mark_spent(&coin_b1.id()).unwrap();
    assert_eq!(ops::balance(&bob, None), vec![(asset_id, 30)]);
    assert_eq!(ops::audit(&chain, &asset_id, None).unwrap(), 30);
    assert_eq!(ops::audit(&chain, &asset_id, Some(0)).unwrap(), 100);

    // --- double-spend: alice re-anchors the same nullifiers to carol; the
    // (mock) proof verifies, but first occurrence wins (paper §4.7 rule 1).
    let mut carol = Wallet::open(tmp.path().join("carol")).unwrap();
    let owner_c = ops::keygen(&mut carol).unwrap();
    let osk_c = carol.secret_for(&owner_c).unwrap();
    let coins_c = [coin(asset_id, 99, &osk_c), coin(asset_id, 1, &osk_c)];
    let (double_consignment, _) = anchor_and_consignment(
        &mut chain,
        AnchorRecord::XferCompressed {
            nullifier_commit: nullifier_commit(&nullifiers).to_anchor(),
        },
        coins_c.iter().map(opening).collect(),
        Some(genesis),
    );
    chain.advance_blocks(6).unwrap();

    match receive(&mut carol, &chain, &double_consignment, 6) {
        ReceiveReport::Rejected(RejectReason::NullifierConflict { first, .. }) => {
            assert_eq!(first, transfer_ref.location);
        }
        other => panic!("expected NullifierConflict, got {other:?}"),
    }
    assert_eq!(ops::balance(&carol, None), vec![]);

    // The authoritative spend remains acceptable to bob (idempotent store).
    match receive(&mut bob, &chain, &transfer_consignment, 6) {
        ReceiveReport::Verified { .. } => {}
        other => panic!("authoritative spend no longer accepted: {other:?}"),
    }
    assert_eq!(ops::balance(&bob, None), vec![(asset_id, 30)]);

    // --- wallet persistence: reopen alice's wallet from disk.
    let alice2 = Wallet::open(alice.dir()).unwrap();
    assert_eq!(alice2.secrets().len(), 1);
    assert!(alice2.issuer_for(&asset_id).is_some());
    assert_eq!(alice2.coins().len(), 2);
    assert!(alice2.coins().iter().all(|c| c.status == CoinStatus::Spent));

    // The chain file shows both occurrences of the double-spent key.
    let key = nullifier_commit(&nullifiers).to_anchor();
    assert_eq!(chain.nullifier_occurrences(&key).len(), 2);
    println!(
        "fast flow ok: mint 100 → send 70+30 → redeem 70 → supply {} (chain {})",
        ops::audit(&chain, &asset_id, None).unwrap(),
        to_hex(&key.as_bytes()[..4])
    );
}
