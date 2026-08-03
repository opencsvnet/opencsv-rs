//! Acceptance test (paper §4 end-to-end): the full OpenCSV protocol flow
//! with **real recursive proofs** plugged into `opencsv-core`'s `accept`
//! driver — no `MockVerifier` anywhere.
//!
//! Flow:
//!
//! 1. Poseidon issuer key commitment and asset genesis; the mint proof
//!    proves issuer control inside the AIR.
//! 2. Genesis mint (2 coins to user A) → MINT anchor on `MockAnchorChain`
//!    → consignment to A → `accept()` with the real `CoinProofVerifier`.
//! 3. A → B transfer (2-in/2-out, two in-circuit predecessor verifications)
//!    → XFER anchor → consignment to B → `accept()` by B.
//! 4. Double-spend: A transfers the *same* two coins again to an attacker
//!    address and anchors it later — the proof is valid, but `accept()`
//!    rejects it with `NullifierConflict` (first occurrence wins, paper
//!    §4.7 rule 1); B's original consignment still verifies afterwards.
//! 5. B redeems one coin → REDEEM anchor → the redeem proof verifies
//!    through the same `CoinProofVerifier` adapter.
//! 6. `audit::supply` equals mint − redeem at every checked height.
//!
//! Slow (~4 min in debug: one mint, two transfers, one redeem), so it is
//! excluded from the default `cargo test -p opencsv-pcd` run. Run it with:
//!
//! ```text
//! cargo test -p opencsv-pcd --test acceptance -- --ignored --nocapture
//! ```

use opencsv_core::accept::{accept, public_input, AcceptParams, ProofVerifier};
use opencsv_core::anchor::{mint_commit, AnchorRecord};
use opencsv_core::asset::AssetGenesis;
use opencsv_core::audit::supply;
use opencsv_core::chain::{AnchorChain, MockAnchorChain};
use opencsv_core::coin::{Coin, OwnerSecret};
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::digest::Digest;
use opencsv_core::issuer::PoseidonIssuerAuthorization;
use opencsv_core::RejectReason;
use opencsv_pcd::{
    encode_coin_proof, prove_coin_transfer, prove_genesis_mint, prove_redeem, CoinProofVerifier,
};

/// Frozen production lineage/profile tag carried in `AcceptParams`.
const VK: &[u8] = opencsv_pcd::COIN_VK_TAG;

fn osk(tag: u8) -> OwnerSecret {
    OwnerSecret::from_bytes([tag; 32])
}

fn opening(coin: &Coin) -> CoinOpening {
    CoinOpening {
        asset_id: coin.asset_id,
        value: coin.value,
        owner: coin.owner,
        randomness: coin.randomness,
    }
}

#[test]
#[ignore = "acceptance test: four full recursive proofs (~4 min in debug)"]
fn full_protocol_flow_with_real_proofs() {
    // --- 1. Issuer keygen and asset genesis (paper §4.2).
    let (isk, ipk) = PoseidonIssuerAuthorization::keypair_from_seed([0x42; 32]);
    let genesis = AssetGenesis {
        issuer_pk: ipk,
        currency_code: *b"USD",
        terms_hash: Digest::from_bytes([0x74; 32]),
        nonce: 1,
    };
    let asset_id = genesis.asset_id();

    let mut chain = MockAnchorChain::new();

    // --- 2. Mint 100 units as two coins owned by A (60 + 40).
    let osk_a = osk(0xa1);
    let coin_a1 = Coin {
        asset_id,
        value: 60,
        owner: osk_a.owner(),
        randomness: Digest::from_bytes([0x01; 32]),
    };
    let coin_a2 = Coin {
        asset_id,
        value: 40,
        owner: osk_a.owner(),
        randomness: Digest::from_bytes([0x02; 32]),
    };
    let mint_nonce = Digest::from_bytes([0xaa; 32]);

    let mint = prove_genesis_mint(&genesis, &isk, &mint_nonce, &[coin_a1, coin_a2])
        .expect("issuer-authorized mint proving");
    let mint_ref = chain.append(AnchorRecord::Mint {
        asset_id: asset_id.to_anchor(),
        value: 100,
        mint_commit: mint_commit(&asset_id, 100, &mint_nonce).to_anchor(),
    });
    chain.advance_blocks(6);
    let mint_height = mint_ref.location.height;
    assert_eq!(supply(&chain, &asset_id, mint_height), Ok(100));

    // Consignment to A → accept with the real verifier.
    let mint_consignment = Consignment {
        coin_openings: vec![opening(&coin_a1), opening(&coin_a2)],
        nullifiers: vec![],
        proof: encode_coin_proof(&mint),
        anchor_ref: mint_ref,
        aux: Some(genesis.clone()),
    };
    let accepted = accept(
        &mint_consignment,
        &chain,
        &CoinProofVerifier,
        &AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: &[osk_a],
            known_assets: &[],
        },
    )
    .expect("A accepts the mint consignment");
    assert_eq!(accepted.coins, vec![coin_a1, coin_a2]);

    let wrong_profile = accept(
        &mint_consignment,
        &chain,
        &CoinProofVerifier,
        &AcceptParams {
            vk: b"opencsv-pcd-coin-v2",
            required_confirmations: 6,
            recipient_secrets: &[osk_a],
            known_assets: &[],
        },
    )
    .expect_err("a legacy proof-profile tag must fail closed");
    assert_eq!(wrong_profile, RejectReason::InvalidProof);

    // --- 3. A → B transfer: 2-in/2-out (70 to B, 30 to B), two in-circuit
    // predecessor verifications of the mint proof.
    let osk_b = osk(0xb1);
    let coin_b1 = Coin {
        asset_id,
        value: 70,
        owner: osk_b.owner(),
        randomness: Digest::from_bytes([0x03; 32]),
    };
    let coin_b2 = Coin {
        asset_id,
        value: 30,
        owner: osk_b.owner(),
        randomness: Digest::from_bytes([0x04; 32]),
    };
    let transfer = prove_coin_transfer(
        &asset_id,
        &[(coin_a1, osk_a), (coin_a2, osk_a)],
        &[coin_b1, coin_b2],
        [&mint, &mint],
        [0, 1],
    )
    .expect("transfer proving");
    let transfer_ctx = chain.fresh_ctx();
    let transfer_ref = chain.append_with_ctx(
        AnchorRecord::xfer(&transfer.statement.nullifiers, &transfer_ctx),
        transfer_ctx,
    );
    chain.advance_blocks(6);
    let transfer_height = transfer_ref.location.height;
    // Shielded transfers neither create nor destroy value.
    assert_eq!(supply(&chain, &asset_id, transfer_height), Ok(100));

    let transfer_consignment = Consignment {
        coin_openings: vec![opening(&coin_b1), opening(&coin_b2)],
        nullifiers: transfer.statement.nullifiers.to_vec(),
        proof: encode_coin_proof(&transfer),
        anchor_ref: transfer_ref,
        aux: None,
    };
    let accepted = accept(
        &transfer_consignment,
        &chain,
        &CoinProofVerifier,
        &AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: &[osk_b],
            known_assets: &[asset_id],
        },
    )
    .expect("B accepts the transfer consignment");
    assert_eq!(accepted.coins, vec![coin_b1, coin_b2]);

    // --- 4. Double-spend: A transfers the same two coins again (to an
    // attacker address) and anchors it *later*. The proof itself is valid —
    // the rejection comes from nullifier first-occurrence (§4.7 rule 1).
    let osk_eve = osk(0xee);
    let coin_e1 = Coin {
        asset_id,
        value: 99,
        owner: osk_eve.owner(),
        randomness: Digest::from_bytes([0x05; 32]),
    };
    let coin_e2 = Coin {
        asset_id,
        value: 1,
        owner: osk_eve.owner(),
        randomness: Digest::from_bytes([0x06; 32]),
    };
    let double_spend = prove_coin_transfer(
        &asset_id,
        &[(coin_a1, osk_a), (coin_a2, osk_a)],
        &[coin_e1, coin_e2],
        [&mint, &mint],
        [0, 1],
    )
    .expect("double-spend proving (the circuit cannot see the chain)");
    // Same consumed coins → same raw nullifiers (recognized off-chain via
    // the consignment) — but the on-chain payloads differ, being bound to
    // different ctxs.
    assert_eq!(
        double_spend.statement.nullifiers,
        transfer.statement.nullifiers
    );
    let double_ctx = chain.fresh_ctx();
    let double_ref = chain.append_with_ctx(
        AnchorRecord::xfer(&double_spend.statement.nullifiers, &double_ctx),
        double_ctx,
    );
    chain.advance_blocks(6);

    let double_consignment = Consignment {
        coin_openings: vec![opening(&coin_e1), opening(&coin_e2)],
        nullifiers: double_spend.statement.nullifiers.to_vec(),
        proof: encode_coin_proof(&double_spend),
        anchor_ref: double_ref,
        aux: None,
    };
    let err = accept(
        &double_consignment,
        &chain,
        &CoinProofVerifier,
        &AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: &[osk_eve],
            known_assets: &[asset_id],
        },
    )
    .expect_err("the double-spend must be rejected");
    assert_eq!(
        err,
        RejectReason::NullifierConflict {
            nullifier: transfer.statement.nullifiers[0].to_anchor(),
            first: transfer_ref.location,
        }
    );
    // First occurrence wins: B's original consignment still verifies.
    accept(
        &transfer_consignment,
        &chain,
        &CoinProofVerifier,
        &AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: &[osk_b],
            known_assets: &[asset_id],
        },
    )
    .expect("the authoritative spend remains acceptable");

    // --- 5. B redeems coin_b1 (70 units) back to the issuer.
    let redeem = prove_redeem(&asset_id, &(coin_b1, osk_b), &transfer, 0).expect("redeem proving");
    let redeem_ctx = chain.fresh_ctx();
    let redeem_ref = chain.append_with_ctx(
        AnchorRecord::redeem(
            asset_id.to_anchor(),
            70,
            &redeem.statement.nullifiers[0],
            &redeem_ctx,
        ),
        redeem_ctx,
    );
    chain.advance_blocks(6);
    let redeem_height = redeem_ref.location.height;

    // The redeem proof verifies through the same adapter (a redeem
    // consignment carries no openings; the check is issuer-side).
    let record = chain.anchor_at(&redeem_ref).expect("redeem anchor exists");
    let ctx = chain.ctx_at(&redeem_ref).expect("redeem anchor ctx exists");
    let x = public_input(&record, &ctx, &[]);
    assert!(CoinProofVerifier.verify(VK, &x, &encode_coin_proof(&redeem)));

    // --- 6. Supply audit: mint − redeem at every height (paper §4.9).
    assert_eq!(supply(&chain, &asset_id, mint_height), Ok(100));
    assert_eq!(supply(&chain, &asset_id, transfer_height), Ok(100));
    assert_eq!(supply(&chain, &asset_id, redeem_height), Ok(30));
    assert_eq!(supply(&chain, &asset_id, chain.tip_height()), Ok(30));

    println!("acceptance test passed: mint 100 → transfer → redeem 70 → supply 30");
}
