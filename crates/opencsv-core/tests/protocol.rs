//! Protocol-level tests for opencsv-core, mirroring paper §4.

use opencsv_core::accept::{accept, public_input};
use opencsv_core::*;

const VK: &[u8] = b"opencsv-test-vk";

fn byte_seed(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn genesis() -> AssetGenesis {
    let (_, pk) = Ed25519IssuerSignature::keypair_from_seed(byte_seed(1));
    AssetGenesis {
        issuer_pk: pk,
        currency_code: *b"USD",
        terms_hash: Digest::from_bytes(byte_seed(2)),
        nonce: 7,
    }
}

fn secret(seed: u8) -> OwnerSecret {
    OwnerSecret::from_bytes(byte_seed(seed))
}

fn opening_for(asset_id: AssetId, value: u64, owner_seed: u8, r_seed: u8) -> CoinOpening {
    CoinOpening {
        asset_id,
        value,
        owner: secret(owner_seed).owner(),
        randomness: Digest::from_bytes(byte_seed(r_seed)),
    }
}

fn params<'a>(secrets: &'a [OwnerSecret], known: &'a [AssetId]) -> AcceptParams<'a> {
    AcceptParams {
        vk: VK,
        required_confirmations: 6,
        recipient_secrets: secrets,
        known_assets: known,
    }
}

/// Build a consignment whose mock proof matches the given chain anchor.
/// `nullifiers` are the raw nullifiers of the consumed coins (empty for
/// mints) — they travel only off-chain, in the consignment.
fn consignment_for(
    chain: &MockAnchorChain,
    anchor_ref: AnchorRef,
    nullifiers: Vec<Digest>,
    openings: Vec<CoinOpening>,
    aux: Option<AssetGenesis>,
) -> Consignment {
    let record = chain.anchor_at(&anchor_ref).unwrap();
    let ctx = chain.ctx_at(&anchor_ref).unwrap();
    let x = public_input(&record, &ctx, &openings);
    Consignment {
        coin_openings: openings,
        nullifiers,
        proof: MockVerifier::prove(VK, &x),
        anchor_ref,
        aux,
    }
}

// --- Round-trip / determinism (§4.2–4.3) ------------------------------------

#[test]
fn genesis_asset_id_is_stable() {
    assert_eq!(genesis().asset_id(), genesis().asset_id());
    let mut other = genesis();
    other.nonce = 8;
    assert_ne!(genesis().asset_id(), other.asset_id());
    other = genesis();
    other.currency_code = *b"EUR";
    assert_ne!(genesis().asset_id(), other.asset_id());
}

#[test]
fn coin_commitment_and_nullifier_are_deterministic() {
    let asset_id = genesis().asset_id();
    let coin = Coin {
        asset_id,
        value: 100,
        owner: secret(3).owner(),
        randomness: Digest::from_bytes(byte_seed(4)),
    };
    assert_eq!(coin.commitment(), coin.commitment());
    assert_eq!(coin.nullifier(&secret(3)), coin.nullifier(&secret(3)));

    // Hiding: different randomness → different commitment.
    let mut coin2 = coin;
    coin2.randomness = Digest::from_bytes(byte_seed(5));
    assert_ne!(coin.commitment(), coin2.commitment());

    // Nullifier is computable only under the owner's secret.
    assert_ne!(coin.nullifier(&secret(3)), coin.nullifier(&secret(9)));
}

#[test]
fn owner_derivation_matches_hash_of_secret() {
    let osk = secret(3);
    assert_eq!(osk.owner(), osk.owner());
    assert_ne!(osk.owner(), secret(4).owner());
}

#[test]
fn issuer_signature_round_trip() {
    let (sk, pk) = Ed25519IssuerSignature::keypair_from_seed(byte_seed(1));
    let msg = mint_signing_message(
        &genesis().asset_id(),
        100,
        &Digest::from_bytes(byte_seed(6)),
    );
    let sig = Ed25519IssuerSignature::sign(&sk, &msg);
    assert!(Ed25519IssuerSignature::verify(&pk, &msg, &sig));

    let mut bad = msg.clone();
    bad[20] ^= 1;
    assert!(!Ed25519IssuerSignature::verify(&pk, &bad, &sig));
    let (_, other_pk) = Ed25519IssuerSignature::keypair_from_seed(byte_seed(9));
    assert!(!Ed25519IssuerSignature::verify(&other_pk, &msg, &sig));
}

// --- Anchor records (§4.4–4.6) ----------------------------------------------

/// Raw-digest helper (nullifiers, contexts live off-chain as full digests).
fn d(seed: u8) -> Digest {
    Digest::from_bytes(byte_seed(seed))
}

fn td(seed: u8) -> TruncatedDigest {
    d(seed).to_anchor()
}

/// Pick (deterministically) a ctx whose bound payload for `raw` avoids the
/// MINT/REDEEM tag bytes, so the record round-trips through `from_bytes`.
fn non_colliding_ctx(raw: &Digest) -> [u8; 32] {
    for s in 0u8..=255 {
        let ctx = byte_seed(s);
        let p = anchor::binding(raw, &ctx).to_anchor();
        if p.as_bytes()[0] != 0x01 && p.as_bytes()[0] != 0x04 {
            return ctx;
        }
    }
    panic!("no non-colliding ctx found");
}

/// A well-formed XFER record over `nfs` and the ctx it is bound to.
fn xfer_for(chain: &MockAnchorChain, nfs: &[Digest]) -> (AnchorRecord, [u8; 32]) {
    let ctx = chain.fresh_ctx();
    (AnchorRecord::xfer(nfs, &ctx), ctx)
}

#[test]
fn anchor_records_are_64_bytes_and_round_trip() {
    let ctx = non_colliding_ctx(&d(3));
    let records = [
        AnchorRecord::Mint {
            asset_id: td(1),
            value: u64::MAX,
            mint_commit: td(2),
        },
        AnchorRecord::xfer(&[d(3)], &ctx),
        AnchorRecord::xfer(&[d(3), d(8)], &ctx),
        AnchorRecord::redeem(td(5), 42, &d(6), &ctx),
    ];
    for record in records {
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), ANCHOR_SIZE);
        assert_eq!(AnchorRecord::from_bytes(&bytes), record);
    }
    // XFER and XFERC share one untagged layout (camouflage): a compressed
    // record parses back as `Xfer` over the same payload bytes (slot 1 = 0).
    let ctx = non_colliding_ctx(&d(13));
    let compressed = AnchorRecord::xfer_compressed(&d(13), &ctx);
    let bytes = compressed.to_bytes();
    assert_eq!(bytes.len(), ANCHOR_SIZE);
    assert_eq!(
        AnchorRecord::from_bytes(&bytes),
        AnchorRecord::Xfer {
            payloads: [
                anchor::binding(&d(13), &ctx).to_anchor(),
                TruncatedDigest([0u8; 24])
            ],
        }
    );
}

#[test]
fn anchor_parse_tagged_vs_untagged() {
    let ctx = non_colliding_ctx(&d(3));
    // Tagged MINT/REDEEM parse unchanged.
    let mint = AnchorRecord::Mint {
        asset_id: td(1),
        value: 7,
        mint_commit: td(2),
    };
    assert_eq!(AnchorRecord::from_bytes(&mint.to_bytes()), mint);
    let redeem = AnchorRecord::redeem(td(5), 42, &d(6), &ctx);
    assert_eq!(AnchorRecord::from_bytes(&redeem.to_bytes()), redeem);

    // Any other first byte is an untagged transfer candidate — parsing never
    // fails (arbitrary OP_RETURN traffic must parse, see module docs).
    let mut bytes = AnchorRecord::xfer(&[d(3)], &ctx).to_bytes();
    bytes[0] = 0x7f;
    assert!(matches!(
        AnchorRecord::from_bytes(&bytes),
        AnchorRecord::Xfer { .. }
    ));
    // A tag-first record whose padding is invalid is not a valid MINT/REDEEM:
    // it, too, parses as an untagged transfer candidate.
    let mut bytes = mint.to_bytes();
    bytes[63] = 1;
    assert!(matches!(
        AnchorRecord::from_bytes(&bytes),
        AnchorRecord::Xfer { .. }
    ));
    let mut bytes = redeem.to_bytes();
    bytes[63] = 1;
    assert!(matches!(
        AnchorRecord::from_bytes(&bytes),
        AnchorRecord::Xfer { .. }
    ));
}

#[test]
fn binding_binds_payload_to_raw_nf_and_ctx() {
    let ctx_a = byte_seed(31);
    let ctx_b = byte_seed(32);

    // Well-formedness is relative to a raw_nf supplied by the verifier.
    let xfer = AnchorRecord::xfer(&[d(3)], &ctx_a);
    assert!(xfer.well_formed(&ctx_a, &d(3)));
    assert!(!xfer.well_formed(&ctx_b, &d(3))); // wrong ctx
    assert!(!xfer.well_formed(&ctx_a, &d(8))); // wrong raw_nf

    // A 2-input XFER recognizes each of its nullifiers.
    let xfer2 = AnchorRecord::xfer(&[d(3), d(8)], &ctx_a);
    assert!(xfer2.well_formed(&ctx_a, &d(3)));
    assert!(xfer2.well_formed(&ctx_a, &d(8)));
    assert!(!xfer2.well_formed(&ctx_a, &d(9)));

    // XFERC recognizes the nullifier *commitment*, not the raw nullifiers.
    let nfs = [d(3), d(8), d(9)];
    let commit = nullifier_commit(&nfs);
    let compressed = AnchorRecord::xfer_compressed(&commit, &ctx_a);
    assert!(compressed.well_formed(&ctx_a, &commit));
    assert!(!compressed.well_formed(&ctx_a, &d(3)));

    let redeem = AnchorRecord::redeem(td(5), 42, &d(6), &ctx_a);
    assert!(redeem.well_formed(&ctx_a, &d(6)));
    assert!(!redeem.well_formed(&ctx_b, &d(6)));

    // Mints carry no payload: never an occurrence of anything.
    let mint = AnchorRecord::Mint {
        asset_id: td(1),
        value: 7,
        mint_commit: td(2),
    };
    assert!(!mint.well_formed(&ctx_a, &d(3)));

    // The binding commits to both halves of its input.
    assert_ne!(
        anchor::binding(&d(3), &ctx_a),
        anchor::binding(&d(8), &ctx_a)
    );
    assert_ne!(
        anchor::binding(&d(3), &ctx_a),
        anchor::binding(&d(3), &ctx_b)
    );
}

// --- Mock chain (§4.7) --------------------------------------------------------

#[test]
fn mock_chain_first_occurrence_and_double_spend() {
    let mut chain = MockAnchorChain::new();
    let nf = d(7);
    let (record_a, ctx_a) = xfer_for(&chain, &[nf]);
    let first = chain.append_with_ctx(record_a, ctx_a);
    chain.advance_blocks(1);
    // A genuine double-spend: a second record binding the same raw nf under
    // its own ctx — the on-chain payloads DIFFER, but raw-nf recognition
    // still links them.
    let (record_b, ctx_b) = xfer_for(&chain, &[nf]);
    let second = chain.append_with_ctx(record_b, ctx_b);
    assert_ne!(record_a, record_b);

    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    assert_eq!(
        chain.nullifier_occurrences(&nf),
        vec![first.location, second.location]
    );
    // The second occurrence is flagged: it is not the authoritative spend.
    assert_ne!(chain.first_nullifier_occurrence(&nf), Some(second.location));
}

#[test]
fn mock_chain_copies_and_forgeries_are_not_occurrences() {
    let mut chain = MockAnchorChain::new();
    let nf = d(7);
    let ctx = chain.fresh_ctx();
    let record = AnchorRecord::xfer(&[nf], &ctx);
    let first = chain.append_with_ctx(record, ctx);
    chain.advance_blocks(1);

    // Copy-grief: the byte-identical record re-anchored under a DIFFERENT
    // ctx. The payload is bound to the victim's ctx, so the copy is not an
    // occurrence of nf under the copier's ctx.
    let grief_ctx = chain.fresh_ctx();
    let grief_ref = chain.append_with_ctx(record, grief_ctx);
    assert!(!record.well_formed(&grief_ctx, &nf));
    // Forge attempt without raw_nf: the spy sees only the bound payload and
    // cannot rebind it; a record built from a guessed payload is not an
    // occurrence either.
    let guess = AnchorRecord::Xfer {
        payloads: [td(99), TruncatedDigest([0u8; 24])],
    };
    chain.append_with_ctx(guess, chain.fresh_ctx());

    // The copy is stored and fetchable (with its ctx)…
    assert_eq!(chain.anchor_at(&grief_ref), Some(record));
    assert_eq!(chain.ctx_at(&grief_ref), Some(grief_ctx));
    // …but only the victim's anchor is an occurrence of the raw nullifier.
    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    assert_eq!(chain.nullifier_occurrences(&nf), vec![first.location]);
    // Occurrence recognition needs the raw nf: querying the on-chain
    // payload bytes as if they were a nullifier finds nothing.
    let payload_as_digest = {
        let mut b = [0u8; 32];
        b[..24].copy_from_slice(record.payload_slots()[0].as_bytes());
        Digest::from_bytes(b)
    };
    assert_eq!(chain.nullifier_occurrences(&payload_as_digest), vec![]);
}

#[test]
fn mock_chain_confirmation_depth() {
    let mut chain = MockAnchorChain::new();
    let (record, ctx) = xfer_for(&chain, &[d(8)]);
    let r = chain.append_with_ctx(record, ctx);
    assert_eq!(chain.confirmations_at(r.location.height), 1);
    chain.advance_blocks(5);
    assert_eq!(chain.confirmations_at(r.location.height), 6);
    assert_eq!(chain.confirmations_at(chain.tip_height() + 10), 0);
}

#[test]
fn mock_chain_lookup_by_txid_and_position() {
    let mut chain = MockAnchorChain::new();
    let record = AnchorRecord::Mint {
        asset_id: td(1),
        value: 10,
        mint_commit: td(2),
    };
    let r = chain.append(record);
    assert_eq!(chain.anchor_at(&r), Some(record));
    let mut wrong = r;
    wrong.txid[0] ^= 1;
    assert_eq!(chain.anchor_at(&wrong), None);
    let mut wrong = r;
    wrong.location.position = 99;
    assert_eq!(chain.anchor_at(&wrong), None);
}

// --- Accept driver (§4.8) ------------------------------------------------------

fn mint_anchor(chain: &mut MockAnchorChain, asset_id: &AssetId, value: u64) -> AnchorRef {
    chain.append(AnchorRecord::Mint {
        asset_id: asset_id.to_anchor(),
        value,
        mint_commit: mint_commit(asset_id, value, &Digest::from_bytes(byte_seed(6))).to_anchor(),
    })
}

#[test]
fn accept_mint_consignment_happy_path_with_genesis_aux() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, vec![], openings, Some(g));
    chain.advance_blocks(5); // → 6 confirmations

    let accepted = accept(
        &consignment,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[]),
    )
    .expect("valid mint consignment");
    assert_eq!(accepted.coins.len(), 1);
    assert_eq!(accepted.coins[0].value, 100);
    assert_eq!(accepted.anchor, anchor_ref.location);
}

#[test]
fn accept_transfer_consignment_happy_path() {
    let g = genesis();
    let asset_id = g.asset_id();
    // The spent coins (sender's), now being consumed.
    let spent = Coin {
        asset_id,
        value: 60,
        owner: secret(8).owner(),
        randomness: Digest::from_bytes(byte_seed(7)),
    };
    let nfs = vec![spent.nullifier(&secret(8))];

    let mut chain = MockAnchorChain::new();
    let (record, ctx) = xfer_for(&chain, &nfs);
    let anchor_ref = chain.append_with_ctx(record, ctx);
    let openings = vec![opening_for(asset_id, 60, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, nfs, openings, None);
    chain.advance_blocks(5);

    let accepted = accept(
        &consignment,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[asset_id]),
    )
    .expect("valid transfer consignment");
    assert_eq!(accepted.coins.len(), 1);
}

#[test]
fn accept_compressed_transfer_happy_path_and_double_spend() {
    let g = genesis();
    let asset_id = g.asset_id();
    let nfs = vec![d(31), d(32), d(33)];
    let commit = nullifier_commit(&nfs);

    let mut chain = MockAnchorChain::new();
    let ctx = chain.fresh_ctx();
    let anchor_ref = chain.append_with_ctx(AnchorRecord::xfer_compressed(&commit, &ctx), ctx);
    let openings = vec![opening_for(asset_id, 60, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, nfs.clone(), openings.clone(), None);
    chain.advance_blocks(5);

    accept(
        &consignment,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[asset_id]),
    )
    .expect("valid compressed-transfer consignment");

    // Re-anchoring the same nullifier list under a fresh ctx (a whole-batch
    // double-spend) is recognized under the commitment and rejected.
    let ctx2 = chain.fresh_ctx();
    let second_ref = chain.append_with_ctx(AnchorRecord::xfer_compressed(&commit, &ctx2), ctx2);
    let second = consignment_for(&chain, second_ref, nfs, openings, None);
    chain.advance_blocks(5);
    let err = accept(
        &second,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[asset_id]),
    )
    .unwrap_err();
    assert_eq!(
        err,
        RejectReason::NullifierConflict {
            nullifier: commit.to_anchor(),
            first: anchor_ref.location,
        }
    );
}

#[test]
fn accept_rejects_consignment_missing_a_nullifier() {
    let g = genesis();
    let asset_id = g.asset_id();
    let nfs = vec![d(41), d(42)];

    let mut chain = MockAnchorChain::new();
    let (record, ctx) = xfer_for(&chain, &nfs);
    let anchor_ref = chain.append_with_ctx(record, ctx);
    // The consignment lists only ONE of the two consumed nullifiers: the
    // record's second payload slot is unmatched — completeness fails.
    let openings = vec![opening_for(asset_id, 60, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, vec![nfs[0]], openings, None);
    chain.advance_blocks(5);

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[asset_id]),
        ),
        Err(RejectReason::IllFormedAnchor)
    );
}

#[test]
fn accept_rejects_bad_proof() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)];
    let mut consignment = consignment_for(&chain, anchor_ref, vec![], openings, Some(g));
    chain.advance_blocks(5);
    let n = consignment.proof.len();
    consignment.proof[n - 1] ^= 1; // corrupt the mock checksum

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[])
        ),
        Err(RejectReason::InvalidProof)
    );
}

#[test]
fn accept_rejects_unknown_anchor() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)];
    let mut consignment = consignment_for(&chain, anchor_ref, vec![], openings, Some(g));
    chain.advance_blocks(5);
    consignment.anchor_ref.location.position = 99;

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[])
        ),
        Err(RejectReason::AnchorNotFound)
    );
}

#[test]
fn accept_rejects_insufficient_confirmations() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, vec![], openings, Some(g));
    chain.advance_blocks(3); // only 4 confirmations

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[])
        ),
        Err(RejectReason::InsufficientConfirmations {
            have: 4,
            required: 6
        })
    );
}

#[test]
fn accept_rejects_earlier_conflicting_nullifier() {
    let g = genesis();
    let asset_id = g.asset_id();
    let spent = Coin {
        asset_id,
        value: 60,
        owner: secret(8).owner(),
        randomness: Digest::from_bytes(byte_seed(7)),
    };
    let nf = spent.nullifier(&secret(8));

    let mut chain = MockAnchorChain::new();
    // The authoritative spend comes first, bound under its own ctx.
    let (record_a, ctx_a) = xfer_for(&chain, &[nf]);
    let first_ref = chain.append_with_ctx(record_a, ctx_a);
    chain.advance_blocks(1);
    // The double-spend race anchor the attacker shows to the victim — also
    // well-formed, under its own ctx (different on-chain payload bytes).
    let (record_b, ctx_b) = xfer_for(&chain, &[nf]);
    let second_ref = chain.append_with_ctx(record_b, ctx_b);
    let openings = vec![opening_for(asset_id, 60, 3, 4)];
    let consignment = consignment_for(&chain, second_ref, vec![nf], openings, None);
    chain.advance_blocks(5);

    let err = accept(
        &consignment,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[asset_id]),
    )
    .unwrap_err();
    assert_eq!(
        err,
        RejectReason::NullifierConflict {
            nullifier: nf.to_anchor(),
            first: first_ref.location,
        }
    );
}

#[test]
fn accept_survives_copy_grief() {
    let g = genesis();
    let asset_id = g.asset_id();
    let spent = Coin {
        asset_id,
        value: 60,
        owner: secret(8).owner(),
        randomness: Digest::from_bytes(byte_seed(7)),
    };
    let nf = spent.nullifier(&secret(8));

    let mut chain = MockAnchorChain::new();
    // The victim's record, bound to the victim's ctx.
    let victim_ctx = chain.fresh_ctx();
    let record = AnchorRecord::xfer(&[nf], &victim_ctx);
    // A mempool spy copies the byte-identical record into their own
    // transaction (different ctx) and gets it mined FIRST.
    let spy_ctx = chain.fresh_ctx();
    let spy_ref = chain.append_with_ctx(record, spy_ctx);
    assert!(!record.well_formed(&spy_ctx, &nf));
    // The victim's anchor lands later.
    let victim_ref = chain.append_with_ctx(record, victim_ctx);
    chain.advance_blocks(6);

    // The copy is not an occurrence of the raw nullifier…
    assert_eq!(
        chain.first_nullifier_occurrence(&nf),
        Some(victim_ref.location)
    );
    assert_eq!(chain.nullifier_occurrences(&nf), vec![victim_ref.location]);
    // …and the legitimate consignment still verifies.
    let openings = vec![opening_for(asset_id, 60, 3, 4)];
    let consignment = consignment_for(&chain, victim_ref, vec![nf], openings.clone(), None);
    accept(
        &consignment,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[asset_id]),
    )
    .expect("copy-grief must not freeze the victim's coins");

    // A consignment pointing at the spy's copy fails check (a): the copy's
    // payload is bound to the victim's ctx, not the spy's.
    let spy_consignment = consignment_for(&chain, spy_ref, vec![nf], openings, None);
    assert_eq!(
        accept(
            &spy_consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[asset_id]),
        ),
        Err(RejectReason::IllFormedAnchor)
    );
}

#[test]
fn accept_rejects_unknown_asset_without_genesis_aux() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, vec![], openings, None); // no aux
    chain.advance_blocks(5);

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[])
        ),
        Err(RejectReason::UnknownAsset)
    );

    // … but is accepted if the asset was pinned, or if aux matches.
    let ok = accept(
        &consignment,
        &chain,
        &MockVerifier,
        &params(&[secret(3)], &[asset_id]),
    );
    assert!(ok.is_ok());
}

#[test]
fn accept_rejects_mismatched_genesis_aux() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut other = g.clone();
    other.nonce = 99; // different asset
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)];
    let consignment = consignment_for(&chain, anchor_ref, vec![], openings, Some(other));
    chain.advance_blocks(5);

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(3)], &[])
        ),
        Err(RejectReason::GenesisMismatch)
    );
}

#[test]
fn accept_rejects_when_nothing_is_owned() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let openings = vec![opening_for(asset_id, 100, 3, 4)]; // owned by secret(3)
    let consignment = consignment_for(&chain, anchor_ref, vec![], openings, Some(g));
    chain.advance_blocks(5);

    assert_eq!(
        accept(
            &consignment,
            &chain,
            &MockVerifier,
            &params(&[secret(9)], &[])
        ),
        Err(RejectReason::NoOwnedOutput)
    );
}

// --- Consignment serialization (§4.8) -----------------------------------------

#[test]
fn consignment_bincode_round_trip() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let anchor_ref = mint_anchor(&mut chain, &asset_id, 100);
    let consignment = consignment_for(
        &chain,
        anchor_ref,
        vec![d(3)],
        vec![opening_for(asset_id, 100, 3, 4)],
        Some(g),
    );
    let bytes = consignment.to_bytes();
    assert_eq!(Consignment::from_bytes(&bytes).unwrap(), consignment);
    assert!(Consignment::from_bytes(&bytes[..bytes.len() - 1]).is_err());
}

// --- Supply audit (§4.9) -------------------------------------------------------

#[test]
fn supply_audit_counts_mints_and_redeems_not_transfers() {
    let g = genesis();
    let asset_id = g.asset_id();
    let other_asset = Digest::from_bytes(byte_seed(42));

    let mut chain = MockAnchorChain::new();
    mint_anchor(&mut chain, &asset_id, 100); // height 0
    let h0 = chain.tip_height();
    chain.advance_blocks(1);
    mint_anchor(&mut chain, &asset_id, 50); // height 1
    let h1 = chain.tip_height();
    // A mint of a *different* asset must not count.
    chain.append(AnchorRecord::Mint {
        asset_id: other_asset.to_anchor(),
        value: 999,
        mint_commit: td(11),
    });
    chain.advance_blocks(1);
    // Transfers do not change supply.
    let ctx = byte_seed(20);
    chain.append_with_ctx(AnchorRecord::xfer(&[d(12)], &ctx), ctx);
    chain.append_with_ctx(AnchorRecord::xfer_compressed(&d(13), &ctx), ctx);
    let h2 = chain.tip_height();
    chain.advance_blocks(1);
    let redeem_ctx = byte_seed(21);
    chain.append_with_ctx(
        AnchorRecord::redeem(asset_id.to_anchor(), 30, &d(14), &redeem_ctx),
        redeem_ctx,
    );
    let h3 = chain.tip_height();

    assert_eq!(supply(&chain, &asset_id, h0), Ok(100));
    assert_eq!(supply(&chain, &asset_id, h1), Ok(150));
    assert_eq!(supply(&chain, &asset_id, h2), Ok(150));
    assert_eq!(supply(&chain, &asset_id, h3), Ok(120));
    assert_eq!(supply(&chain, &other_asset, h3), Ok(999));
}

#[test]
fn supply_audit_dedupes_copied_mints() {
    let g = genesis();
    let asset_id = g.asset_id();
    let mut chain = MockAnchorChain::new();
    let record = AnchorRecord::Mint {
        asset_id: asset_id.to_anchor(),
        value: 100,
        mint_commit: td(2),
    };
    chain.append(record);
    chain.advance_blocks(1);
    // A byte-copied MINT anchor (same mint_commit) must not double-count…
    chain.append(record);
    chain.advance_blocks(1);
    // …but a genuinely distinct mint (fresh nonce → fresh mint_commit) does.
    chain.append(AnchorRecord::Mint {
        asset_id: asset_id.to_anchor(),
        value: 100,
        mint_commit: td(3),
    });

    assert_eq!(supply(&chain, &asset_id, chain.tip_height()), Ok(200));
}

#[test]
fn supply_audit_flags_overspent_asset() {
    let asset_id = genesis().asset_id();
    let mut chain = MockAnchorChain::new();
    let ctx = byte_seed(22);
    chain.append_with_ctx(
        AnchorRecord::redeem(asset_id.to_anchor(), 1, &d(15), &ctx),
        ctx,
    );
    assert_eq!(
        supply(&chain, &asset_id, 0),
        Err(SupplyError::NegativeSupply)
    );
}
