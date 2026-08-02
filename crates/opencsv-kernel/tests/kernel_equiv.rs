//! Kernel ≡ core equivalence tests: the kernel is a rewrite, not a
//! redesign — these port the relevant opencsv-core test scenarios
//! (`opencsv-core/tests/protocol.rs`, `batch.rs` tests) and assert the
//! kernel produces byte-identical results.

use opencsv_core::anchor::{self, AnchorRecord};
use opencsv_core::chain::MockAnchorChain;
use opencsv_core::{AnchorChain, Digest, TruncatedDigest};
use opencsv_kernel::types::Entry;
use opencsv_kernel::{audit as kaudit, batch as kbatch, binding as kbinding, interop, record::Record as KRecord, scan as kscan};

fn byte_seed(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn d(seed: u8) -> Digest {
    Digest::from_bytes(byte_seed(seed))
}

fn td(seed: u8) -> TruncatedDigest {
    d(seed).to_anchor()
}

fn mint_record(asset: TruncatedDigest, value: u64, commit: TruncatedDigest) -> AnchorRecord {
    AnchorRecord::Mint {
        asset_id: asset,
        value,
        mint_commit: commit,
    }
}

// --- binding / well_formed ---------------------------------------------------

#[test]
fn binding_is_byte_identical_to_core() {
    for seed in [0u8, 1, 7, 42, 255] {
        let raw = byte_seed(seed);
        let ctx = byte_seed(seed.wrapping_add(3));
        assert_eq!(
            kbinding::binding(&raw, &ctx),
            anchor::binding(&d(seed), &ctx).to_anchor().0,
            "binding must be byte-identical for seed {seed}"
        );
    }
}

#[test]
fn well_formed_matches_core_on_all_variants() {
    let ctx = byte_seed(7);
    let nf1 = d(1);
    let nf2 = d(2);
    let cases: Vec<AnchorRecord> = vec![
        mint_record(td(1), 100, td(2)),
        AnchorRecord::xfer(&[nf1], &ctx),
        AnchorRecord::xfer(&[nf1, nf2], &ctx),
        AnchorRecord::xfer_compressed(&nf1, &ctx),
        AnchorRecord::batch_header(&[td(3), td(4)], &ctx),
        AnchorRecord::redeem(td(5), 42, &nf2, &ctx),
    ];
    for record in &cases {
        let krecord = interop::record(record);
        for nf in [&nf1, &nf2, &d(3)] {
            assert_eq!(
                krecord.well_formed(&ctx, nf.as_bytes()),
                record.well_formed(&ctx, nf),
                "well_formed mismatch for {record:?} / {nf:?}"
            );
        }
    }
}

// --- first occurrence (§4.7) --------------------------------------------------

/// A scenario mirroring `mock_chain_first_occurrence_and_double_spend`.
#[test]
fn first_occurrence_double_spend_matches_core() {
    let nf = d(7);
    let ctx_a = byte_seed(10);
    let ctx_b = byte_seed(11);

    let record_a = AnchorRecord::xfer(&[nf], &ctx_a);
    let record_b = AnchorRecord::xfer(&[nf], &ctx_b);
    assert_ne!(record_a, record_b, "a genuine double-spend binds differently");

    let mut chain = MockAnchorChain::new();
    let first = chain.append_with_ctx(record_a, ctx_a);
    chain.advance_blocks(1);
    let second = chain.append_with_ctx(record_b, ctx_b);

    let entries = vec![
        interop::entry_at(&chain, &first).unwrap(),
        interop::entry_at(&chain, &second).unwrap(),
    ];
    let idx = kscan::first_occurrence(&entries, nf.as_bytes());
    assert_eq!(
        idx.map(|i| entries[i].location),
        Some(interop::location(&first.location))
    );
    assert_eq!(
        chain.first_nullifier_occurrence(&nf),
        Some(first.location),
        "core sanity check"
    );
}

/// Mirrors `mock_chain_copies_and_forgeries_are_not_occurrences`.
#[test]
fn first_occurrence_copy_grief_matches_core() {
    let nf = d(7);
    let ctx = byte_seed(12);
    let grief_ctx = byte_seed(13);

    let record = AnchorRecord::xfer(&[nf], &ctx);
    let mut chain = MockAnchorChain::new();
    let first = chain.append_with_ctx(record, ctx);
    chain.advance_blocks(1);
    // Copy-grief: byte-identical record re-anchored under a DIFFERENT ctx.
    let grief = chain.append_with_ctx(record, grief_ctx);
    // Forgery: a record built from a guessed payload.
    let guess = AnchorRecord::Xfer {
        payloads: [td(99), TruncatedDigest([0u8; 24])],
    };
    let guess_ref = chain.append_with_ctx(guess, byte_seed(14));

    let entries = vec![
        interop::entry_at(&chain, &first).unwrap(),
        interop::entry_at(&chain, &grief).unwrap(),
        interop::entry_at(&chain, &guess_ref).unwrap(),
    ];
    // The copy is not well-formed under the copier's ctx (kernel view).
    assert!(!entries[1].record.well_formed(&entries[1].ctx, nf.as_bytes()));
    // Only the victim's anchor is an occurrence.
    assert_eq!(
        kscan::first_occurrence(&entries, nf.as_bytes()).map(|i| entries[i].location),
        Some(interop::location(&first.location))
    );
    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    // A raw nullifier that occurs nowhere is not found.
    assert_eq!(kscan::first_occurrence(&entries, d(8).as_bytes()), None);
}

// --- batch occurrence (§4.7.1 amended) ----------------------------------------

/// Mirrors `batch_occurrence_and_commit_binding` (batch.rs tests).
#[test]
fn batch_occurrence_matches_core() {
    let ctx = byte_seed(9);
    let nf1 = d(1);
    let nf2 = d(2);
    let payloads: Vec<TruncatedDigest> = vec![
        anchor::binding(&nf1, &ctx).to_anchor(),
        anchor::binding(&nf2, &ctx).to_anchor(),
    ];
    let record = AnchorRecord::batch_header(&payloads, &ctx);
    let AnchorRecord::BatchHeader {
        count,
        batch_commit,
    } = record
    else {
        panic!("expected batch header");
    };
    let kpayloads: Vec<[u8; 24]> = payloads.iter().map(|p| p.0).collect();

    // Both payloads are occurrences at their own index, kernel and core agree.
    for (nf, expect) in [(nf1, Some(0u32)), (nf2, Some(1u32)), (d(3), None)] {
        assert_eq!(
            kbatch::batch_occurrence(count, &batch_commit.0, &kpayloads, &ctx, nf.as_bytes()),
            expect
        );
        assert_eq!(
            opencsv_core::batch::envelope_occurrence(&record, &payloads, &ctx, &nf),
            expect
        );
    }

    // Tampered envelope (swapped payload): commit mismatch rejects all.
    let mut tampered = kpayloads.clone();
    tampered[1] = kbinding::binding(d(99).as_bytes(), &ctx);
    assert_eq!(
        kbatch::batch_occurrence(count, &batch_commit.0, &tampered, &ctx, nf2.as_bytes()),
        None
    );

    // Wrong ctx and wrong count reject too.
    assert_eq!(
        kbatch::batch_occurrence(count, &batch_commit.0, &kpayloads, &byte_seed(8), nf1.as_bytes()),
        None
    );
    assert_eq!(
        kbatch::batch_occurrence(count, &batch_commit.0, &kpayloads[..1], &ctx, nf1.as_bytes()),
        None
    );
}

// --- supply audit (§4.9) ------------------------------------------------------

fn kernel_anchors(chain: &MockAnchorChain, height: u64) -> Vec<(opencsv_kernel::types::Location, KRecord)> {
    chain
        .anchors_up_to(height)
        .iter()
        .map(|(loc, rec)| (interop::location(loc), interop::record(rec)))
        .collect()
}

/// Mirrors `supply_audit_counts_mints_and_redeems_not_transfers`.
#[test]
fn supply_counts_mints_and_redeems_not_transfers() {
    let asset = d(40);
    let other_asset = d(42);

    let mut chain = MockAnchorChain::new();
    chain.append(mint_record(asset.to_anchor(), 100, td(2)));
    let h0 = chain.tip_height();
    chain.advance_blocks(1);
    chain.append(mint_record(asset.to_anchor(), 50, td(3)));
    let h1 = chain.tip_height();
    chain.append(mint_record(other_asset.to_anchor(), 999, td(11)));
    chain.advance_blocks(1);
    let ctx = byte_seed(20);
    chain.append_with_ctx(AnchorRecord::xfer(&[d(12)], &ctx), ctx);
    chain.append_with_ctx(AnchorRecord::xfer_compressed(&d(13), &ctx), ctx);
    let h2 = chain.tip_height();
    chain.advance_blocks(1);
    let redeem_ctx = byte_seed(21);
    chain.append_with_ctx(
        AnchorRecord::redeem(asset.to_anchor(), 30, &d(14), &redeem_ctx),
        redeem_ctx,
    );
    let h3 = chain.tip_height();

    for (height, expect) in [(h0, 100), (h1, 150), (h2, 150), (h3, 120)] {
        assert_eq!(
            kaudit::supply(&kernel_anchors(&chain, height), &asset.to_anchor().0, height),
            Ok(expect),
            "kernel supply at height {height}"
        );
        assert_eq!(
            opencsv_core::audit::supply(&chain, &asset, height),
            Ok(expect),
            "core sanity at height {height}"
        );
    }
    assert_eq!(
        kaudit::supply(&kernel_anchors(&chain, h3), &other_asset.to_anchor().0, h3),
        Ok(999)
    );
}

/// Mirrors `supply_audit_dedupes_copied_mints`.
#[test]
fn supply_dedupes_copied_mints() {
    let asset = d(40);
    let mut chain = MockAnchorChain::new();
    let record = mint_record(asset.to_anchor(), 100, td(2));
    chain.append(record);
    chain.advance_blocks(1);
    // A byte-copied MINT (same mint_commit) must not double-count…
    chain.append(record);
    chain.advance_blocks(1);
    // …but a genuinely distinct mint (fresh mint_commit) does.
    chain.append(mint_record(asset.to_anchor(), 100, td(3)));
    let tip = chain.tip_height();

    assert_eq!(
        kaudit::supply(&kernel_anchors(&chain, tip), &asset.to_anchor().0, tip),
        Ok(200)
    );
    assert_eq!(
        opencsv_core::audit::supply(&chain, &asset, tip),
        Ok(200)
    );
}

/// Mirrors `supply_audit_flags_overspent_asset`.
#[test]
fn supply_flags_overspent_asset() {
    let asset = d(40);
    let mut chain = MockAnchorChain::new();
    let ctx = byte_seed(22);
    chain.append_with_ctx(AnchorRecord::redeem(asset.to_anchor(), 1, &d(15), &ctx), ctx);

    assert_eq!(
        kaudit::supply(&kernel_anchors(&chain, 0), &asset.to_anchor().0, 0),
        Err(opencsv_kernel::audit::SupplyError::NegativeSupply)
    );
    assert_eq!(
        opencsv_core::audit::supply(&chain, &asset, 0),
        Err(opencsv_core::SupplyError::NegativeSupply)
    );
}
