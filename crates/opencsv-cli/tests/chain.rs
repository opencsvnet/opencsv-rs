//! FileAnchorChain semantics: must match `MockAnchorChain` (raw-nullifier
//! occurrence recognition, confirmations, positions), plus on-disk
//! persistence of the per-anchor transaction context.

use opencsv_cli::chain::FileAnchorChain;
use opencsv_core::chain::AnchorChain;
use opencsv_core::{AnchorRecord, Digest};

fn mint_record(tag: u8) -> AnchorRecord {
    AnchorRecord::Mint {
        asset_id: Digest::from_bytes([tag; 32]).to_anchor(),
        value: u64::from(tag) * 10,
        mint_commit: Digest::from_bytes([tag + 1; 32]).to_anchor(),
    }
}

fn raw_nf(tag: u8) -> Digest {
    Digest::from_bytes([tag; 32])
}

fn xfer_record(tag: u8, ctx: &[u8; 32]) -> AnchorRecord {
    AnchorRecord::xfer(&[raw_nf(tag)], ctx)
}

/// Pick (deterministically) a ctx whose bound payload for `raw` avoids the
/// MINT/REDEEM tag bytes, so the record still parses as a transfer after a
/// disk replay (see opencsv-core's anchor docs).
fn non_colliding_ctx(raw: &Digest, seed_start: u8) -> [u8; 32] {
    for s in seed_start..=255 {
        let ctx = [s; 32];
        let p = opencsv_core::binding(raw, &ctx).to_anchor();
        if p.as_bytes()[0] != 0x01 && p.as_bytes()[0] != 0x04 {
            return ctx;
        }
    }
    panic!("no non-colliding ctx found");
}

#[test]
fn append_advance_and_persistence() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("chain.log");
    let ctx = [0xcc; 32];

    let mint_ref;
    let xfer_ref;
    {
        let mut chain = FileAnchorChain::open(&path).unwrap();
        assert_eq!(chain.tip_height(), 0);
        // Appends land in the current tip block with in-block positions.
        mint_ref = chain.append(mint_record(1), ctx).unwrap();
        let xfer2 = chain.append(mint_record(2), ctx).unwrap();
        assert_eq!(mint_ref.location.height, 0);
        assert_eq!(mint_ref.location.position, 0);
        assert_eq!(xfer2.location.position, 1);
        assert_eq!(chain.confirmations_at(0), 1);

        chain.advance_blocks(6).unwrap();
        assert_eq!(chain.tip_height(), 6);
        assert_eq!(chain.confirmations_at(0), 7);

        let xfer_ctx = non_colliding_ctx(&raw_nf(9), 0);
        xfer_ref = chain.append(xfer_record(9, &xfer_ctx), xfer_ctx).unwrap();
        assert_eq!(xfer_ref.location.height, 6);
        assert_eq!(xfer_ref.location.position, 0);
        // Above-tip heights have zero confirmations.
        assert_eq!(chain.confirmations_at(7), 0);
    }

    // Reopen: everything replays from the log.
    let chain = FileAnchorChain::open(&path).unwrap();
    assert_eq!(chain.tip_height(), 6);
    assert_eq!(chain.anchor_at(&mint_ref), Some(mint_record(1)));
    let xfer_ctx = non_colliding_ctx(&raw_nf(9), 0);
    assert_eq!(chain.anchor_at(&xfer_ref), Some(xfer_record(9, &xfer_ctx)));
    // The transaction context persists across reopen.
    assert_eq!(chain.ctx_at(&xfer_ref), Some(xfer_ctx));
    assert_eq!(chain.ctx_at(&mint_ref), Some(ctx));
    // txid mismatch → not found.
    let mut bogus = mint_ref;
    bogus.txid[0] ^= 1;
    assert_eq!(chain.anchor_at(&bogus), None);
    assert_eq!(chain.ctx_at(&bogus), None);
    assert_eq!(chain.anchors_up_to(0).len(), 2);
    assert_eq!(chain.anchors_up_to(6).len(), 3);
}

#[test]
fn nullifier_first_occurrence_wins() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("chain.log");
    let mut chain = FileAnchorChain::open(&path).unwrap();

    // A genuine double-spend: two records binding the same raw nullifier,
    // each under its own ctx (different on-chain payloads).
    let nf = raw_nf(7);
    let ctx_a = non_colliding_ctx(&nf, 0xa0);
    let ctx_b = non_colliding_ctx(&nf, 0xb0);
    let record_a = AnchorRecord::xfer(&[nf], &ctx_a);
    let record_b = AnchorRecord::xfer(&[nf], &ctx_b);
    assert_ne!(record_a, record_b);
    let first = chain.append(record_a, ctx_a).unwrap();
    chain.advance_blocks(3).unwrap();
    let second = chain.append(record_b, ctx_b).unwrap(); // double-spend attempt
    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    assert_eq!(
        chain.nullifier_occurrences(&nf),
        vec![first.location, second.location]
    );

    // Occurrence recognition works after a replay from disk, too.
    let chain = FileAnchorChain::open(&path).unwrap();
    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    assert_eq!(
        chain.nullifier_occurrences(&nf),
        vec![first.location, second.location]
    );
}

#[test]
fn copies_under_a_foreign_ctx_are_not_occurrences() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("chain.log");
    let mut chain = FileAnchorChain::open(&path).unwrap();

    // Copy-grief: the byte-identical record re-anchored under a foreign ctx.
    let nf = raw_nf(7);
    let ctx = non_colliding_ctx(&nf, 0x70);
    let record = AnchorRecord::xfer(&[nf], &ctx);
    let first = chain.append(record, ctx).unwrap();
    chain.advance_blocks(1).unwrap();
    let grief = chain.append(record, [0x99; 32]).unwrap();
    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    assert_eq!(chain.nullifier_occurrences(&nf), vec![first.location]);
    // The copy is still stored and fetchable (with its ctx).
    assert_eq!(chain.anchor_at(&grief), Some(record));
    assert_eq!(chain.ctx_at(&grief), Some([0x99; 32]));

    // … and it is still not an occurrence after a replay from disk.
    let chain = FileAnchorChain::open(&path).unwrap();
    assert_eq!(chain.first_nullifier_occurrence(&nf), Some(first.location));
    assert_eq!(chain.nullifier_occurrences(&nf), vec![first.location]);
}

#[test]
fn corrupt_log_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("chain.log");
    std::fs::write(&path, "not-a-chain\n").unwrap();
    assert!(FileAnchorChain::open(&path).is_err());

    let path2 = tmp.path().join("chain2.log");
    std::fs::write(&path2, "opencsv-chain-v3\nentry 0 0 zz\n").unwrap();
    assert!(FileAnchorChain::open(&path2).is_err());
}

#[test]
fn old_log_versions_are_rejected_with_a_clear_message() {
    let tmp = tempfile::tempdir().unwrap();
    for (name, magic) in [
        ("chain-v1.log", "opencsv-chain-v1"),
        ("chain-v2.log", "opencsv-chain-v2"),
    ] {
        let path = tmp.path().join(name);
        std::fs::write(&path, format!("{magic}\ntip 3\n")).unwrap();
        let err = match FileAnchorChain::open(&path) {
            Ok(_) => panic!("{magic} log must be rejected"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains(magic), "unexpected error: {err}");
        assert!(err.contains("cannot be migrated"), "unexpected error: {err}");
    }
}
