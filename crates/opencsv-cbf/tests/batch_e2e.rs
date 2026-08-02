//! End-to-end batch-anchor test (v1 format): a 2-payload batch from one
//! wallet, both payloads discovered by the filter-driven scan with the
//! envelope occurrence semantics, per-payload exclusion, batch_commit
//! tamper rejection, and a solo anchor still verifying unchanged.
//!
//! Skipped (silently green) when no `bitcoind` binary is available.

mod common;

use std::time::Duration;

use common::{bitcoind_path, Node};
use opencsv_bitcoin::rpc::RpcAuth;
use opencsv_bitcoin::{funding_ctx, BitcoinAnchorChain, Config as BtcConfig, Network, MARKER_DUST_SATS, MARKER_SPK};
use opencsv_cbf::{CbfClient, Config, ScanIndex};
use opencsv_core::chain::AnchorChain;
use opencsv_core::{binding, AnchorRecord, Digest};

#[test]
fn batch_anchor_two_payloads() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping batch_anchor_two_payloads: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);

    let btc_config = BtcConfig {
        network: Network::Regtest,
        rpc_url: node.rpc_url.clone(),
        auth: RpcAuth::Cookie(node.cookie.clone()),
        wallet: Some("test".into()),
        scan_from: Some(1),
        index_path: tmp.path().join("bitcoin-index.log"),
    };
    let mut anchor_chain = BitcoinAnchorChain::open(&btc_config).unwrap();

    // --- setup: the funding UTXO for batch size 2 (one-time) -----------------
    let batch_ctx = anchor_chain.marker_utxo_ctx(2).unwrap();
    anchor_chain.generate_blocks(1).unwrap();
    // Idempotent: the same ctx is returned on the second call.
    assert_eq!(anchor_chain.marker_utxo_ctx(2).unwrap(), batch_ctx);

    // --- a 2-payload batch from one wallet ----------------------------------
    let nf1 = Digest::from_bytes([41u8; 32]);
    let nf2 = Digest::from_bytes([42u8; 32]);
    let payloads = vec![
        binding(&nf1, &batch_ctx).to_anchor(),
        binding(&nf2, &batch_ctx).to_anchor(),
    ];
    let batch_ref = anchor_chain.anchor_batch(&payloads).unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let batch_loc = anchor_chain.locate(&batch_ref).expect("batch mined");
    let tip = anchor_chain.tip_height();
    assert_eq!(tip, 108);

    // --- on-chain layout (the v1 byte-level format) ---------------------------
    node.wait_for_filter_index();
    let config = Config {
        network: Network::Regtest,
        peers: vec![format!("127.0.0.1:{}", node.p2p_port)],
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(30),
    };
    let mut client = CbfClient::connect(&config).unwrap();
    let batch_hash = client.block_hash(batch_loc.height).unwrap();
    let block = client.fetch_block(&batch_hash).unwrap();
    let tx = &block.txs[batch_loc.position as usize];
    assert_eq!(tx.txid(), batch_ref.txid);
    // Output 0: OP_RETURN batch header record.
    let header_record = AnchorRecord::from_bytes(
        &opencsv_cbf::block::op_return_payload(&tx.outputs[0].script_pubkey).unwrap(),
    );
    let AnchorRecord::BatchHeader { count, batch_commit } = header_record else {
        panic!("output 0 must be the batch header: {header_record:?}");
    };
    assert_eq!(count, 2);
    assert_eq!(
        batch_commit,
        opencsv_core::batch::batch_commit(&payloads, &batch_ctx).to_anchor()
    );
    // Output 1: exactly one constant marker output (filter discovery).
    assert_eq!(tx.outputs[1].script_pubkey.as_slice(), MARKER_SPK.as_slice());
    assert_eq!(tx.outputs[1].value, MARKER_DUST_SATS);
    assert_eq!(
        tx.outputs
            .iter()
            .filter(|o| o.script_pubkey.as_slice() == MARKER_SPK.as_slice())
            .count(),
        1,
        "exactly one marker per batch tx"
    );
    // Output 2: change back to the batch-size funding scriptPubKey.
    assert_eq!(
        tx.outputs[2].script_pubkey.as_slice(),
        opencsv_bitcoin::batch::batch_funding_spk(2).as_slice(),
        "change cycles back to the size-2 funding script"
    );
    // ctx is the funding_ctx of vin[0] (the OP_TRUE outpoint).
    let wire_ctx = funding_ctx(&tx.inputs[0].prev.txid, tx.inputs[0].prev.vout);
    assert_eq!(wire_ctx, batch_ctx);
    // The witness envelope: magic, one 24-byte item per payload, and
    // the drop-script witness script (CLEANSTACK-clean).
    let witness = &tx.witnesses[0];
    assert_eq!(witness[0], b"OCSV");
    assert_eq!(witness.len(), 2 + 2);
    assert_eq!(witness[1], payloads[0].as_bytes());
    assert_eq!(witness[2], payloads[1].as_bytes());
    assert_eq!(
        witness[3].as_slice(),
        opencsv_bitcoin::batch::drop_script(2).as_slice()
    );
    println!("batch tx layout OK: header [0x05][2][commit], marker@1, envelope OCSV+2×24B+OP_DROP×3 OP_TRUE");

    // --- the scan indexes each payload as an occurrence candidate ------------
    let mut index = ScanIndex::open(tmp.path().join("scan"), Network::Regtest).unwrap();
    index.scan_sync(&mut client, 102).unwrap();
    let batch_entries: Vec<_> = index
        .occurrences()
        .iter()
        .filter(|e| e.location == batch_loc)
        .collect();
    assert_eq!(batch_entries.len(), 2);
    assert_eq!(batch_entries[0].batch.as_ref().unwrap().index, 0);
    assert_eq!(batch_entries[1].batch.as_ref().unwrap().index, 1);
    assert_eq!(batch_entries[0].ctx, batch_ctx);

    // --- both recipients verify against the scan (no RPC, no indexer) --------
    assert_eq!(index.scan_check(&nf1, 102, tip), Some((batch_loc, batch_ctx)));
    assert_eq!(index.scan_check(&nf2, 102, tip), Some((batch_loc, batch_ctx)));
    assert!(index.occurrences().iter().any(|e| e.binds(&nf1)));
    assert!(index.occurrences().iter().any(|e| e.binds(&nf2)));
    println!("batch recipient 1 VERIFIED via scan (envelope index 0)");
    println!("batch recipient 2 VERIFIED via scan (envelope index 1)");

    // --- batch_commit mismatch rejects ---------------------------------------
    let mut tampered = batch_entries[0].clone();
    tampered.batch.as_mut().unwrap().envelope[1] = binding(&Digest::from_bytes([99u8; 32]), &batch_ctx).to_anchor();
    assert!(!tampered.binds(&nf1), "a swapped envelope payload breaks batch_commit");
    assert!(!tampered.binds(&Digest::from_bytes([99u8; 32])));
    println!("batch_commit mismatch: rejected");

    // --- per-payload exclusion: a double-spend of one batched coin ------------
    let solo_ref = anchor_chain
        .anchor(|ctx| AnchorRecord::xfer(&[nf1], ctx))
        .unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let solo_loc = anchor_chain.locate(&solo_ref).expect("double-spend mined");
    let tip = anchor_chain.tip_height();
    node.wait_for_filter_index();
    client.sync().unwrap();
    index.scan_sync(&mut client, 102).unwrap();
    assert_eq!(index.nullifier_occurrences(&nf1), vec![batch_loc, solo_loc]);
    assert_eq!(index.first_nullifier_occurrence(&nf1), Some(batch_loc));
    assert_eq!(index.scan_check(&nf2, 102, tip), Some((batch_loc, batch_ctx)));
    println!("per-payload exclusion: batch payload is the first occurrence of nf1");

    // --- a solo anchor still verifies unchanged -------------------------------
    let solo_record = anchor_chain.anchor_at(&solo_ref).unwrap();
    let verdict = client
        .verify_anchor(&solo_record, solo_loc, solo_ref.txid, 6)
        .unwrap();
    assert!(
        matches!(verdict, opencsv_cbf::AnchorVerdict::Confirmed { .. }),
        "solo anchor verifies unchanged: {verdict:?}"
    );

    // --- the node's own scanner saw the marker on the batch block -------------
    assert_eq!(anchor_chain.block_has_marker(batch_loc.height), Some(true));
}
