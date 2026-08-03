//! Unit tests against canned RPC responses (the HTTP layer is stubbed via
//! [`Transport`] — for UNITS only; the product path always uses
//! [`crate::HttpTransport`]).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bitcoin::{absolute, transaction, Transaction};
use opencsv_core::chain::AnchorChain;
use opencsv_core::digest::TruncatedDigest;
use opencsv_core::{AnchorRecord, Digest};
use serde_json::{json, Value};

use super::*;

/// A [`Transport`] that asserts each request's method against a script
/// and returns the scripted JSON-RPC response body, recording requests
/// for later inspection.
#[derive(Default)]
struct ScriptTransport {
    script: Mutex<VecDeque<(String, String)>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl ScriptTransport {
    fn new() -> Self {
        Self::default()
    }

    /// Queue a successful reply to `method`.
    fn reply(&self, method: &str, result: Value) -> &Self {
        self.script.lock().unwrap().push_back((
            method.to_string(),
            json!({"jsonrpc": "1.0", "id": 1, "result": result}).to_string(),
        ));
        self
    }

    /// Queue a JSON-RPC error reply to `method`.
    fn rpc_error(&self, method: &str, code: i64, message: &str) -> &Self {
        self.script.lock().unwrap().push_back((
            method.to_string(),
            json!({
                "jsonrpc": "1.0",
                "id": 1,
                "result": null,
                "error": {"code": code, "message": message}
            })
            .to_string(),
        ));
        self
    }

    /// Handle to the recorded requests (survives moving the transport).
    fn requests(&self) -> Arc<Mutex<Vec<Value>>> {
        Arc::clone(&self.requests)
    }
}

impl Transport for ScriptTransport {
    fn post(&self, body: &str) -> Result<String, Error> {
        let request: Value = serde_json::from_str(body).expect("request is JSON");
        let (method, reply) = self
            .script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unscripted RPC call: {body}"));
        assert_eq!(
            method,
            request["method"].as_str().unwrap(),
            "scripted method mismatch for request {body}"
        );
        self.requests.lock().unwrap().push(request);
        Ok(reply)
    }
}

fn test_config(index_path: PathBuf, network: Network, scan_from: Option<u64>) -> Config {
    Config {
        network,
        rpc_url: "http://127.0.0.1:0".into(),
        auth: RpcAuth::UserPass("u:p".into()),
        wallet: None,
        scan_from,
        index_path,
    }
}

/// Display-order hex of the byte `b` repeated (a valid dummy txid).
fn display_hash(b: u8) -> String {
    to_hex(&[b; 32])
}

fn blockchaininfo(chain: &str, blocks: u64) -> Value {
    json!({"chain": chain, "blocks": blocks})
}

/// C2 broadcasts the exact persisted transaction and treats both mempool
/// discovery and Core's already-known error as idempotent success.
#[test]
fn batch_broadcast_is_exact_and_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };
    let expected = transaction.compute_txid().to_string();
    let transport = ScriptTransport::new();
    let requests = transport.requests();
    transport
        .reply("getblockchaininfo", blockchaininfo("regtest", 100))
        .reply("getblockcount", json!(100))
        .rpc_error("getmempoolentry", -5, "Transaction not in mempool")
        .reply("sendrawtransaction", json!(expected))
        .reply("getmempoolentry", json!({"vsize": 10}))
        .rpc_error("getmempoolentry", -5, "Transaction not in mempool")
        .rpc_error(
            "sendrawtransaction",
            -27,
            "Transaction already in block chain",
        );
    let config = test_config(tmp.path().join("index.log"), Network::Regtest, Some(101));
    let chain = BitcoinAnchorChain::with_transport(RpcClient::new(transport), &config).unwrap();

    assert_eq!(chain.broadcast_transaction(&transaction).unwrap(), expected);
    assert_eq!(chain.broadcast_transaction(&transaction).unwrap(), expected);
    assert_eq!(chain.broadcast_transaction(&transaction).unwrap(), expected);

    let requests = requests.lock().unwrap();
    assert_eq!(requests[3]["method"], "sendrawtransaction");
    assert_eq!(
        requests[3]["params"][0],
        json!(to_hex(&bitcoin::consensus::encode::serialize(&transaction)))
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "sendrawtransaction")
            .count(),
        2
    );
}

/// Transport/auth/node failures from the idempotency probe are not evidence
/// that a transaction is absent from the mempool and must fail closed.
#[test]
fn batch_broadcast_does_not_mask_mempool_probe_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };
    let transport = ScriptTransport::new();
    let requests = transport.requests();
    transport
        .reply("getblockchaininfo", blockchaininfo("regtest", 100))
        .reply("getblockcount", json!(100))
        .rpc_error("getmempoolentry", -28, "Loading block index");
    let config = test_config(tmp.path().join("index.log"), Network::Regtest, Some(101));
    let chain = BitcoinAnchorChain::with_transport(RpcClient::new(transport), &config).unwrap();

    let error = chain.broadcast_transaction(&transaction).unwrap_err();
    assert!(matches!(error, Error::Rpc { code: -28, .. }));
    assert_eq!(requests.lock().unwrap().len(), 3);
}

/// The two-pass anchor construction: funding-input selection, ctx
/// derivation from vin[0], tag-collision retry via input reorder, and the
/// real payload replacing the dummy — all against canned RPC replies.
#[test]
fn anchor_two_pass_construction() {
    let tmp = tempfile::tempdir().unwrap();
    let transport = ScriptTransport::new();
    let requests = transport.requests();
    let tx_a = display_hash(0xaa);
    let tx_b = display_hash(0xbb);
    let tx_c = display_hash(0xcc); // the broadcast anchor txid
    transport
        .reply("getblockchaininfo", blockchaininfo("regtest", 100))
        .reply("getblockcount", json!(100))
        // Pass 1.
        .reply("createrawtransaction", json!("raw1"))
        .reply(
            "fundrawtransaction",
            json!({"hex": "funded1", "fee": 0.00000141, "changepos": 1}),
        )
        .reply(
            "decoderawtransaction",
            json!({
                "txid": tx_c,
                "vin": [
                    {"txid": tx_a, "vout": 0},
                    {"txid": tx_b, "vout": 1},
                ],
                "vout": [
                    {"value": 0, "n": 0, "scriptPubKey": {"type": "nulldata", "hex": format!("6a40{}", to_hex(&[0u8; 64]))}},
                    {"value": MARKER_DUST_BTC, "n": 1, "scriptPubKey": {"type": "witness_v0_scripthash", "address": marker_address(Network::Regtest), "hex": to_hex(&MARKER_SPK)}},
                    {"value": 0.49999859, "n": 2, "scriptPubKey": {"type": "witness_v0_keyhash", "address": "bcrt1qchange"}},
                ],
            }),
        )
        // Pass 2.
        .reply("createrawtransaction", json!("raw2"))
        .reply(
            "signrawtransactionwithwallet",
            json!({"hex": "signed2", "complete": true}),
        )
        .reply("sendrawtransaction", json!(tx_c));
    let config = test_config(tmp.path().join("index.log"), Network::Regtest, Some(101));
    let mut chain = BitcoinAnchorChain::with_transport(RpcClient::new(transport), &config).unwrap();

    // The record builder collides with the MINT tag for the first
    // candidate ctx (input A) and parses cleanly for the second (input B).
    let mut calls = 0;
    let anchor_ref = chain
        .anchor(|_ctx| {
            calls += 1;
            if calls == 1 {
                // First payload byte 0x01 (MINT tag) + zero padding: would
                // misparse as tagged for every verifier.
                AnchorRecord::Xfer {
                    payloads: [TruncatedDigest([0x01; 24]), TruncatedDigest([0x02; 24])],
                }
            } else {
                AnchorRecord::Xfer {
                    payloads: [TruncatedDigest([0x99; 24]), TruncatedDigest([0x02; 24])],
                }
            }
        })
        .unwrap();
    assert_eq!(calls, 2, "the tag collision forced a second candidate");
    assert_eq!(anchor_ref.location, MEMPOOL_LOCATION);
    assert_eq!(anchor_ref.txid, hash_from_rpc(&tx_c).unwrap());

    // Inspect the pass-2 createrawtransaction request: chosen input first,
    // real payload in the data output, change amount passed through.
    let requests = requests.lock().unwrap();
    let pass2 = &requests[5];
    assert_eq!(pass2["method"], "createrawtransaction");
    assert_eq!(pass2["params"][0][0]["txid"], json!(tx_b));
    assert_eq!(pass2["params"][0][0]["vout"], json!(1));
    assert_eq!(pass2["params"][0][1]["txid"], json!(tx_a));
    let good = AnchorRecord::Xfer {
        payloads: [TruncatedDigest([0x99; 24]), TruncatedDigest([0x02; 24])],
    };
    assert_eq!(
        pass2["params"][1][0]["data"],
        json!(to_hex(&good.to_bytes()))
    );
    // Output 1 is the protocol marker, passed through unchanged; output 2
    // is the change.
    assert_eq!(
        pass2["params"][1][1][marker_address(Network::Regtest)],
        json!(MARKER_DUST_BTC)
    );
    assert_eq!(pass2["params"][1][2]["bcrt1qchange"], json!(0.49999859));
    // Pass 1 included the marker so the fee/funding math was exact, with
    // change pinned to position 2.
    let pass1_create = &requests[2];
    assert_eq!(pass1_create["method"], "createrawtransaction");
    assert_eq!(
        pass1_create["params"][1][1][marker_address(Network::Regtest)],
        json!(MARKER_DUST_BTC)
    );
    let pass1_fund = &requests[3];
    assert_eq!(pass1_fund["method"], "fundrawtransaction");
    assert_eq!(pass1_fund["params"][1]["change_position"], json!(2));
    drop(requests);

    // The mempool entry is visible by placeholder reference but is not a
    // confirmed occurrence.
    assert_eq!(chain.anchor_at(&anchor_ref), Some(good));
    assert_eq!(chain.locate(&anchor_ref), Some(MEMPOOL_LOCATION));
    assert_eq!(chain.confirmations_at(0), 0);
    assert!(chain.anchors_up_to(100).is_empty());
}

/// Block scanning: OP_RETURN payload extraction, ctx derivation from
/// vin[0], positions, and index persistence across reopens.
#[test]
fn scan_and_index_persistence() {
    let tmp = tempfile::tempdir().unwrap();
    let index_path = tmp.path().join("index.log");
    let hash_a = display_hash(0xa1);
    let hash_b = display_hash(0xb1);
    let funding_tx = display_hash(0xf1);
    let anchor_tx = display_hash(0xa2);
    let noise_tx = display_hash(0xa3);

    // A real XFER record binding a raw nullifier under the scanned ctx.
    let raw_nf = Digest::from_bytes([0x42; 32]);
    let ctx = funding_ctx(&hash_from_rpc(&funding_tx).unwrap(), 2);
    let record = AnchorRecord::xfer(&[raw_nf], &ctx);
    assert!(record.parses_cleanly());
    let record_hex = to_hex(&record.to_bytes());

    let block_a = json!({
        "hash": hash_a,
        "tx": [
            {"txid": display_hash(0x00), "vin": [{"coinbase": "abcd"}], "vout": []},
            {"txid": anchor_tx,
             "vin": [{"txid": funding_tx, "vout": 2}],
             "vout": [
                 {"value": 0, "n": 0, "scriptPubKey": {"type": "nulldata", "hex": format!("6a40{record_hex}")}},
                 {"value": MARKER_DUST_BTC, "n": 1, "scriptPubKey": {"type": "witness_v0_scripthash", "hex": to_hex(&MARKER_SPK), "address": marker_address(Network::Signet)}},
                 {"value": 0.1, "n": 2, "scriptPubKey": {"type": "witness_v0_keyhash", "address": "tb1qchange"}},
             ]},
        ],
    });
    let block_b = json!({
        "hash": hash_b,
        "tx": [
            {"txid": display_hash(0x01), "vin": [{"coinbase": "abcd"}], "vout": []},
            // 32-byte OP_RETURN: not an anchor, skipped.
            {"txid": noise_tx,
             "vin": [{"txid": funding_tx, "vout": 3}],
             "vout": [{"value": 0, "n": 0, "scriptPubKey": {"type": "nulldata", "hex": format!("6a20{}", to_hex(&[7u8; 32]))}}]},
        ],
    });

    {
        let transport = ScriptTransport::new();
        transport
            .reply("getblockchaininfo", blockchaininfo("signet", 102))
            .reply("getblockcount", json!(102))
            .reply("getblockhash", json!(hash_a))
            .reply("getblock", block_a.clone())
            .reply("getblockhash", json!(hash_b))
            .reply("getblock", block_b.clone());
        let config = test_config(index_path.clone(), Network::Signet, Some(101));
        let chain = BitcoinAnchorChain::with_transport(RpcClient::new(transport), &config).unwrap();
        assert_eq!(chain.start_height(), 101);
        assert_eq!(chain.scanned_height(), Some(102));
        assert_eq!(chain.entry_count(), 1);
        let anchor_ref = AnchorRef {
            txid: hash_from_rpc(&anchor_tx).unwrap(),
            location: MEMPOOL_LOCATION, // placeholder resolves by txid
        };
        assert_eq!(chain.anchor_at(&anchor_ref), Some(record));
        assert_eq!(chain.ctx_at(&anchor_ref), Some(ctx));
        assert_eq!(
            chain.locate(&anchor_ref),
            Some(AnchorLocation {
                height: 101,
                position: 1
            })
        );
        // Occurrence recognition via the bound payload.
        assert_eq!(
            chain.nullifier_occurrences(&raw_nf),
            vec![AnchorLocation {
                height: 101,
                position: 1
            }]
        );
        assert_eq!(chain.confirmations_at(101), 2);
        // Marker presence per scanned block: block A carries the
        // protocol marker, block B does not.
        assert_eq!(chain.block_has_marker(101), Some(true));
        assert_eq!(chain.block_has_marker(102), Some(false));
        assert_eq!(chain.block_has_marker(103), None);
    }

    // Reopen: the index is loaded from disk; only the reorg check hits RPC.
    {
        let transport = ScriptTransport::new();
        transport
            .reply("getblockchaininfo", blockchaininfo("signet", 102))
            .reply("getblockcount", json!(102))
            .reply("getblockhash", json!(hash_b));
        let config = test_config(index_path.clone(), Network::Signet, None);
        let chain = BitcoinAnchorChain::with_transport(RpcClient::new(transport), &config).unwrap();
        assert_eq!(chain.entry_count(), 1);
        assert_eq!(chain.scanned_height(), Some(102));
        assert_eq!(chain.block_has_marker(101), Some(true), "markers persist");
    }

    // A changed tip hash (reorg) truncates the index and forces a rescan.
    {
        let hash_new_a = display_hash(0xd1);
        let transport = ScriptTransport::new();
        transport
            .reply("getblockchaininfo", blockchaininfo("signet", 102))
            .reply("getblockcount", json!(102))
            .reply("getblockhash", json!(display_hash(0xff))) // != stored tip hash
            .reply("getblockhash", json!(hash_new_a))
            .reply(
                "getblock",
                json!({"hash": hash_new_a, "tx": [{"txid": display_hash(0x02), "vin": [{"coinbase": "ab"}], "vout": []}]}),
            )
            .reply("getblockhash", json!(hash_b))
            .reply("getblock", block_b);
        let config = test_config(index_path.clone(), Network::Signet, None);
        let chain = BitcoinAnchorChain::with_transport(RpcClient::new(transport), &config).unwrap();
        assert_eq!(
            chain.entry_count(),
            0,
            "the anchor was on the orphaned fork"
        );
    }
}

/// Small pure-function checks: ctx derivation, hash byte order, OP_RETURN
/// payload shapes.
#[test]
fn primitives() {
    // ctx = SHA-256(txid_internal ∥ vout_le): distinct outpoints give
    // distinct contexts, and the derivation is a hash of the whole
    // outpoint (not a fold of part of it).
    let txid = [0x11; 32];
    let ctx0 = funding_ctx(&txid, 0);
    let ctx5 = funding_ctx(&txid, 5);
    assert_ne!(ctx0, txid);
    assert_ne!(ctx0, ctx5);
    assert_ne!(funding_ctx(&[0x12; 32], 0), ctx0);

    // Canonical test vector — the protocol constant every backend and
    // third-party indexer must reproduce (opencsv-rs#2). Recompute with:
    //   python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex('11'*32)+(5).to_bytes(4,'little')).hexdigest())"
    assert_eq!(
        to_hex(&ctx5),
        "d48f515144348f4b5df84301bc9c842217aa95a09a37beec2bdd243d74c401d8",
    );

    // RPC display order is reversed internal order.
    let internal = hash_from_rpc(&display_hash(0x77)).unwrap();
    assert_eq!(internal, [0x77; 32]);
    let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let bytes = hash_from_rpc(hex).unwrap();
    assert_eq!(bytes[0], 0x1f);
    assert_eq!(bytes[31], 0x00);
    assert_eq!(hash_to_rpc(&bytes), hex);

    // OP_RETURN payload extraction: direct push, PUSHDATA1, PUSHDATA2.
    let payload = [9u8; 64];
    let direct = format!("6a40{}", to_hex(&payload));
    assert_eq!(op_return_payload(&direct), Some(payload));
    let push1 = format!("6a4c40{}", to_hex(&payload));
    assert_eq!(op_return_payload(&push1), Some(payload));
    let push2 = format!("6a4d4000{}", to_hex(&payload));
    assert_eq!(op_return_payload(&push2), Some(payload));
    // Wrong length, no OP_RETURN, trailing garbage: rejected.
    assert_eq!(
        op_return_payload(&format!("6a20{}", to_hex(&[9u8; 32]))),
        None
    );
    assert_eq!(
        op_return_payload(&format!("5140{}", to_hex(&payload))),
        None
    );
    assert_eq!(
        op_return_payload(&format!("6a40{}00", to_hex(&payload))),
        None
    );
}

/// The marker constant is `OP_0 <sha256(OP_TRUE)>` and its address is a
/// valid per-network bech32 form of the same program.
#[test]
fn marker_constant_is_pinned() {
    use sha2::{Digest as _, Sha256};
    let program: [u8; 32] = Sha256::digest(MARKER_SCRIPT).into();
    let mut expected = vec![0x00, 0x20];
    expected.extend_from_slice(&program);
    assert_eq!(MARKER_SPK.as_slice(), expected.as_slice());
    assert_eq!(MARKER_DUST_SATS, 546);
    assert_eq!(MARKER_DUST_BTC, 0.00000546);
    for network in [Network::Mainnet, Network::Signet, Network::Regtest] {
        let address = marker_address(network);
        let hrp = match network {
            Network::Mainnet => "bc",
            Network::Signet => "tb",
            Network::Regtest => "bcrt",
        };
        assert!(
            address.starts_with(&format!("{hrp}1")),
            "{network:?} address {address}"
        );
        assert_eq!(address.len(), hrp.len() + 60, "{network:?} {address}");
    }
    // Cross-check the regtest form against an independent bech32 decode:
    // the payload must be the witness-v0 marker program.
    assert_eq!(
        marker_address(Network::Regtest),
        crate::bech32::encode_v0("bcrt", &Sha256::digest(MARKER_SCRIPT)[..])
    );
}
