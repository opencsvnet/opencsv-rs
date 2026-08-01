//! End-to-end scan-engine test through the C ABI: sync the occurrence
//! index against a real regtest node, verify a real consignment
//! scan-only, local occurrence checks, and a double-spend rejection.
//!
//! Skipped (silently green) when no `bitcoind` binary is available.

mod common;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::Engine as _;
use common::{bitcoind_path, Node};
use opencsv_bitcoin::rpc::RpcAuth;
use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network};
use opencsv_core::accept::{public_input, MockVerifier};
use opencsv_core::chain::{AnchorChain, AnchorRef};
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::{AnchorRecord, AssetGenesis, Digest, OwnerSecret};
use opencsv_ffi::scan::verify_json;
use opencsv_ffi::wallet::COIN_VK;
use opencsv_ffi::*;
use serde_json::{json, Value};

fn take(ptr: *mut c_char) -> Value {
    assert!(!ptr.is_null());
    let json = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("UTF-8")
        .to_owned();
    unsafe { opencsv_string_free(ptr) };
    serde_json::from_str(&json).expect("valid JSON")
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_wallet() -> u64 {
    let secrets = take(opencsv_wallet_create());
    let opened = take(unsafe { opencsv_wallet_open(cstr(&secrets.to_string()).as_ptr()) });
    opened["handle"].as_u64().expect("handle")
}

#[test]
fn scan_sync_check_verify_via_c_abi() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping scan_sync_check_verify_via_c_abi: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);

    // --- a real mint consignment, anchored on-chain ------------------------
    let issuer = open_wallet();
    let asset = take(unsafe { opencsv_wallet_init_issuer(issuer, cstr("USD").as_ptr()) });
    let asset_id = asset["asset_id"].as_str().unwrap().to_string();
    let receiver = open_wallet();
    let status = take(opencsv_wallet_status(receiver));
    let receiver_owner = status["owners"][0].as_str().unwrap().to_string();
    let proved = take(unsafe {
        opencsv_prove_mint(
            issuer,
            cstr(&asset_id).as_ptr(),
            cstr(&receiver_owner).as_ptr(),
            cstr("[80]").as_ptr(),
        )
    });
    let record_bytes: [u8; 64] = (0..64)
        .map(|i| u8::from_str_radix(&proved["anchor_record_hex"].as_str().unwrap()[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let mint_record = AnchorRecord::from_bytes(&record_bytes);

    let btc_config = BtcConfig {
        network: Network::Regtest,
        rpc_url: node.rpc_url.clone(),
        auth: RpcAuth::Cookie(node.cookie.clone()),
        wallet: Some("test".into()),
        scan_from: Some(1),
        index_path: tmp.path().join("bitcoin-index.log"),
    };
    let mut anchor_chain = BitcoinAnchorChain::open(&btc_config).unwrap();
    // MINT records are ctx-independent, so the closure ignores the
    // funding ctx; the marker output is added by the backend.
    let mint_ref = anchor_chain.anchor(|_| mint_record).unwrap();

    // An XFER anchor binding a known raw nullifier (for scan_check and
    // the double-spend scenario).
    let raw_nf = Digest::from_bytes([31u8; 32]);
    let ref1 = anchor_chain
        .anchor(|ctx| AnchorRecord::xfer(&[raw_nf], ctx))
        .unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let mint_location = anchor_chain.locate(&mint_ref).expect("mint mined");
    let loc1 = anchor_chain.locate(&ref1).expect("xfer mined");
    let ctx1 = anchor_chain.ctx_at(&ref1).unwrap();
    let record1 = anchor_chain.anchor_at(&ref1).unwrap();
    let tip = anchor_chain.tip_height();
    assert_eq!(tip, 107);

    // --- scan sync via the ABI ---------------------------------------------
    node.wait_for_filter_index();
    let cache_dir = tmp.path().join("scan-cache");
    let sync_config = || {
        json!({
            "network": "regtest",
            "peers": [format!("127.0.0.1:{}", node.p2p_port)],
            "cache_dir": cache_dir,
            "from_height": 102,
            "required_confirmations": 6,
        })
        .to_string()
    };
    let synced = take(unsafe { opencsv_scan_sync(cstr(&sync_config()).as_ptr()) });
    assert_eq!(synced["tip_height"].as_u64().unwrap(), tip, "{synced}");
    assert_eq!(synced["anchors"].as_u64().unwrap(), 2, "{synced}");
    println!(
        "scan_sync: tip={} filters={}B blocks={}B anchors={}",
        synced["tip_height"], synced["filters_bytes"], synced["blocks_bytes"], synced["anchors"]
    );

    // --- scan verify of the real mint consignment ---------------------------
    let finalized = take(unsafe {
        opencsv_consignment_finalize(
            issuer,
            proved["pending_id"].as_u64().unwrap(),
            cstr(&json!({
                "txid": hex(&mint_ref.txid),
                "height": mint_location.height,
                "position": mint_location.position,
            })
            .to_string())
            .as_ptr(),
        )
    });
    let blob = base64::engine::general_purpose::STANDARD
        .decode(finalized["consignment_base64"].as_str().unwrap())
        .unwrap();
    let verdict = take(unsafe { opencsv_scan_verify(receiver, cstr(&hex(&blob)).as_ptr()) });
    assert_eq!(verdict["status"].as_str().unwrap(), "verified", "{verdict}");
    assert_eq!(verdict["coins"][0]["value"].as_u64().unwrap(), 80);
    assert_eq!(verdict["confirmations"].as_u64().unwrap(), 6);
    println!("scan-only accept via ABI: VERIFIED (no RPC, no indexer)");

    // --- local occurrence checks --------------------------------------------
    let occurrence = take(unsafe {
        opencsv_scan_check(
            receiver,
            cstr(&json!({"raw_nf_hex": hex(raw_nf.as_bytes()), "birth": 102, "spend": tip}).to_string())
                .as_ptr(),
        )
    });
    assert_eq!(
        occurrence["occurrence"]["height"].as_u64().unwrap(),
        loc1.height,
        "{occurrence}"
    );
    assert_eq!(
        occurrence["occurrence"]["ctx_hex"].as_str().unwrap(),
        hex(&ctx1),
        "{occurrence}"
    );
    let none = take(unsafe {
        opencsv_scan_check(
            receiver,
            cstr(&json!({"raw_nf_hex": hex(&[77u8; 32]), "birth": 102, "spend": tip}).to_string())
                .as_ptr(),
        )
    });
    assert!(none["occurrence"].is_null(), "{none}");

    // --- a real double-spend: NullifierConflict ------------------------------
    let ref2 = anchor_chain
        .anchor(|ctx| AnchorRecord::xfer(&[raw_nf], ctx))
        .unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let loc2 = anchor_chain.locate(&ref2).expect("double-spend mined");
    let ctx2 = anchor_chain.ctx_at(&ref2).unwrap();
    let record2 = anchor_chain.anchor_at(&ref2).unwrap();
    node.wait_for_filter_index();
    let synced = take(unsafe { opencsv_scan_sync(cstr(&sync_config()).as_ptr()) });
    assert_eq!(synced["anchors"].as_u64().unwrap(), 3, "{synced}");

    // The double-spend consignment (the exclusion path is what's under
    // test; proof verification is orthogonal — the fast mock verifier
    // stands in, as in the cross-check tests).
    let receiver_secret = OwnerSecret::from_bytes([8u8; 32]);
    let known_asset = AssetGenesis {
        issuer_pk: [7u8; 32],
        currency_code: *b"USD",
        terms_hash: Digest::from_bytes([3u8; 32]),
        nonce: 1,
    }
    .asset_id();
    let opening = CoinOpening {
        asset_id: known_asset,
        value: 50,
        owner: receiver_secret.owner(),
        randomness: Digest::from_bytes([9u8; 32]),
    };
    let ds_consignment = Consignment {
        coin_openings: vec![opening],
        nullifiers: vec![raw_nf],
        proof: MockVerifier::prove(COIN_VK, &public_input(&record2, &ctx2, &[opening])),
        anchor_ref: AnchorRef {
            txid: ref2.txid,
            location: loc2,
        },
        aux: None,
    };
    let rejected = verify_json(
        &hex(&ds_consignment.to_bytes()),
        &[receiver_secret],
        &[known_asset],
        &MockVerifier,
    )
    .unwrap();
    assert_eq!(rejected["status"].as_str().unwrap(), "rejected", "{rejected}");
    assert!(
        rejected["reason"].as_str().unwrap().contains("NullifierConflict"),
        "{rejected}"
    );

    // The legitimate spend still verifies against the same index.
    let legit_consignment = Consignment {
        coin_openings: vec![opening],
        nullifiers: vec![raw_nf],
        proof: MockVerifier::prove(COIN_VK, &public_input(&record1, &ctx1, &[opening])),
        anchor_ref: AnchorRef {
            txid: ref1.txid,
            location: loc1,
        },
        aux: None,
    };
    let verified = verify_json(
        &hex(&legit_consignment.to_bytes()),
        &[receiver_secret],
        &[known_asset],
        &MockVerifier,
    )
    .unwrap();
    assert_eq!(verified["status"].as_str().unwrap(), "verified", "{verified}");
}
