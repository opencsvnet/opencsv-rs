//! Serverless crediting round trip: sync the scan index, export the
//! anchor-snapshot JSON, and verify a REAL consignment through
//! `opencsv_verify_consignment` against exactly that export.
//! Skipped when no `bitcoind` binary is available.

mod common;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::Engine as _;
use common::{bitcoind_path, Node};
use opencsv_bitcoin::rpc::RpcAuth;
use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network};
use opencsv_core::chain::AnchorChain;
use opencsv_core::AnchorRecord;
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
fn export_snapshot_enables_serverless_crediting() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping export_snapshot_enables_serverless_crediting: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);

    // A real mint consignment, anchored on-chain with the marker.
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
        .map(|i| {
            u8::from_str_radix(
                &proved["anchor_record_hex"].as_str().unwrap()[2 * i..2 * i + 2],
                16,
            )
            .unwrap()
        })
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
    let mint_ref = anchor_chain.anchor(|_| mint_record).unwrap();
    // An XFER anchor too, so the export has more than one entry.
    let (raw_nf, xfer_ref) = common::anchor_xfer_retry(&mut anchor_chain, 33);
    anchor_chain.generate_blocks(6).unwrap();
    let mint_location = anchor_chain.locate(&mint_ref).expect("mint mined");
    let xfer_location = anchor_chain.locate(&xfer_ref).expect("xfer mined");
    let tip = anchor_chain.tip_height();

    // Sync the scan index (registers it), then export the snapshot.
    node.wait_for_filter_index();
    let cache_dir = tmp.path().join("scan-cache");
    let synced = take(unsafe {
        opencsv_scan_sync(
            cstr(&json!({
                "network": "regtest",
                "peers": [format!("127.0.0.1:{}", node.p2p_port)],
                "cache_dir": cache_dir,
                "from_height": 102,
                "required_confirmations": 6,
            })
            .to_string())
            .as_ptr(),
        )
    });
    assert_eq!(synced["tip_height"].as_u64().unwrap(), tip, "{synced}");

    let snapshot = take(opencsv_scan_export_snapshot());
    assert_eq!(snapshot["tip_height"].as_u64().unwrap(), tip, "{snapshot}");
    let entries = snapshot["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2, "{snapshot}");
    // Shape: valid 64-hex txid/ctx and 128-hex record, sorted by
    // (height, position), locations matching the chain view.
    let mut last = (0u64, 0u32);
    for entry in entries {
        for key in ["txid", "ctx"] {
            assert_eq!(entry[key].as_str().unwrap().len(), 64, "{entry}");
        }
        assert_eq!(entry["record"].as_str().unwrap().len(), 128, "{entry}");
        let here = (
            entry["height"].as_u64().unwrap(),
            entry["position"].as_u64().unwrap() as u32,
        );
        assert!(here >= last, "entries in chain order");
        last = here;
    }
    let exported_locs: Vec<(u64, u64)> = entries
        .iter()
        .map(|e| {
            (
                e["height"].as_u64().unwrap(),
                e["position"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        exported_locs,
        vec![
            (mint_location.height, mint_location.position as u64),
            (xfer_location.height, xfer_location.position as u64),
        ]
    );
    // And the txids/records/ctxs match the backend's view.
    assert_eq!(entries[0]["txid"].as_str().unwrap(), hex(&mint_ref.txid));
    assert_eq!(entries[1]["txid"].as_str().unwrap(), hex(&xfer_ref.txid));

    // The headline round trip: verify the real consignment against
    // EXACTLY the exported snapshot — serverless crediting.
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
    let verified = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob.as_ptr(),
            blob.len(),
            cstr(&snapshot.to_string()).as_ptr(),
            6,
        )
    });
    assert_eq!(verified["status"].as_str().unwrap(), "verified", "{verified}");
    assert_eq!(verified["credits"][0]["amount"].as_u64().unwrap(), 80);
    println!("serverless crediting round trip: VERIFIED via exported snapshot");

    // === the mempool-sentinel bug ---------------------------------------------
    // A consignment written right after broadcast carries MEMPOOL_LOCATION
    // (0,0) as the claimed anchor location. Prove + anchor a second mint,
    // resync, re-export — then finalize its consignment with the SENTINEL
    // ref, exactly the shape that produced AnchorNotFound on the phone.
    let proved2 = take(unsafe {
        opencsv_prove_mint(
            issuer,
            cstr(&asset_id).as_ptr(),
            cstr(&receiver_owner).as_ptr(),
            cstr("[25]").as_ptr(),
        )
    });
    let record2_bytes: [u8; 64] = (0..64)
        .map(|i| {
            u8::from_str_radix(
                &proved2["anchor_record_hex"].as_str().unwrap()[2 * i..2 * i + 2],
                16,
            )
            .unwrap()
        })
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let mint2_ref = anchor_chain
        .anchor(|_| AnchorRecord::from_bytes(&record2_bytes))
        .unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let mint2_location = anchor_chain.locate(&mint2_ref).expect("second mint mined");
    let tip = anchor_chain.tip_height();
    node.wait_for_filter_index();
    let synced = take(unsafe {
        opencsv_scan_sync(
            cstr(&json!({
                "network": "regtest",
                "peers": [format!("127.0.0.1:{}", node.p2p_port)],
                "cache_dir": cache_dir,
                "from_height": 102,
                "required_confirmations": 6,
            })
            .to_string())
            .as_ptr(),
        )
    });
    assert_eq!(synced["tip_height"].as_u64().unwrap(), tip, "{synced}");
    let snapshot2 = take(opencsv_scan_export_snapshot());

    // (1) Sentinel ref + snapshot containing the mined anchor → VERIFIED
    //     (previously AnchorNotFound).
    let finalized2 = take(unsafe {
        opencsv_consignment_finalize(
            issuer,
            proved2["pending_id"].as_u64().unwrap(),
            cstr(&json!({
                "txid": hex(&mint2_ref.txid),
                "height": 0,
                "position": 0,
            })
            .to_string())
            .as_ptr(),
        )
    });
    let blob2 = base64::engine::general_purpose::STANDARD
        .decode(finalized2["consignment_base64"].as_str().unwrap())
        .unwrap();
    let verified2 = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob2.as_ptr(),
            blob2.len(),
            cstr(&snapshot2.to_string()).as_ptr(),
            6,
        )
    });
    assert_eq!(verified2["status"].as_str().unwrap(), "verified", "{verified2}");
    // (4) The resolved location is the mined one — not (0,0).
    assert_eq!(
        verified2["anchor"]["height"].as_u64().unwrap(),
        mint2_location.height,
        "{verified2}"
    );
    assert_eq!(
        verified2["anchor"]["position"].as_u64().unwrap(),
        mint2_location.position as u64,
        "{verified2}"
    );
    println!("mempool-sentinel consignment: VERIFIED (resolved to {mint2_location:?})");

    // (2) Sentinel txid absent from the snapshot → honest AnchorNotFound
    //     (the first export predates the second mint).
    let rejected = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob2.as_ptr(),
            blob2.len(),
            cstr(&snapshot.to_string()).as_ptr(),
            6,
        )
    });
    assert_eq!(rejected["status"].as_str().unwrap(), "rejected", "{rejected}");
    assert!(
        rejected["reason"].as_str().unwrap().contains("AnchorNotFound"),
        "{rejected}"
    );

    // (3) Non-sentinel claims unchanged: a wrong EXPLICIT location is
    //     still rejected strictly (a third mint, finalized with the
    //     wrong position while its entry sits elsewhere in the snapshot).
    let proved3 = take(unsafe {
        opencsv_prove_mint(
            issuer,
            cstr(&asset_id).as_ptr(),
            cstr(&receiver_owner).as_ptr(),
            cstr("[10]").as_ptr(),
        )
    });
    let record3_bytes: [u8; 64] = (0..64)
        .map(|i| {
            u8::from_str_radix(
                &proved3["anchor_record_hex"].as_str().unwrap()[2 * i..2 * i + 2],
                16,
            )
            .unwrap()
        })
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let mint3_ref = anchor_chain
        .anchor(|_| AnchorRecord::from_bytes(&record3_bytes))
        .unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let mint3_location = anchor_chain.locate(&mint3_ref).expect("third mint mined");
    node.wait_for_filter_index();
    take(unsafe {
        opencsv_scan_sync(
            cstr(&json!({
                "network": "regtest",
                "peers": [format!("127.0.0.1:{}", node.p2p_port)],
                "cache_dir": cache_dir,
                "from_height": 102,
                "required_confirmations": 6,
            })
            .to_string())
            .as_ptr(),
        )
    });
    let snapshot3 = take(opencsv_scan_export_snapshot());
    let finalized3 = take(unsafe {
        opencsv_consignment_finalize(
            issuer,
            proved3["pending_id"].as_u64().unwrap(),
            cstr(&json!({
                "txid": hex(&mint3_ref.txid),
                "height": mint3_location.height,
                "position": mint3_location.position + 1,
            })
            .to_string())
            .as_ptr(),
        )
    });
    let blob3 = base64::engine::general_purpose::STANDARD
        .decode(finalized3["consignment_base64"].as_str().unwrap())
        .unwrap();
    let rejected = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob3.as_ptr(),
            blob3.len(),
            cstr(&snapshot3.to_string()).as_ptr(),
            6,
        )
    });
    assert_eq!(rejected["status"].as_str().unwrap(), "rejected", "{rejected}");
    assert!(
        rejected["reason"].as_str().unwrap().contains("AnchorNotFound"),
        "explicit wrong location stays strict: {rejected}"
    );
}
