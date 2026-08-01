//! Tests for the three batch-3 additions:
//!
//! - pending export/import round-trip across a wallet close/reopen
//!   (the crash-loses-consignment gap);
//! - cross-checked accept (`opencsv_cross_check`) with one malicious
//!   member hiding an occurrence, a tip disagreement, and an
//!   all-honest verified mint through the C ABI;
//! - CBF config error handling (the heavy CBF path is exercised by
//!   `opencsv-cbf`'s own regtest suite).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::Engine as _;
use opencsv_core::accept::{public_input, MockVerifier};
use opencsv_core::chain::AnchorLocation;
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::{AnchorRecord, AssetGenesis, AssetId, Digest, OwnerSecret};
use opencsv_ffi::crosscheck::{run_cross_check, CrossCheckFailure};
use opencsv_ffi::snapshot::{entry_json, Snapshot};
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

fn open_wallet() -> (u64, String) {
    let secrets = take(opencsv_wallet_create());
    let opened = take(unsafe { opencsv_wallet_open(cstr(&secrets.to_string()).as_ptr()) });
    (
        opened["handle"].as_u64().expect("handle"),
        secrets.to_string(),
    )
}

fn digest(byte: u8) -> Digest {
    Digest::from_bytes([byte; 32])
}

/// The test's stand-in anchor log (append-only, mock txids).
#[derive(Default)]
struct TestChain {
    tip_height: u64,
    entries: Vec<opencsv_ffi::snapshot::SnapshotEntry>,
}

impl TestChain {
    fn append(&mut self, record_hex: &str, ctx_hex: &str) -> String {
        let ordinal = self.entries.len() as u32;
        let txid = {
            use opencsv_core::field::hash_felts;
            use p3_baby_bear::BabyBear;
            hash_felts("mock-txid", &[&[BabyBear::new(ordinal)]])
        };
        let txid_hex: String = txid.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let position = self
            .entries
            .iter()
            .filter(|e| e.height == self.tip_height)
            .count() as u32;
        self.entries.push(opencsv_ffi::snapshot::SnapshotEntry {
            height: self.tip_height,
            position,
            txid: txid_hex.clone(),
            ctx: ctx_hex.to_owned(),
            record: record_hex.to_owned(),
        });
        format!(
            "{{\"txid\":\"{txid_hex}\",\"height\":{},\"position\":{position}}}",
            self.tip_height
        )
    }

    fn snapshot_json(&self) -> String {
        serde_json::to_string(&Snapshot {
            tip_height: self.tip_height,
            entries: self.entries.clone(),
        })
        .expect("snapshot serializes")
    }
}

#[test]
fn pending_export_import_survives_wallet_restart() {
    // Issuer wallet proves a mint to the receiver.
    let (issuer, _) = open_wallet();
    let asset = take(unsafe { opencsv_wallet_init_issuer(issuer, cstr("USD").as_ptr()) });
    let asset_id = asset["asset_id"].as_str().unwrap().to_string();
    let (receiver, _) = open_wallet();
    let status = take(opencsv_wallet_status(receiver));
    let receiver_owner = status["owners"][0].as_str().unwrap().to_string();

    let proved = take(unsafe {
        opencsv_prove_mint(
            issuer,
            cstr(&asset_id).as_ptr(),
            cstr(&receiver_owner).as_ptr(),
            cstr("[100]").as_ptr(),
        )
    });
    let pending_id = proved["pending_id"].as_u64().unwrap();
    let record_hex = proved["anchor_record_hex"].as_str().unwrap().to_string();
    let ctx_hex = proved["ctx_hex"].as_str().unwrap().to_string();

    // Export, then simulate a crash: close the wallet and reopen from
    // secrets (pending transactions live only in memory — that is the
    // gap this API closes).
    let exported = take(opencsv_pending_export(issuer, pending_id));
    let pending_json = exported["pending_json"].as_str().unwrap().to_string();
    assert!(pending_json.contains("\"version\":1"));
    let secrets = take(opencsv_wallet_secrets(issuer)).to_string();
    take(opencsv_wallet_close(issuer));
    let reopened = take(unsafe { opencsv_wallet_open(cstr(&secrets).as_ptr()) });
    let issuer2 = reopened["handle"].as_u64().unwrap();

    // The reopened wallet has no pending state; import restores it.
    let err = take(opencsv_pending_export(issuer2, pending_id));
    assert!(err.get("error").is_some(), "export is in-memory only: {err}");
    let imported = take(unsafe {
        opencsv_pending_import(issuer2, cstr(&pending_json).as_ptr())
    });
    let new_pending = imported["pending_id"].as_u64().unwrap();

    // Finalize against the anchor log: the consignment must verify —
    // the export captured everything finalize needs (openings with
    // their fresh randomness, proof, aux genesis).
    let mut chain = TestChain::default();
    let anchor_ref = chain.append(&record_hex, &ctx_hex);
    chain.tip_height = 6;
    let finalized = take(unsafe {
        opencsv_consignment_finalize(issuer2, new_pending, cstr(&anchor_ref).as_ptr())
    });
    let blob = base64::engine::general_purpose::STANDARD
        .decode(finalized["consignment_base64"].as_str().unwrap())
        .unwrap();
    let verified = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob.as_ptr(),
            blob.len(),
            cstr(&chain.snapshot_json()).as_ptr(),
            6,
        )
    });
    assert_eq!(
        verified["status"].as_str().unwrap(),
        "verified",
        "{verified}"
    );
    assert_eq!(verified["credits"][0]["amount"].as_u64().unwrap(), 100);

    // Unknown pending id → error, on both calls.
    let err = take(opencsv_pending_export(issuer2, 9999));
    assert!(err.get("error").is_some());
    let err = take(unsafe { opencsv_pending_import(issuer2, cstr("{}").as_ptr()) });
    assert!(err.get("error").is_some());
}

/// A double-spend scenario as two snapshot backend views: the honest
/// one has both anchors, the malicious one hides the legitimate first.
struct DsScenario {
    nf: Digest,
    honest: Value,
    malicious: Value,
    malicious_tip8: Value,
    consignment: Consignment,
    asset_id: AssetId,
    receiver: OwnerSecret,
}

fn ds_scenario() -> DsScenario {
    let nf = digest(42);
    let ctx1 = [1u8; 32];
    let ctx2 = [2u8; 32];
    let record1 = AnchorRecord::xfer(&[nf], &ctx1);
    let record2 = AnchorRecord::xfer(&[nf], &ctx2);
    let asset_id = AssetGenesis {
        issuer_pk: [7u8; 32],
        currency_code: *b"USD",
        terms_hash: digest(9),
        nonce: 1,
    }
    .asset_id();
    let receiver = OwnerSecret::from_bytes([3u8; 32]);
    let opening = CoinOpening {
        asset_id,
        value: 50,
        owner: receiver.owner(),
        randomness: digest(5),
    };
    let consignment = Consignment {
        coin_openings: vec![opening],
        nullifiers: vec![nf],
        proof: MockVerifier::prove(COIN_VK, &public_input(&record2, &ctx2, &[opening])),
        anchor_ref: opencsv_core::chain::AnchorRef {
            txid: [0xb0; 32],
            location: AnchorLocation {
                height: 1,
                position: 0,
            },
        },
        aux: None,
    };
    let snapshot = |tip: u64, entries: Vec<_>| {
        json!({ "type": "snapshot", "snapshot": { "tip_height": tip, "entries": entries } })
    };
    let e1 = entry_json(
        AnchorLocation {
            height: 0,
            position: 0,
        },
        &[0xa0; 32],
        &record1,
        &ctx1,
    );
    let e2 = entry_json(
        AnchorLocation {
            height: 1,
            position: 0,
        },
        &[0xb0; 32],
        &record2,
        &ctx2,
    );
    DsScenario {
        nf,
        honest: snapshot(7, vec![e1.clone(), e2.clone()]),
        malicious: snapshot(7, vec![e2.clone()]),
        malicious_tip8: snapshot(8, vec![e2]),
        consignment,
        asset_id,
        receiver,
    }
}

fn cross_check_json(s: &DsScenario, backends: Vec<Value>) -> String {
    let blob = base64::engine::general_purpose::STANDARD.encode(s.consignment.to_bytes());
    json!({
        "backends": backends,
        "consignment_base64": blob,
        "required_confirmations": 6,
    })
    .to_string()
}

#[test]
fn cross_check_one_malicious_member_rejects_double_spend() {
    let s = ds_scenario();
    let secrets = [s.receiver];
    let known = [s.asset_id];

    // Control: the malicious backend alone accepts (it sees the
    // double-spend anchor as the first occurrence).
    let alone = run_cross_check(
        &cross_check_json(&s, vec![s.malicious.clone()]),
        &secrets,
        &known,
        &MockVerifier,
    )
    .expect("request runs");
    assert_eq!(alone["status"].as_str().unwrap(), "verified", "{alone}");

    // Cross-checked with an honest member: the earliest reported
    // occurrence is the legitimate anchor → the double-spend is
    // rejected.
    let cross = run_cross_check(
        &cross_check_json(&s, vec![s.honest.clone(), s.malicious.clone()]),
        &secrets,
        &known,
        &MockVerifier,
    )
    .expect("request runs");
    assert_eq!(cross["status"].as_str().unwrap(), "rejected", "{cross}");
    assert!(
        cross["reason"].as_str().unwrap().contains("NullifierConflict"),
        "{cross}"
    );
    let _ = s.nf;
}

#[test]
fn cross_check_tip_disagreement_is_a_hard_error() {
    let s = ds_scenario();
    let failure = run_cross_check(
        &cross_check_json(&s, vec![s.honest.clone(), s.malicious_tip8.clone()]),
        &[s.receiver],
        &[s.asset_id],
        &MockVerifier,
    )
    .expect_err("tip disagreement must not silently resolve");
    match failure {
        CrossCheckFailure::TipDisagreement(tips) => assert_eq!(tips, vec![7, 8]),
        other => panic!("expected TipDisagreement, got {other}"),
    }

    // And through the C ABI it carries the structured kind.
    let (wallet, _) = open_wallet();
    let request = cstr(&cross_check_json(&s, vec![s.honest.clone(), s.malicious_tip8.clone()]));
    let out = take(unsafe { opencsv_cross_check(wallet, request.as_ptr()) });
    assert_eq!(out["kind"].as_str().unwrap(), "tip_disagreement", "{out}");
    assert!(out.get("error").is_some());
}

#[test]
fn cross_check_all_honest_mint_verified_via_c_abi() {
    // A real mint consignment (real PCD proof), two identical snapshot
    // backends.
    let (issuer, _) = open_wallet();
    let asset = take(unsafe { opencsv_wallet_init_issuer(issuer, cstr("USD").as_ptr()) });
    let asset_id = asset["asset_id"].as_str().unwrap().to_string();
    let (receiver, _) = open_wallet();
    let status = take(opencsv_wallet_status(receiver));
    let receiver_owner = status["owners"][0].as_str().unwrap().to_string();
    let proved = take(unsafe {
        opencsv_prove_mint(
            issuer,
            cstr(&asset_id).as_ptr(),
            cstr(&receiver_owner).as_ptr(),
            cstr("[70]").as_ptr(),
        )
    });
    let mut chain = TestChain::default();
    let anchor_ref = chain.append(
        proved["anchor_record_hex"].as_str().unwrap(),
        proved["ctx_hex"].as_str().unwrap(),
    );
    chain.tip_height = 6;
    let finalized = take(unsafe {
        opencsv_consignment_finalize(
            issuer,
            proved["pending_id"].as_u64().unwrap(),
            cstr(&anchor_ref).as_ptr(),
        )
    });
    let snapshot_backend = json!({
        "type": "snapshot",
        "snapshot": serde_json::from_str::<Value>(&chain.snapshot_json()).unwrap(),
    });
    let request = cstr(
        &json!({
            "backends": [snapshot_backend.clone(), snapshot_backend],
            "consignment_base64": finalized["consignment_base64"].as_str().unwrap(),
            "required_confirmations": 6,
        })
        .to_string(),
    );
    let out = take(unsafe { opencsv_cross_check(receiver, request.as_ptr()) });
    assert_eq!(out["status"].as_str().unwrap(), "verified", "{out}");
    assert_eq!(out["coins"][0]["value"].as_u64().unwrap(), 70);
    assert_eq!(out["tip_height"].as_u64().unwrap(), 6);

    // Read-only: the check does not credit the wallet.
    let balance = take(opencsv_balance(receiver));
    assert_eq!(balance["balances"].as_array().unwrap().len(), 0, "{balance}");
}

#[test]
fn cbf_config_errors_are_json() {
    // Unknown network.
    let out = take(unsafe {
        opencsv_cbf_sync(cstr(r#"{"network":"mars","peers":["127.0.0.1:1"],"cache_dir":"/tmp/x"}"#).as_ptr())
    });
    assert!(out.get("error").is_some(), "{out}");
    // Unreachable peers.
    let out = take(unsafe {
        opencsv_cbf_sync(
            cstr(r#"{"network":"regtest","peers":["127.0.0.1:1"],"cache_dir":"/tmp/opencsv-ffi-cbf-test","timeout_ms":500}"#).as_ptr(),
        )
    });
    assert!(out.get("error").is_some(), "{out}");
    // verify_anchor without the anchor member.
    let out = take(unsafe {
        opencsv_cbf_verify_anchor(
            cstr(r#"{"network":"regtest","peers":["127.0.0.1:1"],"cache_dir":"/tmp/x"}"#).as_ptr(),
        )
    });
    assert!(out.get("error").is_some(), "{out}");
}
