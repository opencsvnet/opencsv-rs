//! End-to-end round-trip through the C ABI: issuer wallet mints to a
//! receiver wallet, the test plays the anchor server, and the receiver
//! verifies the consignment against a snapshot — exactly the call sequence
//! a host app makes. (Mint→verify only: a transfer prove is ~100× slower in
//! debug and is exercised by `crates/opencsv-pcd`'s release benches.)

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::Engine as _;
use opencsv_core::field::hash_felts;
use opencsv_ffi::snapshot::{Snapshot, SnapshotEntry};
use opencsv_ffi::*;
use p3_baby_bear::BabyBear;

/// Take ownership of a returned JSON string and parse it.
fn take(ptr: *mut c_char) -> serde_json::Value {
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

fn str_of(v: &serde_json::Value, key: &str) -> String {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing {key} in {v}"))
        .to_owned()
}

/// The test's stand-in for the anchor server: an append-only log with
/// FileAnchorChain's txid derivation.
#[derive(Default)]
struct TestChain {
    tip_height: u64,
    entries: Vec<SnapshotEntry>,
}

impl TestChain {
    /// Append a record (hex) under transaction context `ctx` (hex) at the
    /// tip, returning the anchor-ref JSON the server would respond with.
    fn append(&mut self, record_hex: &str, ctx_hex: &str) -> String {
        let ordinal = self.entries.len() as u32;
        let txid = hash_felts("mock-txid", &[&[BabyBear::new(ordinal)]]);
        let position = self
            .entries
            .iter()
            .filter(|e| e.height == self.tip_height)
            .count() as u32;
        let txid_hex: String = txid.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        self.entries.push(SnapshotEntry {
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
fn mint_to_verify_round_trip() {
    // Issuer wallet with a USD asset.
    let issuer_secrets = take(opencsv_wallet_create());
    let opened = take(unsafe { opencsv_wallet_open(cstr(&issuer_secrets.to_string()).as_ptr()) });
    let issuer = opened["handle"].as_u64().expect("handle");
    let asset_id = str_of(
        &take(unsafe { opencsv_wallet_init_issuer(issuer, cstr("USD").as_ptr()) }),
        "asset_id",
    );

    // Receiver wallet.
    let receiver_secrets = take(opencsv_wallet_create());
    let opened = take(unsafe { opencsv_wallet_open(cstr(&receiver_secrets.to_string()).as_ptr()) });
    let receiver = opened["handle"].as_u64().expect("handle");
    let receiver_owner = opened["owners"][0].as_str().expect("owner").to_owned();

    // Prove the mint (issuer side), publish its anchor, finalize.
    let proved = take(unsafe {
        opencsv_prove_mint(
            issuer,
            cstr(&asset_id).as_ptr(),
            cstr(&receiver_owner).as_ptr(),
            cstr("[100]").as_ptr(),
        )
    });
    assert!(proved["error"].is_null(), "prove_mint failed: {proved}");
    let pending_id = proved["pending_id"].as_u64().expect("pending_id");

    let mut chain = TestChain::default();
    let anchor_ref = chain.append(
        &str_of(&proved, "anchor_record_hex"),
        &str_of(&proved, "ctx_hex"),
    );

    let finalized = take(unsafe {
        opencsv_consignment_finalize(issuer, pending_id, cstr(&anchor_ref).as_ptr())
    });
    assert!(finalized["error"].is_null(), "finalize failed: {finalized}");
    let blob = base64::engine::general_purpose::STANDARD
        .decode(str_of(&finalized, "consignment_base64"))
        .expect("valid base64");

    // Not enough confirmations yet: tip is at the anchor height.
    let verdict = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob.as_ptr(),
            blob.len(),
            cstr(&chain.snapshot_json()).as_ptr(),
            6,
        )
    });
    assert_eq!(verdict["status"], "rejected", "verdict: {verdict}");
    assert!(
        str_of(&verdict, "reason").contains("InsufficientConfirmations"),
        "verdict: {verdict}"
    );

    // Six blocks later the consignment verifies and credits 100 USD.
    chain.tip_height += 6;
    let verdict = take(unsafe {
        opencsv_verify_consignment(
            receiver,
            blob.as_ptr(),
            blob.len(),
            cstr(&chain.snapshot_json()).as_ptr(),
            6,
        )
    });
    assert_eq!(verdict["status"], "verified", "verdict: {verdict}");
    assert_eq!(verdict["credits"][0]["amount"], 100);
    assert_eq!(verdict["credits"][0]["currency"], "USD");
    assert_eq!(str_of(&verdict["credits"][0].clone(), "asset_id"), asset_id);

    let balances = take(opencsv_balance(receiver));
    assert_eq!(balances["balances"][0]["amount"], 100);

    // The public supply audit agrees.
    let audit = take(unsafe {
        opencsv_audit(
            cstr(&asset_id).as_ptr(),
            cstr(&chain.snapshot_json()).as_ptr(),
        )
    });
    assert_eq!(audit["supply"], 100);

    // Replay model: a fresh open from persisted secrets rebuilds the same
    // balance by re-verifying the stored blob, and spend-state replay sticks.
    let reopened =
        take(unsafe { opencsv_wallet_open(cstr(&receiver_secrets.to_string()).as_ptr()) });
    let receiver2 = reopened["handle"].as_u64().expect("handle");
    let verdict = take(unsafe {
        opencsv_verify_consignment(
            receiver2,
            blob.as_ptr(),
            blob.len(),
            cstr(&chain.snapshot_json()).as_ptr(),
            6,
        )
    });
    assert_eq!(verdict["status"], "verified", "verdict: {verdict}");
    let coin_id = str_of(&verdict["coins"][0].clone(), "id");
    let marked = take(unsafe {
        opencsv_wallet_mark_spent(receiver2, cstr(&format!("[\"{coin_id}\"]")).as_ptr())
    });
    assert_eq!(marked["ok"], true, "mark_spent: {marked}");
    let status = take(opencsv_wallet_status(receiver2));
    let coin = status["coins"]
        .as_array()
        .expect("coins")
        .iter()
        .find(|c| c["id"] == coin_id.as_str())
        .expect("marked coin present");
    assert_eq!(coin["unspent"], false);

    for handle in [issuer, receiver, receiver2] {
        take(opencsv_wallet_close(handle));
    }
}

#[test]
fn rejects_garbage_and_unknown_handles() {
    let opened = take(unsafe {
        opencsv_wallet_open(cstr(&take(opencsv_wallet_create()).to_string()).as_ptr())
    });
    let handle = opened["handle"].as_u64().expect("handle");

    // A garbage blob fails decoding with an error, not a panic.
    let garbage = [0u8; 16];
    let result = take(unsafe {
        opencsv_verify_consignment(
            handle,
            garbage.as_ptr(),
            garbage.len(),
            cstr("{\"tip_height\":0,\"entries\":[]}").as_ptr(),
            6,
        )
    });
    assert!(result["error"].as_str().is_some(), "result: {result}");

    // Unknown handles error cleanly.
    let result = take(opencsv_balance(9999));
    assert!(result["error"].as_str().is_some(), "result: {result}");

    // Malformed secrets error cleanly.
    let result = take(unsafe { opencsv_wallet_open(cstr("not json").as_ptr()) });
    assert!(result["error"].as_str().is_some(), "result: {result}");

    take(opencsv_wallet_close(handle));
}
