//! Persistent-client test: two sequential syncs on one `client_id`
//! handshake once (the one-shot `opencsv_scan_sync` re-dials per call).
//! Skipped when no `bitcoind` binary is available.

mod common;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use common::{bitcoind_path, Node};
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

#[test]
fn persistent_client_handshakes_once() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping persistent_client_handshakes_once: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);
    node.wait_for_filter_index();

    let config = || {
        json!({
            "network": "regtest",
            "peers": [format!("127.0.0.1:{}", node.p2p_port)],
            "cache_dir": tmp.path().join("cbf-persistent"),
            "from_height": 100,
            "required_confirmations": 0,
        })
        .to_string()
    };

    // Open: one handshake per configured peer.
    let opened = take(unsafe { opencsv_cbf_open(cstr(&config()).as_ptr()) });
    let client_id = opened["client_id"].as_u64().expect("client_id");
    assert_eq!(opened["tip_height"].as_u64().unwrap(), 101);
    assert_eq!(opened["handshakes"].as_u64().unwrap(), 1, "{opened}");

    // Two sequential syncs on the same client: no re-handshake.
    let first = take(opencsv_scan_sync_with(client_id));
    assert_eq!(first["tip_height"].as_u64().unwrap(), 101, "{first}");
    assert_eq!(first["handshakes"].as_u64().unwrap(), 1, "{first}");
    let second = take(opencsv_scan_sync_with(client_id));
    assert_eq!(second["handshakes"].as_u64().unwrap(), 1, "{second}");
    println!("persistent client: open handshakes=1, sync_with ×2 handshakes=1");

    // The one-shot API still works (and re-dials: its own client).
    let oneshot = take(unsafe { opencsv_scan_sync(cstr(&config()).as_ptr()) });
    assert_eq!(oneshot["tip_height"].as_u64().unwrap(), 101, "{oneshot}");

    let third = take(opencsv_scan_sync_with(client_id));
    assert_eq!(third["handshakes"].as_u64().unwrap(), 1, "{third}");

    // Close: unknown ids are errors.
    assert_eq!(take(opencsv_cbf_close(client_id))["ok"], json!(true));
    let err = take(opencsv_scan_sync_with(client_id));
    assert!(err.get("error").is_some(), "{err}");
}
