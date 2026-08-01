//! Smoke test: invoke the actual `opencsv` binary for the cheap commands
//! (no proving). Real end-to-end flows live in `flow_fast.rs` (mock proofs,
//! library-driven) and `e2e.rs` (real proofs, ignored by default).

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_opencsv");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn opencsv")
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn binary_smoke() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet = tmp.path().join("w");
    let w = wallet.to_str().unwrap();

    // keygen prints an owner key; keys lists it back.
    let out = ok(&run(&["--wallet-dir", w, "keygen"]));
    assert!(out.contains("key 0 owner "), "{out}");
    let owner_hex = out.trim().rsplit(' ').next().unwrap().to_string();
    assert_eq!(owner_hex.len(), 64);
    let out = ok(&run(&["--wallet-dir", w, "keys"]));
    assert!(out.contains(&owner_hex), "{out}");

    // issuer init prints an asset id; assets lists it.
    let out = ok(&run(&[
        "--wallet-dir",
        w,
        "issuer",
        "init",
        "--currency",
        "USD",
    ]));
    assert!(out.contains("asset "), "{out}");
    let asset_hex = out.trim().rsplit(' ').next().unwrap().to_string();
    assert_eq!(asset_hex.len(), 64);
    let out = ok(&run(&["--wallet-dir", w, "assets"]));
    assert!(
        out.contains(&asset_hex) && out.contains("currency USD"),
        "{out}"
    );

    // Empty wallet: zero balance, empty audit supply. The demo chain must
    // be requested explicitly — and warns that it is not Bitcoin.
    let out = ok(&run(&["--wallet-dir", w, "balance"]));
    assert_eq!(out.trim(), "0");
    let output = run(&[
        "--wallet-dir",
        w,
        "--chain",
        "demo",
        "audit",
        "--asset",
        &asset_hex,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("supply 0"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("DEMO CHAIN — not Bitcoin"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The default backend is real bitcoind RPC: an unreachable node is a
    // hard error, never a fallback to the demo chain.
    let output = run(&[
        "--wallet-dir",
        w,
        "--rpc-url",
        "http://127.0.0.1:1", // closed port, deterministically unreachable
        "chain",
        "tip",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error:"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Demo chain control: tip advances.
    let out = ok(&run(&[
        "--wallet-dir",
        w,
        "--chain",
        "demo",
        "chain",
        "tip",
    ]));
    assert_eq!(out.trim(), "tip 0");
    let out = ok(&run(&[
        "--wallet-dir",
        w,
        "--chain",
        "demo",
        "chain",
        "advance",
        "6",
    ]));
    assert_eq!(out.trim(), "tip 6");
    // The chain file lives in the wallet dir by default.
    assert!(wallet.join("chain.log").exists());

    // receive on a missing file fails with an error message.
    let output = run(&["--wallet-dir", w, "receive", "/nonexistent.bin"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));

    // Bad currency code is rejected.
    let output = run(&["--wallet-dir", w, "issuer", "init", "--currency", "USDD"]);
    assert!(!output.status.success());
}
