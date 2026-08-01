//! # opencsv-ffi
//!
//! C ABI for embedding the OpenCSV wallet in native apps (iOS-first).
//! All protocol logic stays in Rust ([`wallet`], over `opencsv-core` /
//! `opencsv-pcd`); the host app supplies transport, persistence, and the
//! anchor-log view:
//!
//! - **Secrets** — [`opencsv_wallet_create`] returns a small secrets JSON;
//!   the host stores it in its keystore (iOS Keychain) and passes it back to
//!   [`opencsv_wallet_open`]. No key material ever touches the filesystem.
//! - **Coins** — rebuilt at open by replaying verified consignment blobs
//!   through [`opencsv_verify_consignment`] (milliseconds each), then
//!   re-marking spends with [`opencsv_wallet_mark_spent`].
//! - **Anchors** — every chain-dependent call takes an *anchor snapshot*
//!   JSON (the whole anchor-log view; see [`snapshot`]), so verification is
//!   fully offline. Producing a transaction is two-phase: `opencsv_prove_*`
//!   returns a 64-byte anchor record plus the 32-byte transaction context it
//!   is bound to for the host to publish together, and
//!   [`opencsv_consignment_finalize`] builds the consignment blob once the
//!   host knows where the record anchored.
//!
//! ## Conventions
//!
//! Every function returns a newly allocated JSON string, freed with
//! [`opencsv_string_free`]. Failures return `{"error":"..."}`; verification
//! rejections (a *result*, not a failure) return `{"status":"rejected",...}`.
//! Handles are process-local and not thread-safe per handle — serialize
//! calls on one handle (proving also takes 0.5–1 s on phone hardware; call
//! from a background queue).

#![warn(missing_docs)]

mod hex;
pub mod snapshot;
pub mod wallet;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{LazyLock, Mutex};

use opencsv_core::chain::{AnchorLocation, AnchorRef};
use serde::Deserialize;
use serde_json::json;

use crate::hex::{from_hex_array, to_hex};
use crate::snapshot::SnapshotChain;
use crate::wallet::MemWallet;

static WALLETS: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        wallets: HashMap::new(),
        next_handle: 1,
    })
});

struct Registry {
    wallets: HashMap<u64, MemWallet>,
    next_handle: u64,
}

// ---------------------------------------------------------------------------
// Boundary helpers.
// ---------------------------------------------------------------------------

fn out(value: serde_json::Value) -> *mut c_char {
    let json = value.to_string();
    CString::new(json)
        .unwrap_or_else(|_| CString::new("{\"error\":\"output contained NUL\"}").expect("no NUL"))
        .into_raw()
}

fn err(message: impl std::fmt::Display) -> *mut c_char {
    out(json!({ "error": message.to_string() }))
}

/// Run `f` with panics converted to an `{"error":...}` JSON result.
fn guarded(f: impl FnOnce() -> *mut c_char) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(ptr) => ptr,
        Err(panic) => {
            let message = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            err(format!("panic: {message}"))
        }
    }
}

/// # Safety
/// `ptr` must be a valid NUL-terminated C string or null.
unsafe fn in_str<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{what} is not UTF-8"))
}

fn with_wallet(
    handle: u64,
    f: impl FnOnce(&mut MemWallet) -> Result<serde_json::Value, String>,
) -> *mut c_char {
    let mut registry = match WALLETS.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    match registry.wallets.get_mut(&handle) {
        Some(wallet) => match f(wallet) {
            Ok(value) => out(value),
            Err(e) => err(e),
        },
        None => err(format!("unknown wallet handle {handle}")),
    }
}

fn parse_amounts(json_str: &str) -> Result<Vec<u64>, String> {
    serde_json::from_str(json_str).map_err(|e| format!("amounts JSON: {e}"))
}

fn parse_ids(json_str: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(json_str).map_err(|e| format!("coin ids JSON: {e}"))
}

#[derive(Deserialize)]
struct AnchorRefJson {
    txid: String,
    height: u64,
    position: u32,
}

fn parse_anchor_ref(json_str: &str) -> Result<AnchorRef, String> {
    let parsed: AnchorRefJson =
        serde_json::from_str(json_str).map_err(|e| format!("anchor ref JSON: {e}"))?;
    Ok(AnchorRef {
        txid: from_hex_array::<32>(&parsed.txid, "anchor txid")?,
        location: AnchorLocation {
            height: parsed.height,
            position: parsed.position,
        },
    })
}

fn proved_json(proved: wallet::Proved) -> serde_json::Value {
    json!({
        "pending_id": proved.pending_id,
        "anchor_record_hex": to_hex(&proved.anchor_record),
        "ctx_hex": to_hex(&proved.ctx),
        "spends": proved.spends,
    })
}

// ---------------------------------------------------------------------------
// C ABI.
// ---------------------------------------------------------------------------

/// Create a fresh wallet (one owner key) and return its secrets JSON for the
/// host keystore. Open it with [`opencsv_wallet_open`].
#[no_mangle]
pub extern "C" fn opencsv_wallet_create() -> *mut c_char {
    guarded(|| {
        let wallet = MemWallet::create();
        match serde_json::to_value(wallet.secrets_json()) {
            Ok(value) => out(value),
            Err(e) => err(e),
        }
    })
}

/// Open a wallet from its secrets JSON. Returns
/// `{"handle":N,"owners":["<hex>",...]}`.
///
/// # Safety
/// `secrets_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_wallet_open(secrets_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let secrets = match unsafe { in_str(secrets_json, "secrets_json") } {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        match MemWallet::open(secrets) {
            Ok(wallet) => {
                let owners = wallet.owners();
                let mut registry = match WALLETS.lock() {
                    Ok(registry) => registry,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let handle = registry.next_handle;
                registry.next_handle += 1;
                registry.wallets.insert(handle, wallet);
                out(json!({ "handle": handle, "owners": owners }))
            }
            Err(e) => err(e),
        }
    })
}

/// Drop a wallet handle. Returns `{"ok":true}`.
#[no_mangle]
pub extern "C" fn opencsv_wallet_close(handle: u64) -> *mut c_char {
    guarded(|| {
        let mut registry = match WALLETS.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        };
        match registry.wallets.remove(&handle) {
            Some(_) => out(json!({ "ok": true })),
            None => err(format!("unknown wallet handle {handle}")),
        }
    })
}

/// Re-export the wallet's secrets JSON (call after key/issuer changes and
/// persist to the keystore).
#[no_mangle]
pub extern "C" fn opencsv_wallet_secrets(handle: u64) -> *mut c_char {
    guarded(|| {
        with_wallet(handle, |w| {
            serde_json::to_value(w.secrets_json()).map_err(|e| e.to_string())
        })
    })
}

/// Wallet status: `{"owners":[...],"coins":[...],"balances":[...]}`.
#[no_mangle]
pub extern "C" fn opencsv_wallet_status(handle: u64) -> *mut c_char {
    guarded(|| {
        with_wallet(handle, |w| {
            Ok(json!({
                "owners": w.owners(),
                "coins": serde_json::to_value(w.list_coins()).map_err(|e| e.to_string())?,
                "balances": serde_json::to_value(w.balance()).map_err(|e| e.to_string())?,
            }))
        })
    })
}

/// Add a fresh owner key. Returns `{"owner":"<hex>"}`; re-export secrets
/// afterwards.
#[no_mangle]
pub extern "C" fn opencsv_wallet_keygen(handle: u64) -> *mut c_char {
    guarded(|| with_wallet(handle, |w| Ok(json!({ "owner": w.keygen() }))))
}

/// Create an issuer identity for a 3-letter currency code. Returns
/// `{"asset_id":"<hex>"}`; re-export secrets afterwards.
///
/// # Safety
/// `currency` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_wallet_init_issuer(
    handle: u64,
    currency: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let currency = match unsafe { in_str(currency, "currency") } {
            Ok(s) => s.to_owned(),
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            w.init_issuer(&currency).map(|id| json!({ "asset_id": id }))
        })
    })
}

/// Prove an issuer mint of `amounts_json` (e.g. `[100]`) to `to_owner_hex`.
/// Returns `{"pending_id":N,"anchor_record_hex":"<128 hex>",
/// "ctx_hex":"<64 hex>","spends":[]}`; publish the record together with its
/// transaction context (`POST /anchor`), then call
/// [`opencsv_consignment_finalize`].
/// Proving takes ~10–60 ms on phone hardware; call from a background queue.
///
/// # Safety
/// All pointer arguments must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn opencsv_prove_mint(
    handle: u64,
    asset_id_hex: *const c_char,
    to_owner_hex: *const c_char,
    amounts_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let (asset_id, to, amounts) = match (|| {
            Ok::<_, String>((
                unsafe { in_str(asset_id_hex, "asset_id_hex") }?.to_owned(),
                unsafe { in_str(to_owner_hex, "to_owner_hex") }?.to_owned(),
                parse_amounts(unsafe { in_str(amounts_json, "amounts_json") }?)?,
            ))
        })() {
            Ok(args) => args,
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            w.prove_mint(&asset_id, &to, &amounts).map(proved_json)
        })
    })
}

/// Prove a transfer spending `coin_ids_json` (exactly 2 ids). `amounts_json`
/// is `[pay]` or `[pay, change]`; the change output returns to this wallet.
/// Returns the same shape as [`opencsv_prove_mint`], with `spends` listing
/// the coin ids the transaction consumes (marked spent at finalize).
/// Proving takes ~0.5–1 s on phone hardware; call from a background queue.
///
/// # Safety
/// All pointer arguments must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn opencsv_prove_transfer(
    handle: u64,
    coin_ids_json: *const c_char,
    to_owner_hex: *const c_char,
    amounts_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let (ids, to, amounts) = match (|| {
            Ok::<_, String>((
                parse_ids(unsafe { in_str(coin_ids_json, "coin_ids_json") }?)?,
                unsafe { in_str(to_owner_hex, "to_owner_hex") }?.to_owned(),
                parse_amounts(unsafe { in_str(amounts_json, "amounts_json") }?)?,
            ))
        })() {
            Ok(args) => args,
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            w.prove_transfer(&ids, &to, &amounts).map(proved_json)
        })
    })
}

/// Prove a redeem (burn) of one coin. Same return shape as
/// [`opencsv_prove_mint`]. The finalized consignment carries no openings —
/// deliver it to the issuer.
///
/// # Safety
/// `coin_id` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_prove_redeem(handle: u64, coin_id: *const c_char) -> *mut c_char {
    guarded(|| {
        let id = match unsafe { in_str(coin_id, "coin_id") } {
            Ok(s) => s.to_owned(),
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| w.prove_redeem(&id).map(proved_json))
    })
}

/// Rebuild a pending transaction's anchor record under a caller-supplied
/// transaction context, without re-proving.
///
/// Real chains derive `ctx` from the anchor transaction's funding outpoint,
/// which the anchoring service reserves after the proof exists: prove once,
/// reserve a context, rebind here, publish, finalize. Returns
/// `{"anchor_record_hex":"<128 hex>"}`, or an error if this context would
/// make the record misparse — reserve another and call again.
///
/// # Safety
/// `ctx_hex` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_pending_rebind(
    handle: u64,
    pending_id: u64,
    ctx_hex: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let ctx = match unsafe { in_str(ctx_hex, "ctx_hex") }
            .and_then(|s| from_hex_array::<32>(s, "ctx"))
        {
            Ok(ctx) => ctx,
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            let record = w.rebind_pending(pending_id, ctx)?;
            Ok(json!({ "anchor_record_hex": to_hex(&record) }))
        })
    })
}

/// Build the consignment blob for a proved transaction.
/// `anchor_ref_json` is `{"txid":"<64 hex>","height":N,"position":M}` — where
/// the published record actually anchored. Marks consumed coins spent.
/// Returns `{"consignment_base64":"...","spends":[...]}`.
///
/// # Safety
/// `anchor_ref_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_consignment_finalize(
    handle: u64,
    pending_id: u64,
    anchor_ref_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let anchor_ref = match unsafe { in_str(anchor_ref_json, "anchor_ref_json") }
            .and_then(parse_anchor_ref)
        {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            use base64::Engine as _;
            let (blob, spends) = w.finalize(pending_id, anchor_ref)?;
            Ok(json!({
                "consignment_base64": base64::engine::general_purpose::STANDARD.encode(blob),
                "spends": spends,
            }))
        })
    })
}

/// Verify a received consignment blob against an anchor snapshot (see
/// [`snapshot`] for the JSON format). On success, credited coins are stored
/// in the wallet. Returns
/// `{"status":"verified","credits":[{"asset_id","currency","amount"}],
///   "coins":[...],"anchor":{"height":N,"position":M}}`
/// or `{"status":"rejected","reason":"..."}`.
/// Verification takes milliseconds; still call off the main thread.
///
/// # Safety
/// `blob` must point to `blob_len` readable bytes; `anchor_snapshot_json`
/// must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_verify_consignment(
    handle: u64,
    blob: *const u8,
    blob_len: usize,
    anchor_snapshot_json: *const c_char,
    required_confirmations: u64,
) -> *mut c_char {
    guarded(|| {
        if blob.is_null() {
            return err("blob is null");
        }
        let blob = unsafe { std::slice::from_raw_parts(blob, blob_len) }.to_vec();
        let chain = match unsafe { in_str(anchor_snapshot_json, "anchor_snapshot_json") }
            .and_then(SnapshotChain::from_json)
        {
            Ok(chain) => chain,
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            match w.verify(&blob, &chain, required_confirmations)? {
                Ok(verified) => Ok(json!({
                    "status": "verified",
                    "credits": serde_json::to_value(verified.credits).map_err(|e| e.to_string())?,
                    "coins": serde_json::to_value(verified.coins).map_err(|e| e.to_string())?,
                    "anchor": { "height": verified.height, "position": verified.position },
                })),
                Err(reason) => Ok(json!({ "status": "rejected", "reason": reason })),
            }
        })
    })
}

/// Mark coins spent by id (replay of host-persisted spend state at open).
/// Returns `{"ok":true}`.
///
/// # Safety
/// `coin_ids_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_wallet_mark_spent(
    handle: u64,
    coin_ids_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let ids = match unsafe { in_str(coin_ids_json, "coin_ids_json") }.and_then(parse_ids) {
            Ok(ids) => ids,
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            w.mark_spent(&ids)?;
            Ok(json!({ "ok": true }))
        })
    })
}

/// Unspent balances per asset:
/// `{"balances":[{"asset_id","currency","amount"}]}`.
#[no_mangle]
pub extern "C" fn opencsv_balance(handle: u64) -> *mut c_char {
    guarded(|| {
        with_wallet(handle, |w| {
            Ok(json!({
                "balances": serde_json::to_value(w.balance()).map_err(|e| e.to_string())?
            }))
        })
    })
}

/// Public supply audit of an asset at the snapshot tip (paper §4.9), needing
/// no wallet: `{"supply":N}`.
///
/// # Safety
/// Both arguments must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn opencsv_audit(
    asset_id_hex: *const c_char,
    anchor_snapshot_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let result = (|| {
            let asset_id = unsafe { in_str(asset_id_hex, "asset_id_hex") }?;
            let chain =
                SnapshotChain::from_json(unsafe { in_str(anchor_snapshot_json, "snapshot") }?)?;
            wallet::audit(asset_id, &chain)
        })();
        match result {
            Ok(supply) => out(json!({ "supply": supply })),
            Err(e) => err(e),
        }
    })
}

/// Free a string returned by any function in this library.
///
/// # Safety
/// `s` must be a pointer previously returned by this library, freed at most
/// once.
#[no_mangle]
pub unsafe extern "C" fn opencsv_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}
