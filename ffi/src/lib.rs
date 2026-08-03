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

pub mod account;
pub mod cbf;
pub mod crosscheck;
mod hex;
pub mod scan;
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

use crate::account::AccountWallet;
use crate::hex::{from_hex_array, to_hex};
use crate::snapshot::SnapshotChain;
use crate::wallet::MemWallet;

static WALLETS: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        wallets: HashMap::new(),
        next_handle: 1,
    })
});

static ACCOUNTS: LazyLock<Mutex<AccountRegistry>> = LazyLock::new(|| {
    Mutex::new(AccountRegistry {
        accounts: HashMap::new(),
        next_handle: 1,
    })
});

struct Registry {
    wallets: HashMap<u64, MemWallet>,
    next_handle: u64,
}

struct AccountRegistry {
    accounts: HashMap<u64, AccountWallet>,
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

/// # Safety
/// `ptr` must be valid for `len` bytes. A null pointer is accepted only when
/// `len` is zero (the linked-device account-open case).
unsafe fn in_bytes<'a>(ptr: *const u8, len: usize, what: &str) -> Result<&'a [u8], String> {
    if ptr.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(format!("{what} is null"))
        };
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
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

fn with_account(
    handle: u64,
    f: impl FnOnce(&mut AccountWallet) -> Result<serde_json::Value, account::AccountError>,
) -> *mut c_char {
    let mut registry = match ACCOUNTS.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    match registry.accounts.get_mut(&handle) {
        Some(account) => match f(account) {
            Ok(value) => out(value),
            Err(error) => out(error.json()),
        },
        None => out(json!({
            "error": format!("unknown account handle {handle}"),
            "reason": "unknown_handle",
        })),
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

/// Open or initialize a Signal-native account wallet.
///
/// `config_json` contains public network/endpoint/role policy,
/// `account_key` and the non-migratable `device_binding_key` are each exactly
/// 32 bytes on a fresh primary phone and empty on a linked device. A primary
/// with a restored 32-byte root but missing binding passes an empty binding and
/// opens read/export-only. The binding key must come from a `ThisDeviceOnly`
/// platform-keystore item. Its public commitment, returned in
/// status/checkpoints, detects a restored clone.
/// `database_path` names the account SQLite database. Returns
/// `{"handle":N,...status}`. No key is accepted in JSON.
///
/// # Safety
/// Strings must be valid NUL-terminated UTF-8. `account_key` must be valid
/// for `account_key_len` bytes and `device_binding_key` must be valid for
/// `device_binding_key_len` bytes. Null pointers are accepted only for the
/// zero-length linked-device values.
#[no_mangle]
pub unsafe extern "C" fn opencsv_account_open(
    config_json: *const c_char,
    account_key: *const u8,
    account_key_len: usize,
    device_binding_key: *const u8,
    device_binding_key_len: usize,
    database_path: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let config = match unsafe { in_str(config_json, "config_json") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let key = match unsafe { in_bytes(account_key, account_key_len, "account_key") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let device_binding = match unsafe {
            in_bytes(
                device_binding_key,
                device_binding_key_len,
                "device_binding_key",
            )
        } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let path = match unsafe { in_str(database_path, "database_path") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        match AccountWallet::open_device_bound(config, key, device_binding, path) {
            Ok(mut account) => {
                let status = match account.status() {
                    Ok(status) => status,
                    Err(error) => return out(error.json()),
                };
                let mut registry = match ACCOUNTS.lock() {
                    Ok(registry) => registry,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let handle = registry.next_handle;
                registry.next_handle += 1;
                registry.accounts.insert(handle, account);
                let mut response = status.as_object().cloned().unwrap_or_default();
                response.insert("handle".into(), json!(handle));
                out(serde_json::Value::Object(response))
            }
            Err(error) => out(error.json()),
        }
    })
}

/// Close a Signal-native account handle.
#[no_mangle]
pub extern "C" fn opencsv_account_close(handle: u64) -> *mut c_char {
    guarded(|| {
        let mut registry = match ACCOUNTS.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        };
        match registry.accounts.remove(&handle) {
            Some(_) => out(json!({ "ok": true })),
            None => out(json!({
                "error": format!("unknown account handle {handle}"),
                "reason": "unknown_handle",
            })),
        }
    })
}

/// Return Bitcoin reserve, OpenCSV balances, deposit address, public watch
/// descriptors, backup policy, and sync provenance.
#[no_mangle]
pub extern "C" fn opencsv_account_status(handle: u64) -> *mut c_char {
    guarded(|| with_account(handle, AccountWallet::status))
}

/// Synchronize the fee wallet through the configured Esplora accelerator.
#[no_mangle]
pub extern "C" fn opencsv_account_sync(handle: u64) -> *mut c_char {
    guarded(|| with_account(handle, AccountWallet::sync))
}

/// Update Secure Backup policy. Disabling it freezes new Bitcoin-writing
/// operations without removing read or receive access.
#[no_mangle]
pub extern "C" fn opencsv_account_set_backup_state(
    handle: u64,
    verified: bool,
    checkpoint_version: u32,
) -> *mut c_char {
    guarded(|| {
        with_account(handle, |account| {
            account.set_backup_state(verified, checkpoint_version)
        })
    })
}

/// Export the compact versioned OpenCSV checkpoint for Signal Secure
/// Backups. BDK chain data is excluded because it is rebuildable.
#[no_mangle]
pub extern "C" fn opencsv_account_checkpoint(handle: u64) -> *mut c_char {
    guarded(|| with_account(handle, |account| account.checkpoint()))
}

/// Credit a received consignment through the unified account wallet.
///
/// # Safety
/// `blob` must be valid for `blob_len` bytes and `snapshot_json` must be a
/// valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_account_verify_consignment(
    handle: u64,
    blob: *const u8,
    blob_len: usize,
    snapshot_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        if blob_len == 0 {
            return out(json!({
                "error": "consignment is empty",
                "reason": "invalid_consignment",
            }));
        }
        let blob = match unsafe { in_bytes(blob, blob_len, "blob") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let snapshot = match unsafe { in_str(snapshot_json, "snapshot_json") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.verify_consignment(blob, snapshot))
    })
}

/// Read-only consignment decision against the locally verified BIP158 scan.
///
/// # Safety
/// `consignment_hex` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_account_scan_verify(
    handle: u64,
    consignment_hex: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let consignment = match unsafe { in_str(consignment_hex, "consignment_hex") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.scan_verify(consignment))
    })
}

/// Read-only N-of-M chain-view decision using the account's private owner
/// identity without exposing it to Swift.
///
/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_account_cross_check(
    handle: u64,
    request_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let request = match unsafe { in_str(request_json, "request_json") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.cross_check(request))
    })
}

/// Prepare an OpenCSV mint and reserve its Bitcoin fee input. The request
/// contains asset/amount/owner data only; no Bitcoin key, UTXO, change
/// address, or coin-selection result is accepted.
///
/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_mint_prepare(
    handle: u64,
    request_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let request = match unsafe { in_str(request_json, "request_json") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.mint_prepare(request))
    })
}

/// Prepare an OpenCSV transfer and reserve its Bitcoin fee input. The strict
/// request is `{"asset_id":"<hex>","to_owner":"<hex>","amount":N}`;
/// Rust selects both OpenCSV coins, all Bitcoin inputs, and both kinds of
/// change.
///
/// # Safety
/// `request_json` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_transfer_prepare(
    handle: u64,
    request_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let request = match unsafe { in_str(request_json, "request_json") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.transfer_prepare(request))
    })
}

/// Acknowledge the exact prepared checkpoint after Signal Secure Backup has
/// durably accepted it.
///
/// # Safety
/// Both arguments must be valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn opencsv_operation_ack_backup(
    handle: u64,
    operation_id: *const c_char,
    checkpoint_hash: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let checkpoint_hash = match unsafe { in_str(checkpoint_hash, "checkpoint_hash") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| {
            account.acknowledge_operation_backup(operation_id, checkpoint_hash)
        })
    })
}

/// Build the exact protocol transaction, sign it, persist it, and only then
/// broadcast it through the configured relays.
///
/// # Safety
/// Both arguments must be valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn opencsv_operation_sign_and_broadcast(
    handle: u64,
    operation_id: *const c_char,
    fee_policy_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let fee_policy = match unsafe { in_str(fee_policy_json, "fee_policy_json") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| {
            account.sign_and_broadcast(operation_id, fee_policy)
        })
    })
}

/// Return and refresh a durable account operation.
///
/// # Safety
/// `operation_id` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_operation_status(
    handle: u64,
    operation_id: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.operation_status(operation_id))
    })
}

/// Idempotently resume a crash-interrupted operation.
///
/// # Safety
/// `operation_id` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_operation_resume(
    handle: u64,
    operation_id: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.resume_operation(operation_id))
    })
}

/// Cancel an operation before any broadcast attempt and release its fee
/// reservation.
///
/// # Safety
/// `operation_id` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_operation_cancel(
    handle: u64,
    operation_id: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| account.cancel_operation(operation_id))
    })
}

/// Create and broadcast a protocol-safe fee replacement.
///
/// # Safety
/// `operation_id` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_fee_bump(
    handle: u64,
    operation_id: *const c_char,
    target_sat_per_vb: u64,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| {
            account.fee_bump(operation_id, target_sat_per_vb)
        })
    })
}

/// Mark the Signal consignment attachment delivered using its stable nonce.
///
/// # Safety
/// Both arguments must be valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn opencsv_operation_mark_delivered(
    handle: u64,
    operation_id: *const c_char,
    delivery_nonce: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let operation_id = match unsafe { in_str(operation_id, "operation_id") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        let delivery_nonce = match unsafe { in_str(delivery_nonce, "delivery_nonce") } {
            Ok(value) => value,
            Err(error) => return err(error),
        };
        with_account(handle, |account| {
            account.mark_consignment_delivered(operation_id, delivery_nonce)
        })
    })
}

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

/// Export a pending (proved, not yet finalized) transaction as a JSON
/// string the host can persist across the broadcast→finalize window —
/// closing the crash-loses-consignment gap: the openings carry fresh
/// randomness proving drew and cannot re-derive, so everything
/// [`opencsv_consignment_finalize`] and [`opencsv_pending_rebind`] need
/// is in the export. Returns `{"pending_json":"{...}"}` — persist the
/// inner string as-is; treat it as sensitive (it reveals coin values
/// and owners).
#[no_mangle]
pub extern "C" fn opencsv_pending_export(handle: u64, pending_id: u64) -> *mut c_char {
    guarded(|| {
        with_wallet(handle, |w| {
            let export = w.export_pending(pending_id)?;
            Ok(json!({ "pending_json": export }))
        })
    })
}

/// Import a pending transaction exported by [`opencsv_pending_export`]
/// (possibly in an earlier process lifetime of the same wallet secrets).
/// Returns `{"pending_id":M}` — a fresh id; the export's original id is
/// not preserved.
///
/// # Safety
/// `pending_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_pending_import(
    handle: u64,
    pending_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let pending_json = match unsafe { in_str(pending_json, "pending_json") } {
            Ok(s) => s.to_owned(),
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            w.import_pending(&pending_json)
                .map(|pending_id| json!({ "pending_id": pending_id }))
        })
    })
}

/// Verify a claimed anchor trustlessly over the BIP157/158 P2P protocol
/// (see [`cbf`] for the config JSON). Returns the verdict JSON:
/// `{"status":"confirmed",...}` / `{"status":"not_present",...}` /
/// `{"status":"insufficient_confirmations",...}`.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_cbf_verify_anchor(config_json: *const c_char) -> *mut c_char {
    guarded(|| {
        match unsafe { in_str(config_json, "config_json") }.and_then(cbf::verify_anchor_json) {
            Ok(value) => out(value),
            Err(e) => err(e),
        }
    })
}

/// Sync the header/filter chains from all configured peers and report
/// the verified tip: `{"tip_height":N}` (see [`cbf`] for the config
/// JSON; the `anchor` member is not needed).
///
/// # Safety
/// `config_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_cbf_sync(config_json: *const c_char) -> *mut c_char {
    guarded(
        || match unsafe { in_str(config_json, "config_json") }.and_then(cbf::sync_json) {
            Ok(value) => out(value),
            Err(e) => err(e),
        },
    )
}

/// Run the accept driver over a received consignment against an N-of-M
/// [`CrossCheckedChain`](opencsv_core::CrossCheckedChain) built from a
/// JSON list of backend specs (see [`crosscheck`]: bitcoind-rpc / http
/// anchor-server / inline snapshot). Read-only: coins are reported, not
/// credited. Returns `{"status":"verified",...}` /
/// `{"status":"rejected",...}`; tip disagreement between backends
/// returns `{"error":"...","kind":"tip_disagreement","tips":[...]}`.
///
/// # Safety
/// `request_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_cross_check(
    handle: u64,
    request_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let request_json = match unsafe { in_str(request_json, "request_json") } {
            Ok(s) => s.to_owned(),
            Err(e) => return err(e),
        };
        let mut registry = match WALLETS.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(wallet) = registry.wallets.get_mut(&handle) else {
            return err(format!("unknown wallet handle {handle}"));
        };
        match crosscheck::run_cross_check(
            &request_json,
            &wallet.owner_secrets(),
            &wallet.known_asset_ids(),
            &opencsv_pcd::CoinProofVerifier,
        ) {
            Ok(value) => out(value),
            Err(crosscheck::CrossCheckFailure::TipDisagreement(tips)) => out(json!({
                "error": format!("anchor backends disagree on tip height: {tips:?}"),
                "kind": "tip_disagreement",
                "tips": tips,
            })),
            Err(crosscheck::CrossCheckFailure::Other(message)) => err(message),
        }
    })
}

/// Sync the self-scan-first occurrence index (see [`scan`]): connect to
/// the P2P network, walk BIP158 filters for the protocol marker output,
/// SPV-fetch matching blocks, and register the scan configuration for
/// [`opencsv_scan_check`] / [`opencsv_scan_verify`]. Returns
/// `{"tip_height":N,"filters_bytes":N,"blocks_bytes":N,"anchors":N}`.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_scan_sync(config_json: *const c_char) -> *mut c_char {
    guarded(
        || match unsafe { in_str(config_json, "config_json") }.and_then(scan::sync_json) {
            Ok(value) => out(value),
            Err(e) => err(e),
        },
    )
}

/// Local-only earliest-occurrence check against the scan index built by
/// [`opencsv_scan_sync`] (no network). `request_json` is
/// `{"raw_nf_hex":"<64 hex>","birth":N,"spend":N}`; returns
/// `{"occurrence":{"height":N,"position":M,"ctx_hex":"<64 hex>"}}` or
/// `{"occurrence":null}`.
///
/// # Safety
/// `request_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_scan_check(
    handle: u64,
    request_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let request_json = match unsafe { in_str(request_json, "request_json") } {
            Ok(s) => s.to_owned(),
            Err(e) => return err(e),
        };
        with_wallet(handle, |_w| scan::check_json(&request_json))
    })
}

/// Run the accept driver over a consignment (hex) against the scan
/// index built by [`opencsv_scan_sync`] (read-only, no network; credit
/// via [`opencsv_verify_consignment`]). Returns
/// `{"status":"verified",...,"confirmations":N,"tip_height":N}` or
/// `{"status":"rejected","reason":"...",...}`.
///
/// # Safety
/// `consignment_hex` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_scan_verify(
    handle: u64,
    consignment_hex: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let consignment_hex = match unsafe { in_str(consignment_hex, "consignment_hex") } {
            Ok(s) => s.to_owned(),
            Err(e) => return err(e),
        };
        with_wallet(handle, |w| {
            scan::verify_json(
                &consignment_hex,
                &w.owner_secrets(),
                &w.known_asset_ids(),
                &opencsv_pcd::CoinProofVerifier,
            )
        })
    })
}

/// Open a persistent CBF client (peers stay connected between syncs —
/// see [`scan`]). Returns
/// `{"client_id":N,"tip_height":N,"handshakes":N}`.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn opencsv_cbf_open(config_json: *const c_char) -> *mut c_char {
    guarded(
        || match unsafe { in_str(config_json, "config_json") }.and_then(scan::open_json) {
            Ok(value) => out(value),
            Err(e) => err(e),
        },
    )
}

/// Drop a persistent CBF client. Returns `{"ok":true}`.
#[no_mangle]
pub extern "C" fn opencsv_cbf_close(client_id: u64) -> *mut c_char {
    guarded(|| out(scan::close_json(client_id)))
}

/// Sync with a persistent client opened by [`opencsv_cbf_open`]:
/// headers on the existing connections (no re-handshake), then the
/// scan index. Returns the [`opencsv_scan_sync`] shape plus
/// `{"handshakes":N}` (constant across calls on one client).
#[no_mangle]
pub extern "C" fn opencsv_scan_sync_with(client_id: u64) -> *mut c_char {
    guarded(|| match scan::sync_with_json(client_id) {
        Ok(value) => out(value),
        Err(e) => err(e),
    })
}

/// Export the registered scan index as an anchor-snapshot JSON (the
/// exact shape [`opencsv_verify_consignment`] consumes) — the
/// serverless crediting path: everything in it was SPV-fetched and
/// PoW-verified by the scan. Local-only; `tip_height` is the synced
/// tip at call time. Returns `{"error":"no scan registered; call
/// opencsv_scan_sync first"}` when no sync has registered an index.
#[no_mangle]
pub extern "C" fn opencsv_scan_export_snapshot() -> *mut c_char {
    guarded(|| match scan::export_snapshot_json() {
        Ok(value) => out(value),
        Err(e) => err(e),
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
