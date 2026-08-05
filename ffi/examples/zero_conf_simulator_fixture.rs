//! Generate a disposable mint consignment and its exact unconfirmed anchor.
//!
//! This is test tooling for the iOS simulator acceptance suite. Issuance
//! remains in the explicitly featured headless toolchain; Signal receives
//! only the public consignment and transaction fixture.

use std::error::Error;

use base64::Engine as _;
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::{
    absolute, consensus::encode::serialize, transaction, Amount, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use opencsv_bitcoin::{funding_ctx, MARKER_DUST_SATS, MARKER_SPK};
use opencsv_core::chain::{AnchorLocation, AnchorRef};
use opencsv_ffi::account::AccountWallet;
use opencsv_ffi::wallet::MemWallet;
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    const AMOUNT: u64 = 1_000_000;
    let account_root = [0x42_u8; 32];
    let device_binding = [0x43_u8; 32];
    let directory = tempfile::tempdir()?;
    let config = json!({
        "version": 1,
        "network": "regtest",
        "esplora_url": "http://127.0.0.1:1",
        "peers": ["127.0.0.1:19444"],
        "verification_peers": ["127.0.0.1:19444"],
        "verification_timeout_secs": 5,
        "max_verification_blocks": 256,
        "role": "primary",
        "backup_verified": false,
        "required_confirmations": 1,
        "stop_gap": 20,
        "parallel_requests": 1
    })
    .to_string();
    let mut account = AccountWallet::open_device_bound(
        &config,
        &account_root,
        &device_binding,
        directory.path().join("receiver.sqlite").to_str().unwrap(),
    )?;
    let receiver_owner = account.status()?["owners"][0]
        .as_str()
        .ok_or("account status omitted its owner")?
        .to_owned();
    drop(account);

    let mut issuer = MemWallet::from_owner_seed([0x51_u8; 32]);
    let asset_id = issuer.init_issuer_from_seed("USD", [0x52_u8; 32], 1, [0_u8; 32])?;
    let proved = issuer.prove_mint(&asset_id, &receiver_owner, &[AMOUNT])?;

    let funding_txid_bytes = [0x33_u8; 32];
    let (funding_vout, record) = (0..1_000_u32)
        .find_map(|vout| {
            issuer
                .rebind_pending(proved.pending_id, funding_ctx(&funding_txid_bytes, vout))
                .ok()
                .map(|record| (vout, record))
        })
        .ok_or("could not find a clean deterministic funding context")?;
    let funding_outpoint = OutPoint::new(Txid::from_byte_array(funding_txid_bytes), funding_vout);
    let record_push = PushBytesBuf::try_from(record.to_vec())?;
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(record_push),
            },
            TxOut {
                value: Amount::from_sat(MARKER_DUST_SATS),
                script_pubkey: ScriptBuf::from_bytes(MARKER_SPK.to_vec()),
            },
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::from_bytes([vec![0x00, 0x14], vec![0x09; 20]].concat()),
            },
        ],
    };
    let transaction_id = transaction.compute_txid();
    let (consignment, _) = issuer.finalize(
        proved.pending_id,
        AnchorRef {
            txid: transaction_id.to_byte_array(),
            location: AnchorLocation {
                height: 0,
                position: 0,
            },
        },
    )?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "version": 1,
            "account_root_hex": hex(&account_root),
            "device_binding_hex": hex(&device_binding),
            "asset_id": asset_id,
            "amount": AMOUNT,
            "anchor_txid": transaction_id.to_string(),
            "raw_transaction_hex": hex(&serialize(&transaction)),
            "consignment_base64": base64::engine::general_purpose::STANDARD.encode(consignment),
            "confirmed_snapshot_json": { "tip_height": 110, "entries": [] }
        }))?
    );
    Ok(())
}
