//! Reproducible live-signet driver for the Rust-owned account wallet.
//!
//! This explicitly featured issuer example exposes only the action-oriented
//! reference boundary. It cannot
//! select a Bitcoin input/change address or send arbitrary Bitcoin. Supply a
//! fresh 32-byte account root and non-migratable-device stand-in through
//! `OPENCSV_ACCOUNT_ROOT_HEX` and `OPENCSV_DEVICE_BINDING_HEX`; neither value
//! is printed or stored outside the account database.
//!
//! Build with `--features issuer-tools`. Signal's default/CocoaPods build does
//! not enable that feature and its C ABI has no asset-definition or mint call.

use std::env;
use std::error::Error;

use opencsv_ffi::account::AccountWallet;
use serde_json::{json, Value};

const DEFAULT_ESPLORA: &str = "https://mempool.space/signet/api";
const DEFAULT_PEERS: &str = "172.233.20.188:38333,15.204.114.107:38333";

fn decode_secret(name: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let encoded = env::var(name).map_err(|_| format!("{name} must be set"))?;
    if encoded.len() != 64 {
        return Err(format!("{name} must contain exactly 64 hex characters").into());
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} is not valid hexadecimal"))?;
    }
    Ok(decoded)
}

fn peer_list(variable: &str) -> Vec<String> {
    env::var(variable)
        .unwrap_or_else(|_| DEFAULT_PEERS.to_owned())
        .split(',')
        .map(str::trim)
        .filter(|peer| !peer.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn config() -> String {
    json!({
        "version": 1,
        "network": "signet",
        "esplora_url": env::var("OPENCSV_SIGNET_ESPLORA")
            .unwrap_or_else(|_| DEFAULT_ESPLORA.to_owned()),
        "peers": peer_list("OPENCSV_SIGNET_RELAY_PEERS"),
        "verification_peers": peer_list("OPENCSV_SIGNET_VERIFICATION_PEERS"),
        "verification_timeout_secs": 180,
        "max_verification_blocks": 2048,
        "role": "primary",
        "backup_verified": env::var("OPENCSV_BACKUP_VERIFIED").as_deref() == Ok("1"),
        "required_confirmations": 1,
        "stop_gap": 20,
        "parallel_requests": 4
    })
    .to_string()
}

fn print_json(value: Value) -> Result<(), Box<dyn Error>> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage: signet_account_acceptance <database> \
         status|sync|prepare-mint|ack-backup|sign|bump|operation|resume [arguments]\n\
         prepare-mint <ASSET_ID> [AMOUNT]\n\
         ack-backup <OPERATION_ID> <CHECKPOINT_HASH>\n\
         sign <OPERATION_ID> <SAT_PER_VB>\n\
         bump <OPERATION_ID> <SAT_PER_VB>\n\
         operation|resume <OPERATION_ID>"
    );
    std::process::exit(2);
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() < 3 {
        usage();
    }
    let account_root = decode_secret("OPENCSV_ACCOUNT_ROOT_HEX")?;
    let device_binding = decode_secret("OPENCSV_DEVICE_BINDING_HEX")?;
    let mut wallet =
        AccountWallet::open_device_bound(&config(), &account_root, &device_binding, &arguments[1])?;

    match arguments[2].as_str() {
        "status" => print_json(wallet.status()?),
        "sync" => print_json(wallet.sync()?),
        "prepare-mint" => {
            let asset_id = arguments.get(3).unwrap_or_else(|| usage());
            let amount = arguments
                .get(4)
                .map(|value| value.parse::<u64>())
                .transpose()?
                .unwrap_or(1);
            print_json(
                wallet.mint_prepare(
                    &json!({ "asset_id": asset_id, "amounts": [amount] }).to_string(),
                )?,
            )
        }
        "ack-backup" => {
            if arguments.len() != 5 {
                usage();
            }
            print_json(wallet.acknowledge_operation_backup(&arguments[3], &arguments[4])?)
        }
        "sign" => {
            if arguments.len() != 5 {
                usage();
            }
            let feerate = arguments[4].parse::<u64>()?;
            print_json(wallet.sign_and_broadcast(
                &arguments[3],
                &json!({ "target_sat_per_vb": feerate }).to_string(),
            )?)
        }
        "bump" => {
            if arguments.len() != 5 {
                usage();
            }
            print_json(wallet.fee_bump(&arguments[3], arguments[4].parse()?)?)
        }
        "operation" => {
            if arguments.len() != 4 {
                usage();
            }
            print_json(wallet.operation_status(&arguments[3])?)
        }
        "resume" => {
            if arguments.len() != 4 {
                usage();
            }
            print_json(wallet.resume_operation(&arguments[3])?)
        }
        _ => usage(),
    }
}
