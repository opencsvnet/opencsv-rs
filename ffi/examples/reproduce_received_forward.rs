//! Reproduce forwarding a persisted simulator consignment without printing keys.

use std::env;
use std::fs;

use base64::Engine as _;
use hkdf::Hkdf;
use opencsv_core::consignment::Consignment;
use opencsv_core::{Coin, Digest, OwnerSecret};
use opencsv_pcd::{decode_coin_proof, prove_one_input_transfer, verify_coin_proof};
use serde_json::Value;
use sha2::Sha256;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let consignment_path = args
        .next()
        .ok_or("usage: reproduce_received_forward <consignment> <simulator-material>")?;
    let material_path = args.next().ok_or("missing simulator material path")?;

    let consignment = Consignment::from_bytes(&fs::read(consignment_path)?)?;
    let predecessor = decode_coin_proof(&consignment.proof).ok_or("invalid proof envelope")?;
    let material: Value = serde_json::from_slice(&fs::read(material_path)?)?;
    let root = base64::engine::general_purpose::STANDARD.decode(
        material
            .get("accountRoot")
            .and_then(Value::as_str)
            .ok_or("missing accountRoot")?,
    )?;
    if root.len() != 32 {
        return Err("accountRoot is not 32 bytes".into());
    }
    let hk = Hkdf::<Sha256>::new(Some(b"OpenCSV Signal account v1"), &root);
    let mut owner_seed = [0u8; 32];
    hk.expand(b"opencsv-owner-v1\0", &mut owner_seed)
        .map_err(|_| "owner HKDF failed")?;
    let owner_secret = OwnerSecret::from_bytes(owner_seed);
    owner_seed.fill(0);

    let opening = consignment
        .coin_openings
        .iter()
        .find(|opening| opening.owner == owner_secret.owner())
        .ok_or("consignment has no output for this simulator owner")?;
    let input = opening.to_coin();
    let selector = predecessor
        .statement
        .output_commitments
        .iter()
        .position(|commitment| *commitment == input.commitment())
        .ok_or("opening is not in predecessor statement")?;
    let sent = input.value.min(10_000_000);
    let outputs = [
        Coin {
            asset_id: input.asset_id,
            value: sent,
            owner: owner_secret.owner(),
            randomness: Digest::from_bytes([0x91; 32]),
        },
        Coin {
            asset_id: input.asset_id,
            value: input.value - sent,
            owner: owner_secret.owner(),
            randomness: Digest::from_bytes([0x92; 32]),
        },
    ];
    eprintln!(
        "reproducing version={} mode={:?} selector={} input_value={}",
        predecessor.version, predecessor.mode, selector, input.value
    );
    let proof = prove_one_input_transfer(
        &input.asset_id,
        &(input, owner_secret),
        &outputs,
        &predecessor,
        selector,
    )?;
    verify_coin_proof(&proof.statement, &proof)?;
    println!("persisted consignment forwarding proof verified");
    Ok(())
}
