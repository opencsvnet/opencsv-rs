//! Inspect non-secret proof-shape metadata in an OpenCSV consignment.

use std::env;
use std::fs;

use opencsv_core::consignment::Consignment;
use opencsv_pcd::decode_coin_proof;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: inspect_consignment <raw-consignment>")?;
    let bytes = fs::read(path)?;
    let consignment = Consignment::from_bytes(&bytes)?;
    let proof = decode_coin_proof(&consignment.proof).ok_or("invalid coin proof envelope")?;

    println!("version={}", proof.version);
    println!("mode={:?}", proof.mode);
    println!("openings={}", consignment.coin_openings.len());
    for (index, opening) in consignment.coin_openings.iter().enumerate() {
        println!("opening[{index}].value={}", opening.value);
        println!("opening[{index}].commitment={:?}", opening.commitment());
    }
    println!("statement.nullifier[0]={:?}", proof.statement.nullifiers[0]);
    println!("statement.nullifier[1]={:?}", proof.statement.nullifiers[1]);
    println!(
        "statement.output[0]={:?}",
        proof.statement.output_commitments[0]
    );
    println!(
        "statement.output[1]={:?}",
        proof.statement.output_commitments[1]
    );
    println!("proof_bytes={}", consignment.proof.len());
    println!("non_primitive_tables={}", proof.proof.non_primitives.len());
    for (index, table) in proof.proof.non_primitives.iter().enumerate() {
        println!("table[{index}]={:?}", table.op_type);
    }
    Ok(())
}
