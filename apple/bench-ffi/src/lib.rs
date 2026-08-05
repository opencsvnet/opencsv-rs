//! C ABI shim for the iOS benchmark app.
//!
//! Exposes the same measurement as `crates/opencsv-pcd/tests/bench.rs`
//! (prove time, verify time, proof size for genesis mint, two transfer
//! hops, redeem) as a single function returning a JSON string. The Swift
//! side only needs `opencsv_bench_run()` + `opencsv_bench_free_string()`.

use std::ffi::CString;
use std::os::raw::c_char;
use std::time::Instant;

use opencsv_core::{AssetGenesis, Coin, Digest, OwnerSecret, PoseidonIssuerAuthorization};
use opencsv_pcd::{
    proof_security_report, prove_coin_transfer, prove_genesis_mint, prove_one_input_transfer,
    prove_redeem, verify_coin_proof, verify_redeem, CoinProof, COIN_PROOF_PROFILE_ID,
};

const ISSUER_SECRET: [u8; 32] = [0x42; 32];

fn asset_genesis() -> AssetGenesis {
    AssetGenesis {
        issuer_pk: PoseidonIssuerAuthorization::public_key(&ISSUER_SECRET),
        currency_code: *b"USD",
        terms_hash: Digest::from_bytes([0x74; 32]),
        nonce: 1,
    }
}

fn asset_id() -> Digest {
    asset_genesis().asset_id()
}

fn osk(tag: u8) -> OwnerSecret {
    OwnerSecret::from_bytes([tag; 32])
}

fn coin(value: u64, owner_tag: u8, r_tag: u8) -> Coin {
    Coin {
        asset_id: asset_id(),
        value,
        owner: osk(owner_tag).owner(),
        randomness: Digest::from_bytes([r_tag; 32]),
    }
}

fn proof_size(proof: &CoinProof) -> usize {
    postcard::to_allocvec(&proof.proof)
        .expect("proof serializes")
        .len()
}

fn fmt_ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn emit_partial(
    circuit: &str,
    prove: std::time::Duration,
    verify: std::time::Duration,
    proof: &CoinProof,
) {
    let security = proof_security_report(proof);
    eprintln!(
        "OPENCSV_BENCH_PARTIAL {{\"circuit\":{circuit:?},\"prove_ms\":{:.1},\"verify_ms\":{:.2},\"proof_bytes\":{},\"proven_bits\":{},\"adjusted_bits\":{},\"degree_bits\":{:?}}}",
        fmt_ms(prove),
        fmt_ms(verify),
        proof_size(proof),
        security.proven_bits,
        security.union_adjusted_bits,
        security.degree_bits,
    );
}

fn run() -> Result<String, String> {
    let mut rows = String::new();

    // Genesis mint (no predecessors).
    let coins = [coin(60, 0x22, 0x33), coin(40, 0x44, 0x55)];
    let nonce = Digest::from_bytes([0xaa; 32]);
    let t = Instant::now();
    let mint = prove_genesis_mint(&asset_genesis(), &ISSUER_SECRET, &nonce, &coins)
        .map_err(|e| e.to_string())?;
    let mint_prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&mint.statement, &mint).map_err(|e| e.to_string())?;
    let mint_verify = t.elapsed();
    let mint_security = proof_security_report(&mint);
    rows.push_str(&format!(
        "{{\"circuit\":\"genesis mint\",\"prove_ms\":{:.1},\"verify_ms\":{:.2},\"proof_bytes\":{},\"proven_bits\":{},\"adjusted_bits\":{},\"degree_bits\":{:?}}},",
        fmt_ms(mint_prove),
        fmt_ms(mint_verify),
        proof_size(&mint),
        mint_security.proven_bits,
        mint_security.union_adjusted_bits,
        mint_security.degree_bits,
    ));
    emit_partial("genesis mint", mint_prove, mint_verify, &mint);

    // Version-4 one-input forwarding (one mint predecessor, recipient + change).
    let one_input_outputs = [coin(45, 0x66, 0x71), coin(15, 0x22, 0x72)];
    let t = Instant::now();
    let one_input = prove_one_input_transfer(
        &asset_id(),
        &(coins[0], osk(0x22)),
        &one_input_outputs,
        &mint,
        0,
    )
    .map_err(|e| e.to_string())?;
    let one_input_prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&one_input.statement, &one_input).map_err(|e| e.to_string())?;
    let one_input_verify = t.elapsed();
    let one_input_security = proof_security_report(&one_input);
    rows.push_str(&format!(
        "{{\"circuit\":\"v4 one-input transfer (mint predecessor)\",\"prove_ms\":{:.1},\"verify_ms\":{:.2},\"proof_bytes\":{},\"proven_bits\":{},\"adjusted_bits\":{},\"degree_bits\":{:?}}},",
        fmt_ms(one_input_prove),
        fmt_ms(one_input_verify),
        proof_size(&one_input),
        one_input_security.proven_bits,
        one_input_security.union_adjusted_bits,
        one_input_security.degree_bits,
    ));
    emit_partial(
        "v4 one-input transfer (mint predecessor)",
        one_input_prove,
        one_input_verify,
        &one_input,
    );

    // Transfer, hop 1 (2 in-circuit verifications of mint proofs).
    let inputs1 = [(coins[0], osk(0x22)), (coins[1], osk(0x44))];
    let outputs1 = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];
    let t = Instant::now();
    let t1 = prove_coin_transfer(&asset_id(), &inputs1, &outputs1, [&mint, &mint], [0, 1])
        .map_err(|e| e.to_string())?;
    let t1_prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&t1.statement, &t1).map_err(|e| e.to_string())?;
    let t1_verify = t.elapsed();
    let t1_security = proof_security_report(&t1);
    rows.push_str(&format!(
        "{{\"circuit\":\"transfer hop 1 (2 mint predecessors)\",\"prove_ms\":{:.1},\"verify_ms\":{:.2},\"proof_bytes\":{},\"proven_bits\":{},\"adjusted_bits\":{},\"degree_bits\":{:?}}},",
        fmt_ms(t1_prove),
        fmt_ms(t1_verify),
        proof_size(&t1),
        t1_security.proven_bits,
        t1_security.union_adjusted_bits,
        t1_security.degree_bits,
    ));
    emit_partial(
        "transfer hop 1 (2 mint predecessors)",
        t1_prove,
        t1_verify,
        &t1,
    );

    // Transfer, hop 2 (2 in-circuit verifications of node proofs).
    let inputs2 = [(outputs1[0], osk(0x66)), (outputs1[1], osk(0x88))];
    let outputs2 = [coin(50, 0x11, 0x12), coin(50, 0x13, 0x14)];
    let t = Instant::now();
    let t2 = prove_coin_transfer(&asset_id(), &inputs2, &outputs2, [&t1, &t1], [0, 1])
        .map_err(|e| e.to_string())?;
    let t2_prove = t.elapsed();
    let t = Instant::now();
    verify_coin_proof(&t2.statement, &t2).map_err(|e| e.to_string())?;
    let t2_verify = t.elapsed();
    let t2_security = proof_security_report(&t2);
    rows.push_str(&format!(
        "{{\"circuit\":\"transfer hop 2 (2 node predecessors)\",\"prove_ms\":{:.1},\"verify_ms\":{:.2},\"proof_bytes\":{},\"proven_bits\":{},\"adjusted_bits\":{},\"degree_bits\":{:?}}},",
        fmt_ms(t2_prove),
        fmt_ms(t2_verify),
        proof_size(&t2),
        t2_security.proven_bits,
        t2_security.union_adjusted_bits,
        t2_security.degree_bits,
    ));
    emit_partial(
        "transfer hop 2 (2 node predecessors)",
        t2_prove,
        t2_verify,
        &t2,
    );

    // Redeem (1 in-circuit verification of a node predecessor).
    let t = Instant::now();
    let redeem =
        prove_redeem(&asset_id(), &(outputs2[0], osk(0x11)), &t2, 0).map_err(|e| e.to_string())?;
    let redeem_prove = t.elapsed();
    let t = Instant::now();
    verify_redeem(&redeem.statement, &redeem).map_err(|e| e.to_string())?;
    let redeem_verify = t.elapsed();
    let redeem_security = proof_security_report(&redeem);
    rows.push_str(&format!(
        "{{\"circuit\":\"redeem (1 node predecessor)\",\"prove_ms\":{:.1},\"verify_ms\":{:.2},\"proof_bytes\":{},\"proven_bits\":{},\"adjusted_bits\":{},\"degree_bits\":{:?}}}",
        fmt_ms(redeem_prove),
        fmt_ms(redeem_verify),
        proof_size(&redeem),
        redeem_security.proven_bits,
        redeem_security.union_adjusted_bits,
        redeem_security.degree_bits,
    ));
    emit_partial(
        "redeem (1 node predecessor)",
        redeem_prove,
        redeem_verify,
        &redeem,
    );

    Ok(format!(
        "{{\"device\":\"{}\",\"profile\":\"{}\",\"results\":[{}]}}",
        std::env::consts::ARCH,
        COIN_PROOF_PROFILE_ID,
        rows
    ))
}

/// Run the full benchmark and return a newly allocated JSON string.
/// The caller must free it with [`opencsv_bench_free_string`].
///
/// Total runtime: a few seconds on a desktop-class machine; possibly much
/// longer on a phone. Call from a background thread.
#[no_mangle]
pub extern "C" fn opencsv_bench_run() -> *mut c_char {
    let json = match run() {
        Ok(json) => json,
        Err(e) => format!("{{\"error\":{e:?}}}"),
    };
    CString::new(json).expect("JSON contains no NUL").into_raw()
}

/// Free a string returned by [`opencsv_bench_run`].
///
/// # Safety
/// `s` must be a pointer previously returned by `opencsv_bench_run`,
/// and must be freed at most once.
#[no_mangle]
pub unsafe extern "C" fn opencsv_bench_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}
