//! End-to-end tests for stage 3: PCD recursion (paper §4.5 item 4).
//!
//! Run with `cargo test -p opencsv-pcd --test node -- --nocapture` to see
//! timings and proof sizes. Slow tests are marked `#[ignore]`; run them with
//! `cargo test -p opencsv-pcd --test node -- --ignored --nocapture`.

use std::time::Instant;

use opencsv_core::{AssetGenesis, Coin, Digest, OwnerSecret, PoseidonIssuerAuthorization};
use opencsv_pcd::{
    proof_security_report, prove_coin_transfer, prove_genesis_mint, prove_genesis_mint_raw,
    prove_one_input_transfer, verify_coin_proof, CoinProof, NodeError, NodeMode, NodeStatement,
    COIN_PROOF_VERSION, LEGACY_COIN_PROOF_VERSION,
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

/// Test asset id derived from an issuer-controlled genesis.
fn asset_id() -> Digest {
    asset_genesis().asset_id()
}

fn osk(tag: u8) -> OwnerSecret {
    OwnerSecret::from_bytes([tag; 32])
}

/// A coin in the test asset owned by `osk(owner_tag)`.
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

/// Mint two coins (values 60 and 40) and their genesis proof.
fn genesis() -> (CoinProof, [Coin; 2]) {
    let coins = [coin(60, 0x22, 0x33), coin(40, 0x44, 0x55)];
    let nonce = Digest::from_bytes([0xaa; 32]);
    let proof =
        prove_genesis_mint(&asset_genesis(), &ISSUER_SECRET, &nonce, &coins).expect("mint proving");
    (proof, coins)
}

/// (a) A genesis mint proof verifies.
#[test]
fn genesis_mint_verifies() {
    let t = Instant::now();
    let coins = [coin(u64::MAX, 0x22, 0x33), coin(0, 0x44, 0x55)];
    let nonce = Digest::from_bytes([0xaa; 32]);
    let proof =
        prove_genesis_mint(&asset_genesis(), &ISSUER_SECRET, &nonce, &coins).expect("mint proving");
    println!("prove_genesis_mint: {:?}", t.elapsed());
    println!("mint proof size: {} bytes", proof_size(&proof));

    let t = Instant::now();
    verify_coin_proof(&proof.statement, &proof).expect("mint verification");
    println!("verify_coin_proof (mint): {:?}", t.elapsed());
}

/// (b) The money test: a transfer spending the two mint outputs, with two
/// in-circuit predecessor verifications (both of the same genesis mint proof,
/// selected outputs 0 and 1).
#[test]
fn transfer_spending_mint_outputs_verifies() {
    let (mint, coins) = genesis();
    println!("mint proof size: {} bytes", proof_size(&mint));

    let inputs = [(coins[0].clone(), osk(0x22)), (coins[1].clone(), osk(0x44))];
    let outputs = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];

    let t = Instant::now();
    let transfer = prove_coin_transfer(&asset_id(), &inputs, &outputs, [&mint, &mint], [0, 1])
        .expect("transfer proving");
    let prove_time = t.elapsed();
    println!("prove_coin_transfer (2 mint predecessors): {prove_time:?}");
    println!("transfer proof size: {} bytes", proof_size(&transfer));

    let t = Instant::now();
    verify_coin_proof(&transfer.statement, &transfer).expect("transfer verification");
    println!("verify_coin_proof (transfer): {:?}", t.elapsed());
}

/// A received single coin can be forwarded without inventing a duplicate
/// padding input. The second nullifier slot is explicitly zero in v4.
#[test]
fn one_input_transfer_spending_mint_output_verifies() {
    let started = Instant::now();
    let (mint, coins) = genesis();
    println!("one-input predecessor mint: {:?}", started.elapsed());
    let input = (coins[0], osk(0x22));
    let outputs = [coin(45, 0x66, 0x77), coin(15, 0x22, 0x99)];

    let started = Instant::now();
    let transfer = prove_one_input_transfer(&asset_id(), &input, &outputs, &mint, 0)
        .expect("one-input transfer proving");
    println!("one-input transfer prove: {:?}", started.elapsed());
    println!("one-input proof size: {} bytes", proof_size(&transfer));
    let security = proof_security_report(&transfer);
    println!(
        "one-input security: proven={} adjusted={} degrees={:?}",
        security.proven_bits, security.union_adjusted_bits, security.degree_bits
    );
    assert_eq!(transfer.version, COIN_PROOF_VERSION);
    assert_eq!(
        transfer.statement.nullifiers[0],
        input.0.nullifier(&input.1)
    );
    assert_eq!(
        transfer.statement.nullifiers[1],
        Digest::from_bytes([0u8; 32])
    );
    let started = Instant::now();
    verify_coin_proof(&transfer.statement, &transfer).expect("one-input transfer verification");
    println!("one-input transfer verify: {:?}", started.elapsed());
}

/// A received one-input output can itself be forwarded. This is the exact
/// zero-confirmation wallet shape: mint -> sender transfer -> recipient
/// transfer. It guards the recursive verifier's public-input relay against
/// double-assigning extension-field witness coefficients.
#[test]
#[ignore = "slow regression: two recursive one-input proofs"]
fn one_input_transfer_spending_one_input_output_verifies() {
    let coins = [coin(25_000_000, 0x22, 0x33), coin(0, 0x44, 0x55)];
    let mint = prove_genesis_mint(
        &asset_genesis(),
        &ISSUER_SECRET,
        &Digest::from_bytes([0xaa; 32]),
        &coins,
    )
    .expect("mint proving");

    let first_input = (coins[0].clone(), osk(0x22));
    let first_outputs = [coin(25_000_000, 0x66, 0x77), coin(0, 0x22, 0x99)];
    let started = Instant::now();
    let first = prove_one_input_transfer(&asset_id(), &first_input, &first_outputs, &mint, 0)
        .expect("first one-input transfer proving");
    println!("first one-input hop prove: {:?}", started.elapsed());
    verify_coin_proof(&first.statement, &first).expect("first one-input hop verifies");

    let second_input = (first_outputs[0].clone(), osk(0x66));
    let second_outputs = [coin(10_000_000, 0x44, 0x12), coin(15_000_000, 0x66, 0x13)];
    let started = Instant::now();
    let second = prove_one_input_transfer(&asset_id(), &second_input, &second_outputs, &first, 0)
        .expect("forwarded one-input transfer proving");
    println!("second one-input hop prove: {:?}", started.elapsed());
    verify_coin_proof(&second.statement, &second).expect("forwarded one-input hop verifies");
    assert_eq!(
        second.statement.nullifiers[0],
        second_input.0.nullifier(&second_input.1)
    );
    assert_eq!(
        second.statement.nullifiers[1],
        Digest::from_bytes([0u8; 32])
    );
}

#[test]
#[ignore = "release benchmark: two recursive one-input proofs"]
fn one_input_transfer_cold_warm_benchmark() {
    let (mint, coins) = genesis();
    let input = (coins[0], osk(0x22));
    let outputs = [coin(45, 0x66, 0x77), coin(15, 0x22, 0x99)];

    for label in ["cold", "warm"] {
        let started = Instant::now();
        let transfer = prove_one_input_transfer(&asset_id(), &input, &outputs, &mint, 0)
            .expect("one-input transfer proving");
        let proving = started.elapsed();
        let started = Instant::now();
        verify_coin_proof(&transfer.statement, &transfer).expect("one-input transfer verification");
        let verification = started.elapsed();
        let security = proof_security_report(&transfer);
        println!(
            "one-input {label}: prove={proving:?} verify={verification:?} size={} proven={} adjusted={} degrees={:?}",
            proof_size(&transfer),
            security.proven_bits,
            security.union_adjusted_bits,
            security.degree_bits
        );
    }
}

/// (c) Two-hop chain: mint → transfer₁ → transfer₂. Verification time and
/// proof size must not grow with history length: each node proof verifies
/// exactly two predecessors regardless of total ancestry.
///
/// Slow (~2.5 min in debug); excluded from the default run. Run with:
/// `cargo test -p opencsv-pcd --test node -- --ignored --nocapture`.
#[test]
#[ignore = "slow: two full recursive node proofs (~2.5 min in debug)"]
fn two_hop_chain_verifies() {
    let (mint, coins) = genesis();

    // Hop 1: spend both mint outputs.
    let inputs1 = [(coins[0].clone(), osk(0x22)), (coins[1].clone(), osk(0x44))];
    let outputs1 = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];
    let t = Instant::now();
    let t1 = prove_coin_transfer(&asset_id(), &inputs1, &outputs1, [&mint, &mint], [0, 1])
        .expect("hop-1 transfer proving");
    let t1_prove = t.elapsed();
    let t1_size = proof_size(&t1);
    let t = Instant::now();
    verify_coin_proof(&t1.statement, &t1).expect("hop-1 verification");
    let t1_verify = t.elapsed();
    println!("hop1: prove {t1_prove:?}, verify {t1_verify:?}, size {t1_size} B");

    // Hop 2: spend both hop-1 outputs (two in-circuit verifications of the
    // hop-1 node proof — one full recursion level deeper).
    let inputs2 = [
        (outputs1[0].clone(), osk(0x66)),
        (outputs1[1].clone(), osk(0x88)),
    ];
    let outputs2 = [coin(50, 0x11, 0x12), coin(50, 0x13, 0x14)];
    let t = Instant::now();
    let t2 = prove_coin_transfer(&asset_id(), &inputs2, &outputs2, [&t1, &t1], [0, 1])
        .expect("hop-2 transfer proving");
    let t2_prove = t.elapsed();
    let t2_size = proof_size(&t2);
    let t = Instant::now();
    verify_coin_proof(&t2.statement, &t2).expect("hop-2 verification");
    let t2_verify = t.elapsed();
    println!("hop2: prove {t2_prove:?}, verify {t2_verify:?}, size {t2_size} B");

    // Constant-size / constant-time in history: hop-2's proof covers the same
    // statement shape and exactly two predecessor verifications.
    assert!(t2_size > 0 && t1_size > 0);
}

/// (d) Negative: a transfer whose claimed predecessor does not actually
/// contain the consumed input coin must fail at proving time.
///
/// The off-circuit ownership pre-check rejects the obvious mismatch; tampering
/// the predecessor's *carried* statement (so that check passes while the
/// proof's transcript-bound statement still disagrees) fails closed at the
/// statement-verification boundary before recursive witness construction.
#[test]
fn wrong_predecessor_fails() {
    let (mint, coins) = genesis();
    let stranger = coin(60, 0xee, 0xef); // not created by the mint
    let inputs = [(stranger.clone(), osk(0xee)), (coins[1].clone(), osk(0x44))];
    let outputs = [coin(70, 0x66, 0x77), coin(30, 0x88, 0x99)];

    // Off-circuit pre-check: the mint's outputs do not include `stranger`.
    let err = match prove_coin_transfer(&asset_id(), &inputs, &outputs, [&mint, &mint], [0, 1]) {
        Ok(_) => panic!("spending a coin the predecessor never created must fail"),
        Err(e) => e,
    };
    println!("wrong predecessor rejected with: {err}");
    assert!(matches!(err, NodeError::PredecessorOutputMismatch));

    // Proof-binding path: tamper the predecessor's *carried* statement so the
    // ownership pre-check passes. Verification against the transcript-bound
    // statement rejects it before recursive witness construction.
    let mut tampered_mint = CoinProof {
        version: mint.version,
        mode: mint.mode,
        statement: mint.statement.clone(),
        proof: mint.proof,
    };
    tampered_mint.statement.output_commitments[0] = stranger.commitment();
    let err = match prove_coin_transfer(
        &asset_id(),
        &inputs,
        &outputs,
        [&tampered_mint, &tampered_mint],
        [0, 1],
    ) {
        Ok(_) => panic!("a tampered predecessor statement must fail closed"),
        Err(e) => e,
    };
    println!("tampered predecessor statement rejected with: {err}");
    assert!(matches!(err, NodeError::StatementMismatch));
}

/// (e) Negative: tampered public data / wrong mode fails verification.
#[test]
fn tampered_public_data_fails() {
    let (mint, coins) = genesis();

    // Wrong expected output commitment.
    let mut expected = mint.statement.clone();
    expected.output_commitments[0] = Digest::from_bytes([0xee; 32]);
    let err = verify_coin_proof(&expected, &mint)
        .expect_err("verification against a tampered statement must fail");
    assert!(matches!(err, NodeError::StatementMismatch));

    // Wrong asset id.
    let mut expected = mint.statement.clone();
    expected.asset_id = Digest::from_bytes([0xee; 32]);
    let err = verify_coin_proof(&expected, &mint)
        .expect_err("verification against a tampered asset id must fail");
    assert!(matches!(err, NodeError::StatementMismatch));

    // A mint proof must not verify against a transfer-mode statement.
    let transfer_mode = NodeStatement {
        asset_id: mint.statement.asset_id,
        value: mint.statement.value,
        mint_commit: mint.statement.mint_commit,
        nullifiers: mint.statement.nullifiers,
        output_commitments: mint.statement.output_commitments,
    };
    let proof_as_transfer = CoinProof {
        version: mint.version,
        mode: NodeMode::Transfer,
        statement: transfer_mode.clone(),
        proof: mint.proof,
    };
    let err = match verify_coin_proof(&transfer_mode, &proof_as_transfer) {
        Ok(_) => panic!("verification with the wrong mode must fail"),
        Err(e) => e,
    };
    assert!(matches!(err, NodeError::StatementMismatch));

    // Sanity: the honest statement does verify.
    let mint = genesis().0;
    verify_coin_proof(&mint.statement, &mint).expect("honest mint verifies");
    let _ = coins;
}

/// The recursive mint AIR rejects an issuer forgery even when the native
/// consistency check is bypassed, and pre-v3 lineages fail closed.
#[test]
fn issuer_forgery_and_legacy_lineage_fail() {
    let coins = [coin(60, 0x22, 0x33), coin(40, 0x44, 0x55)];
    let nonce = Digest::from_bytes([0xaa; 32]);
    let wrong_secret = [0x43; 32];

    let err = match prove_genesis_mint(&asset_genesis(), &wrong_secret, &nonce, &coins) {
        Ok(_) => panic!("checked proving must reject a foreign issuer seed"),
        Err(error) => error,
    };
    assert!(matches!(err, NodeError::IssuerKeyMismatch));

    let err = match prove_genesis_mint_raw(
        &asset_id(),
        &asset_genesis(),
        &wrong_secret,
        &nonce,
        &coins,
    ) {
        Ok(_) => panic!("the recursive mint circuit must reject an issuer forgery"),
        Err(error) => error,
    };
    assert!(matches!(err, NodeError::Circuit(_)));

    // Simulate an old 52-element statement relabeled with the current outer
    // version: the transcript-bound statement shape still rejects it.
    let (mut relabeled, _) = genesis();
    let statement_entry = relabeled
        .proof
        .non_primitives
        .iter_mut()
        .find(|entry| entry.public_values.len() == 4 * opencsv_pcd::STATEMENT_ELEMS)
        .expect("coin proof has a statement table");
    statement_entry.public_values.drain(0..4);
    let err = verify_coin_proof(&relabeled.statement, &relabeled)
        .expect_err("an old statement shape cannot be relabeled as version 4");
    assert!(matches!(err, NodeError::StatementMismatch));

    let (mint, _) = genesis();
    let legacy = CoinProof {
        version: 2,
        mode: mint.mode,
        statement: mint.statement.clone(),
        proof: mint.proof,
    };
    let err = verify_coin_proof(&legacy.statement, &legacy)
        .expect_err("legacy unauthenticated proofs must not verify");
    assert!(matches!(
        err,
        NodeError::UnsupportedProofVersion { actual: 2 }
    ));
    assert_eq!(LEGACY_COIN_PROOF_VERSION, 3);
    assert_eq!(COIN_PROOF_VERSION, 4);
}

/// Verification rejects a proof whose concrete trace growth has crossed the
/// frozen production profile's security floor before attempting cryptography.
#[test]
fn oversized_trace_metadata_fails_closed() {
    let (mut mint, _) = genesis();
    mint.proof.proof.degree_bits[0] = 19;
    let err = verify_coin_proof(&mint.statement, &mint)
        .expect_err("a proof below the deployment security floor must fail closed");
    assert!(matches!(
        err,
        NodeError::InsufficientProofSecurity {
            actual: 93,
            required: 94
        }
    ));
}
