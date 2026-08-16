//! Lean executable-model corpus against the real receiver `accept()` driver.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use opencsv_core::accept::{accept, public_input};
use opencsv_core::anchor::{mint_commit, AnchorRecord};
use opencsv_core::*;
use serde::Deserialize;

const VK: &[u8] = b"opencsv-model-differential-v1";
const CORPUS_ENV: &str = "OPENCSV_MODEL_CORPUS";

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: u32,
    generator_seed: u64,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: u64,
    class: String,
    trace_shape: String,
    case_seed: u64,
    issuer_seed: u64,
    terms_seed: u64,
    sender_seed: u64,
    recipient_seed: u64,
    randomness_seed: u64,
    value: u64,
    proof_valid: bool,
    anchor_mode: String,
    expected_accept: bool,
}

fn corpus_path() -> PathBuf {
    std::env::var_os(CORPUS_ENV).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/model_differential.json"),
        PathBuf::from,
    )
}

/// Expand one Lean-emitted scalar into deterministic bytes without relying on
/// platform RNG state.
fn seeded_bytes(mut state: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_exact_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    bytes
}

fn secret(seed: u64) -> OwnerSecret {
    OwnerSecret::from_bytes(seeded_bytes(seed))
}

fn digest(seed: u64) -> Digest {
    Digest::from_bytes(seeded_bytes(seed))
}

fn genesis(case: &Case) -> AssetGenesis {
    AssetGenesis {
        issuer_pk: seeded_bytes(case.issuer_seed),
        currency_code: *b"USD",
        terms_hash: digest(case.terms_seed),
        nonce: case.case_seed,
    }
}

fn make_consignment(
    chain: &MockAnchorChain,
    anchor_ref: AnchorRef,
    nullifiers: Vec<Digest>,
    openings: Vec<CoinOpening>,
    proof_valid: bool,
) -> Consignment {
    let record = chain
        .anchor_at(&anchor_ref)
        .expect("build the proof before any missing-anchor mutation");
    let ctx = chain
        .ctx_at(&anchor_ref)
        .expect("anchored case has a context");
    let x = public_input(&record, &ctx, &openings);
    let mut proof = MockVerifier::prove(VK, &x);
    if !proof_valid {
        let last = proof.last_mut().expect("mock proof has a checksum");
        *last ^= 1;
    }
    Consignment {
        coin_openings: openings,
        nullifiers,
        proof,
        anchor_ref,
        aux: None,
    }
}

fn run_case(case: &Case) -> Result<AcceptedCoins, RejectReason> {
    assert!(
        matches!(
            case.trace_shape.as_str(),
            "genesis_mint_transfer_redeem" | "genesis_mint_transfer_transfer_reuse"
        ),
        "case {} has an unknown trace shape",
        case.id
    );

    let genesis = genesis(case);
    let asset_id = genesis.asset_id();
    let sender = secret(case.sender_seed);
    let recipient = secret(case.recipient_seed);
    let minted = Coin {
        asset_id,
        value: case.value,
        owner: sender.owner(),
        randomness: digest(case.randomness_seed),
    };
    let nullifier = minted.nullifier(&sender);
    let output_value = if case.class == "unbalanced_value" {
        case.value + 1
    } else {
        case.value
    };
    let opening = CoinOpening {
        asset_id,
        value: output_value,
        owner: recipient.owner(),
        randomness: digest(case.randomness_seed + 1),
    };

    let mut chain = MockAnchorChain::new();
    let mint_nonce = digest(case.case_seed ^ 0x4d49_4e54);
    let mint_ctx = seeded_bytes(case.case_seed ^ 0x4745_4e45_5349_53);
    chain.append_with_ctx(
        AnchorRecord::Mint {
            asset_id: asset_id.to_anchor(),
            value: case.value,
            mint_commit: mint_commit(&asset_id, case.value, &mint_nonce).to_anchor(),
        },
        mint_ctx,
    );
    chain.advance_blocks(1);

    if case.anchor_mode == "reused" {
        let prior_ctx = seeded_bytes(case.case_seed ^ 0x5052_494f_52);
        let prior_record = AnchorRecord::xfer(&[nullifier], &prior_ctx);
        chain.append_with_ctx(prior_record, prior_ctx);
        chain.advance_blocks(1);
    }

    let target_ctx = seeded_bytes(case.case_seed ^ 0x5441_5247_4554);
    let record_ctx = if case.anchor_mode == "bad" {
        seeded_bytes(case.case_seed ^ 0x4241_445f_4249_4e44)
    } else {
        target_ctx
    };
    let target_record = AnchorRecord::xfer(&[nullifier], &record_ctx);
    let target_ref = chain.append_with_ctx(target_record, target_ctx);
    let mut consignment = make_consignment(
        &chain,
        target_ref,
        vec![nullifier],
        vec![opening],
        case.proof_valid,
    );
    if case.anchor_mode == "missing" {
        consignment.anchor_ref.location.position = u32::MAX;
    }
    chain.advance_blocks(5);

    accept(
        &consignment,
        &chain,
        &MockVerifier,
        &AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: &[recipient],
            known_assets: &[asset_id],
        },
    )
}

fn expected_rejection(class: &str) -> Option<&'static str> {
    match class {
        "valid" => None,
        "unbalanced_value" | "wrong_owner" => Some("invalid_proof"),
        "reused_nullifier" => Some("nullifier_conflict"),
        "bad_anchor" => Some("ill_formed_anchor"),
        "missing_anchor" => Some("anchor_not_found"),
        other => panic!("unknown mutation class {other}"),
    }
}

#[test]
fn lean_model_corpus_matches_real_accept_driver() {
    let path = corpus_path();
    let bytes = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read Lean corpus {} (override with {CORPUS_ENV}): {error}",
            path.display()
        )
    });
    let corpus: Corpus = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("invalid Lean corpus {}: {error}", path.display()));
    assert_eq!(corpus.schema, 1);
    assert_eq!(corpus.generator_seed, 1_330_660_686);

    let mut counts = BTreeMap::<String, usize>::new();
    for case in &corpus.cases {
        let result = run_case(case);
        assert_eq!(
            result.is_ok(),
            case.expected_accept,
            "model/code disagreement: case={} class={} trace={} result={result:?}",
            case.id,
            case.class,
            case.trace_shape,
        );
        if let Some(code) = expected_rejection(&case.class) {
            assert_eq!(
                result.unwrap_err().code(),
                code,
                "wrong rejection: case={} class={}",
                case.id,
                case.class,
            );
        }
        *counts.entry(case.class.clone()).or_default() += 1;
    }

    assert_eq!(corpus.cases.len(), 192);
    for class in [
        "valid",
        "unbalanced_value",
        "wrong_owner",
        "reused_nullifier",
        "bad_anchor",
        "missing_anchor",
    ] {
        assert_eq!(counts.get(class), Some(&32), "class count for {class}");
    }
    println!("Lean model differential counts: {counts:?}");
}
