//! D5 value-free profile-closure and desktop security screen.
//!
//! This is deliberately ignored in the default suite because it generates
//! several production-parameter recursive proofs. Run it in release mode:
//!
//! ```text
//! cargo test -p opencsv-pcd --release --features d5-profile-spike --test profile_closure -- --ignored --nocapture
//! ```

use opencsv_core::{AssetGenesis, Coin, Digest, OwnerSecret, PoseidonIssuerAuthorization};
use opencsv_pcd::{
    begin_d5_profile_spike, clear_d5_profile_spike, install_d5_profile_spike,
    proof_security_report, prove_coin_transfer, prove_genesis_mint, prove_one_input_transfer,
    prove_redeem, verify_coin_proof, CoinProof, NodeError, PRODUCTION_SECURITY_TARGET_BITS,
};
use p3_baby_bear::BabyBear;
use p3_circuit_prover::shape::{iterate_profile_closure, BatchStarkShape};

const ISSUER_SECRET: [u8; 32] = [0x42; 32];
const MAX_CLOSURE_ITERS: usize = 8;

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

fn coin(value: u64, owner_tag: u8, randomness_tag: u8) -> Coin {
    Coin {
        asset_id: asset_id(),
        value,
        owner: osk(owner_tag).owner(),
        randomness: Digest::from_bytes([randomness_tag; 32]),
    }
}

fn unlocked_shape(proof: &CoinProof) -> BatchStarkShape<BabyBear> {
    BatchStarkShape::from_proof(&proof.proof)
}

fn locked_shape(proof: &CoinProof) -> BatchStarkShape<BabyBear> {
    BatchStarkShape::from_proof_with_fri(&proof.proof)
}

fn print_shape(label: &str, shape: &BatchStarkShape<BabyBear>) {
    let npo_rows: Vec<_> = shape
        .non_primitives
        .iter()
        .map(|entry| (format!("{:?}", entry.op_type), entry.rows))
        .collect();
    let degrees: Vec<_> = shape
        .instances
        .iter()
        .map(|instance| instance.degree_bits)
        .collect();
    let prep_degrees: Vec<_> = shape
        .preprocessed
        .iter()
        .flat_map(|prep| prep.instances.iter())
        .map(|instance| instance.as_ref().map(|metadata| metadata.degree_bits))
        .collect();
    let fri = shape
        .fri
        .as_ref()
        .map(|fri| (fri.commit_phase_len, fri.final_poly_len, fri.query_count));
    println!(
        "{label}: rows={:?} npo_rows={npo_rows:?} degrees={degrees:?} prep={prep_degrees:?} fri={fri:?}",
        shape.rows.as_array(),
    );
}

fn prove_two_input_successor(
    predecessor: &CoinProof,
    predecessor_coins: &[Coin; 2],
    owner_tags: [u8; 2],
    step: usize,
) -> Result<(CoinProof, [Coin; 2], [u8; 2]), NodeError> {
    let inputs = [
        (predecessor_coins[0].clone(), osk(owner_tags[0])),
        (predecessor_coins[1].clone(), osk(owner_tags[1])),
    ];
    let next_owner_tags = [owner_tags[0].wrapping_add(4), owner_tags[1].wrapping_add(4)];
    let next_outputs = [
        coin(60, next_owner_tags[0], 0x80_u8.wrapping_add(step as u8)),
        coin(40, next_owner_tags[1], 0x90_u8.wrapping_add(step as u8)),
    ];
    let next = prove_coin_transfer(
        &asset_id(),
        &inputs,
        &next_outputs,
        [predecessor, predecessor],
        [0, 1],
    )?;
    Ok((next, next_outputs, next_owner_tags))
}

#[test]
#[ignore = "D5 desktop screen: several production-parameter recursive proofs"]
fn normalized_v5_profile_closes_within_deployment_floor() {
    begin_d5_profile_spike();
    clear_d5_profile_spike().expect("start with padding disabled");

    let mint_coins = [coin(60, 0x22, 0x33), coin(40, 0x44, 0x55)];
    let raw_mint = prove_genesis_mint(
        &asset_genesis(),
        &ISSUER_SECRET,
        &Digest::from_bytes([0xaa; 32]),
        &mint_coins,
    )
    .expect("raw normalized mint profile proof");

    let one_input = (mint_coins[0].clone(), osk(0x22));
    let one_outputs = [coin(45, 0x62, 0x63), coin(15, 0x64, 0x65)];
    let raw_one = prove_one_input_transfer(&asset_id(), &one_input, &one_outputs, &raw_mint, 0)
        .expect("raw one-input profile proof");

    let two_inputs = [
        (mint_coins[0].clone(), osk(0x22)),
        (mint_coins[1].clone(), osk(0x44)),
    ];
    let two_outputs = [coin(60, 0x66, 0x67), coin(40, 0x68, 0x69)];
    let raw_two = prove_coin_transfer(
        &asset_id(),
        &two_inputs,
        &two_outputs,
        [&raw_mint, &raw_mint],
        [0, 1],
    )
    .expect("raw two-input profile proof");

    let raw_redeem = prove_redeem(
        &asset_id(),
        &(mint_coins[1].clone(), osk(0x44)),
        &raw_mint,
        1,
    )
    .expect("raw redeem profile proof");

    let unlocked_classes = [
        ("raw mint", unlocked_shape(&raw_mint)),
        ("raw transfer-one", unlocked_shape(&raw_one)),
        ("raw transfer-two", unlocked_shape(&raw_two)),
        ("raw redeem", unlocked_shape(&raw_redeem)),
    ];
    for (label, class_shape) in &unlocked_classes {
        print_shape(label, class_shape);
    }

    let unlocked_profile = unlocked_classes
        .iter()
        .skip(1)
        .try_fold(
            unlocked_classes[0].1.clone(),
            |profile, (_, class_shape)| profile.union(class_shape),
        )
        .expect("the four semantic classes must share one normalizable structure");
    assert!(unlocked_profile.fri.is_none());
    for (label, class_shape) in &unlocked_classes {
        unlocked_profile
            .covers(class_shape)
            .unwrap_or_else(|error| panic!("class union does not cover {label}: {error}"));
    }
    print_shape("unlocked class-union profile", &unlocked_profile);

    // Close the semantic class family itself. Padding mint changes its proof
    // shape and therefore the verifier embedded in each recursive class; a
    // single union of classes built over the raw mint is not sufficient.
    let mut class_iteration = 0usize;
    let class_profile = iterate_profile_closure(
        unlocked_profile,
        |profile| {
            install_d5_profile_spike(profile.clone()).map_err(|error| {
                format!("class iteration {class_iteration}: profile install failed: {error}")
            })?;
            let padded_mint = prove_genesis_mint(
                &asset_genesis(),
                &ISSUER_SECRET,
                &Digest::from_bytes([0xb0_u8.wrapping_add(class_iteration as u8); 32]),
                &mint_coins,
            )
            .map_err(|error| {
                format!("class iteration {class_iteration}: padded mint failed: {error}")
            })?;
            verify_coin_proof(&padded_mint.statement, &padded_mint).map_err(|error| {
                format!("class iteration {class_iteration}: padded mint verify failed: {error}")
            })?;
            if unlocked_shape(&padded_mint) != *profile {
                return Err(format!(
                    "class iteration {class_iteration}: padded mint did not realize the candidate profile"
                ));
            }

            clear_d5_profile_spike().map_err(|error| {
                format!("class iteration {class_iteration}: disable padding failed: {error}")
            })?;
            let measured_one = prove_one_input_transfer(
                &asset_id(),
                &one_input,
                &one_outputs,
                &padded_mint,
                0,
            )
            .map_err(|error| {
                format!("class iteration {class_iteration}: measure transfer-one failed: {error}")
            })?;
            let measured_two = prove_coin_transfer(
                &asset_id(),
                &two_inputs,
                &two_outputs,
                [&padded_mint, &padded_mint],
                [0, 1],
            )
            .map_err(|error| {
                format!("class iteration {class_iteration}: measure transfer-two failed: {error}")
            })?;
            let measured_redeem = prove_redeem(
                &asset_id(),
                &(mint_coins[1].clone(), osk(0x44)),
                &padded_mint,
                1,
            )
            .map_err(|error| {
                format!("class iteration {class_iteration}: measure redeem failed: {error}")
            })?;
            for (label, proof) in [
                ("measured transfer-one", &measured_one),
                ("measured transfer-two", &measured_two),
                ("measured redeem", &measured_redeem),
            ] {
                verify_coin_proof(&proof.statement, proof).map_err(|error| {
                    format!("class iteration {class_iteration}: {label} verify failed: {error}")
                })?;
            }

            let measured_shapes = [
                ("transfer-one", unlocked_shape(&measured_one)),
                ("transfer-two", unlocked_shape(&measured_two)),
                ("redeem", unlocked_shape(&measured_redeem)),
            ];
            let measured_union = measured_shapes
                .iter()
                .skip(1)
                .try_fold(measured_shapes[0].1.clone(), |candidate, (_, shape)| {
                    candidate.union(shape)
                })
                .map_err(|error| {
                    format!("class iteration {class_iteration}: class union failed: {error}")
                })?;
            for (label, shape) in &measured_shapes {
                measured_union.covers(shape).map_err(|error| {
                    format!(
                        "class iteration {class_iteration}: measured union does not cover {label}: {error}"
                    )
                })?;
            }
            print_shape(
                &format!("class measurement {class_iteration}"),
                &measured_union,
            );
            class_iteration += 1;
            Ok::<_, String>(measured_union)
        },
        MAX_CLOSURE_ITERS,
    )
    .expect("the semantic class family profile must close");
    print_shape("closed semantic-class profile", &class_profile);

    install_d5_profile_spike(class_profile).expect("install closed class profile");
    let mint = prove_genesis_mint(
        &asset_genesis(),
        &ISSUER_SECRET,
        &Digest::from_bytes([0xc0; 32]),
        &mint_coins,
    )
    .expect("closed-profile mint proof");
    let one = prove_one_input_transfer(&asset_id(), &one_input, &one_outputs, &mint, 0)
        .expect("closed-profile one-input proof");
    let two = prove_coin_transfer(
        &asset_id(),
        &two_inputs,
        &two_outputs,
        [&mint, &mint],
        [0, 1],
    )
    .expect("closed-profile two-input proof");
    let redeem = prove_redeem(&asset_id(), &(mint_coins[1].clone(), osk(0x44)), &mint, 1)
        .expect("closed-profile redeem proof");

    let padded_classes = [
        ("padded mint", &mint),
        ("padded transfer-one", &one),
        ("padded transfer-two", &two),
        ("padded redeem", &redeem),
    ];
    let seed = locked_shape(&mint);
    for (label, proof) in padded_classes {
        verify_coin_proof(&proof.statement, proof)
            .unwrap_or_else(|error| panic!("{label} native verification failed: {error}"));
        let actual = locked_shape(proof);
        print_shape(label, &actual);
        assert_eq!(actual, seed, "{label} did not land on the frozen profile");
    }
    print_shape("FRI-locked class seed", &seed);

    let mut predecessor = two;
    let mut predecessor_coins = two_outputs;
    let mut owner_tags = [0x66_u8, 0x68_u8];
    let mut iteration = 0usize;

    let closed = iterate_profile_closure(
        seed,
        |profile| {
            let actual = locked_shape(&predecessor);
            if &actual != profile {
                let mut trace_profile = profile.clone();
                trace_profile.fri = None;
                install_d5_profile_spike(trace_profile).map_err(|error| {
                    format!("iteration {iteration}: lift profile install failed: {error}")
                })?;
                let (lifted, lifted_outputs, lifted_owner_tags) = prove_two_input_successor(
                    &predecessor,
                    &predecessor_coins,
                    owner_tags,
                    iteration,
                )
                .map_err(|error| {
                    format!("iteration {iteration}: predecessor lift failed: {error}")
                })?;
                verify_coin_proof(&lifted.statement, &lifted).map_err(|error| {
                    format!("iteration {iteration}: lifted proof verification failed: {error}")
                })?;
                if locked_shape(&lifted) != *profile {
                    return Err(format!(
                        "iteration {iteration}: lifted predecessor did not realize the grown profile"
                    ));
                }
                predecessor = lifted;
                predecessor_coins = lifted_outputs;
                owner_tags = lifted_owner_tags;
                iteration += 1;
            }

            clear_d5_profile_spike().map_err(|error| {
                format!("iteration {iteration}: disable measurement padding failed: {error}")
            })?;
            let (measured, _, _) = prove_two_input_successor(
                &predecessor,
                &predecessor_coins,
                owner_tags,
                iteration,
            )
            .map_err(|error| format!("iteration {iteration}: wrapper measure failed: {error}"))?;
            verify_coin_proof(&measured.statement, &measured)
                .map_err(|error| format!("iteration {iteration}: native verify failed: {error}"))?;
            let measured_shape = locked_shape(&measured);
            print_shape(
                &format!("wrapper measurement {iteration}"),
                &measured_shape,
            );
            Ok::<_, String>(measured_shape)
        },
        MAX_CLOSURE_ITERS,
    )
    .expect("the normalized two-input wrapper recurrence must close");
    print_shape("closed profile", &closed);

    let mut closed_trace_profile = closed.clone();
    closed_trace_profile.fri = None;
    install_d5_profile_spike(closed_trace_profile).expect("install closed wrapper profile");
    let (closed_proof, closed_outputs, closed_owner_tags) =
        prove_two_input_successor(&predecessor, &predecessor_coins, owner_tags, iteration)
            .expect("prove concrete closed-profile wrapper");
    verify_coin_proof(&closed_proof.statement, &closed_proof)
        .expect("closed-profile wrapper native verification");
    predecessor = closed_proof;
    predecessor_coins = closed_outputs;
    owner_tags = closed_owner_tags;
    assert_eq!(
        locked_shape(&predecessor),
        closed,
        "the final concrete wrapper must exactly realize the closed profile"
    );

    let closed_degrees: Vec<_> = closed
        .instances
        .iter()
        .map(|instance| instance.degree_bits)
        .collect();
    let max_degree = closed_degrees.iter().copied().max().unwrap_or(usize::MAX);
    assert!(
        max_degree < 19,
        "closed profile reaches degree {max_degree}; degree 19 is outside the deployment floor"
    );

    let security = proof_security_report(&predecessor);
    println!(
        "closed security: proven={} adjusted={} union={} degrees={:?}",
        security.proven_bits,
        security.union_adjusted_bits,
        security.union_bound_bits,
        security.degree_bits,
    );
    assert!(
        security.union_adjusted_bits >= PRODUCTION_SECURITY_TARGET_BITS,
        "closed profile has {} adjusted bits; {} required",
        security.union_adjusted_bits,
        PRODUCTION_SECURITY_TARGET_BITS,
    );

    let _ = (predecessor_coins, owner_tags);
}
