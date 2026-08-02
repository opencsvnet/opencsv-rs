//! Feasibility spike for stage 3 (not part of the public API): a minimal
//! end-to-end recursion over a toy circuit with a statement table.
//!
//! - spike 1: prove a toy circuit natively and check the statement table's
//!   instance public values land in the proof;
//! - spike 2: verify that proof *in-circuit* (one full recursive layer),
//!   `connect`ing the statement's public-value targets to the expected
//!   constants, then prove and verify the parent natively.

#![cfg(test)]

use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::ConstraintProfile;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use p3_recursion::FriRecursionConfig;

use crate::recursion_config::{
    new_prover, node_table_provers, setup_circuit, CoinFriParams, CoinRecursionConfig,
};
use crate::setup_cache::lock_setup;
use crate::statement::{statement_op_type, StatementCircuitPlugin, StatementProver};
use crate::EF;

const N: usize = 2;

/// Build a toy circuit with a statement of two private inputs.
fn toy_circuit() -> p3_circuit::Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.register_npo(StatementCircuitPlugin::<N>::new());
    let stmt = builder.alloc_private_inputs(N, "statement");
    // Private inputs must be claimed by an ALU op (bus creator), NPO reads
    // alone do not claim them.
    let _sum = builder.add(stmt[0], stmt[1]);
    builder.push_non_primitive_op_with_outputs(
        statement_op_type(),
        vec![stmt],
        vec![],
        None,
        "toy_statement",
    );
    builder.build().expect("toy circuit builds")
}

/// Pack the toy statement as instance public values (base elements: each
/// statement element contributes D = 4 coefficients).
fn toy_public_values(vals: [u32; N]) -> Vec<BabyBear> {
    let mut out = Vec::with_capacity(N * 4);
    for v in vals {
        out.push(BabyBear::new(v));
        out.extend([BabyBear::ZERO; 3]);
    }
    out
}

#[test]
fn spike_statement_table_native() {
    let t0 = Instant::now();
    let fp = CoinFriParams::testing();
    let s = setup_circuit::<N>(toy_circuit(), &fp).expect("setup");

    let vals = [41u32, 99u32];
    let private: Vec<EF> = vals.iter().map(|&v| EF::from(BabyBear::new(v))).collect();
    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&[]).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let traces = runner.run().expect("witness gen");

    let prover = new_prover::<N>(&s.config, s.table_packing.clone());
    let proof = {
        let circuit_prover_data = lock_setup(&s.circuit_prover_data);
        prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .expect("prove")
    };

    // The statement table's instance public values must be the statement.
    let entry = proof
        .non_primitives
        .iter()
        .find(|e| e.op_type == statement_op_type())
        .expect("statement table present");
    assert_eq!(entry.public_values, toy_public_values(vals));

    let verifier = new_prover::<N>(&s.config, s.table_packing.clone());
    verifier
        .verify_all_tables::<EF>(&proof)
        .expect("native verify");
    eprintln!(
        "spike1 native prove+verify OK in {:?}; {} tables",
        t0.elapsed(),
        3 + proof.non_primitives.len()
    );
}

#[test]
fn spike_in_circuit_verification() {
    let fp = CoinFriParams::testing();

    // --- layer 0: prove the toy circuit natively.
    let t0 = Instant::now();
    let s0 = setup_circuit::<N>(toy_circuit(), &fp).expect("setup l0");
    let vals = [41u32, 99u32];
    let private: Vec<EF> = vals.iter().map(|&v| EF::from(BabyBear::new(v))).collect();
    let mut runner0 = s0.circuit.runner();
    runner0.set_public_inputs(&[]).unwrap();
    runner0.set_private_inputs(&private).unwrap();
    let traces0 = runner0.run().expect("witness gen l0");
    let prover0 = new_prover::<N>(&s0.config, s0.table_packing.clone());
    let proof0 = {
        let circuit_prover_data = lock_setup(&s0.circuit_prover_data);
        prover0
            .prove_all_tables(&traces0, &circuit_prover_data)
            .expect("prove l0")
    };
    eprintln!("spike2 layer0 prove: {:?}", t0.elapsed());

    // --- layer 1: build the parent circuit verifying layer 0 in-circuit.
    let t1 = Instant::now();
    let config = CoinRecursionConfig::new(&fp);
    // Use the effective common data carried in the proof (lane reduction
    // during proving may rebuild it).
    let common_data = &proof0.stark_common;
    let mut builder = CircuitBuilder::<EF>::new();
    config
        .prepare_circuit_for_verification(&mut builder)
        .expect("prepare");
    let lookup_gadget = p3_lookup::logup::LogUpGadget::new();
    let table_provers: Vec<
        Box<dyn p3_circuit_prover::batch_stark_prover::TableProver<CoinRecursionConfig>>,
    > = vec![Box::new(StatementProver::<4, N>::new())];
    let (verifier_inputs, op_ids) = verify_p3_batch_proof_circuit::<
        CoinRecursionConfig,
        <CoinRecursionConfig as FriRecursionConfig>::Commitment,
        <CoinRecursionConfig as FriRecursionConfig>::InputProof,
        <CoinRecursionConfig as FriRecursionConfig>::OpeningProof,
        _,
        _,
        16,
        8,
        4,
    >(
        &config,
        &mut builder,
        &proof0,
        config.pcs_verifier_params(),
        common_data,
        &lookup_gadget,
        p3_recursion::Poseidon2Config::BABY_BEAR_D4_W16,
        &table_provers,
    )
    .expect("verifier circuit");

    // The statement instance is the 4th table (Const, Public, Alu, Statement):
    // connect its public-value targets to the expected statement.
    let stmt_targets = &verifier_inputs.air_public_targets[3];
    assert_eq!(stmt_targets.len(), N * 4);
    for (i, &t) in stmt_targets.iter().enumerate() {
        if i % 4 != 0 {
            // Zero-valued public-input targets: do NOT connect them to the
            // pooled zero constant — the Public table and the Const table
            // would both send the pooled slot with full multiplicity and
            // unbalance the WitnessChecks bus (verified empirically at this
            // pin). The nonzero case below exercises the chaining channel.
            continue;
        }
        let c = builder.alloc_const(EF::from(BabyBear::new(vals[i / 4])), "expected_statement");
        let d = builder.sub(t, c);
        builder.assert_zero(d);
    }
    let parent_circuit = builder.build().expect("parent circuit builds");
    eprintln!(
        "spike2 parent circuit build: {:?}; witness_count = {}",
        t1.elapsed(),
        parent_circuit.witness_count
    );

    // --- layer 1: pack inputs and prove the parent natively.
    let t2 = Instant::now();
    let s1 = setup_circuit::<N>(parent_circuit, &fp).expect("setup l1");
    let table_pvs: Vec<Vec<BabyBear>> = vec![vec![], vec![], vec![], toy_public_values(vals)];
    let public_inputs = verifier_inputs.pack_public_values(&table_pvs, &proof0.proof, &common_data);
    let private_inputs = verifier_inputs.pack_private_values(&proof0.proof);
    eprintln!(
        "spike2 parent public inputs: {}, private inputs: {}",
        public_inputs.len(),
        private_inputs.len()
    );

    let mut runner1 = s1.circuit.runner();
    runner1
        .set_public_inputs(&public_inputs)
        .expect("set public");
    runner1
        .set_private_inputs(&private_inputs)
        .expect("set private");
    CoinRecursionConfig::set_fri_private_data(&mut runner1, &op_ids, &proof0.proof.opening_proof)
        .expect("fri private data");
    let traces1 = runner1.run().expect("witness gen l1");
    eprintln!("spike2 parent witness gen: {:?}", t2.elapsed());

    let t3 = Instant::now();
    let prover1 = new_prover::<N>(&s1.config, s1.table_packing.clone());
    let proof1 = {
        let circuit_prover_data = lock_setup(&s1.circuit_prover_data);
        prover1
            .prove_all_tables(&traces1, &circuit_prover_data)
            .expect("prove l1")
    };
    eprintln!("spike2 parent prove: {:?}", t3.elapsed());

    let t4 = Instant::now();
    let verifier1 = new_prover::<N>(&s1.config, s1.table_packing.clone());
    verifier1
        .verify_all_tables::<EF>(&proof1)
        .expect("verify l1");
    eprintln!(
        "spike2 parent verify: {:?} (total {:?})",
        t4.elapsed(),
        t0.elapsed()
    );
}

#[allow(unused_imports)]
use node_table_provers as _node_table_provers_unused;
/// Silence unused-import warnings for helpers used only by later stages.
#[allow(unused_imports)]
use p3_circuit_prover::batch_stark_prover::TableProver as _TableProverUnused;
#[allow(unused_imports)]
use ConstraintProfile as _CpUnused;
#[allow(unused_imports)]
use PrimeField64 as _Pf64Unused;
