//! Transfer predicate circuit (paper §4.5, stage 2 — still non-recursive).
//!
//! **Restriction:** a single asset per transfer — all input and output coins
//! share one `asset_id`, which is public (paper §4.5 groups by `asset_id`
//! and hides transferred asset IDs; supporting that needs per-coin asset
//! witnesses plus per-asset conservation, left for later stages).
//!
//! Proves, with public statement `x = (asset_id, nf_1, nf_2)`:
//!
//! 1. each input commitment recomputes:
//!    `C_i = H("coin" ∥ asset_id ∥ v_i ∥ owner_i ∥ r_i)`;
//! 2. ownership: knowledge of `osk_i` with `owner_i = H(osk_i)` — exactly
//!    [`opencsv_core::OwnerSecret::owner`] semantics (no domain tag, the
//!    secret absorbed as 3-byte-chunk field elements);
//! 3. nullifiers: `nf_i = H("null" ∥ osk_i ∥ C_i)`, matching
//!    [`opencsv_core::coin::nullifier`];
//! 4. all values in range `0 ≤ v < 2^64` (limb decomposition);
//! 5. conservation: `v_in_1 + v_in_2 = v_out_1 + v_out_2` with exact u64
//!    arithmetic (wrap-around fails proving);
//! 6. each output commitment recomputes.
//!
//! The output commitments are recomputed in-circuit from the witness
//! openings but are not public inputs; they are carried in
//! [`TransferProof`] for the consignment and will be chained to successor
//! proofs at the recursion stage (stage 3). Item 4 of paper §4.5 (PCD
//! recursion over predecessor proofs) is also stage 3.

use opencsv_core::{AssetId, Coin, Commitment, Nullifier, OwnerSecret};
use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear};
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, CircuitError, ExprId};
use p3_circuit_prover::batch_stark_prover::{BatchStarkProof, BatchStarkProverError};
use p3_circuit_prover::config::{baby_bear, BabyBearConfig};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::hash::{
    coin_commitment_base, coin_commitment_limbs, connect_digest, hash_felts_limbs, osk_felts,
    OSK_ELEMS,
};
use crate::prove::{new_prover, setup, Setup};
use crate::setup_cache::lock_setup;
use crate::value::{enforce_sum_eq, range_check_value, u64_to_felts, VALUE_LIMBS};
use crate::{DIGEST_ELEMS, EF};

/// Number of transfer inputs this circuit supports.
pub const TRANSFER_INPUTS: usize = 2;
/// Number of transfer outputs this circuit supports.
pub const TRANSFER_OUTPUTS: usize = 2;

/// Number of public inputs: asset_id (8) + nf_1 (8) + nf_2 (8).
pub const TRANSFER_PUBLIC_ELEMS: usize = 3 * DIGEST_ELEMS; // 24

/// Number of private witness elements: per input v (3) + owner (8) + r (8) +
/// osk (11); per output v (3) + owner (8) + r (8).
pub const TRANSFER_PRIVATE_ELEMS: usize = TRANSFER_INPUTS
    * (VALUE_LIMBS + 2 * DIGEST_ELEMS + OSK_ELEMS)
    + TRANSFER_OUTPUTS * (VALUE_LIMBS + 2 * DIGEST_ELEMS); // 98

/// The public statement of a transfer: the (single) asset and the consumed
/// coins' nullifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferStatement {
    /// Asset all coins in this transfer are denominated in.
    pub asset_id: AssetId,
    /// Nullifiers of the consumed coins, one per input.
    pub nullifiers: [Nullifier; TRANSFER_INPUTS],
}

/// A proof that a transfer satisfies the transfer predicate.
pub struct TransferProof {
    /// The public statement the circuit proved (carried in the proof, not
    /// yet cryptographically bound — see the crate-level limitation).
    pub statement: TransferStatement,
    /// Commitments of the created coins, recomputed in-circuit from the
    /// witness openings; carried for the consignment.
    pub output_commitments: [Commitment; TRANSFER_OUTPUTS],
    /// The batch-STARK proof over the circuit's tables.
    pub proof: BatchStarkProof<BabyBearConfig>,
}

/// Errors from proving or verifying a transfer.
#[derive(Debug)]
pub enum TransferError {
    /// Not all coins are denominated in the stated asset.
    AssetMismatch,
    /// The same coin or nullifier was supplied in more than one input slot.
    DuplicateInput,
    /// Circuit construction failed.
    Builder(CircuitBuilderError),
    /// Witness generation / circuit execution failed (e.g. unbalanced
    /// values, a wrong owner secret, or nullifiers that do not match).
    Circuit(CircuitError),
    /// STARK proving or verification failed.
    Prover(BatchStarkProverError),
    /// The statement embedded in the proof does not match the expected one.
    StatementMismatch,
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AssetMismatch => write!(f, "coin asset does not match the stated asset"),
            Self::DuplicateInput => write!(f, "transfer input coin is duplicated"),
            Self::Builder(e) => write!(f, "circuit build error: {e}"),
            Self::Circuit(e) => write!(f, "circuit execution error: {e}"),
            Self::Prover(e) => write!(f, "STARK prover error: {e}"),
            Self::StatementMismatch => {
                write!(f, "proof statement does not match the expected public data")
            }
        }
    }
}

impl std::error::Error for TransferError {}

impl From<CircuitBuilderError> for TransferError {
    fn from(e: CircuitBuilderError) -> Self {
        Self::Builder(e)
    }
}

impl From<CircuitError> for TransferError {
    fn from(e: CircuitError) -> Self {
        Self::Circuit(e)
    }
}

impl From<BatchStarkProverError> for TransferError {
    fn from(e: BatchStarkProverError) -> Self {
        Self::Prover(e)
    }
}

/// Witness layout within the private input vector.
struct WitnessLayout<'a> {
    /// Per input: `(v limbs, owner, randomness, osk)`.
    inputs: [(&'a [ExprId], &'a [ExprId], &'a [ExprId], &'a [ExprId]); TRANSFER_INPUTS],
    /// Per output: `(v limbs, owner, randomness)`.
    outputs: [(&'a [ExprId], &'a [ExprId], &'a [ExprId]); TRANSFER_OUTPUTS],
}

/// Slice the private input vector into per-input `(v, owner, r, osk)` and
/// per-output `(v, owner, r)` parts, in allocation order.
fn witness_layout(private: &[ExprId]) -> WitnessLayout<'_> {
    const IN_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS + OSK_ELEMS; // 30
    const OUT_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS; // 19
    let inputs = std::array::from_fn(|i| {
        let s = i * IN_ELEMS;
        (
            &private[s..s + VALUE_LIMBS],
            &private[s + VALUE_LIMBS..s + VALUE_LIMBS + DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + DIGEST_ELEMS..s + VALUE_LIMBS + 2 * DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + 2 * DIGEST_ELEMS..s + IN_ELEMS],
        )
    });
    let outputs = std::array::from_fn(|j| {
        let s = TRANSFER_INPUTS * IN_ELEMS + j * OUT_ELEMS;
        (
            &private[s..s + VALUE_LIMBS],
            &private[s + VALUE_LIMBS..s + VALUE_LIMBS + DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + DIGEST_ELEMS..s + OUT_ELEMS],
        )
    });
    WitnessLayout { inputs, outputs }
}

/// Build the transfer circuit (see module docs for the constraints).
fn build_circuit() -> Result<Circuit<EF>, TransferError> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<EF, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);

    let public = builder.alloc_public_inputs(TRANSFER_PUBLIC_ELEMS, "transfer_statement");
    let asset_id = &public[0..DIGEST_ELEMS];
    let nf_public: [&[ExprId]; TRANSFER_INPUTS] = [
        &public[DIGEST_ELEMS..2 * DIGEST_ELEMS],
        &public[2 * DIGEST_ELEMS..3 * DIGEST_ELEMS],
    ];

    let private = builder.alloc_private_inputs(TRANSFER_PRIVATE_ELEMS, "transfer_witness");
    let witness = witness_layout(&private);

    let mut in_values = [[ExprId::ZERO; VALUE_LIMBS]; TRANSFER_INPUTS];
    for (i, in_value) in in_values.iter_mut().enumerate() {
        let (v, owner, r, osk) = witness.inputs[i];
        *in_value = v.try_into().expect("v has 3 limbs");

        // (d) input value in range.
        range_check_value(&mut builder, in_value)?;

        // (a) input commitment recomputes from its witness opening.
        let commitment = coin_commitment_base(&mut builder, asset_id, v, owner, r)?;

        // (b) ownership: owner_i = H(osk_i) (no domain tag, mirroring
        // `OwnerSecret::owner`).
        let own = hash_felts_limbs(&mut builder, "", &[osk])?;
        connect_digest(&mut builder, own, owner)?;

        // (c) nullifier: nf_i = H("null" ∥ osk_i ∥ C_i), connected to the
        // public nullifier.
        let nf = hash_felts_limbs(&mut builder, "null", &[osk, &commitment])?;
        connect_digest(&mut builder, nf, nf_public[i])?;
    }

    let mut out_values = [[ExprId::ZERO; VALUE_LIMBS]; TRANSFER_OUTPUTS];
    for (j, out_value) in out_values.iter_mut().enumerate() {
        let (v, owner, r) = witness.outputs[j];
        *out_value = v.try_into().expect("v has 3 limbs");

        // (d) output value in range.
        range_check_value(&mut builder, out_value)?;

        // (f) output commitment recomputes from its witness opening.
        let _ = coin_commitment_limbs(&mut builder, asset_id, v, owner, r)?;
    }

    // (e) conservation: Σ v_in = Σ v_out, exact u64 arithmetic.
    enforce_sum_eq(
        &mut builder,
        [&in_values[0], &in_values[1]],
        [&out_values[0], &out_values[1]],
    )?;

    Ok(builder.build()?)
}

/// Build the circuit and the prover-side data.
fn circuit_setup() -> Result<Setup, TransferError> {
    Ok(setup(build_circuit()?)?)
}

/// Prove the transfer predicate consuming `inputs` and creating `outputs`,
/// all denominated in `asset_id`.
///
/// Each input is paired with its owner's secret; the nullifiers are computed
/// via [`opencsv_core::coin::nullifier`] and the circuit proves items
/// (a)–(f) from the module docs.
pub fn prove_transfer(
    asset_id: &AssetId,
    inputs: &[(Coin, OwnerSecret); TRANSFER_INPUTS],
    outputs: &[Coin; TRANSFER_OUTPUTS],
) -> Result<TransferProof, TransferError> {
    if inputs.iter().any(|(c, _)| c.asset_id != *asset_id)
        || outputs.iter().any(|c| c.asset_id != *asset_id)
    {
        return Err(TransferError::AssetMismatch);
    }
    if inputs[0].0.commitment() == inputs[1].0.commitment() {
        return Err(TransferError::DuplicateInput);
    }
    let nullifiers = std::array::from_fn(|i| {
        let (coin, osk) = &inputs[i];
        opencsv_core::coin::nullifier(osk, &coin.commitment())
    });
    if nullifiers[0] == nullifiers[1] {
        return Err(TransferError::DuplicateInput);
    }

    let mut public_values = Vec::with_capacity(TRANSFER_PUBLIC_ELEMS);
    public_values.extend(asset_id.to_elems().iter().map(|&x| EF::from(x)));
    for nf in &nullifiers {
        public_values.extend(nf.to_elems().iter().map(|&x| EF::from(x)));
    }

    let mut private_values = Vec::with_capacity(TRANSFER_PRIVATE_ELEMS);
    for (coin, osk) in inputs {
        private_values.extend(u64_to_felts(coin.value).iter().map(|&x| EF::from(x)));
        private_values.extend(coin.owner.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(coin.randomness.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(osk_felts(osk).iter().map(|&x| EF::from(x)));
    }
    for coin in outputs {
        private_values.extend(u64_to_felts(coin.value).iter().map(|&x| EF::from(x)));
        private_values.extend(coin.owner.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(coin.randomness.to_elems().iter().map(|&x| EF::from(x)));
    }

    let s = circuit_setup()?;
    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&public_values)?;
    runner.set_private_inputs(&private_values)?;
    let traces = runner.run()?;

    let prover = new_prover(s.stark_config, s.table_packing);
    let circuit_prover_data = lock_setup(&s.circuit_prover_data);
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data)?;

    Ok(TransferProof {
        statement: TransferStatement {
            asset_id: *asset_id,
            nullifiers,
        },
        output_commitments: [outputs[0].commitment(), outputs[1].commitment()],
        proof,
    })
}

/// Verify a transfer proof against the expected public statement.
///
/// Checks that the statement embedded in the proof equals `expected`, then
/// verifies the batch-STARK proof.
///
/// Note: at the pinned upstream commit the standalone verifier proves
/// satisfiability of the circuit for *some* public inputs; the statement
/// carried in [`TransferProof`] is the value the prover used, compared here
/// for equality. Cryptographic binding of the public inputs arrives with the
/// recursion stage (see crate-level docs).
pub fn verify_transfer(
    expected: &TransferStatement,
    transfer: &TransferProof,
) -> Result<(), TransferError> {
    if *expected != transfer.statement {
        return Err(TransferError::StatementMismatch);
    }
    let prover = new_prover(baby_bear(), transfer.proof.table_packing.clone());
    prover.verify_all_tables::<EF>(&transfer.proof)?;
    Ok(())
}
