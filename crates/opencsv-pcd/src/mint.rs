//! Mint predicate circuit (paper §4.4, stage 2 — still non-recursive).
//!
//! Proves, with public statement `x = (asset_id, V, mint_commit)`:
//!
//! 1. each output commitment recomputes:
//!    `C_i = H("coin" ∥ asset_id ∥ v_i ∥ owner_i ∥ r_i)` (as in the opening
//!    circuit);
//! 2. each output value is in range `0 ≤ v_i < 2^64` (limb decomposition);
//! 3. `Σ v_i = V` with exact u64 arithmetic (a sum overflowing `u64` fails
//!    proving);
//! 4. `mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce)`, matching
//!    [`opencsv_core::mint_commit`].
//!
//! **Deviation from the paper:** issuer authorization (§4.4 item 1 — the
//! Ed25519 signature over `(asset_id, V, mint_nonce)`, with `ipk` bound to
//! `asset_id` through genesis) stays OFF-circuit, verified by
//! `opencsv-core`'s accept driver; the paper names an AIR-native signature
//! as the production target.
//!
//! The output commitments are recomputed in-circuit from the witness
//! openings but are not public inputs (matching the paper's public
//! statement); they are carried in [`MintProof`] for the consignment and
//! will be chained to successor proofs at the recursion stage (stage 3).

use opencsv_core::{mint_commit, AssetId, Coin, Commitment, Digest};
use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear};
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, CircuitError, ExprId};
use p3_circuit_prover::batch_stark_prover::{BatchStarkProof, BatchStarkProverError};
use p3_circuit_prover::config::{baby_bear, BabyBearConfig};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::hash::{coin_commitment_limbs, connect_digest, hash_felts_limbs};
use crate::prove::{new_prover, setup, Setup};
use crate::value::{enforce_sum_eq, range_check_value, u64_to_felts, VALUE_LIMBS};
use crate::{DIGEST_ELEMS, EF};

/// Number of mint outputs this circuit supports.
pub const MINT_OUTPUTS: usize = 2;

/// Number of public inputs: asset_id (8) + `V` limbs (3) + mint_commit (8).
pub const MINT_PUBLIC_ELEMS: usize = 2 * DIGEST_ELEMS + VALUE_LIMBS; // 19

/// Number of private witness elements: mint_nonce (8) + per output
/// v (3) + owner (8) + r (8).
pub const MINT_PRIVATE_ELEMS: usize =
    DIGEST_ELEMS + MINT_OUTPUTS * (VALUE_LIMBS + 2 * DIGEST_ELEMS); // 46

/// The public statement of a mint (paper §4.4: `x = (asset_id, V, mint_commit)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintStatement {
    /// Asset being minted.
    pub asset_id: AssetId,
    /// Total minted value `V = Σ v_i`.
    pub value: u64,
    /// `H("mint" ∥ asset_id ∥ V ∥ mint_nonce)`, binding the mint nonce.
    pub mint_commit: Digest,
}

/// A proof that a mint satisfies the mint predicate.
pub struct MintProof {
    /// The public statement the circuit proved (carried in the proof, not
    /// yet cryptographically bound — see the crate-level limitation).
    pub statement: MintStatement,
    /// Commitments of the created coins, recomputed in-circuit from the
    /// witness openings; carried for the consignment.
    pub output_commitments: [Commitment; MINT_OUTPUTS],
    /// The batch-STARK proof over the circuit's tables.
    pub proof: BatchStarkProof<BabyBearConfig>,
}

/// Errors from proving or verifying a mint.
#[derive(Debug)]
pub enum MintError {
    /// Not all output coins are denominated in the stated asset.
    AssetMismatch,
    /// The output values sum to more than `u64::MAX`.
    ValueOverflow,
    /// Circuit construction failed.
    Builder(CircuitBuilderError),
    /// Witness generation / circuit execution failed (e.g. the values do not
    /// sum to `V`, or `mint_commit` does not match the witness nonce).
    Circuit(CircuitError),
    /// STARK proving or verification failed.
    Prover(BatchStarkProverError),
    /// The statement embedded in the proof does not match the expected one.
    StatementMismatch,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AssetMismatch => write!(f, "output coin asset does not match the stated asset"),
            Self::ValueOverflow => write!(f, "output values overflow u64"),
            Self::Builder(e) => write!(f, "circuit build error: {e}"),
            Self::Circuit(e) => write!(f, "circuit execution error: {e}"),
            Self::Prover(e) => write!(f, "STARK prover error: {e}"),
            Self::StatementMismatch => {
                write!(f, "proof statement does not match the expected public data")
            }
        }
    }
}

impl std::error::Error for MintError {}

impl From<CircuitBuilderError> for MintError {
    fn from(e: CircuitBuilderError) -> Self {
        Self::Builder(e)
    }
}

impl From<CircuitError> for MintError {
    fn from(e: CircuitError) -> Self {
        Self::Circuit(e)
    }
}

impl From<BatchStarkProverError> for MintError {
    fn from(e: BatchStarkProverError) -> Self {
        Self::Prover(e)
    }
}

/// Witness layout within the private input vector.
struct WitnessLayout<'a> {
    mint_nonce: &'a [ExprId],
    /// Per output: `(v limbs, owner, randomness)`.
    outputs: [(&'a [ExprId], &'a [ExprId], &'a [ExprId]); MINT_OUTPUTS],
}

/// Slice the private input vector into `mint_nonce` and per-output
/// `(v, owner, r)` parts, in allocation order.
fn witness_layout(private: &[ExprId]) -> WitnessLayout<'_> {
    const OUT_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS; // 19
    let mint_nonce = &private[0..DIGEST_ELEMS];
    let outputs = std::array::from_fn(|i| {
        let s = DIGEST_ELEMS + i * OUT_ELEMS;
        (
            &private[s..s + VALUE_LIMBS],
            &private[s + VALUE_LIMBS..s + VALUE_LIMBS + DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + DIGEST_ELEMS..s + OUT_ELEMS],
        )
    });
    WitnessLayout {
        mint_nonce,
        outputs,
    }
}

/// Build the mint circuit (see module docs for the constraints).
fn build_circuit() -> Result<Circuit<EF>, MintError> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<EF, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);

    let public = builder.alloc_public_inputs(MINT_PUBLIC_ELEMS, "mint_statement");
    let asset_id = &public[0..DIGEST_ELEMS];
    let value_total = &public[DIGEST_ELEMS..DIGEST_ELEMS + VALUE_LIMBS];
    let mint_commit = &public[DIGEST_ELEMS + VALUE_LIMBS..MINT_PUBLIC_ELEMS];

    let private = builder.alloc_private_inputs(MINT_PRIVATE_ELEMS, "mint_witness");
    let witness = witness_layout(&private);

    // (b) values in range: the public total and every output value.
    let v_total: [ExprId; VALUE_LIMBS] = value_total.try_into().expect("V has 3 limbs");
    range_check_value(&mut builder, &v_total)?;
    let mut out_values = [[ExprId::ZERO; VALUE_LIMBS]; MINT_OUTPUTS];
    for (i, out_value) in out_values.iter_mut().enumerate() {
        *out_value = witness.outputs[i].0.try_into().expect("v has 3 limbs");
        range_check_value(&mut builder, out_value)?;
    }

    // (c) Σ v_i = V, exact u64 arithmetic (overflow fails proving).
    let zero = [ExprId::ZERO; VALUE_LIMBS];
    enforce_sum_eq(
        &mut builder,
        [&out_values[0], &out_values[1]],
        [&v_total, &zero],
    )?;

    // (a) each output commitment recomputes from its witness opening.
    for &(v, owner, r) in &witness.outputs {
        let _ = coin_commitment_limbs(&mut builder, asset_id, v, owner, r)?;
    }

    // (d) mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce).
    let mc = hash_felts_limbs(
        &mut builder,
        "mint",
        &[asset_id, value_total, witness.mint_nonce],
    )?;
    connect_digest(&mut builder, mc, mint_commit)?;

    Ok(builder.build()?)
}

/// Build the circuit and the prover-side data.
fn circuit_setup() -> Result<Setup, MintError> {
    Ok(setup(build_circuit()?)?)
}

/// Prove the mint predicate for `outputs` created under `asset_id`.
///
/// `V = Σ v_i` is computed with overflow checking and
/// `mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce)` is computed via
/// [`opencsv_core::mint_commit`]; the circuit then proves items (a)–(d) from
/// the module docs. The issuer signature is *not* part of this circuit (see
/// the deviation note in the module docs).
pub fn prove_mint(
    asset_id: &AssetId,
    mint_nonce: &Digest,
    outputs: &[Coin; MINT_OUTPUTS],
) -> Result<MintProof, MintError> {
    if outputs.iter().any(|c| c.asset_id != *asset_id) {
        return Err(MintError::AssetMismatch);
    }
    let mut value = 0u64;
    for c in outputs {
        value = value.checked_add(c.value).ok_or(MintError::ValueOverflow)?;
    }
    let mc = mint_commit(asset_id, value, mint_nonce);
    prove_mint_raw(asset_id, value, &mc, mint_nonce, outputs)
}

/// Prove the mint predicate with explicit public data (low-level entry
/// point).
///
/// Unlike [`prove_mint`], the minted total and the mint commitment are
/// supplied by the caller; proving fails with [`MintError::Circuit`] if
/// `value ≠ Σ v_i` or `mint_commit ≠ H("mint" ∥ asset_id ∥ value ∥
/// mint_nonce)`. Exposed for negative tests and for later stages.
#[doc(hidden)]
pub fn prove_mint_raw(
    asset_id: &AssetId,
    value: u64,
    mc: &Digest,
    mint_nonce: &Digest,
    outputs: &[Coin; MINT_OUTPUTS],
) -> Result<MintProof, MintError> {
    let mut public_values = Vec::with_capacity(MINT_PUBLIC_ELEMS);
    public_values.extend(asset_id.to_elems().iter().map(|&x| EF::from(x)));
    public_values.extend(u64_to_felts(value).iter().map(|&x| EF::from(x)));
    public_values.extend(mc.to_elems().iter().map(|&x| EF::from(x)));

    let mut private_values = Vec::with_capacity(MINT_PRIVATE_ELEMS);
    private_values.extend(mint_nonce.to_elems().iter().map(|&x| EF::from(x)));
    for c in outputs {
        private_values.extend(u64_to_felts(c.value).iter().map(|&x| EF::from(x)));
        private_values.extend(c.owner.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(c.randomness.to_elems().iter().map(|&x| EF::from(x)));
    }

    let s = circuit_setup()?;
    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&public_values)?;
    runner.set_private_inputs(&private_values)?;
    let traces = runner.run()?;

    let prover = new_prover(s.stark_config, s.table_packing);
    let proof = prover.prove_all_tables(&traces, &s.circuit_prover_data)?;

    Ok(MintProof {
        statement: MintStatement {
            asset_id: *asset_id,
            value,
            mint_commit: *mc,
        },
        output_commitments: [outputs[0].commitment(), outputs[1].commitment()],
        proof,
    })
}

/// Verify a mint proof against the expected public statement.
///
/// Checks that the statement embedded in the proof equals `expected`, then
/// verifies the batch-STARK proof.
///
/// Note: at the pinned upstream commit the standalone verifier proves
/// satisfiability of the circuit for *some* public inputs; the statement
/// carried in [`MintProof`] is the value the prover used, compared here for
/// equality. Cryptographic binding of the public inputs arrives with the
/// recursion stage (see crate-level docs).
pub fn verify_mint(expected: &MintStatement, mint: &MintProof) -> Result<(), MintError> {
    if *expected != mint.statement {
        return Err(MintError::StatementMismatch);
    }
    let prover = new_prover(baby_bear(), mint.proof.table_packing.clone());
    prover.verify_all_tables::<EF>(&mint.proof)?;
    Ok(())
}
