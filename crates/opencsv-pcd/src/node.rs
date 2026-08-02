//! Stage 3: PCD recursion — the "coin proof" node circuit (paper §4.5 item 4).
//!
//! # Architecture (two circuits — see below for why not one)
//!
//! - **Mint circuit** (genesis): the stage-2 mint predicate plus a statement
//!   table ([`crate::statement`]). No predecessor verification.
//! - **Node (transfer) circuit**: the stage-2 transfer predicate plus a
//!   statement table plus **two in-circuit batch-STARK verifications** of the
//!   predecessor proofs (one per consumed coin), built per proof from the
//!   predecessors' metadata (the upstream `prove_next_layer` pattern).
//!   A predecessor may be a mint proof or another node proof — the verifier
//!   sub-circuits are shape-driven, so both work, and every ancestor's
//!   statement is bound through the same statement-table channel.
//!
//! # Why not one unified circuit with a mode selector
//!
//! The stage-2 recommendation was a single unified circuit (mint = degenerate
//! transfer). At this pin that cannot bootstrap: the unified circuit must
//! *genuinely* verify 2 predecessors of the same shape in every mode (the
//! circuit shape is fixed, and a STARK verification cannot be masked off by a
//! selector), so a MINT node would also need 2 valid predecessor proofs of
//! the same circuit — a circular witness dependency with no base case. The
//! standard escape (a trivial "void" vk whose proofs are verified in MINT
//! mode) still needs the void circuit's table metadata to match the unified
//! circuit's exactly — strictly more machinery than simply keeping the
//! stage-2 mint circuit as the base case (the task's fallback (i)). We
//! therefore ship two circuits; the statement layout and the statement-table
//! binding are shared, so the vk *set* is just `{mint_vk, node_vk(per
//! predecessor-shape variant)}`.
//!
//! # Chaining (paper §4.5 item 4)
//!
//! Each circuit exposes its statement as STARK instance public values of a
//! dedicated statement table (see [`crate::statement`]):
//!
//! ```text
//! [version(1) | mode(1) | asset_id(8) | V(3) | mint_commit(8) | nf_1(8) |
//!  nf_2(8) | out_1(8) | out_2(8)]                         (53 elements)
//! ```
//!
//! `mode` is `1` for mints, `0` for transfers, `2` for redeems (stage 4,
//! paper §4.6). The **redeem circuit** consumes one coin and burns it: the
//! input commitment recomputes, ownership `owner = H(osk)` holds, the
//! nullifier `nf_1 = H("null" ∥ osk ∥ C)` is exposed, and the coin's
//! committed value equals the public `V` (the statement's value limbs *are*
//! the coin's witness value limbs). `mint_commit`, `nf_2` and both outputs
//! are zero. It verifies **one** predecessor proof in-circuit (the coin's
//! ancestry, mint or node) with the same chaining constraints as the node
//! circuit — a separate circuit, not the node circuit with `N_IN = 1`,
//! because the circuit shape is fixed by the number of in-circuit verifier
//! sub-circuits, and a redeem needs exactly one.
//!
//! The node circuit's in-circuit verifier allocates the predecessor's
//! statement public values as targets; the node circuit enforces, for each
//! input `i`, that the predecessor's `asset_id` equals this node's asset and
//! that `select(k_i, out_1, out_0)` equals the recomputed input commitment
//! `C_i` (`k_i` a boolean witness). This is what chains the PCD: the
//! predecessor's statement is transcript-bound (statement table), tied to its
//! computation (AIR + witness bus), and connected to the successor's
//! recomputed commitments.
//!
//! # Verification-key binding (honest)
//!
//! Every predecessor verifier's preprocessed commitment is constrained to
//! the key selected when the parent circuit is built. The proof-carried
//! `stark_common` is therefore a witness for that fixed key, not authority to
//! substitute a different predecessor circuit. The narrow upstream accessor
//! needed for this constraint is pinned with the other recursion sources; see
//! `README.md`.
//!
//! The *root* remains a separate trust boundary: [`verify_coin_proof`]
//! natively verifies the self-described root proof. Production callers must
//! allowlist the accepted root circuit/version rather than treating recursive
//! predecessor binding as root-key authorization.

use opencsv_core::{
    mint_commit, AssetGenesis, AssetId, Coin, Commitment, Digest, Nullifier, OwnerSecret,
    PoseidonIssuerAuthorization,
};
use p3_baby_bear::BabyBear;
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, NpoTypeId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProof, BatchStarkProverError, NUM_PRIMITIVE_TABLES,
};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::public_inputs::BatchStarkVerifierInputsBuilder;
use p3_recursion::verifier::{verify_p3_batch_proof_circuit, VerificationError};
use p3_recursion::{FriRecursionConfig, ObservableCommitment, Poseidon2Config, Recursive};
use serde::{Deserialize, Serialize};

use crate::hash::{coin_commitment_base, connect_digest, hash_felts_base, hash_felts_limbs};
use crate::issuer::{
    enforce_authorization, witness_layout as issuer_witness_layout, witness_values, IssuerWitness,
    ISSUER_AUTH_ELEMS,
};
use crate::recursion_config::{
    new_prover, node_table_provers, setup_circuit, setup_circuit_with_verification_keys,
    CoinFriParams, CoinRecursionConfig, RecSetup,
};
use crate::setup_cache::{lock_setup, SetupIdentity};
use crate::statement::{statement_op_type, StatementCircuitPlugin};
use crate::value::{enforce_sum_eq, range_check_value, u64_to_felts, VALUE_LIMBS};
use crate::{DIGEST_ELEMS, EF};

/// Number of node inputs (consumed coins).
pub const NODE_INPUTS: usize = 2;
/// Number of node outputs (created coins).
pub const NODE_OUTPUTS: usize = 2;

/// Proof lineage version carrying in-circuit issuer authorization.
pub const COIN_PROOF_VERSION: u8 = 2;

/// Statement layout, in field elements (see module docs):
/// version (1) + mode (1) + asset_id (8) + V (3) + mint_commit (8) +
/// nullifiers (16) + output commitments (16).
pub const STATEMENT_ELEMS: usize = 2 + 4 * DIGEST_ELEMS + VALUE_LIMBS + 2 * DIGEST_ELEMS; // 53

// Statement element offsets (version and mode occupy elements 0 and 1).
const OFF_ASSET: usize = 2;
const OFF_VALUE: usize = OFF_ASSET + DIGEST_ELEMS; // 10
const OFF_MINT_COMMIT: usize = OFF_VALUE + VALUE_LIMBS; // 13
const OFF_NULLIFIERS: usize = OFF_MINT_COMMIT + DIGEST_ELEMS; // 21
const OFF_OUTPUTS: usize = OFF_NULLIFIERS + NODE_INPUTS * DIGEST_ELEMS; // 37

/// Number of instance public values the statement table carries (D = 4
/// coefficients per statement element).
pub const STATEMENT_PUBLIC_VALUES: usize = 4 * STATEMENT_ELEMS; // 212

/// Private witness elements of the node (transfer) circuit: asset_id (8) +
/// per input (v 3 + owner 8 + r 8 + osk 11) + per output (v 3 + owner 8 +
/// r 8) + per-input predecessor output selector `k_i` (1).
pub const NODE_PRIVATE_ELEMS: usize = DIGEST_ELEMS
    + NODE_INPUTS * (VALUE_LIMBS + 2 * DIGEST_ELEMS + crate::hash::OSK_ELEMS)
    + NODE_OUTPUTS * (VALUE_LIMBS + 2 * DIGEST_ELEMS)
    + NODE_INPUTS; // 108

/// Private witness elements of the mint circuit: asset_id (8) + V (3) +
/// mint_nonce (8) + issuer authorization (23) + per output
/// (v 3 + owner 8 + r 8).
pub const MINT_PRIVATE_ELEMS: usize = 2 * DIGEST_ELEMS
    + VALUE_LIMBS
    + ISSUER_AUTH_ELEMS
    + NODE_OUTPUTS * (VALUE_LIMBS + 2 * DIGEST_ELEMS); // 80

/// Private witness elements of the redeem circuit: asset_id (8) + input coin
/// (v 3 + owner 8 + r 8 + osk 11) + predecessor output selector `k` (1).
pub const REDEEM_PRIVATE_ELEMS: usize =
    DIGEST_ELEMS + (VALUE_LIMBS + 2 * DIGEST_ELEMS + crate::hash::OSK_ELEMS) + 1; // 39

/// The mode of a coin proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeMode {
    /// Genesis mint (no predecessors).
    Mint,
    /// Transfer spending two coins.
    Transfer,
    /// Redeem (burn) of one coin (paper §4.6).
    Redeem,
}

/// The public statement of a coin proof (mirrors the statement-table layout).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatement {
    /// Asset all coins are denominated in.
    pub asset_id: AssetId,
    /// Minted total `V` (0 for transfers).
    pub value: u64,
    /// `H("mint" ∥ asset_id ∥ V ∥ mint_nonce)` (zero for transfers).
    pub mint_commit: Digest,
    /// Nullifiers of the consumed coins (zeros for mints).
    pub nullifiers: [Nullifier; NODE_INPUTS],
    /// Commitments of the created coins.
    pub output_commitments: [Commitment; NODE_OUTPUTS],
}

impl NodeStatement {
    /// Encode as the statement table's instance public values (`4` base
    /// coefficients per statement element, higher coefficients zero).
    pub fn to_public_values(&self, mode: NodeMode) -> Vec<BabyBear> {
        let mut elems = Vec::with_capacity(STATEMENT_ELEMS);
        elems.push(BabyBear::new(COIN_PROOF_VERSION as u32));
        elems.push(match mode {
            NodeMode::Mint => BabyBear::ONE,
            NodeMode::Transfer => BabyBear::ZERO,
            NodeMode::Redeem => BabyBear::new(2),
        });
        elems.extend(self.asset_id.to_elems());
        elems.extend(u64_to_felts(self.value));
        elems.extend(self.mint_commit.to_elems());
        for nf in &self.nullifiers {
            elems.extend(nf.to_elems());
        }
        for c in &self.output_commitments {
            elems.extend(c.to_elems());
        }
        assert_eq!(elems.len(), STATEMENT_ELEMS);
        let mut out = Vec::with_capacity(STATEMENT_PUBLIC_VALUES);
        for e in elems {
            out.push(e);
            out.extend([BabyBear::ZERO; 3]);
        }
        out
    }
}

/// A proof-carrying-data coin proof: a batch-STARK proof of the mint circuit
/// or the node (transfer) circuit, with its statement.
pub struct CoinProof {
    /// Fail-closed proof lineage version.
    pub version: u8,
    /// Mint or transfer.
    pub mode: NodeMode,
    /// The statement the circuit computed; equals the statement table's
    /// instance public values inside `proof` (checked by
    /// [`verify_coin_proof`]).
    pub statement: NodeStatement,
    /// The batch-STARK proof over the circuit's tables.
    pub proof: BatchStarkProof<CoinRecursionConfig>,
}

impl CoinProof {
    /// The statement table's instance public values inside the proof.
    fn statement_public_values(&self) -> Option<&[BabyBear]> {
        self.proof
            .non_primitives
            .iter()
            .find(|e| e.op_type == statement_op_type())
            .map(|e| e.public_values.as_slice())
    }
}

/// Identity of exactly the predecessor verifier data consumed by recursive
/// setup. D4 will additionally hard-bind this identity in-circuit; D1 uses it
/// to prevent cache aliasing across foreign or changed verifier keys.
fn verification_key_identity(coin: &CoinProof) -> SetupIdentity {
    let proof = &coin.proof;
    let packing = postcard::to_allocvec(&proof.table_packing)
        .expect("table packing has an infallible postcard encoding");
    let manifest = postcard::to_allocvec(&proof.non_primitives)
        .expect("non-primitive manifest has an infallible postcard encoding");
    let proof_metadata = format!(
        "rows={:?}/alu={:?}/ext={}/w={:?}/quintic={}",
        proof.rows,
        proof.alu_variant,
        proof.ext_degree,
        proof.w_binomial,
        proof.alu_quintic_trinomial,
    );
    let lookups = format!("{:?}", proof.stark_common.lookups);
    let mut preprocessed_metadata = Vec::new();
    let commitment = match &proof.stark_common.preprocessed {
        Some(preprocessed) => {
            preprocessed_metadata.extend_from_slice(b"present");
            preprocessed_metadata
                .extend_from_slice(&(preprocessed.instances.len() as u64).to_le_bytes());
            for instance in &preprocessed.instances {
                match instance {
                    Some(instance) => {
                        preprocessed_metadata.push(1);
                        preprocessed_metadata
                            .extend_from_slice(&(instance.matrix_index as u64).to_le_bytes());
                        preprocessed_metadata
                            .extend_from_slice(&(instance.width as u64).to_le_bytes());
                        preprocessed_metadata
                            .extend_from_slice(&(instance.degree_bits as u64).to_le_bytes());
                    }
                    None => preprocessed_metadata.push(0),
                }
            }
            preprocessed_metadata
                .extend_from_slice(&(preprocessed.matrix_to_instance.len() as u64).to_le_bytes());
            for &instance in &preprocessed.matrix_to_instance {
                preprocessed_metadata.extend_from_slice(&(instance as u64).to_le_bytes());
            }
            postcard::to_allocvec(&preprocessed.commitment)
                .expect("preprocessed commitment has an infallible postcard encoding")
        }
        None => {
            preprocessed_metadata.extend_from_slice(b"absent");
            Vec::new()
        }
    };

    SetupIdentity::for_verification_key(
        b"coin-proof-verification-key",
        &[
            packing.as_slice(),
            manifest.as_slice(),
            proof_metadata.as_bytes(),
            commitment.as_slice(),
            preprocessed_metadata.as_slice(),
            lookups.as_bytes(),
        ],
    )
}

/// Errors from proving or verifying a coin proof.
#[derive(Debug)]
pub enum NodeError {
    /// The supplied issuer seed does not control the genesis issuer key.
    IssuerKeyMismatch,
    /// Not all coins are denominated in the stated asset.
    AssetMismatch,
    /// The minted output values sum to more than `u64::MAX`.
    ValueOverflow,
    /// The proof belongs to an unsupported or unauthenticated lineage.
    UnsupportedProofVersion {
        /// Version carried by the proof.
        actual: u8,
    },
    /// A predecessor's `asset_id` does not match this node's asset.
    PredecessorAssetMismatch,
    /// A predecessor's selected output commitment does not equal the consumed
    /// input coin's commitment (detected off-circuit before proving).
    PredecessorOutputMismatch,
    /// A predecessor is not a [`CoinProof`]-shaped proof (no statement table).
    MissingStatement,
    /// A predecessor's statement table belongs to another proof lineage.
    PredecessorStatementShapeMismatch {
        /// Number of statement public values in the predecessor proof.
        actual: usize,
        /// Number required by this proof lineage.
        expected: usize,
    },
    /// A predecessor or verifier circuit has no preprocessed verification key.
    MissingPredecessorVerificationKey,
    /// The allocated predecessor-key target has a different shape than the
    /// expected native verification key.
    PredecessorVerificationKeyShapeMismatch {
        /// Number of allocated commitment elements.
        actual: usize,
        /// Number of expected commitment elements.
        expected: usize,
    },
    /// Circuit construction failed.
    Builder(CircuitBuilderError),
    /// Witness generation / circuit execution failed (e.g. unbalanced values,
    /// a wrong owner secret, or a chaining mismatch surfacing as a witness
    /// conflict).
    Circuit(CircuitError),
    /// In-circuit verifier construction failed.
    Verification(VerificationError),
    /// STARK proving or verification failed.
    Prover(BatchStarkProverError),
    /// The statement embedded in the proof does not match the expected one.
    StatementMismatch,
    /// Setting FRI private data on the runner failed.
    FriPrivateData(&'static str),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IssuerKeyMismatch => {
                write!(f, "issuer seed does not control the asset genesis key")
            }
            Self::AssetMismatch => write!(f, "coin asset does not match the stated asset"),
            Self::ValueOverflow => write!(f, "mint output values overflow u64"),
            Self::UnsupportedProofVersion { actual } => write!(
                f,
                "unsupported coin-proof version {actual}; expected {COIN_PROOF_VERSION}"
            ),
            Self::PredecessorAssetMismatch => {
                write!(f, "predecessor asset does not match this node's asset")
            }
            Self::PredecessorOutputMismatch => write!(
                f,
                "predecessor output commitment does not match the consumed input coin"
            ),
            Self::MissingStatement => write!(f, "predecessor proof has no statement table"),
            Self::PredecessorStatementShapeMismatch { actual, expected } => write!(
                f,
                "predecessor statement shape mismatch: found {actual} public values, expected {expected}"
            ),
            Self::MissingPredecessorVerificationKey => {
                write!(f, "predecessor proof has no preprocessed verification key")
            }
            Self::PredecessorVerificationKeyShapeMismatch { actual, expected } => write!(
                f,
                "predecessor verification-key shape mismatch: allocated {actual} elements, expected {expected}"
            ),
            Self::Builder(e) => write!(f, "circuit build error: {e}"),
            Self::Circuit(e) => write!(f, "circuit execution error: {e}"),
            Self::Verification(e) => write!(f, "in-circuit verifier error: {e}"),
            Self::Prover(e) => write!(f, "STARK prover error: {e}"),
            Self::StatementMismatch => {
                write!(f, "proof statement does not match the expected public data")
            }
            Self::FriPrivateData(e) => write!(f, "FRI private data error: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<CircuitBuilderError> for NodeError {
    fn from(e: CircuitBuilderError) -> Self {
        Self::Builder(e)
    }
}
impl From<CircuitError> for NodeError {
    fn from(e: CircuitError) -> Self {
        Self::Circuit(e)
    }
}
impl From<VerificationError> for NodeError {
    fn from(e: VerificationError) -> Self {
        Self::Verification(e)
    }
}
impl From<BatchStarkProverError> for NodeError {
    fn from(e: BatchStarkProverError) -> Self {
        Self::Prover(e)
    }
}

// ============================================================================
// Statement assembly helpers
// ============================================================================

/// Allocate the statement op over `stmt` (exactly [`STATEMENT_ELEMS`] exprs).
fn push_statement_op(builder: &mut CircuitBuilder<EF>, stmt: Vec<ExprId>) -> Result<(), NodeError> {
    assert_eq!(stmt.len(), STATEMENT_ELEMS);
    // Ensure every statement element has a WitnessChecks creator: hint
    // outputs (hash decompose coefficients) whose only use would be the
    // statement NPO read otherwise have no bus creator, unbalancing the
    // WitnessChecks multiset. A trivial ALU op per element fixes the
    // accounting (a first-use ALU op is the creator for private inputs and
    // hint outputs; for already-defined exprs it is a plain read). The
    // running sum keeps the claim ops live.
    let mut acc: Option<ExprId> = None;
    for &e in &stmt {
        let claim = builder.add(e, e);
        acc = Some(match acc {
            None => claim,
            Some(a) => builder.add(a, claim),
        });
    }
    let _ = acc;
    let _ = builder.push_non_primitive_op_with_outputs(
        statement_op_type(),
        vec![stmt],
        vec![],
        None,
        "coin_statement",
    );
    Ok(())
}

fn const_expr(builder: &mut CircuitBuilder<EF>, v: BabyBear) -> ExprId {
    builder.alloc_const(EF::from(v), "const")
}

// ============================================================================
// Mint circuit
// ============================================================================

/// Witness layout of the mint circuit's private inputs.
struct MintWitness<'a> {
    asset_id: &'a [ExprId],
    value_total: &'a [ExprId],
    mint_nonce: &'a [ExprId],
    issuer: IssuerWitness<'a>,
    outputs: [(&'a [ExprId], &'a [ExprId], &'a [ExprId]); NODE_OUTPUTS],
}

fn mint_witness_layout(private: &[ExprId]) -> MintWitness<'_> {
    const OUT_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS; // 19
    let asset_id = &private[0..DIGEST_ELEMS];
    let value_total = &private[DIGEST_ELEMS..DIGEST_ELEMS + VALUE_LIMBS];
    let mint_nonce = &private[DIGEST_ELEMS + VALUE_LIMBS..2 * DIGEST_ELEMS + VALUE_LIMBS];
    let issuer_start = 2 * DIGEST_ELEMS + VALUE_LIMBS;
    let issuer_end = issuer_start + ISSUER_AUTH_ELEMS;
    let issuer = issuer_witness_layout(&private[issuer_start..issuer_end]);
    let base = issuer_end;
    let outputs = std::array::from_fn(|i| {
        let s = base + i * OUT_ELEMS;
        (
            &private[s..s + VALUE_LIMBS],
            &private[s + VALUE_LIMBS..s + VALUE_LIMBS + DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + DIGEST_ELEMS..s + OUT_ELEMS],
        )
    });
    MintWitness {
        asset_id,
        value_total,
        mint_nonce,
        issuer,
        outputs,
    }
}

/// Build the mint circuit: the stage-2 mint predicate plus the statement
/// table (no predecessor verification).
fn build_mint_circuit() -> Result<Circuit<EF>, NodeError> {
    let mut builder = CircuitBuilder::<EF>::new();
    crate::recursion_config::CoinRecursionConfig::new(&CoinFriParams::testing())
        .prepare_circuit_for_verification(&mut builder)?;
    builder.register_npo(StatementCircuitPlugin::<STATEMENT_ELEMS>::new());

    let private = builder.alloc_private_inputs(MINT_PRIVATE_ELEMS, "mint_witness");
    let witness = mint_witness_layout(&private);

    // Issuer seed -> issuer key -> genesis -> statement asset id.
    enforce_authorization(&mut builder, witness.asset_id, &witness.issuer)?;

    // Values in range: the public total and every output value.
    let v_total: [ExprId; VALUE_LIMBS] = witness.value_total.try_into().expect("V has 3 limbs");
    range_check_value(&mut builder, &v_total)?;
    let mut out_values = [[ExprId::ZERO; VALUE_LIMBS]; NODE_OUTPUTS];
    for (i, out_value) in out_values.iter_mut().enumerate() {
        *out_value = witness.outputs[i].0.try_into().expect("v has 3 limbs");
        range_check_value(&mut builder, out_value)?;
    }

    // Σ v_i = V, exact u64 arithmetic.
    let zero = [ExprId::ZERO; VALUE_LIMBS];
    enforce_sum_eq(
        &mut builder,
        [&out_values[0], &out_values[1]],
        [&v_total, &zero],
    )?;

    // Output commitments recompute from the witness openings.
    let mut out_commitments = [[ExprId::ZERO; DIGEST_ELEMS]; NODE_OUTPUTS];
    for (j, out) in out_commitments.iter_mut().enumerate() {
        let (v, owner, r) = witness.outputs[j];
        *out = coin_commitment_base(&mut builder, witness.asset_id, v, owner, r)?;
    }

    // mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce).
    let mc = hash_felts_base(
        &mut builder,
        "mint",
        &[witness.asset_id, witness.value_total, witness.mint_nonce],
    )?;

    // Statement: [version=2 | mode=1 | asset | V | mint_commit | nf = 0 ×2 | out ×2].
    let mut stmt = Vec::with_capacity(STATEMENT_ELEMS);
    stmt.push(const_expr(
        &mut builder,
        BabyBear::new(COIN_PROOF_VERSION as u32),
    ));
    stmt.push(const_expr(&mut builder, BabyBear::ONE));
    stmt.extend_from_slice(witness.asset_id);
    stmt.extend_from_slice(witness.value_total);
    stmt.extend_from_slice(&mc);
    for _ in 0..NODE_INPUTS * DIGEST_ELEMS {
        stmt.push(ExprId::ZERO);
    }
    for out in &out_commitments {
        stmt.extend_from_slice(out);
    }
    push_statement_op(&mut builder, stmt)?;

    Ok(builder.build()?)
}

// ============================================================================
// Node (transfer) circuit
// ============================================================================

/// Witness layout of the node circuit's own private inputs.
struct NodeWitness<'a> {
    asset_id: &'a [ExprId],
    /// Per input: `(v limbs, owner, randomness, osk)`.
    inputs: [(&'a [ExprId], &'a [ExprId], &'a [ExprId], &'a [ExprId]); NODE_INPUTS],
    /// Per output: `(v limbs, owner, randomness)`.
    outputs: [(&'a [ExprId], &'a [ExprId], &'a [ExprId]); NODE_OUTPUTS],
    /// Per input: predecessor output selector `k_i ∈ {0, 1}`.
    selectors: &'a [ExprId],
}

fn node_witness_layout(private: &[ExprId]) -> NodeWitness<'_> {
    const IN_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS + crate::hash::OSK_ELEMS; // 30
    const OUT_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS; // 19
    let asset_id = &private[0..DIGEST_ELEMS];
    let base = DIGEST_ELEMS;
    let inputs = std::array::from_fn(|i| {
        let s = base + i * IN_ELEMS;
        (
            &private[s..s + VALUE_LIMBS],
            &private[s + VALUE_LIMBS..s + VALUE_LIMBS + DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + DIGEST_ELEMS..s + VALUE_LIMBS + 2 * DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + 2 * DIGEST_ELEMS..s + IN_ELEMS],
        )
    });
    let out_base = base + NODE_INPUTS * IN_ELEMS;
    let outputs = std::array::from_fn(|j| {
        let s = out_base + j * OUT_ELEMS;
        (
            &private[s..s + VALUE_LIMBS],
            &private[s + VALUE_LIMBS..s + VALUE_LIMBS + DIGEST_ELEMS],
            &private[s + VALUE_LIMBS + DIGEST_ELEMS..s + OUT_ELEMS],
        )
    });
    let selectors = &private[out_base + NODE_OUTPUTS * OUT_ELEMS..];
    NodeWitness {
        asset_id,
        inputs,
        outputs,
        selectors,
    }
}

/// In-circuit verifier state for one predecessor proof.
struct PredVerifier {
    /// The instance index of the predecessor's statement table.
    stmt_instance: usize,
    /// Allocated targets/proof structure for packing.
    verifier_inputs: BatchStarkVerifierInputsBuilder<
        CoinRecursionConfig,
        <CoinRecursionConfig as FriRecursionConfig>::Commitment,
        <CoinRecursionConfig as FriRecursionConfig>::OpeningProof,
    >,
    /// MMCS op ids needing FRI private data at runtime.
    op_ids: Vec<p3_circuit::NonPrimitiveOpId>,
}

/// Build the node (transfer) circuit with in-circuit verification of the two
/// predecessor proofs (shape-driven per predecessor: mint or node proofs).
fn build_node_circuit(
    config: &CoinRecursionConfig,
    predecessors: [&CoinProof; 2],
) -> Result<(Circuit<EF>, [PredVerifier; 2]), NodeError> {
    let mut builder = CircuitBuilder::<EF>::new();
    config.prepare_circuit_for_verification(&mut builder)?;
    builder.register_npo(StatementCircuitPlugin::<STATEMENT_ELEMS>::new());

    let private = builder.alloc_private_inputs(NODE_PRIVATE_ELEMS, "node_witness");
    let witness = node_witness_layout(&private);

    // --- transfer predicate (as stage 2).
    let mut in_values = [[ExprId::ZERO; VALUE_LIMBS]; NODE_INPUTS];
    let mut in_commitments = [[ExprId::ZERO; DIGEST_ELEMS]; NODE_INPUTS];
    let mut nullifiers = [[ExprId::ZERO; DIGEST_ELEMS]; NODE_INPUTS];
    for (i, in_value) in in_values.iter_mut().enumerate() {
        let (v, owner, r, osk) = witness.inputs[i];
        *in_value = v.try_into().expect("v has 3 limbs");
        range_check_value(&mut builder, in_value)?;

        // Input commitment recomputes from its witness opening.
        in_commitments[i] = coin_commitment_base(&mut builder, witness.asset_id, v, owner, r)?;

        // Ownership: owner_i = H(osk_i).
        let own = hash_felts_limbs(&mut builder, "", &[osk])?;
        connect_digest(&mut builder, own, owner)?;

        // Nullifier: nf_i = H("null" ∥ osk_i ∥ C_i).
        nullifiers[i] = hash_felts_base(&mut builder, "null", &[osk, &in_commitments[i]])?;
    }

    let mut out_values = [[ExprId::ZERO; VALUE_LIMBS]; NODE_OUTPUTS];
    let mut out_commitments = [[ExprId::ZERO; DIGEST_ELEMS]; NODE_OUTPUTS];
    for (j, out_value) in out_values.iter_mut().enumerate() {
        let (v, owner, r) = witness.outputs[j];
        *out_value = v.try_into().expect("v has 3 limbs");
        range_check_value(&mut builder, out_value)?;
        out_commitments[j] = coin_commitment_base(&mut builder, witness.asset_id, v, owner, r)?;
    }

    // Conservation: Σ v_in = Σ v_out, exact u64 arithmetic.
    enforce_sum_eq(
        &mut builder,
        [&in_values[0], &in_values[1]],
        [&out_values[0], &out_values[1]],
    )?;

    // --- in-circuit predecessor verification + chaining.
    let lookup_gadget = LogUpGadget::new();
    let mut preds: Vec<PredVerifier> = Vec::with_capacity(NODE_INPUTS);
    for (i, pred) in predecessors.iter().enumerate() {
        preds.push(chain_predecessor(
            config,
            &mut builder,
            &lookup_gadget,
            pred,
            witness.asset_id,
            witness.selectors[i],
            &in_commitments[i],
        )?);
    }
    let preds: [PredVerifier; 2] = match preds.try_into() {
        Ok(p) => p,
        Err(_) => unreachable!("two predecessors verified above"),
    };

    // --- statement: [version=2 | mode=0 | asset | V = 0 | mint_commit = 0 | nf ×2 | out ×2].
    let mut stmt = Vec::with_capacity(STATEMENT_ELEMS);
    stmt.push(const_expr(
        &mut builder,
        BabyBear::new(COIN_PROOF_VERSION as u32),
    ));
    stmt.push(ExprId::ZERO);
    stmt.extend_from_slice(witness.asset_id);
    for _ in 0..VALUE_LIMBS + DIGEST_ELEMS {
        stmt.push(ExprId::ZERO);
    }
    for nf in &nullifiers {
        stmt.extend_from_slice(nf);
    }
    for out in &out_commitments {
        stmt.extend_from_slice(out);
    }
    push_statement_op(&mut builder, stmt)?;

    Ok((builder.build()?, preds))
}

// ============================================================================
// Shared in-circuit predecessor verification + chaining
// ============================================================================

/// Relay a base-embedded public input through the recompose table.
///
/// The coefficient-lookups variant is important here: besides yielding an
/// ordinary NPO output that is safe to use in ALU constraints, it receives
/// the source witness as a base-field coefficient. That forces extension
/// coefficients 1..D to zero instead of checking only coefficient zero.
fn relay_base_public_input(
    builder: &mut CircuitBuilder<EF>,
    target: ExprId,
) -> Result<ExprId, NodeError> {
    Ok(
        builder.recompose_base_coeffs_to_ext_with_coeff_lookups::<BabyBear>(&[
            target,
            ExprId::ZERO,
            ExprId::ZERO,
            ExprId::ZERO,
        ])?,
    )
}

/// Constrain one recursive verifier's proof-carried preprocessed commitment
/// to the verification key selected when its parent circuit was built.
fn bind_predecessor_verification_key(
    builder: &mut CircuitBuilder<EF>,
    verifier_inputs: &BatchStarkVerifierInputsBuilder<
        CoinRecursionConfig,
        <CoinRecursionConfig as FriRecursionConfig>::Commitment,
        <CoinRecursionConfig as FriRecursionConfig>::OpeningProof,
    >,
    predecessor: &CoinProof,
) -> Result<(), NodeError> {
    let allocated = verifier_inputs
        .common_data
        .preprocessed_commitment()
        .ok_or(NodeError::MissingPredecessorVerificationKey)?
        .to_observation_targets();
    let expected_commitment = &predecessor
        .proof
        .stark_common
        .preprocessed
        .as_ref()
        .ok_or(NodeError::MissingPredecessorVerificationKey)?
        .commitment;
    let expected =
        <<CoinRecursionConfig as FriRecursionConfig>::Commitment as Recursive<EF>>::get_values(
            expected_commitment,
        );

    if allocated.len() != expected.len() {
        return Err(NodeError::PredecessorVerificationKeyShapeMismatch {
            actual: allocated.len(),
            expected: expected.len(),
        });
    }

    for (target, value) in allocated.into_iter().zip(expected) {
        let relayed = relay_base_public_input(builder, target)?;
        let expected = builder.define_const(value);
        let difference = builder.sub(relayed, expected);
        builder.assert_zero(difference);
    }
    Ok(())
}

fn proof_uses_split_recompose_coefficients(proof: &BatchStarkProof<CoinRecursionConfig>) -> bool {
    proof
        .non_primitives
        .iter()
        .any(|entry| entry.op_type == NpoTypeId::recompose_with_coeff_lookups())
}

/// Verify one predecessor coin proof in-circuit and enforce the chaining
/// constraints (module docs): the predecessor's bound `asset_id` equals this
/// circuit's asset, and `select(k, out_1, out_0)` equals the recomputed input
/// commitment `commitment` (`k` a boolean witness expression).
fn chain_predecessor(
    config: &CoinRecursionConfig,
    builder: &mut CircuitBuilder<EF>,
    lookup_gadget: &LogUpGadget,
    pred: &CoinProof,
    asset_id: &[ExprId],
    selector: ExprId,
    commitment: &[ExprId; DIGEST_ELEMS],
) -> Result<PredVerifier, NodeError> {
    if pred.version != COIN_PROOF_VERSION {
        return Err(NodeError::UnsupportedProofVersion {
            actual: pred.version,
        });
    }
    let stmt_instance = pred
        .proof
        .non_primitives
        .iter()
        .position(|e| e.op_type == statement_op_type())
        .map(|p| NUM_PRIMITIVE_TABLES + p)
        .ok_or(NodeError::MissingStatement)?;

    let table_provers =
        node_table_provers::<STATEMENT_ELEMS>(proof_uses_split_recompose_coefficients(&pred.proof));
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
        config,
        builder,
        &pred.proof,
        config.pcs_verifier_params(),
        &pred.proof.stark_common,
        lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
        &table_provers,
    )?;

    bind_predecessor_verification_key(builder, &verifier_inputs, pred)?;

    let stmt_targets = &verifier_inputs.air_public_targets[stmt_instance];
    if stmt_targets.len() != STATEMENT_PUBLIC_VALUES {
        return Err(NodeError::PredecessorStatementShapeMismatch {
            actual: stmt_targets.len(),
            expected: STATEMENT_PUBLIC_VALUES,
        });
    }
    // Statement element `e` coefficient-0 target (all statement elements
    // are base-embedded by construction).
    let elem = |e: usize| stmt_targets[4 * e];
    // Relay a public-input target through an NPO read so it can be
    // constrained: at this pin, connecting a public input to anything
    // double-sends it on the WitnessChecks bus (Public table sends are
    // unconditional creators), and using one as an ALU operand trips an
    // optimizer slot-rewrite bug when two verifier sub-circuits are
    // present. Recomposing `[t, 0, 0, 0]` reads `t` through the
    // (bus-safe) recompose table and yields an ordinary NPO output.
    let relay = |builder: &mut CircuitBuilder<EF>, t: ExprId| {
        builder.recompose_base_coeffs_to_ext::<BabyBear>(&[
            t,
            ExprId::ZERO,
            ExprId::ZERO,
            ExprId::ZERO,
        ])
    };

    // (a) predecessor asset == this circuit's asset (coefficient 0 per
    // element; remaining coefficients are zero by construction).
    for e in 0..DIGEST_ELEMS {
        let target = relay(builder, elem(OFF_ASSET + e))?;
        let d = builder.sub(target, asset_id[e]);
        builder.assert_zero(d);
    }

    // (b) the selected predecessor output == recomputed input commitment.
    builder.assert_bool(selector);
    for e in 0..DIGEST_ELEMS {
        let out0 = relay(builder, elem(OFF_OUTPUTS + e))?;
        let out1 = relay(builder, elem(OFF_OUTPUTS + DIGEST_ELEMS + e))?;
        let selected = builder.select(selector, out1, out0);
        let d = builder.sub(selected, commitment[e]);
        builder.assert_zero(d);
    }

    Ok(PredVerifier {
        stmt_instance,
        verifier_inputs,
        op_ids,
    })
}

// ============================================================================
// Redeem circuit (paper §4.6)
// ============================================================================

/// Build the redeem circuit: burn one coin, exposing `(asset_id, V, nf)` in
/// the statement, with in-circuit verification of the single predecessor
/// proof (mint or node — the coin's ancestry).
fn build_redeem_circuit(
    config: &CoinRecursionConfig,
    predecessor: &CoinProof,
) -> Result<(Circuit<EF>, PredVerifier), NodeError> {
    let mut builder = CircuitBuilder::<EF>::new();
    config.prepare_circuit_for_verification(&mut builder)?;
    builder.register_npo(StatementCircuitPlugin::<STATEMENT_ELEMS>::new());

    let private = builder.alloc_private_inputs(REDEEM_PRIVATE_ELEMS, "redeem_witness");
    const IN_ELEMS: usize = VALUE_LIMBS + 2 * DIGEST_ELEMS + crate::hash::OSK_ELEMS; // 30
    let asset_id = &private[0..DIGEST_ELEMS];
    let base = DIGEST_ELEMS;
    let v = &private[base..base + VALUE_LIMBS];
    let owner = &private[base + VALUE_LIMBS..base + VALUE_LIMBS + DIGEST_ELEMS];
    let r = &private[base + VALUE_LIMBS + DIGEST_ELEMS..base + VALUE_LIMBS + 2 * DIGEST_ELEMS];
    let osk = &private[base + VALUE_LIMBS + 2 * DIGEST_ELEMS..base + IN_ELEMS];
    let selector = private[base + IN_ELEMS];

    // Value in range; the coin's committed value *is* the public burn
    // amount `V` (the value limbs go into the statement below).
    range_check_value(&mut builder, v.try_into().expect("v has 3 limbs"))?;

    // Input commitment recomputes from the witness opening.
    let commitment = coin_commitment_base(&mut builder, asset_id, v, owner, r)?;

    // Ownership: owner = H(osk).
    let own = hash_felts_limbs(&mut builder, "", &[osk])?;
    connect_digest(&mut builder, own, owner)?;

    // Nullifier: nf = H("null" ∥ osk ∥ C).
    let nf = hash_felts_base(&mut builder, "null", &[osk, &commitment])?;

    // --- in-circuit predecessor verification + chaining (1 predecessor).
    let lookup_gadget = LogUpGadget::new();
    let pred = chain_predecessor(
        config,
        &mut builder,
        &lookup_gadget,
        predecessor,
        asset_id,
        selector,
        &commitment,
    )?;

    // --- statement: [version=2 | mode=2 | asset | V = v | mint_commit = 0 | nf | 0 | 0 | 0].
    let mut stmt = Vec::with_capacity(STATEMENT_ELEMS);
    stmt.push(const_expr(
        &mut builder,
        BabyBear::new(COIN_PROOF_VERSION as u32),
    ));
    stmt.push(const_expr(&mut builder, BabyBear::new(2)));
    stmt.extend_from_slice(asset_id);
    stmt.extend_from_slice(v);
    for _ in 0..DIGEST_ELEMS {
        stmt.push(ExprId::ZERO); // mint_commit
    }
    stmt.extend_from_slice(&nf);
    for _ in 0..DIGEST_ELEMS + NODE_OUTPUTS * DIGEST_ELEMS {
        stmt.push(ExprId::ZERO); // nf_2, out_1, out_2
    }
    push_statement_op(&mut builder, stmt)?;

    Ok((builder.build()?, pred))
}

// ============================================================================
// Proving / verifying
// ============================================================================

/// The FRI parameters used for all stage-3 proofs (test-grade; see
/// [`crate::recursion_config`]).
pub fn coin_fri_params() -> CoinFriParams {
    CoinFriParams::testing()
}

/// Build the mint circuit setup (vk side).
fn mint_setup() -> Result<RecSetup, NodeError> {
    Ok(setup_circuit::<STATEMENT_ELEMS>(
        build_mint_circuit()?,
        &coin_fri_params(),
    )?)
}

/// Prove an issuer-authorized genesis mint with no predecessors (paper §4.4
/// predicate plus the statement table).
pub fn prove_genesis_mint(
    genesis: &AssetGenesis,
    issuer_secret: &[u8; 32],
    mint_nonce: &Digest,
    outputs: &[Coin; NODE_OUTPUTS],
) -> Result<CoinProof, NodeError> {
    if !PoseidonIssuerAuthorization::controls(issuer_secret, &genesis.issuer_pk) {
        return Err(NodeError::IssuerKeyMismatch);
    }
    let asset_id = genesis.asset_id();
    prove_genesis_mint_raw(&asset_id, genesis, issuer_secret, mint_nonce, outputs)
}

/// Low-level genesis prover that skips the native key/genesis consistency
/// precheck so adversarial tests exercise the circuit constraints directly.
#[doc(hidden)]
pub fn prove_genesis_mint_raw(
    asset_id: &AssetId,
    genesis: &AssetGenesis,
    issuer_secret: &[u8; 32],
    mint_nonce: &Digest,
    outputs: &[Coin; NODE_OUTPUTS],
) -> Result<CoinProof, NodeError> {
    if outputs.iter().any(|c| c.asset_id != *asset_id) {
        return Err(NodeError::AssetMismatch);
    }
    let mut value = 0u64;
    for c in outputs {
        value = value.checked_add(c.value).ok_or(NodeError::ValueOverflow)?;
    }
    let mc = mint_commit(asset_id, value, mint_nonce);

    let mut private_values = Vec::with_capacity(MINT_PRIVATE_ELEMS);
    private_values.extend(asset_id.to_elems().iter().map(|&x| EF::from(x)));
    private_values.extend(u64_to_felts(value).iter().map(|&x| EF::from(x)));
    private_values.extend(mint_nonce.to_elems().iter().map(|&x| EF::from(x)));
    private_values.extend(
        witness_values(issuer_secret, genesis)
            .iter()
            .map(|&x| EF::from(x)),
    );
    for c in outputs {
        private_values.extend(u64_to_felts(c.value).iter().map(|&x| EF::from(x)));
        private_values.extend(c.owner.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(c.randomness.to_elems().iter().map(|&x| EF::from(x)));
    }

    let s = mint_setup()?;
    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&[])?;
    runner.set_private_inputs(&private_values)?;
    let traces = runner.run()?;

    let prover = new_prover::<STATEMENT_ELEMS>(&s.config, s.table_packing.clone(), false);
    let circuit_prover_data = lock_setup(&s.circuit_prover_data);
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data)?;

    Ok(CoinProof {
        version: COIN_PROOF_VERSION,
        mode: NodeMode::Mint,
        statement: NodeStatement {
            asset_id: *asset_id,
            value,
            mint_commit: mc,
            nullifiers: [Digest::from_bytes([0u8; 32]); NODE_INPUTS],
            output_commitments: [outputs[0].commitment(), outputs[1].commitment()],
        },
        proof,
    })
}

/// Prove a transfer spending two coins, verifying both predecessor coin
/// proofs in-circuit (paper §4.5 predicate plus PCD recursion).
///
/// `predecessors[i]` must be the coin proof that created `inputs[i].0` as its
/// `k_i`-th output (`selectors[i]`); the circuit enforces the chaining
/// constraints from the module docs, so a mismatch fails proving with
/// [`NodeError::Circuit`] (witness conflict).
pub fn prove_transfer(
    asset_id: &AssetId,
    inputs: &[(Coin, OwnerSecret); NODE_INPUTS],
    outputs: &[Coin; NODE_OUTPUTS],
    predecessors: [&CoinProof; 2],
    selectors: [usize; 2],
) -> Result<CoinProof, NodeError> {
    if inputs.iter().any(|(c, _)| c.asset_id != *asset_id)
        || outputs.iter().any(|c| c.asset_id != *asset_id)
    {
        return Err(NodeError::AssetMismatch);
    }
    for (i, pred) in predecessors.iter().enumerate() {
        if pred.statement.asset_id != *asset_id {
            return Err(NodeError::PredecessorAssetMismatch);
        }
        let k = selectors[i];
        if k >= NODE_OUTPUTS || pred.statement.output_commitments[k] != inputs[i].0.commitment() {
            return Err(NodeError::PredecessorOutputMismatch);
        }
    }
    let nullifiers = std::array::from_fn(|i| {
        let (coin, osk) = &inputs[i];
        opencsv_core::coin::nullifier(osk, &coin.commitment())
    });

    let config = CoinRecursionConfig::new(&coin_fri_params());
    let (circuit, preds) = build_node_circuit(&config, predecessors)?;
    let verification_keys = predecessors.map(verification_key_identity);
    let s = setup_circuit_with_verification_keys::<STATEMENT_ELEMS>(
        circuit,
        &coin_fri_params(),
        &verification_keys,
    )?;

    // Private inputs: own witness, then per-predecessor verifier privates.
    let mut private_values = Vec::new();
    private_values.extend(asset_id.to_elems().iter().map(|&x| EF::from(x)));
    for (coin, osk) in inputs {
        private_values.extend(u64_to_felts(coin.value).iter().map(|&x| EF::from(x)));
        private_values.extend(coin.owner.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(coin.randomness.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(crate::hash::osk_felts(osk).iter().map(|&x| EF::from(x)));
    }
    for coin in outputs {
        private_values.extend(u64_to_felts(coin.value).iter().map(|&x| EF::from(x)));
        private_values.extend(coin.owner.to_elems().iter().map(|&x| EF::from(x)));
        private_values.extend(coin.randomness.to_elems().iter().map(|&x| EF::from(x)));
    }
    for &k in &selectors {
        private_values.push(EF::from(BabyBear::new(k as u32)));
    }

    // Public inputs: per-predecessor verifier publics (statement instance
    // public values + proof targets + common data).
    let mut public_values = Vec::new();
    for (i, pred) in predecessors.iter().enumerate() {
        let stmt_pvs = pred
            .statement_public_values()
            .ok_or(NodeError::MissingStatement)?;
        let mut table_pvs: Vec<Vec<BabyBear>> = vec![Vec::new(); preds[i].stmt_instance];
        table_pvs.push(stmt_pvs.to_vec());
        public_values.extend(preds[i].verifier_inputs.pack_public_values(
            &table_pvs,
            &pred.proof.proof,
            &pred.proof.stark_common,
        ));
    }
    for (i, p) in preds.iter().enumerate() {
        private_values.extend(
            p.verifier_inputs
                .pack_private_values(&predecessors[i].proof.proof),
        );
    }

    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&public_values)?;
    runner.set_private_inputs(&private_values)?;
    for (i, p) in preds.iter().enumerate() {
        CoinRecursionConfig::set_fri_private_data(
            &mut runner,
            &p.op_ids,
            &predecessors[i].proof.proof.opening_proof,
        )
        .map_err(NodeError::FriPrivateData)?;
    }
    let traces = runner.run()?;

    let prover = new_prover::<STATEMENT_ELEMS>(&s.config, s.table_packing.clone(), true);
    let circuit_prover_data = lock_setup(&s.circuit_prover_data);
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data)?;

    Ok(CoinProof {
        version: COIN_PROOF_VERSION,
        mode: NodeMode::Transfer,
        statement: NodeStatement {
            asset_id: *asset_id,
            value: 0,
            mint_commit: Digest::from_bytes([0u8; 32]),
            nullifiers,
            output_commitments: [outputs[0].commitment(), outputs[1].commitment()],
        },
        proof,
    })
}

/// Verify a coin proof against the expected statement: checks that the
/// statement table's instance public values inside the proof equal
/// `expected` (this is the cryptographically bound channel — see module
/// docs), then natively verifies the batch-STARK proof.
pub fn verify_coin_proof(expected: &NodeStatement, coin: &CoinProof) -> Result<(), NodeError> {
    if coin.version != COIN_PROOF_VERSION {
        return Err(NodeError::UnsupportedProofVersion {
            actual: coin.version,
        });
    }
    let pvs = coin
        .statement_public_values()
        .ok_or(NodeError::MissingStatement)?;
    if pvs != expected.to_public_values(coin.mode) {
        return Err(NodeError::StatementMismatch);
    }
    let config = CoinRecursionConfig::new(&coin_fri_params());
    let verifier = new_prover::<STATEMENT_ELEMS>(
        &config,
        coin.proof.table_packing.clone(),
        proof_uses_split_recompose_coefficients(&coin.proof),
    );
    verifier.verify_all_tables::<EF>(&coin.proof)?;
    Ok(())
}

/// A redeem proof (paper §4.6): a [`CoinProof`] with [`NodeMode::Redeem`].
pub type RedeemProof = CoinProof;

/// Prove a redeem: burn `input.0`, exposing `(asset_id, V = value, nf)` in
/// the statement, verifying the coin's ancestry (`predecessor`, mint or
/// node) in-circuit.
///
/// `predecessor` must be the coin proof that created `input.0` as its
/// `selector`-th output; a mismatch fails off-circuit with
/// [`NodeError::PredecessorOutputMismatch`], and a tampered predecessor
/// statement fails in-circuit at witness generation ([`NodeError::Circuit`]),
/// exactly as for [`prove_transfer`].
pub fn prove_redeem(
    asset_id: &AssetId,
    input: &(Coin, OwnerSecret),
    predecessor: &CoinProof,
    selector: usize,
) -> Result<RedeemProof, NodeError> {
    let (coin, osk) = input;
    if coin.asset_id != *asset_id {
        return Err(NodeError::AssetMismatch);
    }
    if predecessor.statement.asset_id != *asset_id {
        return Err(NodeError::PredecessorAssetMismatch);
    }
    if selector >= NODE_OUTPUTS
        || predecessor.statement.output_commitments[selector] != coin.commitment()
    {
        return Err(NodeError::PredecessorOutputMismatch);
    }
    let nf = coin.nullifier(osk);

    let config = CoinRecursionConfig::new(&coin_fri_params());
    let (circuit, pred) = build_redeem_circuit(&config, predecessor)?;
    let verification_keys = [verification_key_identity(predecessor)];
    let s = setup_circuit_with_verification_keys::<STATEMENT_ELEMS>(
        circuit,
        &coin_fri_params(),
        &verification_keys,
    )?;

    // Private inputs: own witness, then the predecessor verifier privates.
    let mut private_values = Vec::new();
    private_values.extend(asset_id.to_elems().iter().map(|&x| EF::from(x)));
    private_values.extend(u64_to_felts(coin.value).iter().map(|&x| EF::from(x)));
    private_values.extend(coin.owner.to_elems().iter().map(|&x| EF::from(x)));
    private_values.extend(coin.randomness.to_elems().iter().map(|&x| EF::from(x)));
    private_values.extend(crate::hash::osk_felts(osk).iter().map(|&x| EF::from(x)));
    private_values.push(EF::from(BabyBear::new(selector as u32)));

    // Public inputs: the predecessor verifier publics (statement instance
    // public values + proof targets + common data).
    let stmt_pvs = predecessor
        .statement_public_values()
        .ok_or(NodeError::MissingStatement)?;
    let mut table_pvs: Vec<Vec<BabyBear>> = vec![Vec::new(); pred.stmt_instance];
    table_pvs.push(stmt_pvs.to_vec());
    let public_values = pred.verifier_inputs.pack_public_values(
        &table_pvs,
        &predecessor.proof.proof,
        &predecessor.proof.stark_common,
    );
    private_values.extend(
        pred.verifier_inputs
            .pack_private_values(&predecessor.proof.proof),
    );

    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&public_values)?;
    runner.set_private_inputs(&private_values)?;
    CoinRecursionConfig::set_fri_private_data(
        &mut runner,
        &pred.op_ids,
        &predecessor.proof.proof.opening_proof,
    )
    .map_err(NodeError::FriPrivateData)?;
    let traces = runner.run()?;

    let prover = new_prover::<STATEMENT_ELEMS>(&s.config, s.table_packing.clone(), true);
    let circuit_prover_data = lock_setup(&s.circuit_prover_data);
    let proof = prover.prove_all_tables(&traces, &circuit_prover_data)?;

    Ok(CoinProof {
        version: COIN_PROOF_VERSION,
        mode: NodeMode::Redeem,
        statement: NodeStatement {
            asset_id: *asset_id,
            value: coin.value,
            mint_commit: Digest::from_bytes([0u8; 32]),
            nullifiers: [nf, Digest::from_bytes([0u8; 32])],
            output_commitments: [Digest::from_bytes([0u8; 32]); NODE_OUTPUTS],
        },
        proof,
    })
}

#[cfg(test)]
mod verification_key_binding_tests {
    use super::*;
    use p3_field::BasedVectorSpace;

    fn run_key_binding(actual: EF, expected: EF) -> Result<(), NodeError> {
        let mut builder = CircuitBuilder::<EF>::new();
        let target = builder.public_input();
        let relayed = relay_base_public_input(&mut builder, target)?;
        let expected = builder.define_const(expected);
        let difference = builder.sub(relayed, expected);
        builder.assert_zero(difference);

        let circuit = builder.build()?;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[actual])?;
        runner.run()?;
        Ok(())
    }

    #[test]
    fn predecessor_key_binding_accepts_the_expected_commitment_element() {
        run_key_binding(EF::ONE, EF::ONE).expect("matching predecessor key element must bind");
    }

    #[test]
    fn predecessor_key_binding_rejects_a_different_commitment_element() {
        let error = run_key_binding(EF::ONE, EF::ZERO)
            .expect_err("foreign predecessor key element must not bind");
        assert!(matches!(error, NodeError::Circuit(_)));
    }

    #[test]
    fn predecessor_key_binding_rejects_non_base_extension_coefficients() {
        let non_base = EF::from_basis_coefficients_slice(&[
            BabyBear::ONE,
            BabyBear::ONE,
            BabyBear::ZERO,
            BabyBear::ZERO,
        ])
        .expect("quartic extension has four coefficients");
        let error = run_key_binding(non_base, EF::ONE)
            .expect_err("predecessor key elements must be base-field embedded");
        assert!(matches!(error, NodeError::Circuit(_)));
    }
}

/// Verify a redeem proof: a mode-checked wrapper around
/// [`verify_coin_proof`] (statement-table comparison, then native batch-STARK
/// verification). The expected statement must have `value` equal to the
/// burned amount, `nullifiers[0]` equal to the published nullifier, and zero
/// `mint_commit` / `nullifiers[1]` / `output_commitments`.
pub fn verify_redeem(expected: &NodeStatement, proof: &RedeemProof) -> Result<(), NodeError> {
    if proof.mode != NodeMode::Redeem {
        return Err(NodeError::StatementMismatch);
    }
    verify_coin_proof(expected, proof)
}
