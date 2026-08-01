//! Coin commitment opening circuit (stage 1, non-recursive).
//!
//! Proves knowledge of `(asset_id, v, owner, r)` such that
//!
//! ```text
//! C = H("coin" ∥ asset_id ∥ v ∥ owner ∥ r)
//! ```
//!
//! reproducing [`opencsv-core`]'s `hash_felts` semantics in-circuit:
//!
//! - the hash input is `[N] ∥ domain_felts ∥ parts…` with `N = 30`
//!   (`2` domain elements `"coin"` + `8 + 3 + 8 + 8` opening elements);
//! - the sponge is Poseidon2 `PaddingFreeSponge` over BabyBear, width 16 /
//!   rate 8 / digest 8, in **overwrite** mode: each row of the circuit
//!   overwrites the rate portion of the state with the next chunk and
//!   permutes; the 30-element input is absorbed as three full 8-element
//!   chunks plus one partial 6-element chunk (the two leftover rate slots
//!   keep the previous permutation output, exactly like the native sponge);
//! - the digest is the rate portion of the final state, connected to the
//!   8 public inputs.
//!
//! # Why the circuit field is the quartic extension
//!
//! The upstream batch-STARK prover at the pinned commit only supports
//! Poseidon2 tables for extension degrees `D ∈ {2, 4, 5}` (there is no
//! `RegisterPoseidon2ForExt<1>` impl and BabyBear has no binomial quadratic
//! extension), so the circuit runs over `BinomialExtensionField<BabyBear, 4>`
//! with the `BABY_BEAR_D4_W16` config: the 16-element BabyBear state is
//! packed into 4 extension limbs (limb `i` ↔ state `4i..4i+4`). All public /
//! private inputs are base field elements embedded in the extension field
//! (only the constant coefficient non-zero), recomposed into limbs; the
//! partial final chunk mixes the two absorbed elements with the two leftover
//! coefficients of the previous row's output (decompose/recompose), which is
//! exactly the native overwrite semantics. This mirrors the absorption
//! pattern in the upstream recursion crate (`recursion/src/pcs/mmcs.rs`).

use opencsv_core::{Coin, Digest};
use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear};
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, CircuitError};
use p3_circuit_prover::batch_stark_prover::{BatchStarkProof, BatchStarkProverError};
use p3_circuit_prover::config::{baby_bear, BabyBearConfig};
use p3_poseidon2_circuit_air::BabyBearD4Width16;

use crate::hash::{connect_digest, hash_felts_limbs};
use crate::prove::{new_prover, setup};
use crate::value::u64_to_felts;
use crate::{DIGEST_ELEMS, EF};

/// Number of public inputs: the commitment digest, 8 BabyBear elements
/// (each embedded in [`EF`]).
pub const PUBLIC_ELEMS: usize = DIGEST_ELEMS; // 8
/// Number of private witness elements: asset_id (8) + v (3) + owner (8) + r (8).
pub const PRIVATE_ELEMS: usize = 27;

/// Errors from proving or verifying a commitment opening.
#[derive(Debug)]
pub enum OpeningError {
    /// Circuit construction failed.
    Builder(CircuitBuilderError),
    /// Witness generation / circuit execution failed (e.g. the witness does
    /// not satisfy the `C = H(…)` constraint).
    Circuit(CircuitError),
    /// STARK proving or verification failed.
    Prover(BatchStarkProverError),
    /// The commitment embedded in the proof does not match the expected one.
    CommitmentMismatch,
}

impl std::fmt::Display for OpeningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Builder(e) => write!(f, "circuit build error: {e}"),
            Self::Circuit(e) => write!(f, "circuit execution error: {e}"),
            Self::Prover(e) => write!(f, "STARK prover error: {e}"),
            Self::CommitmentMismatch => {
                write!(f, "proof commitment does not match the expected digest")
            }
        }
    }
}

impl std::error::Error for OpeningError {}

impl From<CircuitBuilderError> for OpeningError {
    fn from(e: CircuitBuilderError) -> Self {
        Self::Builder(e)
    }
}

impl From<CircuitError> for OpeningError {
    fn from(e: CircuitError) -> Self {
        Self::Circuit(e)
    }
}

impl From<BatchStarkProverError> for OpeningError {
    fn from(e: BatchStarkProverError) -> Self {
        Self::Prover(e)
    }
}

/// Embed a base field element into the circuit (extension) field.
fn embed(x: BabyBear) -> EF {
    EF::from(x)
}

/// The private opening of a coin commitment, encoded as field elements in
/// absorption order (matching `opencsv-core`'s encodings).
#[derive(Clone, Debug)]
pub struct CoinWitness {
    /// `asset_id` digest elements.
    pub asset_id: [BabyBear; DIGEST_ELEMS],
    /// `v` as three little-endian 24-bit limbs.
    pub value_limbs: [BabyBear; 3],
    /// `owner` digest elements.
    pub owner: [BabyBear; DIGEST_ELEMS],
    /// `r` (hiding randomness) digest elements.
    pub randomness: [BabyBear; DIGEST_ELEMS],
}

impl CoinWitness {
    /// Encode a coin's opening exactly as `Coin::commitment` absorbs it.
    pub fn from_coin(coin: &Coin) -> Self {
        Self {
            asset_id: coin.asset_id.to_elems(),
            value_limbs: u64_to_felts(coin.value),
            owner: coin.owner.to_elems(),
            randomness: coin.randomness.to_elems(),
        }
    }

    /// Flatten to the 27-element private input vector in absorption order.
    fn to_elems(&self) -> [BabyBear; PRIVATE_ELEMS] {
        let mut out = [BabyBear::default(); PRIVATE_ELEMS];
        out[0..8].copy_from_slice(&self.asset_id);
        out[8..11].copy_from_slice(&self.value_limbs);
        out[11..19].copy_from_slice(&self.owner);
        out[19..27].copy_from_slice(&self.randomness);
        out
    }
}

/// A proof of knowledge of an opening of the coin commitment `commitment`.
pub struct OpeningProof {
    /// The commitment the circuit proved an opening for (the public inputs,
    /// in allocation order). See the crate-level docs for the binding caveat.
    pub commitment: [BabyBear; DIGEST_ELEMS],
    /// The batch-STARK proof over the circuit's tables.
    pub proof: BatchStarkProof<BabyBearConfig>,
}

/// Build the opening circuit: 8 public inputs (the commitment), 27 private
/// inputs (the opening), 4 Poseidon2 sponge rows (via the shared
/// [`crate::hash`] helpers), digest connected to the public inputs.
fn build_circuit() -> Result<Circuit<EF>, OpeningError> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<EF, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);

    let public = builder.alloc_public_inputs(PUBLIC_ELEMS, "commitment");
    let private = builder.alloc_private_inputs(PRIVATE_ELEMS, "opening");

    // Absorption vector: [N] ∥ "coin" ∥ asset_id ∥ v ∥ owner ∥ r (29 elements
    // after the prefix, absorbed as 3 full chunks + 1 partial of 6 elements).
    let rate = hash_felts_limbs(&mut builder, "coin", &[&private])?;
    connect_digest(&mut builder, rate, &public)?;

    Ok(builder.build()?)
}

/// Prove knowledge of the opening of `coin`'s commitment.
///
/// Computes `C = coin.commitment()` off-circuit (via `opencsv-core`) and
/// proves in-circuit that the opening hashes to `C`.
pub fn prove_opening(coin: &Coin) -> Result<OpeningProof, OpeningError> {
    let commitment = coin.commitment();
    let witness = CoinWitness::from_coin(coin);
    prove_opening_raw(&commitment.to_elems(), &witness)
}

/// Prove that `witness` hashes to `commitment` (low-level entry point).
///
/// Unlike [`prove_opening`], the commitment is supplied explicitly; witness
/// generation fails with [`OpeningError::Circuit`] if the witness does not
/// hash to it. Exposed for negative tests and for later stages that prove
/// statements about commitments computed elsewhere.
#[doc(hidden)]
pub fn prove_opening_raw(
    commitment: &[BabyBear; DIGEST_ELEMS],
    witness: &CoinWitness,
) -> Result<OpeningProof, OpeningError> {
    let s = setup(build_circuit()?)?;

    let public_values: Vec<EF> = commitment.iter().copied().map(embed).collect();
    let private_values: Vec<EF> = witness.to_elems().into_iter().map(embed).collect();

    let mut runner = s.circuit.runner();
    runner.set_public_inputs(&public_values)?;
    runner.set_private_inputs(&private_values)?;
    let traces = runner.run()?;

    let prover = new_prover(s.stark_config, s.table_packing);
    let proof = prover.prove_all_tables(&traces, &s.circuit_prover_data)?;

    Ok(OpeningProof {
        commitment: *commitment,
        proof,
    })
}

/// Verify a proof of knowledge of an opening of `expected_commitment`.
///
/// Checks that the commitment embedded in the proof equals
/// `expected_commitment`, then verifies the batch-STARK proof.
///
/// Note: at the pinned upstream commit the standalone verifier proves
/// satisfiability of the circuit for *some* public inputs; the commitment
/// carried in [`OpeningProof`] is the value the prover used, compared here
/// for equality. Cryptographic binding of the public inputs arrives with the
/// recursion stage (see crate-level docs).
pub fn verify_opening(
    expected_commitment: &Digest,
    opening: &OpeningProof,
) -> Result<(), OpeningError> {
    if expected_commitment.to_elems() != opening.commitment {
        return Err(OpeningError::CommitmentMismatch);
    }

    let prover = new_prover(baby_bear(), opening.proof.table_packing.clone());
    prover.verify_all_tables::<EF>(&opening.proof)?;
    Ok(())
}
