//! STARK configuration for the recursive (stage-3) node circuit.
//!
//! The stage-1/2 circuits use [`p3_circuit_prover::config::baby_bear`], whose
//! FRI parameters (`new_benchmark_high_arity`: 100 queries, 16 PoW bits) are
//! far too expensive to verify *in-circuit*. The recursive node circuit
//! instead proves and verifies under a single custom configuration with
//! recursion-friendly FRI parameters, mirroring the `ConfigWithFriParams`
//! pattern from the upstream `recursive_fibonacci` / `recursive_aggregation`
//! examples (BabyBear, quartic challenge extension, Poseidon2 MMCS and
//! challenger).
//!
//! **Security note:** the default parameters here are test-grade (a handful
//! of FRI queries, no proof-of-work) so that debug-profile tests finish; they
//! offer only a few bits of conjectured soundness. Production parameters must
//! be re-chosen (and the in-circuit verifier cost re-measured) before any of
//! this is relied upon.

use std::sync::{Arc, OnceLock};

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::{CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::config::StarkField;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::{
    set_fri_mmcs_private_data, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::{FriRecursionConfig, FriVerifierParams, Poseidon2Config, RecursionInput};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};

use crate::EF;

/// Poseidon2 width (state elements).
pub(crate) const WIDTH: usize = 16;
/// Poseidon2 sponge rate.
pub(crate) const RATE: usize = 8;
/// Merkle/Poseidon2 digest length in BabyBear elements.
pub(crate) const MERKLE_DIGEST_ELEMS: usize = 8;

pub(crate) type Perm = Poseidon2BabyBear<16>;
pub(crate) type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, MERKLE_DIGEST_ELEMS>;
pub(crate) type MyCompress = TruncatedPermutation<Perm, 2, MERKLE_DIGEST_ELEMS, WIDTH>;
pub(crate) type MyMmcs = MerkleTreeMmcs<
    <BabyBear as Field>::Packing,
    <BabyBear as Field>::Packing,
    MyHash,
    MyCompress,
    2,
    MERKLE_DIGEST_ELEMS,
>;
pub(crate) type ChallengeMmcs = ExtensionMmcs<BabyBear, EF, MyMmcs>;
pub(crate) type Challenger = DuplexChallenger<BabyBear, Perm, WIDTH, RATE>;
pub(crate) type MyPcs = TwoAdicFriPcs<BabyBear, Radix2DitParallel<BabyBear>, MyMmcs, ChallengeMmcs>;

/// The STARK config used for every recursive node proof (one shared "vk" per
/// unified node circuit).
pub type CoinStarkConfig = StarkConfig<MyPcs, EF, Challenger>;

type RecInputMmcs = RecValMmcs<BabyBear, MERKLE_DIGEST_ELEMS, MyHash, MyCompress>;
type InnerFri = p3_recursion::pcs::FriProofTargets<
    BabyBear,
    EF,
    RecExtensionValMmcs<BabyBear, EF, MERKLE_DIGEST_ELEMS, RecInputMmcs>,
    InputProofTargets<BabyBear, EF, RecInputMmcs>,
    p3_recursion::pcs::Witness<BabyBear>,
>;

/// FRI parameters for the recursive node circuit.
#[derive(Clone, Copy, Debug)]
pub struct CoinFriParams {
    /// Log₂ of the FRI blowup factor.
    pub log_blowup: usize,
    /// Log₂ of the maximum FRI folding arity.
    pub max_log_arity: usize,
    /// Height of the Merkle cap.
    pub cap_height: usize,
    /// Log₂ of the final polynomial length after folding.
    pub log_final_poly_len: usize,
    /// Number of FRI query rounds.
    pub num_queries: usize,
    /// PoW grinding bits at commit time.
    pub commit_proof_of_work_bits: usize,
    /// PoW grinding bits at query time.
    pub query_proof_of_work_bits: usize,
}

impl CoinFriParams {
    /// Test-grade parameters: cheap enough to verify in-circuit in a debug
    /// build, cryptographically meaningless (a few bits of conjectured
    /// soundness). See the module-level security note.
    pub const fn testing() -> Self {
        Self {
            log_blowup: 2,
            max_log_arity: 2,
            cap_height: 0,
            log_final_poly_len: 2,
            num_queries: 2,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
        }
    }
}

/// The full recursion configuration: a [`CoinStarkConfig`] plus the matching
/// [`FriVerifierParams`] for in-circuit verification.
#[derive(Clone)]
pub struct CoinRecursionConfig {
    config: Arc<CoinStarkConfig>,
    fri_verifier_params: FriVerifierParams,
}

impl CoinRecursionConfig {
    /// Build the config from FRI parameters.
    pub fn new(fp: &CoinFriParams) -> Self {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, fp.cap_height);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Radix2DitParallel::default();
        let fri_params = FriParameters {
            max_log_arity: fp.max_log_arity,
            log_blowup: fp.log_blowup,
            log_final_poly_len: fp.log_final_poly_len,
            num_queries: fp.num_queries,
            commit_proof_of_work_bits: fp.commit_proof_of_work_bits,
            query_proof_of_work_bits: fp.query_proof_of_work_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = MyPcs::new(dft, val_mmcs, fri_params);
        let challenger = Challenger::new(perm);
        let config = StarkConfig::new(pcs, challenger);
        let fri_verifier_params = FriVerifierParams::with_mmcs(
            fp.log_blowup,
            fp.log_final_poly_len,
            fp.commit_proof_of_work_bits,
            fp.query_proof_of_work_bits,
            fp.num_queries,
            Poseidon2Config::BABY_BEAR_D4_W16,
        );
        Self {
            config: Arc::new(config),
            fri_verifier_params,
        }
    }
}

impl core::ops::Deref for CoinRecursionConfig {
    type Target = CoinStarkConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl StarkGenericConfig for CoinRecursionConfig {
    type Challenge = EF;
    type Challenger = Challenger;
    type Pcs = MyPcs;
    fn pcs(&self) -> &Self::Pcs {
        self.config.pcs()
    }
    fn initialise_challenger(&self) -> Challenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for CoinRecursionConfig
where
    MyPcs: RecursivePcs<
        CoinRecursionConfig,
        InputProofTargets<BabyBear, EF, RecInputMmcs>,
        InnerFri,
        MerkleCapTargets<BabyBear, MERKLE_DIGEST_ELEMS>,
        <MyPcs as Pcs<EF, Challenger>>::Domain,
    >,
{
    type Commitment = MerkleCapTargets<BabyBear, MERKLE_DIGEST_ELEMS>;
    type InputProof = InputProofTargets<BabyBear, EF, RecInputMmcs>;
    type OpeningProof = InnerFri;
    type RawOpeningProof = <MyPcs as Pcs<EF, Challenger>>::Proof;
    const DIGEST_ELEMS: usize = MERKLE_DIGEST_ELEMS;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut p3_circuit::CircuitBuilder<Self::Challenge>,
    ) -> Result<(), p3_recursion::verifier::VerificationError> {
        use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
        use p3_poseidon2_circuit_air::BabyBearD4Width16;
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<EF, BabyBearD4Width16>,
            default_babybear_poseidon2_16(),
        );
        circuit.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<MyPcs as RecursivePcs<
        CoinRecursionConfig,
        InputProofTargets<BabyBear, EF, RecInputMmcs>,
        InnerFri,
        MerkleCapTargets<BabyBear, MERKLE_DIGEST_ELEMS>,
        <MyPcs as Pcs<EF, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, EF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_fri_mmcs_private_data::<
            BabyBear,
            EF,
            ChallengeMmcs,
            MyMmcs,
            MyHash,
            MyCompress,
            MERKLE_DIGEST_ELEMS,
        >(
            runner,
            op_ids,
            opening_proof,
            Poseidon2Config::BABY_BEAR_D4_W16,
        )
    }
}

/// Compile-time check that BabyBear satisfies the field bounds the recursion
/// stack requires.
const _: fn() = || {
    const fn assert_stark_field<T: StarkField>() {}
    assert_stark_field::<BabyBear>();
};

/// Ensure the challenge field is a based vector space over BabyBear (D = 4).
const _: fn() = || {
    fn assert_bvs<T: BasedVectorSpace<BabyBear>>() {}
    assert_bvs::<EF>();
};

// ============================================================================
// Shared proving plumbing for the recursive node circuit
// ============================================================================

use p3_batch_stark::ProverData;
use p3_circuit::Circuit;
use p3_circuit_prover::batch_stark_prover::recompose_air_builders;
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, TableProver};
use p3_circuit_prover::common::{get_airs_and_degrees_with_prep, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};

use crate::setup_cache::{CachedSetup, SetupCache, SetupIdentity};
use crate::statement::{StatementAirBuilder, StatementPreprocessor, StatementProver};

const RECURSIVE_SETUP_CACHE_CAPACITY: usize = 8;

type RecCircuitProverData = CircuitProverData<CoinRecursionConfig>;

fn recursive_setup_cache() -> &'static SetupCache<RecCircuitProverData> {
    static CACHE: OnceLock<SetupCache<RecCircuitProverData>> = OnceLock::new();
    CACHE.get_or_init(|| SetupCache::new(RECURSIVE_SETUP_CACHE_CAPACITY))
}

/// Prover-side data for a built recursive node circuit (statement size `N`).
pub(crate) struct RecSetup {
    /// The built circuit.
    pub circuit: Circuit<EF>,
    /// The recursion config (STARK config + FRI verifier params).
    pub config: CoinRecursionConfig,
    /// The table packing used for proving (carried in the proof).
    pub table_packing: TablePacking,
    /// Preprocessed prover data for this circuit shape (the "vk" side: the
    /// preprocessed commitment in `prover_data.common` binds the circuit).
    pub circuit_prover_data: CachedSetup<RecCircuitProverData>,
}

/// Build the prover-side AIR/preprocessed data for a recursive node circuit
/// with a statement table of `N` elements.
pub(crate) fn setup_circuit<const N: usize>(
    circuit: Circuit<EF>,
    fri_params: &CoinFriParams,
) -> Result<RecSetup, p3_circuit::CircuitError> {
    setup_circuit_with_verification_keys::<N>(circuit, fri_params, &[])
}

/// Build or reuse recursive prover data, including every predecessor
/// verification-key identity in the cache key. The predecessor keys are not
/// a substitute for D4's in-circuit hard binding; they prevent setup data
/// from being aliased across distinct verifier inputs before that boundary is
/// enforced.
pub(crate) fn setup_circuit_with_verification_keys<const N: usize>(
    circuit: Circuit<EF>,
    fri_params: &CoinFriParams,
    verification_keys: &[SetupIdentity],
) -> Result<RecSetup, p3_circuit::CircuitError> {
    let config = CoinRecursionConfig::new(fri_params);
    let table_packing = TablePacking::new(1, 3)
        .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
    let fri_identity = format!("{fri_params:?}");
    let packing_identity = format!("{table_packing:?}");
    let statement_identity = format!("statement-elements={N}");
    let identity = SetupIdentity::for_circuit(
        b"recursive-baby-bear",
        &circuit,
        &[
            fri_identity.as_bytes(),
            packing_identity.as_bytes(),
            statement_identity.as_bytes(),
            b"poseidon2-d4-w16/recompose-d4-limb1+coeff/statement-d4/constraint-standard",
        ],
        verification_keys,
    );

    let circuit_prover_data = recursive_setup_cache().get_or_try_insert_with(
        identity,
        || -> Result<RecCircuitProverData, p3_circuit::CircuitError> {
            let npo_prep: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
                Box::new(Poseidon2Preprocessor),
                Box::new(RecomposePreprocessor::new(true)),
                Box::new(StatementPreprocessor),
            ];
            let mut air_builders = poseidon2_air_builders::<CoinRecursionConfig, 4>();
            air_builders.extend(recompose_air_builders(1, true));
            air_builders.push(Box::new(StatementAirBuilder::<4, N>));
            let (airs_degrees, primitive_columns, non_primitive_columns) =
                get_airs_and_degrees_with_prep::<CoinRecursionConfig, _, 4>(
                    &circuit,
                    &table_packing,
                    &npo_prep,
                    &air_builders,
                    ConstraintProfile::Standard,
                )?;
            let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
            let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &degrees);
            Ok(CircuitProverData::new(
                prover_data,
                primitive_columns,
                non_primitive_columns,
            ))
        },
    )?;

    Ok(RecSetup {
        circuit,
        config,
        table_packing,
        circuit_prover_data,
    })
}

/// Construct a [`BatchStarkProver`] with the recursive node circuit's tables
/// (Poseidon2 + recompose + statement of size `N`).
pub(crate) fn new_prover<const N: usize>(
    config: &CoinRecursionConfig,
    packing: TablePacking,
    split_recompose_coefficients: bool,
) -> BatchStarkProver<CoinRecursionConfig> {
    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(split_recompose_coefficients);
    prover.register_table_prover(Box::new(StatementProver::<4, N>::new()));
    prover
}

/// The non-primitive table provers of a recursive node proof, in proof order
/// (must match the registration order in [`new_prover`]); used to reconstruct
/// the table AIRs for in-circuit verification.
pub(crate) fn node_table_provers<const N: usize>(
    split_recompose_coefficients: bool,
) -> Vec<Box<dyn TableProver<CoinRecursionConfig>>> {
    let mut provers: Vec<Box<dyn TableProver<CoinRecursionConfig>>> = vec![
        Box::new(p3_circuit_prover::Poseidon2Prover::new(
            Poseidon2Config::BABY_BEAR_D4_W16,
            ConstraintProfile::Standard,
        )),
        Box::new(p3_circuit_prover::RecomposeProver::<4>::new(1, false)),
    ];
    if split_recompose_coefficients {
        provers.push(Box::new(p3_circuit_prover::RecomposeProver::<4>::new(
            1, true,
        )));
    }
    provers.push(Box::new(StatementProver::<4, N>::new()));
    provers
}
