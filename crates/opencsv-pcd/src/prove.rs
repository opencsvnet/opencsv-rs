//! Shared proving/verifying plumbing for this crate's circuits (table
//! packing, AIR/preprocessed setup, prover construction), factored out of
//! the stage-1 opening circuit.

use std::sync::OnceLock;

use p3_baby_bear::BabyBear;
use p3_batch_stark::ProverData;
use p3_circuit::ops::Poseidon2Config;
use p3_circuit::Circuit;
use p3_circuit::CircuitError;
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{get_airs_and_degrees_with_prep, NpoPreprocessor};
use p3_circuit_prover::config::{baby_bear, BabyBearConfig};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};

use crate::setup_cache::{CachedSetup, SetupCache, SetupIdentity};
use crate::EF;

const SETUP_CACHE_CAPACITY: usize = 8;

type BaseCircuitProverData = CircuitProverData<BabyBearConfig>;

fn setup_cache() -> &'static SetupCache<BaseCircuitProverData> {
    static CACHE: OnceLock<SetupCache<BaseCircuitProverData>> = OnceLock::new();
    CACHE.get_or_init(|| SetupCache::new(SETUP_CACHE_CAPACITY))
}

/// Prover-side data for a built circuit (shared shape across all circuits
/// in this crate: Poseidon2 + recompose tables, standard profile).
pub(crate) struct Setup {
    /// The built circuit.
    pub circuit: Circuit<EF>,
    /// The STARK config (benchmark-grade FRI parameters — see `README.md`).
    pub stark_config: BabyBearConfig,
    /// The table packing used for proving (carried in the proof).
    pub table_packing: TablePacking,
    /// Preprocessed prover data shared by complete setup identity.
    pub circuit_prover_data: CachedSetup<BaseCircuitProverData>,
}

/// Build or reuse prover-side AIR/preprocessed data for `circuit`.
///
/// The key covers the complete circuit structure, table packing, registered
/// AIR set, constraint profile, STARK configuration family, and pinned
/// upstream revision. Callers must hold the returned setup lock while using
/// its upstream mutable precomputation data.
pub(crate) fn setup(circuit: Circuit<EF>) -> Result<Setup, CircuitError> {
    let stark_config = baby_bear();
    let table_packing = TablePacking::new(2, 2);
    let packing_identity = format!("{table_packing:?}");
    let identity = SetupIdentity::for_circuit(
        b"base-baby-bear",
        &circuit,
        &[
            packing_identity.as_bytes(),
            b"poseidon2-d4-w16/recompose-d4-limb1/constraint-standard",
            b"p3-circuit-prover/baby_bear-default",
        ],
        &[],
    );

    let circuit_prover_data = setup_cache().get_or_try_insert_with(
        identity,
        || -> Result<BaseCircuitProverData, CircuitError> {
            let npo_prep: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
                Box::new(Poseidon2Preprocessor),
                Box::new(RecomposePreprocessor::default()),
            ];
            let mut air_builders = poseidon2_air_builders::<BabyBearConfig, 4>();
            air_builders.extend(recompose_air_builders(1, false));
            let (airs_degrees, primitive_columns, non_primitive_columns) =
                get_airs_and_degrees_with_prep::<BabyBearConfig, _, 4>(
                    &circuit,
                    &table_packing,
                    &npo_prep,
                    &air_builders,
                    ConstraintProfile::Standard,
                )?;
            let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
            let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
            Ok(CircuitProverData::new(
                prover_data,
                primitive_columns,
                non_primitive_columns,
            ))
        },
    )?;

    Ok(Setup {
        circuit,
        stark_config,
        table_packing,
        circuit_prover_data,
    })
}

/// Construct a `BatchStarkProver` with the tables these circuits use.
pub(crate) fn new_prover(
    config: BabyBearConfig,
    packing: TablePacking,
) -> BatchStarkProver<BabyBearConfig> {
    let mut prover = BatchStarkProver::new(config).with_table_packing(packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(false);
    prover
}
