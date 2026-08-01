//! Shared proving/verifying plumbing for this crate's circuits (table
//! packing, AIR/preprocessed setup, prover construction), factored out of
//! the stage-1 opening circuit.

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

use crate::EF;

/// Prover-side data for a built circuit (shared shape across all circuits
/// in this crate: Poseidon2 + recompose tables, standard profile).
pub(crate) struct Setup {
    /// The built circuit.
    pub circuit: Circuit<EF>,
    /// The STARK config (benchmark-grade FRI parameters — see `README.md`).
    pub stark_config: BabyBearConfig,
    /// The table packing used for proving (carried in the proof).
    pub table_packing: TablePacking,
    /// Preprocessed prover data (rebuilt per proof at this stage).
    pub circuit_prover_data: CircuitProverData<BabyBearConfig>,
}

/// Build the prover-side AIR/preprocessed data for `circuit`.
pub(crate) fn setup(circuit: Circuit<EF>) -> Result<Setup, CircuitError> {
    let stark_config = baby_bear();
    let table_packing = TablePacking::new(2, 2);

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
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

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
