//! Statement table: a non-primitive op (NPO) that exposes the unified node
//! circuit's public statement as **STARK instance public values**, closing the
//! public-input binding gap of the pinned upstream stack (see `README.md`).
//!
//! # Why this exists
//!
//! At the pinned upstream commit, a circuit's "public inputs" ride the
//! witness bus: the Public table sends them but no AIR constrains them and no
//! table exposes STARK instance public values, so a batch-STARK circuit proof
//! only attests satisfiability for *some* public inputs. That is fine for the
//! standalone stage-1/2 circuits (the statement is carried in the proof
//! struct and compared), but PCD chaining needs a successor circuit to
//! *cryptographically* bind a predecessor's statement in-circuit.
//!
//! Non-primitive tables *can* carry instance public values
//! (`NonPrimitiveTableEntry.public_values`): they are observed into the
//! Fiat-Shamir transcript by both the native and the in-circuit verifier, and
//! the in-circuit verifier allocates them as parent-circuit targets
//! (`BatchStarkVerifierInputsBuilder::allocate`), which the parent can
//! `connect`. This module implements a minimal table that uses that channel:
//!
//! - the op reads the `N` statement expressions (witnesses) of the node
//!   circuit;
//! - the trace holds their `D = 4` base coefficients in a single row;
//! - the AIR **receives** each `(witness_index, value)` from the
//!   `WitnessChecks` bus (tying the row to the circuit's actual witness
//!   values) and constrains every cell against the instance public values
//!   (`mult · (cell − pv) = 0`, where `mult` is the receive multiplicity:
//!   `−1` on the single active row, `0` on padding).
//!
//! Soundness: the bus receive forces the row to equal the witnesses the
//! circuit actually used; the public-value constraints force the instance
//! public values to equal the row; the transcript binds the instance public
//! values. A cheating prover therefore cannot make a proof whose claimed
//! statement differs from what the circuit computed.

use std::fmt::Debug;
use std::marker::PhantomData;

use hashbrown::HashMap;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_circuit::builder::{NonPrimitiveOperationData, NpoCircuitPlugin, NpoLoweringContext};
use p3_circuit::ops::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitivePreprocessedMap, NpoConfig, NpoTypeId, Op,
    PreprocessedWriter,
};
use p3_circuit::tables::{NonPrimitiveTrace, TraceGeneratorFn, Traces};
use p3_circuit::{CircuitBuilderError, CircuitError, ExprId, PreprocessedColumns, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    BatchTableInstance, NonPrimitiveTableEntry, TableProver,
};
use p3_circuit_prover::common::{CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::{ConstraintProfile, DynamicAirEntry, TablePacking};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};
use p3_util::log2_ceil_usize;

use crate::EF;

/// The statement NPO type id.
pub(crate) fn statement_op_type() -> NpoTypeId {
    NpoTypeId::new("opencsv_statement")
}

// ============================================================================
// Circuit side: plugin + executor + trace
// ============================================================================

/// Execution state: the single statement row captured during execution.
#[derive(Debug, Default)]
struct StatementExecutionState<F: Field> {
    /// `Some` once the (single) statement op executed.
    row: Option<StatementRow<F>>,
}

/// One statement row: the read witness ids and their EF values.
#[derive(Debug, Clone)]
struct StatementRow<F: Field> {
    wids: Vec<WitnessId>,
    values: Vec<F>,
}

/// Executor for the statement op: reads the `N` statement witnesses and
/// records them for trace generation. Writes no outputs.
#[derive(Debug, Clone)]
struct StatementExecutor {
    op_type: NpoTypeId,
    n: usize,
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for StatementExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 || inputs[0].len() != self.n || !outputs.is_empty() {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("1 input group with {} witnesses, no outputs", self.n),
                got: inputs.len(),
            });
        }
        let wids = inputs[0].clone();
        let mut values = Vec::with_capacity(self.n);
        for &wid in &wids {
            values.push(ctx.get_witness(wid)?);
        }
        let state = ctx.get_op_state_mut::<StatementExecutionState<F>>(&self.op_type);
        state.row = Some(StatementRow { wids, values });
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<F>,
    ) -> Result<(), CircuitError> {
        // Register the statement witnesses as reads: appends their D-scaled
        // indices to the op's preprocessed data and increments their read
        // counts (so the Witness table's send side accounts for our receives).
        preprocessed.register_non_primitive_witness_reads(&self.op_type, &inputs[0])
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        Some(0)
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Circuit-layer plugin for the statement NPO.
pub(crate) struct StatementCircuitPlugin<const N: usize>;

impl<const N: usize> StatementCircuitPlugin<N> {
    /// Create the plugin for a statement of `N` field elements.
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl<const N: usize> Debug for StatementCircuitPlugin<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatementCircuitPlugin")
            .field("n", &N)
            .finish()
    }
}

impl<const N: usize> NpoCircuitPlugin<EF> for StatementCircuitPlugin<N> {
    fn type_id(&self) -> NpoTypeId {
        statement_op_type()
    }

    fn lower(
        &self,
        data: &NonPrimitiveOperationData<EF>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, EF>,
    ) -> Result<Op<EF>, CircuitBuilderError> {
        if !output_exprs.is_empty() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Statement",
                expected: "no outputs".into(),
                got: output_exprs.len(),
            });
        }
        if data.input_exprs.len() != 1 || data.input_exprs[0].len() != N {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Statement",
                expected: format!("1 input group with {N} statement elements"),
                got: data.input_exprs.len(),
            });
        }
        let wids: Vec<WitnessId> = data.input_exprs[0]
            .iter()
            .enumerate()
            .map(|(i, &expr)| ctx.resolve_witness_id(expr, || format!("Statement element {i}")))
            .collect::<Result<_, _>>()?;
        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![wids],
            outputs: vec![],
            executor: Box::new(StatementExecutor {
                op_type: statement_op_type(),
                n: N,
            }),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<EF> {
        generate_statement_trace::<EF, N>
    }

    fn config(&self) -> NpoConfig {
        NpoConfig::new(())
    }
}

/// Trace for the statement op: one row of `N × D` base-field cells.
#[derive(Debug, Clone)]
pub struct StatementTrace<F> {
    /// Witness ids of the `N` statement elements.
    pub wids: Vec<WitnessId>,
    /// `N × D` base-field coefficient values (row-major, D coeffs per element).
    pub values: Vec<F>,
}

impl<F: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for StatementTrace<F> {
    fn op_type(&self) -> NpoTypeId {
        statement_op_type()
    }

    fn rows(&self) -> usize {
        1
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

/// Trace generator for the statement NPO (registered with the circuit).
pub fn generate_statement_trace<E, const N: usize>(
    op_states: &p3_circuit::ops::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<E>>>, CircuitError>
where
    E: Field + ExtensionField<BabyBear>,
{
    let Some(state) = op_states
        .get(&statement_op_type())
        .and_then(|s| s.downcast_ref::<StatementExecutionState<E>>())
    else {
        return Ok(None);
    };
    let Some(row) = &state.row else {
        return Ok(None);
    };
    let mut values = Vec::with_capacity(N * 4);
    for v in &row.values {
        values.extend_from_slice(v.as_basis_coefficients_slice());
    }
    Ok(Some(Box::new(StatementTrace {
        wids: row.wids.clone(),
        values,
    })))
}

// ============================================================================
// AIR
// ============================================================================

/// AIR for the statement table: a single active row of `N × D` cells.
///
/// - **Main columns** (`N × D`): base coefficients of the `N` statement
///   elements.
/// - **Preprocessed columns** (`2 × N`): per element `(witness_idx, mult)`,
///   with `mult = −1` (one receive) on the active row and `0` on padding.
/// - **Public values** (`N × D`): the claimed statement, constrained
///   cell-by-cell: `mult_e · (cell − pv) = 0`.
/// - **Interactions**: per element, receive `(witness_idx, coeffs…)` from the
///   `WitnessChecks` bus with count `mult_e`.
#[derive(Debug, Clone)]
pub struct StatementAir<F, const D: usize, const N: usize> {
    /// Flat `[idx, mult]` pairs, `2N` values.
    preprocessed: Vec<F>,
    min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field, const D: usize, const N: usize> StatementAir<F, D, N> {
    /// Create the AIR from flat `[idx, mult]` preprocessed pairs.
    pub fn new(preprocessed: Vec<F>, min_height: usize) -> Self {
        Self {
            preprocessed,
            min_height,
            _phantom: PhantomData,
        }
    }

    /// Number of preprocessed columns (`2` per statement element).
    pub const fn preprocessed_width_const() -> usize {
        2 * N
    }

    /// Build the main trace matrix (one row) from the `N × D` cell values.
    pub fn trace_to_matrix(values: &[F], min_height: usize) -> RowMajorMatrix<F> {
        assert_eq!(values.len(), N * D, "statement trace cell count");
        let mut mat = RowMajorMatrix::new(values.to_vec(), N * D);
        mat.pad_to_min_power_of_two_height(min_height.max(1), F::ZERO);
        mat
    }
}

impl<F: Field, const D: usize, const N: usize> BaseAir<F> for StatementAir<F, D, N> {
    fn width(&self) -> usize {
        N * D
    }

    fn num_public_values(&self) -> usize {
        N * D
    }

    fn preprocessed_width(&self) -> usize {
        Self::preprocessed_width_const()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut mat = RowMajorMatrix::from_flat_padded(self.preprocessed.clone(), 2 * N, F::ZERO);
        mat.pad_to_min_power_of_two_height(self.min_height.max(1), F::ZERO);
        Some(mat)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder + InteractionBuilder, const D: usize, const N: usize> Air<AB>
    for StatementAir<AB::F, D, N>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|&v| v.into()).collect();

        for e in 0..N {
            let idx: AB::Expr = prep_local[2 * e].into();
            let mult: AB::Expr = prep_local[2 * e + 1].into();

            // Receive (witness_idx, coeffs) from the witness bus: ties this
            // row's cells to the circuit's actual witness values.
            let mut fields: Vec<AB::Expr> = Vec::with_capacity(1 + D);
            fields.push(idx);
            for j in 0..D {
                fields.push(main_local[e * D + j].into());
            }
            builder.push_interaction("WitnessChecks", fields, Count::bounded(mult.clone(), 1));

            // Constrain the row's cells against the instance public values
            // (mult = −1 on the active row, 0 on padding).
            for j in 0..D {
                let cell: AB::Expr = main_local[e * D + j].into();
                let pv = pvs[e * D + j].clone();
                builder.assert_zero(mult.clone() * (cell - pv));
            }
        }
    }
}

impl<SC, const D: usize, const N: usize> p3_circuit_prover::batch_stark_prover::BatchAir<SC>
    for StatementAir<Val<SC>, D, N>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

// ============================================================================
// Prover side: preprocessor, air builder, table prover
// ============================================================================

/// [`NpoPreprocessor`] for the statement table: converts the `N` registered
/// read indices into the `[idx, mult]` layout with `mult = −1`.
pub(crate) struct StatementPreprocessor;

impl NpoPreprocessor<BabyBear> for StatementPreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn std::any::Any,
        preprocessed: &mut dyn std::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<BabyBear>, CircuitError> {
        let mut result = HashMap::new();
        let Some(prep) = preprocessed
            .downcast_ref::<PreprocessedColumns<BinomialExtensionField<BabyBear, 4>, 4>>()
        else {
            return Ok(result);
        };
        let Some(ef_data) = prep.non_primitive.get(&statement_op_type()) else {
            return Ok(result);
        };
        if ef_data.is_empty() {
            return Ok(result);
        }
        let mut flat = Vec::with_capacity(ef_data.len() * 2);
        for v in ef_data {
            let idx = v.as_base().ok_or(CircuitError::InvalidPreprocessedValues)?;
            flat.push(idx);
            flat.push(BabyBear::ZERO - BabyBear::ONE); // one receive per element
        }
        result.insert(statement_op_type(), flat);
        Ok(result)
    }
}

/// [`NpoAirBuilder`] for the statement table.
pub(crate) struct StatementAirBuilder<const D: usize, const N: usize>;

impl<SC, const D: usize, const N: usize> NpoAirBuilder<SC, D> for StatementAirBuilder<D, N>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        if op_type.as_str() != statement_op_type().as_str() {
            return None;
        }
        assert_eq!(
            prep_base.len(),
            2 * N,
            "statement preprocessed data must be 2N values"
        );
        let air = StatementAir::<Val<SC>, D, N>::new(prep_base.to_vec(), min_height);
        let padded = min_height.max(1).next_power_of_two();
        let degree = log2_ceil_usize(padded);
        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}

/// [`TableProver`] for the statement table.
pub(crate) struct StatementProver<const D: usize, const N: usize>;

impl<const D: usize, const N: usize> StatementProver<D, N> {
    /// Create the prover for a statement of `N` elements.
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl<const D: usize, const N: usize> StatementProver<D, N> {
    fn build_instance<SC, CF>(
        &self,
        packing: &TablePacking,
        traces: &Traces<CF>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let trace = traces.non_primitive_traces.get(&statement_op_type())?;
        let t = trace.as_any().downcast_ref::<StatementTrace<Val<SC>>>()?;
        let min_height = packing.min_trace_height();

        // Preprocessed `[idx, −1]` pairs, mirroring `StatementPreprocessor`.
        let mut prep = Vec::with_capacity(2 * N);
        for wid in &t.wids {
            prep.push(wid.base_field_index::<Val<SC>, D>());
            prep.push(Val::<SC>::ZERO - Val::<SC>::ONE);
        }

        let air = StatementAir::<Val<SC>, D, N>::new(prep, min_height);
        let matrix = StatementAir::<Val<SC>, D, N>::trace_to_matrix(&t.values, min_height);

        Some(BatchTableInstance {
            op_type: statement_op_type(),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: t.values.clone(),
            rows: 1,
            lanes: 1,
        })
    }
}

impl<SC, const D: usize, const N: usize> TableProver<SC> for StatementProver<D, N>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        statement_op_type()
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.build_instance(packing, traces)
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.build_instance(packing, traces)
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.build_instance(packing, traces)
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.build_instance(packing, traces)
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.build_instance(packing, traces)
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _circuit_extension_degree: u32,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        // Shape-only AIR for verification: preprocessed data comes from the
        // proof's committed preprocessed openings; only widths matter here.
        let air = StatementAir::<Val<SC>, D, N>::new(Vec::new(), 1);
        Ok(DynamicAirEntry::new(Box::new(air)))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        _circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        let air = StatementAir::<Val<SC>, D, N>::new(committed_prep, min_height);
        Some(DynamicAirEntry::new(Box::new(air)))
    }
}
