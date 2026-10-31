//! Fixed native g_bound feasibility through the maintained wallet phase planner.
//! The original caller must fund planner backing and seal execution selection
//! before this function. It constructs no engine, proof, or dispatch capability.
use super::{runtime_geometry::RuntimeGeometry, *};
use crate::block_v2::quotient_program::{MAX_CONSTRAINTS, MAX_NODES, WORDS_PER_INSTRUCTION};
use core::mem::size_of;
use crate::block_v2::native_gpu::g_bound_preparation::{GBoundGeometry, GBoundDescriptor};

mod transfer_storage;

#[cfg(feature = "ringct-research-quota")]
mod owned;
#[cfg(feature = "ringct-research-quota")]
pub(crate) use owned::GBoundDeviceLease;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct GBoundDeviceCensus {
    source: GBoundGeometry,
    #[serde(skip)]
    runtime: RuntimeGeometry,
    #[serde(skip)]
    trees: engine::retained_storage::Selection,
    rows: usize,
    main_width: usize,
    operation_host_bytes: usize,
    managed_ceiling_bytes: usize,
    runtime_baseline_bytes: usize,
    maximum_planned_phase_bytes: usize,
    allocation_ceiling_bytes: usize,
    quotient_partitions: usize,
    source_instruction_words: usize,
}

impl GBoundDeviceCensus {
    /// Covers all five allowed quotient partitions using maximum recorded
    /// compiler geometry, without evaluating AIR constants or guessing the
    /// normalized degree. The ordinary phase planner's temporary allocations
    /// have the same original reservation as its later runtime invocation.
    /// This temporary plan is destroyed before startup, so they do not coexist.
    pub(crate) fn new(
        source: GBoundGeometry,
        operation_host_bytes: usize,
        limits: Limits,
        max_allocation: usize,
        slots: usize,
    ) -> Result<Self, String> {
        let (minimum, shape) = source_geometry(source, operation_host_bytes)?;
        let rows = source.rows();
        let main_width = source.width();
        minimum.check(limits.managed_bytes, max_allocation)?;
        let trees = engine::retained_storage::Selection::from_env()?;
        match (trees.mode, trees.host_bytes) {
            (engine::RetainedTreeStorageMode::Device, 0)
            | (engine::RetainedTreeStorageMode::HostBacking, 8589934592) => {}
            _ => {
                return Err(
                    "native g_bound requires a fixed device or outer_host_v1 tree profile".into(),
                )
            }
        }
        let runtime = RuntimeGeometry::fresh(limits, max_allocation, slots, 0)?;
        let plan = Plan::from_geometry(minimum, runtime)?;
        if plan.quotient_tiles.len() != 5
            || plan
                .quotient_tiles
                .iter()
                .zip([2, 4, 8, 16, 32])
                .any(|(tile, chunks)| tile.chunks != chunks || tile.rows == 0)
            || plan.phases.is_empty()
        {
            return Err("native g_bound maintained phase coverage changed".into());
        }
        let maximum_planned_phase_bytes = plan.phases.iter().map(|p| p.bytes).max().unwrap();
        if maximum_planned_phase_bytes > limits.managed_bytes {
            return Err("native g_bound maintained phase exceeds selected allowance".into());
        }
        Ok(Self {
            source,
            runtime,
            trees,
            rows,
            main_width,
            operation_host_bytes,
            // Runtime may choose larger adaptive tiles for an actual smaller
            // recording. Claim its complete existing managed capacity, not the
            // modeled minimum or this static plan's selected tiles.
            managed_ceiling_bytes: limits.managed_bytes,
            runtime_baseline_bytes: runtime.managed_baseline_bytes(),
            maximum_planned_phase_bytes,
            // This is deliberately the captured hardware/managed ceiling,
            // not a claim that an allocation of this size occurred.
            allocation_ceiling_bytes: max_allocation.min(limits.managed_bytes),
            quotient_partitions: plan.quotient_tiles.len(),
            source_instruction_words: shape.instruction_words,
        })
    }

    pub(crate) fn managed_ceiling_bytes(self) -> usize {
        self.managed_ceiling_bytes
    }

    pub(crate) fn tree_selection(self) -> engine::retained_storage::Selection {
        self.trees
    }

    pub(crate) fn maximum_planned_phase_bytes(self) -> usize {
        self.maximum_planned_phase_bytes
    }

    pub(crate) fn runtime_baseline_bytes(self) -> usize {
        self.runtime_baseline_bytes
    }

    pub(crate) fn allocation_ceiling_bytes(self) -> usize {
        self.allocation_ceiling_bytes
    }

    fn check_prepared_minimum(&self, actual: WalletProofMinimum) -> Result<(), String> {
        let (expected, maximum) =
            source_geometry(self.source, self.operation_host_bytes)?;
        check_minimum(expected, maximum, actual)
    }
}

fn check_minimum(
    expected: WalletProofMinimum,
    maximum: ProgramShape,
    actual: WalletProofMinimum,
) -> Result<(), String> {
    let program = actual
        .program
        .ok_or("native g_bound recording has no program shape")?;
    // Every non-program field must match exactly, including the private
    // constructor's simultaneous/largest minima and compact periodic shape.
    let mut shape = actual;
    shape.program = expected.program;
    if shape != expected
        || program.extension != maximum.extension
        || program.row_words != maximum.row_words
        || program.parameter_words != maximum.parameter_words
        || program.registers == 0
        || program.registers > maximum.registers
        || program.constraints == 0
        || program.constraints > maximum.constraints
        || program.instruction_words
            != (program.registers + program.constraints) * WORDS_PER_INSTRUCTION
        || program.instruction_words > maximum.instruction_words
    {
        return Err("native g_bound actual recording differs from its source model".into());
    }
    Ok(())
}

fn source_geometry(
    source: GBoundGeometry,
    operation_host_bytes: usize,
) -> Result<(WalletProofMinimum, ProgramShape), String> {
    let rows = source.rows();
    let main_width = source.width();
    let periodic_columns = source.periodic_columns();
    let expected = source.kind().geometry_tuple();
    if !cfg!(all(
        not(debug_assertions),
        target_os = "linux",
        target_arch = "x86_64",
        feature = "gpu-bounded-info"
    )) || (rows, main_width, source.public_values(), periodic_columns) != expected
        || !rows.is_power_of_two()
        || source.period() != 128 || source.rows() != 4096
        || operation_host_bytes == 0
        || operation_host_bytes > 24 << 30
        || profile::MAX_QUOTIENT_CHUNKS != 32
        || profile::LOG_BLOWUP != 4
        || profile::CAP_HEIGHT != 6
        || profile::NUM_QUERIES != 128
        || profile::NUM_RANDOM_CODEWORDS != 4
        || size_of::<profile::Challenge>() != 24
    {
        return Err("native g_bound source device geometry refused".into());
    }
    let shape = ProgramShape {
        extension: Extension::Cubic,
        instruction_words: (MAX_NODES + MAX_CONSTRAINTS) * WORDS_PER_INSTRUCTION,
        registers: MAX_NODES,
        constraints: MAX_CONSTRAINTS,
        row_words: 2 * (main_width + periodic_columns),
        parameter_words: source.public_values(),
    };
    let periodic = PeriodicShape::new(rows.ilog2(), std::iter::repeat_n(source.period(), periodic_columns))?;
    let minimum = WalletProofMinimum::new(rows, main_width, periodic_columns, Extension::Cubic)?
        .with_program(shape, operation_host_bytes)?
        .with_periodic(Some(periodic))?;
    Ok((minimum, shape))
}
