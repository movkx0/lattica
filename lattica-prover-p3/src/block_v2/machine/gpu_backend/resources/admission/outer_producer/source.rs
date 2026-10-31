//! Pre-native source ceilings for the fixed owned SHAKE compiler.
//!
//! Counts come from the closed source compiler in the enclosing owner. This
//! module never evaluates a hint, fabricates a Program, admits storage or
//! creates dispatch authority. Every possible packed row height is screened
//! using the existing complete phase planners and the captured runtime profile.
use super::{backing, inspect_bounds, OuterBackendFootprint, RegisteredGpuLimits};
use crate::block_v2::machine::{
    gpu_backend::resources::{admission::output, Bounds},
    gpu_program::{self, WitnessSchedule},
    program::{Op, Program, MAX_WIRES},
    verifier::batch::shape::OperationCounts,
};
use crate::config::Val;
use output::RegisteredGpuOutputFootprint;
use std::{alloc::Layout, mem::size_of, sync::atomic::AtomicUsize};

const PUBLIC_VALUES: usize = 46;
const PROGRAM_BYTES: usize = 2 << 30;
const INPUT_VALUES: usize = 1 << 20;
const FIRST_LOG: u32 = 3;
const LAST_LOG: u32 = 20;
const HEIGHTS: usize = (LAST_LOG - FIRST_LOG + 1) as usize;

mod continuation;
pub use continuation::PreissuedOuterBackend;

fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "outer source sum overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b)
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or_else(|| "outer source capacity overflow".into())
}

// Every supported count is at most 2^20. Keep the two meanings explicit in a
// private checked-width field; no pointer or high-bit tag is accepted as a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WitnessCount {
    Exact(u32),
    UpperBound(u32),
}
impl WitnessCount {
    fn maximum(self) -> usize {
        match self {
            Self::Exact(n) | Self::UpperBound(n) => n as usize,
        }
    }
    fn admits(self, actual: usize) -> bool {
        match self {
            Self::Exact(n) => actual == n as usize,
            Self::UpperBound(n) => actual <= n as usize,
        }
    }
}

/// Validated arithmetic only. This value does not prove where counts came from
/// and carries no source identity, reservation, proof or dispatch capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OuterSourceShape {
    public_values: usize,
    operations: OperationCounts,
    wires: usize,
    witness_values: WitnessCount,
    hint_words: usize,
    active_rows: usize,
    padded_rows: usize,
    instruction_bytes: usize,
    compiler_peak: usize,
    schedule_bytes: usize,
    source_bytes: usize,
}

impl OuterSourceShape {
    /// Output/key/verifier ceilings needed to claim those owners before native
    /// setup consumes the remaining PCS allowance. This is arithmetic only;
    /// complete backend feasibility still requires the full source envelope.
    pub fn output_footprint(self) -> Result<RegisteredGpuOutputFootprint, String> {
        let mut maximum = None;
        for log in FIRST_LOG..=self.padded_rows.ilog2() {
            let next =
                output::inspect_shape(self.public_values, 1usize << log, self.source_bytes as u64)?;
            maximum = Some(maximum.map_or(next, |prior| output_max(prior, next)));
        }
        maximum.ok_or_else(|| "outer source empty output census".into())
    }

    /// Only the unchanged 46-public, 2 GiB construction, 2^20-input compiler
    /// profile is supported. An enclosing source owner must independently bind
    /// these counts to its original request and compiler limits.
    pub fn owned_shake(
        operations: OperationCounts,
        wires_upper_bound: usize,
        witness_values: usize,
        selection_hint_words_upper_bound: usize,
    ) -> Result<Self, String> {
        Self::from_counts(PUBLIC_VALUES, operations, wires_upper_bound,
            witness_values, selection_hint_words_upper_bound)
    }

    fn from_counts(
        public_values: usize,
        operations: OperationCounts,
        wires_upper_bound: usize,
        witness_values: usize,
        selection_hint_words_upper_bound: usize,
    ) -> Result<Self, String> {
        if !cfg!(all(
            not(debug_assertions),
            target_arch = "x86_64",
            feature = "block-v2-wide-lanes"
        )) || size_of::<Val>() != 8
            || wires_upper_bound > MAX_WIRES
            || witness_values > INPUT_VALUES
            || add(public_values, witness_values)? > wires_upper_bound
        {
            return Err("outer source compiler profile refused".into());
        }
        let count = add(
            add(operations.scalar, operations.cubic)?,
            operations.poseidon,
        )?;
        if count > u32::MAX as usize {
            return Err("outer source operation count refused".into());
        }
        let active = operations
            .active_rows(public_values)
            .map_err(|_| "outer source active row overflow")?;
        let padded = operations
            .padded_rows(public_values)
            .map_err(|_| "outer source padded row overflow")?;
        if padded > 1 << LAST_LOG {
            return Err("outer source row ceiling exceeds fixed envelope".into());
        }
        // This is the actual GPU metadata layout, including hint payload and
        // partial rows. Padding contributes trace storage but no row records.
        let ports = add(
            operations.scalar,
            add(mul(operations.cubic, 3)?, mul(operations.poseidon, 8)?)?,
        )?;
        let mut words = gpu_program::HEADER_WORDS;
        for part in [
            mul(count, gpu_program::INSTRUCTION_WORDS)?,
            selection_hint_words_upper_bound,
            mul(active, gpu_program::ROW_WORDS)?,
            mul(ports, gpu_program::PORT_WORDS)?,
            public_values,
        ] {
            words = add(words, part)?;
        }
        let instruction_bytes = mul(words, 8)?;
        let compiler_peak = add(
            mul(add(words, add(wires_upper_bound, mul(count, 4)?)?)?, 8)?,
            1024,
        )?;
        let schedule_bytes =
            WitnessSchedule::storage_bound(count).map_err(|_| "outer source schedule overflow")?;
        // Construction accounting includes the Program and all nested/spare
        // capacity. Adding the complete Arc header/layout again is conservative
        // and matches the separate retained-source census.
        let header = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<Program>())
            .map_err(|_| "outer source Arc layout overflow")?
            .0
            .pad_to_align()
            .size();
        Ok(Self {
            public_values,
            operations,
            wires: wires_upper_bound,
            witness_values: WitnessCount::Exact(
                u32::try_from(witness_values)
                    .map_err(|_| "outer source witness count conversion")?,
            ),
            hint_words: selection_hint_words_upper_bound,
            active_rows: active,
            padded_rows: padded,
            instruction_bytes,
            compiler_peak,
            schedule_bytes,
            source_bytes: add(PROGRAM_BYTES, header)?,
        })
    }

    /// Fixed registered-parent source envelope. The independently admitted
    /// opaque-cap census is a witness upper bound across every child height;
    /// actual captured-cap constants can use fewer witness words. All other
    /// profile and source limits are identical to the exact owned-SHAKE mode.
    /// This is arithmetic only, never source authentication or dispatch.
    pub fn registered_parent_bounds(
        operations: OperationCounts,
        wires_upper_bound: usize,
        witness_values_upper_bound: usize,
        selection_hint_words_upper_bound: usize,
    ) -> Result<Self, String> {
        let mut shape = Self::owned_shake(
            operations,
            wires_upper_bound,
            witness_values_upper_bound,
            selection_hint_words_upper_bound,
        )?;
        shape.witness_values = WitnessCount::UpperBound(
            u32::try_from(witness_values_upper_bound)
                .map_err(|_| "outer source witness count conversion")?,
        );
        Ok(shape)
    }

    /// Source-only upper bounds for complete graph and ordered aggregate
    /// verifiers. The two widths are fixed by the maintained research relations;
    /// this constructor supplies no registration, ownership or dispatch permit.
    pub fn registered_graph_bounds(
        public_values: usize,
        operations: OperationCounts,
        wires_upper_bound: usize,
        witness_values_upper_bound: usize,
        selection_hint_words_upper_bound: usize,
    ) -> Result<Self, String> {
        if !matches!(public_values, 25 | 28) {
            return Err("outer graph source public width refused".into());
        }
        let mut shape = Self::from_counts(public_values, operations,
            wires_upper_bound, witness_values_upper_bound,
            selection_hint_words_upper_bound)?;
        shape.witness_values = WitnessCount::UpperBound(
            u32::try_from(witness_values_upper_bound)
                .map_err(|_| "outer graph source witness count conversion")?,
        );
        Ok(shape)
    }

    fn bounds(self, rows: usize, limits: RegisteredGpuLimits) -> Result<Bounds, String> {
        if !(8..=self.padded_rows).contains(&rows) || !rows.is_power_of_two() {
            return Err("outer source row geometry refused".into());
        }
        let bounds = Bounds {
            rows: rows as u64,
            main_columns: 94,
            preprocessing_columns: 200,
            metadata_bytes: self.instruction_bytes as u64,
            compiler_host_bytes: self.compiler_peak as u64,
            compiler_retained_host_bytes: self.schedule_bytes as u64,
            pcs_retained_host_bytes:
                crate::block_v2::gpu_hash::cache_metadata::bound_with_tree_storage(
                    rows as u64,
                    true,
                    limits.trees,
                )?,
            program_host_bytes: self.source_bytes as u64,
            program_retained_host_bytes: self.source_bytes as u64,
            wires: self.wires as u64,
            input_values: add(self.public_values, self.witness_values.maximum())? as u64,
        };
        bounds.reservation_with_tree_storage(1, limits.trees)?;
        Ok(bounds)
    }

    fn check_program(self, program: &Program) -> Result<(), String> {
        let actual = OperationCounts::from_program(program);
        let hints = program.operations.iter().try_fold(0usize, |words, op| {
            if let Op::SelectHint { entries, bits, .. } = op {
                add(words, add(entries.len(), bits.len())?)
            } else {
                Ok(words)
            }
        })?;
        if program.public_values() != self.public_values
            || !self.witness_values.admits(program.witness_values())
            || program.wire_count() > self.wires
            || program.active_rows() > self.active_rows
            || program.height() > self.padded_rows
            || program.construction_host_bytes() > PROGRAM_BYTES
            || program.source_host_bytes()? > self.source_bytes
            || actual.scalar > self.operations.scalar
            || actual.cubic > self.operations.cubic
            || actual.poseidon > self.operations.poseidon
            || hints > self.hint_words
        {
            return Err("genuine outer source exceeds pre-native shape".into());
        }
        Ok(())
    }
}

struct RowPlan {
    bounds: Bounds,
    backend: OuterBackendFootprint,
    output: RegisteredGpuOutputFootprint,
}

/// Numerical declaration only. All flags about enclosing ownership and
/// workflow authority remain false; copying this cannot reserve or dispatch.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct OuterSourceFootprint {
    pub padded_rows_upper_bound: u64,
    pub screened_row_geometries: usize,
    pub source_program_host_ceiling: u64,
    pub public_backing_host_ceiling: u64,
    pub witness_backing_host_ceiling: u64,
    pub instruction_device_ceiling: u64,
    pub compiler_host_peak_ceiling: u64,
    pub compiler_retained_host_ceiling: u64,
    pub backend_scope_host_bytes: u64,
    pub backend_host_phase_peak_ceiling: u64,
    /// Full fixed managed allowance, including the existing startup backing.
    /// This is not an observed peak and grants no extra device capacity.
    pub complete_device_phase_ceiling: u64,
    pub context_reserve_bytes: u64,
    pub minimum_pcs_host_budget_bytes: u64,
    pub source_phase_bounds_complete: bool,
    pub enclosing_ownership_bound_complete: bool,
    pub workflow_dispatch_authority: bool,
    pub output: RegisteredGpuOutputFootprint,
}

/// Immutable source plan. It contains bounded inline data only and cannot be
/// turned into an admission, native owner, registration or proof by this API.
pub struct OuterSourceEnvelope {
    shape: OuterSourceShape,
    limits: RegisteredGpuLimits,
    rows: [Option<RowPlan>; HEIGHTS],
    report: OuterSourceFootprint,
}

impl OuterSourceEnvelope {
    /// Additional inline source-plan storage, including moved return/refusal
    /// and report slots. The existing separate caller planning reservation is
    /// still required for the shared precommit/opening/verification planners.
    pub fn additional_metadata_host_bytes() -> Result<usize, String> {
        let prior = add(
            mul(size_of::<Self>(), 3)?,
            add(
                mul(size_of::<RowPlan>(), 8)?,
                mul(size_of::<Result<Self, String>>(), 2)?,
            )?,
        )?;
        // Incremental exact/upper-bound branch and conversion helper frames.
        // Parent constructor whole-shape/Result wrappers are separately charged
        // by the enclosing parent producer before this source plan is built.
        let prior = add(
            prior,
            mul(
                8,
                add(
                    size_of::<WitnessCount>(),
                    add(
                        mul(size_of::<usize>(), 2)?,
                        add(
                            size_of::<bool>(),
                            size_of::<Result<u32, std::num::TryFromIntError>>(),
                        )?,
                    )?,
                )?,
            )?,
        )?;
        // The pure genuine-input helper is also used by the real captured
        // envelope. Charge its complete forwarding/result frames separately.
        let input_check = [
            size_of::<OuterSourceShape>(),
            size_of::<&Program>(),
            mul(size_of::<&Vec<Val>>(), 2)?,
            mul(size_of::<u64>(), 2)?,
            size_of::<usize>(),
            size_of::<Result<usize, String>>(),
            size_of::<Result<(), String>>(),
        ];
        let frames = input_check
            .into_iter()
            .try_fold(std::mem::size_of_val(&input_check), add)?;
        add(prior, mul(8, frames)?)
    }

    pub fn inspect(
        shape: OuterSourceShape,
        limits: RegisteredGpuLimits,
        native_host_budget_bytes: u64,
    ) -> Result<Self, String> {
        if limits.device_bytes != 8 << 30
            || limits.host_bytes != 32 << 30
            || limits.context_bytes != 4 << 30
            || limits.max_rows != 1 << LAST_LOG
            || limits.trees.host_bytes != 8 << 30
        {
            return Err("outer source requires unchanged fixed worker profile".into());
        }
        let mut rows = core::array::from_fn(|_| None);
        let mut output = None;
        let mut backend_host_peak = 0;
        let mut minimum_pcs = u64::MAX;
        let public_backing = backing(2 * shape.public_values)?;
        let witness_backing = backing(INPUT_VALUES)?;
        let mut screened = 0;
        for log in FIRST_LOG..=shape.padded_rows.ilog2() {
            let height = 1usize << log;
            let bounds = shape.bounds(height, limits)?;
            let backend = inspect_bounds(
                &bounds,
                shape.public_values,
                public_backing,
                witness_backing,
                limits,
                native_host_budget_bytes,
            )?;
            let row_output =
                output::inspect_shape(shape.public_values, height, shape.source_bytes as u64)?;
            output = Some(output.map_or(row_output, |prior| output_max(prior, row_output)));
            backend_host_peak = backend_host_peak.max(backend.backend_host_phase_peak_bytes);
            minimum_pcs = minimum_pcs.min(backend.pcs_host_budget_bytes);
            rows[(log - FIRST_LOG) as usize] = Some(RowPlan {
                bounds,
                backend,
                output: row_output,
            });
            screened += 1;
        }
        Ok(Self {
            shape,
            limits,
            rows,
            report: OuterSourceFootprint {
                padded_rows_upper_bound: shape.padded_rows as u64,
                screened_row_geometries: screened,
                source_program_host_ceiling: shape.source_bytes as u64,
                public_backing_host_ceiling: public_backing,
                witness_backing_host_ceiling: witness_backing,
                instruction_device_ceiling: shape.instruction_bytes as u64,
                compiler_host_peak_ceiling: shape.compiler_peak as u64,
                compiler_retained_host_ceiling: shape.schedule_bytes as u64,
                backend_scope_host_bytes: super::add(
                    native_host_budget_bytes,
                    limits.trees.host_bytes as u64,
                )?,
                backend_host_phase_peak_ceiling: backend_host_peak,
                complete_device_phase_ceiling: limits.device_bytes,
                context_reserve_bytes: limits.context_bytes,
                minimum_pcs_host_budget_bytes: minimum_pcs,
                source_phase_bounds_complete: true,
                enclosing_ownership_bound_complete: false,
                workflow_dispatch_authority: false,
                output: output.ok_or("outer source empty row census")?,
            },
        })
    }

    pub fn footprint(&self) -> OuterSourceFootprint {
        self.report
    }

    /// Allocation-free conformance of a genuine compiler result. This neither
    /// validates its cryptographic meaning nor reserves any new storage.
    pub fn check_compiled(
        &self,
        program: &Program,
        public: &Vec<Val>,
        witness: &Vec<Val>,
    ) -> Result<(), String> {
        let height = check_compiled_inputs(
            self.shape,
            program,
            public,
            witness,
            self.report.public_backing_host_ceiling,
            self.report.witness_backing_host_ceiling,
        )?;
        self.check_compiled_row(program, height)
    }

    /// The genuine public owner is an immutable fixed array. Its complete
    /// backing is known from N; the witness remains its actual owned Vec.
    /// This performs the same screened-row/GPU/output checks as the Vec entry.
    pub fn check_compiled_fixed_public<const N: usize>(
        &self,
        program: &Program,
        public: &[Val; N],
        witness: &Vec<Val>,
    ) -> Result<(), String> {
        let height = check_compiled_fixed_public_inputs(
            self.shape, program, public, witness,
            self.report.public_backing_host_ceiling,
            self.report.witness_backing_host_ceiling,
        )?;
        self.check_compiled_row(program, height)
    }

    fn check_compiled_row(&self, program: &Program, height: usize) -> Result<(), String> {
        let row = self.rows[(height.ilog2() - FIRST_LOG) as usize]
            .as_ref()
            .ok_or("outer source row was not screened")?;
        let actual = Bounds::for_program_with_tree_storage(program, true, self.limits.trees)?;
        if !covers(&row.bounds, &actual, self.shape.witness_values)
            || !row.backend.backend_phase_bounds_complete
            || row.backend.enclosing_ownership_bound_complete
            || row.backend.workflow_dispatch_authority
        {
            return Err("genuine GPU layout exceeds pre-native source ceiling".into());
        }
        let output =
            output::inspect_shape(self.shape.public_values, height, actual.program_retained_host_bytes)?;
        if output_max(row.output, output) != row.output {
            return Err("genuine output exceeds pre-native source ceiling".into());
        }
        Ok(())
    }
}

/// Pure actual compiler/input conformance only. The genuine envelope calls
/// this same helper before its original screened-row, GPU-layout and output
/// checks. No physical selection, row admission or dispatch is created here.
fn check_compiled_inputs(
    shape: OuterSourceShape,
    program: &Program,
    public: &Vec<Val>,
    witness: &Vec<Val>,
    public_backing: u64,
    witness_backing: u64,
) -> Result<usize, String> {
    check_compiled_original_inputs(shape, program, public, public.capacity(), witness,
        public_backing, witness_backing)
}

fn check_compiled_fixed_public_inputs<const N: usize>(
    shape: OuterSourceShape,
    program: &Program,
    public: &[Val; N],
    witness: &Vec<Val>,
    public_backing: u64,
    witness_backing: u64,
) -> Result<usize, String> {
    check_compiled_original_inputs(shape, program, public, N, witness,
        public_backing, witness_backing)
}

// Only the two concrete owner adapters above supply public_capacity. A caller
// slice and an asserted numeric capacity cannot reach an admission method.
fn check_compiled_original_inputs(
    shape: OuterSourceShape,
    program: &Program,
    public: &[Val],
    public_capacity: usize,
    witness: &Vec<Val>,
    public_backing: u64,
    witness_backing: u64,
) -> Result<usize, String> {
    shape.check_program(program)?;
    let height = program.height();
    if !(8..=shape.padded_rows).contains(&height)
        || !height.is_power_of_two()
        || public.len() != shape.public_values
        || witness.len() != program.witness_values()
        || backing(public_capacity)? > public_backing
        || backing(witness.capacity())? > witness_backing
    {
        return Err("outer source genuine input capacity mismatch".into());
    }
    Ok(height)
}

fn covers(bound: &Bounds, actual: &Bounds, witnesses: WitnessCount) -> bool {
    // Every field is explicit; avoid Bounds::covers, whose legacy PCS fallback
    // reads environment selection instead of this plan's captured profile.
    bound.rows == actual.rows
        && bound.main_columns == actual.main_columns
        && bound.preprocessing_columns == actual.preprocessing_columns
        && bound.metadata_bytes >= actual.metadata_bytes
        && bound.compiler_host_bytes >= actual.compiler_host_bytes
        && bound.compiler_retained_host_bytes >= actual.compiler_retained_host_bytes
        && bound.pcs_retained_host_bytes >= actual.pcs_retained_host_bytes
        && bound.program_host_bytes >= actual.program_host_bytes
        && bound.program_retained_host_bytes >= actual.program_retained_host_bytes
        && bound.wires >= actual.wires
        && match witnesses {
            WitnessCount::Exact(_) => bound.input_values == actual.input_values,
            WitnessCount::UpperBound(_) => bound.input_values >= actual.input_values,
        }
}

fn output_max(
    mut a: RegisteredGpuOutputFootprint,
    b: RegisteredGpuOutputFootprint,
) -> RegisteredGpuOutputFootprint {
    macro_rules! maximum {
        ($($field:ident),+ $(,)?) => { $(a.$field = a.$field.max(b.$field);)+ };
    }
    maximum!(
        public_values,
        rows,
        cap_roots,
        source_program_retained_host_bytes,
        opening_producer_host_bytes,
        final_descriptor_host_bytes,
        native_commitment_host_bytes,
        degree_and_terminal_host_bytes,
        proof_backing_ceiling_host_bytes,
        verifier_metadata_retained_host_bytes,
        verifier_construction_peak_host_bytes,
        verifier_verification_peak_host_bytes,
        verifier_lifecycle_peak_host_bytes,
        copied_key_cap_host_bytes,
    );
    a.producer_backing_bound_complete &= b.producer_backing_bound_complete;
    a.enclosing_ownership_bound_complete |= b.enclosing_ownership_bound_complete;
    a.dispatch_authority |= b.dispatch_authority;
    a
}

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "block-v2-wide-lanes"
))]
mod tests;
