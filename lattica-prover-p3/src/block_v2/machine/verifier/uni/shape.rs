//! Counts-only native verifier compilation for separately admitted trusted AIRs.
//!
//! This is a lower-level bounded compiler, not a generic AIR memory-admission
//! API. The closed caller must reserve its own descriptor/callback allocations,
//! periodic table, invalid template, ProofInputs and returned-wire backing
//! before entry. `ConstructionLimits` enforces compiler storage independently.
//! The private template has exactly three PCS rounds, at most 32 quotient
//! matrices, 128 queries and binary FRI under the unchanged hiding profile.
use super::{BoundedSymbolicAllowance, BoundedSymbolicBuilder, CompileError, Val};
use crate::block_v2::machine::{
    program::{ConstructionLimits, Op, ProgramBuilder},
    verifier::{batch::shape::OperationCounts, ProofInputs},
};
use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCoreCounts {
    pub quotient_chunks: usize,
    pub operations: OperationCounts,
    pub wires: usize,
    pub input_values: usize,
    /// Logical SelectHint entry/bit words from this same private shape program.
    /// The pinned GPU layout uploads one u64 per word. This is not authority to
    /// allocate a GPU program and excludes its instructions, rows and ports.
    pub selection_hint_words: usize,
    /// Streaming canonical-encoding diagnostic, never registration authority.
    pub manifest_sha3_256: [u8; 32],
    /// Observation of this planner only; not a different compiler's admission.
    pub planner_requested_program_bytes_peak: usize,
}

/// Numerical source facts with no Program or manifest materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCoreMetadata {
    pub quotient_chunks: usize,
    pub operations: OperationCounts,
    pub wires: usize,
    pub input_values: usize,
    pub selection_hint_words: usize,
    pub planner_requested_program_bytes_peak: usize,
}

/// Optional component timings for a metadata-only profiling pass.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct NativeMetadataTimings {
    pub symbolic_ns: u128,
    pub lowering_ns: u128,
    pub finalization_ns: u128,
    pub detail: NativeLoweringTimings,
}

/// Disjoint stages inside numeric lowering. Disabled for ordinary compilation.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct NativeLoweringTimings {
    pub setup_ns: u128,
    pub pcs_ns: u128,
    /// Disjoint sub-stages within pcs_ns; omitted work is loop/clock overhead.
    pub pcs_setup_ns: u128,
    pub pcs_query_ns: u128,
    pub pcs_opening_ns: u128,
    pub pcs_reduction_ns: u128,
    pub pcs_folding_ns: u128,
    pub selectors_ns: u128,
    pub periodic_ns: u128,
    pub periodic_specialization_ns: u128,
    pub periodic_interpolation_ns: u128,
    pub periodic_emission_ns: u128,
    pub quotient_ns: u128,
    pub constraints_ns: u128,
}

/// Exact compiler byte-cap failure. Closed cohort coordinators may retry this
/// with fewer workers under the same original reservation. Other errors are fatal.
pub const NATIVE_PROGRAM_BYTE_LIMIT: &str = "native metadata compiler byte limit";

/// Opaque constraints and geometry prepared from one admitted AIR. The caller
/// retains its symbolic graph allowance until this value is dropped. Preparation
/// scratch is released before this value is returned; no proof authority exists.
pub struct PreparedNativeMetadata {
    geometry: PreparedGeometry,
    height: usize,
    constraints: (Vec<p3_air::symbolic::SymbolicExpression<Val>>, usize),
    retained_requested_bytes: usize,
}
struct PreparedGeometry {
    width: usize,
    publics: usize,
    periodic: usize,
    next: bool,
}
impl BaseAir<Val> for PreparedGeometry {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        self.publics
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic
    }
    // The verifier uses only emptiness, never column identities. Symbolic
    // constraints were already obtained from the original AIR, above.
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.next {
            vec![0]
        } else {
            Vec::new()
        }
    }
}
pub fn prepare_native_metadata<A>(
    air: &A,
    height: usize,
    symbolic: BoundedSymbolicAllowance,
) -> Result<PreparedNativeMetadata, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    super::validate_geometry(air, height)?;
    symbolic.check()?;
    if !(1..=1024).contains(&air.width())
        || air.num_public_values() > 384
        || air.num_periodic_columns() > 256
        || height > 1 << 24
    {
        return Err(CompileError::Shape("native core planner geometry"));
    }
    let (constraints, retained_requested_bytes) =
        crate::block_v2::machine::symbolic::prepare_uni_bounded_with_storage(
            air,
            crate::block_v2::machine::compiler_constants::Constants::cpu(),
        )?;
    if constraints.1 > crate::block_v2::profile::LOG_BLOWUP {
        return Err(CompileError::Shape("native counting quotient degree"));
    }
    Ok(PreparedNativeMetadata {
        geometry: PreparedGeometry {
            width: air.width(),
            publics: air.num_public_values(),
            periodic: air.num_periodic_columns(),
            next: !air.main_next_row_columns().is_empty(),
        },
        height,
        constraints,
        retained_requested_bytes,
    })
}
impl PreparedNativeMetadata {
    /// Source-accounted normalization requests cover this original graph's
    /// retained backing. This is neither RSS nor a bound for another graph.
    pub fn retained_requested_bytes(&self) -> usize {
        self.retained_requested_bytes
    }
    /// Periodic columns must come from the same closed descriptor as preparation.
    /// Their backing and the retained graph remain charged by the caller.
    pub fn lower(
        &self,
        columns: &[Vec<Val>],
        construction: ConstructionLimits,
        mut timings: Option<&mut NativeMetadataTimings>,
    ) -> Result<NativeCoreMetadata, CompileError> {
        let (builder, inputs, chunks) =
            self.compile(columns, construction, timings.as_deref_mut())?;
        let started = timings.as_ref().map(|_| std::time::Instant::now());
        let counts = builder.finish_counts().map_err(|e| {
            CompileError::from_builder_admission(e, "native core counting allowance")
        })?;
        if let Some(t) = timings {
            t.finalization_ns = started.unwrap().elapsed().as_nanos();
        }
        debug_assert!(inputs.values.is_empty());
        Ok(NativeCoreMetadata {
            quotient_chunks: chunks,
            operations: OperationCounts {
                scalar: counts.scalar,
                cubic: counts.cubic,
                poseidon: counts.poseidon,
            },
            wires: counts.wires,
            input_values: counts.witnesses,
            selection_hint_words: counts.hint_words,
            planner_requested_program_bytes_peak: counts.requested_bytes_peak,
        })
    }
    fn compile(
        &self,
        columns: &[Vec<Val>],
        construction: ConstructionLimits,
        mut timings: Option<&mut NativeMetadataTimings>,
    ) -> Result<(ProgramBuilder, ProofInputs, usize), CompileError> {
        if columns.len() != self.geometry.periodic
            || columns
                .iter()
                .any(|c| !c.len().is_power_of_two() || c.len() > self.height || c.len() > 65536)
        {
            return Err(CompileError::Shape("native core planner geometry"));
        }
        let started = timings.as_ref().map(|_| std::time::Instant::now());
        let mut builder = ProgramBuilder::new_counting(0, construction).map_err(|e| {
            CompileError::from_builder_admission(e, "native counting builder allowance")
        })?;
        let mut inputs = ProofInputs::counting();
        let compiled = (|| {
            let public = inputs.bases_geometry(&mut builder, self.geometry.publics)?;
            super::verify_counted_prepared(
                &mut builder,
                &mut inputs,
                &self.geometry,
                self.height,
                &public,
                columns,
                &self.constraints,
                timings.as_deref_mut().map(|t| &mut t.detail),
            )
        })();
        if builder.program_byte_limit_exceeded() {
            return Err(CompileError::ResourceAdmission(NATIVE_PROGRAM_BYTE_LIMIT));
        }
        compiled?;
        if let Some(t) = timings {
            t.lowering_ns = started.unwrap().elapsed().as_nanos();
        }
        Ok((builder, inputs, 1 << (self.constraints.1 + 1)))
    }
}

pub fn verifier_core_metadata<A>(
    air: &A,
    height: usize,
    columns: &[Vec<Val>],
    construction: ConstructionLimits,
    symbolic: BoundedSymbolicAllowance,
) -> Result<NativeCoreMetadata, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    metadata_inner(air, height, columns, construction, symbolic, None)
}

pub fn verifier_core_metadata_profiled<A>(
    air: &A,
    height: usize,
    columns: &[Vec<Val>],
    construction: ConstructionLimits,
    symbolic: BoundedSymbolicAllowance,
) -> Result<(NativeCoreMetadata, NativeMetadataTimings), CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    let mut timings = NativeMetadataTimings::default();
    let result = metadata_inner(
        air,
        height,
        columns,
        construction,
        symbolic,
        Some(&mut timings),
    )?;
    Ok((result, timings))
}

fn metadata_inner<A>(
    air: &A,
    height: usize,
    columns: &[Vec<Val>],
    construction: ConstructionLimits,
    symbolic: BoundedSymbolicAllowance,
    mut timings: Option<&mut NativeMetadataTimings>,
) -> Result<NativeCoreMetadata, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    let (builder, inputs, chunks) = compile_core(
        air,
        height,
        columns,
        construction,
        symbolic,
        true,
        timings.as_deref_mut(),
    )?;
    let started = timings.as_ref().map(|_| std::time::Instant::now());
    let counts = builder
        .finish_counts()
        .map_err(|e| CompileError::from_builder_admission(e, "native core counting allowance"))?;
    if let Some(t) = timings {
        t.finalization_ns = started.unwrap().elapsed().as_nanos();
    }
    debug_assert!(inputs.values.is_empty());
    Ok(NativeCoreMetadata {
        quotient_chunks: chunks,
        operations: OperationCounts {
            scalar: counts.scalar,
            cubic: counts.cubic,
            poseidon: counts.poseidon,
        },
        wires: counts.wires,
        input_values: counts.witnesses,
        selection_hint_words: counts.hint_words,
        planner_requested_program_bytes_peak: counts.requested_bytes_peak,
    })
}

/// Compile a fresh-public/fresh-proof-input native core and return only counts.
/// All invalid objects are dropped internally. Numeric proof values cannot
/// influence this program: each becomes a fresh unknown witness input. Exact
/// trusted AIR geometry, periodic values and protocol parameters still matter.
///
/// Before this call the closed caller must account for two complete template
/// backings (construction overlap), both bounded symbolic components, twice
/// `max_input_values * size_of::<Val>()`, cumulative returned wire payload of
/// `max_input_values * size_of::<Wire>()`, template/helper Vec headers and AIR
/// callback allocations. There is no unbounded fallback or proof verification.
pub fn verifier_core_counts<A>(
    air: &A,
    height: usize,
    columns: &[Vec<Val>],
    construction: ConstructionLimits,
    symbolic: BoundedSymbolicAllowance,
) -> Result<NativeCoreCounts, CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    let (builder, inputs, chunks) =
        compile_core(air, height, columns, construction, symbolic, false, None)?;
    let program = builder
        .finish(None)
        .map_err(|e| CompileError::from_builder_admission(e, "native core packing allowance"))?;
    let mut digest = Sha3_256::new();
    program
        .visit_manifest_fields(&mut |word| {
            digest.update(word.to_le_bytes());
            Ok(())
        })
        .map_err(|_| CompileError::Shape("native core manifest encoding"))?;
    let selection_hint_words = program.operations.iter().try_fold(0usize, |total, op| {
        let extra = match op {
            Op::SelectHint { entries, bits, .. } => entries.len().checked_add(bits.len()),
            _ => Some(0),
        };
        extra
            .and_then(|extra| total.checked_add(extra))
            .ok_or(CompileError::ResourceAdmission(
                "native core hint census overflow",
            ))
    })?;
    let result = NativeCoreCounts {
        quotient_chunks: chunks,
        operations: OperationCounts::from_program(&program),
        wires: program.wire_count(),
        input_values: program.witness_values(),
        selection_hint_words,
        manifest_sha3_256: digest.finalize().into(),
        planner_requested_program_bytes_peak: program.construction_host_bytes(),
    };
    debug_assert_eq!(result.input_values, inputs.values.len());
    // Template, program, witness inputs and callback handles never escape.
    Ok(result)
}

fn compile_core<A>(
    air: &A,
    height: usize,
    columns: &[Vec<Val>],
    construction: ConstructionLimits,
    symbolic: BoundedSymbolicAllowance,
    counting: bool,
    mut timings: Option<&mut NativeMetadataTimings>,
) -> Result<(ProgramBuilder, ProofInputs, usize), CompileError>
where
    A: BaseAir<Val> + Air<BoundedSymbolicBuilder>,
{
    let width = air.width();
    let publics = air.num_public_values();
    if !(1..=1024).contains(&width)
        || publics > 384
        || !(8..=1 << 24).contains(&height)
        || !height.is_power_of_two()
        || columns.len() != air.num_periodic_columns()
        || columns.len() > 256
        || columns
            .iter()
            .any(|c| !c.len().is_power_of_two() || c.len() > height || c.len() > 65536)
    {
        return Err(CompileError::Shape("native core planner geometry"));
    }
    if counting {
        let started = timings.as_ref().map(|_| std::time::Instant::now());
        let prepared = prepare_native_metadata(air, height, symbolic)?;
        if let Some(t) = timings.as_deref_mut() {
            t.symbolic_ns = started.unwrap().elapsed().as_nanos();
        }
        return prepared.compile(columns, construction, timings);
    }
    let chunks = super::quotient_chunks_bounded(air, height, symbolic)?;
    let next = !air.main_next_row_columns().is_empty();
    let template = super::super::template::uni_bounded_shape(width, height, next, chunks)?;
    let mut builder = if counting {
        ProgramBuilder::new_counting(0, construction)
    } else {
        ProgramBuilder::new_with_construction_limits(0, construction)
    }
    .map_err(|e| CompileError::from_builder_admission(e, "native core builder allowance"))?;
    let mut inputs = ProofInputs::default();
    let values = [Val::ZERO; 384];
    let public = inputs.bases(&mut builder, &values[..publics])?;
    super::verify_bounded(
        &mut builder,
        &mut inputs,
        air,
        height,
        &public,
        &template,
        columns,
        symbolic,
    )?;
    Ok((builder, inputs, chunks))
}
