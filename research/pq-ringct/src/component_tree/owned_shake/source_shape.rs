//! Original-request-bound SHAKE compiler geometry before native dispatch.
//!
//! The existing closed native shape compiler builds and destroys private invalid
//! templates. Only source-derived counts survive. This module admits that CPU
//! planning pass and its fixed metadata, never a native/outer proving phase.
use super::{
    add, combine, requirement, Category, Contract, EndpointContext, GroupCompilePlan, Ledger,
    OwnedCompiledShake, Requirements, Reservation, ShakeWrapperLayout, ShakeWrapperSpan, HEADER,
    INPUT_VALUES, MAX_ROWS, PROGRAM_BYTES,
};
use crate::{
    component_tree::{
        native_shape::{
            framing, native_core_bound, NativeCoreBound, NativeDescriptor, NativePlanningStorage,
        },
        Kind,
    },
    graph_crypto::ReservedShakeRequest,
    shake_air::lane,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    program::{ConstructionLimits, Program, ProgramBuilder, ProofInputs, MAX_WIRES},
    verifier::{batch::shape::OperationCounts, uni::shape::NativeCoreCounts, CompileError},
};
use p3_air::BaseAir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Authority,
    Source,
    Unsupported,
    Overflow,
    Planner,
    Capacity,
}

type Result<T> = core::result::Result<T, Error>;

fn plus(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn times(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Overflow)
}

struct Identity<'request> {
    owner: &'request ReservedShakeRequest,
    layout: ShakeWrapperLayout,
    ordinal: usize,
    span: ShakeWrapperSpan,
    contract: Contract,
    context: EndpointContext,
}

impl Identity<'_> {
    fn is_for(&self, plan: &GroupCompilePlan<'_>, ledger: &Ledger) -> bool {
        self.owner.belongs_to(ledger)
            && core::ptr::eq(self.owner.request(), plan.request)
            && self.layout == plan.layout
            && self.ordinal == plan.ordinal
            && self.span == plan.span
            && self.contract == plan.contract
            && self.context == plan.context
            && fixed_limits(plan.limits)
    }
}

fn fixed_limits(limits: ConstructionLimits) -> bool {
    limits.max_requested_program_bytes == PROGRAM_BYTES
        && limits.max_input_values == INPUT_VALUES
        && limits.max_wires == MAX_WIRES
}

/// Arithmetic metadata only. Copying this value conveys no reservation or
/// dispatch authority. Both operation classes and hint words come from source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    pub(crate) operations: OperationCounts,
    pub(crate) active_rows_upper_bound: usize,
    pub(crate) padded_rows_upper_bound: usize,
    pub(crate) wires_upper_bound: usize,
    pub(crate) input_values: usize,
    pub(crate) selection_hint_words_upper_bound: usize,
}

impl Geometry {
    fn from_cores(cores: &[Option<NativeCoreCounts>; 2], members: usize) -> Result<Self> {
        if !(1..=2).contains(&members)
            || cores
                .iter()
                .enumerate()
                .any(|(i, core)| core.is_some() != (i < members))
        {
            return Err(Error::Source);
        }
        let framing = framing::shake_wrapper(members).map_err(|_| Error::Source)?;
        let mut operations = framing;
        // A scalar operation creates at most one wire, a cubic one three and a
        // Poseidon one eight. Native core counts already include all fresh
        // native public/proof inputs. Wrapper public wires are additional.
        let mut wires = plus(
            HEADER + 8,
            plus(framing.scalar, times(8, framing.poseidon)?)?,
        )?;
        if framing.cubic != 0 {
            return Err(Error::Unsupported);
        }
        let mut inputs = 0;
        let mut hints = 0;
        for core in cores.iter().flatten() {
            operations = operations
                .with_overhead(core.operations)
                .map_err(|_| Error::Overflow)?;
            wires = plus(wires, core.wires)?;
            inputs = plus(inputs, core.input_values)?;
            hints = plus(hints, core.selection_hint_words)?;
        }
        let active = operations
            .active_rows(HEADER + 8)
            .map_err(|_| Error::Overflow)?;
        let padded = operations
            .padded_rows(HEADER + 8)
            .map_err(|_| Error::Overflow)?;
        if HEADER + 8 != 46 || padded > MAX_ROWS || wires > MAX_WIRES || inputs > INPUT_VALUES {
            return Err(Error::Capacity);
        }
        Ok(Self {
            operations,
            active_rows_upper_bound: active,
            padded_rows_upper_bound: padded,
            wires_upper_bound: wires,
            input_values: inputs,
            selection_hint_words_upper_bound: hints,
        })
    }
}

/// Allocation-free source census. Each descriptor is the exact original native
/// segment. Neither supported source mode splits or regroups native segments.
pub(crate) struct SourceShapePlan<'request> {
    identity: Identity<'request>,
    descriptors: [Option<NativeDescriptor<'static>>; 2],
    storage: [Option<NativePlanningStorage>; 2],
    construction: ConstructionLimits,
    temporary: Requirements,
    metadata: Requirements,
    whole: Requirements,
}

#[derive(Clone, Copy)]
enum SourceSegments {
    SingletonOnly,
    ExistingBatchesV1,
}

impl SourceSegments {
    fn supports(self, units: usize) -> bool {
        match self {
            Self::SingletonOnly => units == 1,
            Self::ExistingBatchesV1 => matches!(units, 1 | 8 | 16),
        }
    }
}

fn metadata_requirement() -> Result<Requirements> {
    // Count moved/final owners independently; no stack-slot elision credit.
    let bytes = [
        2 * size_of::<GroupSourceBound<'static>>(),
        2 * size_of::<Geometry>(),
        2 * size_of::<NativeCoreCounts>(),
        2 * size_of::<Reservation>(),
    ]
    .into_iter()
    .try_fold(0, add)
    .map_err(|_| Error::Overflow)?;
    requirement(Category::RegisteredMetadata, bytes).map_err(|_| Error::Overflow)
}

impl<'request> GroupCompilePlan<'request> {
    pub(crate) fn source_shape_plan(
        &self,
        owner: &'request ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<SourceShapePlan<'request>> {
        self.source_shape_plan_for(owner, ledger, SourceSegments::SingletonOnly)
    }

    /// Separately selected source planning for already-existing native
    /// singleton/batch8/batch16 segments. This does not alter Request::new's
    /// partition, support smaller substitute segments, or grant native/outer
    /// dispatch. The singleton-only entry remains unchanged by default.
    pub(crate) fn source_shape_plan_existing_batches_v1(
        &self,
        owner: &'request ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<SourceShapePlan<'request>> {
        self.source_shape_plan_for(owner, ledger, SourceSegments::ExistingBatchesV1)
    }

    fn source_shape_plan_for(
        &self,
        owner: &'request ReservedShakeRequest,
        ledger: &Ledger,
        mode: SourceSegments,
    ) -> Result<SourceShapePlan<'request>> {
        if !owner.belongs_to(ledger) || !core::ptr::eq(owner.request(), self.request) {
            return Err(Error::Authority);
        }
        if !fixed_limits(self.limits) || !(1..=2).contains(&self.span.segment_count) {
            return Err(Error::Unsupported);
        }
        let Kind::Shake(descriptor) = self.contract.kind else {
            return Err(Error::Source);
        };
        let mut descriptors = [None, None];
        let mut storage = [None, None];
        let mut peak = 0;
        for offset in 0..self.span.segment_count {
            let index = self
                .span
                .first_segment
                .checked_add(offset)
                .ok_or(Error::Overflow)?;
            let segment = self.request.segments().get(index).ok_or(Error::Source)?;
            if !mode.supports(segment.units) {
                return Err(Error::Unsupported);
            }
            let native = self
                .request
                .shake_partition()
                .and_then(|partition| partition.segments().get(index))
                .ok_or(Error::Source)?;
            let width = if segment.units == 1 {
                lane::WIDTH
            } else {
                lane::batch::WIDTH
            };
            let height = times(lane::HEIGHT, segment.units)?;
            if native.first_permutation() != segment.first_unit
                || native.permutations() != segment.units
                || native.width() != width
                || native.height() != height
                || segment.width != width
                || segment.height != height
            {
                return Err(Error::Source);
            }
            let source = NativeDescriptor::Shake {
                descriptor,
                first: segment.first_unit,
                count: segment.units,
            };
            let footprint = NativePlanningStorage::for_descriptor(source, self.limits)
                .map_err(|_| Error::Source)?;
            if footprint.geometry.width != width
                || footprint.geometry.height != height
                || footprint.geometry.public_values != crate::shake_air::PUBLIC_VALUES
                || footprint.geometry.periodic_columns != lane::PERIODIC_COLUMNS
                || footprint.geometry.maximum_period != lane::SCHEDULE_PERIOD
            {
                return Err(Error::Source);
            }
            peak = peak.max(footprint.total_requested_bytes);
            descriptors[offset] = Some(source);
            storage[offset] = Some(footprint);
        }
        // The native planner's enforceable program and template/input/symbolic
        // backings are above. These are additional fixed orchestration owners.
        let inline = [
            2 * size_of::<SourceShapePlan<'static>>(),
            // Complete common-helper and entry/caller result slots, including
            // discriminants and both arrays; never assume return-slot elision.
            4 * size_of::<Result<SourceShapePlan<'static>>>(),
            2 * size_of::<SourceSegments>(),
            2 * size_of::<NativeCoreBound>(),
            size_of::<ProgramBuilder>(),
            size_of::<Program>(),
            size_of::<ProofInputs>(),
            4 * size_of::<CompileError>(),
            2 * size_of::<Ledger>(),
        ]
        .into_iter()
        .try_fold(0, add)
        .map_err(|_| Error::Overflow)?;
        let temporary = requirement(Category::PhaseScratch, plus(peak, inline)?)
            .map_err(|_| Error::Overflow)?;
        let metadata = metadata_requirement()?;
        let whole = combine(&[temporary, metadata]).map_err(|_| Error::Overflow)?;
        Ok(SourceShapePlan {
            identity: Identity {
                owner,
                layout: self.layout,
                ordinal: self.ordinal,
                span: self.span,
                contract: self.contract.clone(),
                context: self.context.clone(),
            },
            descriptors,
            storage,
            construction: self.limits,
            temporary,
            metadata,
            whole,
        })
    }
}

impl<'request> SourceShapePlan<'request> {
    pub(crate) fn requirements(&self) -> Requirements {
        self.whole
    }

    /// Consume the exact original planner reservation. No native proof, GPU
    /// session, synthetic-hint evaluation or independent acceptance occurs.
    pub(crate) fn inspect(
        self,
        mut original: Reservation,
        ledger: &Ledger,
    ) -> Result<GroupSourceBound<'request>> {
        let allowance = ledger.snapshot().allowance;
        if !self.identity.owner.belongs_to(ledger)
            || !original.belongs_to(ledger)
            || original.requirements() != self.whole
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
            || allowance.device > 8 << 30
        {
            return Err(Error::Authority);
        }
        let metadata = original
            .split(self.metadata)
            .map_err(|_| Error::Authority)?;
        let mut cores = [None, None];
        for (offset, destination) in cores
            .iter_mut()
            .enumerate()
            .take(self.identity.span.segment_count)
        {
            let descriptor = self.descriptors[offset].ok_or(Error::Source)?;
            let storage = self.storage[offset].ok_or(Error::Source)?;
            let result =
                native_core_bound(descriptor, self.construction, storage.auxiliary_peak_bytes)
                    .map_err(|_| Error::Planner)?;
            if result.storage != storage {
                return Err(Error::Source);
            }
            *destination = Some(result.counts);
        }
        let geometry = Geometry::from_cores(&cores, self.identity.span.segment_count)?;
        if original.requirements() != self.temporary {
            return Err(Error::Authority);
        }
        // Every private program/template/input/symbolic owner has died inside
        // the lower planner before its original temporary claim is released.
        drop(original);
        Ok(GroupSourceBound {
            identity: self.identity,
            geometry,
            cores,
            metadata,
        })
    }
}

/// Move-only original source metadata. It is not a proof, dispatch permit,
/// complete workflow reservation, or authentication of transaction context.
pub(crate) struct GroupSourceBound<'request> {
    identity: Identity<'request>,
    geometry: Geometry,
    cores: [Option<NativeCoreCounts>; 2],
    metadata: Reservation,
}

impl GroupSourceBound<'_> {
    pub(crate) fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub(crate) fn is_for(&self, plan: &GroupCompilePlan<'_>, ledger: &Ledger) -> bool {
        self.metadata.belongs_to(ledger)
            && metadata_requirement().is_ok_and(|required| self.metadata.requirements() == required)
            && self.identity.is_for(plan, ledger)
    }

    /// Compare the genuine compiler output with this same prior source bound.
    /// This comparison neither verifies a proof nor admits its outer backend.
    pub(crate) fn check_compiled(
        &self,
        output: &OwnedCompiledShake<'_>,
        ledger: &Ledger,
    ) -> Result<()> {
        if !self.identity.owner.belongs_to(ledger)
            || !self.metadata.belongs_to(ledger)
            || !metadata_requirement()
                .is_ok_and(|required| self.metadata.requirements() == required)
            || !output.is_for(self.identity.owner.request())
            || !output._program.belongs_to(ledger)
            || !output._inputs.belongs_to(ledger)
            || !output.report.belongs_to(ledger)
        {
            return Err(Error::Authority);
        }
        let summary = output.summary;
        let node = &output.compiled;
        let program = &node.program;
        if summary.layout != self.identity.layout
            || summary.ordinal != self.identity.ordinal
            || summary.span != self.identity.span
            || summary.independent_native_verifications != self.identity.span.segment_count
            || summary.active_rows != program.active_rows()
            || summary.padded_rows != program.height()
            || summary.wires != program.wire_count()
            || summary.input_values != program.witness_values()
            || node.public.len() != HEADER + 8
            || program.public_values() != HEADER + 8
            || node.witness.len() != program.witness_values()
            || !self
                .identity
                .contract
                .span(
                    self.identity.span.first_unit as u32,
                    self.identity.span.units as u32,
                )
                .is_ok_and(|spec| spec == node.spec)
        {
            return Err(Error::Source);
        }
        let context = &self.identity.context;
        for (offset, values) in [
            (super::super::STATEMENT, context.statement),
            (super::super::EXPECTED_INPUT, context.input),
            (super::super::EXPECTED_OUTPUT, context.output),
        ] {
            if node.public[offset..offset + 4] != values {
                return Err(Error::Source);
            }
        }
        if node.public[super::super::CONTEXT..super::super::CONTEXT + 8]
            != super::super::words(&context.context)
        {
            return Err(Error::Source);
        }
        let operations = OperationCounts::from_program(program);
        let bound = self.geometry;
        if operations.scalar > bound.operations.scalar
            || operations.cubic > bound.operations.cubic
            || operations.poseidon > bound.operations.poseidon
            || program.active_rows() > bound.active_rows_upper_bound
            || program.height() > bound.padded_rows_upper_bound
            || program.wire_count() > bound.wires_upper_bound
            || program.witness_values() != bound.input_values
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
