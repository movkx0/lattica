//! Source-closed unchanged AES request execution. Public selectors remain refused until
//! complete-workflow qualification; no diagnostic receipt authorizes dispatch.

use crate::{
    component_tree::paired_runtime::{self, source, ComponentSourceFacts, ComponentSpan},
    execution::{
        retained_resources::{Category, Ledger, Requirements, Reservation},
        workflow_resources::{PhaseFacts, PhaseKind},
    },
    graph_crypto::{Request, RequestDescriptor},
    graph_tree::GraphContext,
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};
use source::{add, bytes, combine, maxima, requirement};
use std::cell::Cell;

pub(crate) use paired_runtime::{PairedCompiled, PairedFailure, PairedNode};
pub(crate) use operations::{
    OwnedAesEndpointOperation, OwnedAesEndpoints, OwnedAesCompileOperation, OwnedAesMergeOperation,
    OwnedAesNativeOperation, OwnedAesNativeOutput, OwnedAesOuterOperation,
    OwnedAesNativeSource, ProducedAesNative, RecordedAesNative,
};
type Result<T> = core::result::Result<T, PairedFailure>;

mod memory;
mod endpoints;
mod operations;
mod execute;
mod outer;
pub(crate) use outer::{BoundAesOuter, PreissuedAesOuter};
pub(crate) use execute::{OwnedAesExecuteError, OwnedAesRequestOutput, OwnedAesRequestReport};
#[cfg(test)]
mod tests;

/// Node IDs refer only to immutable source topology, never to proof headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedAesNodeSource {
    pub(crate) id: usize,
    pub(crate) span: ComponentSpan,
    pub(crate) source: ComponentSourceFacts,
    pub(crate) children: Option<[usize; 2]>,
    pub(crate) segment: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnedAesStepKind {
    Endpoints,
    Native { index: usize },
    Compile { node: usize },
    Merge { node: usize, left: usize, right: usize },
    Outer { node: usize },
}

/// Exact serial dispatch order. Compile consumes its one native output and
/// borrows endpoints; Merge consumes both recursive children; Outer consumes
/// compiled input. Endpoints remain live until the complete request ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedAesStep {
    pub(crate) kind: OwnedAesStepKind,
    pub(crate) facts: PhaseFacts,
}

/// Category-wise maximum slot sizes. Runtime needs one native slot, one
/// compiled slot and `frontier_slots` recursive slots, plus endpoint/failure.
/// Root replays ordered_steps to assign and prove exact slot lifetimes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnedAesSlotRequirements {
    pub(crate) endpoint: Requirements,
    pub(crate) native: Requirements,
    pub(crate) compiled: Requirements,
    pub(crate) node: Requirements,
    pub(crate) failure: Requirements,
    pub(crate) frontier_slots: usize,
}

pub(crate) struct OwnedAesRequestPlan<'request> {
    request: &'request Request,
    context: GraphContext,
    source_fingerprint: [u8; 32],
    compiled_source_fingerprint: [u8; 32],
    nodes: Vec<OwnedAesNodeSource>,
    steps: Vec<OwnedAesStep>,
    slots: OwnedAesSlotRequirements,
    root: usize,
    source_endpoints: endpoints::SourceEndpointStore<'request>,
    endpoint_attempted: Cell<bool>,
    // Must outlive the metadata vectors and every other field above.
    _metadata_original: Reservation,
}

fn contains(have: Requirements, need: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let h = have.get(category);
        let n = need.get(category);
        n.host <= h.host && n.device <= h.device
    })
}

fn counts(request: &Request) -> Result<(usize, usize, usize)> {
    let RequestDescriptor::Aes(descriptor) = request.descriptor() else { return Err(PairedFailure::Source); };
    let leaves = request.segments().len();
    if leaves == 0 || request.units() != descriptor.blocks() { return Err(PairedFailure::Coverage); }
    let nodes = source::mul(2, leaves)?.checked_sub(1).ok_or(PairedFailure::Overflow)?;
    let steps = add(1, add(leaves, source::mul(2, nodes)?)?)?;
    Ok((leaves, nodes, steps))
}

impl<'request> OwnedAesRequestPlan<'request> {
    /// Retained metadata only. One original scratch reservation is separately
    /// borrowed by all planners before native0; it is not summed per request.
    pub(crate) fn planning_requirements(request: &Request) -> Result<Requirements> {
        let (_, nodes, steps) = counts(request)?;
        let native_packet = add(
            lattica_prover_p3::block_v2::native_gpu::owned_aes::NativeAesReservationPlan::preissue_metadata_host_bytes()
                .map_err(|_| PairedFailure::Resource)?,
            usize::try_from(crate::execution::workflow_resources::aes_native_packet_metadata_host_bytes()
                .map_err(|_| PairedFailure::Resource)?).map_err(|_| PairedFailure::Overflow)?)?;
        requirement(Category::Report, add(
            add(bytes::<OwnedAesNodeSource>(source::mul(2, nodes)?)?,
                bytes::<OwnedAesStep>(source::mul(2, steps)?)?)?,
            add(add(bytes::<Self>(8)?, memory::planning_frames()?)?,
                add(source::mul(nodes, PreissuedAesOuter::metadata_host_bytes()?)?,
                    source::mul(request.segments().len(), native_packet)?)?)?)?)
    }

    /// Allocation-free public descriptor census; no proof/native data used.
    pub(crate) fn planning_scratch_requirements(request: &Request) -> Result<Requirements> {
        let mut peak = source::parent_planning_requirements()?;
        for index in 0..request.segments().len() {
            peak = maxima(peak, source::AesBlueprint::new(request, index)?.planning_requirements()?);
        }
        combine(&[peak, requirement(Category::PhaseScratch, memory::planning_frames()?)?,
            PreissuedAesOuter::planning_scratch_requirement()?])
    }

    pub(crate) fn derive_pre_reserved(
        request: &'request Request, context: GraphContext,
        metadata_original: Reservation, scratch: &Reservation, ledger: &Ledger,
    ) -> Result<Self> {
        let required = Self::planning_requirements(request)?;
        let scratch_required = Self::planning_scratch_requirements(request)?;
        let allowance = ledger.snapshot().allowance;
        if !metadata_original.belongs_to(ledger) || metadata_original.requirements() != required
            || !scratch.belongs_to(ledger) || !contains(scratch.requirements(), scratch_required)
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host) || allowance.device > 8u64 << 30 {
            return Err(PairedFailure::Authority);
        }
        let (leaves, node_count, step_count) = counts(request)?;
        let code = crate::graph_proofs::compiled_source_fingerprint();
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/owned-aes-request-source/v1");
        hash.update(code);
        hash.update(context.context);
        for value in context.statement.into_iter().chain(context.node_manifest) {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        for index in 0..request.segments().len() {
            hash.update(request.cache_key(index).map_err(|_| PairedFailure::Source)?);
        }
        let mut plan = Self { request, context, source_fingerprint: hash.finalize().into(),
            compiled_source_fingerprint: code, nodes: Vec::new(), steps: Vec::new(),
            slots: OwnedAesSlotRequirements::default(), root: 0, source_endpoints: endpoints::SourceEndpointStore::new(request),
            endpoint_attempted: Cell::new(false), _metadata_original: metadata_original };
        plan.nodes.try_reserve_exact(node_count).map_err(|_| PairedFailure::Capacity)?;
        plan.steps.try_reserve_exact(step_count).map_err(|_| PairedFailure::Capacity)?;
        if plan.nodes.capacity() > source::mul(2, node_count)?
            || plan.steps.capacity() > source::mul(2, step_count)? {
            return Err(PairedFailure::Capacity);
        }
        plan.slots.failure = memory::failure_requirements()?;
        plan.slots.endpoint = memory::endpoint_output()?;
        plan.push(OwnedAesStepKind::Endpoints, PhaseKind::EndpointAttach,
            plan.slots.endpoint, requirement(Category::PhaseScratch,
                endpoints::OUTPUT_COPY_FRAME_BYTES)?)?;
        let parent_source = source::parent_source()?;
        let mut carry = [None; usize::BITS as usize];
        let mut live = 0usize;
        let mut maximum_live = 0usize;
        for index in 0..request.segments().len() {
            let blueprint = source::AesBlueprint::new(request, index)?;
            let leaf_source = blueprint.inspect()?;
            let segment = request.segments().get(index).ok_or(PairedFailure::Coverage)?;
            let (output, scratch) = memory::native_requirements(request, index)?;
            plan.slots.native = maxima(plan.slots.native, output);
            plan.push(OwnedAesStepKind::Native { index }, PhaseKind::Native, output, scratch)?;
            let id = plan.nodes.len();
            plan.nodes.push(OwnedAesNodeSource { id,
                span: ComponentSpan {
                    first: u32::try_from(segment.first_unit).map_err(|_| PairedFailure::Overflow)?,
                    count: u32::try_from(segment.units).map_err(|_| PairedFailure::Overflow)?, level: 0 },
                source: leaf_source, children: None, segment: Some(index) });
            let (output, scratch) = blueprint.compiler_requirements()?;
            plan.slots.compiled = maxima(plan.slots.compiled, output);
            plan.push(OwnedAesStepKind::Compile { node: id }, PhaseKind::GroupCompile, output,
                combine(&[scratch, endpoints::group_preparation_requirements(request)?.0])?)?;
            plan.push_outer(id)?;
            live = add(live, 1)?;
            maximum_live = maximum_live.max(live);
            let mut value = id;
            let mut level = 0;
            loop {
                let slot = carry.get_mut(level).ok_or(PairedFailure::Overflow)?;
                match slot.take() {
                    None => { *slot = Some(value); break; }
                    Some(left) => { value = plan.merge(left, value, parent_source)?; live -= 1; level += 1; }
                }
            }
        }
        let mut right = None;
        for left in carry.into_iter().flatten() {
            right = Some(match right {
                None => left,
                Some(right) => { live -= 1; plan.merge(left, right, parent_source)? }
            });
        }
        plan.root = right.ok_or(PairedFailure::Coverage)?;
        let root = plan.nodes[plan.root];
        if root.span.first != 0 || usize::try_from(root.span.count).ok() != Some(request.units())
            || plan.nodes.len() != node_count || plan.steps.len() != step_count || live != 1 || leaves == 0 {
            return Err(PairedFailure::Coverage);
        }
        // Parent outputs are produced only after compiler phase destroys its
        // two children, so maximum occupied frontier slots already suffices.
        plan.slots.frontier_slots = maximum_live;
        Ok(plan)
    }

    fn push(&mut self, kind: OwnedAesStepKind, phase: PhaseKind, output: Requirements, scratch: Requirements) -> Result<()> {
        if self.steps.len() == self.steps.capacity() { return Err(PairedFailure::Capacity); }
        self.steps.push(OwnedAesStep { kind, facts: PhaseFacts { kind: phase,
            source_fingerprint: self.source_fingerprint,
            compiled_source_fingerprint: self.compiled_source_fingerprint,
            output, failure: self.slots.failure, scratch } });
        Ok(())
    }

    fn push_outer(&mut self, id: usize) -> Result<()> {
        let (output, verifier) = self.nodes.get(id).ok_or(PairedFailure::Order)?.source.output_requirements()?;
        self.slots.node = maxima(self.slots.node, output);
        self.push(OwnedAesStepKind::Outer { node: id }, PhaseKind::OuterProve, output,
            combine(&[verifier, paired_runtime::owned_outer_requirements()?,
                PreissuedAesOuter::planning_scratch_requirement()?])?)
    }

    fn merge(&mut self, left: usize, right: usize, source: ComponentSourceFacts) -> Result<usize> {
        let a = *self.nodes.get(left).ok_or(PairedFailure::Order)?;
        let b = *self.nodes.get(right).ok_or(PairedFailure::Order)?;
        let id = self.nodes.len();
        if id == self.nodes.capacity() { return Err(PairedFailure::Capacity); }
        self.nodes.push(OwnedAesNodeSource { id, span: ComponentSpan::merge(a.span, b.span)?, source,
            children: Some([left, right]), segment: None });
        let (output, scratch) = source::compiler_requirements(None)?;
        self.slots.compiled = maxima(self.slots.compiled, output);
        self.push(OwnedAesStepKind::Merge { node: id, left, right }, PhaseKind::ParentCompile, output, scratch)?;
        self.push_outer(id)?;
        Ok(id)
    }

    /// Pure source descriptor census before child proofs or operation owners
    /// exist. The closed scheduler must admit these exact original amounts.
    pub(crate) fn group_preparation_requirements(&self, ordinal: usize)
        -> Result<(Requirements, crate::execution::retained_resources::Bytes)> {
        if !matches!(self.steps.get(ordinal).map(|step| step.kind), Some(OwnedAesStepKind::Compile { .. })) {
            return Err(PairedFailure::Order);
        }
        endpoints::group_preparation_requirements(self.request)
    }

    pub(crate) fn request(&self) -> &'request Request { self.request }
    /// Pure exact source access for A's all-native preissue before proof0.
    /// No timer, cache, proof, source clone or mutable runtime is constructed.
    pub(crate) fn native_source(&self, ordinal: usize) -> Result<OwnedAesNativeSource<'request>> {
        self.check_prepared_endpoints()?;
        let OwnedAesStepKind::Native { index } = self.steps.get(ordinal)
            .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
        if self._metadata_original.requirements() != Self::planning_requirements(self.request)? {
            return Err(PairedFailure::Authority);
        }
        OwnedAesNativeSource::new(self.request, index)
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self._metadata_original.belongs_to(ledger) }
    pub(crate) fn graph_context(&self) -> &GraphContext { &self.context }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.source_fingerprint }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.compiled_source_fingerprint }
    pub(crate) fn root_source(&self) -> ComponentSourceFacts { self.nodes[self.root].source }
    pub(crate) fn root_id(&self) -> usize { self.root }
    pub(crate) fn node_sources(&self) -> &[OwnedAesNodeSource] { &self.nodes }
    pub(crate) fn ordered_steps(&self) -> &[OwnedAesStep] { &self.steps }
    pub(crate) fn slot_requirements(&self) -> OwnedAesSlotRequirements { self.slots }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { self.steps.get(ordinal).map(|step| step.facts) }
}
