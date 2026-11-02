//! Stable source-derived lifetime scheduling. Only concrete typed operations
//! enter the schedule; no numerical event list can authorize proving.
use super::{closure_planning::{self as source, ClosureError, Result, SourceClosurePlanningPlan},
    SourceOperationPlan, SourcePlanningPlan, PreparedWorkflowSources};
use crate::{
    execution::{ProvingContext, retained_resources::{Bytes, Category, Ledger, Requirements, Reservation, Snapshot},
        workflow_resources::{PhaseBinding, PhaseKind, PhaseStep, SlotId, SlotSpec, SourceRetained}},
    graph_crypto::{OwnedAesRequestPlan, OwnedAesStepKind, PairedRequestPlan, Request, RequestStepKind},
    ordered_aggregation::source::{ChildSource, FinalAggregationPlan},
};
use core::mem::size_of;
use source::{add, mul, sum, maximum};
#[cfg(not(debug_assertions))]
mod complete;
#[cfg(not(debug_assertions))]
pub(crate) use complete::tables as producer_tables;
#[cfg(not(debug_assertions))]
pub(crate) use complete::{DispatchVerificationIdentity, verification_identity_frame_bytes, CompleteProducerTables, ParentTables, CompleteStage, CompleteScheduleFailure, CompleteScheduleResult,
    ValidatedCompleteInventory, complete_metadata_requirements, complete_inspection_requirements,
    complete_slot_requirements};
mod dispatch;
pub(crate) use dispatch::{StepDispatch, ProducerRoute, NativeFamily, LeafFamily,
    DirectFamily, CryptoFamily, CryptoOutput, GraphPhase, FinalOutput};
#[cfg(not(debug_assertions))]
use super::metadata_planning::SourceMetadataPlanningPlan;
#[cfg(not(debug_assertions))]
use crate::execution::workflow_resources::{PlanningAdmissionTransition, PlanningAdmissionProjection};

// ExpandAlpha consumes two exact request roots, their endpoint owners,
// and the Uniform/Sparse native owners. Each edge is precharged.
const MAX_PHASE_INPUTS: usize = lattica_prover_p3::block_v2::machine::backend::identity_cpu::MAX_IDENTITY_STREAMS;
mod slot_policy;
mod memory_diagnostics;
use memory_diagnostics::{CloseMemoryStage, MemoryGate};

#[derive(Clone, Copy)]
pub(crate) enum CryptoRequestPlan<'a> {
    Shake(&'a PairedRequestPlan<'a>),
    Aes(&'a OwnedAesRequestPlan<'a>),
}
#[derive(Clone, Copy)]
enum Event {
    Endpoints, Native(usize), Group { node: usize, first: usize, count: usize },
    Merge { node: usize, left: usize, right: usize }, Outer(usize),
}
impl<'a> CryptoRequestPlan<'a> {
    fn request(self) -> &'a Request { match self { Self::Shake(p) => p.request(), Self::Aes(p) => p.request() } }
    fn len(self) -> usize { match self { Self::Shake(p) => p.ordered_steps().len(), Self::Aes(p) => p.ordered_steps().len() } }
    fn belongs_to(self, ledger: &Ledger) -> bool { match self { Self::Shake(p) => p.belongs_to(ledger), Self::Aes(p) => p.belongs_to(ledger) } }
    fn context(self) -> &'a crate::graph_tree::GraphContext { match self { Self::Shake(p) => p.graph_context(), Self::Aes(p) => p.graph_context() } }
    fn root(self) -> usize { match self { Self::Shake(p) => p.root_id(), Self::Aes(p) => p.root_id() } }
    fn binding(self, ordinal: usize) -> Result<PhaseBinding> {
        match self { Self::Shake(p) => PhaseBinding::for_paired(p, ordinal), Self::Aes(p) => PhaseBinding::for_aes(p, ordinal) }
            .map_err(|_| ClosureError::Source)
    }
    fn group_backend(self, ordinal: usize) -> Result<Bytes> {
        match self { Self::Shake(p) => p.group_preparation_requirements(ordinal),
            Self::Aes(p) => p.group_preparation_requirements(ordinal) }
            .map(|(_, backend)| backend).map_err(|_| ClosureError::Resource)
    }
    fn event(self, ordinal: usize) -> Result<Event> {
        Ok(match self {
            Self::Shake(p) => match p.ordered_steps().get(ordinal).ok_or(ClosureError::Order)?.kind {
                RequestStepKind::Endpoints => Event::Endpoints,
                RequestStepKind::Native { index } => Event::Native(index),
                RequestStepKind::Group { node } => {
                    let span = p.node_sources().get(node).and_then(|node| node.group).ok_or(ClosureError::Coverage)?;
                    Event::Group { node, first: span.first_segment, count: span.segment_count }
                }
                RequestStepKind::Merge { node, left, right } => Event::Merge { node, left, right },
                RequestStepKind::Outer { node } => Event::Outer(node),
            },
            Self::Aes(p) => match p.ordered_steps().get(ordinal).ok_or(ClosureError::Order)?.kind {
                OwnedAesStepKind::Endpoints => Event::Endpoints,
                OwnedAesStepKind::Native { index } => Event::Native(index),
                OwnedAesStepKind::Compile { node } => Event::Group { node,
                    first: p.node_sources().get(node).and_then(|node| node.segment).ok_or(ClosureError::Coverage)?, count: 1 },
                OwnedAesStepKind::Merge { node, left, right } => Event::Merge { node, left, right },
                OwnedAesStepKind::Outer { node } => Event::Outer(node),
            },
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RequestRootSlots {
    pub(crate) transaction: usize,
    pub(crate) request: usize,
    pub(crate) root: SlotId,
    pub(crate) endpoints: SlotId,
}

/// Packed output claims and immutable events. This type alone is a planning
/// result; it cannot be passed to WorkflowAdmission. Original metadata outlives
/// all collections, including failure/unwind paths.
pub(crate) struct SupportedSchedule<'a> {
    scope: &'a SourcePlanningPlan<'a>,
    members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>],
    fixed: &'a [&'a SourceOperationPlan<'a>],
    crypto: &'a [CryptoRequestPlan<'a>],
    final_source: &'a FinalAggregationPlan<'a>,
    slots: Vec<SlotSpec>,
    live: Vec<bool>,
    steps: Vec<PhaseStep>,
    inputs: Vec<SlotId>,
    roots: Vec<RequestRootSlots>,
    fixed_slots: [Option<SlotId>; 4],
    scratch: Requirements,
    #[cfg(not(debug_assertions))]
    complete_tables: Option<&'a CompleteProducerTables<'a>>,
    #[cfg(not(debug_assertions))]
    graph_nodes: Vec<complete::GraphRecord<'a>>,
    dispatch: Vec<StepDispatch>,
    original: Reservation,
}

pub(super) fn schedule_metadata_requirements(steps: usize, requests: usize) -> Result<Requirements> {
    let slots = add(steps, 1)?;
    let backing = [mul(slots, size_of::<SlotSpec>())?, mul(slots, size_of::<bool>())?,
        mul(steps, size_of::<PhaseStep>())?, mul(mul(steps, MAX_PHASE_INPUTS)?, size_of::<SlotId>())?,
        mul(requests, size_of::<RequestRootSlots>())?, mul(requests, size_of::<CryptoRequestPlan<'static>>())?,
        mul(steps, size_of::<SourceOperationPlan<'static>>())?,
    ].into_iter().try_fold(0, add)?;
    let frames = [size_of::<SupportedSchedule<'static>>(), size_of::<ClosedWorkflowPlan<'static>>(),
        size_of::<RequestState>(), size_of::<Requirements>(), size_of::<PhaseStep>(),
        size_of::<Result<SupportedSchedule<'static>>>(), size_of::<Result<ClosedWorkflowPlan<'static>>>(),
        size_of::<[SlotId; MAX_PHASE_INPUTS]>(), size_of::<Ledger>(), size_of::<Event>(), size_of::<[u64; 16]>(),
        slot_policy::SELECTION_FRAME_BYTES,
        memory_diagnostics::FRAME_BYTES,
    ].into_iter().try_fold(0, add)?;
    Ok(Requirements::single(Category::RegisteredMetadata, source::host(add(mul(backing, 3)?, mul(frames, 8)?)?)?))
}

fn vector<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| ClosureError::Allocation)?;
    if values.capacity() > count { return Err(ClosureError::Allocation); }
    Ok(values)
}
fn push<T>(values: &mut Vec<T>, value: T) -> Result<()> {
    if values.len() == values.capacity() { return Err(ClosureError::Allocation); }
    values.push(value); Ok(())
}

struct RequestState {
    endpoints: Option<SlotId>,
    native: [Option<(usize, SlotId)>; 2],
    compiled: [Option<(usize, SlotId)>; MAX_PHASE_INPUTS],
    frontier: [Option<(usize, SlotId)>; usize::BITS as usize],
}
impl RequestState {
    fn new() -> Self { Self { endpoints: None, native: [None; 2], compiled: [None; MAX_PHASE_INPUTS], frontier: [None; usize::BITS as usize] } }
    fn insert_compiled(&mut self, node: usize, slot: SlotId) -> Result<()> {
        if self.compiled.iter().flatten().any(|(id, _)| *id == node) { return Err(ClosureError::Order); }
        *self.compiled.iter_mut().find(|entry| entry.is_none()).ok_or(ClosureError::Order)? = Some((node, slot));
        Ok(())
    }
    fn compiled_slot(&self, node: usize) -> Result<SlotId> {
        self.compiled.iter().flatten().find(|(id, _)| *id == node)
            .map(|(_, slot)| *slot).ok_or(ClosureError::Order)
    }
    fn take_compiled(&mut self, node: usize) -> Result<SlotId> {
        self.compiled.iter_mut().find(|entry| entry.is_some_and(|(id, _)| id == node))
            .and_then(Option::take).map(|(_, slot)| slot).ok_or(ClosureError::Order)
    }
    fn node(&mut self, id: usize) -> Result<SlotId> {
        self.frontier.iter_mut().find(|entry| entry.is_some_and(|(node, _)| node == id))
            .and_then(Option::take).map(|(_, slot)| slot).ok_or(ClosureError::Order)
    }
}

/// Keep every runtime-retained original, idle pool claim and current temporary
/// inside the worker budget. Only the authenticated complete transition may
/// account for the exact construction scratch release/startup-original reunion.
/// Historical closure retains its full observed ledger. No measured RSS enters.
fn outer_residual(allowance: Bytes, retained: Bytes, pool: Bytes, scratch: Bytes,
    requested: u64) -> Result<Bytes>
{
    if allowance.host == 0 || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host) || allowance.device != 8 << 30
        || retained.device != 0 || pool.device != 0 || scratch.device != 0 || requested == 0
    { return Err(ClosureError::Resource); }
    let host = allowance.host.checked_sub(retained.host).and_then(|n| n.checked_sub(pool.host))
        .and_then(|n| n.checked_sub(scratch.host)).filter(|n| *n > 0).ok_or(ClosureError::Resource)?;
    Ok(Bytes { host: host.min(requested), device: allowance.device })
}

/// Match the actual preflight admission, including its separate pool owner.
/// Controller/receipt frames remain in their original retained planning claim.
fn admission_pool_requirements(slots: &[SlotSpec]) -> Result<(Requirements, Requirements)> {
    let mut pool = Requirements::default();
    for slot in slots { pool = sum(pool, slot.requirements)?; }
    let bookkeeping = crate::execution::workflow_resources::closed_pool_requirements(slots.len())
        .map_err(|_| ClosureError::Resource)?;
    Ok((pool, bookkeeping))
}

fn check_combined_admission(allowance: Bytes, retained: Bytes, active: Bytes) -> Result<()> {
    if active.host.checked_add(retained.host).is_none_or(|n| n > allowance.host)
        || active.device.checked_add(retained.device).is_none_or(|n| n > allowance.device)
    { return Err(ClosureError::Resource); }
    Ok(())
}

fn is_outer(kind: PhaseKind) -> bool {
    matches!(kind, PhaseKind::OuterProve | PhaseKind::GraphOuter | PhaseKind::FinalOuter)
}
fn is_native(kind: PhaseKind) -> bool {
    matches!(kind, PhaseKind::Native | PhaseKind::SourceNative | PhaseKind::UniformNative
        | PhaseKind::SparseNative | PhaseKind::TranscriptNative | PhaseKind::AffineNative
        | PhaseKind::NttNative | PhaseKind::MulNative | PhaseKind::GBoundNative
        | PhaseKind::PermutationNative | PhaseKind::LinearMapNative)
}

impl<'a> SupportedSchedule<'a> {
    pub(crate) fn derive_pre_reserved(scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>],
        fixed: &'a [&'a SourceOperationPlan<'a>], crypto: &'a [CryptoRequestPlan<'a>],
        final_source: &'a FinalAggregationPlan<'a>, original: Reservation,
        ledger: &Ledger) -> Result<Self>
    {
        if !matches!(members.len(), 3 | 4) || members.len() != scope.natives().len()
            || fixed.len() != members.len() || !original.belongs_to(ledger)
            || !final_source.belongs_to(ledger) || final_source.graphs().len() != members.len()
            || final_source.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
        { return Err(ClosureError::Identity); }
        let mut count = members.len();
        let mut expected_requests = 0;
        for (index, owner) in members.iter().enumerate() {
            let value = owner.get();
            if !owner.belongs_to(ledger) || owner.source_fingerprint() != scope.source_fingerprint()
                || owner.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
                || !core::ptr::eq(value.native_source(), &scope.natives()[index])
                || !core::ptr::eq(fixed[index].sources(), *owner)
                || !core::ptr::eq(fixed[index].context(), scope.context())
                || fixed[index].workflow_source_fingerprint() != scope.source_fingerprint()
                || !core::ptr::eq(final_source.graphs()[index].plan, value.plan())
                || !core::ptr::eq(final_source.graphs()[index].context, value.context())
            { return Err(ClosureError::Identity); }
            for request in value.crypto().requests() {
                let plan = *crypto.get(expected_requests).ok_or(ClosureError::Coverage)?;
                if !plan.belongs_to(ledger) || !core::ptr::eq(plan.request(), request)
                    || plan.context() != value.context()
                    || matches!(plan, CryptoRequestPlan::Shake(p) if p.layout() != scope.layout())
                { return Err(ClosureError::Identity); }
                count = add(count, plan.len())?;
                expected_requests = add(expected_requests, 1)?;
            }
        }
        if expected_requests != crypto.len() { return Err(ClosureError::Coverage); }
        let required = schedule_metadata_requirements(count, crypto.len())?;
        if original.requirements() != required { return Err(ClosureError::Resource); }
        let mut result = Self { scope, members, fixed, crypto, final_source,
            slots: vector(add(count, 1)?)?, live: vector(add(count, 1)?)?,
            steps: vector(count)?, inputs: vector(mul(count, MAX_PHASE_INPUTS)?)?, roots: vector(crypto.len())?,
            fixed_slots: [None; 4], scratch: Requirements::default(),
            #[cfg(not(debug_assertions))]
            complete_tables: None,
            #[cfg(not(debug_assertions))]
            graph_nodes: Vec::new(),
            dispatch: Vec::new(), original };
        // Exactly one failure can survive because its phase poisons the whole
        // admission. This slot never doubles as a successful output.
        push(&mut result.slots, SlotSpec { requirements: Requirements::default() })?;
        push(&mut result.live, false)?;
        let mut request_index = 0;
        for transaction in 0..members.len() {
            let binding = PhaseBinding::for_source(fixed[transaction], 0).map_err(|_| ClosureError::Source)?;
            if fixed[transaction].phase_count() != 1 || binding.kind() != PhaseKind::SourceCompile
                || fixed[transaction].backend_allowance() != Bytes::ZERO { return Err(ClosureError::Source); }
            result.fixed_slots[transaction] = Some(result.record(binding, &[], 0, Bytes::ZERO)?);
            for local in 0..members[transaction].get().crypto().requests().len() {
                let plan = crypto[request_index];
                let (root, endpoints) = result.request(plan)?;
                push(&mut result.roots, RequestRootSlots { transaction, request: local, root, endpoints })?;
                request_index += 1;
            }
        }
        if result.steps.len() != count { return Err(ClosureError::Coverage); }
        result.close_memory(ledger, None)?;
        result.validate_final_topology()?;
        Ok(result)
    }

    fn record(&mut self, binding: PhaseBinding, inputs: &[SlotId], consumed: usize, backend: Bytes) -> Result<SlotId> {
        let facts = binding.facts();
        if self.steps.iter().any(|step| step.binding == binding) { return Err(ClosureError::Order); }
        if inputs.len() > MAX_PHASE_INPUTS || consumed > inputs.len() || facts.compiled_source_fingerprint != self.scope.compiled_source_fingerprint()
            || facts.output.total().map_err(|_| ClosureError::Overflow)? == Bytes::ZERO
            || facts.failure.total().map_err(|_| ClosureError::Overflow)? == Bytes::ZERO
            || facts.output.get(Category::PhaseScratch) != Bytes::ZERO
            || facts.failure.get(Category::PhaseScratch) != Bytes::ZERO
        { return Err(ClosureError::Source); }
        for (index, slot) in inputs.iter().enumerate() {
            if slot.index() == 0 || !self.live.get(slot.index()).copied().unwrap_or(false)
                || inputs[..index].contains(slot) { return Err(ClosureError::Order); }
        }
        // Choose output while every consumed child is STILL live: compiler
        // output overlaps all its children. Reuse only after this event ends.
        // Keep compiler/proof domains separate. The two host compiler owner
        // shapes may retain the union of optional typed-owner metadata; every
        // category keeps its full historical maximum through actual cleanup.
        let index = if let Some(index) = slot_policy::first_compatible(&self.slots, &self.live, facts.output) {
            self.slots[index].requirements = maximum(self.slots[index].requirements, facts.output); index
        } else {
            let index = self.slots.len();
            push(&mut self.slots, SlotSpec { requirements: facts.output })?;
            push(&mut self.live, false)?; index
        };
        let output = SlotId::new(index);
        let start = self.inputs.len();
        for slot in inputs { push(&mut self.inputs, *slot)?; }
        push(&mut self.steps, PhaseStep { binding, output, failure: SlotId::new(0),
            input_start: start, input_count: inputs.len(), consume_count: consumed, backend })?;
        self.slots[0].requirements = maximum(self.slots[0].requirements, facts.failure);
        for slot in &inputs[..consumed] { self.live[slot.index()] = false; }
        self.live[index] = true;
        Ok(output)
    }

    fn request(&mut self, plan: CryptoRequestPlan<'a>) -> Result<(SlotId, SlotId)> {
        self.request_routed(plan, None)
    }

    fn request_routed(&mut self, plan: CryptoRequestPlan<'a>, route: Option<dispatch::CryptoRoute>) -> Result<(SlotId, SlotId)> {
        let mut state = RequestState::new();
        let mut next_native = 0;
        for ordinal in 0..plan.len() {
            let binding = plan.binding(ordinal)?;
            let routed = route.map(|route| route.step(plan, ordinal)).transpose()?;
            match plan.event(ordinal)? {
                Event::Endpoints => {
                    if ordinal != 0 || state.endpoints.is_some() || binding.kind() != PhaseKind::EndpointAttach { return Err(ClosureError::Order); }
                    state.endpoints = Some(self.record_request(binding, &[], 0, Bytes::ZERO, routed)?);
                }
                Event::Native(index) => {
                    if index != next_native || binding.kind() != PhaseKind::Native { return Err(ClosureError::Order); }
                    let target = state.native.iter_mut().find(|slot| slot.is_none()).ok_or(ClosureError::Order)?;
                    *target = Some((index, self.record_request(binding, &[], 0,
                        Bytes { host: self.scope.budgets().native_bytes, device: 8 << 30 }, routed)?));
                    next_native = add(next_native, 1)?;
                }
                Event::Group { node, first, count } => {
                    if !matches!(count, 1 | 2) || binding.kind() != PhaseKind::GroupCompile
                        || state.native.iter().filter(|entry| entry.is_some()).count() != count { return Err(ClosureError::Coverage); }
                    let mut inputs = [SlotId::new(0); 3];
                    for offset in 0..count {
                        let (index, slot) = state.native[offset].take().ok_or(ClosureError::Coverage)?;
                        if index != add(first, offset)? { return Err(ClosureError::Coverage); }
                        inputs[offset] = slot;
                    }
                    inputs[count] = state.endpoints.ok_or(ClosureError::Order)?;
                    state.insert_compiled(node, self.record_request(binding, &inputs[..count + 1], count, plan.group_backend(ordinal)?, routed)?)?;
                }
                Event::Merge { node, left, right } => {
                    if left == right || binding.kind() != PhaseKind::ParentCompile { return Err(ClosureError::Order); }
                    let inputs = [state.node(left)?, state.node(right)?];
                    state.insert_compiled(node, self.record_request(binding, &inputs, 2, Bytes::ZERO, routed)?)?;
                }
                Event::Outer(node) => {
                    if binding.kind() != PhaseKind::OuterProve || state.frontier.iter().any(|entry| entry.is_some_and(|(id, _)| id == node)) { return Err(ClosureError::Order); }
                    let mut inputs = [SlotId::new(0); MAX_PHASE_INPUTS];
                    inputs[0] = state.take_compiled(node)?;
                    let mut count = 1;
                    if let CryptoRequestPlan::Shake(request) = plan {
                        let (nodes, cohort) = request.identity_cohort(node).map_err(|_| ClosureError::Source)?;
                        for sibling in &nodes[1..cohort.max(1)] {
                            inputs[count] = state.compiled_slot(*sibling)?;
                            count += 1;
                        }
                    }
                    // Host allowance is sealed after ALL pool slots and current
                    // scratch categories are known. No runtime sees this draft.
                    let output = self.record_request(binding, &inputs[..count], 1, Bytes::ZERO, routed)?;
                    *state.frontier.iter_mut().find(|slot| slot.is_none()).ok_or(ClosureError::Order)? = Some((node, output));
                }
            }
        }
        let root = state.node(plan.root())?;
        if next_native != plan.request().segments().len() || state.native.iter().any(Option::is_some)
            || state.compiled.iter().any(Option::is_some) || state.frontier.iter().any(Option::is_some) { return Err(ClosureError::Coverage); }
        Ok((root, state.endpoints.ok_or(ClosureError::Coverage)?))
    }

    fn record_request(&mut self, binding: PhaseBinding, inputs: &[SlotId], consume: usize,
        backend: Bytes, route: Option<ProducerRoute>) -> Result<SlotId>
    {
        match route {
            Some(route) => self.record_routed(binding, inputs, consume, backend, route),
            None => self.record(binding, inputs, consume, backend),
        }
    }

    fn close_memory(&mut self, ledger: &Ledger, observation: Option<&mut CloseMemoryStage>) -> Result<()> {
        let snapshot = ledger.snapshot();
        self.close_memory_accounted(snapshot, snapshot.current, Requirements::default(),
            Requirements::default(), observation)
    }

    #[cfg(not(debug_assertions))]
    fn close_memory_for_admission(&mut self, ledger: &Ledger,
        transition: &PlanningAdmissionTransition<'_, '_>, mut observation: Option<&mut CloseMemoryStage>)
        -> Result<PlanningAdmissionProjection>
    {
        let snapshot = ledger.snapshot();
        if let Some(stage) = observation.as_deref_mut() {
            stage.at(MemoryGate::Transition, None);
            stage.allowance = Some(Bytes { host: snapshot.allowance.host, device: snapshot.allowance.device });
            stage.observed_retained = Some(snapshot.current);
        }
        let projection = transition.project(self.scope, ledger).map_err(|_| ClosureError::Identity)?;
        if projection.observed_retained() != snapshot.current { return Err(ClosureError::Identity); }
        self.close_memory_accounted(snapshot, projection.projected_retained(),
            projection.released_planning_scratch(), projection.transferred_startup(), observation)?;
        Ok(projection)
    }

    /// Private arithmetic shared by historical closure and the authenticated
    /// complete transition above. No external scalar-credit entry point exists.
    fn close_memory_accounted(&mut self, snapshot: Snapshot, retained: Bytes,
        planning_scratch_release: Requirements, startup_transfer: Requirements,
        mut observation: Option<&mut CloseMemoryStage>) -> Result<()> {
        if let Some(stage) = observation.as_deref_mut() {
            stage.at(MemoryGate::Pool, None);
            stage.allowance = Some(Bytes { host: snapshot.allowance.host, device: snapshot.allowance.device });
            stage.observed_retained = Some(snapshot.current);
            stage.projected_retained = Some(retained);
            stage.released_planning_scratch = planning_scratch_release.total().ok();
            stage.transferred_startup = startup_transfer.total().ok();
            let observed = snapshot.categories[Category::SymbolicCompiler as usize].current;
            let released = planning_scratch_release.get(Category::SymbolicCompiler);
            let transferred = startup_transfer.get(Category::SymbolicCompiler);
            stage.retained_compiler = observed.host.checked_sub(released.host)
                .and_then(|host| host.checked_sub(transferred.host))
                .zip(observed.device.checked_sub(released.device)
                    .and_then(|device| device.checked_sub(transferred.device)))
                .map(|(host, device)| Bytes { host, device });
        }
        #[cfg(test)]
        memory_diagnostics::profile_slots(&self.slots);
        #[cfg(test)]
        memory_diagnostics::profile_retained(&snapshot, planning_scratch_release, startup_transfer);
        let (pool, bookkeeping) = admission_pool_requirements(&self.slots)?;
        let pool_bytes = pool.total().map_err(|_| ClosureError::Overflow)?;
        let admission_pool = sum(pool, bookkeeping)?;
        let admission_pool_bytes = admission_pool.total().map_err(|_| ClosureError::Overflow)?;
        if let Some(stage) = observation.as_deref_mut() {
            stage.pool = Some(pool_bytes);
            stage.pool_bookkeeping = bookkeeping.total().ok();
            stage.pool_compiler = Some(pool.get(Category::SymbolicCompiler));
        }
        // Every non-PhaseScratch category is held at its complete source
        // maximum, including while a different phase is executing. Use that
        // exact combined owner when selecting each outer residual.
        let mut fixed = Requirements::default();
        for (ordinal, step) in self.steps.iter().enumerate() {
            let backend = if is_outer(step.binding.kind()) { Bytes::ZERO } else { step.backend };
            let scratch = step.binding.facts().scratch;
            if let Some(stage) = observation.as_deref_mut() {
                stage.at(MemoryGate::FixedScratch, Some(ordinal));
                stage.current_scratch = scratch.total().ok();
                stage.requested_backend = Some(backend);
            }
            let next = maximum(fixed, sum(scratch,
                Requirements::single(Category::PhaseScratch, backend))?);
            #[cfg(test)]
            memory_diagnostics::profile_maxima(ordinal, step.binding.kind(), fixed, next);
            fixed = next;
        }
        if let Some(stage) = observation.as_deref_mut() {
            stage.at(MemoryGate::FixedOther, None);
            stage.fixed_scratch = fixed.total().ok();
            stage.compiler_scratch = Some(fixed.get(Category::SymbolicCompiler));
        }
        let mut other = Requirements::default();
        for category in Category::ALL {
            if category != Category::PhaseScratch {
                other.add(category, fixed.get(category)).map_err(|_| ClosureError::Overflow)?;
            }
        }
        for (ordinal, step) in self.steps.iter_mut().enumerate() {
            let scratch = step.binding.facts().scratch;
            if is_outer(step.binding.kind()) {
                if let Some(stage) = observation.as_deref_mut() {
                    stage.at(MemoryGate::OuterResidual, Some(ordinal));
                    stage.requested_backend = Some(Bytes { host: self.scope.budgets().outer_bytes,
                        device: snapshot.allowance.device });
                }
                let held = sum(other, Requirements::single(Category::PhaseScratch,
                    scratch.get(Category::PhaseScratch)))?;
                let held_bytes = held.total().map_err(|_| ClosureError::Overflow)?;
                if let Some(stage) = observation.as_deref_mut() {
                    stage.current_scratch = Some(held_bytes);
                    // The residual gate requires at least one host byte; the
                    // requested cap is a ceiling, not a minimum allocation.
                    if let Some(host) = admission_pool_bytes.host.checked_add(held_bytes.host)
                        .and_then(|host| host.checked_add(1)) {
                        stage.combined(Bytes { host, device: snapshot.allowance.device });
                    }
                }
                step.backend = outer_residual(Bytes { host: snapshot.allowance.host, device: snapshot.allowance.device },
                    retained, admission_pool_bytes,
                    held_bytes, self.scope.budgets().outer_bytes)?;
            }
            if let Some(stage) = observation.as_deref_mut() {
                stage.at(MemoryGate::Backend, Some(ordinal));
                stage.current_scratch = scratch.total().ok();
                stage.requested_backend = Some(step.backend);
            }
            if step.backend.device != 0 && step.backend.device != 8 << 30 { return Err(ClosureError::Resource); }
            if is_native(step.binding.kind()) && (step.backend.host == 0 || step.backend.host > 24 << 30) { return Err(ClosureError::Resource); }
            if let Some(stage) = observation.as_deref_mut() { stage.gate = MemoryGate::ScratchMaximum; }
            self.scratch = maximum(self.scratch, sum(scratch,
                Requirements::single(Category::PhaseScratch, step.backend))?);
        }
        // Category maxima can exceed the maximum scalar sum when distinct
        // phases peak in different categories. Check the actual combined owner.
        if let Some(stage) = observation.as_deref_mut() {
            stage.at(MemoryGate::CombinedAdmission, None);
            stage.current_scratch = self.scratch.total().ok();
            stage.compiler_scratch = Some(self.scratch.get(Category::SymbolicCompiler));
        }
        // Actual admission subtracts only this authentic startup subset and
        // reunites its original after source-session retirement. It must fit
        // the complete runtime scratch in the same categories before dispatch.
        if !source::contains(self.scratch, startup_transfer) { return Err(ClosureError::Resource); }
        let active = sum(admission_pool, self.scratch)?.total().map_err(|_| ClosureError::Overflow)?;
        if let Some(stage) = observation.as_deref_mut() { stage.combined(active); }
        check_combined_admission(Bytes { host: snapshot.allowance.host, device: snapshot.allowance.device },
            retained, active)
    }

    fn validate_final_topology(&self) -> Result<()> {
        let total = self.members.len();
        if self.final_source.merge_count() != total - 1 { return Err(ClosureError::Coverage); }
        let mut graph = [true; 4]; let mut merges = [false; 3];
        for ordinal in 0..total - 1 {
            let merge = self.final_source.merge(ordinal).ok_or(ClosureError::Coverage)?;
            let (first, count) = merge.span(); let mut next = first;
            if merge.ordinal() != ordinal || merge.rows().1 > 1 << 20 { return Err(ClosureError::Coverage); }
            for child in merge.children() {
                let (start, length) = match child {
                    ChildSource::Graph(index) if index < total && graph[index] => { graph[index] = false; (index, 1) }
                    ChildSource::Merge(index) if index < ordinal && merges[index] => {
                        merges[index] = false; self.final_source.merge(index).ok_or(ClosureError::Coverage)?.span()
                    }
                    _ => return Err(ClosureError::Coverage),
                };
                if start != next { return Err(ClosureError::Coverage); }
                next = add(next, length)?;
            }
            if next != add(first, count)? { return Err(ClosureError::Coverage); }
            merges[ordinal] = true;
        }
        if graph[..total].iter().any(|live| *live) || merges.iter().filter(|live| **live).count() != 1
            || self.final_source.merge(total - 2).ok_or(ClosureError::Coverage)?.span() != (0, total)
        { return Err(ClosureError::Coverage); }
        Ok(())
    }
}

/// The historical refusal remains distinct from complete constructor authority.
/// Only the complete path validates all concrete producer tables and issues a
/// complete-inventory token; source geometry cannot substitute for that walk.
#[derive(Clone, Copy)]
enum ClosureAuthority<'a> {
    Historical(&'a SourceClosurePlanningPlan<'a>),
    #[cfg(not(debug_assertions))]
    Complete(&'a SourceMetadataPlanningPlan<'a>),
}
impl<'a> ClosureAuthority<'a> {
    fn context(&self) -> &'a ProvingContext {
        match self {
            Self::Historical(plan) => plan.context(),
            #[cfg(not(debug_assertions))]
            Self::Complete(plan) => plan.context(),
        }
    }
    fn source_fingerprint(&self) -> [u8; 32] {
        match self {
            Self::Historical(plan) => plan.source_fingerprint(),
            #[cfg(not(debug_assertions))]
            Self::Complete(plan) => plan.source_fingerprint(),
        }
    }
    fn compiled_source_fingerprint(&self) -> [u8; 32] {
        match self {
            Self::Historical(plan) => plan.compiled_source_fingerprint(),
            #[cfg(not(debug_assertions))]
            Self::Complete(plan) => plan.compiled_source_fingerprint(),
        }
    }
    fn enclosing_bytes(&self) -> Bytes {
        match self {
            Self::Historical(plan) => plan.enclosing_bytes(),
            #[cfg(not(debug_assertions))]
            Self::Complete(plan) => plan.enclosing_bytes(),
        }
    }
    fn belongs_to(&self, ledger: &Ledger) -> bool {
        match self {
            Self::Historical(plan) => plan.belongs_to(ledger),
            #[cfg(not(debug_assertions))]
            Self::Complete(plan) => plan.belongs_to(ledger),
        }
    }
}

pub(crate) struct ClosedWorkflowPlan<'a> {
    authority: ClosureAuthority<'a>,
    // Numeric projection with private original-owner provenance. Runtime
    // revalidates it before performing the already-required real transition.
    // Its observation handles drop before schedule.original releases the
    // complete metadata reservation which pays for their retained storage.
    #[cfg(not(debug_assertions))]
    admission_projection: Option<PlanningAdmissionProjection>,
    schedule: SupportedSchedule<'a>,
    native_cache: &'a crate::graph_crypto::ProofCache,
    outer_cache: &'a crate::graph_crypto::OuterProofCache,
}
impl<'a> ClosedWorkflowPlan<'a> {
    pub(crate) fn planning_requirements(closure: &SourceClosurePlanningPlan<'_>) -> Result<Requirements> {
        let inspection = closure.inspection();
        schedule_metadata_requirements(inspection.known_steps, inspection.crypto_requests)
    }

    pub(crate) fn derive_pre_reserved(closure: &'a SourceClosurePlanningPlan<'a>,
        fixed: &'a [&'a SourceOperationPlan<'a>], crypto: &'a [CryptoRequestPlan<'a>],
        final_source: &'a FinalAggregationPlan<'a>, original: Reservation,
        native_cache: &'a crate::graph_crypto::ProofCache,
        outer_cache: &'a crate::graph_crypto::OuterProofCache) -> Result<Self>
    {
        if native_cache.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly
            || outer_cache.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly {
            return Err(ClosureError::Source);
        }
        closure.inspection().unavailable.require_complete()?;
        let schedule = SupportedSchedule::derive_pre_reserved(closure.scope(), closure.members(), fixed,
            crypto, final_source, original, closure.ledger())?;
        // Known crypto roots and compiled fixed-source nodes must all be
        // consumed by real graph producers, and final proof+CPU verification
        // must appear. No current supported operation does so; inspect actual
        // retained outputs rather than fabricating a terminal phase.
        if schedule.steps.last().map(|step| step.binding.kind()) != Some(PhaseKind::FinalVerify) {
            return Err(ClosureError::Coverage);
        }
        Ok(Self { authority: ClosureAuthority::Historical(closure), schedule, native_cache, outer_cache,
            #[cfg(not(debug_assertions))]
            admission_projection: None })
    }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.authority.context() }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.authority.source_fingerprint() }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.authority.compiled_source_fingerprint() }
    pub(crate) fn enclosing_bytes(&self) -> Bytes { self.authority.enclosing_bytes() }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.authority.belongs_to(ledger) && self.schedule.original.belongs_to(ledger)
            && self.schedule.crypto.iter().all(|plan| plan.belongs_to(ledger))
            && self.schedule.final_source.belongs_to(ledger)
    }
    pub(crate) fn fresh_only(&self) -> bool {
        self.native_cache.policy() == crate::proof_cache_policy::ProofCachePolicy::FreshOnly
            && self.outer_cache.policy() == crate::proof_cache_policy::ProofCachePolicy::FreshOnly
    }
    pub(crate) fn slots(&self) -> &[SlotSpec] { &self.schedule.slots }
    pub(crate) fn steps(&self) -> &[PhaseStep] { &self.schedule.steps }
    pub(crate) fn dispatch(&self) -> &[StepDispatch] { &self.schedule.dispatch }
    pub(crate) fn inputs(&self) -> &[SlotId] { &self.schedule.inputs }
    pub(crate) fn scratch_requirements(&self) -> Requirements { self.schedule.scratch }
}

#[cfg(test)]
mod tests;
