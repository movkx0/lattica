//! Fixed-capacity replay of the immutable request schedule. Proofs remain in
//! their original Retained owners through every move and failure unwind.
use super::*;
use crate::{
    execution::workflow_resources::{OuterOwnedError, PhaseFailure, PreissuedPairedNative, Retained, RetainedNative, SlotId, WorkflowAdmission},
    graph_crypto::{OuterProofCache, ProofCache},
};
use std::time::Instant;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(super) mod retaining;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PairedRequestReport {
    pub(crate) native_proofs: usize,
    pub(crate) recursive_leaves: usize,
    pub(crate) recursive_parents: usize,
    pub(crate) active_rows: usize,
    pub(crate) padded_rows: usize,
    pub(crate) maximum_padded_rows: usize,
    pub(crate) endpoint_preparation_ns: u128,
    /// Native preparation, proving, independent verification and validation.
    /// The maintained native factory does not provide a split of these times.
    pub(crate) native_phase_ns: u128,
    pub(crate) compile_ns: u128,
    pub(crate) setup_ns: u128,
    pub(crate) registered_phase_ns: u128,
    pub(crate) proving_ns: u128,
    pub(crate) cpu_verification_ns: u128,
    /// Execution after source closure; preclosure endpoint preparation is
    /// reported separately above. Whole-workflow timing starts before both.
    pub(crate) request_ns: u128,
}

#[derive(Debug)]
pub(crate) enum PairedExecuteError {
    Source(PairedFailure),
    Phase(PhaseFailure<PairedFailure>),
    Outer(PhaseFailure<OuterOwnedError>),
}
impl From<PairedFailure> for PairedExecuteError {
    fn from(value: PairedFailure) -> Self { Self::Source(value) }
}
impl From<PhaseFailure<PairedFailure>> for PairedExecuteError {
    fn from(value: PhaseFailure<PairedFailure>) -> Self { Self::Phase(value) }
}
impl From<PhaseFailure<OuterOwnedError>> for PairedExecuteError {
    fn from(value: PhaseFailure<OuterOwnedError>) -> Self { Self::Outer(value) }
}

/// Both final owners are consumed by the graph operation. There is deliberately
/// no public extraction of a raw proof/key or unowned endpoint context.
pub(crate) struct PairedRequestOutput<'request> {
    pub(super) root: Retained<PairedNode<'request>>,
    pub(super) endpoints: Retained<PairedEndpoints<'request>>,
    pub(super) report: PairedRequestReport,
}
impl PairedRequestOutput<'_> {
    pub(crate) fn report(&self) -> PairedRequestReport { self.report }
    pub(crate) fn root_slot(&self) -> SlotId { self.root.slot_id() }
    pub(crate) fn endpoint_slot(&self) -> SlotId { self.endpoints.slot_id() }
    pub(crate) fn root_binding(&self) -> crate::execution::workflow_resources::PhaseBinding {
        self.root.binding()
    }
    pub(crate) fn endpoint_binding(&self) -> crate::execution::workflow_resources::PhaseBinding {
        self.endpoints.binding()
    }
    pub(crate) fn node(&self) -> &PairedNode<'_> { self.root.get() }
    pub(crate) fn belongs_to(&self, access: &crate::execution::workflow_resources::ExecutionAccess<'_>) -> bool {
        self.root.belongs_to(access) && self.endpoints.belongs_to(access)
    }
    pub(crate) fn check_source(&self, plan: &PairedRequestPlan<'_>,
        access: &crate::execution::workflow_resources::ExecutionAccess<'_>) -> Result<()> {
        use crate::execution::workflow_resources::PhaseBinding;
        let root_ordinal = plan.steps.iter().position(|step|
            step.kind == RequestStepKind::Outer { node: plan.root }).ok_or(PairedFailure::Order)?;
        if !self.belongs_to(access)
            || self.root.binding() != PhaseBinding::for_paired(plan, root_ordinal).map_err(|_| PairedFailure::Authority)?
            || self.endpoints.binding() != PhaseBinding::for_paired(plan, 0).map_err(|_| PairedFailure::Authority)?
            || self.root.get().source() != plan.root_source() {
            return Err(PairedFailure::Authority);
        }
        self.root.get().check_root(plan.request, &plan.context)
    }
}

struct State<'request> {
    endpoints: Option<Retained<PairedEndpoints<'request>>>,
    native: [Option<RetainedNative<PairedNativeOutput<'request>>>; 2],
    compiled: Option<Retained<PairedCompiled<'request>>>,
    frontier: [Option<(usize, Retained<PairedNode<'request>>)>; usize::BITS as usize],
    report: PairedRequestReport,
}
pub(super) fn execution_frames() -> Result<usize> {
    let total = add(bytes::<State<'static>>(4)?, add(bytes::<PairedRequestOutput<'static>>(8)?,
        bytes::<PairedExecuteError>(8)?)?)?;
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    let total = add(total, add(retaining::forwarding_bytes()?,
        bytes::<[crate::execution::workflow_resources::PhaseBinding; 2]>(8)?)?)?;
    Ok(total)
}

fn take_node<'request>(state: &mut State<'request>, id: usize) -> Result<Retained<PairedNode<'request>>> {
    state.frontier.iter_mut().find(|slot| slot.as_ref().is_some_and(|(node, _)| *node == id))
        .and_then(Option::take).map(|(_, value)| value).ok_or(PairedFailure::Order)
}

impl<'request> PairedRequestPlan<'request> {
    pub(crate) fn execute<'plan>(&'plan self, workflow: &mut WorkflowAdmission<'_, '_>,
        native_cache: &ProofCache, outer_cache: &OuterProofCache,
        native_packets: &mut [Option<PreissuedPairedNative<'plan, 'request>>],
        outer_packets: &mut [Option<PreissuedPairedOuter<'plan, 'request>>])
        -> core::result::Result<PairedRequestOutput<'request>, PairedExecuteError> {
        // The standalone diagnostic executor has a single compiler slot. Only
        // the closed complete driver implements the admitted cohort schedule.
        if self.identity_limits != IdentityBatchLimits::default() {
            return Err(PairedFailure::Authority.into());
        }
        self.check_prepared_endpoints()?;
        if native_cache.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly
            || outer_cache.policy() != crate::proof_cache_policy::ProofCachePolicy::FreshOnly {
            return Err(PairedFailure::Authority.into());
        }
        // Every native and outer backend already exists under original
        // complete workflow claims. Refuse missing, reordered or foreign
        // packets before request native0; workflow admission enforces the
        // same all-source closure across every request in the transaction.
        if native_packets.len() != self.request.segments().len()
            || outer_packets.len() != self.nodes.len() {
            return Err(PairedFailure::Coverage.into());
        }
        for (ordinal, step) in self.steps.iter().enumerate() {
            if let RequestStepKind::Native { index } = step.kind {
                let packet = native_packets.get(index).and_then(Option::as_ref)
                    .ok_or(PairedFailure::Coverage)?;
                if packet.binding() != crate::execution::workflow_resources::PhaseBinding::for_paired(self, ordinal)
                    .map_err(|_| PairedFailure::Authority)? { return Err(PairedFailure::Authority.into()); }
                packet.check_before_native().map_err(|_| PairedFailure::Authority)?;
            }
            if let RequestStepKind::Outer { node } = step.kind {
                let packet = outer_packets.get(node).and_then(Option::as_ref)
                    .ok_or(PairedFailure::Coverage)?;
                if packet.binding() != crate::execution::workflow_resources::PhaseBinding::for_paired(self, ordinal)
                    .map_err(|_| PairedFailure::Authority)? { return Err(PairedFailure::Authority.into()); }
                packet.check_before_native()?;
            }
        }
        let started = Instant::now();
        let mut state = State { endpoints: None, native: [None, None], compiled: None,
            frontier: core::array::from_fn(|_| None), report: PairedRequestReport::default() };
        for (ordinal, step) in self.steps.iter().enumerate() {
            match step.kind {
                RequestStepKind::Endpoints => {
                    if state.endpoints.is_some() { return Err(PairedFailure::Order.into()); }
                    let operation = self.endpoint_operation(ordinal)?;
                    let phase = workflow.next_phase(operation.binding()).map_err(PhaseFailure::<PairedFailure>::Admission)?;
                    let output = phase.prepare_endpoints(operation)?;
                    state.report.endpoint_preparation_ns = output.get().elapsed_ns();
                    state.endpoints = Some(output);
                }
                RequestStepKind::Native { index } => {
                    let slot = state.native.iter_mut().find(|slot| slot.is_none()).ok_or(PairedFailure::Order)?;
                    let operation = self.native_operation(ordinal, native_cache)?;
                    let phase = workflow.next_phase(operation.binding()).map_err(PhaseFailure::<PairedFailure>::Admission)?;
                    let packet = native_packets.get_mut(index).and_then(Option::take)
                        .ok_or(PairedFailure::Coverage)?;
                    let output = phase.produce_native(operation, packet)?;
                    state.report.native_phase_ns = state.report.native_phase_ns
                        .checked_add(output.get().elapsed_ns()).ok_or(PairedFailure::Overflow)?;
                    *slot = Some(output);
                    state.report.native_proofs = add(state.report.native_proofs, 1)?;
                }
                RequestStepKind::Group { .. } => {
                    if state.compiled.is_some() { return Err(PairedFailure::Order.into()); }
                    let native = core::mem::replace(&mut state.native, [None, None]);
                    let operation = self.group_operation(ordinal,
                        state.endpoints.as_ref().ok_or(PairedFailure::Order)?, native)?;
                    let phase = workflow.next_phase(operation.binding()).map_err(PhaseFailure::<PairedFailure>::Admission)?;
                    state.compiled = Some(phase.compile_pair(operation)?);
                }
                RequestStepKind::Merge { left, right, .. } => {
                    if state.compiled.is_some() { return Err(PairedFailure::Order.into()); }
                    let left = take_node(&mut state, left)?;
                    let right = take_node(&mut state, right)?;
                    let operation = self.merge_operation(ordinal, left, right)?;
                    let phase = workflow.next_phase(operation.binding()).map_err(PhaseFailure::<PairedFailure>::Admission)?;
                    state.compiled = Some(phase.compile_parent(operation)?);
                }
                RequestStepKind::Outer { node } => {
                    let compiled = state.compiled.take().ok_or(PairedFailure::Order)?;
                    let operation = self.outer_operation(ordinal, compiled, outer_cache)?;
                    let phase = workflow.next_phase(operation.binding()).map_err(PhaseFailure::<OuterOwnedError>::Admission)?;
                    let packet = outer_packets.get_mut(node).and_then(Option::take)
                        .ok_or(PairedFailure::Coverage)?;
                    let output = phase.prove_owned_outer(operation, packet)?;
                    let report = output.get().report();
                    let source = self.nodes.get(node).ok_or(PairedFailure::Order)?;
                    if source.children.is_some() { state.report.recursive_parents = add(state.report.recursive_parents, 1)?; }
                    else { state.report.recursive_leaves = add(state.report.recursive_leaves, 1)?; }
                    state.report.active_rows = add(state.report.active_rows, report.active_rows)?;
                    state.report.padded_rows = add(state.report.padded_rows, report.padded_rows)?;
                    state.report.maximum_padded_rows = state.report.maximum_padded_rows.max(report.padded_rows);
                    for (total, elapsed) in [
                        (&mut state.report.compile_ns, report.compile_ns),
                        (&mut state.report.setup_ns, report.setup_ns),
                        (&mut state.report.registered_phase_ns, report.registered_phase_ns),
                        (&mut state.report.proving_ns, report.proving_ns),
                        (&mut state.report.cpu_verification_ns, report.cpu_verification_ns),
                    ] { *total = total.checked_add(elapsed).ok_or(PairedFailure::Overflow)?; }
                    let slot = state.frontier.iter_mut().find(|slot| slot.is_none()).ok_or(PairedFailure::Order)?;
                    *slot = Some((node, output));
                }
            }
        }
        let root = take_node(&mut state, self.root)?;
        root.get().check_root(self.request, &self.context)?;
        if state.frontier.iter().any(Option::is_some) || state.native.iter().any(Option::is_some)
            || state.compiled.is_some() || native_packets.iter().any(Option::is_some)
            || outer_packets.iter().any(Option::is_some) {
            return Err(PairedFailure::Order.into());
        }
        state.report.request_ns = started.elapsed().as_nanos();
        Ok(PairedRequestOutput { root,
            endpoints: state.endpoints.take().ok_or(PairedFailure::Order)?, report: state.report })
    }
}
