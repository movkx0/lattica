//! Concrete paired outer production from preissued source/backend owners.
//! No supplied proof, callback, new quota admission or retry enters this path.
use super::*;
use crate::{
    execution::{
        phase_lifecycle::{owned_partition::OriginalPhasePartition,
            outer_partition::OuterRuntimePartitionPlan, OwnedPhase},
        retained_resources::{Category, Ledger, Reservation},
    },
    graph_crypto::{PairedFailure, PairedNode, PairedOuterOperation, PreissuedPairedOuter},
    opencl::{RetiredSourceSession, Session, StartupTiming},
};
use lattica_prover_p3::{
    block_v2::machine::{backend::RegisteredProgram, MachineAir},
    proving::{CoverageScope, Policy, Request},
};
use std::sync::Arc;

mod scope;
#[cfg(feature = "identity-batch-experiment")]
mod identity;
#[cfg(feature = "identity-batch-experiment")]
pub(crate) use identity::PairedIdentityPeers;
mod aes;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod fixed_leaf;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod parameters_pp;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod equality;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod auxiliary;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod graph_parent;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod native_leaf;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod affine_leaf;
use super::native_retirement::{RetirementGuard, RetirementState};
#[cfg(test)]
mod retirement_tests;
pub(crate) use scope::OwnedOuterScope;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OuterOwnedError {
    Authority, Runtime, Partition, Setup, Report, Operation(PairedFailure),
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    GraphOperation(crate::graph_tree::owned_parent::GraphParentFailure),
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    FinalOperation(crate::ordered_aggregation::owned_final::FinalFailure),
}

#[derive(Default, serde::Serialize)]
struct EpochTelemetry {
    #[cfg(feature = "identity-batch-experiment")]
    #[serde(skip_serializing_if = "identity::PrefixEpoch::is_empty")]
    identity_prefix: identity::PrefixEpoch,
    #[cfg(feature = "identity-batch-experiment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_prefix_use: Option<identity::PrefixUse>,
    startup: Option<StartupTiming>,
    retirement: Option<lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::Retirement>,
    independent_verification_complete: bool,
    cpu_verification_ns: Option<u128>,
}

#[derive(serde::Serialize)]
struct EpochEntry<'a> { schema: &'static str, ordinal: usize, binding: VerificationBinding, epoch: &'a EpochTelemetry }
// Both nested runtime records derive Serialize over fixed scalar fields only.
impl crate::execution::report_transport::FixedPayload for EpochEntry<'_> {}

/// Additional caller/forwarding frames; shared report payloads, source-owned
/// compiler/packet metadata, core runtime and OCL storage are separate claims.
pub(crate) fn forwarding_host_bytes() -> Result<u64, OuterOwnedError> {
    use core::mem::size_of;
    let mut bytes = 0usize;
    for part in [
        verification_binding_frame_bytes().map_err(|_| OuterOwnedError::Partition)?,
        8 * size_of::<crate::component_tree::paired_runtime::PairedNodeReport>(),
        8 * size_of::<Option<u128>>(),
        8 * size_of::<RetirementGuard<'static, PairedOuterOperation<'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_crypto::OwnedAesOuterOperation<'static, 'static>>>(),
        8 * size_of::<RetirementState>(),
        16 * size_of::<RetirementGuard<'static, Reservation>>(),
        16 * size_of::<RetirementGuard<'static, SlotClaim>>(),
        8 * size_of::<RetirementGuard<'static, Result<(), OuterOwnedError>>>(),
        8 * size_of::<RetirementGuard<'static, Option<PairedNode<'static>>>>(),
        8 * size_of::<OwnedOuterScope<'static, 'static>>(),
        8 * size_of::<Option<(usize, usize)>>(),
        8 * size_of::<Result<(), crate::execution::owned_workflow_observation::ObservationError>>(),
        8 * size_of::<EpochTelemetry>(), 8 * size_of::<EpochEntry<'static>>(),
        8 * size_of::<ExecutionAccess<'static>>(),
        8 * size_of::<OriginalPhasePartition<'static, 'static>>(),
        8 * size_of::<OuterRuntimePartitionPlan>(),
        8 * size_of::<RegisteredProgram>(), 8 * size_of::<Request>(),
        8 * size_of::<Result<PairedNode<'static>, OuterOwnedError>>(),
        8 * size_of::<Result<Retained<PairedNode<'static>>, PhaseFailure<OuterOwnedError>>>(),
        8 * size_of::<Result<(), OuterOwnedError>>(),
        16 * size_of::<Reservation>(), 8 * size_of::<[Reservation; 3]>(),
        16 * size_of::<Requirements>(),
        8 * size_of::<Ledger>(), 8 * size_of::<crate::opencl::StartupTiming>(),
        8 * size_of::<lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::RetiredRuntime>(),
        crate::execution::report_transport::required_host_bytes(),
    ] {
        bytes = bytes.checked_add(part).ok_or(OuterOwnedError::Partition)?;
    }
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    let bytes = bytes.checked_add(graph_forwarding_host_bytes()?).ok_or(OuterOwnedError::Partition)?;
    #[cfg(feature = "identity-batch-experiment")]
    let bytes = bytes.checked_add(identity::forwarding_bytes()?).ok_or(OuterOwnedError::Partition)?;
    u64::try_from(bytes).map_err(|_| OuterOwnedError::Partition)
}
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
fn graph_forwarding_host_bytes() -> Result<usize, OuterOwnedError> {
    use core::mem::size_of;
    [
        8 * size_of::<crate::graph_tree::owned_parent::GraphNodeReport>(),
        8 * size_of::<Option<u128>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::GraphParentOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::NativeLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::PermutationLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::LinearMapLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::NttLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::AffineLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::GBoundLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::MulLeafOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, Option<crate::graph_tree::owned_parent::OwnedGraphNode<'static>>>>(),
        8 * size_of::<Result<crate::graph_tree::owned_parent::OwnedGraphNode<'static>, OuterOwnedError>>(),
        8 * size_of::<Result<Retained<crate::graph_tree::owned_parent::OwnedGraphNode<'static>>, PhaseFailure<OuterOwnedError>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::ParametersPpOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::AuxiliaryOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::EqualityOuterOperation<'static, 'static, 'static>>>(),
        8 * size_of::<RetirementGuard<'static, crate::graph_tree::owned_parent::FixedLeafOuterOperation<'static, 'static, 'static>>>(),
    ].into_iter().try_fold(0usize, |sum, part| sum.checked_add(part).ok_or(OuterOwnedError::Partition))
}


impl EpochTelemetry {
    fn emit(&self, binding: &PhaseBinding) -> Result<(), OuterOwnedError> {
        crate::execution::report_transport::emit(b"owned_outer_epoch ", &EpochEntry {
            schema: "ringct-owned-outer-epoch-v2", ordinal: binding.ordinal(),
            binding: binding.verification_binding(), epoch: self,
        }).map_err(|_| OuterOwnedError::Report)
    }
}

// Failed restoration never returns accounting credit to a reusable pool.
// The active phase's outstanding marker also remains permanently poisoned.
fn reunite(partition: &mut OriginalPhasePartition<'_, '_>, original: Reservation)
    -> Result<(), OuterOwnedError>
{
    match partition.reunite(original) {
        Ok(()) => Ok(()),
        Err((_error, original)) => {
            core::mem::forget(original);
            Err(OuterOwnedError::Partition)
        }
    }
}

fn restore(mut partition: OriginalPhasePartition<'_, '_>,
    startup: Reservation, wrappers: Reservation, pcs: Reservation)
    -> Result<(), OuterOwnedError>
{
    // Process every owner even after an earlier refusal. No still-live
    // original can be dropped accidentally by an early `?` here.
    let mut valid = true;
    for original in [startup, wrappers, pcs] {
        valid &= reunite(&mut partition, original).is_ok();
    }
    if !valid { return Err(OuterOwnedError::Partition); }
    partition.restore().map_err(|_poisoned| OuterOwnedError::Partition)
}

/// The caller keeps its exact output/failure slots and all source owners live.
/// On success the output remains covered by that original unsplit output slot.
///
/// # Safety
/// The same exclusive device and immutable process/environment contract used
/// for complete preissue must hold until this exact owned runtime retires.
unsafe fn attempt_pair<'plan, 'request>(
    access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>, output: &SlotClaim, failure: &SlotClaim,
    operation: &PairedOuterOperation<'plan, 'request>,
    packet: PreissuedPairedOuter<'plan, 'request>, backend_bytes: Bytes,
    telemetry: &mut EpochTelemetry, retirement: &RetirementState,
) -> Result<PairedNode<'request>, OuterOwnedError> {
    if access.binding() != operation.binding() || packet.binding() != operation.binding()
        || access.context().policy() != Policy::GpuRequired
        || !output.belongs_to(phase.ledger()) || !failure.belongs_to(phase.ledger())
    {
        return Err(OuterOwnedError::Authority);
    }
    let plan = OuterRuntimePartitionPlan::new(source.limits(), backend_bytes)
        .map_err(|_| OuterOwnedError::Partition)?;
    let startup_requirement = plan.startup_requirement();
    let wrapper_requirement = plan.wrapper_requirement();
    let pcs_requirement = plan.pcs_requirement();
    let partition_requirement = plan.complete_requirement();
    // This consumes the pre-native backend packet; it cannot replan from
    // observed proof rows or select a larger allowance after proving begins.
    let bound = packet.bind(operation, access).map_err(OuterOwnedError::Operation)?;
    let footprint = bound.admission().footprint();
    if footprint.backend_scope_host_bytes.checked_sub(8 << 30)
        != Some(pcs_requirement.get(Category::PhaseScratch).host)
        || footprint.managed_limit_bytes != 8 << 30
        || footprint.full_tree_quota_host_bytes != 8 << 30
        || plan.operation_host() as u64 != pcs_requirement.get(Category::PhaseScratch).host
    {
        return Err(OuterOwnedError::Authority);
    }
    let mut partition = phase.partition_originals(partition_requirement)
        .map_err(|_| OuterOwnedError::Partition)?;
    let ledger = partition.ledger().clone();
    let startup = partition.split(startup_requirement).map_err(|_| OuterOwnedError::Partition)?;
    let wrappers = RetirementGuard::new(
        partition.split(wrapper_requirement).map_err(|_| OuterOwnedError::Partition)?, retirement);
    let pcs = RetirementGuard::new(
        partition.split(pcs_requirement).map_err(|_| OuterOwnedError::Partition)?, retirement);
    let pending = match plan.into_startup_plan().claim(startup, &ledger, source) {
        Ok(pending) => pending,
        Err((_error, startup)) => {
            drop(bound);
            restore(partition, startup, wrappers.into_original(), pcs.into_original())?;
            return Err(OuterOwnedError::Runtime);
        }
    };
    // All Rust/core backing owners precede the actual owned Session. Core
    // partial-start refusal destroys its epoch before returning its original.
    retirement.arm();
    let (session, startup_timing) = match unsafe { pending.start_preserving() } {
        Ok(started) => started,
        Err((_error, startup_timing, startup)) => {
            retirement.after_failed_start();
            telemetry.startup = Some(startup_timing);
            drop(bound);
            restore(partition, startup, wrappers.into_original(), pcs.into_original())?;
            return Err(OuterOwnedError::Runtime);
        }
    };
    telemetry.startup = Some(startup_timing);
    // Keep a returned payload in this outer frame, including when the
    // subsequent timing audit refuses. It must not be forgotten early
    // and then lose its slot when runtime retirement later succeeds.
    let mut produced = RetirementGuard::new(None, retirement);
    let attempted = (|| {
        let (program, _, _) = operation.borrowed_parts(access)
            .map_err(OuterOwnedError::Operation)?;
        let mut scope = OwnedOuterScope::new(access, program, bound.admission(),
            &session, &ledger, output, failure)?;
        let request = Request { policy: Policy::GpuRequired, emit_report: false };
        #[cfg(feature = "identity-batch-experiment")]
        let (registered, report) = identity::register(operation, program, bound.admission().host_budget_bytes(), request,
            &mut telemetry.identity_prefix_use)?;
        #[cfg(not(feature = "identity-batch-experiment"))]
        let (registered, report) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
            MachineAir::from_shared_program(Arc::clone(program)),
            bound.admission().host_budget_bytes(), request, None,
        ).map_err(|_error| OuterOwnedError::Setup)?;
        scope.record_report(&report, CoverageScope::Preprocessing)?;
        drop(report);
        *produced.get_mut() = Some(bound.prove_registered(&mut scope, registered)
            .map_err(OuterOwnedError::Operation)?);
        scope.timings()?;
        Ok(())
    })();
    // Every original and returned payload remains guarded through the sealed
    // retirement owner extraction. No copied receipt can disarm these guards.
    let attempted = RetirementGuard::new(attempted, retirement);
    let retired = session.finish_reserved_with_owner(&ledger)
        .map_err(|_| OuterOwnedError::Runtime)?;
    telemetry.retirement = Some(retired.receipt());
    let startup = retired.into_outer_host_original(&ledger).map_err(|(_error, owner)| {
        core::mem::forget(owner);
        OuterOwnedError::Runtime
    })?;
    retirement.after_authenticated_retirement();
    drop(bound);
    restore(partition, startup, wrappers.into_original(), pcs.into_original())?;
    let attempted = attempted.into_original();
    telemetry.independent_verification_complete = attempted.is_ok();
    match attempted {
        Ok(()) => produced.into_original().ok_or(OuterOwnedError::Authority),
        Err(error) => { drop(produced.into_original()); Err(error) }
    }
}

impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn prove_owned_outer<'plan, 'request>(
        self, operation: PairedOuterOperation<'plan, 'request>,
        packet: PreissuedPairedOuter<'plan, 'request>,
    ) -> Result<Retained<PairedNode<'request>>, PhaseFailure<OuterOwnedError>> {
        self.prove_owned_outer_cohort(operation, packet,
            #[cfg(feature = "identity-batch-experiment")]
            &mut PairedIdentityPeers::default())
    }

    pub(crate) fn prove_owned_outer_cohort<'plan, 'request>(
        mut self, operation: PairedOuterOperation<'plan, 'request>,
        packet: PreissuedPairedOuter<'plan, 'request>,
        #[cfg(feature = "identity-batch-experiment")] peers: &mut PairedIdentityPeers<'request>,
    ) -> Result<Retained<PairedNode<'request>>, PhaseFailure<OuterOwnedError>> {
        if self.step.binding != operation.binding() || packet.binding() != operation.binding()
            || !self.admission.retired_context.belongs_to(self.admission.context)
        {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        let mut expected = [operation.input_slot(); 16];
        let mut expected_count = 1;
        #[cfg(feature = "identity-batch-experiment")]
        for peer in peers.owners.iter().flatten() {
            expected[expected_count] = peer.slot_id();
            expected_count += 1;
        }
        if self.step.input_count != expected_count || self.step.consume_count != 1
            || preflight::inputs(self.admission.plan, self.step)
                .map_err(PhaseFailure::Admission)? != &expected[..expected_count]
        {
            return Err(PhaseFailure::Admission(WorkflowError::Sequence));
        }
        let retirement = RetirementState::new();
        let output_claim = RetirementGuard::new(
            self.output.take().expect("preissued output"), &retirement);
        let failure_claim = RetirementGuard::new(
            self.failure.take().expect("preissued failure"), &retirement);
        let operation = RetirementGuard::new(operation, &retirement);
        #[cfg(feature = "identity-batch-experiment")]
        let peers_guard = RetirementGuard::new(core::mem::take(peers), &retirement);
        let binding = self.step.binding;
        let mut telemetry = EpochTelemetry::default();
        let result = {
            let access = ExecutionAccess {
                context: self.admission.context, binding, backend: self.step.backend,
                pool: &self.admission.pool,
            };
            // Only the complete closed workflow admits this concrete method.
            // The enclosing runner maintains the exclusive process contract.
            #[cfg(feature = "identity-batch-experiment")]
            let prefix = unsafe { identity::prepare(&access,
                self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(), operation.get(), peers_guard.get(),
                self.step.backend, &mut telemetry.identity_prefix, &retirement) };
            #[cfg(not(feature = "identity-batch-experiment"))]
            let prefix: Result<(), OuterOwnedError> = Ok(());
            prefix.and_then(|()| unsafe { attempt_pair(
                &access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(),
                output_claim.get(),
                failure_claim.get(),
                operation.get(), packet, self.step.backend, &mut telemetry, &retirement,
            ) })
        };
        // Compiled input ownership survives the actual runtime's retirement.
        // The consumed-input slot must be free before the common cleanup gate.
        if retirement.is_required() {
            // The output, failure, compiler and backend originals remain
            // pinned together with any returned proof. Never extract an
            // original or continue the workflow on uncertain retirement.
            self.admission.failed = true;
            self.admission.pool.poison();
            self.completed = true;
            return Err(PhaseFailure::Admission(WorkflowError::Poisoned));
        }
        drop(operation);
        #[cfg(feature = "identity-batch-experiment")]
        { *peers = peers_guard.into_original(); }
        telemetry.cpu_verification_ns = result.as_ref().ok().map(|payload| payload.report().cpu_verification_ns);
        let result = match telemetry.emit(&binding) {
            Ok(()) => result,
            Err(error) => { drop(result); Err(error) }
        };
        let output_claim = output_claim.into_original();
        let failure_claim = failure_claim.into_original();
        match result {
            Ok(payload) => {
                let output = Retained::produced(payload, output_claim, binding);
                match self.cleanup() {
                    Ok(()) => {
                        drop(failure_claim);
                        self.admission.next += 1;
                        self.completed = true;
                        Ok(output)
                    }
                    Err(status) => {
                        drop(output);
                        self.admission.failed = true;
                        self.admission.pool.poison();
                        self.completed = true;
                        Err(PhaseFailure::Retained(RetainedFailure::produced(
                            None, Some(status), failure_claim)))
                    }
                }
            }
            Err(error) => {
                let mut failure = RetainedFailure::produced(Some(error), None, failure_claim);
                drop(output_claim);
                if let Err(status) = self.cleanup() {
                    failure = failure.with_status(status);
                    self.admission.pool.poison();
                }
                self.admission.failed = true;
                self.completed = true;
                Err(PhaseFailure::Retained(failure))
            }
        }
    }
}

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod final_aggregation;


#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod ntt_leaf;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod mul_leaf;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod g_bound_leaf;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod permutation_leaf;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod linear_map_leaf;
