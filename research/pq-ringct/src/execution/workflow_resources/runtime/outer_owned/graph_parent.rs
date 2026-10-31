//! Concrete graph parent outer producer. This child module uses its parent's private
//! scope issuer, telemetry and restoration functions; it exposes no generic
//! producer callback or runtime constructor. All dynamic source packet and
//! compiled-operation owners have their own exact graph parent source census.
use super::*;
use crate::graph_tree::owned_parent::{GraphParentOuterOperation, PreissuedGraphParentOuter, OwnedGraphNode};

/// The caller keeps its exact output/failure slots and all source owners live.
/// On success the output remains covered by that original unsplit output slot.
///
/// # Safety
/// The same exclusive device and immutable process/environment contract used
/// for complete preissue must hold until this exact owned runtime retires.
unsafe fn attempt_graph_parent<'plan, 'source_plan, 'graph>(
    access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>, output: &SlotClaim, failure: &SlotClaim,
    operation: &GraphParentOuterOperation<'plan, 'source_plan, 'graph>,
    packet: PreissuedGraphParentOuter<'plan, 'source_plan, 'graph>, backend_bytes: Bytes,
    telemetry: &mut EpochTelemetry, retirement: &RetirementState,
) -> Result<OwnedGraphNode<'graph>, OuterOwnedError> {
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
    let bound = packet.bind(operation, access).map_err(OuterOwnedError::GraphOperation)?;
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
            .map_err(OuterOwnedError::GraphOperation)?;
        let mut scope = OwnedOuterScope::new(access, program, bound.admission(),
            &session, &ledger, output, failure)?;
        let request = Request { policy: Policy::GpuRequired, emit_report: false };
        let (registered, report) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
            MachineAir::from_shared_program(Arc::clone(program)),
            bound.admission().host_budget_bytes(), request, None,
        ).map_err(|_error| OuterOwnedError::Setup)?;
        scope.record_report(&report, CoverageScope::Preprocessing)?;
        drop(report);
        *produced.get_mut() = Some(bound.prove_registered(&mut scope, registered)
            .map_err(OuterOwnedError::GraphOperation)?);
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
    pub(crate) fn prove_owned_graph_parent_outer<'plan, 'source_plan, 'graph>(
        mut self, operation: GraphParentOuterOperation<'plan, 'source_plan, 'graph>,
        packet: PreissuedGraphParentOuter<'plan, 'source_plan, 'graph>,
    ) -> Result<Retained<OwnedGraphNode<'graph>>, PhaseFailure<OuterOwnedError>> {
        if self.step.binding != operation.binding() || packet.binding() != operation.binding()
            || !self.admission.retired_context.belongs_to(self.admission.context)
        {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        if self.step.input_count != 1 || self.step.consume_count != 1
            || preflight::inputs(self.admission.plan, self.step)
                .map_err(PhaseFailure::Admission)? != [operation.input_slot()]
        {
            return Err(PhaseFailure::Admission(WorkflowError::Sequence));
        }
        let retirement = RetirementState::new();
        let output_claim = RetirementGuard::new(
            self.output.take().expect("preissued output"), &retirement);
        let failure_claim = RetirementGuard::new(
            self.failure.take().expect("preissued failure"), &retirement);
        let operation = RetirementGuard::new(operation, &retirement);
        let binding = self.step.binding;
        let mut telemetry = EpochTelemetry::default();
        let result = {
            let access = ExecutionAccess {
                context: self.admission.context, binding, backend: self.step.backend,
                pool: &self.admission.pool,
            };
            // Only the complete closed workflow admits this concrete method.
            // The enclosing runner maintains the exclusive process contract.
            unsafe { attempt_graph_parent(
                &access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(),
                output_claim.get(),
                failure_claim.get(),
                operation.get(), packet, self.step.backend, &mut telemetry, &retirement,
            ) }
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
