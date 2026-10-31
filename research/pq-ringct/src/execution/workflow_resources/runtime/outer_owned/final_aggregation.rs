//! Concrete final aggregate producer under the original preissued backend.
//! This module exposes no caller callback, proof factory or numeric admission.
use super::*;
use crate::ordered_aggregation::owned_final::{FinalOuterOperation, PreissuedFinalOuter, FinalNode};
use super::super::final_owned::{self, guard::RetirementGuard as FinalRetirementGuard};
use std::cell::Cell;

/// # Safety
/// The complete runner preserves exclusive device/process selection from
/// preissue through exact runtime retirement. Original inputs stay retained.
unsafe fn attempt_final<'plan, 'source>(access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>, output: &SlotClaim, failure: &SlotClaim,
    operation: &FinalOuterOperation<'plan, 'source>, packet: PreissuedFinalOuter<'plan, 'source>,
    backend_bytes: Bytes, telemetry: &mut EpochTelemetry, required: &Cell<bool>)
    -> Result<FinalNode<'source>, OuterOwnedError>
{
    if access.binding() != operation.binding() || packet.binding() != operation.binding()
        || access.binding().kind() != PhaseKind::FinalOuter
        || access.context().policy() != Policy::GpuRequired
        || !output.belongs_to(phase.ledger()) || !failure.belongs_to(phase.ledger()) {
        return Err(OuterOwnedError::Authority);
    }
    let plan = OuterRuntimePartitionPlan::new(source.limits(), backend_bytes)
        .map_err(|_| OuterOwnedError::Partition)?;
    let startup_requirement = plan.startup_requirement();
    let wrapper_requirement = plan.wrapper_requirement();
    let pcs_requirement = plan.pcs_requirement();
    let partition_requirement = plan.complete_requirement();
    let bound = packet.bind(operation, access).map_err(OuterOwnedError::FinalOperation)?;
    let footprint = bound.admission().footprint();
    if footprint.backend_scope_host_bytes.checked_sub(8 << 30)
        != Some(pcs_requirement.get(Category::PhaseScratch).host)
        || footprint.managed_limit_bytes != 8 << 30 || footprint.full_tree_quota_host_bytes != 8 << 30
        || plan.operation_host() as u64 != pcs_requirement.get(Category::PhaseScratch).host {
        return Err(OuterOwnedError::Authority);
    }
    let mut partition = phase.partition_originals(partition_requirement).map_err(|_| OuterOwnedError::Partition)?;
    let ledger = partition.ledger().clone();
    let startup = partition.split(startup_requirement).map_err(|_| OuterOwnedError::Partition)?;
    let wrappers = FinalRetirementGuard::new(
        partition.split(wrapper_requirement).map_err(|_| OuterOwnedError::Partition)?, required);
    let pcs = FinalRetirementGuard::new(
        partition.split(pcs_requirement).map_err(|_| OuterOwnedError::Partition)?, required);
    let pending = match plan.into_startup_plan().claim(startup, &ledger, source) {
        Ok(pending) => pending,
        Err((_error, startup)) => {
            drop(bound);
            restore(partition, startup, wrappers.into_retired().map_err(OuterOwnedError::FinalOperation)?,
                pcs.into_retired().map_err(OuterOwnedError::FinalOperation)?)?;
            return Err(OuterOwnedError::Runtime);
        }
    };
    required.set(true);
    let (session, startup_timing) = match unsafe { pending.start_preserving() } {
        Ok(started) => started,
        Err((_error, startup_timing, startup)) => {
            required.set(false);
            telemetry.startup = Some(startup_timing);
            drop(bound);
            restore(partition, startup, wrappers.into_retired().map_err(OuterOwnedError::FinalOperation)?,
                pcs.into_retired().map_err(OuterOwnedError::FinalOperation)?)?;
            return Err(OuterOwnedError::Runtime);
        }
    };
    telemetry.startup = Some(startup_timing);
    // Keep the output in this outer scope: a later timing refusal must not
    // discard its guard before the actual retirement can disarm it.
    let mut produced = FinalRetirementGuard::new(None, required);
    let attempted = (|| {
        let (program, _, _) = operation.borrowed_parts(access).map_err(OuterOwnedError::FinalOperation)?;
        let mut scope = OwnedOuterScope::new(access, program, bound.admission(),
            &session, &ledger, output, failure)?;
        let (registered, report) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
            MachineAir::from_shared_program(Arc::clone(program)), bound.admission().host_budget_bytes(),
            Request { policy: Policy::GpuRequired, emit_report: false }, None,
        ).map_err(|_| OuterOwnedError::Setup)?;
        scope.record_report(&report, CoverageScope::Preprocessing)?;
        drop(report);
        *produced.get_mut() = Some(bound.prove_registered(&mut scope, registered)
            .map_err(OuterOwnedError::FinalOperation)?);
        scope.timings()?;
        Ok(())
    })();
    // Inputs, raw backend claims AND a successfully returned proof stay pinned
    // on failure/unwind until the actual runtime returns its sealed owner.
    let retired = session.finish_reserved_with_owner(&ledger).map_err(|_| OuterOwnedError::Runtime)?;
    telemetry.retirement = Some(retired.receipt());
    let startup = retired.into_outer_host_original(&ledger).map_err(|(_error, retired)| {
        core::mem::forget(retired); OuterOwnedError::Runtime
    })?;
    required.set(false);
    drop(bound);
    restore(partition, startup, wrappers.into_retired().map_err(OuterOwnedError::FinalOperation)?,
        pcs.into_retired().map_err(OuterOwnedError::FinalOperation)?)?;
    let produced = produced.into_retired().map_err(OuterOwnedError::FinalOperation)?;
    let attempted = attempted.and_then(|()| produced.ok_or(OuterOwnedError::Authority));
    telemetry.independent_verification_complete = attempted.is_ok();
    attempted
}

impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn prove_owned_final_outer<'plan, 'source>(mut self,
        operation: FinalOuterOperation<'plan, 'source>, packet: PreissuedFinalOuter<'plan, 'source>)
        -> Result<Retained<FinalNode<'source>>, PhaseFailure<OuterOwnedError>>
    {
        if self.step.binding != operation.binding() || packet.binding() != operation.binding()
            || !self.admission.retired_context.belongs_to(self.admission.context) {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        if self.step.input_count != 1 || self.step.consume_count != 1
            || preflight::inputs(self.admission.plan, self.step).map_err(PhaseFailure::Admission)?
                != [operation.input_slot()] {
            return Err(PhaseFailure::Admission(WorkflowError::Sequence));
        }
        let required = Cell::new(false);
        let operation = FinalRetirementGuard::new(operation, &required);
        // The produced node borrows this unsplit slot's accounting. Preserve
        // both slots with any retained payload if actual retirement is absent.
        let output_claim = FinalRetirementGuard::new(
            self.output.take().expect("preissued final output"), &required);
        let failure_claim = FinalRetirementGuard::new(
            self.failure.take().expect("preissued final failure"), &required);
        let binding = self.step.binding;
        let mut telemetry = EpochTelemetry::default();
        let result = {
            let access = ExecutionAccess { context: self.admission.context, binding,
                backend: self.step.backend, pool: &self.admission.pool };
            unsafe { attempt_final(&access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(), output_claim.get(),
                failure_claim.get(), operation.get(), packet,
                self.step.backend, &mut telemetry, &required) }
        };
        if required.get() {
            self.admission.failed = true;
            self.admission.pool.poison();
            self.completed = true;
            return Err(PhaseFailure::Admission(WorkflowError::Poisoned));
        }
        drop(operation);
        telemetry.cpu_verification_ns = result.as_ref().ok().map(|payload| payload.report().cpu_verification_ns);
        let result = match telemetry.emit(&binding) {
            Ok(()) => result, Err(error) => { drop(result); Err(error) }
        }.and_then(|payload| {
            final_owned::emit_stage(binding.ordinal(), final_owned::Stage::Outer, &payload.report())
                .map_err(OuterOwnedError::FinalOperation)?;
            Ok(payload)
        });
        let output_claim = output_claim.into_retired()
            .map_err(|_| PhaseFailure::Admission(WorkflowError::Poisoned))?;
        let failure_claim = failure_claim.into_retired()
            .map_err(|_| PhaseFailure::Admission(WorkflowError::Poisoned))?;
        match result {
            Ok(payload) => {
                let output = Retained::produced(payload, output_claim, binding);
                match self.cleanup() {
                    Ok(()) => {
                        drop(failure_claim); self.admission.next += 1; self.completed = true; Ok(output)
                    }
                    Err(status) => {
                        drop(output); self.admission.failed = true; self.admission.pool.poison(); self.completed = true;
                        Err(PhaseFailure::Retained(RetainedFailure::produced(None, Some(status), failure_claim)))
                    }
                }
            }
            Err(error) => {
                let mut failure = RetainedFailure::produced(Some(error), None, failure_claim);
                drop(output_claim);
                if let Err(status) = self.cleanup() { failure = failure.with_status(status); self.admission.pool.poison(); }
                self.admission.failed = true; self.completed = true;
                Err(PhaseFailure::Retained(failure))
            }
        }
    }
}
