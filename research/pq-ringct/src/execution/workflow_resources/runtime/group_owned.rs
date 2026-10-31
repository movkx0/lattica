//! Raw group boundaries execute in a real original-owned runtime epoch.
//! Startup host storage is additive to raw backend host and compiler/report
//! storage. Its device claim is split from the existing managed8GiB allowance.
use super::*;
use crate::{
    execution::{phase_lifecycle::owned_partition::OriginalPhasePartition,
        retained_resources::Ledger},
    graph_crypto::OwnedAesCompileOperation,
    opencl::{RetiredSourceSession, StartupTiming, WorkflowRuntimePlan},
};
use lattica_prover_p3::{
    block_v2::{gpu_hash::device::ringct_runtime::Retirement, native_gpu},
    proving::{Policy, Report, Request},
};
use std::time::Instant;

enum GroupOperation<'plan, 'request> {
    Shake(PairedGroupOperation<'plan, 'request>),
    Aes(OwnedAesCompileOperation<'plan, 'request>),
}
impl<'request> GroupOperation<'_, 'request> {
    fn binding(&self) -> PhaseBinding {
        match self { Self::Shake(op) => op.binding(), Self::Aes(op) => op.binding() }
    }
    fn requirements(&self) -> Result<(Requirements, Bytes), PairedFailure> {
        match self { Self::Shake(op) => op.preparation_requirements(),
            Self::Aes(op) => op.preparation_requirements() }
    }
    fn execute(self, access: &ExecutionAccess<'_>, operations: &native_gpu::OperationContext<'_>)
        -> Result<PairedCompiled<'request>, PairedFailure>
    {
        match self { Self::Shake(op) => op.execute_with_operations(access, operations),
            Self::Aes(op) => op.execute_with_operations(access, operations) }
    }
}

struct GroupPartitionPlan {
    startup: Requirements,
    operation: Requirements,
    complete: Requirements,
}
impl GroupPartitionPlan {
    fn new(startup: Requirements, backend: Bytes) -> Result<Self, WorkflowError> {
        let bytes = startup.get(Category::PhaseScratch);
        if bytes.host == 0 || bytes.host > MAX_NATIVE_BYTES || bytes.device == 0 || bytes.device > MAX_DEVICE_BYTES
            || startup.total()? != bytes || backend.host == 0 || backend.host > MAX_NATIVE_BYTES
            || backend.device != MAX_DEVICE_BYTES
        { return Err(WorkflowError::BackendAllowance); }
        // The source startup owns staging/constants only. The raw operation
        // keeps the rest of the SAME managed allowance, never a second8GiB.
        let operation = Requirements::single(Category::PhaseScratch, Bytes {
            host: backend.host,
            device: backend.device.checked_sub(bytes.device).ok_or(WorkflowError::BackendAllowance)?,
        });
        let complete = combine(startup, operation)?;
        if complete.total()?.host > MAX_HOST_BYTES { return Err(WorkflowError::BackendAllowance); }
        Ok(Self { startup, operation, complete })
    }
}

#[derive(Default, serde::Serialize)]
struct GroupTelemetry {
    startup: Option<StartupTiming>,
    preparation_ns: Option<u128>,
    retirement: Option<Retirement>,
    preparation_complete: bool,
}
#[derive(serde::Serialize)]
struct GroupEntry<'a> { schema: &'static str, ordinal: usize, epoch: &'a GroupTelemetry }
impl crate::execution::report_transport::FixedPayload for GroupEntry<'_> {}
impl GroupTelemetry {
    fn emit(&self, ordinal: usize) -> Result<(), PairedFailure> {
        crate::execution::report_transport::emit(b"owned_group_epoch ", &GroupEntry {
            schema: "ringct-owned-group-epoch-v1", ordinal, epoch: self,
        }).map_err(|_| PairedFailure::Resource)
    }
}

/// Source census, not admission. B adds this to every raw group phase before
/// complete workflow closure. Device remains in PhaseStep.backend exactly once.
pub(crate) fn group_issuer_scratch_requirements() -> Result<Requirements, WorkflowError> {
    use core::mem::size_of;
    let startup = WorkflowRuntimePlan::outer_host_v1_requirement().map_err(|_| WorkflowError::Planning)?;
    let startup_bytes = startup.get(Category::PhaseScratch);
    if startup.total()? != startup_bytes || startup_bytes.device == 0 || startup_bytes.device > MAX_DEVICE_BYTES {
        return Err(WorkflowError::Planning);
    }
    let frames = [
        size_of::<GroupOperation<'static, 'static>>(), size_of::<GroupPartitionPlan>(),
        size_of::<GroupTelemetry>(), size_of::<GroupEntry<'static>>(),
        size_of::<OriginalPhasePartition<'static, 'static>>(), size_of::<[Reservation; 2]>(),
        size_of::<Result<(PairedCompiled<'static>, Report), String>>(),
        size_of::<Result<(PairedCompiled<'static>, Report), PairedFailure>>(),
        size_of::<Result<Retained<PairedCompiled<'static>>, PhaseFailure<PairedFailure>>>(),
        size_of::<Ledger>(), size_of::<Requirements>(), size_of::<Instant>(),
        size_of::<native_gpu::OperationContext<'static>>(), size_of::<Request>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|sum| sum.checked_mul(8))
        .and_then(|sum| sum.checked_add(crate::execution::report_transport::required_host_bytes()))
        .ok_or(WorkflowError::Overflow)?;
    let host = startup_bytes.host.checked_add(u64::try_from(frames).map_err(|_| WorkflowError::Overflow)?)
        .ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes { host, device: 0 }))
}

fn restore(mut partition: OriginalPhasePartition<'_, '_>, originals: [Reservation; 2])
    -> Result<(), PairedFailure>
{
    let mut failed = false;
    for original in originals {
        if let Err((_error, original)) = partition.reunite(original) {
            core::mem::forget(original); failed = true;
        }
    }
    if failed { return Err(PairedFailure::Resource); }
    partition.restore().map_err(|partition| { drop(partition); PairedFailure::Resource })
}

/// # Safety
/// The closed runner excludes process/environment mutation and other GPU work
/// from original runtime selection through actual retirement.
unsafe fn attempt<'request>(access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>, operation: GroupOperation<'_, 'request>,
    telemetry: &mut GroupTelemetry) -> Result<PairedCompiled<'request>, PairedFailure>
{
    if access.binding() != operation.binding() || access.binding().kind() != PhaseKind::GroupCompile
        || access.context().policy() != Policy::GpuRequired {
        return Err(PairedFailure::Authority);
    }
    let (scratch, backend) = operation.requirements()?;
    if backend != access.backend || !contains(access.binding().facts().scratch, scratch)
        || !contains(scratch, group_issuer_scratch_requirements().map_err(|_| PairedFailure::Resource)?) {
        return Err(PairedFailure::Authority);
    }
    let runtime_plan = WorkflowRuntimePlan::outer_host_v1(source.limits()).map_err(|_| PairedFailure::Resource)?;
    let startup = runtime_plan.requirement().map_err(|_| PairedFailure::Resource)?;
    if startup != WorkflowRuntimePlan::outer_host_v1_requirement().map_err(|_| PairedFailure::Resource)? {
        return Err(PairedFailure::SourceDrift);
    }
    let plan = GroupPartitionPlan::new(startup, backend).map_err(|_| PairedFailure::Resource)?;
    let host = usize::try_from(backend.host).map_err(|_| PairedFailure::Overflow)?;
    let mut partition = phase.partition_originals(plan.complete).map_err(|_| PairedFailure::Resource)?;
    let ledger = partition.ledger().clone();
    let startup = partition.split(plan.startup).map_err(|_| PairedFailure::Resource)?;
    let raw = partition.split(plan.operation).map_err(|_| PairedFailure::Resource)?;
    let pending = match runtime_plan.claim(startup, &ledger, source) {
        Ok(pending) => pending,
        Err((_error, startup)) => {
            drop(operation);
            restore(partition, [startup, raw])?;
            return Err(PairedFailure::Preparation);
        }
    };
    let (session, timing) = match unsafe { pending.start_preserving() } {
        Ok(started) => started,
        Err((_error, timing, startup)) => {
            telemetry.startup = Some(timing); drop(operation);
            restore(partition, [startup, raw])?;
            return Err(PairedFailure::Preparation);
        }
    };
    telemetry.startup = Some(timing);
    let started = Instant::now();
    let prepared = (|| {
        let guard = session.check_reserved_runtime(&ledger).map_err(|_| PairedFailure::Authority)?;
        let runtime = guard.borrow_core().map_err(|_| PairedFailure::Authority)?;
        // The exact Runtime borrow remains live across DeviceSession and its
        // capacity lease; both are destroyed before its retirement below.
        let result = native_gpu::with_operations(host,
            Request { policy: Policy::GpuRequired, emit_report: false },
            |operations| operation.execute(access, operations)
                .map_err(|_| String::from("owned group compilation refused")));
        // Dynamic driver/report errors die while their original claims and
        // actual runtime still exist. No error allocation escapes this scope.
        let result = result.map_err(|error| { drop(error); PairedFailure::Preparation });
        drop(runtime); drop(guard); result
    })();
    telemetry.preparation_ns = Some(started.elapsed().as_nanos());
    let retired = match session.finish_reserved_with_owner(&ledger) {
        Ok(retired) => retired,
        Err(_) => { drop(prepared); core::mem::forget(raw); return Err(PairedFailure::Preparation); }
    };
    telemetry.retirement = Some(retired.receipt());
    let startup = match retired.into_outer_host_original(&ledger) {
        Ok(startup) => startup,
        Err((_error, retired)) => {
            drop(prepared); core::mem::forget(retired); core::mem::forget(raw);
            return Err(PairedFailure::Preparation);
        }
    };
    let result = match prepared {
        Ok((payload, report)) => {
            let accepted = access.context().owned_workflow_observations.preparation_report(&report)
                .map_err(|_| PairedFailure::Authority)
                .and_then(|()| crate::execution::report_transport::emit(b"owned_group_report ", &report)
                    .map_err(|_| PairedFailure::Resource));
            drop(report);
            match accepted { Ok(()) => Ok(payload), Err(error) => { drop(payload); Err(error) } }
        }
        Err(error) => Err(error),
    };
    restore(partition, [startup, raw])?;
    telemetry.preparation_complete = result.is_ok();
    result
}

impl WorkflowPhase<'_, '_, '_> {
    fn compile_group<'request>(mut self, operation: GroupOperation<'_, 'request>)
        -> Result<Retained<PairedCompiled<'request>>, PhaseFailure<PairedFailure>>
    {
        if self.step.binding != operation.binding()
            || !self.admission.retired_context.belongs_to(self.admission.context) {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        let binding = self.step.binding;
        let mut telemetry = GroupTelemetry::default();
        let result = {
            let access = ExecutionAccess { context: self.admission.context, binding,
                backend: self.step.backend, pool: &self.admission.pool };
            unsafe { attempt(&access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(), operation, &mut telemetry) }
        };
        let result = match telemetry.emit(binding.ordinal()) {
            Ok(()) => result, Err(error) => { drop(result); Err(error) }
        };
        let output_claim = self.output.take().expect("preissued output");
        let failure_claim = self.failure.take().expect("preissued failure");
        match result {
            Ok(payload) => {
                let output = Retained::produced(payload, output_claim, binding);
                match self.cleanup() {
                    Ok(()) => {
                        drop(failure_claim); self.admission.next += 1; self.completed = true; Ok(output)
                    }
                    Err(status) => {
                        drop(output); self.admission.failed = true; self.admission.pool.poison();
                        self.completed = true;
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

    pub(crate) fn compile_pair<'request>(self, operation: PairedGroupOperation<'_, 'request>)
        -> Result<Retained<PairedCompiled<'request>>, PhaseFailure<PairedFailure>>
    { self.compile_group(GroupOperation::Shake(operation)) }

    pub(crate) fn compile_aes<'request>(self, operation: OwnedAesCompileOperation<'_, 'request>)
        -> Result<Retained<PairedCompiled<'request>>, PhaseFailure<PairedFailure>>
    { self.compile_group(GroupOperation::Aes(operation)) }
}

#[cfg(test)]
mod tests;
