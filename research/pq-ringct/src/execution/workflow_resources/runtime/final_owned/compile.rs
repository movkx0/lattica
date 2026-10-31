//! Final compiler hashes its ordered children in one actual owned runtime.
//! Every child and its original slot remains live through sealed retirement.
use super::*;
use super::guard::RetirementGuard;
use crate::{
    execution::{phase_lifecycle::owned_partition::OriginalPhasePartition,
        retained_resources::Ledger},
    opencl::{RetiredSourceSession, StartupTiming, WorkflowRuntimePlan},
};
use lattica_prover_p3::{
    block_v2::{gpu_hash::device::ringct_runtime::Retirement, native_gpu},
    proving::{Policy, Report, Request},
};
use std::{cell::Cell, time::Instant};

struct CompilePartition {
    startup: Requirements,
    raw: Requirements,
    complete: Requirements,
}
impl CompilePartition {
    fn new(startup: Requirements, backend: Bytes) -> Result<Self, WorkflowError> {
        let bytes = startup.get(Category::PhaseScratch);
        if startup.total()? != bytes || bytes.host == 0 || bytes.host > MAX_NATIVE_BYTES
            || bytes.device == 0 || bytes.device >= MAX_DEVICE_BYTES
            || backend.host == 0 || backend.host > MAX_NATIVE_BYTES
            || backend.device != MAX_DEVICE_BYTES
        { return Err(WorkflowError::BackendAllowance); }
        let raw = Requirements::single(Category::PhaseScratch, Bytes {
            host: backend.host,
            device: backend.device.checked_sub(bytes.device).ok_or(WorkflowError::Overflow)?,
        });
        let complete = combine(startup, raw)?;
        if complete.total()?.host > MAX_HOST_BYTES { return Err(WorkflowError::BackendAllowance); }
        Ok(Self { startup, raw, complete })
    }
}

#[derive(Default, serde::Serialize)]
struct CompileTelemetry {
    startup: Option<StartupTiming>,
    preparation_ns: Option<u128>,
    retirement: Option<Retirement>,
    preparation_complete: bool,
}
#[derive(serde::Serialize)]
struct CompileEntry<'a> { schema: &'static str, ordinal: usize, epoch: &'a CompileTelemetry }
impl crate::execution::report_transport::FixedPayload for CompileEntry<'_> {}
impl CompileTelemetry {
    fn emit(&self, ordinal: usize) -> Result<(), FinalFailure> {
        crate::execution::report_transport::emit(b"owned_final_compile_epoch ", &CompileEntry {
            schema: "ringct-owned-final-compile-epoch-v1", ordinal, epoch: self,
        }).map_err(|_| FinalFailure::Report)
    }
}

pub(crate) fn final_compile_issuer_requirements() -> Result<Requirements, WorkflowError> {
    let startup = WorkflowRuntimePlan::outer_host_v1_requirement().map_err(|_| WorkflowError::Planning)?;
    let startup_bytes = startup.get(Category::PhaseScratch);
    if startup.total()? != startup_bytes || startup_bytes.device == 0
        || startup_bytes.device >= MAX_DEVICE_BYTES { return Err(WorkflowError::Planning); }
    let frames = [
        size_of::<CompilePartition>(), size_of::<CompileTelemetry>(), size_of::<CompileEntry<'static>>(),
        size_of::<OriginalPhasePartition<'static, 'static>>(), size_of::<[Reservation; 2]>(),
        size_of::<RetirementGuard<'static, FinalCompileOperation<'static, 'static, 'static>>>(),
        size_of::<RetirementGuard<'static, Reservation>>(),
        size_of::<RetirementGuard<'static, SlotClaim>>(),
        size_of::<Result<SlotClaim, FinalFailure>>(),
        size_of::<RetirementGuard<'static, Option<FinalCompiled<'static>>>>(),
        size_of::<RetirementGuard<'static, Result<((), Report), FinalFailure>>>(),
        size_of::<Option<FinalCompiled<'static>>>(),
        size_of::<Result<Option<FinalCompiled<'static>>, FinalFailure>>(),
        size_of::<Result<((), Report), String>>(),
        size_of::<Result<FinalCompiled<'static>, FinalFailure>>(),
        size_of::<Result<Retained<FinalCompiled<'static>>, PhaseFailure<FinalFailure>>>(),
        size_of::<Ledger>(), size_of::<Requirements>(), size_of::<Instant>(), size_of::<Cell<bool>>(),
        size_of::<native_gpu::OperationContext<'static>>(), size_of::<Request>(),
    ].into_iter().try_fold(0usize, |sum, next| sum.checked_add(next))
        .and_then(|sum| sum.checked_mul(8))
        .and_then(|sum| sum.checked_add(final_report_transport_host_bytes()))
        .ok_or(WorkflowError::Overflow)?;
    let host = startup_bytes.host.checked_add(u64::try_from(frames).map_err(|_| WorkflowError::Overflow)?)
        .ok_or(WorkflowError::Overflow)?;
    // Startup device storage is split from PhaseStep.backend, never added to it.
    Ok(Requirements::single(Category::PhaseScratch, Bytes { host, device: 0 }))
}

fn restore(mut partition: OriginalPhasePartition<'_, '_>, originals: [Reservation; 2])
    -> Result<(), FinalFailure>
{
    let mut failed = false;
    for original in originals {
        if let Err((_error, original)) = partition.reunite(original) {
            core::mem::forget(original); failed = true;
        }
    }
    if failed { return Err(FinalFailure::Partition); }
    partition.restore().map_err(|poisoned| { drop(poisoned); FinalFailure::Partition })
}

/// # Safety
/// The closed runner preserves exclusive physical/process selection from
/// whole-case preissue through actual runtime retirement.
unsafe fn attempt<'source>(access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    source: &RetiredSourceSession<'_>, operation: &FinalCompileOperation<'_, '_, 'source>,
    required: &Cell<bool>, telemetry: &mut CompileTelemetry)
    -> Result<FinalCompiled<'source>, FinalFailure>
{
    if access.binding() != operation.binding() || access.binding().kind() != PhaseKind::FinalCompile
        || access.context().policy() != Policy::GpuRequired {
        return Err(FinalFailure::Authority);
    }
    let (scratch, backend) = operation.preparation_requirements()?;
    if backend != access.backend || !contains(access.binding().facts().scratch, scratch)
        || !contains(scratch, final_compile_issuer_requirements().map_err(|_| FinalFailure::Source)?) {
        return Err(FinalFailure::Authority);
    }
    let runtime_plan = WorkflowRuntimePlan::outer_host_v1(source.limits()).map_err(|_| FinalFailure::Runtime)?;
    let startup = runtime_plan.requirement().map_err(|_| FinalFailure::Source)?;
    if startup != WorkflowRuntimePlan::outer_host_v1_requirement().map_err(|_| FinalFailure::Source)? {
        return Err(FinalFailure::Source);
    }
    let plan = CompilePartition::new(startup, backend).map_err(|_| FinalFailure::Partition)?;
    let host = usize::try_from(backend.host).map_err(|_| FinalFailure::Overflow)?;
    let mut partition = phase.partition_originals(plan.complete).map_err(|_| FinalFailure::Partition)?;
    let ledger = partition.ledger().clone();
    let startup = partition.split(plan.startup).map_err(|_| FinalFailure::Partition)?;
    let raw = RetirementGuard::new(partition.split(plan.raw).map_err(|_| FinalFailure::Partition)?, required);
    let pending = match runtime_plan.claim(startup, &ledger, source) {
        Ok(pending) => pending,
        Err((_error, startup)) => {
            restore(partition, [startup, raw.into_retired()?])?;
            return Err(FinalFailure::Runtime);
        }
    };
    // A panic during partial startup also preserves input and raw originals.
    // The preserving error branch returns the actual unstarted original.
    required.set(true);
    let (session, timing) = match unsafe { pending.start_preserving() } {
        Ok(started) => started,
        Err((_error, timing, startup)) => {
            required.set(false);
            telemetry.startup = Some(timing);
            restore(partition, [startup, raw.into_retired()?])?;
            return Err(FinalFailure::Runtime);
        }
    };
    telemetry.startup = Some(timing);
    let started = Instant::now();
    // with_operations finishes its report after the callback returns. Keep
    // the actual compiler payload outside that fallible helper interval.
    let mut compiled = RetirementGuard::new(None, required);
    let prepared = (|| {
        let guard = session.check_reserved_runtime(&ledger).map_err(|_| FinalFailure::Authority)?;
        let runtime = guard.borrow_core().map_err(|_| FinalFailure::Authority)?;
        let result = native_gpu::with_operations(host,
            Request { policy: Policy::GpuRequired, emit_report: false },
            |operations| {
                *compiled.get_mut() = Some(operation.execute_with_operations(access, operations)
                    .map_err(|_| String::from("owned final compilation refused"))?);
                Ok(())
            });
        let result = result.map_err(|error| { drop(error); FinalFailure::Compile });
        drop(runtime); drop(guard); result
    })();
    let prepared = RetirementGuard::new(prepared, required);
    telemetry.preparation_ns = Some(started.elapsed().as_nanos());
    let retired = session.finish_reserved_with_owner(&ledger).map_err(|_| FinalFailure::Runtime)?;
    telemetry.retirement = Some(retired.receipt());
    let startup = retired.into_outer_host_original(&ledger).map_err(|(_error, retired)| {
        core::mem::forget(retired); FinalFailure::Runtime
    })?;
    required.set(false);
    let compiled = compiled.into_retired()?;
    let result = match prepared.into_retired()? {
        Ok(((), report)) => {
            let accepted = access.context().owned_workflow_observations.preparation_report(&report)
                .map_err(|_| FinalFailure::Authority)
                .and_then(|()| crate::execution::report_transport::emit(b"owned_final_compile_report ", &report)
                    .map_err(|_| FinalFailure::Report));
            drop(report);
            match accepted {
                Ok(()) => compiled.ok_or(FinalFailure::Compile),
                Err(error) => { drop(compiled); Err(error) }
            }
        }
        Err(error) => { drop(compiled); Err(error) },
    };
    restore(partition, [startup, raw.into_retired()?])?;
    telemetry.preparation_complete = result.is_ok();
    result
}

impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_final<'source>(mut self, operation: FinalCompileOperation<'_, '_, 'source>)
        -> Result<Retained<FinalCompiled<'source>>, PhaseFailure<FinalFailure>>
    {
        let inputs = preflight::inputs(self.admission.plan, self.step).map_err(PhaseFailure::Admission)?;
        if self.step.binding != operation.binding() || self.step.input_count != 2
            || self.step.consume_count != 2 || inputs != operation.input_slots()
            || !self.admission.retired_context.belongs_to(self.admission.context) {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        let binding = self.step.binding;
        let required = Cell::new(false);
        let operation = RetirementGuard::new(operation, &required);
        let output_claim = RetirementGuard::new(
            self.output.take().expect("preissued final compiler output"), &required);
        let failure_claim = RetirementGuard::new(
            self.failure.take().expect("preissued final compiler failure"), &required);
        let mut telemetry = CompileTelemetry::default();
        let result = {
            let access = ExecutionAccess { context: self.admission.context, binding,
                backend: self.step.backend, pool: &self.admission.pool };
            unsafe { attempt(&access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.admission.retired_context.source(), operation.get(), &required, &mut telemetry) }
        };
        if required.get() {
            self.admission.failed = true;
            self.admission.pool.poison();
            self.completed = true;
            return Err(PhaseFailure::Admission(WorkflowError::Poisoned));
        }
        // Only the authentic retirement path releases retained child slots.
        drop(operation);
        let result = match telemetry.emit(binding.ordinal()) {
            Ok(()) => result, Err(error) => { drop(result); Err(error) }
        }.and_then(|payload| {
            emit_stage(binding.ordinal(), Stage::Compile, &payload.report())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_raw_partition_adds_host_and_preserves_one_device_allowance() {
        let startup = Requirements::single(Category::PhaseScratch, Bytes { host: 1234, device: 4096 });
        let raw = Bytes { host: 184, device: 8 << 30 };
        let plan = CompilePartition::new(startup, raw).unwrap();
        assert_eq!(plan.raw.get(Category::PhaseScratch), Bytes { host: 184, device: (8 << 30) - 4096 });
        assert_eq!(plan.complete.total().unwrap(), Bytes { host: 1418, device: 8 << 30 });
    }
    #[test]
    fn final_raw_partition_refuses_missing_or_double_device_allowance() {
        for device in [0, 8 << 30, (8 << 30) + 1] {
            let startup = Requirements::single(Category::PhaseScratch, Bytes { host: 1234, device });
            assert!(CompilePartition::new(startup, Bytes { host: 184, device: 8 << 30 }).is_err());
        }
    }
}
