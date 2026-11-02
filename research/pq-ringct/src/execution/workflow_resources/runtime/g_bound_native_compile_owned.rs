//! Execution-only transfer of one original compiler output slot. Compilation
//! copies from a retired, independently verified native child, then destroys
//! that consumed owner. No payload detach, replacement claim or GPU dispatch.
use super::*;
use super::super::owners::{OriginalOutput, RetainedOriginal};
use crate::{
    execution::phase_lifecycle::owned_partition::OriginalPhasePartition,
    graph_tree::g_bound_sources::{GBoundCompileOutcome, OwnedCompiledGBound},
    spend_pipeline::full_workflow::g_bound_native_compile::{GBoundNativeCompileOperation,
        GBoundNativeCompileFailure},
};

impl OriginalOutput for OwnedCompiledGBound<'_, '_, '_> {
    fn destroy_into_originals(self) -> [Option<Reservation>; 4] {
        [Some(self.destroy_into_original()), None, None, None]
    }
}

/// Includes the concrete result/owner/partition forwarding frames throughout
/// success and refusal. Low-level compiler storage and named-plan frames are
/// charged separately by the source blueprint and compiler plan.
pub(crate) fn g_bound_native_compile_issuer_scratch_requirements() -> Result<Requirements, WorkflowError> {
    use core::mem::size_of;
    let bytes = [
        size_of::<GBoundNativeCompileOperation<'static, 'static>>(),
        size_of::<OwnedCompiledGBound<'static, 'static, 'static>>(),
        size_of::<GBoundCompileOutcome<'static, 'static, 'static>>(),
        size_of::<RetainedOriginal<OwnedCompiledGBound<'static, 'static, 'static>>>(),
        size_of::<Result<RetainedOriginal<OwnedCompiledGBound<'static, 'static, 'static>>,
            PhaseFailure<GBoundNativeCompileFailure>>>(),
        size_of::<OriginalPhasePartition<'static, 'static>>(),
        size_of::<Result<OriginalPhasePartition<'static, 'static>, crate::execution::phase_lifecycle::Error>>(),
        size_of::<ExecutionAccess<'static>>(), size_of::<SlotClaim>(),
        size_of::<Result<Reservation, WorkflowError>>(),
        size_of::<Result<(), (WorkflowError, Reservation)>>(),
        size_of::<Result<(), GBoundNativeCompileFailure>>(),
        size_of::<[Reservation; 4]>(), size_of::<[Requirements; 4]>(),
        size_of::<crate::execution::retained_resources::Ledger>(),
        size_of::<PhaseBinding>(), size_of::<Option<GBoundNativeCompileFailure>>(),
    ].into_iter().try_fold(0usize, |sum, value| sum.checked_add(value))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

fn restore_phase(mut partition: OriginalPhasePartition<'_, '_>, scratch: Reservation)
    -> Result<(), GBoundNativeCompileFailure>
{
    if let Err((_error, original)) = partition.reunite(scratch) {
        core::mem::forget(original);
        // Partition destruction poisons the phase and retains residual credit.
        return Err(GBoundNativeCompileFailure::Authority);
    }
    partition.restore().map_err(|_poisoned| GBoundNativeCompileFailure::Authority)
}
fn restore_output(output: &mut SlotClaim, original: Reservation)
    -> Result<(), GBoundNativeCompileFailure>
{
    output.reunite(original).map_err(|(_error, original)| {
        core::mem::forget(original);
        // Slot destruction poisons the pool if the complete original did not
        // return. It cannot expose a partial replacement slot to another phase.
        GBoundNativeCompileFailure::Authority
    })
}

fn attempt<'a>(access: &ExecutionAccess<'_>, phase: &mut OwnedPhase<'_>,
    output: &mut SlotClaim, operation: GBoundNativeCompileOperation<'_, 'a>)
    -> Result<OwnedCompiledGBound<'a, 'a, 'a>, GBoundNativeCompileFailure>
{
    operation.validate(access, phase.ledger())?;
    let (compiler_output, compiler_scratch) = operation.plan().source_compile_plan()
        .compiler_requirements();
    if access.backend != Bytes::ZERO || !output.belongs_to(phase.ledger())
        || access.binding().facts().output != compiler_output
        || !contains(access.binding().facts().scratch, compiler_scratch)
        || !contains(access.binding().facts().scratch,
            g_bound_native_compile_issuer_scratch_requirements().map_err(|_| GBoundNativeCompileFailure::Resource)?)
    { return Err(GBoundNativeCompileFailure::Authority); }
    let mut partition = phase.partition_originals(access.binding().facts().scratch)
        .map_err(|_| GBoundNativeCompileFailure::Resource)?;
    let ledger = partition.ledger().clone();
    let scratch = match partition.split(compiler_scratch) {
        Ok(scratch) => scratch,
        Err(_) => {
            partition.restore().map_err(|_poisoned| GBoundNativeCompileFailure::Authority)?;
            return Err(GBoundNativeCompileFailure::Resource);
        }
    };
    let original = match output.split(compiler_output) {
        Ok(original) => original,
        Err(_) => {
            restore_phase(partition, scratch)?;
            return Err(GBoundNativeCompileFailure::Resource);
        }
    };
    // The exact slot original moves directly into the compiler payload. The
    // output SlotClaim retains only its residual during this interval.
    let result = operation.plan().source_compile_plan().compile_retaining(
        operation.native_output().proof(), original, &scratch, &ledger);
    // All compiler reads and witness copies have ended. Destroying this exact
    // input owner returns the native slot originals before phase cleanup.
    drop(operation);
    let restored = restore_phase(partition, scratch);
    match result {
        Ok(payload) => match restored {
            Ok(()) => Ok(payload),
            Err(error) => {
                restore_output(output, payload.destroy_into_original())?;
                Err(error)
            }
        },
        Err((error, original)) => {
            let output_result = restore_output(output, original);
            // Process both original-return paths even when either is refused.
            output_result.and(restored)?;
            Err(GBoundNativeCompileFailure::Compile(error))
        }
    }
}

impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_g_bound_native<'a>(mut self,
        operation: GBoundNativeCompileOperation<'_, 'a>)
        -> Result<RetainedOriginal<OwnedCompiledGBound<'a, 'a, 'a>>,
            PhaseFailure<GBoundNativeCompileFailure>>
    {
        let inputs = preflight::inputs(self.admission.plan, self.step)
            .map_err(PhaseFailure::Admission)?;
        if self.step.binding != operation.binding() || self.step.backend != Bytes::ZERO
            || self.step.consume_count != 1 || inputs.len() != 1
            || inputs[0] != operation.input_slot()
            || !self.admission.retired_context.belongs_to(self.admission.context)
        { return Err(PhaseFailure::Admission(WorkflowError::Identity)); }
        let binding = self.step.binding;
        let result = {
            let access = ExecutionAccess { context: self.admission.context, binding,
                backend: self.step.backend, pool: &self.admission.pool };
            attempt(&access, self.admission.phase.as_mut().expect("active closed workflow"),
                self.output.as_mut().expect("preissued compiler output"), operation)
        };
        let output_claim = self.output.take().expect("preissued compiler output");
        let failure_claim = self.failure.take().expect("preissued compiler failure");
        match result {
            Ok(payload) => {
                let output = RetainedOriginal::produced(payload, output_claim, binding);
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
}
