use super::*;
use crate::execution::workflow_resources::SlotId;

pub(super) fn inputs<'a>(
    plan: &'a ClosedWorkflowPlan<'_>,
    step: PhaseStep,
) -> Result<&'a [SlotId], WorkflowError> {
    if step.consume_count > step.input_count {
        return Err(WorkflowError::Sequence);
    }
    let end = step
        .input_start
        .checked_add(step.input_count)
        .ok_or(WorkflowError::Overflow)?;
    plan.inputs()
        .get(step.input_start..end)
        .ok_or(WorkflowError::Sequence)
}

/// Allocation-free liveness replay. A slot is live iff its latest event before
/// this step was production rather than consumption. The bounded source plan
/// pays the CPU cost; no bitmap/vector is allocated before source admission.
fn live_before(
    plan: &ClosedWorkflowPlan<'_>,
    before: usize,
    wanted: SlotId,
) -> Result<bool, WorkflowError> {
    for step in plan.steps()[..before].iter().rev().copied() {
        if step.output == wanted {
            return Ok(true);
        }
        if inputs(plan, step)?[..step.consume_count].contains(&wanted) {
            return Ok(false);
        }
    }
    Ok(false)
}

pub(super) fn check(
    plan: &ClosedWorkflowPlan<'_>,
    managed_device: u64,
) -> Result<Requirements, WorkflowError> {
    if plan.slots().is_empty() || plan.steps().is_empty() {
        return Err(WorkflowError::Empty);
    }
    let scratch = plan.scratch_requirements();
    if scratch.total()? == Bytes::ZERO {
        return Err(WorkflowError::Empty);
    }
    let mut whole = combine(scratch, SlotPool::bookkeeping_requirements(plan.slots().len())?)?;
    for slot in plan.slots() {
        if slot.requirements.total()? == Bytes::ZERO
            || slot.requirements.get(Category::PhaseScratch) != Bytes::ZERO
        {
            return Err(WorkflowError::Slot);
        }
        whole = combine(whole, slot.requirements)?;
    }
    let compiled_source = plan.compiled_source_fingerprint();
    for (index, step) in plan.steps().iter().copied().enumerate() {
        let facts = step.binding.facts();
        if facts.compiled_source_fingerprint != compiled_source {
            return Err(WorkflowError::Source);
        }
        if step.output == step.failure {
            return Err(WorkflowError::Slot);
        }
        let output = plan.slots().get(step.output.index()).ok_or(WorkflowError::Slot)?;
        let failure = plan.slots().get(step.failure.index()).ok_or(WorkflowError::Slot)?;
        if !contains(output.requirements, facts.output)
            || !contains(failure.requirements, facts.failure)
            || facts.output.total()? == Bytes::ZERO
            || facts.failure.total()? == Bytes::ZERO
            || live_before(plan, index, step.output)?
            || live_before(plan, index, step.failure)?
        {
            return Err(WorkflowError::SlotBusy);
        }
        let inputs = inputs(plan, step)?;
        for (position, input) in inputs.iter().copied().enumerate() {
            if input.index() >= plan.slots().len()
                || input == step.output
                || input == step.failure
                || inputs[..position].contains(&input)
                || !live_before(plan, index, input)?
            {
                return Err(WorkflowError::Sequence);
            }
        }
        let backend_limit = if facts.kind.is_native() || facts.kind.is_preparation() {
            MAX_NATIVE_BYTES
        } else {
            MAX_HOST_BYTES
        };
        if step.backend.host > backend_limit
            || step.backend.device > MAX_DEVICE_BYTES
            || step.backend.host > plan.context().host_bytes()
            || (facts.kind.requires_gpu_backend()
                && (step.backend.host == 0 || step.backend.device == 0))
            || (step.backend.device != 0 && step.backend.device != managed_device)
        {
            return Err(WorkflowError::BackendAllowance);
        }
        // Enclosing owners, every preissued output slot, source-plan originals
        // and non-backend scratch all remain charged while the engine runs.
        let phase = combine(
            facts.scratch,
            Requirements::single(Category::PhaseScratch, step.backend),
        )?;
        if !contains(scratch, phase) {
            return Err(WorkflowError::BackendAllowance);
        }
    }
    // Admission of this one combined request also includes every still-live
    // original planning claim on the same ledger. It occurs before native0.
    whole.total()?;
    Ok(whole)
}
