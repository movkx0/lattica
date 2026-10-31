//! Sealed complete-sequence evidence. This cannot admit work or adopt proofs.
use super::*;
use crate::execution::retained_resources::Ledger;

/// Non-Clone receipt issued only after the exact closed sequence and original
/// phase finish successfully. The small original remains live for this receipt.
pub(crate) struct WorkflowCompletionReceipt<'context> {
    context: &'context ProvingContext,
    source: [u8; 32],
    compiled_source: [u8; 32],
    plan_identity: *const (),
    steps: usize,
    final_binding: PhaseBinding,
    original: Reservation,
}
pub(in crate::execution::workflow_resources) fn host_bytes() -> Result<usize, WorkflowError> {
    use core::mem::size_of;
    [size_of::<WorkflowCompletionReceipt<'static>>(),
        size_of::<Result<WorkflowCompletionReceipt<'static>, WorkflowError>>(),
        2 * size_of::<Requirements>(), 2 * size_of::<Reservation>(),
        size_of::<sha3::Sha3_256>()]
        .into_iter().try_fold(0usize, |sum, part| sum.checked_add(part))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)
}
pub(super) fn requirements() -> Result<Requirements, WorkflowError> {
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(host_bytes()?).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}
impl<'context> WorkflowCompletionReceipt<'context> {
    // Private runtime-only construction; the caller has already consumed its
    // original phase through complete_after_cleanup and retired the slot pool.
    pub(super) fn from_finished(admission: &WorkflowAdmission<'_, 'context>,
        original: Reservation) -> Result<Self, WorkflowError>
    {
        let final_binding = admission.plan.steps().last().ok_or(WorkflowError::Incomplete)?.binding;
        if !admission.completed || admission.failed || admission.phase.is_some()
            || admission.next != admission.plan.steps().len() || !admission.preissue_complete()
            || final_binding.kind() != PhaseKind::FinalVerify
            || original.requirements() != requirements()?
        { return Err(WorkflowError::Incomplete); }
        Ok(Self { context: admission.context, source: admission.plan.source_fingerprint(),
            compiled_source: admission.plan.compiled_source_fingerprint(),
            plan_identity: admission.plan as *const ClosedWorkflowPlan<'_> as *const (),
            steps: admission.next, final_binding, original })
    }
    pub(crate) fn validate_for(&self, context: &ProvingContext, ledger: &Ledger)
        -> Result<(), WorkflowError>
    {
        if !core::ptr::eq(context, self.context) || !self.original.belongs_to(ledger)
            || self.steps == 0 || self.final_binding.kind() != PhaseKind::FinalVerify
            || self.compiled_source != crate::graph_proofs::compiled_source_fingerprint()
            || self.original.requirements() != requirements()?
        { return Err(WorkflowError::Identity); }
        context.validate_workflow_completion_original(&self.original)?;
        Ok(())
    }
    pub(crate) fn matches_plan(&self, plan: &ClosedWorkflowPlan<'_>) -> bool {
        self.plan_identity == plan as *const ClosedWorkflowPlan<'_> as *const ()
            && core::ptr::eq(self.context, plan.context())
            && self.source == plan.source_fingerprint()
            && self.compiled_source == plan.compiled_source_fingerprint()
            && self.steps == plan.steps().len()
            && plan.steps().last().is_some_and(|step| step.binding == self.final_binding)
    }
}
