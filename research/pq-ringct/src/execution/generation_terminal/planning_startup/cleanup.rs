//! Authenticate completed workflow cleanup while immutable source plans still
//! borrow the inert context. Source retirement happened before proof zero;
//! this path never shuts down a later runtime or releases an original claim.
use super::*;
use crate::execution::workflow_resources::WorkflowCompletionReceipt;

/// Non-Clone evidence tied to the exact original planning-context allocation.
/// It grants neither another phase nor permission to attach unrelated owners.
pub(crate) struct PlanningCleanupReceipt<'planning, 'terminal> {
    planning: &'planning FreshPlanningContext<'terminal>,
}
impl PlanningCleanupReceipt<'_, '_> {
    pub(crate) fn belongs_to(&self, planning: &FreshPlanningContext<'_>) -> bool {
        core::ptr::eq(self.planning, planning) && planning.cleanup_confirmed.get()
    }
    pub(crate) fn belongs_to_generation(&self, terminal: &NativeGenerationTerminal) -> bool {
        self.planning.belongs_to_generation(terminal) && self.planning.cleanup_confirmed.get()
    }
}

impl<'terminal> FreshPlanningContext<'terminal> {
    /// The sealed completion must come from the actual final closed sequence.
    /// The private source-session state additionally proves real prior GPU
    /// shutdown. Context storage remains allocated for source-plan borrows.
    /// After using this receipt, drop source plans and call consuming finish.
    pub(crate) fn confirm_workflow_cleanup<'planning>(&'planning self,
        completed: &WorkflowCompletionReceipt<'_>)
        -> GenerationResult<PlanningCleanupReceipt<'planning, 'terminal>>
    {
        if self.cleanup_confirmed.get() || !self.belongs_to_generation(self.terminal)
            || !self.permanent.as_ref().is_some_and(|original| original.belongs_to(&self.startup.ledger)) {
            return Err(GenerationError::Authority);
        }
        completed.validate_for(self.context(), &self.startup.ledger)
            .map_err(|_| GenerationError::Authority)?;
        self.context().validate_completed_planning_startup(&self.startup)
            .map_err(|_| GenerationError::Authority)?;
        self.context().session.as_ref().ok_or(GenerationError::Authority)?
            .confirm_retired_original_planning_context()?;
        // Every check above is borrowed and allocation-free. The phase is
        // permanently retired and its startup original has already reunited
        // and completed, so this state can never authorize another dispatch.
        self.cleanup_confirmed.set(true);
        Ok(PlanningCleanupReceipt { planning: self })
    }
}

pub(super) fn additional_host_bytes() -> GenerationResult<usize> {
    use core::mem::size_of;
    [size_of::<PlanningCleanupReceipt<'static, 'static>>(),
        size_of::<GenerationResult<PlanningCleanupReceipt<'static, 'static>>>(),
        size_of::<&WorkflowCompletionReceipt<'static>>(),
        size_of::<&FreshPlanningContext<'static>>(), size_of::<GenerationResult<()>>(),
    ].into_iter().try_fold(0usize, |sum, part| part.checked_mul(8)
        .and_then(|part| sum.checked_add(part)).ok_or(GenerationError::Overflow))
}
