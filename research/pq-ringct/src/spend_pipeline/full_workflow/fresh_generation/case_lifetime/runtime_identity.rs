//! Runtime dispatch is tied to the exact plan sealed by this actual case.
use super::*;

impl CaseRetirementState {
    pub(crate) fn matches_runtime_plan(&self, plan: &ClosedWorkflowPlan<'_>,
        context: &crate::execution::ProvingContext, ledger: &Ledger) -> bool
    {
        self.state.get() == State::Sealed
            && self.sealed_plan.get() == plan as *const _ as *const ()
            && self.sealed_context.get() == context as *const _ as *const ()
            && core::ptr::eq(plan.context(), context)
            && self.sealed_source.get() == (plan.source_fingerprint(), plan.compiled_source_fingerprint())
            && self.original.as_ref().is_some_and(|original|
                original.belongs_to(&self.ledger) && original.belongs_to(ledger))
            && plan.belongs_to(ledger) && plan.fresh_only()
    }
}
