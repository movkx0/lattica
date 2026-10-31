//! The metadata issuer is tied to the actual guarded fresh planning owner.
use super::*;
use crate::spend_pipeline::full_workflow::SourcePlanningPlan;

impl<'case> CaseOwnerSlot<'case, Result<FreshPlanningContext<'_>>> {
    pub(crate) fn metadata_case_state(&self, scope: &SourcePlanningPlan<'_>, ledger: &Ledger)
        -> Result<&'case CaseRetirementState>
    {
        let context = self.get()?.as_ref().map_err(|_| source("metadata requires successful fresh planning"))?;
        let original = self.original.as_ref().ok_or_else(|| source("metadata planning slot original missing"))?;
        if self.state.state.get() != State::Armed
            || self.state.batch_identity.get().is_null()
            || self.state.transactions != scope.natives().len()
            || !original.belongs_to(&self.state.ledger)
            || !original.belongs_to(ledger)
            || !context.belongs_to_original_generation(ledger, self.state.generation_session)
            || !core::ptr::eq(context.context(), scope.context())
            || scope.fresh_context().is_none_or(|known| !core::ptr::eq(known, context))
        { return Err(source("metadata case/planning owner mismatch")); }
        Ok(self.state)
    }
}
