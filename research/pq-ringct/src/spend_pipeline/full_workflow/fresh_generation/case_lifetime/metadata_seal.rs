//! Seal the concrete complete-schedule Result owner after authenticated closure.
use super::*;
use crate::spend_pipeline::full_workflow::closed_plan::CompleteScheduleResult;

impl CaseRetirementState {
    pub(crate) fn seal_complete_metadata<const N: usize>(&self,
        batch_slot: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>,
        planning: &FreshPlanningContext<'_>,
        plan_slot: &CaseOwnerSlot<'_, CompleteScheduleResult<'_>>,
    ) -> Result<()> {
        let batch = batch_slot.get()?;
        let closed = plan_slot.get()?.as_ref().map_err(|_| source("case cannot seal refused complete schedule"))?;
        let original = plan_slot.original.as_ref().ok_or_else(|| source("missing complete schedule slot original"))?;
        // The opaque complete token independently rules out sealing an older
        // partial-path plan through this named complete-result slot.
        let complete = closed.validated_complete_inventory()
            .map_err(|_| source("case requires authenticated complete schedule"))?;
        if self.state.get() != State::Armed || !core::ptr::eq(batch_slot.state, self)
            || !core::ptr::eq(plan_slot.state, self)
            || self.batch_identity.get() != batch as *const FreshGenerationBatch<N> as *const ()
            || self.transactions != N || self.generation_session != batch.terminal.session_id()
            || !batch.terminal.belongs_to(&self.ledger)
            || !planning.belongs_to_generation(&batch.terminal)
            || !core::ptr::eq(closed.context(), planning.context())
            || !core::ptr::eq(complete.closed_plan(), closed)
            || !original.belongs_to(&self.ledger)
            || original.requirements() != Self::owner_slot_requirements::<CompleteScheduleResult<'static>>()?
            || !closed.belongs_to(&self.ledger) || !closed.fresh_only()
        { return Err(source("case complete schedule identity mismatch")); }
        self.sealed_plan.set(closed as *const ClosedWorkflowPlan<'_> as *const ());
        self.sealed_context.set(closed.context() as *const _ as *const ());
        self.sealed_source.set((closed.source_fingerprint(), closed.compiled_source_fingerprint()));
        self.state.set(State::Sealed);
        Ok(())
    }
}
