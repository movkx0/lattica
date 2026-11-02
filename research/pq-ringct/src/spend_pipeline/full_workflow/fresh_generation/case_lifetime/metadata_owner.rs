//! Construction ownership is independent of permission to execute proofs.
use super::*;
use crate::spend_pipeline::full_workflow::SourcePlanningPlan;

pub(crate) enum MetadataOwner<'view, 'case, 'terminal> {
    Fresh(&'view CaseOwnerSlot<'case, Result<FreshPlanningContext<'terminal>>>),
    #[cfg(test)]
    Fixture { case: &'case CaseRetirementState,
        startup: &'view crate::execution::generation_terminal::planning_startup::FixturePlanningContext },
}
impl<'view, 'case, 'terminal> MetadataOwner<'view, 'case, 'terminal> {
    pub(crate) fn metadata_case_state(&self, scope: &SourcePlanningPlan<'_>, ledger: &Ledger)
        -> Result<&'case CaseRetirementState>
    {
        match self {
            Self::Fresh(slot) => slot.metadata_case_state(scope, ledger),
            #[cfg(test)]
            Self::Fixture { case, startup } => {
                if case.state.get() != State::Armed || case.generation_session != 0
                    || case.fixture_context != Some(startup.context() as *const _)
                    || case.transactions != scope.natives().len()
                    || !core::ptr::eq(startup.context(), scope.context())
                    || scope.fixture_context().is_none_or(|owner| !core::ptr::eq(owner, *startup))
                    || case.original.as_ref().is_none_or(|held| !held.belongs_to(ledger) || !held.belongs_to(startup.ledger()))
                { return Err(source("fixture metadata owner mismatch")); }
                Ok(case)
            }
        }
    }
    pub(crate) fn fresh_slot(&self) -> Result<&'view CaseOwnerSlot<'case, Result<FreshPlanningContext<'terminal>>>> {
        match self {
            Self::Fresh(slot) => Ok(slot),
            #[cfg(test)]
            Self::Fixture { .. } => Err(source("fixture metadata cannot execute proofs")),
        }
    }
}

impl CaseRetirementState {
    #[cfg(test)]
    pub(crate) fn prepare_fixture(startup: &crate::execution::generation_terminal::planning_startup::FixturePlanningContext) -> Result<Self> {
        let original = startup.ledger().admit_phase(state_requirements()?)
            .map_err(|_| source("fixture case admission"))?;
        Ok(Self { state: Cell::new(State::Armed), ledger: startup.ledger().clone(),
            generation_session: 0, transactions: 3, fixture_context: Some(startup.context()),
            batch_identity: Cell::new(core::ptr::null()), sealed_plan: Cell::new(core::ptr::null()),
            sealed_context: Cell::new(core::ptr::null()), sealed_source: Cell::new(([0; 32], [0; 32])),
            batch_original: RefCell::new(None), planning_original: RefCell::new(None),
            planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None), original: Some(original) })
    }
    pub(super) fn metadata_owner_installed(&self) -> bool {
        #[cfg(test)]
        if self.fixture_context.is_some() && self.generation_session == 0 { return true; }
        !self.batch_identity.get().is_null()
    }
}
