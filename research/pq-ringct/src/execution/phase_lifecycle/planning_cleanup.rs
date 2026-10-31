//! Borrowed final validation of the exact original generation/planning ledger.
use super::*;
use crate::execution::generation_terminal::planning_startup::OriginalPlanningStartup;
use std::rc::Rc;

impl ProvingContext {
    /// Check terminal context state against an existing authentic receipt
    /// original. The receipt separately checks this same original against its
    /// supplied ledger, proving identity without a new ledger or numeric test.
    /// This check alone is not a workflow-success or dispatch capability.
    pub(in crate::execution) fn validate_workflow_completion_original(&self,
        original: &Reservation) -> Result<(), Error>
    {
        let state = self.phases.state.try_borrow().map_err(|_| Error::ContextBusy)?;
        let ledger = self.phases.ledger.get().ok_or(Error::EnclosingAllowance)?;
        if !original.belongs_to(ledger)
            || self.policy() != lattica_prover_p3::proving::Policy::GpuRequired
            || state.status != Status::Retired || state.generation == 0
            || state.held.is_some() || state.partition.is_some()
        { return Err(Error::EnclosingAllowance); }
        Ok(())
    }

    pub(in crate::execution) fn validate_completed_planning_startup(&self,
        expected: &Rc<OriginalPlanningStartup>) -> Result<(), Error>
    {
        let state = self.phases.state.try_borrow().map_err(|_| Error::ContextBusy)?;
        let actual = self.phases.planning_startup.get().ok_or(Error::EnclosingAllowance)?;
        if !Rc::ptr_eq(actual, expected) || expected.session_id() != Some(self.session_id)
            || !expected.capability_issued.get() || expected.closed_requirements.get().is_some()
            || state.status != Status::Retired || state.generation == 0
            || state.held.is_some() || state.partition.is_some()
            || expected.current_requirements().map_err(|_| Error::EnclosingAllowance)? != Requirements::default()
        { return Err(Error::EnclosingAllowance); }
        Ok(())
    }
}
