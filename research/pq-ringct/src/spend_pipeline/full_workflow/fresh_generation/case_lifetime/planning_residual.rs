//! One exact planning residual survives every nested metadata/runtime caller.
//! Only the enclosing case may release it after all those scopes have ended.
use super::*;

impl CaseRetirementState {
    pub(crate) fn claim_planning_residual(&self, original: &Reservation) -> Result<()> {
        if self.state.get() != State::Armed || !self.metadata_owner_installed()
            || !original.belongs_to(&self.ledger)
            || self.original.as_ref().is_none_or(|state| !state.belongs_to(&self.ledger))
            || self.planning_residual_issued.get()
        { return Err(source("case planning residual identity or one-shot mismatch")); }
        self.planning_residual_issued.set(true);
        Ok(())
    }

    pub(crate) fn poison_planning_residual(&self) { self.state.set(State::Poisoned); }

    /// Called by the original's Drop on success, error and unwind. Cell has
    /// no dynamic borrow to panic during unwinding and owns the actual token.
    pub(crate) fn retain_planning_residual(&self, original: Reservation) {
        if !self.planning_residual_issued.get() || !original.belongs_to(&self.ledger) {
            self.poison_planning_residual();
            core::mem::forget(original);
            return;
        }
        if let Some(previous) = self.planning_residual.replace(Some(original)) {
            self.poison_planning_residual();
            core::mem::forget(previous);
        }
    }
}

#[cfg(test)]
mod tests;
