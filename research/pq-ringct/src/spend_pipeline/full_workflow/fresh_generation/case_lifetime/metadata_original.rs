//! Stable case owners consume metadata backing already reserved by the source
//! planner. This path never releases/re-admits an original or issues credit.
use super::{CaseOwnerSlot, CaseRetirementState, FreshGenerationError, Requirements,
    Reservation, Result, State, OnceCell, slot_requirements, source};

impl CaseRetirementState {
    /// Pure typed backing census. It does not allocate a table or admit credit.
    pub(crate) fn owner_slot_requirements<T>() -> Result<Requirements> {
        slot_requirements::<T>()
    }

    /// Transfer the exact original split into the stable owning slot before T
    /// is constructed. A refused transfer returns the unchanged original; the
    /// caller must retain that full failure and permanently stop construction.
    /// No fresh reservation is acquired, even when spare allowance exists.
    pub(crate) fn preclaim_from_original<T>(&self, original: Reservation)
        -> core::result::Result<CaseOwnerSlot<'_, T>, (FreshGenerationError, Reservation)>
    {
        let checked = (|| {
            if self.state.get() != State::Armed {
                return Err(source("case metadata slot outside active case"));
            }
            if !original.belongs_to(&self.ledger)
                || original.requirements() != slot_requirements::<T>()?
            {
                return Err(source("case metadata original mismatch"));
            }
            Ok(())
        })();
        match checked {
            Ok(()) => Ok(CaseOwnerSlot { owner: OnceCell::new(), state: self,
                original: Some(original) }),
            Err(error) => Err((error, original)),
        }
    }
}

impl<T> CaseOwnerSlot<'_, T> {
    /// Inspect slot occupancy before invoking a constructor. A stored failure
    /// is occupied too; this grants no extraction, retry or replacement credit.
    pub(crate) fn is_initialized(&self) -> bool { self.owner.get().is_some() }
}

#[cfg(test)]
mod tests;
