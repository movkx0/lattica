//! Fixed N3/N4 source-layer owners are claimed before source planning starts.
//! The enclosing original is acquired before constructing the array, and the
//! actual partial array is installed before a failed element claim is inspected.
use super::{CaseOwnerSlot, CaseRetirementState, FreshGenerationError, Result, State, source};

pub(crate) struct FixedCaseOwnerSlots<'case, T, const N: usize> {
    slots: [Option<CaseOwnerSlot<'case, T>>; N],
    failure: Option<FreshGenerationError>,
    state: &'case CaseRetirementState,
}

impl CaseRetirementState {
    pub(crate) fn preclaim_n3<T>(&self) -> Result<CaseOwnerSlot<'_, FixedCaseOwnerSlots<'_, T, 3>>> {
        self.preclaim_fixed()
    }

    pub(crate) fn preclaim_n4<T>(&self) -> Result<CaseOwnerSlot<'_, FixedCaseOwnerSlots<'_, T, 4>>> {
        self.preclaim_fixed()
    }

    fn preclaim_fixed<T, const N: usize>(
        &self,
    ) -> Result<CaseOwnerSlot<'_, FixedCaseOwnerSlots<'_, T, N>>> {
        if !matches!(N, 3 | 4) || self.transactions != N {
            return Err(source("fixed source table case mismatch"));
        }
        let owner = self.preclaim::<FixedCaseOwnerSlots<'_, T, N>>()?;
        let mut table = FixedCaseOwnerSlots { slots: [const { None }; N], failure: None, state: self };
        for slot in &mut table.slots {
            match self.preclaim::<T>() {
                Ok(original) => *slot = Some(original),
                Err(error) => {
                    table.failure = Some(error);
                    break;
                }
            }
        }
        owner.install(table)?;
        if owner.get()?.failure.is_some() {
            // The outer slot now owns the partial array and original error.
            // Its armed drop retains both; there is no retry or naked result.
            self.state.set(State::Poisoned);
            return Err(source("fixed source table element admission failed"));
        }
        Ok(owner)
    }
}

impl<'case, T, const N: usize> FixedCaseOwnerSlots<'case, T, N> {
    /// The caller authenticates `case` against its guarded startup owner and
    /// current WorkflowPlanning ledger. Equal case sizes or ledger identities
    /// alone never authorize using another state's actual owning slots.
    pub(crate) fn check_case(&self, case: &CaseRetirementState) -> Result<()> {
        if !core::ptr::eq(self.state, case) || case.state.get() != State::Armed
            || case.transactions != N || self.failure.is_some()
            || self.slots.iter().any(|slot| slot.as_ref().is_none_or(|slot|
                !core::ptr::eq(slot.state, case)
                || slot.original.as_ref().is_none_or(|original| !original.belongs_to(&case.ledger))))
        {
            return Err(source("fixed source table belongs to another case"));
        }
        Ok(())
    }

    pub(crate) fn get(&self, index: usize) -> Result<&CaseOwnerSlot<'case, T>> {
        if self.failure.is_some() {
            return Err(source("fixed source table construction failed"));
        }
        self.slots.get(index).and_then(Option::as_ref)
            .ok_or_else(|| source("fixed source table ordinal out of bounds"))
    }
}

#[cfg(test)]
mod tests;
