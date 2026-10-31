//! Concrete frozen Vec backing is separate from each stable owning slot.
//! Constructor refusal and unwind retain partial tables and original remainders.
use super::{CaseOwnerSlot, CaseRetirementState, FreshGenerationError, Reservation,
    Requirements, Category, Bytes, State, Result, source, combine, frames};
use core::mem::size_of;

pub(crate) struct CaseOwnerTable<'case, T> {
    // Actual values die before either backing original on completed cleanup.
    slots: Option<Vec<CaseOwnerSlot<'case, T>>>,
    state: &'case CaseRetirementState,
    backing: Option<Reservation>,
    unissued: Option<Reservation>,
}

/// The complete failed construction owns its partially allocated table and
/// every original remainder. There is deliberately no extraction/retry API.
pub(crate) struct CaseOwnerTableFailure<'case, T> {
    error: FreshGenerationError,
    table: CaseOwnerTable<'case, T>,
}

impl<T> CaseOwnerTableFailure<'_, T> {
    pub(crate) fn error(&self) -> &FreshGenerationError { &self.error }
    pub(crate) fn retained_slots(&self) -> usize { self.table.slots().len() }
}

fn backing_requirements<T>(count: usize) -> Result<Requirements> {
    let array = size_of::<CaseOwnerSlot<'static, T>>().checked_mul(count)
        .filter(|n| *n <= isize::MAX as usize).ok_or_else(|| source("case table capacity overflow"))?;
    let array = Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(array).map_err(|_| source("case table census width"))?, device: 0,
    });
    let forwarding = frames(&[
        size_of::<CaseOwnerTable<'static, T>>(), size_of::<Option<CaseOwnerTable<'static, T>>>(),
        size_of::<CaseOwnerTableFailure<'static, T>>(),
        size_of::<core::result::Result<CaseOwnerTable<'static, T>, CaseOwnerTableFailure<'static, T>>>(),
        size_of::<Vec<CaseOwnerSlot<'static, T>>>(), size_of::<Option<Vec<CaseOwnerSlot<'static, T>>>>(),
        size_of::<core::result::Result<CaseOwnerSlot<'static, T>, (FreshGenerationError, Reservation)>>(),
        size_of::<std::collections::TryReserveError>(), size_of::<Result<()>>(),
        size_of::<Result<Requirements>>(), size_of::<[Requirements; 3]>(),
        size_of::<[Result<Requirements>; 2]>(), size_of::<[&CaseRetirementState; 2]>(),
        size_of::<&[CaseOwnerSlot<'static, T>]>(),
        size_of::<core::slice::Iter<'_, CaseOwnerSlot<'_, T>>>(),
        size_of::<[&Reservation; 2]>(), size_of::<[bool; 4]>(),
        size_of::<[Option<Reservation>; 3]>(), size_of::<[usize; 4]>(),
        size_of::<core::result::Result<Reservation,
            (crate::execution::retained_resources::Error, Reservation, Reservation)>>(),
    ])?;
    combine(array, forwarding)
}

impl<'case, T> CaseOwnerTable<'case, T> {
    /// Source inventory calls this for its exact typed table and cardinality.
    /// The count is not permission to allocate or admit a replacement claim.
    pub(crate) fn requirements(count: usize) -> Result<Requirements> {
        let mut total = backing_requirements::<T>(count)?;
        let slot = CaseRetirementState::owner_slot_requirements::<T>()?;
        let count = u64::try_from(count).map_err(|_| source("case table slot count width"))?;
        for category in Category::ALL {
            let part = slot.get(category);
            total.add(category, Bytes {
                host: part.host.checked_mul(count).ok_or_else(|| source("case table host census overflow"))?,
                device: part.device.checked_mul(count).ok_or_else(|| source("case table device census overflow"))?,
            }).map_err(|_| source("case table total overflow"))?;
        }
        Ok(total)
    }

    /// Only the named source-metadata bridge supplies this exact original.
    /// Slots and Vec capacity are frozen before dependent plan borrows begin.
    pub(crate) fn from_original(state: &'case CaseRetirementState, count: usize,
        original: Reservation) -> core::result::Result<Self, CaseOwnerTableFailure<'case, T>>
    {
        // This owner exists before validation/allocation and guards every
        // remainder even if construction unwinds midway through the table.
        let mut table = Self { slots: Some(Vec::new()), state, backing: None,
            unissued: Some(original) };
        let result = table.construct(count);
        match result {
            Ok(()) => Ok(table),
            Err(error) => {
                if state.retaining() { state.state.set(State::Poisoned); }
                Err(CaseOwnerTableFailure { error, table })
            }
        }
    }

    fn construct(&mut self, count: usize) -> Result<()> {
        let original = self.unissued.as_ref().ok_or_else(|| source("case table original missing"))?;
        if self.state.state.get() != State::Armed || !original.belongs_to(&self.state.ledger)
            || original.requirements() != Self::requirements(count)?
        { return Err(source("case table original mismatch")); }
        let backing = backing_requirements::<T>(count)?;
        let slot = CaseRetirementState::owner_slot_requirements::<T>()?;
        self.backing = Some(self.unissued.as_mut().expect("checked original").split(backing)
            .map_err(|_| source("case table backing split failed"))?);
        let slots = self.slots.as_mut().expect("construction owns vector");
        slots.try_reserve_exact(count).map_err(|_| source("case table allocation refused"))?;
        if slots.capacity() != count { return Err(source("case table capacity drift")); }
        for _ in 0..count {
            let original = self.unissued.as_mut().expect("construction remainder").split(slot)
                .map_err(|_| source("case table slot split failed"))?;
            match self.state.preclaim_from_original(original) {
                Ok(slot) => slots.push(slot),
                Err((error, original)) => {
                    let remainder = self.unissued.take().expect("construction remainder");
                    match remainder.reunite(original) {
                        Ok(original) => self.unissued = Some(original),
                        Err((_error, remainder, refused)) => {
                            // Unexpected provenance failure must not release
                            // either owner while the case remains unretired.
                            core::mem::forget(remainder);
                            core::mem::forget(refused);
                        }
                    }
                    return Err(error);
                }
            }
        }
        if self.unissued.as_ref().ok_or_else(|| source("case table remainder lost"))?
            .requirements().total().map_err(|_| source("case table remainder overflow"))? != Bytes::ZERO
        { return Err(source("case table unissued slot credit")); }
        Ok(())
    }

    pub(crate) fn slots(&self) -> &[CaseOwnerSlot<'case, T>] {
        self.slots.as_deref().unwrap_or(&[])
    }

    /// Authenticate the actual frozen table and every original slot against
    /// the exact case state. Equal ledger identities alone are insufficient.
    /// This read-only projection grants no extraction or replacement credit.
    pub(crate) fn belongs_to_case(&self, case: &CaseRetirementState) -> bool {
        if !core::ptr::eq(self.state, case)
            || !matches!(case.state.get(), State::Armed | State::Sealed)
        { return false; }
        let Some(slots) = self.slots.as_ref() else { return false; };
        if slots.len() != slots.capacity() { return false; }
        let (Ok(backing), Ok(slot)) = (
            backing_requirements::<T>(slots.len()),
            CaseRetirementState::owner_slot_requirements::<T>(),
        ) else { return false; };
        self.backing.as_ref().is_some_and(|original|
            original.belongs_to(&case.ledger) && original.requirements() == backing)
            && self.unissued.as_ref().is_some_and(|original|
                original.belongs_to(&case.ledger)
                    && original.requirements() == Requirements::default())
            && slots.iter().all(|owner|
                core::ptr::eq(owner.state, case)
                    && owner.original.as_ref().is_some_and(|original|
                        original.belongs_to(&case.ledger) && original.requirements() == slot))
    }

    pub(crate) fn get(&self, ordinal: usize) -> Result<&CaseOwnerSlot<'case, T>> {
        self.slots().get(ordinal).ok_or_else(|| source("case table ordinal out of bounds"))
    }
}

impl<T> Drop for CaseOwnerTable<'_, T> {
    fn drop(&mut self) {
        if self.state.retaining() {
            if let Some(slots) = self.slots.take() { core::mem::forget(slots); }
            if let Some(original) = self.backing.take() { core::mem::forget(original); }
            if let Some(original) = self.unissued.take() { core::mem::forget(original); }
        } else {
            // Destroy slot payloads before returning array/backing originals.
            drop(self.slots.take());
        }
    }
}

#[cfg(test)]
mod tests;
