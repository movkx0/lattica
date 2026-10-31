//! Move an active phase's original claims through a closed owned backend.
//! This module issues no runtime or dispatch permission. Only execution-owned
//! typed adapters may use it, after checking the immutable operation binding.
use super::*;

fn contains(envelope: Requirements, value: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let a = envelope.get(category);
        let b = value.get(category);
        b.host <= a.host && b.device <= a.device
    })
}

impl PhaseLease<'_, '_> {
    /// Read the actual original source-phase claim without extracting backend
    /// credit. Only closed pre-retirement source operations use this borrow.
    pub(in crate::execution) fn original_for_source(
        &self,
    ) -> Result<std::cell::Ref<'_, Reservation>, Error> {
        let state = self.capability.context.phases.state.try_borrow()
            .map_err(|_| Error::ContextBusy)?;
        ContextPhases::check_active(&state, self.generation)?;
        ContextPhases::check_no_partition(&state)?;
        if state.held.is_none() { return Err(Error::IncompleteOwnedPartition); }
        Ok(std::cell::Ref::map(state, |state| {
            state.held.as_ref().expect("checked source original")
        }))
    }
}

/// The context keeps an outstanding marker even if this owner is forgotten.
/// Backend callers split the same original claim and return its exact pieces;
/// they never reserve replacement quota. An incomplete drop poisons the phase.
pub(in crate::execution) struct OriginalPhasePartition<'phase, 'context> {
    phase: &'phase mut OwnedPhase<'context>,
    original: Option<Reservation>,
    requirements: Requirements,
    restored: bool,
}

impl<'context> OwnedPhase<'context> {
    /// Borrow the already admitted original while a closed source packet is
    /// preissued. This supplies no extraction or backend dispatch authority.
    /// RefCell's live borrow also prevents any partition transfer underneath
    /// the inspector. The packet must not retain this borrow.
    pub(in crate::execution) fn original_for_preissue(
        &self,
    ) -> Result<std::cell::Ref<'_, Reservation>, Error> {
        let state = self.capability.context.phases.state.try_borrow()
            .map_err(|_| Error::ContextBusy)?;
        ContextPhases::check_active(&state, self.generation)?;
        ContextPhases::check_no_partition(&state)?;
        if state.held.is_none() {
            return Err(Error::IncompleteOwnedPartition);
        }
        Ok(std::cell::Ref::map(state, |state| {
            state.held.as_ref().expect("checked original phase")
        }))
    }

    /// Execution-private accounting transfer, not a backend entry point.
    /// The caller must be an exact typed native or outer operation issuer.
    pub(in crate::execution) fn partition_originals(
        &mut self,
        requirements: Requirements,
    ) -> Result<OriginalPhasePartition<'_, 'context>, Error> {
        let original = {
            let context = self.capability.context;
            let mut state = context.phases.state.borrow_mut();
            ContextPhases::check_active(&state, self.generation)?;
            ContextPhases::check_no_partition(&state)?;
            if requirements.total()? == Bytes::ZERO {
                return Err(Error::EmptyPhase);
            }
            let original = state.held.as_mut().expect("active original phase")
                .split(requirements)?;
            state.partition = Some(requirements);
            original
        };
        Ok(OriginalPhasePartition {
            phase: self,
            original: Some(original),
            requirements,
            restored: false,
        })
    }
}

impl OriginalPhasePartition<'_, '_> {
    pub(in crate::execution) fn ledger(&self) -> &Ledger {
        self.phase.ledger()
    }

    pub(in crate::execution) fn split(
        &mut self,
        requirements: Requirements,
    ) -> Result<Reservation, Error> {
        self.original.as_mut().ok_or(Error::IncompleteOwnedPartition)?
            .split(requirements).map_err(Error::from)
    }

    /// Return original claims only after the corresponding payload has died.
    /// Typed adapters enforce runtime retirement before returning backend
    /// claims. This cannot attach reservations to supplied proofs or runtimes.
    pub(in crate::execution) fn reunite(
        &mut self,
        original: Reservation,
    ) -> Result<(), (Error, Reservation)> {
        if !original.belongs_to(self.ledger()) {
            return Err((Error::Reservation(ReservationError::DifferentLedger), original));
        }
        let Some(held) = self.original.as_ref() else {
            return Err((Error::IncompleteOwnedPartition, original));
        };
        let mut total = held.requirements();
        for category in Category::ALL {
            if let Err(error) = total.add(category, original.requirements().get(category)) {
                return Err((error.into(), original));
            }
        }
        if !contains(self.requirements, total) {
            return Err((Error::IncompleteOwnedPartition, original));
        }
        let held = self.original.take().expect("checked original partition");
        match held.reunite(original) {
            Ok(held) => {
                self.original = Some(held);
                Ok(())
            }
            Err((error, held, original)) => {
                self.original = Some(held);
                Err((error.into(), original))
            }
        }
    }

    /// Called only by a closed operation's no-start refusal or exact retirement
    /// branch, after all core owners have returned their originals. Byte
    /// equality is an additional check, never the evidence of backend cleanup.
    pub(in crate::execution) fn restore(mut self) -> Result<(), Self> {
        let context = self.phase.capability.context;
        let mut state = context.phases.state.borrow_mut();
        if ContextPhases::check_active(&state, self.phase.generation).is_err()
            || state.partition != Some(self.requirements)
            || self.original.as_ref().is_none_or(|original| {
                !original.belongs_to(context.phases.ledger())
                    || original.requirements() != self.requirements
            })
        {
            drop(state);
            return Err(self);
        }
        let Some(held) = state.held.take() else {
            drop(state);
            return Err(self);
        };
        let original = self.original.take().expect("checked complete originals");
        match held.reunite(original) {
            Ok(held) => {
                state.held = Some(held);
                state.partition = None;
                self.restored = true;
                drop(state);
                Ok(())
            }
            Err((_error, held, original)) => {
                state.held = Some(held);
                self.original = Some(original);
                drop(state);
                Err(self)
            }
        }
    }
}

impl Drop for OriginalPhasePartition<'_, '_> {
    fn drop(&mut self) {
        if !self.restored {
            self.phase.capability.context.phases.abandon(self.phase.generation);
            // No retirement branch returned the complete originals. Keep the
            // original residual credit held rather than freeing asynchronous
            // backend capacity. The caller must terminate this failed worker.
            if let Some(original) = self.original.take() {
                core::mem::forget(original);
            }
        }
    }
}

/// Additive execution controller backing; copied inline frame inventory only.
pub(in crate::execution) fn bookkeeping_bytes() -> usize {
    4 * core::mem::size_of::<OriginalPhasePartition<'static, 'static>>()
        + 8 * core::mem::size_of::<Reservation>()
        + 8 * core::mem::size_of::<Requirements>()
        + 4 * core::mem::size_of::<Result<(), (Error, Reservation)>>()
}

#[cfg(test)]
mod tests;
