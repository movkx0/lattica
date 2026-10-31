//! Stack-only retention until the driver authenticates its actual runtime end.
//! This guard grants no admission, dispatch, or retirement authority.
use std::cell::Cell;

pub(super) struct RetirementState {
    required: Cell<bool>,
}
impl RetirementState {
    pub(super) fn new() -> Self { Self { required: Cell::new(false) } }
    /// Observation only: unresolved cleanup must not release phase slots.
    pub(super) fn is_required(&self) -> bool { self.required.get() }
    /// Arm before entering runtime startup, including its unwind paths.
    pub(super) fn arm(&self) { self.required.set(true); }
    /// Call only on start_preserving's error path: that sealed API destroys
    /// every partial epoch before returning its original startup reservation.
    pub(super) fn after_failed_start(&self) { self.required.set(false); }
    /// Call only after the sealed retirement matches the native phase and
    /// ledger, or after the unattempted path extracts the outer startup owner.
    pub(super) fn after_authenticated_retirement(&self) { self.required.set(false); }
}

pub(super) struct RetirementGuard<'state, T> {
    held: Option<T>,
    state: &'state RetirementState,
}
impl<'state, T> RetirementGuard<'state, T> {
    pub(super) fn new(held: T, state: &'state RetirementState) -> Self {
        Self { held: Some(held), state }
    }
    pub(super) fn get(&self) -> &T { self.held.as_ref().expect("guarded native original") }
    pub(super) fn get_mut(&mut self) -> &mut T {
        self.held.as_mut().expect("guarded native original")
    }
    pub(super) fn into_original(mut self) -> T {
        // An accidental early extraction retains the original during unwind.
        assert!(!self.state.required.get(), "native retirement is still required");
        self.held.take().expect("retired native original")
    }
}
impl<T> Drop for RetirementGuard<'_, T> {
    fn drop(&mut self) {
        if self.state.required.get() {
            // Preserve payload and its non-Clone original claim together.
            // Dropping the phase partition alone preserves only its residual.
            if let Some(held) = self.held.take() { core::mem::forget(held); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Bytes, Category, Ledger, WorkerAllowance};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: 64, device: 64 }) }

    #[test]
    fn every_split_original_survives_unwind_and_an_ordinary_retirement_failure() {
        for unwind in [false, true] {
            let ledger = ledger();
            let result = catch_unwind(AssertUnwindSafe(|| {
                let state = RetirementState::new();
                let preparation = RetirementGuard::new(ledger.reserve(Category::PhaseScratch,
                    Bytes { host: 16, device: 0 }).unwrap(), &state);
                let verifier = RetirementGuard::new(ledger.reserve(Category::PhaseScratch,
                    Bytes { host: 16, device: 0 }).unwrap(), &state);
                let native = RetirementGuard::new(ledger.reserve(Category::PhaseScratch,
                    Bytes { host: 16, device: 64 }).unwrap(), &state);
                state.arm();
                let produced = RetirementGuard::new((
                    ledger.reserve(Category::NativeProof, Bytes { host: 8, device: 0 }).unwrap(),
                    ledger.reserve(Category::Report, Bytes { host: 8, device: 0 }).unwrap(),
                ), &state);
                if unwind { panic!("injected failure without authenticated retirement"); }
                drop((preparation, verifier, native, produced));
            }));
            assert_eq!(result.is_err(), unwind);
            assert_eq!(ledger.snapshot().current, Bytes { host: 64, device: 64 });
            assert!(ledger.reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 }).is_err());
        }
    }

    #[test]
    fn an_uncertain_retirement_keeps_the_produced_payload_with_its_original() {
        struct Payload<'a>(&'a Cell<bool>);
        impl Drop for Payload<'_> { fn drop(&mut self) { self.0.set(true); } }
        let ledger = ledger();
        let destroyed = Cell::new(false);
        {
            let state = RetirementState::new();
            let output = RetirementGuard::new((Payload(&destroyed),
                ledger.reserve(Category::NativeProof, Bytes { host: 64, device: 0 }).unwrap()), &state);
            state.arm();
            drop(output);
        }
        assert!(!destroyed.get());
        assert_eq!(ledger.snapshot().current.host, 64);
    }

    #[test]
    fn guarded_payload_dies_before_its_original_after_authentication() {
        struct Payload<'a> { destroyed: &'a Cell<bool>, ledger: &'a Ledger }
        impl Drop for Payload<'_> {
            fn drop(&mut self) {
                assert_eq!(self.ledger.snapshot().current.host, 64);
                self.destroyed.set(true);
            }
        }
        let ledger = ledger();
        let destroyed = Cell::new(false);
        let state = RetirementState::new();
        let mut output = RetirementGuard::new((Payload { destroyed: &destroyed, ledger: &ledger },
            ledger.reserve(Category::NativeProof, Bytes { host: 64, device: 0 }).unwrap()), &state);
        state.arm();
        assert!(!output.get().0.destroyed.get());
        let _exclusive = output.get_mut();
        state.after_authenticated_retirement();
        drop(output.into_original());
        assert!(destroyed.get());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn an_early_extraction_panics_without_releasing_original_credit() {
        let ledger = ledger();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let state = RetirementState::new();
            let original = RetirementGuard::new(ledger.reserve(Category::PhaseScratch,
                Bytes { host: 64, device: 0 }).unwrap(), &state);
            state.arm();
            drop(original.into_original());
        }));
        assert!(result.is_err());
        assert_eq!(ledger.snapshot().current.host, 64);
    }

    #[test]
    fn a_failed_start_or_no_start_releases_the_original_normally() {
        for started in [false, true] {
            let ledger = ledger();
            let state = RetirementState::new();
            let original = RetirementGuard::new(ledger.reserve(Category::PhaseScratch,
                Bytes { host: 64, device: 0 }).unwrap(), &state);
            if started { state.arm(); state.after_failed_start(); }
            drop(original.into_original());
            assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        }
    }
}
