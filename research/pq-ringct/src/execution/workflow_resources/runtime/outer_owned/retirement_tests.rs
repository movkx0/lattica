//! Destruction order at the outer issuer's fallible startup/timing boundaries.
//! No GPU or copied cleanup receipt is used as retirement evidence here.
use super::{OuterOwnedError, RetirementGuard, RetirementState};
use crate::execution::retained_resources::{Bytes, Category, Ledger, Reservation, WorkerAllowance};
use std::{cell::Cell, panic::{catch_unwind, AssertUnwindSafe}};

fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: 64, device: 64 }) }
fn original(ledger: &Ledger, category: Category, host: u64, device: u64) -> Reservation {
    ledger.reserve(category, Bytes { host, device }).unwrap()
}

struct Payload<'a> { destroyed: &'a Cell<bool>, ledger: &'a Ledger }
impl Drop for Payload<'_> {
    fn drop(&mut self) {
        // Output/failure slots and all split backend originals still cover
        // this payload when an authenticated path destroys it.
        assert_eq!(self.ledger.snapshot().current, Bytes { host: 64, device: 64 });
        self.destroyed.set(true);
    }
}

#[test]
fn produced_payload_survives_timing_refusal_until_authenticated_retirement() {
    let ledger = ledger();
    let destroyed = Cell::new(false);
    let state = RetirementState::new();
    let input = RetirementGuard::new(original(&ledger, Category::CompilerInputs, 16, 0), &state);
    let wrappers = RetirementGuard::new(original(&ledger, Category::PhaseScratch, 8, 0), &state);
    let pcs = RetirementGuard::new(original(&ledger, Category::PhaseScratch, 8, 64), &state);
    let output = RetirementGuard::new(original(&ledger, Category::NativeProof, 24, 0), &state);
    let failure = RetirementGuard::new(original(&ledger, Category::Report, 8, 0), &state);
    state.arm();
    let mut produced = RetirementGuard::new(None, &state);
    let attempted = (|| -> Result<(), OuterOwnedError> {
        *produced.get_mut() = Some(Payload { destroyed: &destroyed, ledger: &ledger });
        Err(OuterOwnedError::Report)
    })();
    let attempted = RetirementGuard::new(attempted, &state);
    assert!(state.is_required());
    assert!(!destroyed.get());
    state.after_authenticated_retirement();
    assert!(matches!(attempted.into_original(), Err(OuterOwnedError::Report)));
    drop(produced.into_original());
    assert!(destroyed.get());
    drop((input.into_original(), wrappers.into_original(), pcs.into_original(),
        output.into_original(), failure.into_original()));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn uncertain_outer_end_retains_output_failure_and_backend_originals_together() {
    // Startup unwind, unwind after producing, and ordinary retirement refusal.
    for (make_output, unwind) in [(false, true), (true, true), (true, false)] {
        let ledger = ledger();
        let destroyed = Cell::new(false);
        let observed = catch_unwind(AssertUnwindSafe(|| {
            let state = RetirementState::new();
            let input = RetirementGuard::new(original(&ledger, Category::CompilerInputs, 16, 0), &state);
            let wrappers = RetirementGuard::new(original(&ledger, Category::PhaseScratch, 8, 0), &state);
            let pcs = RetirementGuard::new(original(&ledger, Category::PhaseScratch, 8, 64), &state);
            let output = RetirementGuard::new(original(&ledger, Category::NativeProof, 24, 0), &state);
            let failure = RetirementGuard::new(original(&ledger, Category::Report, 8, 0), &state);
            state.arm();
            let mut produced = RetirementGuard::new(None, &state);
            if make_output {
                *produced.get_mut() = Some(Payload { destroyed: &destroyed, ledger: &ledger });
            }
            if unwind { panic!("outer startup/retirement boundary injection"); }
            assert!(state.is_required());
            drop((produced, input, wrappers, pcs, output, failure));
        }));
        assert_eq!(observed.is_err(), unwind);
        assert!(!destroyed.get());
        assert_eq!(ledger.snapshot().current, Bytes { host: 64, device: 64 });
        assert!(ledger.reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 }).is_err());
        assert!(ledger.reserve(Category::PhaseScratch, Bytes { host: 0, device: 1 }).is_err());
    }
}

#[test]
fn returned_partial_start_original_disarms_before_same_ledger_restoration() {
    let ledger = ledger();
    let state = RetirementState::new();
    let wrapper = original(&ledger, Category::PhaseScratch, 16, 0);
    let expected = wrapper.requirements();
    let wrapper = RetirementGuard::new(wrapper, &state);
    let pcs = RetirementGuard::new(original(&ledger, Category::PhaseScratch, 48, 64), &state);
    state.arm();
    assert!(state.is_required());
    state.after_failed_start();
    assert!(!state.is_required());
    let wrapper = wrapper.into_original();
    assert!(wrapper.belongs_to(&ledger));
    assert_eq!(wrapper.requirements(), expected);
    drop((wrapper, pcs.into_original()));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
