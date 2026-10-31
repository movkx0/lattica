use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use std::{rc::Rc, panic::{catch_unwind, AssertUnwindSafe}};

struct Payload {
    bytes: Vec<u8>,
    drops: Rc<Cell<usize>>,
    _original: Reservation,
}
impl Drop for Payload {
    fn drop(&mut self) {
        assert_eq!(self.bytes.len(), 64);
        self.drops.set(self.drops.get() + 1);
    }
}
fn payload(ledger: &Ledger, drops: &Rc<Cell<usize>>) -> Payload {
    let original = ledger.reserve(Category::NativeProof, Bytes { host: 64, device: 0 }).unwrap();
    Payload { bytes: vec![7; 64], drops: drops.clone(), _original: original }
}
fn state(ledger: &Ledger) -> CaseRetirementState {
    CaseRetirementState {
        state: Cell::new(State::Prepared), ledger: ledger.clone(), generation_session: 7,
        transactions: 3, batch_identity: Cell::new(core::ptr::null()),
        sealed_plan: Cell::new(core::ptr::null()), sealed_context: Cell::new(core::ptr::null()),
        sealed_source: Cell::new(([0; 32], [0; 32])),
        batch_original: RefCell::new(None), planning_original: RefCell::new(None),
        planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None),
        original: Some(ledger.admit_phase(state_requirements().unwrap()).unwrap()),
    }
}
fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 }) }

#[test]
fn armed_case_retains_payload_and_originals_across_unwind() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let before_unwind = Cell::new(Bytes::ZERO);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let state = state(&ledger);
        state.state.set(State::Armed);
        let slot = state.preclaim::<Payload>().unwrap();
        slot.install(payload(&ledger, &drops)).unwrap();
        before_unwind.set(ledger.snapshot().current);
        panic!("injected failure after actual source owner installed");
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, before_unwind.get());
}

#[test]
fn case_result_slot_keeps_owned_error_payload_and_original() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let expected;
    {
        let state = state(&ledger);
        state.state.set(State::Armed);
        let slot = state.preclaim::<core::result::Result<(), Payload>>().unwrap();
        slot.install(Err(payload(&ledger, &drops))).unwrap();
        assert!(slot.get().unwrap().is_err());
        expected = ledger.snapshot().current;
    }
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, expected);
}

#[test]
fn duplicate_case_install_preserves_both_owners_and_poisoned_backing() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let slot = state.preclaim::<Payload>().unwrap();
    slot.install(payload(&ledger, &drops)).unwrap();
    assert!(slot.install(payload(&ledger, &drops)).is_err());
    assert!(state.state.get() == State::Poisoned);
    let expected = ledger.snapshot().current;
    drop(slot);
    drop(state);
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, expected);
}

#[test]
fn completed_case_rejects_installation_and_releases_refused_payload() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let slot = state.preclaim::<Payload>().unwrap();
    let expected = ledger.snapshot().current;
    state.state.set(State::Completed);
    assert!(slot.install(payload(&ledger, &drops)).is_err());
    assert_eq!(drops.get(), 1);
    assert_eq!(ledger.snapshot().current, expected);
}

#[test]
fn inactive_case_drops_real_payload_before_releasing_all_backing() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let slot = state.preclaim::<Payload>().unwrap();
    slot.install(payload(&ledger, &drops)).unwrap();
    // Destructor mechanics only: no production receipt or cleanup is forged.
    state.state.set(State::Completed);
    drop(slot);
    drop(state);
    assert_eq!(drops.get(), 1);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn case_owner_admission_refuses_before_payload_allocation() {
    let ledger = ledger();
    let state = state(&ledger);
    assert!(state.preclaim::<Payload>().is_err());
    state.state.set(State::Armed);
    let before = ledger.snapshot().current;
    assert!(state.preclaim::<[u8; 1 << 16]>().is_err());
    assert_eq!(ledger.snapshot().current, before);
}

#[test]
fn sealed_case_can_fill_preclaimed_results_but_cannot_admit_more_slots() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let slot = state.preclaim::<Payload>().unwrap();
    // State-machine mechanics; a production seal requires the real plan slot.
    state.state.set(State::Sealed);
    let before = ledger.snapshot().current;
    assert!(state.preclaim::<Payload>().is_err());
    assert_eq!(ledger.snapshot().current, before);
    slot.install(payload(&ledger, &drops)).unwrap();
    let expected = ledger.snapshot().current;
    drop(slot);
    drop(state);
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, expected);
}

#[test]
fn late_case_finalization_failure_keeps_remaining_real_owners() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let slot = state.preclaim::<Payload>().unwrap();
    slot.install(payload(&ledger, &drops)).unwrap();
    state.state.set(State::Finalizing);
    let expected = ledger.snapshot().current;
    drop(slot);
    drop(state);
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, expected);
}

fn payload_context(owner: &Payload) -> Result<*const ()> {
    Ok(&owner.bytes as *const Vec<u8> as *const ())
}

#[test]
fn completed_case_finalizes_installed_owner_before_releasing_slot_backing() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let mut slot = state.preclaim::<Payload>().unwrap();
    slot.install(payload(&ledger, &drops)).unwrap();
    state.sealed_context.set(payload_context(slot.get().unwrap()).unwrap());
    // Exercise finalization mechanics, not a forged production cleanup receipt.
    state.state.set(State::Completed);
    slot.finish_in_place(payload_context, |owner| { drop(owner); Ok(()) }).unwrap();
    assert_eq!(drops.get(), 1);
    assert!(slot.get().is_err());
    assert!(state.state.get() == State::Completed);
    assert_eq!(ledger.snapshot().current,
        combine(state.original.as_ref().unwrap().requirements(),
            slot.original.as_ref().unwrap().requirements()).unwrap().total().unwrap());
    drop(slot);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn moved_case_owner_is_rejected_before_finish_and_keeps_its_backing() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let expected;
    {
        // The separate allocation forces the move to change the embedded address.
        let slot = Box::new(state.preclaim::<Payload>().unwrap());
        slot.install(payload(&ledger, &drops)).unwrap();
        state.sealed_context.set(payload_context(slot.get().unwrap()).unwrap());
        state.state.set(State::Completed);
        expected = ledger.snapshot().current;
        let mut moved = *slot;
        assert!(matches!(moved.finish_in_place(payload_context, |_| panic!("moved owner finalized")),
            Err(FreshGenerationError::Resource("case planning finish context mismatch"))));
        assert!(state.state.get() == State::Finalizing);
        assert!(moved.get().is_ok());
        drop(moved);
    }
    drop(state);
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, expected);
}

#[test]
fn unfinished_case_cannot_extract_its_owner_for_finalization() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let state = state(&ledger);
    state.state.set(State::Armed);
    let mut slot = state.preclaim::<Payload>().unwrap();
    slot.install(payload(&ledger, &drops)).unwrap();
    state.state.set(State::Sealed);
    let expected = ledger.snapshot().current;
    assert!(matches!(slot.finish_in_place(|_| panic!("unauthenticated identity check"),
        |_| panic!("unfinished owner finalized")),
        Err(FreshGenerationError::Resource("case planning owner lacks completed cleanup"))));
    assert!(state.state.get() == State::Sealed);
    assert!(slot.get().is_ok());
    drop(slot);
    drop(state);
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, expected);
}

#[test]
fn failed_or_unwound_case_finish_retains_remaining_originals() {
    for unwind in [false, true] {
        let ledger = ledger();
        let drops = Rc::new(Cell::new(0));
        let state = state(&ledger);
        state.state.set(State::Armed);
        let mut slot = state.preclaim::<Payload>().unwrap();
        slot.install(payload(&ledger, &drops)).unwrap();
        state.sealed_context.set(payload_context(slot.get().unwrap()).unwrap());
        state.state.set(State::Completed);
        let expected = ledger.snapshot().current;
        let outcome = catch_unwind(AssertUnwindSafe(|| slot.finish_in_place(payload_context, |owner| {
            // Model the context's own fail-closed cleanup of its live payload.
            core::mem::forget(owner);
            if unwind { panic!("injected planning finish unwind"); }
            Err(source("injected planning finish failure"))
        })));
        if unwind {
            assert!(outcome.is_err());
            assert!(state.state.get() == State::Finalizing);
        } else {
            assert!(outcome.unwrap().is_err());
            assert!(state.state.get() == State::Poisoned);
        }
        drop(slot);
        drop(state);
        assert_eq!(drops.get(), 0);
        assert_eq!(ledger.snapshot().current, expected);
    }
}
