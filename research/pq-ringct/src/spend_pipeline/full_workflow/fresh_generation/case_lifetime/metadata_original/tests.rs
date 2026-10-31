use super::*;
use crate::execution::retained_resources::{Bytes, Category, Ledger, WorkerAllowance};
use std::cell::{Cell, RefCell};

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 })
}

fn state(ledger: &Ledger) -> CaseRetirementState {
    CaseRetirementState {
        state: Cell::new(State::Armed), ledger: ledger.clone(), generation_session: 7,
        transactions: 3, batch_identity: Cell::new(core::ptr::null()),
        sealed_plan: Cell::new(core::ptr::null()), sealed_context: Cell::new(core::ptr::null()),
        sealed_source: Cell::new(([0; 32], [0; 32])),
        batch_original: RefCell::new(None), planning_original: RefCell::new(None),
        planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None),
        original: Some(ledger.admit_phase(super::super::state_requirements().unwrap()).unwrap()),
    }
}

#[test]
fn exact_metadata_original_moves_without_changing_current_or_peak() {
    let ledger = ledger();
    let state = state(&ledger);
    let requirement = CaseRetirementState::owner_slot_requirements::<[u8; 32]>().unwrap();
    let original = ledger.admit_phase(requirement).unwrap();
    let before = ledger.snapshot();
    let slot = match state.preclaim_from_original::<[u8; 32]>(original) {
        Ok(slot) => slot,
        Err(_) => panic!("exact original refused"),
    };
    let after = ledger.snapshot();
    assert_eq!(before.current, after.current);
    assert_eq!(before.peak, after.peak);
    slot.install([9; 32]).unwrap();
    assert_eq!(slot.get().unwrap(), &[9; 32]);
    state.state.set(State::Completed);
    drop(slot);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn foreign_metadata_original_is_returned_intact() {
    let ledger = ledger();
    let foreign = self::ledger();
    let state = state(&ledger);
    let requirement = CaseRetirementState::owner_slot_requirements::<[u8; 32]>().unwrap();
    let original = foreign.admit_phase(requirement).unwrap();
    let before = foreign.snapshot().current;
    let (_, returned) = match state.preclaim_from_original::<[u8; 32]>(original) {
        Err(refused) => refused,
        Ok(_) => panic!("foreign original accepted"),
    };
    assert!(returned.belongs_to(&foreign));
    assert!(!returned.belongs_to(&ledger));
    assert_eq!(returned.requirements(), requirement);
    assert_eq!(foreign.snapshot().current, before);
    state.state.set(State::Completed);
}

#[test]
fn metadata_slot_refuses_oversized_original_without_splitting_it() {
    let ledger = ledger();
    let state = state(&ledger);
    let mut requirement = CaseRetirementState::owner_slot_requirements::<u64>().unwrap();
    requirement.add(Category::RegisteredMetadata, Bytes { host: 1, device: 0 }).unwrap();
    let original = ledger.admit_phase(requirement).unwrap();
    let before = ledger.snapshot().current;
    let (_, returned) = match state.preclaim_from_original::<u64>(original) {
        Err(refused) => refused,
        Ok(_) => panic!("non-exact original accepted"),
    };
    assert_eq!(returned.requirements(), requirement);
    assert_eq!(ledger.snapshot().current, before);
    state.state.set(State::Completed);
}

#[test]
fn sealed_case_cannot_issue_a_slot_from_preexisting_credit() {
    let ledger = ledger();
    let state = state(&ledger);
    let requirement = CaseRetirementState::owner_slot_requirements::<u64>().unwrap();
    let original = ledger.admit_phase(requirement).unwrap();
    state.state.set(State::Sealed);
    let before = ledger.snapshot().current;
    let (_, returned) = match state.preclaim_from_original::<u64>(original) {
        Err(refused) => refused,
        Ok(_) => panic!("sealed case issued slot"),
    };
    assert_eq!(returned.requirements(), requirement);
    assert_eq!(ledger.snapshot().current, before);
    state.state.set(State::Completed);
}

#[test]
fn initialized_slot_detects_retained_failure_without_extracting_its_original() {
    let ledger = ledger();
    let state = state(&ledger);
    type Stored = core::result::Result<(), Reservation>;
    let requirement = CaseRetirementState::owner_slot_requirements::<Stored>().unwrap();
    let original = ledger.admit_phase(requirement).unwrap();
    let slot = match state.preclaim_from_original::<Stored>(original) {
        Ok(slot) => slot, Err(_) => panic!("exact slot refused"),
    };
    assert!(!slot.is_initialized());
    let failed = Requirements::single(Category::Report, Bytes { host: 17, device: 0 });
    let retained = ledger.admit_phase(failed).unwrap();
    let before = ledger.snapshot();
    slot.install(Err(retained)).unwrap();
    assert!(slot.is_initialized());
    assert!(slot.is_initialized());
    let original = slot.get().unwrap().as_ref().err().unwrap();
    assert!(original.belongs_to(&ledger));
    assert_eq!(original.requirements(), failed);
    assert_eq!(ledger.snapshot().current, before.current);
    assert_eq!(ledger.snapshot().peak, before.peak);
    state.state.set(State::Completed);
    drop(slot);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
