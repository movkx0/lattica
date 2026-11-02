use super::*;
use crate::execution::retained_resources::{Ledger, WorkerAllowance};
use std::{cell::{Cell, RefCell}, rc::Rc, panic::{catch_unwind, AssertUnwindSafe}};

fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 }) }
fn state(ledger: &Ledger) -> CaseRetirementState {
    CaseRetirementState {
        state: Cell::new(State::Armed), ledger: ledger.clone(), generation_session: 7,
        transactions: 3, batch_identity: Cell::new(core::ptr::null()),
        #[cfg(test)] fixture_context: None, sealed_plan: Cell::new(core::ptr::null()), sealed_context: Cell::new(core::ptr::null()),
        sealed_source: Cell::new(([0; 32], [0; 32])), batch_original: RefCell::new(None),
        planning_original: RefCell::new(None),
        planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None),
        original: Some(ledger.admit_phase(super::super::state_requirements().unwrap()).unwrap()),
    }
}

#[test]
fn frozen_table_consumes_originals_without_re_admission_and_keeps_stable_slots() {
    let ledger = ledger();
    let state = state(&ledger);
    let original = ledger.admit_phase(CaseOwnerTable::<[u8; 32]>::requirements(3).unwrap()).unwrap();
    let before = ledger.snapshot();
    let table = match CaseOwnerTable::<[u8; 32]>::from_original(&state, 3, original) {
        Ok(table) => table, Err(_) => panic!("exact table refused"),
    };
    let address = table.get(0).unwrap() as *const _;
    table.get(0).unwrap().install([7; 32]).unwrap();
    table.get(1).unwrap().install([8; 32]).unwrap();
    table.get(2).unwrap().install([9; 32]).unwrap();
    assert_eq!(address, table.get(0).unwrap() as *const _);
    assert_eq!(table.get(0).unwrap().get().unwrap(), &[7; 32]);
    assert!(table.get(3).is_err());
    assert_eq!(ledger.snapshot().current, before.current);
    assert_eq!(ledger.snapshot().peak, before.peak);
    state.state.set(State::Completed);
    drop(table);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn wrong_table_cardinality_poison_retains_complete_refusal_original() {
    let ledger = ledger();
    let state = state(&ledger);
    let original = ledger.admit_phase(CaseOwnerTable::<u64>::requirements(2).unwrap()).unwrap();
    let before = ledger.snapshot().current;
    let failure = match CaseOwnerTable::<u64>::from_original(&state, 3, original) {
        Err(failure) => failure, Ok(_) => panic!("wrong table original accepted"),
    };
    assert_eq!(failure.retained_slots(), 0);
    assert!(state.state.get() == State::Poisoned);
    assert_eq!(ledger.snapshot().current, before);
    drop(failure);
    assert_eq!(ledger.snapshot().current, before);
}

struct Dropped(Rc<Cell<usize>>);
impl Drop for Dropped { fn drop(&mut self) { self.0.set(self.0.get() + 1); } }

#[test]
fn table_unwind_preserves_actual_payloads_array_and_original_slots() {
    let ledger = ledger();
    let drops = Rc::new(Cell::new(0));
    let before = Cell::new(Bytes::ZERO);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let state = state(&ledger);
        let original = ledger.admit_phase(CaseOwnerTable::<Dropped>::requirements(3).unwrap()).unwrap();
        let table = match CaseOwnerTable::<Dropped>::from_original(&state, 3, original) {
            Ok(table) => table, Err(_) => panic!("exact table refused"),
        };
        table.get(0).unwrap().install(Dropped(drops.clone())).unwrap();
        table.get(1).unwrap().install(Dropped(drops.clone())).unwrap();
        before.set(ledger.snapshot().current);
        panic!("failure after partial plan installation");
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, before.get());
}

#[test]
fn complete_case_destroys_real_table_payloads_and_all_backing() {
    let ledger = ledger();
    let state = state(&ledger);
    let drops = Rc::new(Cell::new(0));
    let original = ledger.admit_phase(CaseOwnerTable::<Dropped>::requirements(3).unwrap()).unwrap();
    let table = match CaseOwnerTable::<Dropped>::from_original(&state, 3, original) {
        Ok(table) => table, Err(_) => panic!("exact table refused"),
    };
    for slot in table.slots() { slot.install(Dropped(drops.clone())).unwrap(); }
    state.state.set(State::Completed);
    drop(table);
    assert_eq!(drops.get(), 3);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn empty_concrete_family_table_still_owns_its_forwarding_frames() {
    let ledger = ledger();
    let state = state(&ledger);
    let requirement = CaseOwnerTable::<u64>::requirements(0).unwrap();
    assert_ne!(requirement.total().unwrap(), Bytes::ZERO);
    let original = ledger.admit_phase(requirement).unwrap();
    let table = match CaseOwnerTable::<u64>::from_original(&state, 0, original) {
        Ok(table) => table, Err(_) => panic!("empty table refused"),
    };
    assert!(table.slots().is_empty());
    state.state.set(State::Completed);
    drop(table);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
#[test]
fn table_shares_transient_frames_but_cannot_issue_an_underfunded_standalone_slot() {
    type Payload = [u8; 4096];
    let one = CaseOwnerTable::<Payload>::requirements(1).unwrap().total().unwrap().host;
    let many = CaseOwnerTable::<Payload>::requirements(64).unwrap().total().unwrap().host;
    // Every actual array element and its independent retained original remain
    // charged. Additional entries do not create simultaneous caller stacks.
    assert_eq!(many - one, (63 * (size_of::<CaseOwnerSlot<'static, Payload>>()
        + size_of::<CaseOwnerSlot<'static, ()>>())) as u64);
    let ledger = ledger();
    let state = state(&ledger);
    let original = ledger.admit_phase(table_slot_requirements::<Payload>().unwrap()).unwrap();
    let before = ledger.snapshot();
    let original = match state.preclaim_from_original::<Payload>(original) {
        Err((_, original)) => original,
        Ok(_) => panic!("shared-frame claim escaped into a standalone slot"),
    };
    assert_eq!(ledger.snapshot().current, before.current);
    assert_eq!(ledger.snapshot().peak, before.peak);
    state.state.set(State::Completed);
    drop(original);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn table_projection_requires_exact_case_and_healthy_state() {
    let ledger = ledger();
    let first = state(&ledger);
    let same_ledger_other_case = state(&ledger);
    let foreign_ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let foreign_case = state(&foreign_ledger);
    let original = ledger.admit_phase(CaseOwnerTable::<u64>::requirements(2).unwrap()).unwrap();
    let table = match CaseOwnerTable::<u64>::from_original(&first, 2, original) {
        Ok(table) => table, Err(_) => panic!("exact table refused"),
    };
    let before = ledger.snapshot();
    assert!(table.belongs_to_case(&first));
    assert!(!table.belongs_to_case(&same_ledger_other_case));
    assert!(!table.belongs_to_case(&foreign_case));
    first.state.set(State::Sealed);
    assert!(table.belongs_to_case(&first));
    for unhealthy in [State::Prepared, State::Completed, State::Finalizing, State::Poisoned] {
        first.state.set(unhealthy);
        assert!(!table.belongs_to_case(&first));
    }
    assert_eq!(ledger.snapshot().current, before.current);
    assert_eq!(ledger.snapshot().peak, before.peak);
    first.state.set(State::Completed);
    same_ledger_other_case.state.set(State::Completed);
    foreign_case.state.set(State::Completed);
    drop(table);
    drop(first);
    drop(same_ledger_other_case);
    drop(foreign_case);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(foreign_ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn table_projection_rejects_partial_backing_and_slot_originals() {
    let ledger = ledger();
    let state = state(&ledger);
    let original = ledger.admit_phase(CaseOwnerTable::<u64>::requirements(2).unwrap()).unwrap();
    let mut table = match CaseOwnerTable::<u64>::from_original(&state, 2, original) {
        Ok(table) => table, Err(_) => panic!("exact table refused"),
    };
    let before = ledger.snapshot();
    let slots = table.slots.take();
    assert!(!table.belongs_to_case(&state));
    table.slots = slots;
    table.slots.as_mut().unwrap()[0].shared_table_frames = false;
    assert!(!table.belongs_to_case(&state));
    table.slots.as_mut().unwrap()[0].shared_table_frames = true;
    let last = table.slots.as_mut().unwrap().pop().unwrap();
    assert!(!table.belongs_to_case(&state));
    table.slots.as_mut().unwrap().push(last);
    let backing = table.backing.take();
    assert!(!table.belongs_to_case(&state));
    table.backing = backing;
    let remainder = table.unissued.take();
    assert!(!table.belongs_to_case(&state));
    table.unissued = remainder;
    let slot_original = table.slots.as_mut().unwrap()[0].original.take();
    assert!(!table.belongs_to_case(&state));
    table.slots.as_mut().unwrap()[0].original = slot_original;
    let byte = Requirements::single(Category::RegisteredMetadata, Bytes { host: 1, device: 0 });
    let detached = table.backing.as_mut().unwrap().split(byte).unwrap();
    assert!(!table.belongs_to_case(&state));
    let backing = table.backing.take().unwrap();
    table.backing = Some(match backing.reunite(detached) {
        Ok(original) => original, Err(_) => panic!("same backing originals did not reunite"),
    });
    let detached = table.slots.as_mut().unwrap()[0].original.as_mut().unwrap().split(byte).unwrap();
    assert!(!table.belongs_to_case(&state));
    let slot_original = table.slots.as_mut().unwrap()[0].original.take().unwrap();
    table.slots.as_mut().unwrap()[0].original = Some(match slot_original.reunite(detached) {
        Ok(original) => original, Err(_) => panic!("same slot originals did not reunite"),
    });
    assert!(table.belongs_to_case(&state));
    assert_eq!(ledger.snapshot().current, before.current);
    assert_eq!(ledger.snapshot().peak, before.peak);
    state.state.set(State::Completed);
    drop(table);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn table_projection_checks_each_slots_state_and_zero_remainder_ledger() {
    let ledger = ledger();
    let first = state(&ledger);
    let same_ledger_other_case = state(&ledger);
    let foreign_ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let original = ledger.admit_phase(CaseOwnerTable::<u64>::requirements(1).unwrap()).unwrap();
    let mut table = match CaseOwnerTable::<u64>::from_original(&first, 1, original) {
        Ok(table) => table, Err(_) => panic!("exact table refused"),
    };
    table.slots.as_mut().unwrap()[0].state = &same_ledger_other_case;
    assert!(!table.belongs_to_case(&first));
    table.slots.as_mut().unwrap()[0].state = &first;
    let foreign_zero = foreign_ledger.admit_phase(Requirements::default()).unwrap();
    let own_zero = table.unissued.replace(foreign_zero).unwrap();
    assert!(!table.belongs_to_case(&first));
    let foreign_zero = table.unissued.replace(own_zero).unwrap();
    drop(foreign_zero);
    assert!(table.belongs_to_case(&first));
    first.state.set(State::Completed);
    same_ledger_other_case.state.set(State::Completed);
    drop(table);
    drop(first);
    drop(same_ledger_other_case);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(foreign_ledger.snapshot().current, Bytes::ZERO);
}
