use super::*;
use super::super::{Bytes, Category, Requirements, slot_requirements, state_requirements};
use crate::execution::retained_resources::{Ledger, WorkerAllowance};
use std::{cell::{Cell, RefCell}, panic::{catch_unwind, AssertUnwindSafe}, rc::Rc};

fn state(ledger: &Ledger, transactions: usize) -> CaseRetirementState {
    CaseRetirementState {
        state: Cell::new(State::Armed), ledger: ledger.clone(), generation_session: 7,
        transactions, batch_identity: Cell::new(core::ptr::null()),
        sealed_plan: Cell::new(core::ptr::null()), sealed_context: Cell::new(core::ptr::null()),
        sealed_source: Cell::new(([0; 32], [0; 32])), batch_original: RefCell::new(None),
        planning_original: RefCell::new(None),
        planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None),
        original: Some(ledger.admit_phase(state_requirements().unwrap()).unwrap()),
    }
}

struct Dropped(Rc<Cell<usize>>);
impl Drop for Dropped {
    fn drop(&mut self) { self.0.set(self.0.get() + 1); }
}

#[test]
fn fixed_bootstrap_owns_all_values_and_releases_only_after_completion() {
    let ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let state = state(&ledger, 3);
    let drops = Rc::new(Cell::new(0));
    let table = state.preclaim_n3::<core::result::Result<Dropped, Dropped>>().unwrap();
    let before = ledger.snapshot();
    let slots = table.get().unwrap();
    slots.get(0).unwrap().install(Ok(Dropped(drops.clone()))).unwrap();
    slots.get(1).unwrap().install(Err(Dropped(drops.clone()))).unwrap();
    slots.get(2).unwrap().install(Ok(Dropped(drops.clone()))).unwrap();
    assert!(slots.get(3).is_err());
    assert_eq!(ledger.snapshot().current, before.current);
    state.state.set(State::Completed);
    drop(table);
    assert_eq!(drops.get(), 3);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn fixed_bootstrap_unwind_retains_payloads_and_originals() {
    let ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let state = state(&ledger, 4);
    let drops = Rc::new(Cell::new(0));
    let retained = Cell::new(Bytes::ZERO);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let table = state.preclaim_n4::<Dropped>().unwrap();
        table.get().unwrap().get(0).unwrap().install(Dropped(drops.clone())).unwrap();
        retained.set(ledger.snapshot().current);
        panic!("bootstrap caller failed");
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 0);
    assert_eq!(ledger.snapshot().current, retained.get());
}

#[test]
fn fixed_bootstrap_partial_admission_is_retained_and_poisoned() {
    let ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let state = state(&ledger, 3);
    let outer = slot_requirements::<FixedCaseOwnerSlots<'_, u64, 3>>().unwrap().total().unwrap().host;
    let element = slot_requirements::<u64>().unwrap().total().unwrap().host;
    let initial = ledger.snapshot().current.host;
    let hold = ledger.admit_phase(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: (1 << 20) - initial - outer - element, device: 0,
    })).unwrap();
    assert!(state.preclaim_n3::<u64>().is_err());
    assert!(state.state.get() == State::Poisoned);
    assert_eq!(ledger.snapshot().current.host, 1 << 20);
    drop(hold);
    assert_eq!(ledger.snapshot().current.host, initial + outer + element);
}

#[test]
fn fixed_bootstrap_refuses_wrong_case_and_closed_state_before_claiming() {
    let ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let state = state(&ledger, 3);
    let before = ledger.snapshot();
    assert!(state.preclaim_n4::<u64>().is_err());
    assert_eq!(ledger.snapshot().current, before.current);
    state.state.set(State::Sealed);
    assert!(state.preclaim_n3::<u64>().is_err());
    assert_eq!(ledger.snapshot().current, before.current);
    state.state.set(State::Completed);
}

#[test]
fn fixed_bootstrap_refuses_same_ledger_distinct_case_before_populating() {
    let ledger = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let first = state(&ledger, 3);
    let second = state(&ledger, 3);
    let table = first.preclaim_n3::<u64>().unwrap();
    let before = ledger.snapshot();
    let slots = table.get().unwrap();
    assert!(slots.check_case(&first).is_ok());
    assert!(slots.check_case(&second).is_err());
    for ordinal in 0..3 { assert!(slots.get(ordinal).unwrap().get().is_err()); }
    assert_eq!(ledger.snapshot().current, before.current);
    assert_eq!(ledger.snapshot().peak, before.peak);
    first.state.set(State::Completed);
    second.state.set(State::Completed);
    drop(table);
    drop(first);
    drop(second);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn fixed_bootstrap_refuses_foreign_ledger_case_before_populating() {
    let own = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let foreign = Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 });
    let first = state(&own, 4);
    let second = state(&foreign, 4);
    let table = first.preclaim_n4::<u64>().unwrap();
    let before = own.snapshot();
    let foreign_before = foreign.snapshot();
    let slots = table.get().unwrap();
    assert!(slots.check_case(&first).is_ok());
    assert!(slots.check_case(&second).is_err());
    for ordinal in 0..4 { assert!(slots.get(ordinal).unwrap().get().is_err()); }
    assert_eq!(own.snapshot().current, before.current);
    assert_eq!(foreign.snapshot().current, foreign_before.current);
    first.state.set(State::Completed);
    second.state.set(State::Completed);
    drop(table);
    drop(first);
    drop(second);
    assert_eq!(own.snapshot().current, Bytes::ZERO);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
}
