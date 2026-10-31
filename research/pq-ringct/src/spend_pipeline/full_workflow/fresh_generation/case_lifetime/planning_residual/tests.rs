use super::*;
use crate::execution::{retained_resources::WorkerAllowance,
    workflow_resources::GuardedPlanningOriginal};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: 1 << 20, device: 0 }) }
fn bytes(host: u64) -> Bytes { Bytes { host, device: 0 } }
fn required(host: u64) -> Requirements { Requirements::single(Category::RegisteredMetadata, bytes(host)) }
// These private fixtures exercise reservation/destructor mechanics only.
// Direct state transitions never issue a production completion/cleanup receipt.
fn state(ledger: &Ledger) -> CaseRetirementState {
    CaseRetirementState {
        state: Cell::new(State::Armed), ledger: ledger.clone(), generation_session: 7,
        transactions: 3, batch_identity: Cell::new(ledger as *const _ as *const ()),
        sealed_plan: Cell::new(core::ptr::null()), sealed_context: Cell::new(core::ptr::null()),
        sealed_source: Cell::new(([0; 32], [0; 32])),
        batch_original: RefCell::new(None), planning_original: RefCell::new(None),
        planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None),
        original: Some(ledger.admit_phase(state_requirements().unwrap()).unwrap()),
    }
}

struct CallerFrame<'a> { ledger: &'a Ledger, expected: Bytes, dropped: &'a Cell<bool> }
impl Drop for CallerFrame<'_> {
    fn drop(&mut self) {
        assert_eq!(self.ledger.snapshot().current, self.expected);
        self.dropped.set(true);
    }
}

#[test]
fn residual_outlives_inner_success_and_late_caller_frames() {
    let ledger = ledger();
    let state = state(&ledger);
    let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
    guard.pin_case(&state).unwrap();
    let dropped = Cell::new(false);
    let before = ledger.snapshot().current;
    {
        let _caller = CallerFrame { ledger: &ledger, expected: before, dropped: &dropped };
        let moved = Some(guard);
        // Destructor mechanics only; no production completion receipt is forged.
        drop(moved);
        state.state.set(State::Completed);
        assert_eq!(ledger.snapshot().current, before);
    }
    assert!(dropped.get());
    assert!(state.planning_residual_issued.get());
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn small_split_drops_independently_without_releasing_the_residual() {
    let ledger = ledger();
    let state = state(&ledger);
    let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
    guard.pin_case(&state).unwrap();
    let small = guard.split(required(128)).unwrap();
    assert_eq!(small.requirements(), required(128));
    assert_eq!(guard.requirements(), required(3968));
    let before = ledger.snapshot().current;
    drop(guard);
    assert_eq!(ledger.snapshot().current, before);
    drop(small);
    assert_eq!(ledger.snapshot().current, bytes(before.host - 128));
    state.state.set(State::Completed);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

fn inner_error(guard: GuardedPlanningOriginal<'_>) -> core::result::Result<(), ()> {
    let moved = Some(guard);
    drop(moved);
    Err(())
}

#[test]
fn moved_planning_error_keeps_original_through_outer_failure_teardown() {
    let ledger = ledger();
    let state = state(&ledger);
    let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
    guard.pin_case(&state).unwrap();
    let before = ledger.snapshot().current;
    let dropped = Cell::new(false);
    {
        let _caller = CallerFrame { ledger: &ledger, expected: before, dropped: &dropped };
        assert!(inner_error(guard).is_err());
    }
    assert!(dropped.get());
    drop(state);
    assert_eq!(ledger.snapshot().current, before);
}

#[test]
fn moved_admission_unwind_keeps_original_before_outer_frame_destructors() {
    let ledger = ledger();
    let before = Cell::new(Bytes::ZERO);
    let dropped = Cell::new(false);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let state = state(&ledger);
        let original = ledger.admit_phase(required(4096)).unwrap();
        before.set(ledger.snapshot().current);
        let _caller = CallerFrame { ledger: &ledger, expected: before.get(), dropped: &dropped };
        let mut guard = GuardedPlanningOriginal::new(original);
        guard.pin_case(&state).unwrap();
        let _inner = Some(guard);
        panic!("injected nested caller unwind");
    }));
    assert!(result.is_err());
    assert!(dropped.get());
    assert_eq!(ledger.snapshot().current, before.get());
}

#[test]
fn bootstrap_replacement_preserves_the_pin_and_exact_new_original() {
    let ledger = ledger();
    let state = state(&ledger);
    let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(256)).unwrap());
    guard.pin_case(&state).unwrap();
    drop(guard.split(required(256)).unwrap());
    let replacement = ledger.admit_phase(required(8192)).unwrap();
    let before = ledger.snapshot().current;
    guard.replace_depleted(replacement, &ledger).unwrap();
    assert!(guard.is_pinned_to(&state));
    assert_eq!(guard.requirements(), required(8192));
    assert_eq!(ledger.snapshot().current, before);
    // A refused split leaves the exact newly installed residual in the guard.
    assert!(guard.split(required(8193)).is_err());
    drop(guard);
    assert_eq!(ledger.snapshot().current, before);
    state.state.set(State::Completed);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn pin_refuses_foreign_ledger_duplicate_case_and_rebinding_without_moving_claims() {
    let ledger = ledger();
    let other_ledger = self::ledger();
    let state = state(&ledger);
    let mut first = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
    let mut second = GuardedPlanningOriginal::new(ledger.admit_phase(required(2048)).unwrap());
    let mut foreign = GuardedPlanningOriginal::new(other_ledger.admit_phase(required(1024)).unwrap());
    let before = ledger.snapshot().current;
    let other_before = other_ledger.snapshot().current;
    assert!(foreign.pin_case(&state).is_err());
    assert!(!state.planning_residual_issued.get());
    first.pin_case(&state).unwrap();
    assert!(first.pin_case(&state).is_err());
    assert!(second.pin_case(&state).is_err());
    assert_eq!(ledger.snapshot().current, before);
    assert_eq!(other_ledger.snapshot().current, other_before);
    drop(second);
    drop(foreign);
    drop(first);
    state.state.set(State::Completed);
    drop(state);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(other_ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn nonempty_or_foreign_replacement_quarantines_every_exact_claim() {
    for foreign in [false, true] {
        let ledger = ledger();
        let other_ledger = self::ledger();
        let state = state(&ledger);
        let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
        guard.pin_case(&state).unwrap();
        if foreign { drop(guard.split(required(4096)).unwrap()); }
        let replacement_ledger = if foreign { &other_ledger } else { &ledger };
        let replacement = replacement_ledger.admit_phase(required(2048)).unwrap();
        let before = ledger.snapshot().current;
        let other_before = other_ledger.snapshot().current;
        assert!(guard.replace_depleted(replacement, &ledger).is_err());
        assert!(state.state.get() == State::Poisoned);
        assert!(guard.is_pinned_to(&state));
        drop(guard);
        drop(state);
        assert_eq!(ledger.snapshot().current, before);
        assert_eq!(other_ledger.snapshot().current, other_before);
    }
}

#[test]
fn residual_collision_or_foreign_transfer_cannot_release_backing() {
    for foreign in [false, true] {
        let ledger = ledger();
        let other_ledger = self::ledger();
        let state = state(&ledger);
        let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
        guard.pin_case(&state).unwrap();
        drop(guard);
        let incoming_ledger = if foreign { &other_ledger } else { &ledger };
        let incoming = incoming_ledger.admit_phase(required(2048)).unwrap();
        let before = ledger.snapshot().current;
        let other_before = other_ledger.snapshot().current;
        state.retain_planning_residual(incoming);
        assert!(state.state.get() == State::Poisoned);
        drop(state);
        assert_eq!(ledger.snapshot().current, before);
        assert_eq!(other_ledger.snapshot().current, other_before);
    }
}

#[test]
fn late_context_cleanup_failure_keeps_already_deposited_residual() {
    let ledger = ledger();
    let state = state(&ledger);
    let mut guard = GuardedPlanningOriginal::new(ledger.admit_phase(required(4096)).unwrap());
    guard.pin_case(&state).unwrap();
    let before = ledger.snapshot().current;
    drop(guard);
    state.state.set(State::Finalizing);
    state.poison_planning_residual();
    drop(state);
    assert_eq!(ledger.snapshot().current, before);
}
