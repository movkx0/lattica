//! These adapters have no process; real shutdown receipts remain mandatory.
use super::*;

#[test]
fn insufficient_service_window_closes_without_issuing_an_attempt() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    state.borrow_mut().dispatch_deadline_ms = Some(50);
    assert!(pool.step(1).unwrap().is_empty());
    assert!(pool.idle() && pool.workers_closed());
    assert_eq!(state.borrow().dispatches, 0);
    assert_eq!(state.borrow().closed, 1);
    assert!(state.borrow().contexts.is_empty());
    assert_eq!(pool.owner.resource_use().unwrap(), Resources::default());
    assert!(!pool.owner.ready().unwrap().is_empty());
}

#[test]
fn exhausted_window_cannot_forge_a_successful_shutdown() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    state.borrow_mut().dispatch_deadline_ms = Some(50);
    state.borrow_mut().fail_close = true;
    assert!(pool
        .step(1)
        .err()
        .unwrap()
        .to_string()
        .contains("physical shutdown"));
    assert!(!pool.workers_closed());
    assert_eq!(state.borrow().dispatches, 0);
    assert_eq!(state.borrow().closed, 0);
    state.borrow_mut().fail_close = false;
    assert!(pool.step(2).unwrap().is_empty());
    assert!(pool.workers_closed());
    assert_eq!(state.borrow().closed, 1);
}

#[test]
fn impossible_candidate_deadline_is_not_misreported_as_service_retirement() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = pool.submit(&selection, context, [3; 32], 50, 0).unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    state.borrow_mut().dispatch_deadline_ms = Some(10_000);
    assert!(pool
        .step(1)
        .err()
        .unwrap()
        .to_string()
        .contains("no deadline-admissible placement"));
    assert!(!pool.workers_closed());
    assert_eq!(state.borrow().closed, 0);
    assert_eq!(state.borrow().dispatches, 0);
    pool.close(2).unwrap();
}

#[test]
fn context_negotiation_cannot_consume_the_window_then_issue_a_lease() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    state.borrow_mut().dispatch_deadline_ms = Some(10_000);
    state.borrow_mut().shrink_window_on_context = true;
    assert!(pool.step(1).unwrap().is_empty());
    assert!(pool.workers_closed());
    assert_eq!(state.borrow().contexts.len(), 1);
    assert_eq!(state.borrow().dispatches, 0);
    assert_eq!(state.borrow().closed, 1);
    assert_eq!(pool.owner.resource_use().unwrap(), Resources::default());
}

#[test]
fn another_worker_dispatches_and_idle_expiry_closes_while_it_is_active() {
    let temp = Temp::new();
    let (mut pool, selection, context, first) = fixture(&temp);
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 0)
        .unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    let second = Rc::new(RefCell::new(Observed::default()));
    let mut cap = pool.slots[0].endpoint.capabilities();
    cap.worker = WorkerId(3);
    pool.slots.push(Slot {
        endpoint: Box::new(SimulatedEndpoint {
            cap,
            state: second.clone(),
        }),
        active: None,
        closed: false,
    });
    first.borrow_mut().dispatch_deadline_ms = Some(50);
    pool.step(1).unwrap();
    assert_eq!(first.borrow().dispatches, 0);
    assert_eq!(second.borrow().dispatches, 1);
    assert!(!pool.idle());
    pool.step(50).unwrap();
    assert_eq!(first.borrow().closed, 1);
    assert_eq!(second.borrow().closed, 0);
    assert!(!pool.workers_closed());
    pool.retire(candidate, 100).unwrap();
    pool.close(101).unwrap();
    assert!(pool.workers_closed());
}
