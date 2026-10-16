//! Adoption must preserve the durable sealed selection and its deadline.
use super::*;

fn sealed(pool: &mut PoolCoordinator, selection: &Selection, deadline: u64) -> CandidateId {
    let candidate = selection
        .attach(&mut pool.owner, [3; 32], deadline, 0)
        .unwrap();
    pool.owner.seal(candidate, [3; 32], 0).unwrap();
    candidate
}

#[test]
fn adoption_preserves_candidate_and_deadline_and_dispatches_bound_context() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = sealed(&mut pool, &selection, 10_000);
    pool.adopt_sealed(&selection, context.clone(), candidate, [3; 32], 1)
        .unwrap();
    assert_eq!(pool.candidates.len(), 1);
    assert_eq!(pool.candidates[&candidate].deadline_ms, 10_000);
    assert_eq!(pool.jobs.len(), selection.jobs().len());
    assert!(pool
        .adopt_sealed(&selection, context, candidate, [3; 32], 2)
        .is_err());
    assert_eq!(pool.candidates.len(), 1);
    pool.step(3).unwrap();
    assert_eq!(state.borrow().dispatches, 1);
    assert_eq!(state.borrow().contexts, vec![[42; 32]]);
    pool.retire(candidate, 4).unwrap();
    pool.close(5).unwrap();
}

#[test]
fn adoption_requires_current_eligibility_and_complete_wallet_policy() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = sealed(&mut pool, &selection, 10_000);
    let missing = PolicyContext::new([42; 32], vec![]).unwrap();
    assert!(pool
        .adopt_sealed(&selection, missing, candidate, [3; 32], 1)
        .is_err());
    assert!(pool
        .adopt_sealed(&selection, context.clone(), candidate, [4; 32], 2)
        .is_err());
    assert!(pool.candidates.is_empty() && pool.jobs.is_empty());
    assert_eq!(state.borrow().dispatches, 0);
    pool.adopt_sealed(&selection, context, candidate, [3; 32], 3)
        .unwrap();
    pool.close(4).unwrap();
}

#[test]
fn adoption_rejects_another_selection_even_with_valid_policies() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = sealed(&mut pool, &selection, 10_000);
    let pin = selection.root().pin();
    let other = typed_wallet_for(pin, 2, 1, &[2]);
    let other_context = PolicyContext::new(
        [42; 32],
        vec![(
            other.artifact(),
            crate::block_v2::typed_recursive::Policy::JoinSplit,
        )],
    )
    .unwrap();
    let other_selection =
        Selection::new(pin, [9; 32], &[PublicInput::new(other, vec![2]).unwrap()]).unwrap();
    assert_ne!(selection.root().id(), other_selection.root().id());
    let error = pool
        .adopt_sealed(&other_selection, other_context, candidate, [3; 32], 1)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "pool sealed candidate selection mismatch"
    );
    assert!(pool.candidates.is_empty() && pool.jobs.is_empty());
    assert_eq!(state.borrow().dispatches, 0);
    pool.adopt_sealed(&selection, context, candidate, [3; 32], 2)
        .unwrap();
    pool.close(3).unwrap();
}

#[test]
fn adoption_rejects_unsealed_cancelled_and_expired_candidates() {
    for state in ["unsealed", "cancelled", "expired"] {
        let temp = Temp::new();
        let (mut pool, selection, context, worker) = fixture(&temp);
        let candidate = selection.attach(&mut pool.owner, [3; 32], 100, 0).unwrap();
        if state != "unsealed" {
            pool.owner.seal(candidate, [3; 32], 0).unwrap();
        }
        if state == "cancelled" {
            pool.owner.cancel(candidate, 1).unwrap();
        }
        let now = if state == "expired" { 100 } else { 2 };
        assert!(
            pool.adopt_sealed(&selection, context, candidate, [3; 32], now)
                .is_err(),
            "{state}"
        );
        assert!(pool.candidates.is_empty() && pool.jobs.is_empty());
        assert_eq!(worker.borrow().dispatches, 0);
        pool.close(now + 1).unwrap();
    }
}
