//! Structural transition tests; simulated tickets do not prove GPU validity.
use super::*;
use crate::block_v2::execution::job::test_support::node;
use crate::block_v2::typed_recursive::Policy;

fn selection(pool: &PoolCoordinator, values: &[u8]) -> (Selection, PolicyContext) {
    let registry = pool.registry.as_registry();
    let pin = RegistryPin::new_typed(registry, registry.id().unwrap()).unwrap();
    let inputs = values.iter().map(|value| {
        PublicInput::new(typed_wallet_for(pin, u64::from(*value), 1, &[*value]), vec![*value]).unwrap()
    }).collect::<Vec<_>>();
    let policies = values.iter().map(|value| {
        (typed_wallet_for(pin, u64::from(*value), 1, &[*value]).artifact(), Policy::JoinSplit)
    }).collect();
    (Selection::new(pin, [9; 32], &inputs).unwrap(), PolicyContext::new([42; 32], policies).unwrap())
}

fn cache_prefix(pool: &mut PoolCoordinator, selection: &Selection) {
    for job in selection.jobs().filter(|job| job.is_complete_non_root_subtree()) {
        let bytes = job.id().to_bytes().to_vec();
        pool.owner.cache_node(node(job, &bytes), bytes, 1).unwrap();
    }
}

#[test]
fn extension_keeps_one_candidate_clock_verified_bytes_and_live_worker() {
    for (before, after) in [(2, 4), (3, 4), (4, 4), (6, 8)] {
        let temp = Temp::new();
        let (mut pool, _, _, worker) = fixture(&temp);
        let (prefix, context) = selection(&pool, &(1..=before).collect::<Vec<_>>());
        let candidate = pool.submit_prefix(&prefix, context, [3; 32], 1000, 0).unwrap();
        cache_prefix(&mut pool, &prefix);
        let retained = prefix.jobs().filter(|job| job.is_complete_non_root_subtree()).map(|job| {
            (job.id(), pool.owner.verified_node_bytes(job.id()).unwrap().unwrap().as_ptr())
        }).collect::<Vec<_>>();
        let (final_selection, policies) = selection(&pool, &(1..=after).collect::<Vec<_>>());
        pool.seal_prefix_extension(candidate, &final_selection, policies, [3; 32], 2).unwrap();
        assert_eq!(pool.candidates.len(), 1);
        assert!(!pool.candidates[&candidate].prefix_only);
        assert_eq!(pool.candidates[&candidate].deadline_ms, 1000);
        assert_eq!(pool.owner.sealed_candidate_binding(candidate, [3; 32], 3).unwrap(), (final_selection.root().id(), 1000));
        for (job, pointer) in retained {
            assert_eq!(pool.owner.verified_node_bytes(job).unwrap().unwrap().as_ptr(), pointer);
            assert_eq!(pool.status(job).unwrap(), JobStatus::Completed);
        }
        assert!(pool.prefix_node(candidate, prefix.root().id(), [3; 32], 3).is_err());
        assert!(pool.root(candidate, [3; 32], 3).unwrap().is_none());
        assert!(pool.seal_prefix_extension(candidate, &final_selection, policies, [3; 32], 3).is_err());
        pool.step(4).unwrap();
        assert_eq!(worker.borrow().closed, 0);
        assert_eq!(worker.borrow().dispatches, 1);
        assert!(pool.owner.ready().unwrap().iter().all(|job| *job != prefix.root().id() || before == after));
        pool.retire(candidate, 5).unwrap();
        assert_eq!(worker.borrow().cancelled, 1);
        pool.close(6).unwrap();
        assert!(pool.workers_closed());
        assert_eq!(worker.borrow().closed, 0); // cancellation already stopped it
    }
}

#[test]
fn transition_rejects_head_policy_scope_deadline_and_worker_state_changes() {
    for invalid in ["head", "context", "policy", "expired", "cancelled", "sealed", "partial", "active", "closed"] {
        let temp = Temp::new();
        let (mut pool, _, _, _) = fixture(&temp);
        let (prefix, context) = selection(&pool, &[1, 2]);
        let candidate = pool.submit_prefix(&prefix, context, [3; 32], 1000, 0).unwrap();
        if !matches!(invalid, "partial" | "active") { cache_prefix(&mut pool, &prefix); }
        if invalid == "active" { pool.step(1).unwrap(); }
        if invalid == "closed" { pool.close(1).unwrap(); }
        if invalid == "cancelled" { pool.owner.cancel(candidate, 1).unwrap(); }
        if invalid == "sealed" { pool.owner.seal(candidate, [3; 32], 1).unwrap(); }
        let (next, mut policies) = selection(&pool, &[1, 2, 3, 4]);
        if matches!(invalid, "context" | "policy") {
            let entries = next.jobs().flat_map(|job| job.wallet_inputs()).copied().map(|artifact| {
                (artifact, if invalid == "policy" { Policy::Issuance { authorized_mint: 1 } } else { Policy::JoinSplit })
            }).collect();
            policies = PolicyContext::new(if invalid == "context" { [43; 32] } else { [42; 32] }, entries).unwrap();
        }
        let result = pool.seal_prefix_extension(candidate, &next, policies,
            if invalid == "head" { [4; 32] } else { [3; 32] }, if invalid == "expired" { 1000 } else { 2 });
        assert!(result.is_err(), "{invalid}");
        assert!(pool.candidates[&candidate].prefix_only);
        assert_eq!(pool.candidates[&candidate].deadline_ms, 1000);
        if invalid == "active" { pool.retire(candidate, 3).unwrap(); }
        pool.close(if invalid == "expired" { 1001 } else { 3 }).unwrap();
    }
}

#[test]
fn transition_rejects_reordering_shrinkage_and_substitution_of_an_unproved_odd_wallet() {
    for values in [&[2, 1, 3, 4][..], &[1, 2][..], &[1, 2, 9, 4][..]] {
        let temp = Temp::new();
        let (mut pool, _, _, worker) = fixture(&temp);
        let (prefix, context) = selection(&pool, &[1, 2, 3]);
        let candidate = pool.submit_prefix(&prefix, context, [3; 32], 1000, 0).unwrap();
        cache_prefix(&mut pool, &prefix);
        let (next, policies) = selection(&pool, values);
        assert!(pool.seal_prefix_extension(candidate, &next, policies, [3; 32], 2).is_err());
        assert_eq!(pool.owner.unsealed_candidate_binding(candidate, [3; 32], 3).unwrap(), (prefix.root().id(), 1000));
        assert_eq!(worker.borrow().dispatches, 0);
        pool.close(4).unwrap();
    }
}

#[test]
fn additional_host_horizon_cannot_dispatch_or_renew_the_durable_deadline() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let candidate = pool.submit(&selection, context, [3; 32], 10_000, 0).unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    assert!(pool.step_before(1, 50).is_err());
    assert_eq!(state.borrow().dispatches, 0);
    assert!(pool.idle());
    assert_eq!(pool.owner.sealed_candidate_binding(candidate, [3; 32], 2).unwrap().1, 10_000);
    assert!(pool.step_before(50, 50).is_err());
    pool.close(51).unwrap();
}
