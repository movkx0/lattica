//! Structural fixtures test scheduling authority, not proof validity.
use super::*;
use crate::block_v2::execution::job::test_support::node;

fn prefix_selection(pool: &PoolCoordinator, count: u8) -> (Selection, PolicyContext) {
    let registry = pool.registry.as_registry();
    let pin = RegistryPin::new_typed(registry, registry.id().unwrap()).unwrap();
    let inputs: Vec<_> = (1..=count)
        .map(|value| {
            let proof = vec![value];
            PublicInput::new(typed_wallet_for(pin, value.into(), 1, &proof), proof).unwrap()
        })
        .collect();
    let policies = (1..=count)
        .map(|value| {
            (
                typed_wallet_for(pin, value.into(), 1, &[value]).artifact(),
                crate::block_v2::typed_recursive::Policy::JoinSplit,
            )
        })
        .collect();
    (
        Selection::new(pin, [9; 32], &inputs).unwrap(),
        PolicyContext::new([42; 32], policies).unwrap(),
    )
}

#[test]
fn empty_prefix_work_is_rejected_before_durable_admission() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let before: Vec<_> = std::fs::read_dir(temp.0.join("journal"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let contents = std::fs::read(&path).unwrap();
            (path, contents)
        })
        .collect();
    assert!(pool
        .submit_prefix(&selection, context, [3; 32], 10_000, 0)
        .is_err());
    assert!(pool.candidates.is_empty() && pool.jobs.is_empty());
    assert!(pool.owner.ready().unwrap().is_empty());
    for (path, contents) in before {
        assert_eq!(std::fs::read(path).unwrap(), contents);
    }
    assert_eq!(state.borrow().dispatches, 0);
    pool.close(1).unwrap();
}

#[test]
fn only_complete_subtrees_dispatch_and_no_padding_or_root_is_exported() {
    for (count, proofs) in [(2, 1), (4, 3), (6, 4)] {
        let temp = Temp::new();
        let (mut pool, _, _, state) = fixture(&temp);
        let (selection, context) = prefix_selection(&pool, count);
        let candidate = pool
            .submit_prefix(&selection, context, [3; 32], 10_000, 0)
            .unwrap();
        assert_eq!(pool.jobs.len(), proofs);
        assert!(pool.seal(candidate, [3; 32], 1).is_err());
        assert!(pool.root(candidate, [3; 32], 2).is_err());
        assert!(!pool
            .visit_complete_prefix(candidate, [3; 32], 2, |_, _| panic!(
                "partial prefix exported"
            ))
            .unwrap());
        let mut now = 3;
        while pool
            .jobs
            .keys()
            .any(|job| pool.status(*job).unwrap() != JobStatus::Completed)
        {
            pool.step(now).unwrap();
            let lease = state.borrow().last_lease.unwrap();
            let job = pool.jobs[&lease.job()].clone();
            assert!(job.is_complete_non_root_subtree());
            let proof = job.id().to_bytes().to_vec();
            // Only the structural test bypasses proof verification; production
            // results enter through PoolCoordinator::step's CPU verifier.
            pool.owner.worker_stopped(lease, now + 1).unwrap();
            pool.owner.begin_verification(lease, now + 2).unwrap();
            assert_eq!(
                pool.owner
                    .finish_verification(lease, Some((node(&job, &proof), proof.clone())), now + 3)
                    .unwrap(),
                Completion::Accepted
            );
            pool.slots[0].active = None;
            assert_eq!(
                pool.prefix_node(candidate, job.id(), [3; 32], now + 4)
                    .unwrap(),
                Some(proof.as_slice())
            );
            now += 5;
        }
        pool.step(now).unwrap();
        assert_eq!(state.borrow().dispatches, proofs);
        let mut exported = 0;
        assert!(pool
            .visit_complete_prefix(candidate, [3; 32], now, |job, proof| {
                assert!(job.is_complete_non_root_subtree());
                assert_eq!(proof, job.id().to_bytes());
                exported += 1;
                Ok(())
            })
            .unwrap());
        assert_eq!(exported, proofs);
        assert!(pool
            .prefix_node(candidate, selection.root().id(), [3; 32], now + 1)
            .is_err());
        assert_eq!(
            pool.owner
                .unsealed_candidate_binding(candidate, [3; 32], now + 2)
                .unwrap(),
            (selection.root().id(), 10_000)
        );
        pool.close(now + 3).unwrap();
    }
}

#[test]
fn prefix_access_rechecks_head_scope_membership_cancellation_and_deadline() {
    for invalid in ["head", "normal_scope", "membership", "cancelled", "expired"] {
        let temp = Temp::new();
        let (mut pool, _, _, state) = fixture(&temp);
        let (selection, context) = prefix_selection(&pool, 2);
        let job = selection
            .jobs()
            .find(|job| job.is_complete_non_root_subtree())
            .unwrap();
        let candidate = if invalid == "normal_scope" {
            pool.submit(&selection, context, [3; 32], 100, 0).unwrap()
        } else {
            pool.submit_prefix(&selection, context, [3; 32], 100, 0)
                .unwrap()
        };
        pool.owner.cache_node(node(job, &[9]), vec![9], 1).unwrap();
        if invalid == "cancelled" {
            pool.owner.cancel(candidate, 2).unwrap();
        }
        let head = if invalid == "head" { [4; 32] } else { [3; 32] };
        let requested = if invalid == "membership" {
            selection.root().id()
        } else {
            job.id()
        };
        let now = if invalid == "expired" { 100 } else { 3 };
        assert!(
            pool.prefix_node(candidate, requested, head, now).is_err(),
            "{invalid}"
        );
        if invalid != "membership" {
            assert!(pool
                .visit_complete_prefix(candidate, head, now, |_, _| panic!(
                    "invalid scope exported"
                ))
                .is_err());
        }
        assert_eq!(state.borrow().dispatches, 0);
        pool.close(now + 1).unwrap();
    }
}

#[test]
fn prefix_adoption_requires_exact_unsealed_selection_and_original_deadline() {
    for invalid in [
        "sealed",
        "cancelled",
        "expired",
        "head",
        "selection",
        "policy",
        "valid",
    ] {
        let temp = Temp::new();
        let (mut pool, _, _, state) = fixture(&temp);
        let (selection, context) = prefix_selection(&pool, 2);
        let candidate = selection
            .attach(&mut pool.owner, [3; 32], 10_000, 0)
            .unwrap();
        if invalid == "sealed" {
            pool.owner.seal(candidate, [3; 32], 1).unwrap();
        }
        if invalid == "cancelled" {
            pool.owner.cancel(candidate, 1).unwrap();
        }
        let (selection, context) = if invalid == "selection" {
            prefix_selection(&pool, 4)
        } else {
            (selection, context)
        };
        let context = if invalid == "policy" {
            PolicyContext::new([42; 32], vec![]).unwrap()
        } else {
            context
        };
        let head = if invalid == "head" { [4; 32] } else { [3; 32] };
        let now = if invalid == "expired" { 10_000 } else { 2 };
        let outcome = pool.adopt_prefix(&selection, context.clone(), candidate, head, now);
        if invalid == "valid" {
            outcome.unwrap();
            assert_eq!(pool.candidates[&candidate].deadline_ms, 10_000);
            assert!(pool
                .adopt_prefix(&selection, context, candidate, head, now + 1)
                .is_err());
            pool.step(now + 2).unwrap();
            assert_eq!(state.borrow().dispatches, 1);
            assert_eq!(state.borrow().contexts, vec![[42; 32]]);
            pool.retire(candidate, now + 3).unwrap();
        } else {
            assert!(outcome.is_err(), "{invalid}");
            assert!(pool.candidates.is_empty() && pool.jobs.is_empty());
            assert_eq!(state.borrow().dispatches, 0);
        }
        pool.close(now + 4).unwrap();
    }
}

#[test]
fn sealed_selection_can_share_verified_prefix_without_authorizing_prefix_root() {
    let temp = Temp::new();
    let (mut pool, _, _, state) = fixture(&temp);
    let (selection, context) = prefix_selection(&pool, 2);
    let prefix = pool
        .submit_prefix(&selection, context.clone(), [3; 32], 10_000, 0)
        .unwrap();
    let job = selection
        .jobs()
        .find(|job| job.is_complete_non_root_subtree())
        .unwrap();
    pool.owner.cache_node(node(job, &[9]), vec![9], 1).unwrap();
    let candidate = pool
        .submit(&selection, context, [3; 32], 10_000, 2)
        .unwrap();
    pool.seal(candidate, [3; 32], 3).unwrap();
    pool.retire(prefix, 4).unwrap();
    assert_eq!(pool.status(job.id()).unwrap(), JobStatus::Completed);
    pool.step(5).unwrap();
    assert_ne!(state.borrow().last_lease.unwrap().job(), job.id());
    assert_eq!(state.borrow().dispatches, 1);
    assert!(pool.prefix_node(candidate, job.id(), [3; 32], 6).is_err());
    pool.retire(candidate, 7).unwrap();
    pool.close(8).unwrap();
}
