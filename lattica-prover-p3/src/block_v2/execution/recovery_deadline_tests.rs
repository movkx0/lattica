//! Structural journal fixtures test recovery authority, not GPU proof validity.
use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn repeated_recovery_preserves_original_deadline_and_verified_artifacts() {
    let temp = Temp::new();
    let mut owner = temp.create();
    let (root, first) = candidate(&mut owner, 3);
    let mut clock = 0;
    while let Some(job) = owner.ready().unwrap().first().copied() {
        complete(&mut owner, job, &mut clock);
    }
    owner.seal(first, [1; 32], clock).unwrap();
    drop(owner);
    for (index, now) in [100, 250, 500, 999].into_iter().enumerate() {
        let epoch = index as u64 + 2;
        let recovery = recover(&temp, epoch);
        assert_eq!(recovery.previous_epoch(), epoch - 1);
        assert_eq!(recovery.previous_candidates().len(), 1);
        let previous = &recovery.previous_candidates()[0];
        assert_eq!(previous.deadline_ms, 1000);
        let previous = previous.id;
        let (mut owner, candidate) = recovery
            .resume_sealed_candidate_with_workspaces(
                |_| panic!("completed attempt resurrected"),
                |_| panic!("workspace resurrected"),
                || now,
                previous,
                root.id(),
                [1; 32],
            )
            .unwrap();
        assert_eq!(
            owner
                .sealed_candidate_binding(candidate, [1; 32], now)
                .unwrap(),
            (root.id(), 1000)
        );
        assert_eq!(
            owner
                .candidate_result(candidate, [1; 32], now)
                .unwrap()
                .unwrap(),
            root.id().to_bytes()
        );
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
        assert!(owner.ready().unwrap().is_empty());
    }
    let recovery = recover(&temp, 6);
    let previous = recovery.previous_candidates()[0].id;
    assert!(recovery
        .resume_sealed_candidate_with_workspaces(
            |_| Ok(()),
            |_| Ok(()),
            || 1000,
            previous,
            root.id(),
            [1; 32],
        )
        .is_err());
    let recovery = recover(&temp, 6);
    assert_eq!(recovery.previous_epoch(), 5);
    assert_eq!(recovery.previous_candidates()[0].deadline_ms, 1000);
}

#[test]
fn wrong_binding_or_unsealed_cancelled_candidate_never_reconciles_or_commits() {
    for state in [
        "wrong_id",
        "wrong_root",
        "wrong_head",
        "unsealed",
        "cancelled",
    ] {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 1);
        let other = owner.attach(root.id(), [2; 32], 999, 0).unwrap();
        if state != "unsealed" {
            owner.seal(candidate, [1; 32], 0).unwrap();
        }
        if state == "cancelled" {
            owner.cancel(candidate, 1).unwrap();
        }
        drop(owner);
        let before = fs::read(temp.journal().join(STATE)).unwrap();
        let requested = if state == "wrong_id" {
            other
        } else {
            candidate
        };
        let root = if state == "wrong_root" {
            leaf(0).id()
        } else {
            root.id()
        };
        let head = if state == "wrong_head" {
            [2; 32]
        } else {
            [1; 32]
        };
        assert!(
            recover(&temp, 2)
                .resume_sealed_candidate_with_workspaces(
                    |_| panic!("invalid candidate must not reconcile attempts"),
                    |_| panic!("invalid candidate must not reconcile workspaces"),
                    || panic!("invalid candidate must not start an epoch"),
                    requested,
                    root,
                    head,
                )
                .is_err(),
            "{state}"
        );
        assert_eq!(fs::read(temp.journal().join(STATE)).unwrap(), before);
        assert_eq!(recover(&temp, 2).previous_epoch(), 1);
    }
}

#[test]
fn deadline_is_sampled_after_attempt_and_workspace_reconciliation() {
    for final_time in [999, 1000, 1001] {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 1);
        owner.seal(candidate, [1; 32], 0).unwrap();
        let workspace = owner.reserve_workspace(WorkerId(7), request(), 0).unwrap();
        let workspace_lease = workspace.lease().unwrap();
        let lease = owner
            .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
            .unwrap();
        drop(workspace);
        drop(owner);
        let before = fs::read(temp.journal().join(STATE)).unwrap();
        let clock = Cell::new(10);
        let order = RefCell::new(Vec::new());
        let outcome = recover(&temp, 2).resume_sealed_candidate_with_workspaces(
            |attempt| {
                assert_eq!(attempt.lease, lease);
                order.borrow_mut().push("attempt");
                clock.set(900);
                Ok(())
            },
            |workspace| {
                assert_eq!(*workspace, workspace_lease);
                order.borrow_mut().push("workspace");
                clock.set(final_time);
                Ok(())
            },
            || {
                order.borrow_mut().push("clock");
                clock.get()
            },
            candidate,
            root.id(),
            [1; 32],
        );
        assert_eq!(*order.borrow(), ["attempt", "workspace", "clock"]);
        if final_time < 1000 {
            let (mut owner, candidate) = outcome.unwrap();
            assert_eq!(owner.resource_use().unwrap(), Resources::default());
            assert_eq!(
                owner
                    .sealed_candidate_binding(candidate, [1; 32], 999)
                    .unwrap()
                    .1,
                1000
            );
            drop(owner);
            let recovery = recover(&temp, 3);
            assert!(recovery.unresolved_attempts().is_empty());
            assert!(recovery.unresolved_workspaces().is_empty());
        } else {
            assert!(outcome.is_err());
            assert_eq!(fs::read(temp.journal().join(STATE)).unwrap(), before);
            let recovery = recover(&temp, 2);
            assert_eq!(recovery.previous_epoch(), 1);
            assert_eq!(recovery.unresolved_attempts().len(), 1);
            assert_eq!(recovery.unresolved_workspaces().len(), 1);
        }
    }
}

#[test]
fn failed_physical_reconciliation_cannot_publish_or_consume_a_deadline() {
    for failed in ["attempt", "workspace"] {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 1);
        owner.seal(candidate, [1; 32], 0).unwrap();
        let workspace = owner.reserve_workspace(WorkerId(7), request(), 0).unwrap();
        owner
            .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
            .unwrap();
        drop(workspace);
        drop(owner);
        let before = fs::read(temp.journal().join(STATE)).unwrap();
        assert!(recover(&temp, 2)
            .resume_sealed_candidate_with_workspaces(
                |_| if failed == "attempt" {
                    Err("worker still alive".into())
                } else {
                    Ok(())
                },
                |_| Err("workspace still alive".into()),
                || panic!("clock must follow successful reconciliation"),
                candidate,
                root.id(),
                [1; 32],
            )
            .is_err());
        assert_eq!(fs::read(temp.journal().join(STATE)).unwrap(), before);
        let recovery = recover(&temp, 2);
        assert_eq!(recovery.previous_epoch(), 1);
        assert_eq!(recovery.previous_candidates()[0].deadline_ms, 1000);
        let (mut owner, new_candidate) = recovery
            .resume_sealed_candidate_with_workspaces(
                |_| Ok(()),
                |_| Ok(()),
                || 750,
                candidate,
                root.id(),
                [1; 32],
            )
            .unwrap();
        assert_eq!(
            owner
                .sealed_candidate_binding(new_candidate, [1; 32], 750)
                .unwrap()
                .1,
            1000
        );
    }
}

#[test]
fn interrupted_atomic_recovery_keeps_the_deadline_in_both_authoritative_epochs() {
    for fault in FAULTS {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 1);
        owner.seal(candidate, [1; 32], 0).unwrap();
        drop(owner);
        let mut recovery = recover(&temp, 2);
        recovery.journal.fault = Some(fault);
        assert!(recovery
            .resume_sealed_candidate_with_workspaces(
                |_| Ok(()),
                |_| Ok(()),
                || 100,
                candidate,
                root.id(),
                [1; 32],
            )
            .is_err());
        let recovery = recover(&temp, 3);
        let previous = &recovery.previous_candidates()[0];
        assert_eq!(previous.deadline_ms, 1000);
        assert!(previous.sealed && !previous.cancelled);
        let previous = previous.id;
        let (mut owner, candidate) = recovery
            .resume_sealed_candidate_with_workspaces(
                |_| Ok(()),
                |_| Ok(()),
                || 900,
                previous,
                root.id(),
                [1; 32],
            )
            .unwrap();
        assert_eq!(
            owner
                .sealed_candidate_binding(candidate, [1; 32], 900)
                .unwrap()
                .1,
            1000
        );
    }
}

#[test]
fn original_absolute_deadline_needs_no_lifetime_addition() {
    let temp = Temp::new();
    let mut owner = temp.create();
    let root = tree(&mut owner, 1, 0, DEPTH);
    let candidate = owner.attach(root.id(), [1; 32], u64::MAX, 0).unwrap();
    owner.seal(candidate, [1; 32], 0).unwrap();
    drop(owner);
    let (mut owner, candidate) = recover(&temp, 2)
        .resume_sealed_candidate_with_workspaces(
            |_| Ok(()),
            |_| Ok(()),
            || u64::MAX - 1,
            candidate,
            root.id(),
            [1; 32],
        )
        .unwrap();
    assert_eq!(
        owner
            .sealed_candidate_binding(candidate, [1; 32], u64::MAX - 1)
            .unwrap()
            .1,
        u64::MAX
    );
}
