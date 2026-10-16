//! Structural recovery fixtures enforce scope and clocks, not GPU validity.
use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn repeated_prefix_recovery_preserves_unsealed_scope_deadline_and_cached_bytes() {
    let temp = Temp::new();
    let mut owner = temp.create();
    let (root, first) = candidate(&mut owner, 4);
    let mut clock = 0;
    complete(&mut owner, leaf(0).id(), &mut clock);
    assert!(owner.candidate_result(first, [1; 32], clock).is_err());
    drop(owner);
    for (index, now) in [100, 250, 500, 999].into_iter().enumerate() {
        let recovery = recover(&temp, index as u64 + 2);
        assert_eq!(recovery.previous_candidates().len(), 1);
        let previous = &recovery.previous_candidates()[0];
        assert!(!previous.sealed && !previous.cancelled);
        assert_eq!(previous.deadline_ms, 1000);
        let previous = previous.id;
        let (mut owner, candidate) = recovery
            .resume_prefix_candidate_with_workspaces(
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
                .unsealed_candidate_binding(candidate, [1; 32], now)
                .unwrap(),
            (root.id(), 1000)
        );
        assert!(owner
            .sealed_candidate_binding(candidate, [1; 32], now)
            .is_err());
        assert_eq!(
            owner.verified_node_bytes(leaf(0).id()).unwrap().unwrap(),
            leaf(0).id().to_bytes()
        );
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
    }
    let before = fs::read(temp.journal().join(STATE)).unwrap();
    let recovery = recover(&temp, 6);
    let previous = recovery.previous_candidates()[0].id;
    assert!(recovery
        .resume_prefix_candidate_with_workspaces(
            |_| Ok(()),
            |_| Ok(()),
            || 1000,
            previous,
            root.id(),
            [1; 32]
        )
        .is_err());
    assert_eq!(fs::read(temp.journal().join(STATE)).unwrap(), before);
    assert_eq!(recover(&temp, 6).previous_epoch(), 5);
}

#[test]
fn prefix_recovery_rejects_sealed_cancelled_or_changed_binding_before_reconciliation() {
    for invalid in ["sealed", "cancelled", "id", "head", "root"] {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 4);
        let other = owner.attach(root.id(), [2; 32], 999, 0).unwrap();
        if invalid == "sealed" {
            owner.seal(candidate, [1; 32], 0).unwrap();
        }
        if invalid == "cancelled" {
            owner.cancel(candidate, 1).unwrap();
        }
        drop(owner);
        let before = fs::read(temp.journal().join(STATE)).unwrap();
        assert!(
            recover(&temp, 2)
                .resume_prefix_candidate_with_workspaces(
                    |_| panic!("invalid prefix must not reconcile attempts"),
                    |_| panic!("invalid prefix must not reconcile workspaces"),
                    || panic!("invalid prefix must not start an epoch"),
                    if invalid == "id" { other } else { candidate },
                    if invalid == "root" {
                        leaf(0).id()
                    } else {
                        root.id()
                    },
                    if invalid == "head" { [2; 32] } else { [1; 32] },
                )
                .is_err(),
            "{invalid}"
        );
        assert_eq!(fs::read(temp.journal().join(STATE)).unwrap(), before);
        assert_eq!(recover(&temp, 2).previous_epoch(), 1);
    }
}

#[test]
fn prefix_deadline_is_checked_after_physical_reconciliation_before_publication() {
    for final_time in [999, 1000, 1001] {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 4);
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
        let outcome = recover(&temp, 2).resume_prefix_candidate_with_workspaces(
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
                    .unsealed_candidate_binding(candidate, [1; 32], 999)
                    .unwrap()
                    .1,
                1000
            );
            drop(owner);
            assert!(recover(&temp, 3).unresolved_attempts().is_empty());
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
fn failed_prefix_reconciliation_preserves_journal_and_deadline() {
    let temp = Temp::new();
    let mut owner = temp.create();
    let (root, candidate) = candidate(&mut owner, 4);
    let workspace = owner.reserve_workspace(WorkerId(7), request(), 0).unwrap();
    owner
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    drop(workspace);
    drop(owner);
    let before = fs::read(temp.journal().join(STATE)).unwrap();
    for failed in ["attempt", "workspace"] {
        assert!(recover(&temp, 2)
            .resume_prefix_candidate_with_workspaces(
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
    }
}

#[test]
fn atomic_recovery_faults_never_seal_or_renew_prefix() {
    for fault in FAULTS {
        let temp = Temp::new();
        let mut owner = temp.create();
        let (root, candidate) = candidate(&mut owner, 4);
        drop(owner);
        let mut recovery = recover(&temp, 2);
        recovery.journal.fault = Some(fault);
        assert!(recovery
            .resume_prefix_candidate_with_workspaces(
                |_| Ok(()),
                |_| Ok(()),
                || 100,
                candidate,
                root.id(),
                [1; 32]
            )
            .is_err());
        let recovery = recover(&temp, 3);
        let previous = &recovery.previous_candidates()[0];
        assert_eq!(previous.deadline_ms, 1000);
        assert!(!previous.sealed && !previous.cancelled);
        let previous = previous.id;
        let (mut owner, candidate) = recovery
            .resume_prefix_candidate_with_workspaces(
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
                .unsealed_candidate_binding(candidate, [1; 32], 900)
                .unwrap()
                .1,
            1000
        );
    }
}
