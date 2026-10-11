use super::*;

#[test]
fn durable_guard_census_counts_expired_weak_backing_until_rejection() {
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    let plan = d.storage_plan().unwrap();
    let empty = d.owner_storage_bytes().unwrap();
    let mut workspace = d.reserve_workspace(WorkerId(2), request(), 0).unwrap();
    let user = workspace.begin_use().unwrap();
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.worker_stopped(lease, 1).unwrap();
    let task = d.begin_guarded_verification(lease, 1).unwrap();
    let live = d.owner_storage_bytes().unwrap();
    assert!(live > empty && live <= plan.owner_metadata_bytes);
    assert!(d.finish_verification(lease, None, 2).is_err());
    assert!(d.release_workspace(&mut workspace, 2).is_err());
    drop(task);
    assert!(d.verifiers[&lease.id()].upgrade().is_none());
    let expired = d.owner_storage_bytes().unwrap();
    assert_eq!(expired, live);
    d.finish_verification(lease, None, 3).unwrap();
    let second = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 4)
        .unwrap();
    d.worker_stopped(second, 5).unwrap();
    let result = d.begin_guarded_verification(second, 5).unwrap().reject();
    assert_eq!(d.owner_storage_bytes().unwrap(), live);
    assert!(d.finish_verification(second, None, 6).is_err());
    d.finish_guarded_verification(result, 7).unwrap();
    drop(user);
    d.release_workspace(&mut workspace, 8).unwrap();
    let released = d.owner_storage_bytes().unwrap();
    assert_eq!(released, empty);
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    println!("bounded_durable_owners empty_bytes={empty} live_bytes={live} expired_bytes={expired} released_bytes={released}");
}

#[test]
fn pending_journal_names_and_anchor_keep_bounded_capacity_after_cleanup() {
    let temp = Temp::new();
    drop(temp.create());
    for index in 0..MAX_PENDING {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.journal().join(format!(".pending-{index:032x}")))
            .unwrap();
    }
    let (mut log, _) = SnapshotLog::open(&temp.journal(), journal_limits()).unwrap();
    assert_eq!(
        log.path.capacity(),
        crate::block_v2::execution::io_storage::ANCHOR_BYTES
    );
    assert_eq!(log.pending.len(), MAX_PENDING);
    assert!(log.pending.iter().all(|name| name.capacity() == 41));
    let capacity = log.pending.capacity();
    log.cleanup_pending().unwrap();
    assert!(log.pending.is_empty());
    assert_eq!(log.pending.capacity(), capacity);
    println!(
        "bounded_journal_paths anchor_bytes={} pending_capacity={capacity} name_bytes=41",
        log.path.capacity()
    );
}

#[test]
fn durable_component_admission_adds_all_known_shared_owners() {
    for (name, graph, store, snapshot_bytes) in [
        (
            "cli",
            Limits {
                jobs: 256,
                candidates: 8,
                attempts: 256,
                artifact_bytes: 256 << 20,
                ..limits()
            },
            StoreLimits {
                entries: 512,
                bytes: 256 << 20,
            },
            1 << 20,
        ),
        (
            "hard",
            Limits {
                jobs: 4096,
                candidates: 256,
                attempts: 16384,
                artifact_bytes: 512 << 20,
                ..limits()
            },
            StoreLimits {
                entries: 16384,
                bytes: 512 << 20,
            },
            8 << 20,
        ),
    ] {
        let plan = JournalLimits { snapshot_bytes }
            .durable_storage(graph, store)
            .unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        assert!(total > plan.graph.total_bytes().unwrap());
        println!("bounded_durable_storage profile={name} graph_bytes={} transition_bytes={} store_bytes={} owner_bytes={} path_bytes={} total_bytes={total}",
            plan.graph.total_bytes().unwrap(), plan.transitions.total_bytes().unwrap(), plan.store.total_bytes().unwrap(),
            plan.owner_metadata_bytes, plan.path_work_bytes);
    }
    assert_eq!(
        StoreLimits {
            entries: 2,
            bytes: 2
        }
        .storage_plan()
        .unwrap()
        .read_bytes,
        2
    );
    assert!(journal_limits()
        .durable_storage(
            limits(),
            StoreLimits {
                entries: 1,
                bytes: 2
            }
        )
        .is_err());
}
