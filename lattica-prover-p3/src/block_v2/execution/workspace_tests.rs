//! Persistent-budget and ownership tests use structural fixtures, not proofs.

use super::*;
use std::cell::Cell;

// These cases resume into epoch 2; replay must advance again, to epoch 3.
fn assert_recovered_durable(d: &DurableDag) {
    let bytes = fs::read(d.journal.path.join(STATE)).unwrap();
    let (_, payload) = decode_frame(&bytes, journal_limits()).unwrap();
    assert_eq!(payload, d.core.snapshot().unwrap());
    restored(payload, &d.store, 3).unwrap();
}

#[test]
fn idle_workspace_stays_charged_through_timers_and_pruning() {
    let temp = Temp::new();
    let mut d = temp.create();
    let mut reservation = d.reserve_workspace(WorkerId(7), request(), 0).unwrap();
    assert_eq!(reservation.lease().unwrap().resources(), request());
    d.advance(100).unwrap();
    d.prune(100).unwrap();
    assert_eq!(d.resource_use().unwrap(), request());
    assert_durable(&d);
    d.release_workspace(&mut reservation, 101).unwrap();
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert!(reservation.lease().is_err());
    assert!(reservation.begin_use().is_err());
    assert!(d.release_workspace(&mut reservation, 102).is_err());
    assert_durable(&d);
}

#[test]
fn workspace_and_cold_attempts_share_one_budget_without_worker_aliases() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (_, candidate) = candidate(&mut d, 1);
    let resources = request().add(request()).unwrap().add(request()).unwrap();
    let mut reservation = d.reserve_workspace(WorkerId(7), resources, 0).unwrap();
    assert!(d
        .lease(leaf(0).id(), WorkerId(7), request(), 1, 100, 0)
        .is_err());
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    assert_eq!(d.resource_use().unwrap(), limits().workers);
    assert!(d.reserve_workspace(WorkerId(8), request(), 0).is_err());
    assert!(d.reserve_workspace(WorkerId(1), request(), 0).is_err());
    assert_durable(&d);
    d.cancel(candidate, 1).unwrap();
    assert_eq!(d.resource_use().unwrap(), limits().workers);
    d.worker_stopped(lease, 2).unwrap();
    assert_eq!(d.resource_use().unwrap(), resources);
    d.release_workspace(&mut reservation, 3).unwrap();
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert_durable(&d);
}

#[test]
fn live_cold_worker_cannot_be_reclassified_as_a_workspace() {
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    assert!(d.reserve_workspace(WorkerId(1), request(), 0).is_err());
    d.reject_worker(lease, 1).unwrap();
    assert!(d.reserve_workspace(WorkerId(1), request(), 1).is_err());
    d.worker_stopped(lease, 2).unwrap();
    let mut workspace = d.reserve_workspace(WorkerId(1), request(), 2).unwrap();
    d.release_workspace(&mut workspace, 3).unwrap();
    assert_durable(&d);
}

#[test]
fn workspace_close_waits_for_all_local_users_and_is_retryable() {
    let temp = Temp::new();
    let mut d = temp.create();
    let mut workspace = d.reserve_workspace(WorkerId(1), request(), 0).unwrap();
    let lease = workspace.lease().unwrap();
    let first = workspace.begin_use().unwrap();
    let second = workspace.begin_use().unwrap();
    assert_eq!(first.lease(), lease);
    assert!(d.release_workspace(&mut workspace, 1).is_err());
    assert_eq!(workspace.lease().unwrap(), lease);
    drop(first);
    assert!(d.release_workspace(&mut workspace, 1).is_err());
    assert_eq!(d.resource_use().unwrap(), request());
    drop(second);
    d.release_workspace(&mut workspace, 2).unwrap();
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert_durable(&d);
}

#[test]
fn wrong_owner_cannot_close_or_consume_a_workspace() {
    let a = Temp::new();
    let b = Temp::new();
    let mut da = a.create();
    let mut db = b.create();
    let mut wa = da.reserve_workspace(WorkerId(1), request(), 0).unwrap();
    let mut wb = db.reserve_workspace(WorkerId(1), request(), 0).unwrap();
    assert_ne!(wa.lease().unwrap(), wb.lease().unwrap());
    assert!(db.release_workspace(&mut wa, 1).is_err());
    assert_eq!(da.resource_use().unwrap(), request());
    assert_eq!(db.resource_use().unwrap(), request());
    da.release_workspace(&mut wa, 1).unwrap();
    db.release_workspace(&mut wb, 1).unwrap();
    assert_durable(&da);
    assert_durable(&db);
}

#[test]
fn workspace_use_keeps_recovery_locked_after_owner_and_reservation_drop() {
    let temp = Temp::new();
    let mut d = temp.create();
    let workspace = d.reserve_workspace(WorkerId(1), request(), 0).unwrap();
    let lease = workspace.lease().unwrap();
    let user = workspace.begin_use().unwrap();
    drop(d);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    drop(workspace);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    drop(user);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.unresolved_workspaces(), &[lease]);
    assert!(recovery.unresolved_attempts().is_empty());
    assert!(recovery.resume(|_| Ok(()), || 100).is_err());
    let before = fs::read(temp.journal().join(STATE)).unwrap();
    let clock_called = Cell::new(false);
    assert!(recover(&temp, 2)
        .resume_with_workspaces(
            |_| Ok(()),
            |_| Err("workspace drain not confirmed".into()),
            || {
                clock_called.set(true);
                100
            },
        )
        .is_err());
    assert!(!clock_called.get());
    assert_eq!(fs::read(temp.journal().join(STATE)).unwrap(), before);
    let mut d = recover(&temp, 2)
        .resume_with_workspaces(
            |_| panic!("no old attempts"),
            |old| {
                assert_eq!(*old, lease);
                Ok(()) // Structural fixture: all local holders explicitly dropped.
            },
            || 100,
        )
        .unwrap();
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert!(d.ready().unwrap().is_empty());
    let mut fresh = d.reserve_workspace(WorkerId(1), request(), 100).unwrap();
    assert_ne!(fresh.lease().unwrap(), lease);
    assert!(d.core.release_workspace(lease, 100).is_err());
    d.release_workspace(&mut fresh, 101).unwrap();
    assert_recovered_durable(&d);
}

#[test]
fn workspace_envelope_preserves_exact_cold_snapshot_bytes() {
    let temp = Temp::new();
    let mut d = temp.create();
    let before = d.core.snapshot().unwrap();
    let mut workspace = d.reserve_workspace(WorkerId(1), request(), 0).unwrap();
    let bytes = d.core.snapshot().unwrap();
    assert_eq!(&bytes[..8], b"LVDAG004");
    let n = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    assert_eq!(&bytes[12..12 + n], before);
    let parsed = restored(&bytes, &d.store, 2).unwrap();
    assert_eq!(parsed.workspaces, vec![workspace.lease().unwrap()]);
    assert_eq!(parsed.dag.resource_use(), Resources::default());
    d.release_workspace(&mut workspace, 0).unwrap();
    assert_eq!(d.core.snapshot().unwrap(), before);
    assert!(restored(&before, &d.store, 2)
        .unwrap()
        .workspaces
        .is_empty());
}

fn malformed_workspace_rejected_before_proofs(bytes: &[u8]) {
    let result = dag::snapshot::restore_with(
        bytes,
        pin(),
        [9; 32],
        2,
        limits(),
        |_| panic!("malformed workspace loaded a wallet proof"),
        |_, _| panic!("malformed workspace loaded a node proof"),
    );
    assert!(result.is_err());
}

#[test]
fn workspace_snapshot_rejects_malformed_identity_budgets_and_nesting() {
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    let _a = d.reserve_workspace(WorkerId(20), request(), 0).unwrap();
    let _b = d.reserve_workspace(WorkerId(21), request(), 0).unwrap();
    d.lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let bytes = d.core.snapshot().unwrap();
    let base_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let meta = 12 + base_len;
    let first = meta + 12;
    let second = first + 44;
    assert_eq!(bytes.len(), second + 44);
    for end in 0..bytes.len() {
        malformed_workspace_rejected_before_proofs(&bytes[..end]);
    }
    for (offset, value) in [
        (meta, 0),         // sequence counter
        (first, 0),        // zero workspace ID
        (second, 1),       // duplicate/out-of-order ID
        (first + 8, 0),    // zero worker
        (second + 8, 20),  // duplicate workspace worker
        (first + 8, 1),    // alias of live cold worker
        (first + 16, 0),   // zero RAM
        (first + 16, 401), // workspace alone exceeds cap
        (first + 16, 300), // workspaces fit, combined cold budget fails
        (first + 24, 41),  // VRAM cap
        (first + 32, 401), // scratch cap
    ] {
        let mut changed = bytes.clone();
        changed[offset..offset + 8].copy_from_slice(&u64::to_le_bytes(value));
        malformed_workspace_rejected_before_proofs(&changed);
    }
    for (offset, value) in [
        (8, 0),
        (meta + 8, 0),
        (meta + 8, 257),
        (first + 40, 0),
        (first + 40, 5),
    ] {
        let mut changed = bytes.clone();
        changed[offset..offset + 4].copy_from_slice(&u32::to_le_bytes(value));
        malformed_workspace_rejected_before_proofs(&changed);
    }
    let mut nested = bytes.clone();
    nested[12..20].copy_from_slice(b"LVDAG004");
    malformed_workspace_rejected_before_proofs(&nested);
    let mut trailing = bytes;
    trailing.push(0);
    malformed_workspace_rejected_before_proofs(&trailing);
}

#[test]
fn interrupted_workspace_reservation_never_returns_a_live_handle() {
    for (i, fault) in FAULTS.into_iter().enumerate() {
        let temp = Temp::new();
        let mut d = temp.create();
        d.journal.fault = Some(fault);
        assert!(d.reserve_workspace(WorkerId(1), request(), 0).is_err());
        assert!(d.resource_use().is_err());
        drop(d);
        let recovery = recover(&temp, 2);
        assert_eq!(recovery.unresolved_workspaces().len(), usize::from(i >= 2));
        let d = recovery
            .resume_with_workspaces(|_| Ok(()), |_| Ok(()), || 100)
            .unwrap();
        assert_eq!(d.resource_use().unwrap(), Resources::default());
        assert_recovered_durable(&d);
    }
}

#[test]
fn interrupted_workspace_close_keeps_guard_and_requires_recovery() {
    for (i, fault) in FAULTS.into_iter().enumerate() {
        let temp = Temp::new();
        let mut d = temp.create();
        let mut workspace = d.reserve_workspace(WorkerId(1), request(), 0).unwrap();
        let lease = workspace.lease().unwrap();
        d.journal.fault = Some(fault);
        assert!(d.release_workspace(&mut workspace, 1).is_err());
        assert_eq!(workspace.lease().unwrap(), lease);
        assert!(d.resource_use().is_err());
        drop(d);
        assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
        drop(workspace);
        let recovery = recover(&temp, 2);
        assert_eq!(recovery.unresolved_workspaces().len(), usize::from(i < 2));
        let d = recovery
            .resume_with_workspaces(|_| Ok(()), |_| Ok(()), || 100)
            .unwrap();
        assert_eq!(d.resource_use().unwrap(), Resources::default());
        assert_recovered_durable(&d);
    }
}

#[test]
#[ignore = "requires pinned public CPU fixtures and an existing pair proof"]
fn cpu_workspace_snapshot_replays_cached_pair_and_requires_explicit_drain() -> Result<(), Error> {
    use crate::block_v2::execution::{
        job::Operation,
        selection::{PublicInput, Selection},
        test_fixture,
    };
    let f = test_fixture::load()?;
    let bytes = test_fixture::read(
        &PathBuf::from(std::env::var("LATTICA_V2_GUARDED_PAIR")?),
        MAX_PROOF_BYTES,
    )?;
    let inputs = f.wallets[..2]
        .iter()
        .zip(&f.bytes[..2])
        .map(|(wallet, bytes)| PublicInput::new(*wallet, bytes.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let selection = Selection::new(f.pin, [0x5a; 32], &inputs)?;
    let job = selection
        .jobs()
        .find(|job| job.operation() == Operation::WrapPair)
        .ok_or("missing pair job")?
        .clone();
    let capacity = Resources {
        ram_bytes: 2 << 30,
        vram_bytes: 0,
        scratch_bytes: 128 << 20,
        threads: 3,
    };
    let proving = Resources {
        ram_bytes: 1 << 30,
        vram_bytes: 0,
        scratch_bytes: 64 << 20,
        threads: 2,
    };
    let cache = Resources {
        ram_bytes: 64 << 20,
        vram_bytes: 0,
        scratch_bytes: 1 << 20,
        threads: 1,
    };
    let limits = Limits {
        workers: capacity,
        ..limits()
    };
    let temp = Temp::new();
    let store = ArtifactStore::create(&temp.store(), store_limits())?;
    let mut owner = DurableDag::create(
        &temp.journal(),
        journal_limits(),
        store,
        f.pin,
        [0x5a; 32],
        1,
        limits,
    )?;
    selection.attach(&mut owner, [1; 32], 10_000, 0)?;
    let workspace = owner.reserve_workspace(WorkerId(7), cache, 0)?;
    let workspace_lease = workspace.lease()?;
    let lease = owner.lease(job.id(), WorkerId(1), proving, 1, 1000, 1)?;
    assert_eq!(owner.resource_use()?, cache.add(proving).unwrap());
    // Existing public proof: no prover process or actual preprocessing cache.
    owner.worker_stopped(lease, 2)?;
    let result = owner
        .begin_guarded_verification(lease, 2)?
        .verify(&f.registry, bytes.clone());
    assert!(result.error().is_none());
    assert_eq!(
        owner.finish_guarded_verification(result, 3)?,
        Completion::Accepted
    );
    assert_eq!(owner.resource_use()?, cache);
    drop(owner);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    drop(workspace);
    let recover = || {
        let store = ArtifactStore::open(&temp.store(), store_limits())?;
        DurableDag::recover(
            &temp.journal(),
            journal_limits(),
            store,
            f.pin,
            &f.registry,
            [0x5a; 32],
            2,
            limits,
        )
    };
    let recovery = recover()?;
    assert_eq!(recovery.unresolved_workspaces(), &[workspace_lease]);
    assert!(recovery.unresolved_attempts().is_empty());
    assert!(recovery.resume(|_| Ok(()), || 100).is_err());
    let owner = recover()?.resume_with_workspaces(
        |_| panic!("completed pair has no unresolved attempt"),
        |old| {
            assert_eq!(*old, workspace_lease);
            Ok(()) // No real cache exists and its only guard was dropped.
        },
        || 100,
    )?;
    assert_eq!(owner.resource_use()?, Resources::default());
    assert_eq!(owner.status(job.id())?, JobStatus::Completed);
    assert!(owner.ready()?.is_empty());
    let mut mutation = bytes;
    *mutation.last_mut().ok_or("empty proof")? ^= 1;
    assert!(VerifiedNode::verify(&job, &f.registry, &mutation).is_err());
    println!("workspace_cpu_recovery=PASS cached_pair_reverified=true explicit_workspace_drain=true old_eligibility_revived=false actual_preprocessing_cache=false prover_process_launched=false production_ready=false");
    Ok(())
}
