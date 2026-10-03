//! Guard ownership/state tests use the parent's explicit structural fixtures.
//! The ignored CPU case separately verifies an existing real public pair proof.
use super::*;
use std::sync::mpsc;

#[path = "verification_process_tests.rs"]
mod process;

fn guarded(d: &mut DurableDag) -> (Lease, VerificationTask) {
    candidate(d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.worker_stopped(lease, 1).unwrap();
    let task = d.begin_guarded_verification(lease, 1).unwrap();
    (lease, task)
}

#[test]
fn guarded_task_and_pending_result_keep_recovery_locked_after_owner_drop() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (lease, task) = guarded(&mut d);
    assert_eq!(task.lease(), lease);
    assert_durable(&d);
    drop(d);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    let result = task.reject();
    assert!(result.error().is_some());
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    drop(result);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.unresolved_attempts().len(), 1);
    assert!(recovery.unresolved_attempts()[0].verification_active);
    let d = recovery
        .resume(
            |old| {
                assert_eq!(old.lease, lease);
                assert!(old.worker_stopped);
                Ok(()) // This structural fixture has no external verifier.
            },
            || 200,
        )
        .unwrap();
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert!(d.ready().unwrap().is_empty());
}

#[test]
fn guarded_verification_blocks_raw_completion_through_cancellation() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (_, selection) = candidate(&mut d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.worker_stopped(lease, 1).unwrap();
    let task = d.begin_guarded_verification(lease, 1).unwrap();
    assert!(d.begin_guarded_verification(lease, 2).is_err());
    assert!(d.finish_verification(lease, None, 2).is_err());
    d.cancel(selection, 3).unwrap();
    assert_eq!(d.resource_use().unwrap(), request());
    let result = task.reject();
    assert!(d.finish_verification(lease, None, 4).is_err());
    assert_eq!(
        d.finish_guarded_verification(result, 5).unwrap(),
        Completion::Fenced
    );
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert_durable(&d);
}

#[test]
fn abandoned_guard_can_only_be_rejected_and_cannot_invent_success() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (lease, task) = guarded(&mut d);
    let bytes = vec![42];
    let ticket = node(&task.job, &bytes);
    drop(task);
    assert!(d
        .finish_verification(lease, Some((ticket, bytes)), 2)
        .is_err());
    assert_eq!(d.resource_use().unwrap(), request());
    assert_eq!(
        d.finish_verification(lease, None, 3).unwrap(),
        Completion::Rejected
    );
    assert_eq!(d.resource_use().unwrap(), Resources::default());
}

#[test]
fn guarded_results_are_bound_to_the_issuing_owner_and_attempt() {
    let a = Temp::new();
    let b = Temp::new();
    let mut da = a.create();
    let mut db = b.create();
    let (la, ta) = guarded(&mut da);
    let (lb, tb) = guarded(&mut db);
    assert!(db.finish_guarded_verification(ta.reject(), 2).is_err());
    assert_eq!(db.resource_use().unwrap(), request());
    assert!(db.finish_verification(lb, None, 2).is_err());
    assert_eq!(
        da.finish_verification(la, None, 2).unwrap(),
        Completion::Rejected
    );
    assert_eq!(
        db.finish_guarded_verification(tb.reject(), 3).unwrap(),
        Completion::Rejected
    );
    assert_eq!(da.resource_use().unwrap(), Resources::default());
    assert_eq!(db.resource_use().unwrap(), Resources::default());
}

#[test]
fn thread_handoff_holds_barrier_until_returned_result_is_discarded() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (_, task) = guarded(&mut d);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        go_rx.recv().unwrap();
        task.reject()
    });
    ready_rx.recv().unwrap();
    drop(d);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    go_tx.send(()).unwrap();
    let finished = thread.join().unwrap();
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    drop(finished);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_ok());
}

#[test]
fn guarded_structural_success_is_durable_and_releases_only_after_completion() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (lease, task) = guarded(&mut d);
    let bytes = vec![42];
    let ticket = node(&task.job, &bytes);
    // Explicit structural authority, not a cryptographic verification result.
    let finished = VerificationResult {
        owner: task.owner,
        result: Some((ticket, bytes)),
        error: None,
    };
    assert!(d.finish_verification(lease, None, 2).is_err());
    assert_eq!(d.resource_use().unwrap(), request());
    assert_eq!(
        d.finish_guarded_verification(finished, 3).unwrap(),
        Completion::Accepted
    );
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert_eq!(d.status(lease.job()).unwrap(), JobStatus::Completed);
    assert_durable(&d);
}

#[test]
#[ignore = "requires pinned public CPU fixtures and an existing pair proof"]
fn cpu_guarded_verifier_recovers_after_owner_loss_and_rejects_mutation() -> Result<(), Error> {
    use crate::block_v2::execution::{
        job::Operation,
        selection::{PublicInput, Selection},
        test_fixture,
    };
    let f = test_fixture::load()?;
    let proof_path = PathBuf::from(std::env::var("LATTICA_V2_GUARDED_PAIR")?);
    let bytes = test_fixture::read(&proof_path, MAX_PROOF_BYTES)?;
    let inputs = f.wallets[..2]
        .iter()
        .zip(&f.bytes[..2])
        .map(|(w, bytes)| PublicInput::new(*w, bytes.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let selection = Selection::new(f.pin, [0x5a; 32], &inputs)?;
    let job = selection
        .jobs()
        .find(|job| job.operation() == Operation::WrapPair)
        .ok_or("missing pair job")?
        .clone();
    let budget = Resources {
        ram_bytes: 1 << 30,
        vram_bytes: 0,
        scratch_bytes: 128 << 20,
        threads: 2,
    };
    let limits = Limits {
        workers: budget,
        ..limits()
    };
    let temp = Temp::new();
    let store = ArtifactStore::create(&temp.store(), store_limits())?;
    let mut d = DurableDag::create(
        &temp.journal(),
        journal_limits(),
        store,
        f.pin,
        [0x5a; 32],
        1,
        limits,
    )?;
    selection.attach(&mut d, [1; 32], 10000, 0)?;
    let lease = d.lease(job.id(), WorkerId(1), budget, 1, 1000, 1)?;
    // Existing proof fixture: no prover process is launched in this test.
    d.worker_stopped(lease, 2)?;
    let task = d.begin_guarded_verification(lease, 2)?;
    let registry = f.registry.clone();
    let proof = bytes.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        go_rx.recv().unwrap();
        task.verify(&registry, proof)
    });
    ready_rx.recv()?;
    drop(d);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    go_tx.send(())?;
    let result = thread
        .join()
        .map_err(|_| "guarded verifier thread panicked")?;
    assert!(result.error().is_none(), "{:?}", result.error());
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    drop(result);
    let store = ArtifactStore::open(&temp.store(), store_limits())?;
    let recovery = DurableDag::recover(
        &temp.journal(),
        journal_limits(),
        store,
        f.pin,
        &f.registry,
        [0x5a; 32],
        2,
        limits,
    )?;
    assert_eq!(recovery.unresolved_attempts().len(), 1);
    let mut d = recovery.resume(
        |old| {
            assert_eq!(old.lease, lease);
            assert!(old.worker_stopped && old.verification_active);
            // The only verifier was joined and its guarded result discarded.
            Ok(())
        },
        || 100,
    )?;
    assert_eq!(d.resource_use()?, Resources::default());
    assert!(d.ready()?.is_empty());
    selection.attach(&mut d, [2; 32], 10000, 101)?;
    let next = d.lease(job.id(), WorkerId(2), budget, 1, 1000, 101)?;
    d.worker_stopped(next, 102)?;
    let task = d.begin_guarded_verification(next, 102)?;
    let mut changed = bytes;
    *changed.last_mut().unwrap() ^= 1;
    let rejected = task.verify(&f.registry, changed);
    assert!(rejected.error().is_some());
    assert_eq!(
        d.finish_guarded_verification(rejected, 103)?,
        Completion::Rejected
    );
    assert_eq!(d.resource_use()?, Resources::default());
    println!("guarded_cpu_recovery=PASS pair_verified=true task_barrier=true result_barrier=true old_eligibility_revived=false mutation_rejected=true prover_process_launched=false production_ready=false");
    Ok(())
}
