//! Structural fixtures are not cryptographic evidence. The ignored pinned CPU
//! replay below separately exercises the public, CPU-verifying recovery path.
use super::*;
#[path = "verification_tests.rs"]
mod verification;

#[path = "workspace_tests.rs"]
mod workspace;
use crate::block_v2::{
    commitment::DEPTH,
    execution::{
        artifact_store::StoreLimits,
        dag::AttemptStatus,
        job::{
            test_support::{node, pin, wallet},
            VerifiedWallet,
        },
    },
    profile::MAX_PROOF_BYTES,
};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    process::Command,
};

struct Temp {
    path: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "lattica-journal-test-{}",
            artifact_store::hex(&nonce)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn journal(&self) -> PathBuf {
        self.path.join("journal")
    }
    fn store(&self) -> PathBuf {
        self.path.join("store")
    }
    fn create(&self) -> DurableDag {
        let store = ArtifactStore::create(&self.store(), store_limits()).unwrap();
        DurableDag::create(
            &self.journal(),
            journal_limits(),
            store,
            pin(),
            [9; 32],
            1,
            limits(),
        )
        .unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn journal_limits() -> JournalLimits {
    JournalLimits {
        snapshot_bytes: 256 * 1024,
    }
}
fn store_limits() -> StoreLimits {
    StoreLimits {
        bytes: 32 * (1 << 20),
        entries: 512,
    }
}
fn request() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 10,
        scratch_bytes: 100,
        threads: 1,
    }
}
fn limits() -> Limits {
    Limits {
        jobs: 512,
        candidates: 16,
        attempts: 256,
        artifact_bytes: 32 * (1 << 20),
        recovery_window_ms: 10,
        workers: Resources {
            ram_bytes: 400,
            vram_bytes: 40,
            scratch_bytes: 400,
            threads: 4,
        },
    }
}
fn leaf(start: u8) -> Job {
    Job::wrap(start, wallet(u64::from(start) + 1, &[start + 1])).unwrap()
}
fn tree(d: &mut DurableDag, count: u8, start: u8, level: u8) -> Job {
    let (job, bytes) = if start >= count {
        (Job::empty(pin(), [9; 32], start, level).unwrap(), vec![])
    } else if level == 0 {
        (leaf(start), vec![vec![start + 1]])
    } else {
        let left = tree(d, count, start, level - 1);
        let right = tree(d, count, start + (1 << (level - 1)), level - 1);
        (Job::merge(&left, &right).unwrap(), vec![])
    };
    d.admit(job.clone(), bytes, 0).unwrap();
    job
}
fn candidate(d: &mut DurableDag, count: u8) -> (Job, CandidateId) {
    let root = tree(d, count, 0, DEPTH);
    let id = d.attach(root.id(), [1; 32], 1000, 0).unwrap();
    (root, id)
}
fn complete(d: &mut DurableDag, id: JobId, now: &mut u64) -> Lease {
    let lease = d.lease(id, WorkerId(1), request(), 1, 100, *now).unwrap();
    let job = d.leased_job(lease).unwrap().clone();
    let bytes = job.id().to_bytes().to_vec();
    *now += 1;
    d.worker_stopped(lease, *now).unwrap();
    d.begin_verification(lease, *now).unwrap();
    *now += 1;
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &bytes), bytes)), *now)
            .unwrap(),
        Completion::Accepted
    );
    lease
}
fn restored(
    bytes: &[u8],
    store: &ArtifactStore,
    epoch: u64,
) -> Result<dag::snapshot::Restored, Error> {
    dag::snapshot::restore_with(
        bytes,
        pin(),
        [9; 32],
        epoch,
        limits(),
        |id| {
            let bytes = store.read_exact(id)?;
            Ok((wallet(u64::from(bytes[0]), &bytes), bytes))
        },
        |job, id| {
            let bytes = store.read_exact(id)?;
            Ok((node(job, &bytes), bytes))
        },
    )
}
fn recover(temp: &Temp, epoch: u64) -> Recovery {
    let store = ArtifactStore::open(&temp.store(), store_limits()).unwrap();
    let (journal, bytes) = SnapshotLog::open(&temp.journal(), journal_limits()).unwrap();
    let restored = restored(&bytes, &store, epoch).unwrap();
    Recovery {
        restored,
        journal,
        store,
    }
}
fn assert_durable(d: &DurableDag) {
    let bytes = fs::read(d.journal.path.join(STATE)).unwrap();
    let (generation, payload) = decode_frame(&bytes, journal_limits()).unwrap();
    assert_eq!(generation, d.generation().unwrap());
    assert_eq!(payload, d.core.snapshot().unwrap());
    restored(payload, &d.store, 2).unwrap();
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn frame_rejects_truncation_corruption_trailing_data_and_bad_bounds() {
    let frame = encode_frame(4, b"bounded snapshot", journal_limits()).unwrap();
    assert_eq!(
        decode_frame(&frame, journal_limits()).unwrap(),
        (4, b"bounded snapshot".as_slice())
    );
    for end in 0..frame.len() {
        assert!(decode_frame(&frame[..end], journal_limits()).is_err());
    }
    for i in 0..frame.len() {
        let mut bad = frame.clone();
        bad[i] ^= 1;
        assert!(decode_frame(&bad, journal_limits()).is_err());
    }
    let mut extra = frame.clone();
    extra.push(0);
    assert!(decode_frame(&extra, journal_limits()).is_err());
    assert!(encode_frame(0, b"x", journal_limits()).is_err());
    assert!(encode_frame(1, b"", journal_limits()).is_err());
    assert!(encode_frame(
        1,
        &[1; 257],
        JournalLimits {
            snapshot_bytes: 256
        }
    )
    .is_err());
    assert!(JournalLimits {
        snapshot_bytes: 255
    }
    .validate()
    .is_err());
    assert!(JournalLimits {
        snapshot_bytes: dag::snapshot::MAX_SNAPSHOT_BYTES + 1
    }
    .validate()
    .is_err());
}

#[test]
fn journal_has_exclusive_owner_and_remains_anchored_after_path_replacement() {
    let temp = Temp::new();
    let path = temp.journal();
    let mut log = SnapshotLog::create(&path, journal_limits()).unwrap();
    log.commit(b"old").unwrap();
    assert!(SnapshotLog::create(&path, journal_limits()).is_err());
    assert!(SnapshotLog::open(&path, journal_limits()).is_err());
    let moved = temp.path.join("moved");
    fs::rename(&path, &moved).unwrap();
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    private_file(&path.join(STATE), b"replacement");
    log.commit(b"new").unwrap();
    assert_eq!(fs::read(path.join(STATE)).unwrap(), b"replacement");
    drop(log);
    assert_eq!(
        SnapshotLog::open(&moved, journal_limits()).unwrap().1,
        b"new"
    );
}

#[test]
fn journal_rejects_unsafe_entries_changed_owners_and_corrupt_authoritative_state() {
    let temp = Temp::new();
    let mut log = SnapshotLog::create(&temp.journal(), journal_limits()).unwrap();
    log.commit(b"good").unwrap();
    fs::remove_file(log.path.join(LOCK)).unwrap();
    private_file(&log.path.join(LOCK), b"");
    assert!(log.commit(b"bad").is_err());
    drop(log);
    let state = temp.journal().join(STATE);
    let saved = fs::read(&state).unwrap();
    fs::write(&state, b"corrupt").unwrap();
    private_file(
        &temp.journal().join(format!(".pending-{}", "0".repeat(32))),
        &saved,
    );
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    fs::remove_file(&state).unwrap();
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    private_file(&state, &saved);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = temp.path.join("alias");
    symlink(temp.journal(), &alias).unwrap();
    assert!(SnapshotLog::open(&alias, journal_limits()).is_err());
    let unknown = temp.journal().join("unknown");
    private_file(&unknown, b"x");
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    fs::remove_file(unknown).unwrap();
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_ok());
}

#[test]
fn pending_inventory_is_bounded_and_initial_creation_never_guesses_a_state() {
    let temp = Temp::new();
    drop(SnapshotLog::create(&temp.journal(), journal_limits()).unwrap());
    let frame = encode_frame(1, b"uncommitted", journal_limits()).unwrap();
    private_file(&temp.journal().join(format!(".pending-{:032x}", 0)), &frame);
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    private_file(&temp.journal().join(STATE), &frame);
    for i in 1..=MAX_PENDING {
        private_file(&temp.journal().join(format!(".pending-{i:032x}")), b"");
    }
    assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
    fs::remove_file(
        temp.journal()
            .join(format!(".pending-{:032x}", MAX_PENDING)),
    )
    .unwrap();
    let (mut log, _) = SnapshotLog::open(&temp.journal(), journal_limits()).unwrap();
    assert_eq!(log.pending.len(), MAX_PENDING);
    assert!(log.commit(b"next").is_err());
    log.cleanup_pending().unwrap();
    log.commit(b"next").unwrap();
}

const FAULTS: [Fault; 4] = [
    Fault::AfterWrite,
    Fault::AfterFileSync,
    Fault::AfterRename,
    Fault::AfterDirectorySync,
];
#[test]
fn interrupted_commits_poison_live_handle_and_recover_only_authoritative_state() {
    for (i, fault) in FAULTS.into_iter().enumerate() {
        let temp = Temp::new();
        let mut log = SnapshotLog::create(&temp.journal(), journal_limits()).unwrap();
        log.commit(b"before").unwrap();
        log.fault = Some(fault);
        assert!(log.commit(b"after").is_err());
        assert!(log.check_current().is_err());
        assert!(log.commit(b"retry").is_err());
        drop(log);
        let (mut log, bytes) = SnapshotLog::open(&temp.journal(), journal_limits()).unwrap();
        assert_eq!(
            bytes,
            if i < 2 {
                b"before".as_slice()
            } else {
                b"after".as_slice()
            }
        );
        assert_eq!(log.generation, if i < 2 { 1 } else { 2 });
        assert_eq!(log.pending.len(), usize::from(i < 2));
        log.cleanup_pending().unwrap();
        log.commit(b"resumed").unwrap();
    }
}

#[test]
#[ignore = "subprocess helper; invoked by abrupt_exit_boundaries_recover_atomic_snapshots"]
fn abrupt_exit_helper() {
    let path = PathBuf::from(std::env::var("LATTICA_JOURNAL_CRASH_PATH").unwrap());
    let index: usize = std::env::var("LATTICA_JOURNAL_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let (mut log, _) = SnapshotLog::open(&path, journal_limits()).unwrap();
    log.fault = Some(FAULTS[index]);
    log.crash = true;
    log.commit(b"after").unwrap();
    panic!("fault did not terminate child");
}

#[test]
fn abrupt_exit_boundaries_recover_atomic_snapshots() {
    for i in 0..FAULTS.len() {
        let temp = Temp::new();
        let mut log = SnapshotLog::create(&temp.journal(), journal_limits()).unwrap();
        log.commit(b"before").unwrap();
        drop(log);
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "block_v2::execution::journal::tests::abrupt_exit_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("LATTICA_JOURNAL_CRASH_PATH", temp.journal())
            .env("LATTICA_JOURNAL_CRASH_STAGE", i.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(74));
        let (mut log, bytes) = SnapshotLog::open(&temp.journal(), journal_limits()).unwrap();
        assert_eq!(
            bytes,
            if i < 2 {
                b"before".as_slice()
            } else {
                b"after".as_slice()
            }
        );
        log.cleanup_pending().unwrap();
        log.commit(b"resumed").unwrap();
    }
}

#[test]
fn completed_cache_survives_but_old_candidates_and_handles_do_not() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (root, old_candidate) = candidate(&mut d, 3);
    let mut now = 0;
    let mut old_lease = None;
    while let Some(id) = d.ready().unwrap().first().copied() {
        old_lease = Some(complete(&mut d, id, &mut now));
    }
    d.seal(old_candidate, [1; 32], now).unwrap();
    assert!(d
        .candidate_result(old_candidate, [1; 32], now)
        .unwrap()
        .is_some());
    assert_durable(&d);
    drop(d);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.previous_candidates().len(), 1);
    assert!(recovery.previous_candidates()[0].sealed);
    assert!(recovery.unresolved_attempts().is_empty());
    let mut d = recovery
        .resume(|_| panic!("released attempt resurrected"), || 5000)
        .unwrap();
    assert_eq!(d.status(root.id()).unwrap(), JobStatus::Completed);
    assert!(d.ready().unwrap().is_empty());
    assert!(d.worker_stopped(old_lease.unwrap(), 5000).is_err());
    assert!(d.candidate_result(old_candidate, [1; 32], 5000).is_err());
    let current = d.attach(root.id(), [2; 32], 6000, 5000).unwrap();
    assert_ne!(current, old_candidate);
    d.seal(current, [2; 32], 5000).unwrap();
    assert!(d.candidate_result(current, [1; 32], 5000).is_err());
    assert_eq!(
        d.candidate_result(current, [2; 32], 5000).unwrap().unwrap(),
        root.id().to_bytes()
    );
}

#[test]
fn recovery_requires_reconciliation_and_rebases_retention_after_success() {
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 2);
    let leased = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let verifying = d
        .lease(leaf(1).id(), WorkerId(2), request(), 1, 100, 0)
        .unwrap();
    d.worker_stopped(verifying, 1).unwrap();
    d.begin_verification(verifying, 1).unwrap();
    assert_durable(&d);
    let generation = d.generation().unwrap();
    drop(d);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.unresolved_attempts().len(), 2);
    assert!(recovery
        .unresolved_attempts()
        .iter()
        .any(|a| a.lease == leased && !a.worker_stopped));
    assert!(recovery
        .unresolved_attempts()
        .iter()
        .any(|a| a.lease == verifying && a.verification_active));
    assert!(recovery
        .resume(
            |_| Err("worker not drained".into()),
            || panic!("clock before reconciliation")
        )
        .is_err());
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.journal.generation, generation);
    let mut stopped = Vec::new();
    let mut d = recovery
        .resume(
            |a| {
                stopped.push(a.lease);
                Ok(())
            },
            || 10000,
        )
        .unwrap();
    assert_eq!(stopped.len(), 2);
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert!(d.ready().unwrap().is_empty());
    assert_eq!(d.prune(10009).unwrap().jobs, 0);
    assert!(d.prune(10010).unwrap().jobs > 0);
    assert_eq!(d.store_usage().unwrap().artifacts, 0);
}

#[test]
fn each_mutation_and_error_path_is_durable_before_visibility() {
    let temp = Temp::new();
    let mut d = temp.create();
    assert_durable(&d);
    let (root, candidate) = candidate(&mut d, 1);
    assert_durable(&d);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    assert_durable(&d);
    assert_eq!(d.input_bytes(lease, 0).unwrap(), [1]);
    assert_eq!(d.input_manifest(lease).unwrap(), leaf(0).wallet_inputs());
    d.worker_stopped(lease, 1).unwrap();
    assert_durable(&d);
    let job = d.begin_verification(lease, 2).unwrap();
    assert_durable(&d);
    let bytes = vec![42];
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &bytes), bytes.clone())), 3)
            .unwrap(),
        Completion::Accepted
    );
    assert_durable(&d);
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &bytes), bytes)), 4)
            .unwrap(),
        Completion::Duplicate
    );
    assert_durable(&d);
    assert!(d
        .finish_verification(lease, Some((node(&job, &[43]), vec![43])), 5)
        .is_err());
    assert_durable(&d);
    d.cache_node(node(&root, &[99]), vec![99], 6).unwrap();
    assert_durable(&d);
    d.seal(candidate, [1; 32], 7).unwrap();
    assert_durable(&d);
    assert_eq!(
        d.candidate_result(candidate, [1; 32], 8).unwrap().unwrap(),
        [99]
    );
    assert_durable(&d);
    assert!(d.seal(candidate, [2; 32], 9).is_err());
    assert_durable(&d);
    d.cancel(candidate, 10).unwrap();
    assert_durable(&d);
    d.advance(11).unwrap();
    assert_durable(&d);
    d.prune(20).unwrap();
    assert_durable(&d);
    assert_eq!(d.store_usage().unwrap().artifacts, 0);
}

#[test]
fn input_and_quota_rejections_do_not_poison_the_coordinator() {
    let temp = Temp::new();
    let store = ArtifactStore::create(
        &temp.store(),
        StoreLimits {
            bytes: 2,
            entries: 3,
        },
    )
    .unwrap();
    let mut d = DurableDag::create(
        &temp.journal(),
        journal_limits(),
        store,
        pin(),
        [9; 32],
        1,
        limits(),
    )
    .unwrap();
    assert!(d.admit(leaf(0), vec![vec![2]], 0).is_err());
    assert_eq!(d.generation().unwrap(), 1);
    d.admit(leaf(0), vec![vec![1]], 0).unwrap();
    let generation = d.generation().unwrap();
    assert!(d.admit(leaf(1), vec![vec![2]], 0).is_err());
    assert_eq!(d.generation().unwrap(), generation);
    assert!(d.cache_node(node(&leaf(0), &[42]), vec![43], 0).is_err());
    assert!(d.ready().is_ok());
    assert_eq!(d.prune(10).unwrap().jobs, 1);
    d.admit(leaf(1), vec![vec![2]], 10).unwrap();
}

#[test]
fn invalid_result_bytes_can_be_retried_without_losing_verifier_reservation() {
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.worker_stopped(lease, 1).unwrap();
    let job = d.begin_verification(lease, 1).unwrap();
    assert!(d
        .finish_verification(lease, Some((node(&job, &[42]), vec![43])), 2)
        .is_err());
    assert_eq!(d.resource_use().unwrap(), request());
    assert_eq!(d.status(job.id()).unwrap(), JobStatus::Verifying);
    assert_eq!(
        d.finish_verification(lease, Some((node(&job, &[42]), vec![42])), 2)
            .unwrap(),
        Completion::Accepted
    );
    assert_durable(&d);
}

#[test]
fn cancelled_verification_and_old_unreleased_attempt_with_new_output_recover() {
    let temp = Temp::new();
    let mut d = temp.create();
    let (_, candidate) = candidate(&mut d, 2);
    let old = d
        .lease(leaf(0).id(), WorkerId(2), request(), 1, 100, 0)
        .unwrap();
    d.reject_worker(old, 1).unwrap();
    let mut now = 1;
    complete(&mut d, leaf(0).id(), &mut now);
    let verifying = d
        .lease(leaf(1).id(), WorkerId(3), request(), 1, 100, now)
        .unwrap();
    d.worker_stopped(verifying, now).unwrap();
    d.begin_verification(verifying, now).unwrap();
    d.cancel(candidate, now).unwrap();
    assert_durable(&d);
    drop(d);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.unresolved_attempts().len(), 2);
    assert!(recovery
        .unresolved_attempts()
        .iter()
        .any(|a| a.lease == old && a.status == AttemptStatus::Rejected));
    assert!(recovery
        .unresolved_attempts()
        .iter()
        .any(|a| a.lease == verifying
            && a.status == AttemptStatus::Cancelled
            && a.verification_active));
    let d = recovery.resume(|_| Ok(()), || 100).unwrap();
    assert_eq!(d.status(leaf(0).id()).unwrap(), JobStatus::Completed);
    assert_eq!(d.status(leaf(1).id()).unwrap(), JobStatus::Dormant);
}

#[test]
fn failed_completion_commit_never_publishes_orphan_as_completed_job() {
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    d.worker_stopped(lease, 1).unwrap();
    let job = d.begin_verification(lease, 1).unwrap();
    d.journal.fault = Some(Fault::AfterFileSync);
    assert!(d
        .finish_verification(lease, Some((node(&job, &[42]), vec![42])), 2)
        .is_err());
    assert!(d.ready().is_err());
    assert!(d.status(job.id()).is_err());
    assert!(d
        .lease(job.id(), WorkerId(2), request(), 1, 100, 2)
        .is_err());
    drop(d);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.unresolved_attempts().len(), 1);
    assert_eq!(recovery.store.usage().artifacts, 2);
    let mut d = recovery.resume(|_| Ok(()), || 10).unwrap();
    assert_eq!(d.status(job.id()).unwrap(), JobStatus::Dormant);
    let pruned = d.prune(10).unwrap();
    assert_eq!(pruned.jobs, 0);
    assert_eq!(pruned.artifacts, 1);
    assert_eq!(d.store_usage().unwrap().artifacts, 1);
}

#[test]
fn garbage_collection_waits_for_committed_reference_removal() {
    let temp = Temp::new();
    let mut d = temp.create();
    d.admit(leaf(0), vec![vec![1]], 0).unwrap();
    d.journal.fault = Some(Fault::AfterFileSync);
    assert!(d.prune(10).is_err());
    assert_eq!(d.store.usage().artifacts, 1);
    drop(d);
    let recovery = recover(&temp, 2);
    assert_eq!(recovery.restored.dag.job_count(), 1);
    let mut d = recovery.resume(|_| Ok(()), || 100).unwrap();
    assert_eq!(d.prune(109).unwrap().artifacts, 0);
    let pruned = d.prune(110).unwrap();
    assert_eq!(pruned.jobs, 1);
    assert_eq!(pruned.artifacts, 1);
    drop(d);
    let recovery = recover(&temp, 3);
    assert_eq!(recovery.restored.dag.job_count(), 0);
}

#[test]
fn snapshot_metadata_is_rejected_before_any_proof_callback() {
    fn reject(bytes: &[u8], epoch: u64, config: Limits) {
        let result = dag::snapshot::restore_with(
            bytes,
            pin(),
            [9; 32],
            epoch,
            config,
            |_| panic!("wallet callback reached for invalid metadata"),
            |_, _| panic!("node callback reached for invalid metadata"),
        );
        assert!(result.is_err());
    }
    let temp = Temp::new();
    let mut d = temp.create();
    d.admit(leaf(0), vec![vec![1]], 0).unwrap();
    let bytes = d.core.snapshot().unwrap();
    for end in 0..bytes.len() {
        reject(&bytes[..end], 2, limits());
    }
    reject(&bytes, 1, limits());
    reject(
        &bytes,
        2,
        Limits {
            recovery_window_ms: 11,
            ..limits()
        },
    );
    for (offset, value) in [
        (0, 0),
        (8, 0),
        (40, 2),
        (41, 0),
        (229, 255),
        (230, 64),
        (231, 1),
        (232, 3),
        (233, 2),
        (271, 2),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        reject(&bad, 2, limits());
    }
    let mut bad = bytes.clone();
    bad[193..197].copy_from_slice(&513u32.to_le_bytes());
    reject(&bad, 2, limits());
    let mut bad = bytes.clone();
    bad.push(0);
    reject(&bad, 2, limits());
    drop(d);
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    d.lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let bytes = legacy_unbound_snapshot(&d);
    // Fixed v1 attempt body: 88 metadata bytes and one 37-byte input descriptor.
    let start = bytes.len() - 125;
    for (offset, value) in [(84, 255), (85, 2), (86, 1), (87, 3), (124, 1)] {
        let mut bad = bytes.clone();
        bad[start + offset] ^= value;
        reject(&bad, 2, limits());
    }
    let mut bad = bytes.clone();
    bad[start + 40..start + 48].fill(0);
    reject(&bad, 2, limits());
}

#[test]
fn changed_or_missing_artifacts_do_not_survive_recovery() {
    let temp = Temp::new();
    let mut d = temp.create();
    d.admit(leaf(0), vec![vec![1]], 0).unwrap();
    let bytes = d.core.snapshot().unwrap();
    let id = leaf(0).wallet_inputs()[0];
    let path = temp.store().join(format!(
        "w-{}.proof",
        artifact_store::hex(&id.digest_bytes())
    ));
    fs::write(&path, [2]).unwrap();
    assert!(restored(&bytes, &d.store, 2).is_err());
    fs::remove_file(&path).unwrap();
    assert!(restored(&bytes, &d.store, 2).is_err());
}

#[test]
#[ignore = "requires independently pinned eight-wallet inputs and root-only bundle"]
fn cpu_journal_recovery_revalidates_pinned_wallets_and_root() -> Result<(), Error> {
    use crate::block_v2::{
        commitment, machine::program::Val, profile, recursive::WrapperConstruction,
    };
    use p3_field::PrimeCharacteristicRing;

    fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
        let before = fs::symlink_metadata(path)?;
        if !before.is_file() || before.len() > limit as u64 {
            return Err("fixture type/size".into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(artifact_store::safe_file_flags())
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit as u64 {
            return Err("fixture type/size".into());
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err("fixture grew".into());
        }
        Ok(bytes)
    }
    fn fixed_hex(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
    }
    fn root_job(wallets: &[VerifiedWallet]) -> Result<Job, Error> {
        let pairs: Vec<_> = (0..4)
            .map(|i| Job::wrap_pair((i * 2) as u8, wallets[2 * i], wallets[2 * i + 1]))
            .collect::<Result<_, _>>()?;
        Job::merge(
            &Job::merge(&pairs[0], &pairs[1])?,
            &Job::merge(&pairs[2], &pairs[3])?,
        )
    }
    let inputs = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_INPUTS")?);
    let bundle = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_ROOT")?);
    let expected_profile =
        fixed_hex("8ec1bbde8ade9c60a90398a6a30f3bb095d5adc1f1fed881e7b72ea051bab3cb");
    let expected_root =
        fixed_hex("23ccda6b5581d09e8d0107be85d09c2795f3f767bfc844a9b5168e7f4a9c20e8");
    let chain = [0x5a; 32];
    let height =
        u32::from_le_bytes(read(&inputs.join("height"), 4)?.as_slice().try_into()?) as usize;
    if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
        return Err("fixture geometry".into());
    }
    let mut caps = core::array::from_fn(|_| Vec::new());
    let key_size = (1 << profile::CAP_HEIGHT) * 32;
    for (i, cap) in caps.iter_mut().enumerate() {
        let bytes = read(&inputs.join(format!("key.{}", i + 1)), key_size)?;
        if bytes.len() != key_size {
            return Err("fixture cap size".into());
        }
        for digest in bytes.chunks_exact(32) {
            let mut values = [Val::ZERO; 4];
            for (value, word) in values.iter_mut().zip(digest.chunks_exact(8)) {
                let decoded = u64::from_le_bytes(word.try_into()?);
                if decoded >= commitment::MODULUS {
                    return Err("fixture noncanonical cap".into());
                }
                *value = Val::from_u64(decoded);
            }
            cap.push(values);
        }
    }
    let registry = Registry { height, caps };
    let pin = RegistryPin::new(
        &registry,
        expected_profile,
        WrapperConstruction::GroupedPair,
    )?;

    let temp = Temp::new();
    let store = ArtifactStore::create(&temp.store(), store_limits())?;
    let mut d = DurableDag::create(
        &temp.journal(),
        journal_limits(),
        store,
        pin,
        chain,
        1,
        limits(),
    )?;
    let mut wallets = Vec::new();
    let mut bytes = Vec::new();
    for i in 0..8 {
        let proof = read(&inputs.join(format!("wallet.{i}")), MAX_PROOF_BYTES)?;
        wallets.push(VerifiedWallet::verify(pin, &registry, chain, &proof)?);
        bytes.push(proof);
    }
    let mut pairs = Vec::new();
    for i in 0..4 {
        let job = Job::wrap_pair((2 * i) as u8, wallets[2 * i], wallets[2 * i + 1])?;
        d.admit(
            job.clone(),
            vec![bytes[2 * i].clone(), bytes[2 * i + 1].clone()],
            0,
        )?;
        pairs.push(job);
    }
    let left = Job::merge(&pairs[0], &pairs[1])?;
    let right = Job::merge(&pairs[2], &pairs[3])?;
    d.admit(left.clone(), vec![], 0)?;
    d.admit(right.clone(), vec![], 0)?;
    let job = Job::merge(&left, &right)?;
    assert_eq!(job.id(), root_job(&wallets)?.id());
    assert_eq!(
        commitment::digest_bytes(job.expected().root)?,
        expected_root
    );
    d.admit(job.clone(), vec![], 0)?;
    let root_bytes = read(&bundle.join("node.3.0"), MAX_PROOF_BYTES)?;
    let ticket = VerifiedNode::verify(&job, &registry, &root_bytes)?;
    d.cache_node(ticket, root_bytes.clone(), 0)?;
    assert_eq!(d.core.job_count(), 7);
    assert_eq!(d.store_usage()?.artifacts, 9);
    drop(d);
    for (context, epoch) in [([0x5b; 32], 2), (chain, 1)] {
        let store = ArtifactStore::open(&temp.store(), store_limits())?;
        assert!(DurableDag::recover(
            &temp.journal(),
            journal_limits(),
            store,
            pin,
            &registry,
            context,
            epoch,
            limits()
        )
        .is_err());
    }
    let store = ArtifactStore::open(&temp.store(), store_limits())?;
    let recovery = DurableDag::recover(
        &temp.journal(),
        journal_limits(),
        store,
        pin,
        &registry,
        chain,
        2,
        limits(),
    )?;
    assert!(recovery.previous_candidates().is_empty());
    assert!(recovery.unresolved_attempts().is_empty());
    let mut d = recovery.resume(|_| panic!("unexpected worker"), || 100)?;
    assert_eq!(d.status(job.id())?, JobStatus::Completed);
    assert!(d.ready()?.is_empty());
    let (loaded, recovered_bytes) = d.store.load_node(ticket.artifact(), &job, &registry)?;
    assert_eq!(loaded.job(), job.id());
    assert_eq!(recovered_bytes, root_bytes);
    // The level-three/count-eight fixture is not a full block candidate.
    assert!(d.attach(job.id(), [1; 32], 1000, 100).is_err());
    let root_path = temp.store().join(format!(
        "n-{}.proof",
        artifact_store::hex(&ticket.artifact().digest_bytes())
    ));
    drop(d);
    let mut changed = root_bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&root_path, &changed)?;
    let store = ArtifactStore::open(&temp.store(), store_limits())?;
    assert!(DurableDag::recover(
        &temp.journal(),
        journal_limits(),
        store,
        pin,
        &registry,
        chain,
        3,
        limits()
    )
    .is_err());
    fs::write(&root_path, &root_bytes)?;
    let store = ArtifactStore::open(&temp.store(), store_limits())?;
    let recovery = DurableDag::recover(
        &temp.journal(),
        journal_limits(),
        store,
        pin,
        &registry,
        chain,
        3,
        limits(),
    )?;
    let mut d = recovery.resume(|_| panic!("unexpected worker"), || 200)?;
    assert_eq!(d.prune(209)?.jobs, 0);
    let removed = d.prune(210)?;
    assert_eq!(removed.jobs, 7);
    assert_eq!(removed.artifacts, 9);
    assert_eq!(d.store_usage()?.artifacts, 0);
    // Historical root verification is independent of the temporary job cache.
    VerifiedNode::verify(&job, &registry, &root_bytes)?;
    drop(d);
    let store = ArtifactStore::open(&temp.store(), store_limits())?;
    let recovery = DurableDag::recover(
        &temp.journal(),
        journal_limits(),
        store,
        pin,
        &registry,
        chain,
        4,
        limits(),
    )?;
    assert_eq!(recovery.restored.dag.job_count(), 0);
    Ok(())
}

// Reconstruct the historical V1 body from a freshly leased V3-only fixture.
// This is compatibility evidence only, not a production downgrade operation.
fn legacy_unbound_snapshot(d: &DurableDag) -> Vec<u8> {
    let mut bytes = d.core.snapshot().unwrap();
    assert_eq!(&bytes[..8], b"LVDAG003");
    assert_eq!(d.core.launch_root().unwrap().store, [0; 2]);
    let restored = restored(&bytes, &d.store, 2).unwrap();
    assert!(restored
        .attempts
        .iter()
        .all(|a| a.launch_binding == Some(dag::LaunchBinding::Unissued)));
    let trailer = 1 + 32 + 4 + 9 * restored.attempts.len();
    bytes.truncate(bytes.len() - trailer);
    bytes[..8].copy_from_slice(b"LVDAG001");
    bytes
}

#[test]
fn launch_bound_snapshot_preserves_roles_and_global_root_through_rebase() {
    use crate::block_v2::execution::dag::LaunchBinding;
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 2);
    let first = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let second = d
        .lease(leaf(1).id(), WorkerId(2), request(), 1, 100, 0)
        .unwrap();
    let legacy = legacy_unbound_snapshot(&d);
    assert_eq!(&legacy[..8], b"LVDAG001");
    assert!(restored(&legacy, &d.store, 2)
        .unwrap()
        .attempts
        .iter()
        .all(|a| a.launch_binding.is_none() && a.launch_root.is_none()));
    let claim = [3; 32];
    d.bind_launch(first, [7, 8], LaunchBinding::Direct).unwrap();
    d.bind_launch(second, [7, 8], LaunchBinding::Supervised(claim))
        .unwrap();
    assert_durable(&d);
    let bytes = d.core.snapshot().unwrap();
    assert_eq!(&bytes[..8], b"LVDAG002");
    assert_eq!(&bytes[8..legacy.len()], &legacy[8..]);
    let root = d.core.launch_root().unwrap();
    assert_eq!(root.journal, d.journal.identity().unwrap());
    assert_eq!(root.store, [7, 8]);
    let restored = restored(&bytes, &d.store, 2).unwrap();
    assert_eq!(
        restored.attempts[0].launch_binding,
        Some(LaunchBinding::Direct)
    );
    assert_eq!(
        restored.attempts[1].launch_binding,
        Some(LaunchBinding::Supervised(claim))
    );
    assert!(restored
        .attempts
        .iter()
        .all(|a| a.launch_root == Some(root)));
    drop(d);
    let recovery = recover(&temp, 2);
    let d = recovery.resume(|_| Ok(()), || 1000).unwrap();
    assert_eq!(d.core.launch_root(), Some(root));
    assert_eq!(d.resource_use().unwrap(), Resources::default());
    assert!(d.ready().unwrap().is_empty());
}

#[test]
fn launch_snapshot_trailer_rejects_malformed_metadata_before_proof_work() {
    use crate::block_v2::execution::dag::LaunchBinding;
    fn reject(bytes: &[u8]) {
        assert!(dag::snapshot::restore_with(
            bytes,
            pin(),
            [9; 32],
            2,
            limits(),
            |_| panic!("invalid admission reached wallet verification"),
            |_, _| panic!("invalid admission reached node verification")
        )
        .is_err());
    }
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 2);
    let first = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let second = d
        .lease(leaf(1).id(), WorkerId(2), request(), 1, 100, 0)
        .unwrap();
    let start = legacy_unbound_snapshot(&d).len();
    d.bind_launch(first, [7, 8], LaunchBinding::Direct).unwrap();
    d.bind_launch(second, [7, 8], LaunchBinding::Supervised([3; 32]))
        .unwrap();
    let bytes = d.core.snapshot().unwrap();
    assert_eq!(bytes.len() - start, 32 + 4 + 9 + 41);
    let mut unassigned = bytes.clone();
    unassigned[start + 16..start + 32].fill(0);
    reject(&unassigned);
    for end in start..bytes.len() {
        reject(&bytes[..end]);
    }
    let mut bad = bytes.clone();
    bad.push(0);
    reject(&bad);
    for offset in [start + 8, start + 24] {
        let mut bad = bytes.clone();
        bad[offset..offset + 8].fill(0);
        reject(&bad);
    }
    for count in [0u32, 3] {
        let mut bad = bytes.clone();
        bad[start + 32..start + 36].copy_from_slice(&count.to_le_bytes());
        reject(&bad);
    }
    for offset in [start + 44, start + 53] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        reject(&bad);
    }
    let first_sequence = u64::from_le_bytes(bytes[start + 36..start + 44].try_into().unwrap());
    for sequence in [0u64, first_sequence, 999] {
        let mut bad = bytes.clone();
        bad[start + 45..start + 53].copy_from_slice(&sequence.to_le_bytes());
        reject(&bad);
    }
    let mut bad = bytes.clone();
    bad[start + 54..].fill(255);
    reject(&bad);
}

#[test]
fn staged_snapshot_distinguishes_unissued_preparing_and_authorized() {
    use dag::LaunchBinding;
    let temp = Temp::new();
    let mut d = temp.create();
    candidate(&mut d, 1);
    let lease = d
        .lease(leaf(0).id(), WorkerId(1), request(), 1, 100, 0)
        .unwrap();
    let bytes = d.core.snapshot().unwrap();
    assert_eq!(&bytes[..8], b"LVDAG003");
    let unissued = restored(&bytes, &d.store, 2).unwrap();
    assert_eq!(
        unissued.attempts[0].launch_binding,
        Some(LaunchBinding::Unissued)
    );
    let root = unissued.attempts[0].launch_root.unwrap();
    assert_eq!(root.journal, d.journal.identity().unwrap());
    assert_ne!(root.journal[1], 0);
    assert_eq!(root.store, [0; 2]);
    // A complete V3 without its birth-time journal pin must fail before proof
    // callbacks, not only because a truncated trailer is invalid.
    let unissued_start = bytes.len() - (1 + 32 + 4 + 9);
    let mut unpinned = bytes.clone();
    unpinned[unissued_start] = 0;
    unpinned.drain(unissued_start + 1..unissued_start + 33);
    assert!(dag::snapshot::restore_with(
        &unpinned,
        pin(),
        [9; 32],
        2,
        limits(),
        |_| panic!("unpinned preparation reached proof work"),
        |_, _| panic!("unpinned preparation reached proof work")
    )
    .is_err());
    assert!(d
        .authorize_supervisor(lease, [7, 8], [3; 32], [9, 10])
        .is_err());
    d.bind_launch(lease, [7, 8], LaunchBinding::Preparing([3; 32]))
        .unwrap();
    let bytes = d.core.snapshot().unwrap();
    let preparing = restored(&bytes, &d.store, 2).unwrap();
    assert_eq!(
        preparing.attempts[0].launch_binding,
        Some(LaunchBinding::Preparing([3; 32]))
    );
    assert!(preparing.attempts[0].launch_root.is_some());
    assert!(d.bind_launch(lease, [7, 8], LaunchBinding::Direct).is_err());
    assert!(d
        .authorize_supervisor(lease, [7, 8], [4; 32], [9, 10])
        .is_err());
    d.authorize_supervisor(lease, [7, 8], [3; 32], [9, 10])
        .unwrap();
    assert_durable(&d);
    let bytes = d.core.snapshot().unwrap();
    let authorized = restored(&bytes, &d.store, 2).unwrap();
    assert_eq!(
        authorized.attempts[0].launch_binding,
        Some(LaunchBinding::Authorized {
            path: [3; 32],
            directory: [9, 10]
        })
    );
    assert!(d
        .authorize_supervisor(lease, [7, 8], [3; 32], [9, 10])
        .is_err());
    let start = bytes.len() - (1 + 32 + 4 + 57);
    let mut unassigned = bytes.clone();
    unassigned[start + 17..start + 33].fill(0);
    assert!(dag::snapshot::restore_with(
        &unassigned,
        pin(),
        [9; 32],
        2,
        limits(),
        |_| panic!("unassigned authorization reached proof work"),
        |_, _| panic!("unassigned authorization reached proof work")
    )
    .is_err());
    for offset in [start, start + 45] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(dag::snapshot::restore_with(
            &bad,
            pin(),
            [9; 32],
            2,
            limits(),
            |_| panic!("bad staged metadata reached proof work"),
            |_, _| panic!("bad staged metadata reached proof work")
        )
        .is_err());
    }
    for field in [start + 46, start + 86] {
        let mut bad = bytes.clone();
        if field == start + 46 {
            bad[field..field + 32].fill(255);
        } else {
            bad[field..field + 8].fill(0);
        }
        assert!(dag::snapshot::restore_with(
            &bad,
            pin(),
            [9; 32],
            2,
            limits(),
            |_| panic!("bad authorization reached proof work"),
            |_, _| panic!("bad authorization reached proof work")
        )
        .is_err());
    }
}

#[test]
fn empty_new_journal_retains_birth_identity_through_recovery() {
    let temp = Temp::new();
    let d = temp.create();
    let bytes = d.core.snapshot().unwrap();
    assert_eq!(&bytes[..8], b"LVDAG003");
    let root = d.core.launch_root().unwrap();
    assert_eq!(root.journal, d.journal.identity().unwrap());
    assert_eq!(root.store, [0; 2]);
    assert!(restored(&bytes, &d.store, 2).unwrap().attempts.is_empty());
    drop(d);
    let recovery = recover(&temp, 2);
    let d = recovery
        .resume(|_| panic!("empty journal has no attempts"), || 1000)
        .unwrap();
    assert_eq!(d.core.launch_root(), Some(root));
    assert_eq!(d.resource_use().unwrap(), Resources::default());
}
