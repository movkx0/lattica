//! Structural/native checks, not live service or cryptographic qualification.
use super::*;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::{Completion, Limits, WorkerId},
    job::{
        test_support::{pin, wallet},
        Job,
    },
    launch::{LaunchLimits, WorkerGate},
};
use rand::TryRng;
use std::{
    fs::{self, DirBuilder},
    os::unix::fs::{symlink, DirBuilderExt},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("lattica-supervisor-test-{}", hex(&nonce)));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("supervisor")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn resources() -> Resources {
    Resources {
        ram_bytes: 1 << 20,
        vram_bytes: 0,
        scratch_bytes: 1 << 20,
        threads: 1,
    }
}
fn fixture(temp: &Temp) -> (DurableDag, LaunchStore, Lease, Record) {
    let store = ArtifactStore::create(
        &temp.0.join("artifacts"),
        StoreLimits {
            bytes: 8 << 20,
            entries: 32,
        },
    )
    .unwrap();
    let mut owner = DurableDag::create(
        &temp.0.join("dag"),
        JournalLimits {
            snapshot_bytes: 256 << 10,
        },
        store,
        pin(),
        [9; 32],
        1,
        Limits {
            jobs: 32,
            candidates: 4,
            attempts: 16,
            artifact_bytes: 8 << 20,
            recovery_window_ms: 10,
            workers: resources(),
        },
    )
    .unwrap();
    let job = Job::wrap(0, wallet(1, &[1])).unwrap();
    owner.admit(job.clone(), vec![vec![1]], 0).unwrap();
    let mut root = job.clone();
    for level in 0..commitment::DEPTH {
        let empty = Job::empty(pin(), [9; 32], 1 << level, level).unwrap();
        owner.admit(empty.clone(), vec![], 0).unwrap();
        root = Job::merge(&root, &empty).unwrap();
        owner.admit(root.clone(), vec![], 0).unwrap();
    }
    owner.attach(root.id(), [1; 32], 10000, 0).unwrap();
    let lease = owner
        .lease(job.id(), WorkerId(1), resources(), 1, 9000, 0)
        .unwrap();
    let launch_path = temp.0.join("launches");
    let launches = LaunchStore::create(&launch_path, LaunchLimits { records: 4 }).unwrap();
    let record = Record {
        key: lease.process_key().unwrap(),
        resources: resources(),
        task: temp.0.join("task"),
        executable: temp.0.join("worker"),
        launch_path,
        launch_directory: launches.directory_identity().unwrap(),
        image: [1; 32],
        timeout_seconds: 60,
        token: None,
        dispatch_boot: None,
        observed: None,
        cancelled: false,
        revoked: false,
        stopped: false,
        admission: None,
    };
    (owner, launches, lease, record)
}
fn prepared(temp: &Temp) -> (DurableDag, LaunchStore, Lease, Supervisor) {
    let (mut owner, mut launches, lease, mut record) = fixture(temp);
    let path = path_digest(&temp.journal()).unwrap();
    launches
        .reserve_supervisor(&mut owner, lease, path)
        .unwrap();
    record.admission = Some(Admission {
        path,
        directory: [0; 2],
    });
    let supervisor = Supervisor::create_record(&temp.journal(), record).unwrap();
    owner
        .authorize_supervisor(
            lease,
            supervisor.record.launch_directory,
            path,
            supervisor.record.admission.as_ref().unwrap().directory,
        )
        .unwrap();
    (owner, launches, lease, supervisor)
}
fn bound(temp: &Temp) -> (DurableDag, LaunchStore, Lease, Supervisor) {
    let (mut owner, mut launches, lease, mut supervisor) = prepared(temp);
    let path = supervisor.record.admission.as_ref().unwrap().path;
    let mut record = supervisor.record.clone();
    record.token = Some(
        launches
            .issue_reserved(&mut owner, lease, b"native-request", [2; 32], path)
            .unwrap(),
    );
    supervisor.commit(record).unwrap();
    (owner, launches, lease, supervisor)
}
fn identity(record: &Record) -> Identity {
    Identity {
        boot: record.dispatch_boot.unwrap(),
        invocation: [3; 16],
        pid: 123,
        start_ticks: 7,
        group: format!("/user.slice/{}", record.unit()),
        device: 1,
        inode: 2,
    }
}
fn open(temp: &Temp, record: &Record) -> Supervisor {
    Supervisor::open_record(&temp.journal(), record.key, record.resources).unwrap()
}

#[test]
fn supervisor_codec_rejects_truncation_excess_and_invalid_state() {
    let temp = Temp::new();
    let (_, _, _, mut supervisor) = bound(&temp);
    supervisor.mark_dispatch([1; 16]).unwrap();
    supervisor
        .record_observation(identity(&supervisor.record))
        .unwrap();
    let record = supervisor.record.clone();
    let bytes = record.encode().unwrap();
    assert_eq!(Record::decode(&bytes).unwrap(), record);
    for end in 0..bytes.len() {
        assert!(Record::decode(&bytes[..end]).is_err(), "{end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Record::decode(&extra).is_err());
    for index in 0..8 {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert!(Record::decode(&bad).is_err());
    }
    let flags = bytes.len() - 48 - 3;
    for index in flags..flags + 3 {
        let mut bad = bytes.clone();
        bad[index] = 2;
        assert!(Record::decode(&bad).is_err());
    }
    assert!(Record::decode(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
    for index in 0..11 {
        let mut bad = record.clone();
        match index {
            0 => bad.token = None,
            1 => bad.dispatch_boot = None,
            2 => bad.dispatch_boot = Some([0; 16]),
            3 => bad.observed.as_mut().unwrap().invocation = [0; 16],
            4 => bad.observed.as_mut().unwrap().group = "/substitute.service".into(),
            5 => bad.revoked = true,
            6 => bad.stopped = true,
            7 => bad.task = "/tmp/../unsafe".into(),
            8 => bad.resources.vram_bytes = 1,
            9 => bad.timeout_seconds = 0,
            _ => bad.resources.threads = 249,
        }
        assert!(bad.encode().is_err(), "{index}");
    }
}

#[test]
fn supervisor_rejects_legacy_token_and_wrong_lease() {
    let temp = Temp::new();
    let (mut owner, mut launches, lease, mut record) = fixture(&temp);
    record.token = Some(launches.issue(&mut owner, lease, b"inline").unwrap());
    assert!(record.encode().is_err());
    let mut wrong = record.token.clone().unwrap().encode().unwrap();
    wrong[8] ^= 1;
    // Changed key may be canonical, but must still differ from this record.
    if let Ok(token) = Token::decode(&wrong) {
        record.token = Some(token);
        assert!(record.encode().is_err());
    }
}

#[test]
fn supervisor_owner_lock_and_authoritative_reopen_are_required() {
    let temp = Temp::new();
    let (_, _, _, supervisor) = bound(&temp);
    let record = supervisor.record.clone();
    assert!(Supervisor::open_record(&temp.journal(), record.key, record.resources).is_err());
    drop(supervisor);
    assert!(Supervisor::open_record(&temp.journal(), [1; 32], record.resources).is_err());
    let mut wrong = record.resources;
    wrong.ram_bytes += 1;
    assert!(Supervisor::open_record(&temp.journal(), record.key, wrong).is_err());
    let reopened = open(&temp, &record);
    assert_eq!(reopened.status().unwrap(), Status::Ready);
    drop(reopened);
    let alias = temp.0.join("alias");
    symlink(temp.journal(), &alias).unwrap();
    assert!(Supervisor::open_record(&alias, record.key, record.resources).is_err());
}

#[test]
fn supervisor_dispatch_persistence_forbids_retries_after_restart() {
    let temp = Temp::new();
    let (owner, mut launches, lease, mut supervisor) = bound(&temp);
    supervisor
        .mark_dispatch(os_worker::boot_id().unwrap())
        .unwrap();
    assert_eq!(supervisor.status().unwrap(), Status::DispatchUncertain);
    assert!(supervisor
        .mark_dispatch(os_worker::boot_id().unwrap())
        .is_err());
    let record = supervisor.record.clone();
    drop(supervisor);
    let mut supervisor = open(&temp, &record);
    assert_eq!(supervisor.status().unwrap(), Status::DispatchUncertain);
    assert!(supervisor
        .mark_dispatch(os_worker::boot_id().unwrap())
        .is_err());
    supervisor.cancel(&mut launches, lease).unwrap();
    assert_eq!(supervisor.status().unwrap(), Status::Cancelled);
    assert_eq!(
        supervisor
            .record
            .exit_basis(os_worker::boot_id().unwrap())
            .unwrap(),
        ExitBasis::Unknown
    );
    assert!(!supervisor.record.stopped);
    assert_eq!(owner.resource_use().unwrap(), resources());
    assert!(supervisor
        .mark_dispatch(os_worker::boot_id().unwrap())
        .is_err());
    assert!(WorkerGate::enter(
        &record.launch_path,
        record.token.as_ref().unwrap(),
        b"native-request"
    )
    .is_err());
    // Native test deliberately does not query the user bus. A live missing-unit
    // check must use the exclusive bounded integration controller.
}

#[test]
fn supervisor_observation_is_persistent_and_cannot_change_invocation() {
    let temp = Temp::new();
    let (_, _, _, mut supervisor) = bound(&temp);
    assert!(supervisor
        .record_observation(Identity {
            boot: [1; 16],
            invocation: [3; 16],
            pid: 123,
            start_ticks: 7,
            group: format!("/user.slice/{}", supervisor.service_name()),
            device: 1,
            inode: 2
        })
        .is_err());
    supervisor.mark_dispatch([1; 16]).unwrap();
    let observed = identity(&supervisor.record);
    supervisor.record_observation(observed.clone()).unwrap();
    supervisor.record_observation(observed.clone()).unwrap();
    let record = supervisor.record.clone();
    drop(supervisor);
    let mut supervisor = open(&temp, &record);
    assert_eq!(supervisor.observed_identity(), Some(&observed));
    for index in 0..4 {
        let mut wrong = observed.clone();
        match index {
            0 => wrong.invocation = [4; 16],
            1 => wrong.pid += 1,
            2 => wrong.start_ticks += 1,
            _ => wrong.inode += 1,
        }
        assert!(supervisor.record_observation(wrong).is_err());
    }
}

#[test]
fn supervisor_never_dispatched_receipt_does_not_accept_proof_or_drain_verifier() {
    let temp = Temp::new();
    let (mut owner, mut launches, lease, mut supervisor) = prepared(&temp);
    assert!(supervisor.mark_dispatch([1; 16]).is_err());
    let Reconciliation::Stopped(receipt) = supervisor.reconcile(&mut launches, lease).unwrap()
    else {
        panic!("never-dispatched lease not reconciled");
    };
    assert_eq!(receipt.lease(), lease);
    receipt.acknowledge(&mut owner, 1).unwrap();
    assert_eq!(supervisor.status().unwrap(), Status::Stopped);
    assert_eq!(owner.resource_use().unwrap(), resources());
    owner.begin_verification(lease, 2).unwrap();
    assert_eq!(owner.resource_use().unwrap(), resources());
    assert_eq!(
        owner.finish_verification(lease, None, 3).unwrap(),
        Completion::Rejected
    );
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
}

#[test]
fn supervisor_prior_boot_can_reconcile_only_after_revocation() {
    let temp = Temp::new();
    let (owner, mut launches, lease, mut supervisor) = bound(&temp);
    let mut old = os_worker::boot_id().unwrap();
    old[0] ^= 0x80;
    supervisor.mark_dispatch(old).unwrap();
    let record = supervisor.record.clone();
    drop(supervisor);
    let mut supervisor = open(&temp, &record);
    let Reconciliation::Stopped(receipt) = supervisor.reconcile(&mut launches, lease).unwrap()
    else {
        panic!("prior boot");
    };
    assert!(supervisor.record.cancelled && supervisor.record.revoked && supervisor.record.stopped);
    assert_eq!(owner.resource_use().unwrap(), resources()); // receipt not yet acknowledged
    drop(receipt);
    assert!(WorkerGate::enter(
        &record.launch_path,
        record.token.as_ref().unwrap(),
        b"native-request"
    )
    .is_err());
}

#[test]
fn supervisor_launch_store_substitution_retains_reservation() {
    let temp = Temp::new();
    let (owner, _, lease, mut supervisor) = bound(&temp);
    let mut other =
        LaunchStore::create(&temp.0.join("other-launches"), LaunchLimits { records: 4 }).unwrap();
    assert!(supervisor.reconcile(&mut other, lease).is_err());
    assert!(!supervisor.record.cancelled);
    assert_eq!(owner.resource_use().unwrap(), resources());
}

#[test]
fn supervisor_command_is_cpu_bounded_and_shell_free() {
    let temp = Temp::new();
    let (_, _, _, supervisor) = bound(&temp);
    let command = supervisor
        .command("lattica-v2-native-controller.service")
        .unwrap();
    assert_eq!(command.get_program(), "/usr/bin/systemd-run");
    let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
    for expected in [
        "--user",
        "--wait",
        "--expand-environment=no",
        "--slice=lattica-v2-grouped.slice",
        "--property=Type=exec",
        "--property=MemoryMax=1048576",
        "--property=MemorySwapMax=0",
        "--property=CPUQuota=100%",
        "--property=TasksMax=9",
        "--property=RuntimeMaxSec=90",
        "--property=KillMode=control-group",
        "--property=Restart=no",
        "--property=LimitCORE=0",
        "--setenv=LATTICA_V2_GPU_HASH=0",
        "--setenv=LATTICA_V2_QUOTIENT_FUSION=0",
        "--task",
    ] {
        assert!(args.contains(&expected), "{expected}");
    }
    assert_eq!(
        &args[args.len() - 4..],
        &[
            "--",
            supervisor.record.executable.to_str().unwrap(),
            "--task",
            supervisor.record.task.to_str().unwrap()
        ]
    );
}

#[test]
#[ignore = "explicit bounded controller: query a unique, never-started user unit"]
fn supervisor_missing_service_and_idle_gate_do_not_release_unknown_dispatch() {
    let temp = Temp::new();
    let (owner, mut launches, lease, mut supervisor) = bound(&temp);
    supervisor
        .mark_dispatch(os_worker::boot_id().unwrap())
        .unwrap();
    assert!(matches!(
        supervisor.reconcile(&mut launches, lease).unwrap(),
        Reconciliation::Quarantined
    ));
    let revoked = launches.revoke(lease).unwrap();
    assert!(launches.try_idle(&revoked).unwrap().is_some());
    assert!(!supervisor.record.stopped);
    assert_eq!(owner.resource_use().unwrap(), resources());
    let record = supervisor.record.clone();
    drop(supervisor);
    let mut supervisor = open(&temp, &record);
    assert!(matches!(
        supervisor.reconcile(&mut launches, lease).unwrap(),
        Reconciliation::Quarantined
    ));
    assert!(supervisor
        .mark_dispatch(os_worker::boot_id().unwrap())
        .is_err());
}

#[test]
#[ignore = "subprocess-only abrupt journal boundary helper"]
fn supervisor_crash_helper() {
    let Some(path) = std::env::var_os("LATTICA_V2_SUPERVISOR_CRASH_PATH") else {
        return;
    };
    let temp = std::mem::ManuallyDrop::new(Temp(PathBuf::from(path)));
    let (_, mut launches, lease, mut supervisor) = bound(&temp);
    let stage: u8 = std::env::var("LATTICA_V2_SUPERVISOR_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    if stage >= 1 {
        supervisor
            .mark_dispatch(os_worker::boot_id().unwrap())
            .unwrap();
    }
    if stage == 2 {
        supervisor
            .record_observation(identity(&supervisor.record))
            .unwrap();
    }
    if stage == 3 {
        let mut next = supervisor.record.clone();
        next.cancelled = true;
        supervisor.commit(next).unwrap();
    }
    if stage == 4 {
        supervisor.cancel(&mut launches, lease).unwrap();
    }
    std::process::exit(71);
}

#[test]
fn supervisor_abrupt_journal_boundaries_remain_fenced() {
    for stage in 0..=4 {
        let temp = Temp::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "block_v2::execution::supervisor::tests::supervisor_crash_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("LATTICA_V2_SUPERVISOR_CRASH_PATH", &temp.0)
            .env("LATTICA_V2_SUPERVISOR_CRASH_STAGE", stage.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(71), "stage={stage}");
        let (log, bytes) = SnapshotLog::open(
            &temp.journal(),
            JournalLimits {
                snapshot_bytes: MAX_RECORD_BYTES,
            },
        )
        .unwrap();
        let record = Record::decode(&bytes).unwrap();
        drop(log);
        let mut recovered = open(&temp, &record);
        assert!(!recovered.record.stopped);
        if stage >= 1 {
            assert!(recovered
                .mark_dispatch(os_worker::boot_id().unwrap())
                .is_err());
        }
        assert_eq!(recovered.record.observed.is_some(), stage == 2);
        assert_eq!(recovered.record.cancelled, stage >= 3);
        assert_eq!(recovered.record.revoked, stage == 4);
    }
}

#[test]
fn admission_codec_preserves_legacy_and_rejects_invalid_binding() {
    let temp = Temp::new();
    let (owner, _, lease, legacy) = fixture(&temp);
    let encoded = legacy.encode().unwrap();
    assert_eq!(&encoded[..8], MAGIC);
    assert_eq!(Record::decode(&encoded).unwrap(), legacy);
    let legacy = Supervisor::create_record(&temp.journal(), legacy).unwrap();
    assert!(legacy.check_admission(&owner, lease).is_err());
    drop(legacy);
    // V3 unissued authority cannot be downgraded into a historical record.
    assert!(Supervisor::reopen(&temp.journal(), &owner, lease).is_err());
    let historical = PreviousAttempt {
        lease,
        resources: resources(),
        status: crate::block_v2::execution::dag::AttemptStatus::Leased,
        worker_stopped: false,
        verification_active: false,
        input_manifest: vec![],
        launch_binding: None,
        launch_root: None,
    };
    assert!(Supervisor::recover(&temp.journal(), &historical).is_ok());
    let temp = Temp::new();
    let (owner, _, lease, supervisor) = bound(&temp);
    assert!(supervisor.check_admission(&owner, lease).is_ok());
    let bytes = supervisor.record.encode().unwrap();
    assert_eq!(&bytes[..8], BOUND_MAGIC);
    for bad_binding in [
        Admission {
            path: [255; 32],
            directory: [1, 2],
        },
        Admission {
            path: supervisor.record.admission.as_ref().unwrap().path,
            directory: [1, 0],
        },
    ] {
        let mut bad = supervisor.record.clone();
        bad.admission = Some(bad_binding);
        assert!(bad.encode().is_err());
    }
}

#[test]
#[ignore = "subprocess-only preparation crash helper"]
fn preparation_crash_helper() {
    let Some(path) = std::env::var_os("LATTICA_V2_PREPARATION_CRASH_PATH") else {
        return;
    };
    let temp = std::mem::ManuallyDrop::new(Temp(PathBuf::from(path)));
    let (mut owner, mut launches, lease, record) = fixture(&temp);
    Supervisor::prepare(
        &temp.journal(),
        &mut owner,
        lease,
        &mut launches,
        &record.launch_path,
        &record.task,
        &std::env::current_exe().unwrap(),
        60,
    )
    .unwrap();
    panic!("preparation crash boundary was not reached");
}

#[test]
fn abrupt_supervisor_preparation_distinguishes_journal_from_authorization() {
    for stage in ["journal", "authorized"] {
        let temp = Temp::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "block_v2::execution::supervisor::tests::preparation_crash_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("LATTICA_V2_PREPARATION_CRASH_PATH", &temp.0)
            .env("LATTICA_V2_PREPARATION_CRASH_STAGE", stage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77), "{stage}");
        let (log, bytes) = SnapshotLog::open(
            &temp.0.join("dag"),
            JournalLimits {
                snapshot_bytes: 256 << 10,
            },
        )
        .unwrap();
        let store = ArtifactStore::open(
            &temp.0.join("artifacts"),
            StoreLimits {
                bytes: 8 << 20,
                entries: 32,
            },
        )
        .unwrap();
        // Structural fixture replay only; pinned CPU recovery is a separate test.
        let restored = crate::block_v2::execution::dag::snapshot::restore_with(
            &bytes,
            pin(),
            [9; 32],
            2,
            Limits {
                jobs: 32,
                candidates: 4,
                attempts: 16,
                artifact_bytes: 8 << 20,
                recovery_window_ms: 10,
                workers: resources(),
            },
            |id| {
                let bytes = store.read_exact(id)?;
                Ok((wallet(1, &bytes), bytes))
            },
            |_, _| panic!("preparation fixture has no completed recursive proof"),
        )
        .unwrap();
        assert_eq!(restored.attempts.len(), 1);
        let attempt = &restored.attempts[0];
        assert_eq!(
            attempt.launch_root.unwrap().journal,
            log.identity().unwrap()
        );
        assert!(!attempt.verification_active);
        let mut launches =
            LaunchStore::open(&temp.0.join("launches"), LaunchLimits { records: 1 }).unwrap();
        assert_eq!(launches.record_count().unwrap(), 1);
        if stage == "journal" {
            assert_eq!(
                attempt.launch_binding,
                Some(LaunchBinding::Preparing(
                    path_digest(&temp.journal()).unwrap()
                ))
            );
            assert!(Supervisor::recover(&temp.journal(), attempt).is_err());
            let receipt = launches.reconcile_preparation(attempt).unwrap();
            assert_eq!(receipt.lease(), attempt.lease);
        } else {
            assert!(matches!(
                attempt.launch_binding,
                Some(LaunchBinding::Authorized { .. })
            ));
            assert!(launches.reconcile_preparation(attempt).is_err());
            let mut supervisor = Supervisor::recover(&temp.journal(), attempt).unwrap();
            assert!(supervisor.record.token.is_none());
            assert!(matches!(
                supervisor.reconcile(&mut launches, attempt.lease).unwrap(),
                Reconciliation::Stopped(_)
            ));
        }
        assert_eq!(launches.record_count().unwrap(), 1);
        assert!(!temp.0.join("task").exists());
    }
}

#[test]
fn admitted_supervisor_rejects_copied_or_replaced_journal_directory() {
    for replace in [false, true] {
        let temp = Temp::new();
        let (owner, _, lease, supervisor) = bound(&temp);
        let bytes = supervisor.record.encode().unwrap();
        let key = supervisor.record.key;
        drop(supervisor);
        let destination = if replace {
            fs::rename(temp.journal(), temp.0.join("original-journal")).unwrap();
            temp.journal()
        } else {
            temp.0.join("copied-journal")
        };
        let mut log = SnapshotLog::create(
            &destination,
            JournalLimits {
                snapshot_bytes: MAX_RECORD_BYTES,
            },
        )
        .unwrap();
        log.commit(&bytes).unwrap();
        drop(log);
        assert!(Supervisor::open_record(&destination, key, resources()).is_err());
        assert!(Supervisor::reopen(&destination, &owner, lease).is_err());
        assert_eq!(owner.resource_use().unwrap(), resources());
    }
}

#[test]
fn admitted_supervisor_cannot_be_prepared_at_another_path_or_store() {
    let temp = Temp::new();
    let (mut owner, mut launches, lease, supervisor) = bound(&temp);
    let original = supervisor.record.admission.as_ref().unwrap().path;
    assert!(launches
        .reserve_supervisor(&mut owner, lease, original)
        .is_err());
    assert!(launches
        .reserve_supervisor(
            &mut owner,
            lease,
            path_digest(&temp.0.join("other")).unwrap()
        )
        .is_err());
    let mut other =
        LaunchStore::create(&temp.0.join("other-launches"), LaunchLimits { records: 4 }).unwrap();
    assert!(other
        .reserve_supervisor(&mut owner, lease, original)
        .is_err());
    assert_eq!(other.record_count().unwrap(), 0);
}
