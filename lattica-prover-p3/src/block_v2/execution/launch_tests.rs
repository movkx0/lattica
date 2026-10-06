//! Launch lifecycle tests use structural jobs, not cryptographic proof fixtures.
//! Subprocess boundaries exercise the same private persistence primitives used
//! after public lease validation. A lock-only check is never an OS-stop claim.
use super::*;
use crate::block_v2::{
    commitment::DEPTH,
    execution::{
        artifact_store::{ArtifactStore, StoreLimits},
        dag::{CandidateId, Limits, WorkerId},
        job::{
            test_support::{pin, wallet},
            Job,
        },
        journal::JournalLimits,
    },
};
use rand::TryRng;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const REQUEST: &[u8] = b"bounded immutable public CPU assignment";
const CHILD_TEST: &str = "block_v2::execution::launch::tests::subprocess_helper";
const FAULTS: [Fault; 8] = [
    Fault::WorkerLockDurable,
    Fault::IntentDurable,
    Fault::PermitBeforeDirectorySync,
    Fault::PermitDurable,
    Fault::RevocationCreated,
    Fault::RevocationDurable,
    Fault::PermitRemoved,
    Fault::RevocationComplete,
];

struct Temp {
    path: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("lattica-launch-test-{}", hex(&nonce)));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self { path }
    }
    fn launches(&self) -> PathBuf {
        self.path.join("launches")
    }
    fn gate(&self) -> LaunchStore {
        LaunchStore::create(&self.launches(), limits()).unwrap()
    }
    fn owner(&self) -> (DurableDag, Lease, CandidateId) {
        let store = ArtifactStore::create(
            &self.path.join("artifacts"),
            StoreLimits {
                bytes: 32 * (1 << 20),
                entries: 128,
            },
        )
        .unwrap();
        let mut d = DurableDag::create(
            &self.path.join("journal"),
            JournalLimits {
                snapshot_bytes: 256 * 1024,
            },
            store,
            pin(),
            [9; 32],
            1,
            Limits {
                jobs: 128,
                candidates: 8,
                attempts: 128,
                artifact_bytes: 32 * (1 << 20),
                recovery_window_ms: 10,
                workers: request(),
            },
        )
        .unwrap();
        let leaf = Job::wrap(0, wallet(1, &[1])).unwrap();
        d.admit(leaf.clone(), vec![vec![1]], 0).unwrap();
        let mut root = leaf.clone();
        for level in 0..DEPTH {
            let right = Job::empty(pin(), [9; 32], 1 << level, level).unwrap();
            d.admit(right.clone(), vec![], 0).unwrap();
            root = Job::merge(&root, &right).unwrap();
            d.admit(root.clone(), vec![], 0).unwrap();
        }
        let candidate = d.attach(root.id(), [1; 32], 1000, 0).unwrap();
        let lease = d
            .lease(leaf.id(), WorkerId(1), request(), 1, 100, 0)
            .unwrap();
        (d, lease, candidate)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
#[test]
fn recovered_revocation_rejects_a_substituted_launch_directory() {
    let temp = Temp::new();
    let other = Temp::new();
    let mut launches = temp.gate();
    let mut wrong = other.gate();
    let (mut owner, lease, _) = temp.owner();
    let token = launches.issue(&mut owner, lease, REQUEST).unwrap();
    let previous = super::super::journal::PreviousAttempt {
        lease,
        resources: request(),
        status: super::super::dag::AttemptStatus::Leased,
        worker_stopped: false,
        verification_active: false,
        input_manifest: Vec::new(),
        launch_binding: None,
        launch_root: Some(super::super::dag::LaunchRoot {
            journal: [1, 1],
            store: launches.directory.identity().unwrap(),
        }),
    };
    assert!(wrong.revoke_recovered(&previous).is_err());
    drop(WorkerGate::enter(&temp.launches(), &token, REQUEST).unwrap());
    let revoked = launches.revoke_recovered(&previous).unwrap();
    assert!(launches.try_idle(&revoked).unwrap().is_some());
    assert!(WorkerGate::enter(&temp.launches(), &token, REQUEST).is_err());
}

fn limits() -> LaunchLimits {
    LaunchLimits { records: 16 }
}
fn request() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 0,
        scratch_bytes: 100,
        threads: 1,
    }
}
fn token(gate: &LaunchStore, lease: Lease) -> Token {
    Token {
        key: lease.process_key().unwrap(),
        root: gate.directory.identity().unwrap(),
        resources: request(),
        request: request_digest(REQUEST).unwrap(),
        execution: None,
    }
}

#[test]
fn execution_bound_token_preserves_legacy_and_rejects_substitution() {
    let t = Temp::new();
    let mut gate = t.gate();
    let (mut owner, lease, _) = t.owner();
    let legacy = token(&gate, lease);
    assert_eq!(legacy.encode().unwrap().len(), TOKEN_BYTES);
    assert_eq!(Token::decode(&legacy.encode().unwrap()).unwrap(), legacy);
    assert!(legacy.check_execution([0; 32]).is_err());
    let specification = digest(0x4c42563277, b"pinned execution spec").unwrap();
    let bound = gate
        .issue_bound(&mut owner, lease, REQUEST, specification)
        .unwrap();
    let bytes = bound.encode().unwrap();
    assert_eq!(bytes.len(), MAX_TOKEN_BYTES);
    assert_eq!(Token::decode(&bytes).unwrap(), bound);
    bound.check_execution(specification).unwrap();
    assert!(bound.check_execution([0; 32]).is_err());
    for end in 0..bytes.len() {
        assert!(Token::decode(&bytes[..end]).is_err());
    }
    for index in [0, 8, BODY, MAX_TOKEN_BYTES - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(Token::decode(&changed).is_err());
    }
    let mut changed = bytes.clone();
    changed[..8].copy_from_slice(MAGIC);
    assert!(Token::decode(&changed).is_err());
    let mut extra = bytes;
    extra.push(0);
    assert!(Token::decode(&extra).is_err());
    let mut noncanonical = bound.clone();
    noncanonical.execution = Some([255; 32]);
    assert!(noncanonical.encode().is_err());
    let mut wrong = bound.clone();
    wrong.execution = Some([0; 32]);
    assert!(WorkerGate::enter(&t.launches(), &wrong, REQUEST).is_err());
    drop(WorkerGate::enter(&t.launches(), &bound, REQUEST).unwrap());
    assert!(WorkerGate::enter(&t.launches(), &bound, REQUEST).is_err());
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
fn rewrite_checksum(bytes: &mut [u8]) {
    let checksum = digest(INTENT_DOMAIN, &bytes[..BODY]).unwrap();
    bytes[BODY..].copy_from_slice(&checksum);
}

#[test]
fn token_roundtrip_binds_exact_lease_resources_and_request() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = temp.gate();
    let t = gate.issue(&mut owner, lease, REQUEST).unwrap();
    assert_eq!(t.key(), lease.process_key().unwrap());
    assert_eq!(t.resources(), owner.assignment(lease).unwrap().resources());
    assert_eq!(
        t.service_name(),
        format!("lattica-v2-worker-{}.service", hex(&t.key()))
    );
    let bytes = t.encode().unwrap();
    assert_eq!(bytes.len(), TOKEN_BYTES);
    assert_eq!(Token::decode(&bytes).unwrap(), t);
    assert_eq!(token(&gate, lease), t);
    for at in [0, 8, 40, 48, 56, 64, 72, 80, 84, BODY] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(Token::decode(&changed).is_err(), "unbound offset {at}");
    }
    for len in [0, 7, 8, BODY, TOKEN_BYTES - 1] {
        assert!(Token::decode(&bytes[..len]).is_err());
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Token::decode(&longer).is_err());
}

#[test]
fn token_rejects_noncanonical_digests_and_invalid_cpu_budgets() {
    let temp = Temp::new();
    let (_, lease, _) = temp.owner();
    let gate = temp.gate();
    let t = token(&gate, lease);
    for at in [8, 84] {
        let mut bytes = t.encode().unwrap();
        bytes[at..at + 8].fill(255);
        rewrite_checksum(&mut bytes);
        assert!(Token::decode(&bytes).is_err());
    }
    for resources in [
        Resources {
            ram_bytes: 0,
            ..request()
        },
        Resources {
            threads: 0,
            ..request()
        },
        Resources {
            ram_bytes: u64::MAX,
            ..request()
        },
        Resources {
            vram_bytes: u64::MAX,
            ..request()
        },
        Resources {
            scratch_bytes: u64::MAX,
            ..request()
        },
        Resources {
            threads: u32::MAX,
            ..request()
        },
    ] {
        let mut invalid = t.clone();
        invalid.resources = resources;
        assert!(invalid.encode().is_err());
    }
    // The issuing DAG and device admission bind actual capacity. Tokens carry
    // that reservation without imposing a historical single-workstation cap.
    let mut admitted = t.clone();
    admitted.resources = Resources {
        ram_bytes: 46 << 30,
        vram_bytes: 13 << 30,
        scratch_bytes: 129 << 30,
        threads: 257,
    };
    let encoded = admitted.encode().unwrap();
    assert_eq!(Token::decode(&encoded).unwrap(), admitted);
    // A valid checksum cannot turn a zero-RAM request into an admitted token.
    let mut bytes = t.encode().unwrap();
    bytes[56..64].fill(0);
    rewrite_checksum(&mut bytes);
    assert!(Token::decode(&bytes).is_err());
    assert!(request_digest(&[]).is_err());
    assert!(request_digest(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
    assert!(request_digest(&vec![0; MAX_REQUEST_BYTES]).is_ok());
}

#[test]
fn issuance_requires_current_durable_assignment_and_prewrite_errors_do_not_poison() {
    let temp = Temp::new();
    let (mut owner, lease, candidate) = temp.owner();
    let mut gate = temp.gate();
    assert!(gate.issue(&mut owner, lease, &[]).is_err());
    assert_eq!(gate.record_count().unwrap(), 0);
    let foreign = Temp::new();
    let (mut other, other_lease, _) = foreign.owner();
    assert_ne!(
        lease.process_key().unwrap(),
        other_lease.process_key().unwrap()
    );
    assert!(gate.issue(&mut other, lease, REQUEST).is_err());
    owner.cancel(candidate, 1).unwrap();
    assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
    assert_eq!(gate.record_count().unwrap(), 0);
    assert_eq!(owner.resource_use().unwrap(), request());
    assert!(gate.issue(&mut other, other_lease, REQUEST).is_ok());
}

#[test]
fn issuance_and_entry_are_single_use_even_after_worker_exit_and_store_reopen() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = temp.gate();
    let t = gate.issue(&mut owner, lease, REQUEST).unwrap();
    assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
    assert!(WorkerGate::enter(&temp.launches(), &t, b"substituted").is_err());
    assert!(!temp.launches().join(name(t.key, "started")).exists());
    let active = WorkerGate::enter(&temp.launches(), &t, REQUEST).unwrap();
    assert_eq!(active.token(), &t);
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    drop(active);
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    drop(gate);
    let mut gate = LaunchStore::open(&temp.launches(), limits()).unwrap();
    assert_eq!(gate.record_count().unwrap(), 1);
    assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    let revoked = gate.revoke(lease).unwrap();
    assert_eq!(revoked.lease(), lease);
    assert!(gate.try_idle(&revoked).unwrap().is_some());
}

#[test]
fn intent_and_directory_identity_reject_substitution_without_consuming_permission() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = temp.gate();
    let t = gate.issue(&mut owner, lease, REQUEST).unwrap();
    for modified in [
        Token {
            resources: Resources {
                ram_bytes: 101,
                ..request()
            },
            ..t.clone()
        },
        Token {
            request: request_digest(b"different").unwrap(),
            ..t.clone()
        },
        Token {
            root: [t.root[0], t.root[1] + 1],
            ..t.clone()
        },
    ] {
        assert!(WorkerGate::enter(&temp.launches(), &modified, REQUEST).is_err());
    }
    let other = Temp::new();
    let other_gate = other.gate();
    assert!(WorkerGate::enter(&other.launches(), &t, REQUEST).is_err());
    assert!(other_gate.try_idle(&gate.revoke(lease).unwrap()).is_err());
    assert!(!temp.launches().join(name(t.key, "started")).exists());
}

#[test]
fn revocation_fences_never_issued_and_previously_issued_late_starts() {
    for issued in [false, true] {
        let temp = Temp::new();
        let (mut owner, lease, _) = temp.owner();
        let mut gate = temp.gate();
        let t = if issued {
            gate.issue(&mut owner, lease, REQUEST).unwrap()
        } else {
            token(&gate, lease)
        };
        let revoked = gate.revoke(lease).unwrap();
        assert!(gate.try_idle(&revoked).unwrap().is_some());
        assert!(gate.revoke(lease).is_ok());
        assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
        drop(gate);
        let mut gate = LaunchStore::open(&temp.launches(), limits()).unwrap();
        let revoked = gate.revoke(lease).unwrap();
        assert!(gate.try_idle(&revoked).unwrap().is_some());
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
        assert_eq!(owner.resource_use().unwrap(), request());
    }
}

#[test]
fn record_capacity_preserves_existing_revocation_and_never_releases_unfenced_resources() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = LaunchStore::create(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
    gate.issue(&mut owner, lease, REQUEST).unwrap();
    let other_temp = Temp::new();
    let (mut other, other_lease, _) = other_temp.owner();
    assert!(gate.issue(&mut other, other_lease, REQUEST).is_err());
    assert!(gate.revoke(other_lease).is_err());
    assert_eq!(other.resource_use().unwrap(), request());
    assert!(other.assignment(other_lease).is_ok());
    let revoked = gate.revoke(lease).unwrap();
    assert!(gate.try_idle(&revoked).unwrap().is_some());
    assert_eq!(gate.record_count().unwrap(), 1);
    assert!(LaunchLimits { records: 0 }.validate().is_err());
    assert!(LaunchLimits { records: 16385 }.validate().is_err());
}

#[test]
fn exclusive_owner_and_private_directory_requirements_fail_closed() {
    let temp = Temp::new();
    let gate = temp.gate();
    assert!(LaunchStore::open(&temp.launches(), limits()).is_err());
    assert!(LaunchStore::create(&temp.launches(), limits()).is_err());
    assert!(LaunchStore::create(Path::new("relative"), limits()).is_err());
    let alias = temp.path.join("alias");
    symlink(temp.launches(), &alias).unwrap();
    assert!(LaunchStore::open(&alias, limits()).is_err());
    drop(gate);
    fs::set_permissions(temp.launches(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(LaunchStore::open(&temp.launches(), limits()).is_err());
    fs::set_permissions(temp.launches(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(LaunchStore::open(&temp.launches(), limits()).is_ok());
}

#[test]
fn descriptor_anchor_survives_directory_rename_and_rejects_replacement() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = temp.gate();
    let t = gate.issue(&mut owner, lease, REQUEST).unwrap();
    let moved = temp.path.join("moved");
    fs::rename(temp.launches(), &moved).unwrap();
    let replacement = temp.gate();
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    let worker = WorkerGate::enter(&moved, &t, REQUEST).unwrap();
    let revoked = gate.revoke(lease).unwrap();
    assert!(gate.try_idle(&revoked).unwrap().is_none());
    assert!(replacement.try_idle(&revoked).is_err());
    drop(worker);
    assert!(gate.try_idle(&revoked).unwrap().is_some());
}

#[test]
fn changed_owner_lock_links_permissions_and_unknown_inventory_are_rejected() {
    for case in 0..6 {
        let temp = Temp::new();
        let gate = temp.gate();
        let lock = temp.launches().join(OWNER);
        match case {
            0 => {
                fs::remove_file(&lock).unwrap();
                private_file(&lock, &[]);
            }
            1 => {
                fs::hard_link(&lock, temp.path.join("outside-link")).unwrap();
            }
            2 => fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap(),
            3 => private_file(&temp.launches().join("unknown"), &[]),
            4 => {
                fs::remove_file(&lock).unwrap();
                let target = temp.path.join("target");
                private_file(&target, &[]);
                symlink(target, &lock).unwrap();
            }
            _ => {
                fs::remove_file(&lock).unwrap();
                private_file(&lock, &[1]);
            }
        }
        if case != 3 {
            assert!(gate.record_count().is_err());
        }
        drop(gate);
        // A same-uid owner-lock replacement is detected by the old owner, but a
        // well-formed new empty lock has no historical identity after reopening.
        if case != 0 {
            assert!(LaunchStore::open(&temp.launches(), limits()).is_err());
        }
    }
}

#[test]
fn bounded_inventory_rejects_bad_names_sizes_links_and_nonempty_markers() {
    for case in 0..7 {
        let temp = Temp::new();
        let (_, lease, _) = temp.owner();
        let gate = temp.gate();
        let t = token(&gate, lease);
        let path = temp.launches().join(name(t.key, "intent"));
        drop(gate);
        match case {
            0 => private_file(&path, &vec![0; MAX_TOKEN_BYTES + 1]),
            1 => private_file(&temp.launches().join(name(t.key, "permit")), &[1]),
            2 => private_file(&temp.launches().join(name(t.key, "started")), &[1]),
            3 => {
                private_file(&path, &[]);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            4 => {
                let target = temp.path.join("target");
                private_file(&target, &[]);
                symlink(target, path).unwrap();
            }
            5 => {
                private_file(&path, &[]);
                fs::hard_link(&path, temp.path.join("outside-link")).unwrap();
            }
            _ => private_file(
                &temp.launches().join(format!("{}.invalid", hex(&t.key))),
                &[],
            ),
        }
        assert!(
            LaunchStore::open(&temp.launches(), limits()).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn inventory_quota_is_checked_on_reopen_and_partial_intents_are_never_permissions() {
    let temp = Temp::new();
    let (_, lease, _) = temp.owner();
    let gate = temp.gate();
    let t = token(&gate, lease);
    private_file(&temp.launches().join(name(t.key, "worker")), &[]);
    private_file(&temp.launches().join(name(t.key, "intent")), &[1, 2, 3]);
    private_file(&temp.launches().join(name(t.key, "permit")), &[]);
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    drop(gate);
    let mut gate = LaunchStore::open(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
    let revoked = gate.revoke(lease).unwrap();
    assert!(gate.try_idle(&revoked).unwrap().is_some());
    let second = request_digest(b"second key").unwrap();
    private_file(&temp.launches().join(name(second, "revoked")), &[]);
    drop(gate);
    assert!(LaunchStore::open(&temp.launches(), LaunchLimits { records: 1 }).is_err());
}

#[test]
fn missing_worker_lock_cannot_be_replaced_beside_issued_or_consumed_records() {
    for suffix in ["intent", "permit", "started"] {
        let temp = Temp::new();
        let (_, lease, _) = temp.owner();
        let mut gate = temp.gate();
        let t = token(&gate, lease);
        private_file(&temp.launches().join(name(t.key, suffix)), &[]);
        assert!(gate.revoke(lease).is_err());
        assert!(gate.record_count().is_err());
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
        assert!(!temp.launches().join(name(t.key, "worker")).exists());
    }
}

#[test]
fn injected_persistence_errors_poison_owner_until_reopen_and_revoke() {
    for (index, stage) in FAULTS.into_iter().enumerate() {
        let temp = Temp::new();
        let (mut owner, lease, _) = temp.owner();
        let mut gate = temp.gate();
        let t = if index >= 4 {
            gate.issue(&mut owner, lease, REQUEST).unwrap()
        } else {
            token(&gate, lease)
        };
        gate.fault = Some(stage);
        if index < 4 {
            assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
        } else {
            assert!(gate.revoke(lease).is_err());
        }
        assert!(gate.record_count().is_err());
        drop(gate);
        let mut gate = LaunchStore::open(&temp.launches(), limits()).unwrap();
        assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
        let revoked = gate.revoke(lease).unwrap();
        assert!(gate.try_idle(&revoked).unwrap().is_some());
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    }
}

fn child(temp: &Temp, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            CHILD_TEST,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("LATTICA_LAUNCH_TEST_ROOT", &temp.path)
        .env("LATTICA_LAUNCH_TEST_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "bounded subprocess helper, invoked by launch lifecycle tests"]
fn subprocess_helper() {
    let root = PathBuf::from(std::env::var_os("LATTICA_LAUNCH_TEST_ROOT").unwrap());
    let mode = std::env::var("LATTICA_LAUNCH_TEST_MODE").unwrap();
    let t = Token::decode(&fs::read(root.join("token")).unwrap()).unwrap();
    let launches = root.join("launches");
    if mode == "hold" {
        let _worker = WorkerGate::enter(&launches, &t, REQUEST).unwrap();
        private_file(&root.join("ready"), b"lock held");
        let mut byte = [0; 1];
        std::io::stdin().read_exact(&mut byte).unwrap();
        return;
    }
    let index: usize = mode.parse().unwrap();
    if index < 8 {
        let mut gate = LaunchStore::open(&launches, limits()).unwrap();
        gate.fault = Some(FAULTS[index]);
        gate.crash = true;
        if index < 4 {
            gate.publish(&t).unwrap();
        } else {
            gate.revoke_key(t.key).unwrap();
        }
    } else {
        let fault = match index {
            8 => EntryFault::StartedCreated,
            9 => EntryFault::StartedDurable,
            _ => panic!("unknown child stage"),
        };
        let _worker = WorkerGate::enter_inner(&launches, &t, REQUEST, Some(fault)).unwrap();
    }
    panic!("fault did not terminate subprocess");
}

#[test]
fn abrupt_exit_at_ten_boundaries_never_revives_consumed_or_revoked_permission() {
    for index in 0..10 {
        let temp = Temp::new();
        let (mut owner, lease, _) = temp.owner();
        let mut gate = temp.gate();
        let t = if index >= 4 {
            gate.issue(&mut owner, lease, REQUEST).unwrap()
        } else {
            token(&gate, lease)
        };
        private_file(&temp.path.join("token"), &t.encode().unwrap());
        drop(gate);
        let mut child = ChildGuard(child(&temp, &index.to_string()).spawn().unwrap());
        let status = child.0.wait().unwrap();
        assert_eq!(
            status.code(),
            Some(if index < 8 { 76 } else { 77 }),
            "stage {index}"
        );
        let mut gate = LaunchStore::open(&temp.launches(), limits()).unwrap();
        assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
        if index >= 4 {
            assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
        }
        let revoked = gate.revoke(lease).unwrap();
        assert!(gate.try_idle(&revoked).unwrap().is_some());
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
        assert_eq!(owner.resource_use().unwrap(), request());
    }
}

#[test]
fn live_child_holds_reservation_boundary_until_exact_spawned_process_is_reaped() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = temp.gate();
    let t = gate.issue(&mut owner, lease, REQUEST).unwrap();
    private_file(&temp.path.join("token"), &t.encode().unwrap());
    let mut child = ChildGuard(child(&temp, "hold").spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !temp.path.join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before handshake"
        );
        assert!(Instant::now() < deadline, "worker did not acquire gate");
        std::thread::sleep(Duration::from_millis(10));
    }
    let revoked = gate.revoke(lease).unwrap();
    assert!(child.0.try_wait().unwrap().is_none());
    assert!(gate.try_idle(&revoked).unwrap().is_none());
    assert_eq!(owner.resource_use().unwrap(), request());
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    drop(gate);
    let mut gate = LaunchStore::open(&temp.launches(), limits()).unwrap();
    let revoked = gate.revoke(lease).unwrap();
    assert!(gate.try_idle(&revoked).unwrap().is_none());
    // The test owns this exact Child handle. No PID search or unrelated kill.
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    let idle = gate.try_idle(&revoked).unwrap().unwrap();
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    drop(idle);
    assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    // Gate operations never acknowledge scheduler stop themselves.
    assert_eq!(owner.resource_use().unwrap(), request());
}

#[test]
fn durable_admission_binds_one_store_and_one_dispatch_role() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut first = temp.gate();
    let token = first.issue(&mut owner, lease, REQUEST).unwrap();
    let mut other = LaunchStore::create(&temp.path.join("other-launches"), limits()).unwrap();
    assert!(other.issue(&mut owner, lease, REQUEST).is_err());
    assert_eq!(other.record_count().unwrap(), 0);
    let claim = request_digest(b"supervisor journal").unwrap();
    assert!(first.reserve_supervisor(&mut owner, lease, claim).is_err());
    assert!(other.reserve_supervisor(&mut owner, lease, claim).is_err());
    assert_eq!(other.record_count().unwrap(), 0);
    assert!(WorkerGate::enter(&temp.launches(), &token, REQUEST).is_ok());
}

#[test]
fn supervised_reservation_is_unique_and_revocable_at_capacity() {
    let temp = Temp::new();
    let (mut owner, lease, _) = temp.owner();
    let mut gate = LaunchStore::create(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
    let claim = request_digest(b"supervisor journal").unwrap();
    gate.reserve_supervisor(&mut owner, lease, claim).unwrap();
    assert_eq!(gate.record_count().unwrap(), 1);
    assert!(gate.reserve_supervisor(&mut owner, lease, claim).is_err());
    assert!(gate
        .reserve_supervisor(&mut owner, lease, request_digest(b"other").unwrap())
        .is_err());
    assert!(gate.issue(&mut owner, lease, REQUEST).is_err());
    assert!(gate
        .issue_bound(&mut owner, lease, REQUEST, [2; 32])
        .is_err());
    assert!(gate
        .issue_reserved(
            &mut owner,
            lease,
            REQUEST,
            [2; 32],
            request_digest(b"other").unwrap()
        )
        .is_err());
    assert!(!temp
        .launches()
        .join(name(lease.process_key().unwrap(), "permit"))
        .exists());
    let revoked = gate.revoke(lease).unwrap();
    assert!(gate.try_idle(&revoked).unwrap().is_some());
    assert!(gate
        .issue_reserved(&mut owner, lease, REQUEST, [2; 32], claim)
        .is_err());
    // An idle launch lock is not a worker-stop or verifier-drain receipt.
    assert_eq!(owner.resource_use().unwrap(), request());
}

#[test]
fn reserved_publication_requires_the_exact_unconsumed_reservation() {
    for suffix in [None, Some("intent"), Some("started"), Some("revoked")] {
        let temp = Temp::new();
        let (mut owner, lease, _) = temp.owner();
        let mut gate = LaunchStore::create(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
        let claim = request_digest(b"supervisor journal").unwrap();
        gate.reserve_supervisor(&mut owner, lease, claim).unwrap();
        assert!(gate
            .issue_reserved(&mut owner, lease, REQUEST, [2; 32], claim)
            .is_err());
        owner
            .authorize_supervisor(lease, gate.directory.identity().unwrap(), claim, [3, 4])
            .unwrap();
        if let Some(suffix) = suffix {
            private_file(
                &temp
                    .launches()
                    .join(name(lease.process_key().unwrap(), suffix)),
                &[],
            );
            assert!(gate
                .issue_reserved(&mut owner, lease, REQUEST, [2; 32], claim)
                .is_err());
            assert!(!temp
                .launches()
                .join(name(lease.process_key().unwrap(), "permit"))
                .exists());
        } else {
            let t = gate
                .issue_reserved(&mut owner, lease, REQUEST, [2; 32], claim)
                .unwrap();
            assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_ok());
            assert!(gate
                .issue_reserved(&mut owner, lease, REQUEST, [2; 32], claim)
                .is_err());
        }
        let revoked = gate.revoke(lease).unwrap();
        assert!(gate.try_idle(&revoked).unwrap().is_some());
    }
}

#[test]
fn interrupted_reservations_recover_from_durable_no_permission_states() {
    for fault in [
        Fault::ReservationStarted,
        Fault::ReservationWorkerDurable,
        Fault::ReservationDurable,
        Fault::ReservationAdmissionDurable,
    ] {
        let temp = Temp::new();
        let (mut owner, lease, _) = temp.owner();
        let mut gate = LaunchStore::create(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
        let claim = request_digest(b"supervisor journal").unwrap();
        gate.fault = Some(fault);
        assert!(gate.reserve_supervisor(&mut owner, lease, claim).is_err());
        assert!(gate.record_count().is_err());
        assert!(gate.revoke(lease).is_err());
        assert!(owner.assignment(lease).is_err()); // whole owner requires recovery
        drop(gate);
        drop(owner);
        let attempt = recovered_preparation(&temp);
        let mut gate = LaunchStore::open(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
        assert_eq!(
            gate.record_count().unwrap(),
            usize::from(fault != Fault::ReservationStarted)
        );
        let receipt = gate.reconcile_preparation(&attempt).unwrap();
        assert_eq!(receipt.lease(), lease);
        let t = token(&gate, lease);
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
        assert_eq!(
            gate.record_count().unwrap(),
            usize::from(fault != Fault::ReservationStarted)
        );
    }
}

#[test]
#[ignore = "subprocess-only reservation crash helper"]
fn reservation_crash_helper() {
    let Some(path) = std::env::var_os("LATTICA_LAUNCH_RESERVATION_ROOT") else {
        return;
    };
    let temp = std::mem::ManuallyDrop::new(Temp {
        path: PathBuf::from(path),
    });
    let (mut owner, lease, _) = temp.owner();
    let mut gate = LaunchStore::create(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
    let t = token(&gate, lease);
    private_file(&temp.path.join("token"), &t.encode().unwrap());
    gate.fault = Some(
        match std::env::var("LATTICA_LAUNCH_RESERVATION_STAGE")
            .unwrap()
            .as_str()
        {
            "none" => Fault::ReservationStarted,
            "bound" => Fault::ReservationAdmissionDurable,
            "worker" => Fault::ReservationWorkerDurable,
            "reserved" => Fault::ReservationDurable,
            _ => panic!("reservation crash stage"),
        },
    );
    gate.crash = true;
    gate.reserve_supervisor(
        &mut owner,
        lease,
        request_digest(b"supervisor journal").unwrap(),
    )
    .unwrap();
    panic!("reservation fault did not exit");
}

#[test]
fn abrupt_reservation_boundaries_recover_without_launch_or_new_capacity() {
    for stage in ["none", "worker", "reserved", "bound"] {
        let temp = Temp::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "block_v2::execution::launch::tests::reservation_crash_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("LATTICA_LAUNCH_RESERVATION_ROOT", &temp.path)
            .env("LATTICA_LAUNCH_RESERVATION_STAGE", stage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(76), "{stage}");
        let attempt = recovered_preparation(&temp);
        let mut gate = LaunchStore::open(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
        assert_eq!(gate.record_count().unwrap(), usize::from(stage != "none"));
        let receipt = gate.reconcile_preparation(&attempt).unwrap();
        assert_eq!(receipt.lease(), attempt.lease);
        let t = Token::decode(&fs::read(temp.path.join("token")).unwrap()).unwrap();
        assert!(!temp.launches().join(name(t.key, "permit")).exists());
        assert!(WorkerGate::enter(&temp.launches(), &t, REQUEST).is_err());
    }
}

fn recovered_preparation(temp: &Temp) -> super::super::journal::PreviousAttempt {
    let (_log, bytes) = super::super::journal::SnapshotLog::open(
        &temp.path.join("journal"),
        JournalLimits {
            snapshot_bytes: 256 * 1024,
        },
    )
    .unwrap();
    let store = ArtifactStore::open(
        &temp.path.join("artifacts"),
        StoreLimits {
            bytes: 32 * (1 << 20),
            entries: 128,
        },
    )
    .unwrap();
    let recovered = super::super::dag::snapshot::restore_with(
        &bytes,
        pin(),
        [9; 32],
        2,
        Limits {
            jobs: 128,
            candidates: 8,
            attempts: 128,
            artifact_bytes: 32 * (1 << 20),
            recovery_window_ms: 10,
            workers: request(),
        },
        |id| {
            let bytes = store.read_exact(id)?;
            Ok((wallet(1, &bytes), bytes))
        },
        |_, _| panic!("structural preparation fixture has no completed recursive proof"),
    )
    .unwrap();
    assert_eq!(recovered.attempts.len(), 1);
    recovered.attempts[0].clone()
}

#[test]
fn unissued_recovery_needs_no_free_slot_and_cannot_drain_a_verifier() {
    let temp = Temp::new();
    let (owner, _, _) = temp.owner();
    drop(owner);
    let attempt = recovered_preparation(&temp);
    let mut gate = LaunchStore::create(&temp.launches(), LaunchLimits { records: 1 }).unwrap();
    let foreign = Temp::new();
    let (mut other, lease, _) = foreign.owner();
    let token = gate.issue(&mut other, lease, REQUEST).unwrap();
    assert_eq!(gate.record_count().unwrap(), 1);
    let receipt = gate.reconcile_preparation(&attempt).unwrap();
    assert_eq!(receipt.lease(), attempt.lease);
    assert_eq!(gate.record_count().unwrap(), 1);
    let mut verifying = attempt.clone();
    verifying.verification_active = true;
    assert!(gate.reconcile_preparation(&verifying).is_err());
    let mut unpinned = attempt.clone();
    unpinned.launch_root = None;
    assert!(gate.reconcile_preparation(&unpinned).is_err());
    let mut impossible = attempt.clone();
    impossible.launch_binding = Some(LaunchBinding::Preparing([3; 32]));
    assert!(gate.reconcile_preparation(&impossible).is_err());
    let mut foreign = attempt.clone();
    foreign.launch_root.as_mut().unwrap().store = [7, 8];
    assert!(gate.reconcile_preparation(&foreign).is_err());
    for binding in [
        None,
        Some(LaunchBinding::Direct),
        Some(LaunchBinding::Supervised([3; 32])),
        Some(LaunchBinding::Authorized {
            path: [3; 32],
            directory: [4, 5],
        }),
    ] {
        let mut unknown = attempt.clone();
        unknown.launch_binding = binding;
        assert!(gate.reconcile_preparation(&unknown).is_err());
    }
    assert!(WorkerGate::enter(&temp.launches(), &token, REQUEST).is_ok());
}
