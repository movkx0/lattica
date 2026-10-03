//! Local filesystem/identity tests. Native synthetic caps are not proof keys.
use super::*;
use crate::block_v2::execution::{
    artifact_store::{hex, ArtifactStore, StoreLimits},
    dag::{Limits, WorkerId},
    job::Job,
    journal::JournalLimits,
    launch::LaunchLimits,
    resources::Resources,
    test_fixture,
};
use rand::TryRng;
use std::{
    os::unix::fs::symlink,
    process::{Command, Stdio},
};

#[cfg(feature = "stream")]
#[path = "process_tests.rs"]
mod process_tests;
#[cfg(feature = "stream")]
#[path = "supervisor_process_tests.rs"]
mod supervisor_process_tests;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut bytes = [0; 16];
        rand::rngs::SysRng.try_fill_bytes(&mut bytes).unwrap();
        let path = std::env::temp_dir().join(format!("lattica-task-test-{}", hex(&bytes)));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("task")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn config() -> WorkerConfig {
    let registry = Registry {
        height: 8,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let pin = RegistryPin::new(
        &registry,
        registry.id().unwrap(),
        WrapperConstruction::GroupedPair,
    )
    .unwrap();
    WorkerConfig {
        registry,
        pin,
        chain: [9; 32],
        executable: [1; 32],
        timeout_seconds: 120,
        mode: Mode::Prove,
    }
}
fn spec() -> Spec {
    Spec {
        config: config(),
        root: [1, 2],
        launch_path: PathBuf::from("/tmp/private-launches"),
    }
}
fn private_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
}

#[test]
fn spec_codec_is_bounded_canonical_and_pins_all_configuration() {
    let value = spec();
    let bytes = value.encode().unwrap();
    assert_eq!(Spec::decode(&bytes).unwrap().encode().unwrap(), bytes);
    assert!(bytes.len() < MAX_SPEC_BYTES);
    for end in 0..bytes.len() {
        assert!(Spec::decode(&bytes[..end]).is_err(), "truncated at {end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Spec::decode(&extra).is_err());
    for offset in [0, 8, 9, 130] {
        let mut altered = bytes.clone();
        altered[offset] = 255;
        assert!(Spec::decode(&altered).is_err(), "offset {offset}");
    }
    // The height is at 126; the first field in the first cap starts at 130.
    let mut altered = bytes.clone();
    altered[130..138].copy_from_slice(&commitment::MODULUS.to_le_bytes());
    assert!(Spec::decode(&altered).is_err());
    for change in 0..7 {
        let mut changed = Spec::decode(&bytes).unwrap();
        match change {
            0 => changed.config.executable = [2; 32],
            1 => changed.config.chain = [3; 32],
            2 => changed.config.mode = Mode::Check,
            3 => changed.config.timeout_seconds += 1,
            4 => changed.root[1] += 1,
            5 => changed.launch_path = PathBuf::from("/tmp/other"),
            _ => {
                changed.config.pin = RegistryPin::new(
                    &changed.config.registry,
                    changed.config.pin.profile(),
                    WrapperConstruction::SingleWallet,
                )
                .unwrap()
            }
        }
        assert_ne!(changed.digest().unwrap(), value.digest().unwrap());
    }
    for path in [
        "relative",
        "/",
        "/tmp/../task",
        "/tmp/./task",
        "/tmp//task",
        "/tmp/task/",
        "/tmp/ta\nsk",
    ] {
        assert!(absolute_path(Path::new(path)).is_err(), "{path:?}");
    }
    let mut value = spec();
    value.config.timeout_seconds = 0;
    assert!(value.encode().is_err());
    value.config.timeout_seconds = 7201;
    assert!(value.encode().is_err());
}

#[test]
fn owner_is_exclusive_and_publication_is_non_overwriting() {
    let temp = Temp::new();
    let owner = TaskOwner::create(&temp.path()).unwrap();
    assert!(TaskOwner::create(&temp.path()).is_err());
    assert!(TaskOwner::open(&temp.path()).is_err());
    owner
        .directory
        .publish("spec", b"first", MAX_SPEC_BYTES)
        .unwrap();
    assert_eq!(
        owner.directory.read("spec", MAX_SPEC_BYTES).unwrap(),
        b"first"
    );
    assert!(owner
        .directory
        .publish("spec", b"replacement", MAX_SPEC_BYTES)
        .is_err());
    // Failed overwrite leaves an untrusted stage and cannot alter the final file.
    assert_eq!(
        owner.directory.read("spec", MAX_SPEC_BYTES).unwrap(),
        b"first"
    );
    assert!(owner.directory.inventory(false).is_err());
    drop(owner);
    let reopened = TaskOwner::open(&temp.path()).unwrap();
    assert!(reopened.directory.inventory(false).is_err());
}

#[test]
fn payloads_reject_unsafe_files_and_bounds() {
    for case in 0..7 {
        let temp = Temp::new();
        let owner = TaskOwner::create(&temp.path()).unwrap();
        let file = temp.path().join("request");
        match case {
            0 => private_file(&file, b"x", 0o644),
            1 => private_file(&file, b"x", 0o600),
            2 => {
                let other = temp.0.join("outside");
                private_file(&other, b"x", 0o400);
                symlink(other, &file).unwrap();
            }
            3 => {
                private_file(&file, b"x", 0o400);
                fs::hard_link(&file, temp.0.join("link")).unwrap();
            }
            4 => private_file(&file, &[], 0o400),
            5 => private_file(&file, &[0; 33], 0o400),
            _ => DirBuilder::new().mode(0o700).create(&file).unwrap(),
        }
        assert!(owner.directory.read("request", 32).is_err(), "case {case}");
    }
    let temp = Temp::new();
    let owner = TaskOwner::create(&temp.path()).unwrap();
    assert!(owner.directory.publish("request", &[], 32).is_err());
    assert!(owner.directory.publish("request", &[0; 33], 32).is_err());
    private_file(&temp.path().join("unknown"), &[], 0o600);
    assert!(owner.directory.inventory(true).is_err());
}

#[test]
fn replaced_lock_or_exposed_directory_is_rejected() {
    for case in 0..3 {
        let temp = Temp::new();
        let owner = TaskOwner::create(&temp.path()).unwrap();
        match case {
            0 => {
                fs::remove_file(temp.path().join(OWNER)).unwrap();
                private_file(&temp.path().join(OWNER), &[], 0o600);
            }
            1 => fs::set_permissions(temp.path(), Permissions::from_mode(0o755)).unwrap(),
            _ => fs::hard_link(temp.path().join(OWNER), temp.0.join("outside")).unwrap(),
        }
        assert!(owner.check().is_err());
    }
}

#[test]
fn image_identity_covers_content_length_and_rejects_unsafe_paths() {
    let temp = Temp::new();
    let path = temp.0.join("worker");
    private_file(&path, &[11; IMAGE_CHUNK_BYTES + 17], 0o700);
    let first = image_fingerprint(&path).unwrap();
    assert_eq!(first, image_fingerprint(&path).unwrap());
    let copy = temp.0.join("copy");
    fs::copy(&path, &copy).unwrap();
    assert_eq!(first, image_fingerprint(&copy).unwrap());
    OpenOptions::new()
        .append(true)
        .open(&copy)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    assert_ne!(first, image_fingerprint(&copy).unwrap());
    fs::set_permissions(&copy, Permissions::from_mode(0o722)).unwrap();
    assert!(image_fingerprint(&copy).is_err());
    let link = temp.0.join("symlink");
    symlink(&path, &link).unwrap();
    assert!(image_fingerprint(&link).is_err());
    let oversized = temp.0.join("oversized");
    private_file(&oversized, b"x", 0o700);
    OpenOptions::new()
        .write(true)
        .open(&oversized)
        .unwrap()
        .set_len(MAX_IMAGE_BYTES + 1)
        .unwrap();
    assert!(image_fingerprint(&oversized).is_err());
}

const FAULTS: [PublishFault; 6] = [
    PublishFault::StageCreated,
    PublishFault::StageDurable,
    PublishFault::Linked,
    PublishFault::Published,
    PublishFault::StageRemoved,
    PublishFault::Complete,
];

// Structural metadata fixtures only; these tokens have no issued launch permit.
fn startup_token(spec: &Spec, key: [u8; 32]) -> Token {
    let mut bytes = b"LVCPU002".to_vec();
    bytes.extend(key);
    for word in [1u64, 2, 1 << 20, 0, 1 << 20] {
        bytes.extend(word.to_le_bytes());
    }
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(launch::request_digest(b"native-request").unwrap());
    bytes.extend(spec.digest().unwrap());
    bytes.extend(launch::digest(0x4c42563275, &bytes).unwrap());
    Token::decode(&bytes).unwrap()
}
fn startup_identity(token: &Token) -> Identity {
    Identity {
        boot: [1; 16],
        invocation: [2; 16],
        pid: 1234,
        start_ticks: 42,
        group: format!("/user.slice/{}", token.service_name()),
        device: 29,
        inode: 17,
    }
}
fn startup_fixture(path: &Path) -> (TaskOwner, Token, Identity) {
    let task = TaskOwner::create(path).unwrap();
    let mut spec = spec();
    spec.root = task.directory.identity().unwrap();
    let token = startup_token(&spec, [3; 32]);
    let identity = startup_identity(&token);
    task.directory
        .publish("spec", &spec.encode().unwrap(), MAX_SPEC_BYTES)
        .unwrap();
    task.directory
        .publish("token", &token.encode().unwrap(), MAX_TOKEN_BYTES)
        .unwrap();
    (task, token, identity)
}

#[test]
fn worker_start_codec_binds_exact_token_and_bounded_process_identity() {
    let token = startup_token(&spec(), [3; 32]);
    let identity = startup_identity(&token);
    let bytes = encode_worker_start(&token, &identity).unwrap();
    assert_eq!(decode_worker_start(&bytes, &token).unwrap(), identity);
    for end in 0..bytes.len() {
        assert!(decode_worker_start(&bytes[..end], &token).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode_worker_start(&extra, &token).is_err());
    assert!(decode_worker_start(&bytes, &startup_token(&spec(), [4; 32])).is_err());
    for variant in 0..6 {
        let mut bad = identity.clone();
        match variant {
            0 => bad.boot = [0; 16],
            1 => bad.invocation = [0; 16],
            2 => bad.pid = 1,
            3 => bad.start_ticks = 0,
            4 => bad.inode = 0,
            _ => bad.group.push_str("/other.service"),
        }
        assert!(encode_worker_start(&token, &bad).is_err());
    }
    for at in [8 + MAX_TOKEN_BYTES, 24 + MAX_TOKEN_BYTES] {
        let mut bad = bytes.clone();
        bad[at..at + 16].fill(0);
        assert!(decode_worker_start(&bad, &token).is_err());
    }
    let mut huge = bytes.clone();
    let length_at = 8 + MAX_TOKEN_BYTES + 16 + 16 + 4 + 8 + 8 + 8;
    huge[length_at..length_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_worker_start(&huge, &token).is_err());
}

#[cfg(feature = "stream")]
#[test]
fn worker_start_recovery_rejects_task_copy_substitution_and_unsafe_files() {
    let temp = Temp::new();
    let (task, token, identity) = startup_fixture(&temp.path());
    assert_eq!(
        worker_start_identity(&temp.path(), &token, [1; 32]).unwrap(),
        None
    );
    task.directory
        .publish(
            "worker-start",
            &encode_worker_start(&token, &identity).unwrap(),
            MAX_WORKER_START_BYTES,
        )
        .unwrap();
    assert_eq!(
        worker_start_identity(&temp.path(), &token, [1; 32]).unwrap(),
        Some(identity.clone())
    );
    assert!(worker_start_identity(&temp.path(), &token, [2; 32]).is_err());
    let different = startup_token(
        &Spec::decode(&task.directory.read("spec", MAX_SPEC_BYTES).unwrap()).unwrap(),
        [4; 32],
    );
    assert!(worker_start_identity(&temp.path(), &different, [1; 32]).is_err());
    // Incomplete output publication does not erase independently durable birth.
    private_file(&temp.path().join(".stage-result"), b"partial", 0o400);
    assert_eq!(
        worker_start_identity(&temp.path(), &token, [1; 32]).unwrap(),
        Some(identity)
    );
    let copy = temp.0.join("copied");
    let _owner = TaskOwner::create(&copy).unwrap();
    for name in ["spec", "token", "worker-start"] {
        fs::copy(temp.path().join(name), copy.join(name)).unwrap();
    }
    assert!(worker_start_identity(&copy, &token, [1; 32]).is_err());
    fs::remove_file(temp.path().join("worker-start")).unwrap();
    symlink(copy.join("worker-start"), temp.path().join("worker-start")).unwrap();
    assert!(worker_start_identity(&temp.path(), &token, [1; 32]).is_err());
}

#[cfg(feature = "stream")]
#[test]
#[ignore = "subprocess-only worker startup publication helper"]
fn worker_start_crash_helper() {
    let Some(root) = std::env::var_os("LATTICA_V2_START_CRASH_ROOT") else {
        return;
    };
    let index: usize = std::env::var("LATTICA_V2_START_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let (mut task, token, identity) = startup_fixture(Path::new(&root));
    task.directory.fault = Some(FAULTS[index]);
    task.directory
        .publish(
            "worker-start",
            &encode_worker_start(&token, &identity).unwrap(),
            MAX_WORKER_START_BYTES,
        )
        .unwrap();
    panic!("startup publication fault did not exit");
}

#[cfg(feature = "stream")]
#[test]
fn abrupt_worker_start_publication_never_promotes_partial_identity() {
    for index in 0..FAULTS.len() {
        let temp = Temp::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "block_v2::execution::transport::tests::worker_start_crash_helper",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("LATTICA_V2_START_CRASH_ROOT", temp.path())
            .env("LATTICA_V2_START_CRASH_STAGE", index.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let task = TaskOwner::open(&temp.path()).unwrap();
        let token = Token::decode(&task.directory.read("token", MAX_TOKEN_BYTES).unwrap()).unwrap();
        let result = worker_start_identity(&temp.path(), &token, [1; 32]);
        match index {
            0 | 1 => assert_eq!(result.unwrap(), None),
            2 | 3 => assert!(result.is_err()),
            _ => assert_eq!(result.unwrap(), Some(startup_identity(&token))),
        }
        // No OS-stop or launch-eligibility claim follows from any of these files.
    }
}
#[test]
fn crash_helper() {
    let Ok(root) = std::env::var("LATTICA_V2_TRANSPORT_CRASH_ROOT") else {
        return;
    };
    let index: usize = std::env::var("LATTICA_V2_TRANSPORT_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let mut owner = TaskOwner::create(Path::new(&root)).unwrap();
    owner.directory.fault = Some(FAULTS[index]);
    owner
        .directory
        .publish("spec", &spec().encode().unwrap(), MAX_SPEC_BYTES)
        .unwrap();
    panic!("fault did not terminate child");
}
#[test]
fn abrupt_publication_keeps_partial_task_untrusted() {
    for index in 0..FAULTS.len() {
        let temp = Temp::new();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "block_v2::execution::transport::tests::crash_helper",
                "--exact",
                "--nocapture",
            ])
            .env("LATTICA_V2_TRANSPORT_CRASH_ROOT", temp.path())
            .env("LATTICA_V2_TRANSPORT_CRASH_STAGE", index.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77)); // exact child is terminal/reaped
        let owner = TaskOwner::open(&temp.path()).unwrap();
        assert!(WorkerTask::open(&temp.path()).is_err());
        assert!(!temp.path().join("token").exists());
        if index < 4 {
            assert!(owner.directory.inventory(false).is_err());
        } else {
            assert_eq!(
                owner.directory.read("spec", MAX_SPEC_BYTES).unwrap(),
                spec().encode().unwrap()
            );
        }
    }
}

fn real_pair(
    temp: &Temp,
    f: &test_fixture::Fixture,
    r: Resources,
) -> Result<(DurableDag, Assignment), Error> {
    let store = ArtifactStore::create(
        &temp.0.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 128,
        },
    )?;
    let mut owner = DurableDag::create(
        &temp.0.join("journal"),
        JournalLimits {
            snapshot_bytes: 256 << 10,
        },
        store,
        f.pin,
        [0x5a; 32],
        1,
        Limits {
            jobs: 128,
            candidates: 8,
            attempts: 128,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 10,
            workers: r,
        },
    )?;
    let pair = Job::wrap_pair(0, f.wallets[0], f.wallets[1])?;
    owner.admit(
        pair.clone(),
        vec![f.bytes[0].clone(), f.bytes[1].clone()],
        0,
    )?;
    let mut root = pair.clone();
    for level in 1..commitment::DEPTH {
        let empty = Job::empty(f.pin, [0x5a; 32], 1 << level, level)?;
        owner.admit(empty.clone(), vec![], 0)?;
        root = Job::merge(&root, &empty)?;
        owner.admit(root.clone(), vec![], 0)?;
    }
    owner.attach(root.id(), [1; 32], 2_000_000, 0)?;
    let lease = owner.lease(pair.id(), WorkerId(1), r, 1, 1_900_000, 0)?;
    let assignment = owner.assignment(lease)?;
    Ok((owner, assignment))
}

#[test]
#[ignore = "explicit pinned public fixture; no proving, bounded CPU verification"]
fn cpu_task_transport_binds_real_assignment_and_rejects_copied_directory() -> Result<(), Error> {
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let (mut owner, assignment) = real_pair(
        &temp,
        &f,
        Resources {
            ram_bytes: 3 << 30,
            vram_bytes: 0,
            scratch_bytes: 32 << 20,
            threads: 8,
        },
    )?;
    let launch_path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 16 })?;
    let config = WorkerConfig {
        registry: f.registry.clone(),
        pin: f.pin,
        chain: [0x5a; 32],
        executable: [1; 32],
        timeout_seconds: 120,
        mode: Mode::Check,
    };
    let mut task = TaskOwner::create(&temp.path())?;
    let token = task.issue(
        &mut owner,
        &mut launches,
        &launch_path,
        assignment.lease(),
        config.clone(),
    )?;
    let loaded = WorkerTask::open(&temp.path())?;
    token.check_execution(loaded.spec.digest()?)?;
    assert_eq!(loaded.request, packet::encode_request(&assignment)?);
    assert!(task
        .issue(
            &mut owner,
            &mut launches,
            &launch_path,
            assignment.lease(),
            config
        )
        .is_err());
    let guard = WorkerGate::enter(&launch_path, &loaded.token, &loaded.request)?;
    let worker = super::super::worker::CpuWorker::new(f.registry, f.pin)?;
    assert_eq!(
        worker
            .check_packet(&guard, &loaded.request, [0x5a; 32])?
            .expected
            .count,
        2
    );
    assert!(loaded.publish_result(&guard, b"not a proof").is_err()); // check-only
    let copy = temp.0.join("copied");
    let _copy_owner = TaskOwner::create(&copy)?;
    for name in ["spec", "request", "token"] {
        fs::copy(temp.path().join(name), copy.join(name))?;
    }
    assert!(WorkerTask::open(&copy).is_err());
    let revoked = launches.revoke(assignment.lease())?;
    assert!(launches.try_idle(&revoked)?.is_none());
    drop(guard);
    assert!(launches.try_idle(&revoked)?.is_some()); // no process-stop claim
    Ok(())
}

#[cfg(feature = "stream")]
#[test]
#[ignore = "explicit pinned public fixture and preserved CPU worker; no service launch"]
fn cpu_supervisor_binds_real_task_and_keeps_verification_separate() -> Result<(), Error> {
    use crate::block_v2::execution::supervisor::{Reconciliation, Status, Supervisor};
    let temp = Temp::new();
    let f = test_fixture::load()?;
    let resources = Resources {
        ram_bytes: 3 << 30,
        vram_bytes: 0,
        scratch_bytes: 32 << 20,
        threads: 8,
    };
    let (mut owner, assignment) = real_pair(&temp, &f, resources)?;
    let image = PathBuf::from(
        std::env::var_os("LATTICA_V2_CPU_WORKER").ok_or("explicit CPU worker missing")?,
    );
    let launch_path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 16 })?;
    let path = temp.0.join("supervisor");
    let mut supervisor = Supervisor::prepare(
        &path,
        &mut owner,
        assignment.lease(),
        &mut launches,
        &launch_path,
        &temp.path(),
        &image,
        120,
    )?;
    assert_eq!(supervisor.status()?, Status::Prepared);
    let config = WorkerConfig {
        registry: f.registry.clone(),
        pin: f.pin,
        chain: [0x5a; 32],
        executable: image_fingerprint(&image)?,
        timeout_seconds: 120,
        mode: Mode::Check,
    };
    let task = supervisor.issue_task(&mut owner, assignment.lease(), &mut launches, config)?;
    assert_eq!(supervisor.status()?, Status::Ready);
    assert!(supervisor
        .bind_task(&owner, assignment.lease(), &launches, &task)
        .is_err());
    drop(supervisor);
    let mut supervisor = Supervisor::reopen(&path, &owner, assignment.lease())?;
    assert_eq!(supervisor.status()?, Status::Ready);
    let Reconciliation::Stopped(receipt) =
        supervisor.reconcile(&mut launches, assignment.lease())?
    else {
        return Err("unlaunched supervisor did not reconcile".into());
    };
    receipt.acknowledge(&mut owner, 1)?;
    assert_eq!(owner.resource_use()?, resources);
    assert!(!temp.path().join("result").exists());
    owner.begin_verification(assignment.lease(), 2)?;
    assert_eq!(owner.resource_use()?, resources);
    assert_eq!(
        owner.finish_verification(assignment.lease(), None, 3)?,
        crate::block_v2::execution::dag::Completion::Rejected
    );
    assert_eq!(owner.resource_use()?, Resources::default());
    println!(
        "cpu_supervisor_task=PASS launch=false proof=false independent_verification_required=true"
    );
    Ok(())
}

#[cfg(feature = "stream")]
#[test]
#[ignore = "explicit pinned public fixture and preserved CPU worker; no service launch"]
fn cpu_admission_recovery_rejects_copied_dag_and_preserves_supervisor_binding() -> Result<(), Error>
{
    use crate::block_v2::execution::{
        dag::LaunchBinding,
        supervisor::{Reconciliation, Supervisor},
    };
    let f = test_fixture::load()?;
    let temp = Temp::new();
    let resources = Resources {
        ram_bytes: 3 << 30,
        vram_bytes: 0,
        scratch_bytes: 32 << 20,
        threads: 8,
    };
    let (mut owner, assignment) = real_pair(&temp, &f, resources)?;
    let lease = assignment.lease();
    let image =
        PathBuf::from(std::env::var_os("LATTICA_V2_CPU_WORKER").ok_or("CPU worker missing")?);
    let launch_path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 1 })?;
    let supervisor_path = temp.0.join("supervisor");
    let mut supervisor = Supervisor::prepare(
        &supervisor_path,
        &mut owner,
        lease,
        &mut launches,
        &launch_path,
        &temp.path(),
        &image,
        120,
    )?;
    let task = supervisor.issue_task(
        &mut owner,
        lease,
        &mut launches,
        WorkerConfig {
            registry: f.registry.clone(),
            pin: f.pin,
            chain: [0x5a; 32],
            executable: image_fingerprint(&image)?,
            timeout_seconds: 120,
            mode: Mode::Check,
        },
    )?;
    drop(task);
    drop(supervisor);
    drop(owner);
    let journal = temp.0.join("journal");
    let copy = temp.0.join("copied-journal");
    DirBuilder::new().mode(0o700).create(&copy)?;
    fs::copy(journal.join("state"), copy.join("state"))?;
    let recover = |path: &Path| {
        DurableDag::recover(
            path,
            JournalLimits {
                snapshot_bytes: 256 << 10,
            },
            ArtifactStore::open(
                &temp.0.join("artifacts"),
                StoreLimits {
                    bytes: 32 << 20,
                    entries: 128,
                },
            )?,
            f.pin,
            &f.registry,
            [0x5a; 32],
            2,
            Limits {
                jobs: 128,
                candidates: 8,
                attempts: 128,
                artifact_bytes: 32 << 20,
                recovery_window_ms: 10,
                workers: resources,
            },
        )
    };
    let error = match recover(&copy) {
        Ok(_) => return Err("copied DAG accepted".into()),
        Err(e) => e,
    };
    assert!(
        error.to_string().contains("journal directory replaced"),
        "{error}"
    );
    let recovery = recover(&journal)?;
    assert_eq!(recovery.unresolved_attempts().len(), 1);
    let attempt = recovery.unresolved_attempts()[0].clone();
    assert!(matches!(
        attempt.launch_binding,
        Some(LaunchBinding::Authorized { .. })
    ));
    assert!(attempt.launch_root.is_some());
    for variant in 0..3 {
        let mut wrong = attempt.clone();
        match variant {
            0 => wrong.launch_binding = Some(LaunchBinding::Direct),
            1 => wrong.launch_binding = None,
            _ => wrong.launch_root = None,
        }
        assert!(Supervisor::recover(&supervisor_path, &wrong).is_err());
    }
    let mut receipts = Vec::new();
    let owner = recovery.resume(
        |attempt| {
            let mut supervisor = Supervisor::recover(&supervisor_path, attempt)?;
            match supervisor.reconcile(&mut launches, attempt.lease)? {
                Reconciliation::Stopped(receipt) => {
                    receipts.push(receipt);
                    Ok(())
                }
                _ => Err("never-dispatched admitted task did not reconcile".into()),
            }
        },
        || 1000,
    )?;
    assert_eq!(owner.resource_use()?, Resources::default());
    assert!(owner.ready()?.is_empty());
    assert!(owner.assignment(lease).is_err());
    assert_eq!(launches.record_count()?, 1);
    println!("cpu_admission_recovery=PASS copied_dag=rejected roles=bound no_dispatch=true");
    Ok(())
}

#[cfg(feature = "stream")]
#[test]
#[ignore = "explicit pinned public fixture and preserved CPU worker; no service launch"]
fn cpu_incomplete_preparation_recovers_without_invented_worker_stop() -> Result<(), Error> {
    use crate::block_v2::execution::{
        dag::LaunchBinding,
        supervisor::{Reconciliation, Supervisor},
    };
    let f = test_fixture::load()?;
    let image =
        PathBuf::from(std::env::var_os("LATTICA_V2_CPU_WORKER").ok_or("CPU worker missing")?);
    for stage in 0..3 {
        let temp = Temp::new();
        let r = Resources {
            ram_bytes: 3 << 30,
            vram_bytes: 0,
            scratch_bytes: 32 << 20,
            threads: 8,
        };
        let (mut owner, assignment) = real_pair(&temp, &f, r)?;
        let lease = assignment.lease();
        let launch_path = temp.0.join("launches");
        let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 1 })?;
        let path = if stage == 1 {
            temp.0.join("missing-parent").join("supervisor")
        } else {
            temp.0.join("supervisor")
        };
        if stage == 1 {
            assert!(Supervisor::prepare(
                &path,
                &mut owner,
                lease,
                &mut launches,
                &launch_path,
                &temp.path(),
                &image,
                120
            )
            .is_err());
        } else if stage == 2 {
            drop(Supervisor::prepare(
                &path,
                &mut owner,
                lease,
                &mut launches,
                &launch_path,
                &temp.path(),
                &image,
                120,
            )?);
        }
        assert!(!temp.path().exists());
        drop(owner);
        drop(launches);
        let mut launches = LaunchStore::open(&launch_path, LaunchLimits { records: 1 })?;
        let recover = |journal: &Path| {
            DurableDag::recover(
                journal,
                JournalLimits {
                    snapshot_bytes: 256 << 10,
                },
                ArtifactStore::open(
                    &temp.0.join("artifacts"),
                    StoreLimits {
                        bytes: 32 << 20,
                        entries: 128,
                    },
                )?,
                f.pin,
                &f.registry,
                [0x5a; 32],
                2,
                Limits {
                    jobs: 128,
                    candidates: 8,
                    attempts: 128,
                    artifact_bytes: 32 << 20,
                    recovery_window_ms: 10,
                    workers: r,
                },
            )
        };
        if stage == 0 {
            let copy = temp.0.join("copied-unissued");
            DirBuilder::new().mode(0o700).create(&copy)?;
            fs::copy(temp.0.join("journal/state"), copy.join("state"))?;
            let error = match recover(&copy) {
                Ok(_) => return Err("copied Unissued DAG accepted".into()),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("journal directory replaced"),
                "{error}"
            );
        }
        let recovery = recover(&temp.0.join("journal"))?;
        assert_eq!(recovery.unresolved_attempts().len(), 1);
        match stage {
            0 => assert_eq!(
                recovery.unresolved_attempts()[0].launch_binding,
                Some(LaunchBinding::Unissued)
            ),
            1 => assert!(matches!(
                recovery.unresolved_attempts()[0].launch_binding,
                Some(LaunchBinding::Preparing(_))
            )),
            2 => assert!(matches!(
                recovery.unresolved_attempts()[0].launch_binding,
                Some(LaunchBinding::Authorized { .. })
            )),
            _ => unreachable!(),
        }
        let mut preparations = Vec::new();
        let mut stops = Vec::new();
        let owner = recovery.resume(
            |attempt| {
                match attempt.launch_binding {
                    Some(LaunchBinding::Unissued) | Some(LaunchBinding::Preparing(_)) => {
                        assert!(stage < 2);
                        let receipt = launches.reconcile_preparation(attempt)?;
                        assert_eq!(receipt.lease(), lease);
                        preparations.push(receipt);
                    }
                    Some(LaunchBinding::Authorized { .. }) => {
                        assert_eq!(stage, 2);
                        assert!(launches.reconcile_preparation(attempt).is_err());
                        let mut supervisor = Supervisor::recover(&path, attempt)?;
                        match supervisor.reconcile(&mut launches, attempt.lease)? {
                            Reconciliation::Stopped(receipt) => stops.push(receipt),
                            _ => {
                                return Err(
                                    "never-dispatched authorized supervisor did not stop".into()
                                )
                            }
                        }
                    }
                    _ => return Err("unexpected preparation phase".into()),
                }
                Ok(())
            },
            || 1000,
        )?;
        assert_eq!(owner.resource_use()?, Resources::default());
        assert!(owner.ready()?.is_empty());
        assert!(owner.assignment(lease).is_err());
        assert_eq!(launches.record_count()?, usize::from(stage != 0));
    }
    println!("cpu_incomplete_preparation=PASS unissued=true copied_unissued=rejected failed_journal=preparing authorized=true synthetic_process_stop=false");
    Ok(())
}
