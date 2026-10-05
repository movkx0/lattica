//! Explicit real-service tests. Run only under the exclusive bounded controller.
//! No synthetic stop receipts, relaxed profiles, or production activation.
use super::*;
use crate::block_v2::execution::{
    dag::{Completion, Limits},
    job::VerifiedNode,
    os_worker,
    supervisor::{Launcher, Reconciliation, Status, StopReceipt, Supervisor},
};
use std::time::{Duration, Instant};

#[path = "arrival_process_tests.rs"]
mod arrivals;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Check,
    Prove,
    Cancel,
    Crash,
}

fn opt_in() -> Result<(PathBuf, PathBuf), Error> {
    if std::env::var("LATTICA_V2_RUN_CPU_SUPERVISOR_TEST").as_deref() != Ok("1") {
        return Err("explicit supervisor integration opt-in required".into());
    }
    let controller = os_worker::current_controller()?;
    if std::env::var("LATTICA_V2_ACCOUNTING_UNIT")? != controller {
        return Err("supervisor integration controller mismatch".into());
    }
    let image = PathBuf::from(std::env::var("LATTICA_V2_CPU_WORKER_IMAGE")?);
    let root = PathBuf::from(std::env::var("LATTICA_V2_PROCESS_TEST_DIR")?);
    absolute_path(&image)?;
    absolute_path(&root)?;
    Ok((image, root))
}
fn resources(case: Case) -> Resources {
    Resources {
        ram_bytes: if case == Case::Check {
            3 << 30
        } else {
            44 << 30
        },
        vram_bytes: 0,
        scratch_bytes: if case == Case::Check {
            32 << 20
        } else {
            120 << 30
        },
        threads: 8,
    }
}
fn observe(supervisor: &mut Supervisor, launcher: &mut Launcher) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if supervisor.observe()? {
            return Ok(());
        }
        if let Some(status) = launcher.poll()? {
            return Err(format!(
                "worker exited before exact capture ({status}); preserve uncertain reservation"
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err("live capture deadline; preserve uncertain reservation".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn wait_started(launch_path: &Path, token: &Token, launcher: &mut Launcher) -> Result<(), Error> {
    let marker = launch_path.join(format!("{}.started", hex(&token.key())));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.is_file() && metadata.len() == 0 => return Ok(()),
            Ok(_) => return Err("worker start marker type/length".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        if let Some(status) = launcher.poll()? {
            return Err(format!("worker ended before guard entry: {status}").into());
        }
        if Instant::now() >= deadline {
            return Err("worker guard-entry deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn wait_launcher(launcher: &mut Launcher) -> Result<std::process::ExitStatus, Error> {
    let deadline = Instant::now() + Duration::from_secs(1830);
    loop {
        if let Some(status) = launcher.poll()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("launcher completion uncertain; retain reservation".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn stop(
    supervisor: &mut Supervisor,
    launches: &mut LaunchStore,
    lease: crate::block_v2::execution::dag::Lease,
) -> Result<StopReceipt, Error> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match supervisor.reconcile(launches, lease)? {
            Reconciliation::Stopped(receipt) => return Ok(receipt),
            Reconciliation::Quarantined => {
                return Err("unexpected unobserved launch quarantine; reservation retained".into())
            }
            Reconciliation::Pending => (),
        }
        if Instant::now() >= deadline {
            return Err("OS stop still pending; reservation retained".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn run(case: Case) -> Result<(), Error> {
    let (image, root) = opt_in()?;
    DirBuilder::new().mode(0o700).create(&root)?;
    // Preserve journals, task and proof even on test failure/intentional exit.
    let temp = std::mem::ManuallyDrop::new(Temp(root));
    let f = test_fixture::load()?;
    let resources = resources(case);
    let (mut owner, assignment) = real_pair(&temp, &f, resources)?;
    let lease = assignment.lease();
    let launch_path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 16 })?;
    let path = temp.0.join("supervisor");
    let timeout = if case == Case::Check { 60 } else { 1800 };
    let mut supervisor = Supervisor::prepare(
        &path,
        &mut owner,
        lease,
        &mut launches,
        &launch_path,
        &temp.path(),
        &image,
        timeout,
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
            timeout_seconds: timeout,
            mode: if case == Case::Check {
                Mode::Check
            } else {
                Mode::Prove
            },
        },
    )?;
    let (token, _, _) = task.launch_binding(
        &owner.assignment(lease)?,
        &temp.path(),
        &image,
        &launch_path,
    )?;
    assert_eq!(supervisor.status()?, Status::Ready);
    let start = Instant::now();
    let mut launcher = supervisor.dispatch(&owner, lease, &launches, &task)?;
    observe(&mut supervisor, &mut launcher)?;
    let identity = supervisor
        .observed_identity()
        .ok_or("missing captured identity")?
        .clone();
    private_file(
        &temp.0.join("worker-started.txt"),
        format!("{identity:?}\n").as_bytes(),
        0o600,
    );
    println!(
        "supervisor_worker_unit={} case={case:?} observed={identity:?}",
        supervisor.service_name()
    );
    assert_eq!(supervisor.status()?, Status::Observed);
    if matches!(case, Case::Cancel | Case::Crash) {
        wait_started(&launch_path, &token, &mut launcher)?;
    }
    if case == Case::Crash {
        assert!(!temp.path().join("result").exists());
        println!("supervisor_intentional_exit=73 observed=true verification_started=false");
        use std::io::Write;
        std::io::stdout().flush()?;
        // Skip all Rust drops: the next actor must recover persisted ownership.
        // The enclosing dedicated service stops its bound worker and helper.
        std::process::exit(73);
    }
    let helper_status = if case == Case::Cancel {
        None
    } else {
        Some(wait_launcher(&mut launcher)?)
    };
    if let Some(status) = helper_status {
        if !status.success() {
            return Err(format!("supervised worker failed: {status}").into());
        }
    }
    // Exercise persisted identity, not the original supervisor's in-memory FDs.
    drop(supervisor);
    let mut supervisor = Supervisor::reopen(&path, &owner, lease)?;
    assert_eq!(supervisor.observed_identity(), Some(&identity));
    if case == Case::Cancel {
        assert!(
            !os_worker::exited(&identity, &supervisor.service_name())?,
            "cancellation must target the still-live captured process"
        );
        // Reproduce the linked-but-not-cleaned startup publication window while
        // the worker is live. Strict file recovery rejects it; kernel capture
        // must still succeed without consulting the partial file first.
        let stage = temp.path().join(".stage-worker-start");
        fs::hard_link(temp.path().join("worker-start"), &stage)?;
        assert!(worker_start_identity(&temp.path(), &token, image_fingerprint(&image)?).is_err());
        assert!(supervisor.observe()?);
        fs::remove_file(stage)?;
        drop(supervisor);
        supervisor = Supervisor::reopen(&path, &owner, lease)?;
        assert_eq!(supervisor.observed_identity(), Some(&identity));
        println!("cpu_supervisor_live_publication_race=PASS kernel_capture_first=true persisted_identity=true");
    }
    let receipt = stop(&mut supervisor, &mut launches, lease)?;
    let helper_status = match helper_status {
        Some(status) => status,
        None => wait_launcher(&mut launcher)?,
    };
    // systemd may report a requested SIGTERM stop as success. Helper status is
    // diagnostic only; the exact process/cgroup receipt above is stop authority.
    private_file(&temp.0.join("worker-status.txt"),
        format!("PersistedIdentityMatched=true\nKernelStopConfirmed=true\nHelperStatus={helper_status}\nCase={case:?}\n").as_bytes(), 0o600);
    assert_eq!(owner.resource_use()?, resources);
    receipt.acknowledge(&mut owner, u64::try_from(start.elapsed().as_millis())?)?;
    assert_eq!(supervisor.status()?, Status::Stopped);
    assert_eq!(owner.resource_use()?, resources); // No CPU result accepted yet.
    let verification =
        owner.begin_guarded_verification(lease, u64::try_from(start.elapsed().as_millis())?)?;
    if case == Case::Prove {
        drop(task);
        let task = TaskOwner::open(&temp.path())?;
        let result = task.result(&assignment)?;
        let verified = verification.verify(&f.registry, result.bytes().to_vec());
        if let Some(error) = verified.error() {
            return Err(error.to_owned().into());
        }
        let elapsed = u64::try_from(start.elapsed().as_millis())?;
        assert_eq!(
            owner.finish_guarded_verification(verified, elapsed)?,
            Completion::Accepted
        );
        private_file(&temp.0.join("pair.1.0"), result.bytes(), 0o600);
        println!("cpu_supervisor_proof=PASS transactions=2 proof_bytes={} elapsed_ms={} input_verification_ms={} proving_ms={}",
            result.bytes().len(), start.elapsed().as_millis(), result.timings().input_verification_ms, result.timings().proving_ms);
    } else {
        assert!(!temp.path().join("result").exists());
        assert_eq!(
            owner.finish_guarded_verification(
                verification.reject(),
                u64::try_from(start.elapsed().as_millis())?
            )?,
            Completion::Rejected
        );
        println!(
            "cpu_supervisor_check_or_cancel=PASS case={case:?} elapsed_ms={} proof=false",
            start.elapsed().as_millis()
        );
    }
    assert_eq!(owner.resource_use()?, Resources::default());
    Ok(())
}

#[test]
#[ignore = "actual CPU service through supervisor; dedicated bounded controller required"]
fn cpu_supervisor_actual_check_and_persisted_stop() -> Result<(), Error> {
    run(Case::Check)
}
#[test]
#[ignore = "actual 44GiB paired-wrapper proving through supervisor; explicit opt-in"]
fn cpu_supervisor_actual_proof_and_independent_acceptance() -> Result<(), Error> {
    run(Case::Prove)
}
#[test]
#[ignore = "actual live prover cancellation; dedicated bounded controller required"]
fn cpu_supervisor_cancels_live_worker_before_releasing_resources() -> Result<(), Error> {
    run(Case::Cancel)
}
#[test]
#[ignore = "intentional exit73 after live capture; dedicated bounded controller required"]
fn cpu_supervisor_coordinator_crash_after_capture() -> Result<(), Error> {
    run(Case::Crash)
}

#[test]
#[ignore = "fresh actor after intentional coordinator crash; exact pinned directory required"]
fn cpu_supervisor_recovers_crashed_coordinator_before_rebase() -> Result<(), Error> {
    let (_, root) = opt_in()?;
    let f = test_fixture::load()?;
    let resources = resources(Case::Crash);
    let store = ArtifactStore::open(
        &root.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 128,
        },
    )?;
    let recovery = DurableDag::recover(
        &root.join("journal"),
        JournalLimits {
            snapshot_bytes: 256 << 10,
        },
        store,
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
    )?;
    assert_eq!(recovery.unresolved_attempts().len(), 1);
    let prior = &recovery.unresolved_attempts()[0];
    assert!(!prior.worker_stopped);
    // This experiment crashes before beginning CPU verification. It does not
    // establish recovery of concurrently active verifier work.
    assert!(!prior.verification_active);
    let mut launches = LaunchStore::open(&root.join("launches"), LaunchLimits { records: 16 })?;
    let mut supervisor = Supervisor::recover(&root.join("supervisor"), prior)?;
    let identity = supervisor
        .observed_identity()
        .ok_or("crash record lost observed identity")?
        .clone();
    assert_eq!(supervisor.status()?, Status::Observed);
    let mut receipt = None;
    let recovered = recovery.resume(
        |attempt| {
            assert!(!attempt.verification_active);
            receipt = Some(stop(&mut supervisor, &mut launches, attempt.lease)?);
            Ok(())
        },
        || 100_000,
    )?;
    assert_eq!(recovered.resource_use()?, Resources::default());
    assert!(
        recovered.ready()?.is_empty(),
        "historical eligibility must not be revived"
    );
    assert_eq!(supervisor.status()?, Status::Stopped);
    assert_eq!(supervisor.observed_identity(), Some(&identity));
    private_file(&root.join("recovered.txt"), format!("ExactPriorWorkerStopped=true\nPriorVerifierActive=false\nResourcesReleasedAfterReconciliation=true\nHistoricalEligibilityRevived=false\nIdentity={identity:?}\n").as_bytes(), 0o600);
    assert!(receipt.is_some());
    println!("cpu_supervisor_crash_recovery=PASS exact_worker=true prior_verifier_active=false resources=0 epoch=2");
    Ok(())
}

fn run_without_live_capture(crash: bool) -> Result<(), Error> {
    let (image, root) = opt_in()?;
    DirBuilder::new().mode(0o700).create(&root)?;
    let temp = std::mem::ManuallyDrop::new(Temp(root));
    let f = test_fixture::load()?;
    let resources = resources(Case::Check);
    let (mut owner, assignment) = real_pair(&temp, &f, resources)?;
    let lease = assignment.lease();
    let launch_path = temp.0.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 16 })?;
    let mut supervisor = Supervisor::prepare(
        &temp.0.join("supervisor"),
        &mut owner,
        lease,
        &mut launches,
        &launch_path,
        &temp.path(),
        &image,
        60,
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
            timeout_seconds: 60,
            mode: Mode::Check,
        },
    )?;
    let (token, _, _) = task.launch_binding(&assignment, &temp.path(), &image, &launch_path)?;
    let mut launcher = supervisor.dispatch(&owner, lease, &launches, &task)?;
    // Deliberately never call Supervisor::observe while the worker is live.
    assert!(wait_launcher(&mut launcher)?.success());
    assert!(supervisor.observed_identity().is_none());
    assert_eq!(owner.resource_use()?, resources);
    let identity = worker_start_identity(&temp.path(), &token, image_fingerprint(&image)?)?
        .ok_or("completed worker has no durable startup identity")?;
    private_file(
        &temp.0.join("worker-started.txt"),
        format!("{identity:?}\n").as_bytes(),
        0o600,
    );
    assert!(!temp.path().join("result").exists());
    if crash {
        println!("supervisor_intentional_exit=73 observed=false worker_start_durable=true verification_started=false");
        use std::io::Write;
        std::io::stdout().flush()?;
        std::process::exit(73);
    }
    drop(launcher);
    drop(task);
    drop(supervisor);
    drop(launches);
    drop(owner);
    recover_without_live_capture()
}

fn recover_without_live_capture() -> Result<(), Error> {
    let (image, root) = opt_in()?;
    let f = test_fixture::load()?;
    let resources = resources(Case::Check);
    let recovery = DurableDag::recover(
        &root.join("journal"),
        JournalLimits {
            snapshot_bytes: 256 << 10,
        },
        ArtifactStore::open(
            &root.join("artifacts"),
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
    )?;
    assert_eq!(recovery.unresolved_attempts().len(), 1);
    let prior = &recovery.unresolved_attempts()[0];
    assert!(!prior.worker_stopped && !prior.verification_active);
    let token = Token::decode(&fs::read(root.join("task/token"))?)?;
    let expected = worker_start_identity(&root.join("task"), &token, image_fingerprint(&image)?)?
        .ok_or("startup identity missing in fresh recovery")?;
    let mut launches = LaunchStore::open(&root.join("launches"), LaunchLimits { records: 16 })?;
    let mut supervisor = Supervisor::recover(&root.join("supervisor"), prior)?;
    assert!(
        supervisor.observed_identity().is_none(),
        "test must recover a missed observation"
    );
    let mut receipt = None;
    let owner = recovery.resume(
        |attempt| {
            assert!(!attempt.verification_active);
            receipt = Some(stop(&mut supervisor, &mut launches, attempt.lease)?);
            Ok(())
        },
        || 100_000,
    )?;
    assert_eq!(supervisor.observed_identity(), Some(&expected));
    assert!(os_worker::exited(&expected, &supervisor.service_name())?);
    assert_eq!(supervisor.status()?, Status::Stopped);
    assert_eq!(owner.resource_use()?, Resources::default());
    assert!(owner.ready()?.is_empty());
    assert!(receipt.is_some());
    private_file(&root.join("recovered.txt"), format!("LiveObservationMissed=true\nWorkerIdentityDurablyBound=true\nExactKernelStopConfirmed=true\nPriorVerifierActive=false\nHistoricalEligibilityRevived=false\nIdentity={expected:?}\n").as_bytes(), 0o600);
    println!("cpu_supervisor_unobserved_recovery=PASS durable_identity=true exact_kernel_stop=true prior_verifier_active=false resources=0 epoch=2");
    Ok(())
}

#[test]
#[ignore = "actual check worker, deliberately no live coordinator capture"]
fn cpu_supervisor_recovers_worker_exit_without_live_capture() -> Result<(), Error> {
    run_without_live_capture(false)
}

#[test]
#[ignore = "intentional exit73 after worker completion but before coordinator observation"]
fn cpu_supervisor_crashes_without_live_capture() -> Result<(), Error> {
    run_without_live_capture(true)
}

#[test]
#[ignore = "fresh actor recovery of a worker never live-observed by the coordinator"]
fn cpu_supervisor_fresh_recovery_without_live_capture() -> Result<(), Error> {
    recover_without_live_capture()
}
