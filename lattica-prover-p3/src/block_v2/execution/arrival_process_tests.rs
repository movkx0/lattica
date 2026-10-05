//! Real bounded arrival-driven CPU proving. Opt-in only; no host activation.
//! The 3-transaction join-split fixture is not full-type/full64 qualification.
use super::*;
use crate::block_v2::{
    codec,
    commitment::{Context, NodeSummary},
    execution::{
        dag::JobStatus,
        job::{ArtifactKind, ArtifactRef, JobId},
        selection::{PublicInput, Selection},
    },
    machine::programs,
};

fn now(start: Instant) -> Result<u64, Error> {
    Ok(u64::try_from(start.elapsed().as_millis())?)
}

fn external_root() -> Result<commitment::Digest, Error> {
    let text = std::env::var("LATTICA_V2_ARRIVAL_EXPECTED_ROOT")?;
    if text.len() != 64 || !text.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err("independent expected root must be 32 hexadecimal bytes".into());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(commitment::digest_from_bytes(&bytes)?)
}

fn execute(
    owner: &mut DurableDag,
    launches: &mut LaunchStore,
    launch_path: &Path,
    root: &Path,
    image: &Path,
    fixture: &test_fixture::PublicFixture,
    job: &Job,
    index: usize,
    clock: Instant,
    reused_left: Option<ArtifactRef>,
) -> Result<Vec<u8>, Error> {
    assert_eq!(owner.status(job.id())?, JobStatus::Ready);
    let budget = resources(Case::Prove);
    // Research qualification deadline, not the production 180s admission model.
    let lease = owner.lease(job.id(), WorkerId(1), budget, 1, 1_900_000, now(clock)?)?;
    let assignment = owner.assignment(lease)?;
    if let Some(artifact) = reused_left {
        assert_eq!(owner.input_manifest(lease)?.first(), Some(&artifact));
    }
    let dir = root.join(format!("job-{index:02}"));
    DirBuilder::new().mode(0o700).create(&dir)?;
    let task_path = dir.join("task");
    let supervisor_path = dir.join("supervisor");
    let mut supervisor = Supervisor::prepare(
        &supervisor_path,
        owner,
        lease,
        launches,
        launch_path,
        &task_path,
        image,
        1800,
    )?;
    let task = supervisor.issue_task(
        owner,
        lease,
        launches,
        WorkerConfig {
            registry: fixture.registry.clone(),
            pin: fixture.pin,
            chain: [0x5a; 32],
            executable: image_fingerprint(image)?,
            timeout_seconds: 1800,
            mode: Mode::Prove,
        },
    )?;
    let mut launcher = supervisor.dispatch(owner, lease, launches, &task)?;
    observe(&mut supervisor, &mut launcher)?;
    let identity = supervisor
        .observed_identity()
        .ok_or("arrival worker unobserved")?
        .clone();
    private_file(
        &dir.join("worker-started.txt"),
        format!("{identity:?}\n").as_bytes(),
        0o600,
    );
    println!("arrival_job_start index={index} operation={:?} level={} start={} unit={} observed={identity:?}",
        job.operation(), job.expected().level, job.start(), supervisor.service_name());
    std::io::stdout().flush()?;
    let helper = wait_launcher(&mut launcher)?;
    if !helper.success() {
        return Err(format!("arrival worker failed: {helper}").into());
    }
    drop(supervisor);
    let mut supervisor = Supervisor::reopen(&supervisor_path, owner, lease)?;
    assert_eq!(supervisor.observed_identity(), Some(&identity));
    let receipt = stop(&mut supervisor, launches, lease)?;
    assert_eq!(owner.resource_use()?, budget);
    receipt.acknowledge(owner, now(clock)?)?;
    assert_eq!(owner.resource_use()?, budget);
    let verification = owner.begin_guarded_verification(lease, now(clock)?)?;
    drop(task);
    let task = TaskOwner::open(&task_path)?;
    let result = task.result(&assignment)?;
    let bytes = result.bytes().to_vec();
    let verified = verification.verify(&fixture.registry, bytes.clone());
    if let Some(error) = verified.error() {
        return Err(error.to_owned().into());
    }
    assert_eq!(
        owner.finish_guarded_verification(verified, now(clock)?)?,
        Completion::Accepted
    );
    assert_eq!(owner.resource_use()?, Resources::default());
    private_file(&dir.join("accepted.bin"), &bytes, 0o600);
    private_file(&dir.join("worker-status.txt"),
        b"PersistedIdentityMatched=true\nKernelStopConfirmed=true\nOwnerCpuVerified=true\nResourcesReleased=true\n", 0o600);
    println!("arrival_job_accept index={index} job={} bytes={} elapsed_ms={} input_verification_ms={} proving_ms={} reused_left={}",
        hex(&job.id().to_bytes()), bytes.len(), now(clock)?, result.timings().input_verification_ms,
        result.timings().proving_ms, reused_left.is_some());
    std::io::stdout().flush()?;
    Ok(bytes)
}

#[test]
#[ignore = "15 actual full-strength CPU jobs; exclusive bounded arrival controller and independent Zig root required"]
fn cpu_arrivals_reuse_subtree_and_finalize_three_wallet_root() -> Result<(), Error> {
    if std::env::var("LATTICA_V2_RUN_CPU_ARRIVAL_PROOF").as_deref() != Ok("1") {
        return Err("explicit arrival proving opt-in required".into());
    }
    let (image, root) = opt_in()?;
    DirBuilder::new().mode(0o700).create(&root)?;
    let clock = Instant::now();
    let fixture = test_fixture::load_single_public()?;
    let inputs = fixture
        .wallets
        .iter()
        .zip(&fixture.bytes)
        .map(|(w, b)| PublicInput::new(*w, b.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let first = Selection::new(fixture.pin, [0x5a; 32], &inputs[..2])?;
    let sealed = Selection::new(fixture.pin, [0x5a; 32], &inputs[..3])?;
    if sealed.root().expected().root != external_root()? {
        return Err("arrival selection differs from independent expected statement".into());
    }
    let store = ArtifactStore::create(
        &root.join("artifacts"),
        StoreLimits {
            bytes: 128 << 20,
            entries: 512,
        },
    )?;
    let mut owner = DurableDag::create(
        &root.join("journal"),
        JournalLimits {
            snapshot_bytes: 512 << 10,
        },
        store,
        fixture.pin,
        [0x5a; 32],
        1,
        Limits {
            jobs: 256,
            candidates: 8,
            attempts: 64,
            artifact_bytes: 128 << 20,
            recovery_window_ms: 10,
            workers: resources(Case::Prove),
        },
    )?;
    let launch_path = root.join("launches");
    let mut launches = LaunchStore::create(&launch_path, LaunchLimits { records: 64 })?;
    let deadline = 7_200_000; // Explicit long research deadline; never production admission evidence.
    let before = first.attach(&mut owner, [1; 32], deadline, now(clock)?)?;
    let subtree = first
        .jobs()
        .find(|j| j.start() == 0 && j.expected().level == 1)
        .ok_or("missing two-wallet subtree")?;
    let mut completed = Vec::<JobId>::new();
    for id in subtree.dependencies() {
        let job = first
            .jobs()
            .find(|j| j.id() == *id)
            .ok_or("missing wrapper")?;
        execute(
            &mut owner,
            &mut launches,
            &launch_path,
            &root,
            &image,
            &fixture,
            job,
            completed.len(),
            clock,
            None,
        )?;
        completed.push(job.id());
    }
    let bytes = execute(
        &mut owner,
        &mut launches,
        &launch_path,
        &root,
        &image,
        &fixture,
        subtree,
        completed.len(),
        clock,
        None,
    )?;
    completed.push(subtree.id());
    let reused = ArtifactRef::from_bytes(ArtifactKind::Node, &bytes)?;
    let current = sealed.attach(&mut owner, [2; 32], deadline, now(clock)?)?;
    owner.cancel(before, now(clock)?)?;
    assert_eq!(owner.status(subtree.id())?, JobStatus::Completed);
    assert!(sealed.jobs().any(|j| j.id() == subtree.id()));
    assert!(owner
        .candidate_result(current, [2; 32], now(clock)?)
        .is_err());
    owner.seal(current, [2; 32], now(clock)?)?;
    let seal_time = now(clock)?;
    // A later arrival gets another immutable selection and is deferred. It must
    // neither reopen this sealed candidate nor fence the shared completed work.
    let late = Selection::new(fixture.pin, [0x5a; 32], &inputs[..4])?;
    let deferred = late.attach(&mut owner, [3; 32], deadline, now(clock)?)?;
    owner.cancel(deferred, now(clock)?)?;
    assert_eq!(owner.status(subtree.id())?, JobStatus::Completed);
    assert!(owner
        .candidate_result(current, [3; 32], now(clock)?)
        .is_err());
    println!("arrival_selection_sealed count=3 reused_jobs=3 late_count=4 deferred=true elapsed_ms={seal_time}");
    std::io::stdout().flush()?;
    for job in sealed.jobs() {
        if owner.status(job.id())? == JobStatus::Completed {
            continue;
        }
        let left = if job.expected().level == 2 && job.start() == 0 {
            Some(reused)
        } else {
            None
        };
        execute(
            &mut owner,
            &mut launches,
            &launch_path,
            &root,
            &image,
            &fixture,
            job,
            completed.len(),
            clock,
            left,
        )?;
        completed.push(job.id());
    }
    assert_eq!(completed.len(), 15);
    assert_eq!(
        completed
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        15
    );
    let root_bytes = owner
        .candidate_result(current, [2; 32], now(clock)?)?
        .ok_or("root not ready")?
        .to_vec();
    VerifiedNode::verify(sealed.root(), &fixture.registry, &root_bytes)?;
    assert!(owner
        .candidate_result(before, [1; 32], now(clock)?)
        .is_err());
    assert!(owner
        .candidate_result(deferred, [3; 32], now(clock)?)
        .is_err());
    assert_eq!(owner.resource_use()?, Resources::default());
    let export = root.join("root-only");
    DirBuilder::new().mode(0o700).create(&export)?;
    let registry_path = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_SINGLE")?);
    for name in ["height", "key.1", "key.2", "key.3"] {
        private_file(
            &export.join(name),
            &test_fixture::read(&registry_path.join(name), 2048)?,
            0o600,
        );
    }
    private_file(&export.join("root.bin"), &root_bytes, 0o600);
    assert_eq!(fs::read_dir(&export)?.count(), 5);
    let elapsed = now(clock)?;
    println!("cpu_arrivals=PASS count=3 level=6 jobs=15 wrappers=3 empties=5 merges=7 reused_jobs=3 proof_bytes={} fixture_to_root_ms={elapsed} seal_to_root_ms={} root={} root_only_files=5 join_split_fixture_only=true full64=false complete_host_finalization=false production_ready=false",
        root_bytes.len(), elapsed-seal_time, hex(&commitment::digest_bytes(sealed.root().expected().root)?));
    Ok(())
}

#[test]
#[ignore = "fresh CPU root-only arrival replay; no wallet or intermediate proof files"]
fn cpu_arrival_root_replays_without_wallet_or_inner_proofs() -> Result<(), Error> {
    let (registry, pin) = test_fixture::load_single_registry()?;
    let dir = PathBuf::from(std::env::var("LATTICA_V2_EXECUTION_TEST_SINGLE")?);
    let inventory = fs::read_dir(&dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let expected_inventory = ["height", "key.1", "key.2", "key.3", "root.bin"]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect();
    assert_eq!(inventory, expected_inventory);
    let bytes = test_fixture::read(
        &dir.join("root.bin"),
        crate::block_v2::profile::MAX_PROOF_BYTES,
    )?;
    let proof = codec::decode_node(&bytes)?;
    let expected = NodeSummary {
        context: Context {
            profile_id: pin.profile(),
            chain_id: [0x5a; 32],
        },
        level: 6,
        count: 3,
        root: external_root()?,
    };
    registry.verify(
        pin.profile(),
        &proof,
        &programs::statement(expected, programs::MERGE),
    )?;
    let mut wrong = expected;
    wrong.root[0] ^= 1;
    assert!(registry
        .verify(
            pin.profile(),
            &proof,
            &programs::statement(wrong, programs::MERGE)
        )
        .is_err());
    let mut mutated = bytes.clone();
    *mutated.last_mut().ok_or("empty root")? ^= 1;
    if let Ok(decoded) = codec::decode_node(&mutated) {
        assert!(registry
            .verify(
                pin.profile(),
                &decoded,
                &programs::statement(expected, programs::MERGE)
            )
            .is_err());
    }
    println!("cpu_arrival_root_replayed=PASS count=3 level=6 bytes={} wallet_proofs_loaded=0 inner_proofs_loaded=0 wrong_root_rejected=true mutation_rejected=true production_ready=false", bytes.len());
    Ok(())
}
