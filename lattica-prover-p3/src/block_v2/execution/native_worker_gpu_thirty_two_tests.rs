//! Explicitly seeded 32-wallet calibration; not a fresh full-DAG qualification.
use super::pool_resume::{journal_limits, now_ms, setting};
#[path = "native_worker_gpu_thirty_two_fixture.rs"]
mod fixture;
#[path = "native_worker_gpu_thirty_two_pool_tests.rs"]
mod fresh_pool;
#[path = "native_worker_gpu_thirty_two_timing_tests.rs"]
mod timing;
#[path = "native_worker_gpu_sixty_four_tests.rs"]
mod sixty_four;
use super::*;
use crate::block_v2::execution::{
    dag::CandidateId,
    scheduler::{CostModel, TimingCalibration, TimingIdentity},
};
use fixture::{limits, store_limits, thirty_two_wallet_fixture, WALLETS};

const MODES: [u64; 4] = [11, 3, 3, 12];
fn probe() -> bool {
    matches!(
        std::env::var("LATTICA_NATIVE_TIMING_ROUTE").as_deref(),
        Ok("probe" | "finalizer")
    )
}
fn standalone_finalizer() -> bool {
    std::env::var("LATTICA_NATIVE_TIMING_ROUTE").as_deref() == Ok("finalizer")
}
fn seed_count() -> usize {
    if standalone_finalizer() {
        31
    } else {
        15
    }
}
fn is_seed(job: &Job) -> bool {
    if standalone_finalizer() {
        job.expected().level < 6
    } else {
        job.start() < 16 && job.expected().level <= 4
    }
}
fn epoch(phase: usize) -> u64 {
    if standalone_finalizer() {
        1
    } else {
        phase as u64 + 1
    }
}
fn count(phase: usize) -> usize {
    [8, 4, 4, 1][phase]
}
fn completed(phase: usize) -> usize {
    [23, 27, 31, 32][phase]
}
fn in_phase(job: &Job, phase: usize) -> bool {
    match phase {
        0 => job.expected().level == 1 && job.start() >= 16,
        1 => job.expected().level == 2 && job.start() >= 16,
        2 => {
            (job.start() >= 16 && [3, 4].contains(&job.expected().level))
                || job.expected().level == 5
        }
        3 => job.expected().level == 6,
        _ => false,
    }
}
fn seed_nodes(owner: &mut DurableDag, f: &Fixture, selection: &Selection) {
    assert!(probe());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SEED_NODES").unwrap());
    let mut seen = std::collections::BTreeSet::new();
    for entry in fs::read_dir(directory).unwrap() {
        let bytes = read(&entry.unwrap().path());
        let storage = codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
        let node = storage.node(&bytes).unwrap();
        let job = selection
            .jobs()
            .find(|job| job.expected_public() == node.public)
            .unwrap();
        assert!(is_seed(job) && seen.insert(job.id()));
        drop(node);
        let ticket = VerifiedNode::verify_typed(job, &f.bootstrap.registry, &bytes).unwrap();
        owner.cache_node(ticket, bytes, now_ms()).unwrap();
    }
    assert_eq!(seen.len(), seed_count());
}

#[test]
#[ignore = "CPU-only verification of public calibration seeds; separate finalizer workflow imports 31 nodes"]
fn native_thirty_two_seed_selection() {
    assert!(!gpu_hash::is_enabled() && probe());
    let (registry, selection, _) = thirty_two_wallet_fixture();
    let source = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SEED_SOURCE").unwrap());
    let output = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SEED_NODES").unwrap());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    let mut seen = std::collections::BTreeSet::new();
    for entry in fs::read_dir(source).unwrap() {
        let path = entry.unwrap().path();
        let bytes = read(&path);
        let storage = codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
        let node = storage.node(&bytes).unwrap();
        let job = selection
            .jobs()
            .find(|job| job.expected_public() == node.public)
            .unwrap();
        assert!(is_seed(job) && seen.insert(job.id()));
        drop(node);
        VerifiedNode::verify_typed(job, &registry, &bytes).unwrap();
        fs::write(output.join(path.file_name().unwrap()), bytes).unwrap();
    }
    assert_eq!(seen.len(), seed_count());
    assert!(!gpu_hash::is_enabled());
    println!(
        "native_thirty_two_seed_selection selected_nodes={} cpu_verified=true gpu_initialized=false", seed_count()
    );
}

fn checkpoint_owner(
    directory: &Path,
    phase: usize,
    f: &Fixture,
    selection: &Selection,
    context: &PolicyContext,
    deadline: u64,
) -> (DurableDag, CandidateId) {
    let (peak, jobs) = worker_budget::resources(&f.assignment).unwrap();
    if phase == 0 || standalone_finalizer() {
        let store = ArtifactStore::create(&directory.join("artifacts"), store_limits()).unwrap();
        let mut owner = DurableDag::create(
            &directory.join("journal"),
            journal_limits(),
            store,
            selection.root().pin(),
            typed_fixture::CHAIN,
            1,
            limits(peak, jobs),
        )
        .unwrap();
        let candidate = selection
            .attach(&mut owner, [31; 32], deadline, now_ms())
            .unwrap();
        owner.seal(candidate, [31; 32], now_ms()).unwrap();
        assert!(selection
            .jobs()
            .all(|job| owner.verified_node_bytes(job.id()).unwrap().is_none()));
        if probe() {
            seed_nodes(&mut owner, f, selection);
        }
        (owner, candidate)
    } else {
        let store = ArtifactStore::open(&directory.join("artifacts"), store_limits()).unwrap();
        let recovery = DurableDag::recover_typed(
            &directory.join("journal"),
            journal_limits(),
            store,
            selection.root().pin(),
            &f.bootstrap.registry,
            typed_fixture::CHAIN,
            phase as u64 + 1,
            limits(peak, jobs),
            |artifact| context.policy(artifact),
        )
        .unwrap();
        assert_eq!(recovery.previous_epoch(), phase as u64);
        assert_eq!(recovery.previous_candidates().len(), 1);
        let previous = &recovery.previous_candidates()[0];
        assert_eq!(previous.root, selection.root().id());
        assert_eq!(previous.eligibility, [31; 32]);
        assert!(previous.sealed && !previous.cancelled);
        assert!(
            recovery.unresolved_attempts().is_empty()
                && recovery.unresolved_workspaces().is_empty()
        );
        let now = now_ms();
        let remaining = deadline.checked_sub(now).filter(|ms| *ms > 0).unwrap();
        let (mut owner, candidate) = recovery
            .resume_sealed_with_workspaces(
                |_| Err("unexpected unresolved calibration attempt".into()),
                |_| Err("unexpected unresolved calibration workspace".into()),
                || now,
                selection.root().id(),
                [31; 32],
                remaining,
            )
            .unwrap();
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
        assert_eq!(
            selection
                .jobs()
                .filter(|job| owner.status(job.id()).unwrap() == JobStatus::Completed)
                .count(),
            completed(phase - 1)
        );
        if probe() {
            seed_nodes(&mut owner, f, selection);
        }
        (owner, candidate)
    }
}

pub(super) fn host_identity(f: &Fixture) -> TimingIdentity {
    let path = PathBuf::from(std::env::var_os("LATTICA_NATIVE_TIMING_IDENTITY").unwrap());
    assert!(fs::metadata(&path).unwrap().len() <= 4096);
    let fields: [[u8; 32]; 5] = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    // The controller pins this executable's SHA256; the existing native
    // handshake independently uses the transport's image fingerprint.
    TimingIdentity::new(
        fields[0],
        fields[1],
        f.bootstrap.executable,
        fields[2],
        fields[3],
        fields[4],
    )
    .unwrap()
}

pub(super) fn save_calibration(
    directory: &Path,
    index: usize,
    record: TimingCalibration,
) -> serde_json::Value {
    let bytes = record.encode();
    let name = format!("timing-{index}.bin");
    assert!(!directory.join(&name).exists());
    fs::write(directory.join(&name), bytes).unwrap();
    serde_json::json!({"file":name, "content_identity": process::configuration_digest(&bytes).unwrap()})
}

#[test]
#[ignore = "seeded 32-wallet native calibration; finalizer may use a separately declared seeded workflow"]
fn native_thirty_two_calibration_phase() {
    let started = Instant::now();
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let route = std::env::var("LATTICA_NATIVE_TIMING_ROUTE").unwrap();
    assert!(probe());
    assert!(!standalone_finalizer() || phase == 3);
    let deadline = setting("LATTICA_NATIVE_DAG_DEADLINE_MS");
    assert!(deadline > now_ms());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selection, context) = thirty_two_wallet_fixture();
    let mut f = Fixture::with_registry(
        "full-size",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    f.bootstrap.launches = directory.join("launches");
    let (mut owner, candidate) =
        checkpoint_owner(&directory, phase, &f, &selection, &context, deadline);
    let (_, jobs) = worker_budget::resources(&f.assignment).unwrap();
    let mut worker = ProcessWorker::prepare(
        &mut owner,
        f.bootstrap.config(&f.assignment).unwrap(),
        WorkerId(1),
        WorkerId(2),
        now_ms(),
    )
    .unwrap();
    let mut launches = if phase == 0 || standalone_finalizer() {
        LaunchStore::create(&f.bootstrap.launches, LaunchLimits { records: 32 }).unwrap()
    } else {
        LaunchStore::open(&f.bootstrap.launches, LaunchLimits { records: 32 }).unwrap()
    };
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(worker.service_identity().unwrap()).unwrap(),
    )
    .unwrap();
    let identity = host_identity(&f);
    let mut accepted = Vec::new();
    let mut timings = Vec::new();
    let mut calibration = Vec::new();
    {
        // Explicit host calibration assignments use the ordinary native job,
        // lease, resource and CPU-verification path. No scheduler estimates
        // are fabricated to get the first observations of unknown classes.
        worker.replace_context(&context).unwrap();
        let cap = worker
            .scheduling_capabilities_with_timing(identity)
            .unwrap();
        let mut costs = CostModel::new(180_000).unwrap();
        let mut phase_jobs: Vec<_> = selection
            .jobs()
            .filter(|job| in_phase(job, phase))
            .collect();
        phase_jobs.sort_by_key(|job| (job.expected().level, job.start()));
        assert_eq!(phase_jobs.len(), count(phase));
        for (index, job) in phase_jobs.into_iter().enumerate() {
            assert!(started.elapsed() < Duration::from_secs(175) && now_ms() < deadline);
            assert_eq!(owner.status(job.id()).unwrap(), JobStatus::Ready);
            let proving = Instant::now();
            let lease = owner
                .lease(job.id(), WorkerId(2), jobs, 180_000, 180_000, now_ms())
                .unwrap();
            let task = worker.task(&mut owner, lease, now_ms()).unwrap();
            let token = launches
                .issue_bound(
                    &mut owner,
                    lease,
                    &task.request().unwrap(),
                    worker.execution_digest().unwrap(),
                )
                .unwrap();
            let completed = worker.execute(&token, task).unwrap();
            assert!(!worker.retirement_requested());
            let revoked = launches.revoke(lease).unwrap();
            assert!(launches.try_idle(&revoked).unwrap().is_some());
            let output = completed.reconcile(&mut owner, now_ms()).unwrap();
            let expected = owner.begin_verification(lease, now_ms()).unwrap();
            assert_eq!(expected.id(), job.id());
            let verified =
                VerifiedNode::verify_typed(&expected, &registry, output.bytes()).unwrap();
            assert_eq!(
                owner
                    .finish_verification(lease, Some((verified, output.bytes().to_vec())), now_ms())
                    .unwrap(),
                Completion::Accepted
            );
            let elapsed = u64::try_from(proving.elapsed().as_millis()).unwrap().max(1);
            costs.observe(&cap, job, index != 0, elapsed).unwrap();
            calibration.push(save_calibration(
                &f.directory,
                index,
                costs.export_calibration(&cap, job, index != 0).unwrap(),
            ));
            accepted.push(job.id());
            timings.push(elapsed as f64 / 1000.0);
        }
        if phase == 3 {
            let proof = owner
                .verified_node_bytes(selection.root().id())
                .unwrap()
                .unwrap();
            verify_mutations(selection.root(), &registry, proof);
            fs::write(f.directory.join("root.bin"), proof).unwrap();
        } else {
            assert!(owner
                .verified_node_bytes(selection.root().id())
                .unwrap()
                .is_none());
        }
        worker.close(&mut owner, now_ms()).unwrap();
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
    }
    assert!(now_ms() < deadline);
    f.check_memory_reports(count(phase));
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    fs::write(f.directory.join("phase-summary.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "phase":phase, "route":route, "mode":MODES[phase], "levels":accepted.iter().map(|id| selection.jobs().find(|job| job.id()==*id).unwrap().expected().level).collect::<Vec<_>>(), "proofs":count(phase),
        "retained_proofs":completed(phase), "epoch":epoch(phase), "deadline_ms":deadline,
        "jobs":accepted.iter().map(|job| job.to_bytes()).collect::<Vec<_>>(), "wallets":WALLETS,
        "real_local_adapter":false, "durable_recovery":phase > 0 && !standalone_finalizer(),
        "standalone_seeded_finalizer":standalone_finalizer(), "seed_nodes":seed_count(),
        "existing_recursive_proofs_imported":probe(), "reservations_held_until_exit":true,
        "root_available":phase == 3, "calibration":calibration
    })).unwrap()).unwrap();
    println!("native_thirty_two_calibration_verified route={route} phase={phase} proofs={} retained_proofs={} gpu_initialized_in_coordinator=false", count(phase), completed(phase));
}

#[test]
#[ignore = "independent CPU recovery and root mutation audit after each native thirty-two-wallet phase"]
fn native_thirty_two_saved_dag_verifies_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let (registry, selection, context) = thirty_two_wallet_fixture();
    let budget: serde_json::Value =
        serde_json::from_slice(&fs::read(public.join("budget.json")).unwrap()).unwrap();
    let (peak, jobs) = worker_budget::resources(&budget).unwrap();
    let store = ArtifactStore::open(&directory.join("artifacts"), store_limits()).unwrap();
    let recovery = DurableDag::recover_typed(
        &directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        epoch(phase) + 1,
        limits(peak, jobs),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert_eq!(recovery.previous_epoch(), epoch(phase));
    assert!(
        recovery.unresolved_attempts().is_empty() && recovery.unresolved_workspaces().is_empty()
    );
    assert_eq!(recovery.previous_candidates().len(), 1);
    assert!(recovery.previous_candidates()[0].sealed);
    assert_eq!(
        recovery.previous_candidates()[0].root,
        selection.root().id()
    );
    if phase == 3 {
        verify_mutations(
            selection.root(),
            &registry,
            &read(&public.join("full-size/root.bin")),
        );
    }
    println!("native_thirty_two_saved_cpu_verified phase={phase} retained_dag=true gpu_initialized=false unresolved_owners=0");
}
