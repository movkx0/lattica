//! Native sixteen-wallet probes, with separately reported seeded calibration.
use super::pool_resume::{
    journal_limits, limits as shared_limits, now_ms, setting, store_limits as shared_store_limits,
};
use super::*;
use crate::block_v2::execution::{
    dag::CandidateId,
    scheduler::{CostModel, TimingCalibration, TimingIdentity},
};

const WALLETS: [usize; 16] = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60];
const MODES: [u64; 4] = [1, 3, 3, 12];
const COUNTS: [usize; 4] = [8, 4, 3, 1];
const COMPLETED: [usize; 4] = [8, 12, 15, 16];

/// Retain each public input plus one maximum-size proof per semantic job.
/// This is test fixture storage within the unchanged coordinator RAM cap.
fn artifact_bytes() -> usize {
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let max = crate::block_v2::profile::MAX_PROOF_BYTES;
    WALLETS.iter().fold(WALLETS.len() * max, |total, index| {
        let len = usize::try_from(
            fs::metadata(directory.join(format!("wallet.{index}")))
                .unwrap()
                .len(),
        )
        .unwrap();
        assert!((1..=max).contains(&len));
        total.checked_add(len).unwrap()
    })
}

pub(super) fn store_limits() -> StoreLimits {
    StoreLimits {
        bytes: artifact_bytes() as u64,
        ..shared_store_limits()
    }
}

pub(super) fn limits(peak: Resources, jobs: Resources) -> crate::block_v2::execution::dag::Limits {
    crate::block_v2::execution::dag::Limits {
        artifact_bytes: artifact_bytes(),
        ..shared_limits(peak, jobs)
    }
}

fn seeded_calibration() -> bool {
    std::env::var_os("LATTICA_NATIVE_SEED_NODES").is_some()
}

fn seed_nodes(owner: &mut DurableDag, f: &Fixture, selection: &Selection) {
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
        assert!(in_phase(job, 0) || in_phase(job, 1));
        assert!(seen.insert(job.id()));
        drop(node);
        let ticket = VerifiedNode::verify_typed(job, &f.bootstrap.registry, &bytes).unwrap();
        owner.cache_node(ticket, bytes, now_ms()).unwrap();
    }
    assert_eq!(seen.len(), COMPLETED[1]);
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRecord {
    path: PathBuf,
    content_identity: [u8; 32],
    evidence: [u8; 32],
}

fn import_calibration(costs: &mut CostModel, cap: &WorkerCapabilities) -> bool {
    if std::env::var("LATTICA_NATIVE_USE_CALIBRATION").as_deref() != Ok("1") {
        return false;
    }
    let path = PathBuf::from(std::env::var_os("LATTICA_NATIVE_TIMING_RECORDS").unwrap());
    assert!(fs::metadata(&path).unwrap().len() <= 16 << 10);
    let records: Vec<ApprovedRecord> = serde_json::from_slice(&read(&path)).unwrap();
    assert_eq!(records.len(), 7);
    for record in records {
        let bytes = read(&record.path);
        assert_eq!(bytes.len(), TimingCalibration::ENCODED_BYTES);
        assert_eq!(
            process::configuration_digest(&bytes).unwrap(),
            record.content_identity
        );
        costs
            .import_calibration(
                cap,
                &TimingCalibration::decode_host(&bytes).unwrap(),
                record.evidence,
            )
            .unwrap();
    }
    true
}

pub(super) fn sixteen_wallet_fixture() -> (Registry<12>, Selection, PolicyContext) {
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let registry = Registry::<12> {
        height: serde_json::from_slice(&read(&directory.join("height.json"))).unwrap(),
        caps: std::array::from_fn(|index| {
            let bytes = read(&directory.join(format!("key.{}", index + 1)));
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    assert_eq!(registry.height, 1 << 18);
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let mut policies = Vec::new();
    let mut summaries = Vec::new();
    let inputs: Vec<_> = WALLETS
        .into_iter()
        .map(|index| {
            let bytes = read(&directory.join(format!("wallet.{index}")));
            let wallet = VerifiedWallet::verify_typed(
                pin,
                &registry,
                typed_fixture::CHAIN,
                Policy::JoinSplit,
                &bytes,
            )
            .unwrap();
            assert!(!summaries.contains(&wallet.summary().root));
            summaries.push(wallet.summary().root);
            policies.push((wallet.artifact(), Policy::JoinSplit));
            PublicInput::new(wallet, bytes).unwrap()
        })
        .collect();
    let selection = Selection::new(pin, typed_fixture::CHAIN, &inputs).unwrap();
    assert_eq!(selection.jobs().len(), 16);
    assert_eq!(
        (
            selection.root().expected().count,
            selection.root().expected().level
        ),
        (16, 6)
    );
    (
        registry,
        selection,
        PolicyContext::new([8; 32], policies).unwrap(),
    )
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
    if phase == 0 || (phase == 2 && seeded_calibration()) {
        let store = ArtifactStore::create(&directory.join("artifacts"), store_limits()).unwrap();
        let mut owner = DurableDag::create(
            &directory.join("journal"),
            journal_limits(),
            store,
            selection.root().pin(),
            typed_fixture::CHAIN,
            phase as u64 + 1,
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
        if seeded_calibration() {
            assert_eq!(phase, 2);
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
        let (owner, candidate) = recovery
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
            COMPLETED[phase - 1]
        );
        (owner, candidate)
    }
}

fn host_identity(f: &Fixture) -> TimingIdentity {
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

fn save_calibration(
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

// Balance the two merge lifetimes within the unchanged 180-second cap.
// A level-three merge shares immutable mode-three preprocessing with its
// level-two predecessors; phase two additionally exercises level four.
fn in_phase(job: &crate::block_v2::execution::job::Job, phase: usize) -> bool {
    match phase {
        0 => job.expected().level == 1,
        1 => {
            (job.expected().level == 2 && job.start() < 12)
                || (job.expected().level == 3 && job.start() == 0)
        }
        2 => {
            (job.expected().level == 2 && job.start() == 12)
                || (job.expected().level == 3 && job.start() == 8)
                || job.expected().level == 4
        }
        3 => job.expected().level == 6,
        _ => false,
    }
}

#[test]
#[ignore = "sixteen-wallet native probes; optional seeded calibration is separately reported"]
fn native_sixteen_wallet_calibration_phase() {
    let started = Instant::now();
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let route = std::env::var("LATTICA_NATIVE_TIMING_ROUTE").unwrap();
    assert_eq!(route, "probe");
    let deadline = setting("LATTICA_NATIVE_DAG_DEADLINE_MS");
    assert!(deadline > now_ms());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selection, context) = sixteen_wallet_fixture();
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
    let mut launches = if phase == 0 || (phase == 2 && seeded_calibration()) {
        LaunchStore::create(&f.bootstrap.launches, LaunchLimits { records: 16 }).unwrap()
    } else {
        LaunchStore::open(&f.bootstrap.launches, LaunchLimits { records: 16 }).unwrap()
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
        let imported = import_calibration(&mut costs, &cap);
        fs::write(
            f.directory.join("calibration-imported.json"),
            serde_json::to_vec(&imported).unwrap(),
        )
        .unwrap();
        let mut phase_jobs: Vec<_> = selection
            .jobs()
            .filter(|job| in_phase(job, phase))
            .collect();
        phase_jobs.sort_by_key(|job| (job.expected().level, job.start()));
        assert_eq!(phase_jobs.len(), COUNTS[phase]);
        for (index, job) in phase_jobs.into_iter().enumerate() {
            assert!(started.elapsed() < Duration::from_secs(175) && now_ms() < deadline);
            assert_eq!(owner.status(job.id()).unwrap(), JobStatus::Ready);
            let proving = Instant::now();
            // Explicit probes admit this assignment; unknown classes retain 180 s.
            // Approved exact-class estimates retain their existing 10% margin.
            // Pool scheduling must still admit its full downstream path.
            let estimate = costs.estimate(&cap, job, index != 0).unwrap().0;
            let lease = owner
                .lease(job.id(), WorkerId(2), jobs, estimate, 180_000, now_ms())
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
    f.check_memory_reports(COUNTS[phase]);
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    fs::write(f.directory.join("phase-summary.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "phase":phase, "route":route, "mode":MODES[phase], "levels":accepted.iter().map(|id| selection.jobs().find(|job| job.id() == *id).unwrap().expected().level).collect::<Vec<_>>(), "proofs":COUNTS[phase],
        "retained_proofs":COMPLETED[phase], "epoch":phase + 1, "deadline_ms":deadline,
        "jobs":accepted.iter().map(|job| job.to_bytes()).collect::<Vec<_>>(), "wallets":WALLETS,
        "real_local_adapter":route == "pool", "durable_recovery":phase > 0 && !(phase == 2 && seeded_calibration()),
        "existing_recursive_proofs_imported":seeded_calibration(), "reservations_held_until_exit":true,
        "root_available":phase == 3, "calibration":calibration
    })).unwrap()).unwrap();
    println!("native_sixteen_wallet_verified route={route} phase={phase} proofs={} retained_proofs={} gpu_initialized_in_coordinator=false", COUNTS[phase], COMPLETED[phase]);
}

#[test]
#[ignore = "independent CPU recovery and root mutation audit after each native sixteen-wallet phase"]
fn native_sixteen_wallet_saved_dag_verifies_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let (registry, selection, context) = sixteen_wallet_fixture();
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
        phase as u64 + 2,
        limits(peak, jobs),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert_eq!(recovery.previous_epoch(), phase as u64 + 1);
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
    println!("native_sixteen_wallet_saved_cpu_verified phase={phase} retained_dag=true gpu_initialized=false unresolved_owners=0");
}
