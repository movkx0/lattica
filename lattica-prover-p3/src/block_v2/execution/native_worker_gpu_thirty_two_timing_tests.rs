//! Exact-image timing classes for mixed 32-wallet jobs, using 20 verified seeds.
//! This deliberately leaves the finalizer unproved; its separate qualification
//! is imported only after the new observations pass independent CPU audits.
use super::*;

const MODES: [u64; 4] = [1, 11, 3, 3];
fn probe() -> bool {
    std::env::var("LATTICA_NATIVE_TIMING_ROUTE").as_deref() == Ok("probe")
}
fn seed_count() -> usize {
    20
}
fn epoch(phase: usize) -> u64 {
    phase as u64 + 1
}
fn count(phase: usize) -> usize {
    [2, 2, 2, 5][phase]
}
fn completed(phase: usize) -> usize {
    [22, 24, 26, 31][phase]
}
fn in_phase(job: &Job, phase: usize) -> bool {
    match phase {
        0 => job.expected().level == 1 && [0, 2].contains(&job.start()),
        1 => job.expected().level == 1 && [16, 18].contains(&job.start()),
        2 => job.expected().level == 2 && [0, 16].contains(&job.start()),
        3 => {
            (job.expected().level == 3 && [0, 16].contains(&job.start()))
                || [4, 5].contains(&job.expected().level)
        }
        _ => false,
    }
}
fn is_seed(job: &Job) -> bool {
    job.expected().level < 6 && !(0..4).any(|phase| in_phase(job, phase))
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
#[ignore = "CPU-only selection and verification of 20 public timing-calibration seeds"]
fn native_thirty_two_targeted_seed_selection() {
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
        if !is_seed(job) {
            continue;
        }
        assert!(seen.insert(job.id()));
        drop(node);
        VerifiedNode::verify_typed(job, &registry, &bytes).unwrap();
        fs::write(output.join(path.file_name().unwrap()), bytes).unwrap();
    }
    assert_eq!(seen.len(), seed_count());
    assert!(!gpu_hash::is_enabled());
    println!(
        "native_thirty_two_targeted_seed_selection selected_nodes={} cpu_verified=true gpu_initialized=false", seed_count()
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
    if phase == 0 {
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
            completed(phase - 1)
        );
        (owner, candidate)
    }
}

#[test]
#[ignore = "11 fresh native timing probes with 20 verified seeds; no finalizer or fresh-workflow claim"]
fn native_thirty_two_targeted_calibration_phase() {
    let started = Instant::now();
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let route = std::env::var("LATTICA_NATIVE_TIMING_ROUTE").unwrap();
    assert!(probe());
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
    let (mut owner, _candidate) =
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
    let mut launches = if phase == 0 {
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
        assert!(owner
            .verified_node_bytes(selection.root().id())
            .unwrap()
            .is_none());
        assert_eq!(
            selection
                .jobs()
                .filter(|job| owner.status(job.id()).unwrap() == JobStatus::Completed)
                .count(),
            completed(phase)
        );
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
        "real_local_adapter":false, "durable_recovery":phase > 0,
        "standalone_seeded_finalizer":false, "seed_nodes":seed_count(),
        "existing_recursive_proofs_imported":probe(), "reservations_held_until_exit":true,
        "root_available":false, "calibration":calibration
    })).unwrap()).unwrap();
    println!("native_thirty_two_targeted_verified route={route} phase={phase} proofs={} retained_proofs={} gpu_initialized_in_coordinator=false", count(phase), completed(phase));
}

#[test]
#[ignore = "independent CPU recovery after each targeted native timing phase"]
fn native_thirty_two_targeted_saved_dag_verifies_without_worker() {
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
    assert!(!public.join("full-size/root.bin").exists());
    println!("native_thirty_two_targeted_saved_cpu_verified phase={phase} retained_dag=true gpu_initialized=false unresolved_owners=0");
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRecord {
    path: PathBuf,
    content_identity: [u8; 32],
    evidence: [u8; 32],
}

#[test]
#[ignore = "CPU-only scheduler diagnosis from approved exact-image timings; no workflow qualification"]
fn native_thirty_two_approved_cost_replay_without_gpu() {
    assert!(!gpu_hash::is_enabled());
    let (registry, selection, _) = thirty_two_wallet_fixture();
    let f = Fixture::with_registry(
        "diagnostic",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    let (peak, job_resources) = worker_budget::resources(&f.assignment).unwrap();
    let store = ArtifactStore::create(&f.directory.join("artifacts"), store_limits()).unwrap();
    let mut owner = DurableDag::create(
        &f.directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        typed_fixture::CHAIN,
        1,
        limits(peak, job_resources),
    )
    .unwrap();
    let worker = ProcessWorker::prepare(
        &mut owner,
        f.bootstrap.config(&f.assignment).unwrap(),
        WorkerId(1),
        WorkerId(2),
        0,
    )
    .unwrap();
    // Preparing a descriptor reserves accounting only: no service is started.
    // Use the real process binding so incompatible calibration cannot replay.
    let mut cap = worker
        .scheduling_capabilities_with_timing(host_identity(&f))
        .unwrap();
    cap.forecast_retained_mode = true;
    let path = PathBuf::from(std::env::var_os("LATTICA_NATIVE_TIMING_RECORDS").unwrap());
    assert!(fs::metadata(&path).unwrap().len() <= 16 << 10);
    let records: Vec<ApprovedRecord> = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(records.len(), 11);
    let mut costs = CostModel::new(180_000).unwrap();
    for record in records {
        assert_eq!(
            fs::metadata(&record.path).unwrap().len(),
            TimingCalibration::ENCODED_BYTES as u64
        );
        let bytes = fs::read(record.path).unwrap();
        assert_eq!(
            process::configuration_digest(&bytes).unwrap(),
            record.content_identity
        );
        costs
            .import_calibration(
                &cap,
                &TimingCalibration::decode_host(&bytes).unwrap(),
                record.evidence,
            )
            .unwrap();
    }
    let jobs: BTreeMap<_, _> = selection
        .jobs()
        .map(|job| (job.id(), job.clone()))
        .collect();
    let mut completed = std::collections::BTreeSet::new();
    let mut decisions = Vec::new();
    let mut now = 0u64;
    loop {
        let ready: Vec<_> = jobs
            .values()
            .filter(|job| {
                !completed.contains(&job.id())
                    && job.dependencies().iter().all(|id| completed.contains(id))
            })
            .map(Job::id)
            .collect();
        if ready.is_empty() {
            break;
        }
        let deadlines = ready.iter().map(|id| (*id, 600_000)).collect();
        let Some(choice) = costs
            .select(&jobs, &ready, &[cap.clone()], &deadlines, now)
            .unwrap()
        else {
            break;
        };
        let job = &jobs[&choice.job];
        decisions.push(serde_json::json!({"job":choice.job.to_bytes(),"mode":job.operation().proof_mode(),
            "level":job.expected().level,"count":job.expected().count,"start":job.start(),
            "warm":choice.warm,"service_ms":choice.service_ms,"remaining_path_ms":choice.remaining_path_ms,
            "source":format!("{:?}",choice.source),"simulated_start_ms":now}));
        now = now.checked_add(choice.service_ms).unwrap();
        assert!(completed.insert(choice.job));
        // This intentionally optimistic diagnosis assumes successful cache retention
        // and worker survival; it does not simulate the 180-second service teardown,
        // coordinator recovery, independent audits, or new live timing samples.
        cap.resident_mode = Some(job.operation().proof_mode());
    }
    // No child was ever launched. A normal close correctly requires a GPU
    // shutdown receipt, so reconcile this exact prepared-only workspace after
    // dropping its sole local descriptor. Never use this for a started worker.
    assert!(worker.pid().is_none() && worker.service_identity().is_none());
    assert!(!worker.has_pending());
    let workspace = worker.workspace().unwrap();
    drop(worker);
    drop(owner);
    let store = ArtifactStore::open(&f.directory.join("artifacts"), store_limits()).unwrap();
    let recovery = DurableDag::recover_typed(
        &f.directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        2,
        limits(peak, job_resources),
        |_| Err("diagnostic has no wallet artifacts".into()),
    )
    .unwrap();
    assert!(recovery.unresolved_attempts().is_empty());
    assert_eq!(recovery.unresolved_workspaces(), &[workspace]);
    let owner = recovery
        .resume_with_workspaces(
            |_| Err("diagnostic has no attempts".into()),
            |previous| {
                assert_eq!(*previous, workspace);
                Ok(())
            },
            || 0,
        )
        .unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(!gpu_hash::is_enabled());
    let report = serde_json::json!({"simulated":true,"gpu_initialized":false,"native_worker_started":false,"prepared_workspace_reconciled":true,
        "complete_workflow_qualified":false,"fresh_proofs":0,"approved_classes":11,
        "bootstrap_ms":180_000,"deadline_ms":600_000,"elapsed_estimate_ms":now,
        "selected_jobs":completed.len(),"total_jobs":jobs.len(),"all_jobs_selected":completed.len()==jobs.len(),
        "assumes_single_worker_survives":true,"models_worker_retirement":false,"decisions":decisions});
    fs::write(
        f.directory.join("cost-replay.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("native_thirty_two_cost_replay selected_jobs={} total_jobs={} simulated=true gpu_initialized=false",completed.len(),jobs.len());
}
