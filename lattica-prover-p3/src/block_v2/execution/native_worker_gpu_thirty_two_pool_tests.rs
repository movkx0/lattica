//! Shared fresh-pool execution and independent recovery under fixed service limits.
use super::*;

/// The fixture owns its exact graph and disk quotas. Both sizes exercise the
/// same production pool, process adapter, retirement and recovery machinery.
pub(super) struct PoolWorkload {
    pub(super) name: &'static str,
    pub(super) wallets: &'static [usize],
    pub(super) jobs: usize,
    pub(super) eligibility: [u8; 32],
    pub(super) timing_classes: usize,
    pub(super) fixture: fn() -> (Registry<12>, Selection, PolicyContext),
    pub(super) store_limits: fn() -> StoreLimits,
    pub(super) limits: fn(Resources, Resources) -> crate::block_v2::execution::dag::Limits,
}

fn thirty_two() -> PoolWorkload {
    PoolWorkload {
        name: "thirty_two",
        wallets: &WALLETS,
        jobs: 32,
        eligibility: [31; 32],
        timing_classes: 11,
        fixture: thirty_two_wallet_fixture,
        store_limits,
        limits,
    }
}

fn completed(pool: &PoolCoordinator, selection: &Selection) -> usize {
    selection
        .jobs()
        .filter(|job| pool.status(job.id()).unwrap() == JobStatus::Completed)
        .count()
}

fn owner(
    workload: &PoolWorkload,
    path: &Path,
    phase: u64,
    f: &Fixture,
    selection: &Selection,
    context: &PolicyContext,
    deadline: u64,
    prior_count: usize,
) -> (DurableDag, CandidateId) {
    let (peak, jobs) = worker_budget::resources(&f.assignment).unwrap();
    if phase == 0 {
        assert_eq!(prior_count, 0);
        let store =
            ArtifactStore::create(&path.join("artifacts"), (workload.store_limits)()).unwrap();
        let mut owner = DurableDag::create(
            &path.join("journal"),
            journal_limits(),
            store,
            selection.root().pin(),
            typed_fixture::CHAIN,
            1,
            (workload.limits)(peak, jobs),
        )
        .unwrap();
        let candidate = selection
            .attach(&mut owner, workload.eligibility, deadline, now_ms())
            .unwrap();
        owner
            .seal(candidate, workload.eligibility, now_ms())
            .unwrap();
        assert!(selection
            .jobs()
            .all(|job| owner.verified_node_bytes(job.id()).unwrap().is_none()));
        (owner, candidate)
    } else {
        let store =
            ArtifactStore::open(&path.join("artifacts"), (workload.store_limits)()).unwrap();
        let recovery = DurableDag::recover_typed(
            &path.join("journal"),
            journal_limits(),
            store,
            selection.root().pin(),
            &f.bootstrap.registry,
            typed_fixture::CHAIN,
            phase + 1,
            (workload.limits)(peak, jobs),
            |artifact| context.policy(artifact),
        )
        .unwrap();
        assert_eq!(recovery.previous_epoch(), phase);
        assert!(
            recovery.unresolved_attempts().is_empty()
                && recovery.unresolved_workspaces().is_empty()
        );
        assert_eq!(recovery.previous_candidates().len(), 1);
        let prior = &recovery.previous_candidates()[0];
        assert_eq!(prior.root, selection.root().id());
        assert_eq!(prior.eligibility, workload.eligibility);
        assert!(prior.sealed && !prior.cancelled);
        let now = now_ms();
        let remaining = deadline.checked_sub(now).filter(|ms| *ms > 0).unwrap();
        let (owner, candidate) = recovery
            .resume_sealed_with_workspaces(
                |_| Err("unexpected unresolved native attempt".into()),
                |_| Err("unexpected unresolved native workspace".into()),
                || now,
                selection.root().id(),
                workload.eligibility,
                remaining,
            )
            .unwrap();
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
        assert_eq!(
            selection
                .jobs()
                .filter(|j| owner.status(j.id()).unwrap() == JobStatus::Completed)
                .count(),
            prior_count
        );
        (owner, candidate)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRecord {
    path: PathBuf,
    content_identity: [u8; 32],
    evidence: [u8; 32],
}

fn import(pool: &mut PoolCoordinator, classes: usize) {
    let path = PathBuf::from(std::env::var_os("LATTICA_NATIVE_TIMING_RECORDS").unwrap());
    assert!(fs::metadata(&path).unwrap().len() <= 16 << 10);
    let records: Vec<ApprovedRecord> = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert!((1..=32).contains(&classes));
    assert_eq!(records.len(), classes);
    for record in records {
        let bytes = fs::read(record.path).unwrap();
        assert_eq!(bytes.len(), TimingCalibration::ENCODED_BYTES);
        assert_eq!(
            process::configuration_digest(&bytes).unwrap(),
            record.content_identity
        );
        pool.import_worker_calibration(
            WorkerId(2),
            &TimingCalibration::decode_host(&bytes).unwrap(),
            record.evidence,
        )
        .unwrap();
    }
}

struct Dispatch {
    job: crate::block_v2::execution::job::JobId,
    warm: bool,
    issued_ms: u64,
    result_ms: Option<u64>,
    durable_ms: Option<u64>,
    accepted_elapsed_ms: Option<u64>,
}

struct Endpoint {
    inner: ObservedEndpoint,
    trace: Rc<RefCell<Vec<Dispatch>>>,
}

impl WorkerEndpoint for Endpoint {
    fn retirement_requested(&self) -> bool {
        self.inner.retirement_requested()
    }
    fn heartbeat(&mut self) -> Result<(), Error> {
        self.inner.heartbeat()
    }
    fn capabilities(&self) -> WorkerCapabilities {
        self.inner.capabilities()
    }
    fn set_context(&mut self, context: &PolicyContext) -> Result<(), Error> {
        self.inner.set_context(context)
    }
    fn dispatch(&mut self, owner: &mut DurableDag, lease: Lease, now: u64) -> Result<(), Error> {
        let job = owner.leased_job(lease)?;
        let cap = self.capabilities();
        assert!(cap.dispatch_deadline_ms.is_some_and(|limit| now < limit));
        self.trace.borrow_mut().push(Dispatch {
            job: job.id(),
            warm: cap.resident_mode == Some(job.operation().proof_mode()),
            issued_ms: now,
            result_ms: None,
            durable_ms: None,
            accepted_elapsed_ms: None,
        });
        self.inner.dispatch(owner, lease, now)
    }
    fn try_result(
        &mut self,
        owner: &mut DurableDag,
        now: u64,
    ) -> Result<Option<WorkerResult>, Error> {
        let result = self.inner.try_result(owner, now)?;
        if result.is_some() {
            let mut trace = self.trace.borrow_mut();
            let event = trace.last_mut().unwrap();
            assert!(event.result_ms.replace(now_ms()).is_none());
        }
        Ok(result)
    }
    fn cancel(&mut self, owner: &mut DurableDag, lease: Lease, now: u64) -> Result<(), Error> {
        self.inner.cancel(owner, lease, now)
    }
    fn close(&mut self, owner: &mut DurableDag, now: u64) -> Result<(), Error> {
        self.inner.close(owner, now)
    }
}

#[test]
#[ignore = "fresh recursive DAG through the real pool; dynamic 180-second worker lifetimes and fixed 600-second candidate"]
fn native_thirty_two_fresh_pool_phase() {
    run_phase(thirty_two());
}

pub(super) fn run_phase(workload: PoolWorkload) {
    assert!(!gpu_hash::is_enabled());
    assert!(std::env::var_os("LATTICA_NATIVE_SEED_NODES").is_none());
    assert_eq!(
        std::env::var("LATTICA_NATIVE_TIMING_ROUTE").unwrap(),
        "pool"
    );
    let phase = setting("LATTICA_NATIVE_DAG_PHASE");
    assert!(phase < workload.jobs as u64);
    let prior_count = usize::try_from(setting("LATTICA_NATIVE_PRIOR_COMPLETED")).unwrap();
    assert!(prior_count < workload.jobs);
    let deadline = setting("LATTICA_NATIVE_DAG_DEADLINE_MS");
    let coordinator_launch = setting("LATTICA_NATIVE_COORDINATOR_LAUNCH_MS");
    let dispatch_deadline = setting("LATTICA_NATIVE_DISPATCH_DEADLINE_MS");
    assert_eq!(
        dispatch_deadline,
        coordinator_launch.checked_add(150_000).unwrap()
    );
    assert!(now_ms() < dispatch_deadline && now_ms() < deadline);
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selection, context) = (workload.fixture)();
    assert_eq!(selection.jobs().len(), workload.jobs);
    assert_eq!(
        usize::from(selection.root().expected().count),
        workload.wallets.len()
    );
    let mut f = Fixture::with_registry(
        "full-size",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    f.bootstrap.launches = directory.join("launches");
    let (mut owner, candidate) = owner(
        &workload,
        &directory,
        phase,
        &f,
        &selection,
        &context,
        deadline,
        prior_count,
    );
    let (peak, jobs) = worker_budget::resources(&f.assignment).unwrap();
    let held = Resources { threads: 0, ..peak };
    let mut worker = ProcessWorker::prepare(
        &mut owner,
        f.bootstrap.config(&f.assignment).unwrap(),
        WorkerId(1),
        WorkerId(2),
        now_ms(),
    )
    .unwrap();
    let launches = if phase == 0 {
        LaunchStore::create(
            &f.bootstrap.launches,
            LaunchLimits {
                records: workload.jobs,
            },
        )
        .unwrap()
    } else {
        LaunchStore::open(
            &f.bootstrap.launches,
            LaunchLimits {
                records: workload.jobs,
            },
        )
        .unwrap()
    };
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(worker.service_identity().unwrap()).unwrap(),
    )
    .unwrap();
    let observed = Rc::new(RefCell::new(Observed::default()));
    let trace = Rc::new(RefCell::new(Vec::with_capacity(
        workload.jobs - prior_count,
    )));
    let endpoint = Endpoint {
        inner: ObservedEndpoint {
            endpoint: LocalProcessEndpoint::new(worker, Arc::new(Mutex::new(launches)))
                .unwrap()
                .with_dispatch_deadline(dispatch_deadline)
                .unwrap()
                .with_timing_identity(host_identity(&f))
                .unwrap()
                .with_retention_forecast()
                .unwrap(),
            held,
            verifying: held.add(jobs).unwrap(),
            observed: observed.clone(),
        },
        trace: trace.clone(),
    };
    let mut pool =
        PoolCoordinator::new(owner, registry.clone(), vec![Box::new(endpoint)], 180_000).unwrap();
    import(&mut pool, workload.timing_classes);
    pool.adopt_sealed(
        &selection,
        context,
        candidate,
        workload.eligibility,
        now_ms(),
    )
    .unwrap();
    assert_eq!(completed(&pool, &selection), prior_count);
    let mut stop_reason = "root_ready";
    let mut rejection = None;
    loop {
        assert!(now_ms() < deadline);
        let step = pool.step(now_ms());
        if let Ok(accepted) = &step {
            for result in accepted {
                let mut trace = trace.borrow_mut();
                let event = trace
                    .iter_mut()
                    .find(|event| event.job == result.job)
                    .unwrap();
                assert!(event
                    .accepted_elapsed_ms
                    .replace(result.elapsed_ms)
                    .is_none());
            }
        }
        for event in trace.borrow_mut().iter_mut() {
            if event.durable_ms.is_none()
                && event.result_ms.is_some()
                && pool.status(event.job).unwrap() == JobStatus::Completed
            {
                event.durable_ms = Some(now_ms());
            }
        }
        assert!(pool.take_failures().is_empty());
        if let Err(error) = step {
            assert!(pool.idle());
            let message = error.to_string();
            assert!(
                message == "pool has no deadline-admissible placement"
                    || (message == "pool has no surviving workers" && pool.workers_closed()),
                "{message}"
            );
            stop_reason = if pool.workers_closed() {
                "worker_retired"
            } else {
                "candidate_deadline_rejected"
            };
            rejection = Some(message);
            break;
        }
        if completed(&pool, &selection) == workload.jobs {
            break;
        }
        if pool.workers_closed() {
            stop_reason = "worker_retired";
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pool.idle());
    let retained = completed(&pool, &selection);
    let root = pool
        .root(candidate, workload.eligibility, now_ms())
        .unwrap();
    assert_eq!(root.is_some(), retained == workload.jobs);
    if let Some(bytes) = &root {
        verify_mutations(selection.root(), &registry, bytes);
        fs::write(f.directory.join("root.bin"), bytes).unwrap();
    }
    pool.close(now_ms()).unwrap();
    assert!(pool.workers_closed());
    let trace = trace.borrow();
    let proofs = trace.len();
    assert_eq!(retained, prior_count + proofs);
    assert!(trace
        .iter()
        .all(|event| event.result_ms.is_some() && event.durable_ms.is_some()));
    let cold = trace.iter().filter(|event| !event.warm).count();
    let seen = observed.borrow();
    assert_eq!(
        (seen.dispatches, seen.results, seen.closes),
        (proofs, proofs, 1)
    );
    assert!(seen.contexts.iter().all(|binding| *binding == [8; 32]));
    if proofs > 0 {
        f.check_memory_reports_with_setups(proofs, cold);
    }
    let events: Vec<_> = trace.iter().map(|event| {
        let job = selection.jobs().find(|job| job.id() == event.job).unwrap();
        serde_json::json!({"job":event.job.to_bytes(),"mode":job.operation().proof_mode(),
            "level":job.expected().level,"count":job.expected().count,"start":job.start(),"warm":event.warm,
            "issued_ms":event.issued_ms,"result_ms":event.result_ms,"durable_observed_ms":event.durable_ms,
            "accepted_elapsed_ms":event.accepted_elapsed_ms})
    }).collect();
    fs::write(
        f.directory.join("dispatches.json"),
        serde_json::to_vec_pretty(&events).unwrap(),
    )
    .unwrap();
    fs::write(f.directory.join("phase-summary.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "phase":phase,"route":"pool","proofs":proofs,"cold_jobs":cold,"warm_jobs":proofs-cold,
        "retained_proofs":retained,"prior_completed":prior_count,"epoch":phase+1,"deadline_ms":deadline,
        "coordinator_launch_ms":coordinator_launch,"dispatch_deadline_ms":dispatch_deadline,
        "service_runtime_ms":180_000,"shutdown_reserve_ms":30_000,
        "real_local_adapter":true,"durable_recovery":phase>0,"fresh_recursive_dag":true,
        "existing_recursive_proofs_imported":false,"reservations_held_until_exit":true,
        "root_available":root.is_some(),"stop_reason":stop_reason,"rejection":rejection,"wallets":workload.wallets,
        "total_jobs":workload.jobs,"root_level":selection.root().expected().level,
        "root_count":selection.root().expected().count,"root_mode":selection.root().operation().proof_mode(),
        "gpu_initialized_in_coordinator":false,"forced_job_order":false,"dispatches":events
    })).unwrap()).unwrap();
    assert!(now_ms() < deadline);
    println!("native_{}_fresh_pool_verified phase={phase} proofs={proofs} retained_proofs={retained} root_available={} stop_reason={stop_reason} gpu_initialized_in_coordinator=false",workload.name,root.is_some());
}

#[test]
#[ignore = "independent CPU recovery of a fresh pool prefix after native worker exit"]
fn native_thirty_two_fresh_saved_dag_verifies_without_worker() {
    audit_saved(thirty_two());
}

pub(super) fn audit_saved(workload: PoolWorkload) {
    assert!(!gpu_hash::is_enabled());
    let phase = setting("LATTICA_NATIVE_DAG_PHASE");
    let expected = setting("LATTICA_NATIVE_EXPECTED_COMPLETED") as usize;
    assert!(expected <= workload.jobs);
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let (registry, selection, context) = (workload.fixture)();
    assert_eq!(selection.jobs().len(), workload.jobs);
    let budget: serde_json::Value =
        serde_json::from_slice(&fs::read(public.join("budget.json")).unwrap()).unwrap();
    let (peak, jobs) = worker_budget::resources(&budget).unwrap();
    let store =
        ArtifactStore::open(&directory.join("artifacts"), (workload.store_limits)()).unwrap();
    let recovery = DurableDag::recover_typed(
        &directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        phase + 2,
        (workload.limits)(peak, jobs),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert_eq!(recovery.previous_epoch(), phase + 1);
    assert!(
        recovery.unresolved_attempts().is_empty() && recovery.unresolved_workspaces().is_empty()
    );
    assert_eq!(recovery.previous_candidates().len(), 1);
    assert!(recovery.previous_candidates()[0].sealed);
    assert_eq!(
        recovery.previous_candidates()[0].root,
        selection.root().id()
    );
    let nodes = fs::read_dir(directory.join("artifacts"))
        .unwrap()
        .filter(|p| {
            let name = p.as_ref().unwrap().file_name();
            let name = name.to_str().unwrap();
            name.starts_with("n-") && name.ends_with(".proof")
        })
        .count();
    assert_eq!(nodes, expected);
    let root_path = public.join("full-size/root.bin");
    assert_eq!(root_path.exists(), expected == workload.jobs);
    if expected == workload.jobs {
        verify_mutations(selection.root(), &registry, &read(&root_path));
    }
    assert!(!gpu_hash::is_enabled());
    println!("native_{}_fresh_saved_cpu_verified phase={phase} retained_proofs={expected} gpu_initialized=false unresolved_owners=0", workload.name);
}
