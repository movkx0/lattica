//! A fresh recursive DAG, resumed through the real pool after clean exits.
use super::*;
use crate::block_v2::execution::dag::CandidateId;

pub(super) fn now_ms() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) },
        0
    );
    u64::try_from(value.tv_sec).unwrap() * 1000 + u64::try_from(value.tv_nsec).unwrap() / 1_000_000
}

pub(super) fn setting(name: &str) -> u64 {
    std::env::var(name).unwrap().parse().unwrap()
}

pub(super) fn store_limits() -> StoreLimits {
    StoreLimits {
        bytes: 32 << 20,
        entries: 64,
    }
}

pub(super) fn journal_limits() -> JournalLimits {
    JournalLimits {
        snapshot_bytes: 1 << 20,
    }
}

pub(super) fn limits(peak: Resources, jobs: Resources) -> Limits {
    Limits {
        jobs: 32,
        candidates: 4,
        attempts: 16,
        artifact_bytes: 32 << 20,
        recovery_window_ms: 1000,
        workers: Resources {
            ram_bytes: peak.ram_bytes + jobs.ram_bytes,
            ..peak
        },
    }
}

struct PhaseEndpoint {
    inner: ObservedEndpoint,
    jobs: usize,
    mode: u64,
}

impl WorkerEndpoint for PhaseEndpoint {
    fn retirement_requested(&self) -> bool {
        self.inner.retirement_requested() || self.inner.observed.borrow().results >= self.jobs
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
        assert_eq!(owner.leased_job(lease)?.operation().proof_mode(), self.mode);
        self.inner.dispatch(owner, lease, now)
    }
    fn try_result(
        &mut self,
        owner: &mut DurableDag,
        now: u64,
    ) -> Result<Option<WorkerResult>, Error> {
        self.inner.try_result(owner, now)
    }
    fn cancel(&mut self, owner: &mut DurableDag, lease: Lease, now: u64) -> Result<(), Error> {
        self.inner.cancel(owner, lease, now)
    }
    fn close(&mut self, owner: &mut DurableDag, now: u64) -> Result<(), Error> {
        self.inner.close(owner, now)
    }
}

fn resumed_owner(
    path: &Path,
    phase: u64,
    f: &Fixture,
    selection: &Selection,
    context: &PolicyContext,
    deadline: u64,
) -> (DurableDag, CandidateId) {
    let (peak, jobs) = worker_budget::resources(&f.assignment).unwrap();
    let pin = selection.root().pin();
    let eligibility = [31; 32];
    if phase == 0 {
        let store = ArtifactStore::create(&path.join("artifacts"), store_limits()).unwrap();
        let mut owner = DurableDag::create(
            &path.join("journal"),
            journal_limits(),
            store,
            pin,
            typed_fixture::CHAIN,
            1,
            limits(peak, jobs),
        )
        .unwrap();
        let candidate = selection
            .attach(&mut owner, eligibility, deadline, now_ms())
            .unwrap();
        owner.seal(candidate, eligibility, now_ms()).unwrap();
        assert!(selection
            .jobs()
            .all(|job| owner.verified_node_bytes(job.id()).unwrap().is_none()));
        (owner, candidate)
    } else {
        let store = ArtifactStore::open(&path.join("artifacts"), store_limits()).unwrap();
        let recovery = DurableDag::recover_typed(
            &path.join("journal"),
            journal_limits(),
            store,
            pin,
            &f.bootstrap.registry,
            typed_fixture::CHAIN,
            phase + 1,
            limits(peak, jobs),
            |artifact| context.policy(artifact),
        )
        .unwrap();
        assert_eq!(recovery.previous_epoch(), phase);
        assert_eq!(recovery.previous_candidates().len(), 1);
        let previous = &recovery.previous_candidates()[0];
        assert_eq!(previous.root, selection.root().id());
        assert_eq!(previous.eligibility, eligibility);
        assert_eq!(previous.deadline_ms, deadline);
        assert!(previous.sealed && !previous.cancelled);
        let previous = previous.id;
        assert!(recovery.unresolved_attempts().is_empty());
        assert!(recovery.unresolved_workspaces().is_empty());
        let (owner, candidate) = recovery
            .resume_sealed_candidate_with_workspaces(
                |_| Err("unexpected unresolved native attempt".into()),
                |_| Err("unexpected unresolved native workspace".into()),
                now_ms,
                previous,
                selection.root().id(),
                eligibility,
            )
            .unwrap();
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
        let completed = selection
            .jobs()
            .filter(|job| owner.status(job.id()).unwrap() == JobStatus::Completed)
            .count();
        assert_eq!(completed, if phase == 1 { 2 } else { 3 });
        (owner, candidate)
    }
}

#[test]
#[ignore = "three capped native pool phases create a fresh pair/merge/finalizer DAG through durable recovery"]
fn native_pool_resumes_fresh_recursive_dag_after_clean_exit() {
    let started = Instant::now();
    assert!(!gpu_hash::is_enabled());
    let phase = setting("LATTICA_NATIVE_DAG_PHASE");
    assert!(phase <= 2);
    let mode = [1, 3, 12][phase as usize];
    let count = [2, 1, 1][phase as usize];
    let deadline = setting("LATTICA_NATIVE_DAG_DEADLINE_MS");
    assert!(deadline > now_ms());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selections, context) = fixture_for([16, 20, 24, 28]);
    let selection = &selections[0];
    assert_eq!(selection.jobs().len(), 4);
    let mut f = Fixture::with_registry(
        "full-size",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    f.bootstrap.launches = directory.join("launches");
    let (mut owner, candidate) =
        resumed_owner(&directory, phase, &f, selection, &context, deadline);
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
    let observed = Rc::new(RefCell::new(Observed::default()));
    let endpoint = PhaseEndpoint {
        inner: ObservedEndpoint {
            endpoint: LocalProcessEndpoint::new(worker, Arc::new(Mutex::new(launches))).unwrap(),
            held,
            verifying: held.add(jobs).unwrap(),
            observed: observed.clone(),
        },
        jobs: count,
        mode,
    };
    let mut pool =
        PoolCoordinator::new(owner, registry.clone(), vec![Box::new(endpoint)], 180_000).unwrap();
    pool.adopt_sealed(selection, context, candidate, [31; 32], now_ms())
        .unwrap();
    assert!(pool.root(candidate, [31; 32], now_ms()).unwrap().is_none());
    let mut accepted = Vec::new();
    let mut timings = Vec::new();
    while accepted.len() < count {
        assert!(started.elapsed() < Duration::from_secs(175));
        assert!(now_ms() < deadline);
        for result in pool.step(now_ms()).unwrap() {
            let job = selection.jobs().find(|job| job.id() == result.job).unwrap();
            assert_eq!(job.operation().proof_mode(), mode);
            assert!(!accepted.contains(&result.job));
            assert_eq!(pool.status(result.job).unwrap(), JobStatus::Completed);
            accepted.push(result.job);
            timings.push(result.elapsed_ms as f64 / 1000.0);
        }
        assert!(pool.take_failures().is_empty());
        if accepted.len() < count {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(pool.idle());
    if phase == 2 {
        assert!(pool.root(candidate, [30; 32], now_ms()).is_err());
        let root = pool.root(candidate, [31; 32], now_ms()).unwrap().unwrap();
        verify_mutations(selection.root(), &registry, &root);
        fs::write(f.directory.join("root.bin"), &root).unwrap();
        assert_eq!(
            codec::decode_node(&root).unwrap().public,
            selection.root().expected_public()
        );
    } else {
        assert!(pool.root(candidate, [31; 32], now_ms()).unwrap().is_none());
    }
    pool.retire_idle_workers(now_ms()).unwrap();
    pool.close(now_ms()).unwrap();
    let seen = observed.borrow();
    assert_eq!(
        (seen.dispatches, seen.results, seen.closes),
        (count, count, 1)
    );
    assert!(seen.contexts.iter().all(|binding| *binding == [8; 32]));
    drop(seen);
    drop(pool);
    f.check_memory_reports(count);
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    fs::write(f.directory.join("phase-summary.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "phase": phase, "mode": mode, "proofs": count, "epoch": phase + 1,
            "accepted": accepted.iter().map(|job| job.to_bytes()).collect::<Vec<_>>(),
            "wallets": [16,20,24,28], "deadline_ms": deadline,
        "real_pool": true, "durable_recovery": phase > 0, "existing_recursive_proofs_imported": false,
        "reservations_held_until_exit": true, "root_available": phase == 2
    })).unwrap()).unwrap();
    println!("native_pool_resume_verified phase={phase} mode={mode} proofs={count} real_local_adapter=true durable_recovery={} existing_recursive_proofs_imported=false", phase > 0);
}

#[test]
#[ignore = "CPU re-verification of the entire retained fresh DAG after each native phase has exited"]
fn native_pool_saved_dag_verifies_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let phase = setting("LATTICA_NATIVE_DAG_PHASE");
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selections, context) = fixture_for([16, 20, 24, 28]);
    let selection = &selections[0];
    let budget: serde_json::Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap())
                .join("budget.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let (peak, jobs) = worker_budget::resources(&budget).unwrap();
    let store = ArtifactStore::open(&directory.join("artifacts"), store_limits()).unwrap();
    // Opening recovery verifies every retained node and wallet. Do not resume or
    // write a new epoch in this independent audit process.
    let recovery = DurableDag::recover_typed(
        &directory.join("journal"),
        journal_limits(),
        store,
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        phase + 2,
        limits(peak, jobs),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert_eq!(recovery.previous_epoch(), phase + 1);
    assert!(
        recovery.unresolved_attempts().is_empty() && recovery.unresolved_workspaces().is_empty()
    );
    assert_eq!(recovery.previous_candidates().len(), 1);
    assert!(recovery.previous_candidates()[0].sealed);
    if phase == 2 {
        let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
        verify_mutations(
            selection.root(),
            &registry,
            &read(&public.join("full-size/root.bin")),
        );
    }
    assert!(!gpu_hash::is_enabled());
    println!("native_pool_saved_cpu_verified phase={phase} retained_dag=true gpu_initialized=false unresolved_owners=0");
}
