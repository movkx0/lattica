//! Fresh native eight-wallet timing probes, then a separately fresh pool DAG.
use super::pool_resume::{journal_limits, limits, now_ms, setting, store_limits};
use super::*;
use crate::block_v2::execution::{
    dag::CandidateId,
    scheduler::{CostModel, TimingCalibration, TimingIdentity},
};

const WALLETS: [usize; 8] = [0, 4, 8, 12, 16, 20, 24, 28];
const MODES: [u64; 4] = [1, 3, 3, 12];
const LEVELS: [u8; 4] = [1, 2, 3, 6];
const COUNTS: [usize; 4] = [4, 2, 1, 1];
const COMPLETED: [usize; 4] = [4, 6, 7, 8];

fn eight_wallet_fixture() -> (Registry<12>, Selection, PolicyContext) {
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
    assert_eq!(selection.jobs().len(), 8);
    assert_eq!(
        (
            selection.root().expected().count,
            selection.root().expected().level
        ),
        (8, 6)
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedRecord {
    path: PathBuf,
    content_identity: [u8; 32],
    evidence: [u8; 32],
}

fn import_records(pool: &mut PoolCoordinator) {
    let path = PathBuf::from(std::env::var_os("LATTICA_NATIVE_TIMING_RECORDS").unwrap());
    assert!(fs::metadata(&path).unwrap().len() <= 16 << 10);
    let records: Vec<ApprovedRecord> = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(records.len(), 6); // cold/warm pair + cold/warm level-two merge + two cold parents
    for record in records {
        assert_eq!(
            fs::metadata(&record.path).unwrap().len(),
            TimingCalibration::ENCODED_BYTES as u64
        );
        let bytes = fs::read(&record.path).unwrap();
        assert_eq!(
            process::configuration_digest(&bytes).unwrap(),
            record.content_identity
        );
        let calibration = TimingCalibration::decode_host(&bytes).unwrap();
        pool.import_worker_calibration(WorkerId(2), &calibration, record.evidence)
            .unwrap();
    }
}

struct PhaseEndpoint {
    inner: ObservedEndpoint,
    phase: usize,
}

impl WorkerEndpoint for PhaseEndpoint {
    fn retirement_requested(&self) -> bool {
        self.inner.retirement_requested()
            || self.inner.observed.borrow().results >= COUNTS[self.phase]
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
        assert_eq!(
            (job.operation().proof_mode(), job.expected().level),
            (MODES[self.phase], LEVELS[self.phase])
        );
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

#[test]
#[ignore = "fresh native eight-wallet calibration probes followed by a separately fresh calibrated pool DAG"]
fn native_eight_wallet_calibration_and_pool_phase() {
    let started = Instant::now();
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let route = std::env::var("LATTICA_NATIVE_TIMING_ROUTE").unwrap();
    assert!(route == "probe" || route == "pool");
    let deadline = setting("LATTICA_NATIVE_DAG_DEADLINE_MS");
    assert!(deadline > now_ms());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selection, context) = eight_wallet_fixture();
    let mut f = Fixture::with_registry(
        "full-size",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    f.bootstrap.launches = directory.join("launches");
    let (mut owner, candidate) =
        checkpoint_owner(&directory, phase, &f, &selection, &context, deadline);
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
    let mut launches = if phase == 0 {
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
    if route == "probe" {
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
            .filter(|job| job.expected().level == LEVELS[phase])
            .collect();
        phase_jobs.sort_by_key(|job| job.start());
        assert_eq!(phase_jobs.len(), COUNTS[phase]);
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
    } else {
        let observed = Rc::new(RefCell::new(Observed::default()));
        let endpoint = PhaseEndpoint {
            inner: ObservedEndpoint {
                endpoint: LocalProcessEndpoint::new(worker, Arc::new(Mutex::new(launches)))
                    .unwrap()
                    .with_timing_identity(identity)
                    .unwrap(),
                held,
                verifying: held.add(jobs).unwrap(),
                observed: observed.clone(),
            },
            phase,
        };
        let mut pool =
            PoolCoordinator::new(owner, registry.clone(), vec![Box::new(endpoint)], 180_000)
                .unwrap();
        import_records(&mut pool);
        pool.adopt_sealed(&selection, context, candidate, [31; 32], now_ms())
            .unwrap();
        assert!(pool.root(candidate, [31; 32], now_ms()).unwrap().is_none());
        while accepted.len() < COUNTS[phase] {
            assert!(started.elapsed() < Duration::from_secs(175) && now_ms() < deadline);
            for result in pool.step(now_ms()).unwrap() {
                let job = selection.jobs().find(|job| job.id() == result.job).unwrap();
                assert_eq!(
                    (job.operation().proof_mode(), job.expected().level),
                    (MODES[phase], LEVELS[phase])
                );
                assert!(!accepted.contains(&result.job));
                assert_eq!(pool.status(result.job).unwrap(), JobStatus::Completed);
                calibration.push(save_calibration(
                    &f.directory,
                    accepted.len(),
                    pool.export_worker_calibration(result.worker, result.job, !accepted.is_empty())
                        .unwrap(),
                ));
                accepted.push(result.job);
                timings.push(result.elapsed_ms as f64 / 1000.0);
            }
            assert!(pool.take_failures().is_empty());
            if accepted.len() < COUNTS[phase] {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert!(pool.idle());
        if phase == 3 {
            assert!(pool.root(candidate, [30; 32], now_ms()).is_err());
            let proof = pool.root(candidate, [31; 32], now_ms()).unwrap().unwrap();
            verify_mutations(selection.root(), &registry, &proof);
            fs::write(f.directory.join("root.bin"), proof).unwrap();
        } else {
            assert!(pool.root(candidate, [31; 32], now_ms()).unwrap().is_none());
        }
        pool.retire_idle_workers(now_ms()).unwrap();
        pool.close(now_ms()).unwrap();
        let seen = observed.borrow();
        assert_eq!(
            (seen.dispatches, seen.results, seen.closes),
            (COUNTS[phase], COUNTS[phase], 1)
        );
        assert!(seen.contexts.iter().all(|binding| *binding == [8; 32]));
    }
    assert!(now_ms() < deadline);
    f.check_memory_reports(COUNTS[phase]);
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    fs::write(f.directory.join("phase-summary.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "phase":phase, "route":route, "mode":MODES[phase], "level":LEVELS[phase], "proofs":COUNTS[phase],
        "retained_proofs":COMPLETED[phase], "epoch":phase + 1, "deadline_ms":deadline,
        "jobs":accepted.iter().map(|job| job.to_bytes()).collect::<Vec<_>>(), "wallets":WALLETS,
        "real_local_adapter":route == "pool", "durable_recovery":phase > 0,
        "existing_recursive_proofs_imported":false, "reservations_held_until_exit":true,
        "root_available":phase == 3, "calibration":calibration
    })).unwrap()).unwrap();
    println!("native_eight_wallet_verified route={route} phase={phase} proofs={} retained_proofs={} gpu_initialized_in_coordinator=false", COUNTS[phase], COMPLETED[phase]);
}

#[test]
#[ignore = "independent CPU recovery and root mutation audit after each native eight-wallet phase"]
fn native_eight_wallet_saved_dag_verifies_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < 4);
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let (registry, selection, context) = eight_wallet_fixture();
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
    println!("native_eight_wallet_saved_cpu_verified phase={phase} retained_dag=true gpu_initialized=false unresolved_owners=0");
}
