//! Transaction-bearing native jobs, then independently verified pool roots.
#[path = "native_worker_gpu_mixed_tests.rs"]
mod mixed;
#[path = "native_worker_gpu_pool_calibration_tests.rs"]
mod pool_calibration;
#[path = "native_worker_gpu_pool_resume_tests.rs"]
mod pool_resume;
#[path = "native_worker_gpu_retention_pool_tests.rs"]
mod retention_pool;
#[path = "native_worker_gpu_sixteen_tests.rs"]
mod sixteen;
#[path = "native_worker_gpu_thirty_two_tests.rs"]
mod thirty_two;

use super::*;
use crate::block_v2::{
    execution::{
        dag::{JobStatus, Lease},
        job::{RegistryPin, VerifiedWallet},
        pool::{local::LocalProcessEndpoint, PoolCoordinator, WorkerEndpoint, WorkerResult},
        scheduler::{CostModel, WorkerCapabilities},
        selection::{PublicInput, Selection},
    },
    machine::typed_pairs,
    typed_fixture,
    typed_recursive::Policy,
};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Instant,
};

fn read(path: &Path) -> Vec<u8> {
    assert!(fs::symlink_metadata(path).unwrap().is_file());
    assert!(fs::metadata(path).unwrap().len() <= crate::block_v2::profile::MAX_PROOF_BYTES as u64);
    fs::read(path).unwrap()
}

fn wallet_indices() -> [usize; 4] {
    let selected =
        std::env::var("LATTICA_NATIVE_WALLETS").unwrap_or_else(|_| "0,4,8,12".to_owned());
    let indices: [usize; 4] = selected
        .split(',')
        .map(|part| part.parse::<usize>().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    for (position, index) in indices.iter().enumerate() {
        assert!(*index < 64 && !indices[..position].contains(index));
    }
    indices
}

fn wallet_policy(index: usize) -> Policy {
    match index % 4 {
        0 => Policy::JoinSplit,
        1 | 2 => Policy::Htlc {
            expected_height: typed_fixture::HEIGHT,
        },
        3 => Policy::Issuance {
            authorized_mint: typed_fixture::MINT,
        },
        _ => unreachable!(),
    }
}

fn is_pair(mode: u64) -> bool {
    typed_pairs::leaf_modes(mode).is_ok()
}

fn fixture() -> (Registry<12>, Vec<Selection>, PolicyContext) {
    fixture_for(wallet_indices())
}

fn fixture_for(indices: [usize; 4]) -> (Registry<12>, Vec<Selection>, PolicyContext) {
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
    let inputs: Vec<_> = indices
        .into_iter()
        .map(|index| {
            let bytes = read(&directory.join(format!("wallet.{index}")));
            let policy = wallet_policy(index);
            let wallet =
                VerifiedWallet::verify_typed(pin, &registry, typed_fixture::CHAIN, policy, &bytes)
                    .unwrap();
            let wrong_policy = match policy {
                Policy::JoinSplit => Policy::Issuance {
                    authorized_mint: typed_fixture::MINT,
                },
                Policy::Htlc { expected_height } => Policy::Htlc {
                    expected_height: expected_height + 1,
                },
                Policy::Issuance { authorized_mint } => Policy::Issuance {
                    authorized_mint: authorized_mint + 1,
                },
            };
            assert!(VerifiedWallet::verify_typed(
                pin,
                &registry,
                typed_fixture::CHAIN,
                wrong_policy,
                &bytes,
            )
            .is_err());
            assert!(!summaries.contains(&wallet.summary().root));
            summaries.push(wallet.summary().root);
            policies.push((wallet.artifact(), policy));
            PublicInput::new(wallet, bytes).unwrap()
        })
        .collect();
    let reversed = [
        inputs[2].clone(),
        inputs[3].clone(),
        inputs[0].clone(),
        inputs[1].clone(),
    ];
    let selections = vec![
        Selection::new(pin, typed_fixture::CHAIN, &inputs).unwrap(),
        Selection::new(pin, typed_fixture::CHAIN, &reversed).unwrap(),
    ];
    assert_ne!(
        selections[0].root().expected_public(),
        selections[1].root().expected_public()
    );
    for selection in &selections {
        assert_eq!(
            (
                selection.root().expected().count,
                selection.root().expected().level
            ),
            (4, 6)
        );
    }
    (
        registry,
        selections,
        PolicyContext::new([8; 32], policies).unwrap(),
    )
}

fn mode() -> u64 {
    let mode = std::env::var("LATTICA_FULL_SIZE_MODE")
        .unwrap()
        .parse()
        .unwrap();
    assert!(is_pair(mode) || [3, 12].contains(&mode));
    mode
}

fn targets(selections: &[Selection], mode: u64) -> Vec<Job> {
    if is_pair(mode) {
        selections[0]
            .jobs()
            .filter(|job| job.operation().proof_mode() == mode)
            .cloned()
            .collect()
    } else {
        selections
            .iter()
            .map(|s| {
                s.jobs()
                    .find(|job| job.operation().proof_mode() == mode)
                    .unwrap()
                    .clone()
            })
            .collect()
    }
}

fn cache_prefix(
    owner: &mut DurableDag,
    registry: &Registry<12>,
    selections: &[Selection],
    mode: u64,
) {
    for selection in selections {
        selection.admit(owner, 0).unwrap();
    }
    for (input_mode, variable) in [
        (1, "LATTICA_NATIVE_PAIR_DIR"),
        (3, "LATTICA_NATIVE_MERGE_DIR"),
    ] {
        if is_pair(mode) || (mode == 3 && input_mode == 3) {
            continue;
        }
        let directory = PathBuf::from(std::env::var_os(variable).unwrap());
        let proofs: Vec<_> = (0..2)
            .map(|index| read(&directory.join(format!("proof-{index}.bin"))))
            .collect();
        for selection in selections {
            for job in selection.jobs().filter(|job| {
                let child_mode = job.operation().proof_mode();
                (input_mode == 1 && is_pair(child_mode)) || child_mode == input_mode
            }) {
                let bytes = proofs
                    .iter()
                    .find(|bytes| {
                        codec::decode_node(bytes).unwrap().public == job.expected_public()
                    })
                    .unwrap();
                let verified = VerifiedNode::verify_typed(job, registry, bytes).unwrap();
                owner.cache_node(verified, bytes.clone(), 0).unwrap();
            }
        }
    }
}

fn verify_mutations(job: &Job, registry: &Registry<12>, bytes: &[u8]) {
    assert!(!gpu_hash::is_enabled());
    VerifiedNode::verify_typed(job, registry, bytes).unwrap();
    for index in [0, programs::LEVEL, programs::COUNT, programs::ROOT] {
        let mut altered = codec::decode_node(bytes).unwrap();
        altered.public[index] += crate::config::Val::ONE;
        assert!(
            VerifiedNode::verify_typed(job, registry, &codec::encode_node(&altered).unwrap())
                .is_err()
        );
    }
}

#[derive(Default)]
struct Observed {
    dispatches: usize,
    results: usize,
    closes: usize,
    contexts: Vec<[u8; 32]>,
}

// Delegate every operation to the real adapter. Observe resource ownership at
// the adapter boundary without exposing or changing production pool internals.
struct ObservedEndpoint {
    endpoint: LocalProcessEndpoint,
    held: Resources,
    verifying: Resources,
    observed: Rc<RefCell<Observed>>,
}

impl WorkerEndpoint for ObservedEndpoint {
    fn retirement_requested(&self) -> bool {
        self.endpoint.retirement_requested()
    }
    fn heartbeat(&mut self) -> Result<(), Error> {
        self.endpoint.heartbeat()
    }
    fn capabilities(&self) -> WorkerCapabilities {
        self.endpoint.capabilities()
    }
    fn set_context(&mut self, context: &PolicyContext) -> Result<(), Error> {
        self.endpoint.set_context(context)?;
        self.observed.borrow_mut().contexts.push(context.binding());
        Ok(())
    }
    fn dispatch(&mut self, owner: &mut DurableDag, lease: Lease, now: u64) -> Result<(), Error> {
        self.endpoint.dispatch(owner, lease, now)?;
        self.observed.borrow_mut().dispatches += 1;
        Ok(())
    }
    fn try_result(
        &mut self,
        owner: &mut DurableDag,
        now: u64,
    ) -> Result<Option<WorkerResult>, Error> {
        let result = self.endpoint.try_result(owner, now)?;
        if result.is_some() {
            // Collection precedes the coordinator's CPU verification and
            // durable acceptance. Keep its job bytes and threads reserved.
            assert_eq!(owner.resource_use()?, self.verifying);
            self.observed.borrow_mut().results += 1;
        }
        Ok(result)
    }
    fn cancel(&mut self, owner: &mut DurableDag, lease: Lease, now: u64) -> Result<(), Error> {
        self.endpoint.cancel(owner, lease, now)
    }
    fn close(&mut self, owner: &mut DurableDag, now: u64) -> Result<(), Error> {
        assert_eq!(owner.resource_use()?, self.held);
        self.endpoint.close(owner, now)?;
        assert_eq!(owner.resource_use()?, Resources::default());
        self.observed.borrow_mut().closes += 1;
        Ok(())
    }
}

#[test]
#[ignore = "full-size native pairs/merges and pool finalizers, with archived registry and bounded services"]
fn native_service_nonempty_jobs_and_pool_roots_verify_independently() {
    let started = Instant::now();
    let clock = || u64::try_from(started.elapsed().as_millis()).unwrap();
    assert!(!gpu_hash::is_enabled());
    let mode = mode();
    let (registry, selections, context) = fixture();
    let profile = registry.id().unwrap();
    let jobs = targets(&selections, mode);
    assert_eq!(jobs.len(), 2);
    let mut f = Fixture::with_registry("full-size", registry, profile, typed_fixture::CHAIN);
    f.bootstrap.policy_context = context.encode();
    let (mut owner, mut worker, mut launches) = f.owner();
    cache_prefix(&mut owner, &f.bootstrap.registry, &selections, mode);
    let (peak, resources) = worker_budget::resources(&f.assignment).unwrap();
    let held = Resources { threads: 0, ..peak };
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(worker.service_identity().unwrap()).unwrap(),
    )
    .unwrap();
    let mut timings = Vec::new();
    let mut calibration = Vec::new();
    let mut calibration_costs = std::env::var_os("LATTICA_NATIVE_TIMING_IDENTITY").map(|_| {
        assert_ne!(mode, 12, "pool finalizers use the pool calibration harness");
        let capabilities = worker
            .scheduling_capabilities_with_timing(thirty_two::host_identity(&f))
            .unwrap();
        (capabilities, CostModel::new(180_000).unwrap())
    });
    if mode != 12 {
        for (index, selection) in selections.iter().enumerate() {
            owner
                .attach(
                    selection.root().id(),
                    [index as u8 + 11; 32],
                    600_000,
                    clock(),
                )
                .unwrap();
        }
        for (index, job) in jobs.iter().enumerate() {
            // Match scheduler calibration: include lease, publication, CPU verification
            // and durable acceptance. Mutation probes are outside the timed interval.
            let proving = Instant::now();
            let lease = owner
                .lease(job.id(), WorkerId(2), resources, 180_000, 180_000, clock())
                .unwrap();
            let task = worker.task(&mut owner, lease, clock()).unwrap();
            let token = launches
                .issue_bound(
                    &mut owner,
                    lease,
                    &task.request().unwrap(),
                    worker.execution_digest().unwrap(),
                )
                .unwrap();
            let start = Instant::now();
            let completed = worker.execute(&token, task).unwrap();
            timings.push(start.elapsed().as_secs_f64());
            assert!(!worker.retirement_requested());
            let revoked = launches.revoke(lease).unwrap();
            assert!(launches.try_idle(&revoked).unwrap().is_some());
            let output = completed.reconcile(&mut owner, clock()).unwrap();
            let expected = owner.begin_verification(lease, clock()).unwrap();
            assert_eq!(expected.id(), job.id());
            let verified =
                VerifiedNode::verify_typed(&expected, &f.bootstrap.registry, output.bytes())
                    .unwrap();
            let bytes = output.bytes().to_vec();
            assert_eq!(
                owner
                    .finish_verification(lease, Some((verified, bytes.clone())), clock())
                    .unwrap(),
                Completion::Accepted
            );
            let elapsed = u64::try_from(proving.elapsed().as_millis()).unwrap().max(1);
            if let Some((capabilities, costs)) = &mut calibration_costs {
                costs.observe(capabilities, job, index != 0, elapsed).unwrap();
                let record = costs.export_calibration(capabilities, job, index != 0).unwrap();
                calibration.push(serde_json::json!({
                    "job":job.id().to_bytes(), "mode":job.operation().proof_mode(),
                    "level":job.expected().level, "input_count":job.expected().count,
                    "warm":index != 0, "elapsed_ms":elapsed,
                    "record":thirty_two::save_calibration(&f.directory, index, record)
                }));
            }
            verify_mutations(&expected, &f.bootstrap.registry, output.bytes());
            assert_eq!(owner.status(job.id()).unwrap(), JobStatus::Completed);
            fs::write(f.directory.join(format!("proof-{index}.bin")), bytes).unwrap();
            assert_eq!(
                worker.stats().unwrap(),
                CacheStats {
                    setups: 1,
                    hits: index as u64
                }
            );
            assert_eq!(owner.resource_use().unwrap(), held);
        }
        worker.close(&mut owner, clock()).unwrap();
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
    } else {
        let observed = Rc::new(RefCell::new(Observed::default()));
        let endpoint = ObservedEndpoint {
            endpoint: LocalProcessEndpoint::new(worker, Arc::new(Mutex::new(launches))).unwrap(),
            held,
            verifying: held.add(resources).unwrap(),
            observed: observed.clone(),
        };
        let mut pool = PoolCoordinator::new(
            owner,
            f.bootstrap.registry.clone(),
            vec![Box::new(endpoint)],
            180_000,
        )
        .unwrap();
        let mut candidates = Vec::new();
        for (index, selection) in selections.iter().enumerate() {
            let mut policies = Vec::new();
            for job in selection.jobs() {
                for artifact in job.wallet_inputs() {
                    if !policies.iter().any(|(old, _)| old == artifact) {
                        policies.push((*artifact, context.policy(*artifact).unwrap()));
                    }
                }
            }
            let eligibility = [index as u8 + 21; 32];
            let candidate = pool
                .submit(
                    selection,
                    PolicyContext::new(eligibility, policies).unwrap(),
                    eligibility,
                    600_000,
                    clock(),
                )
                .unwrap();
            pool.seal(candidate, eligibility, clock()).unwrap();
            assert!(pool
                .root(candidate, eligibility, clock())
                .unwrap()
                .is_none());
            candidates.push((candidate, eligibility));
        }
        let mut accepted = Vec::new();
        while accepted.len() < 2 {
            assert!(started.elapsed() < Duration::from_secs(175));
            for result in pool.step(clock()).unwrap() {
                assert!(jobs.iter().any(|job| job.id() == result.job));
                assert!(!accepted.contains(&result.job));
                assert_eq!(pool.status(result.job).unwrap(), JobStatus::Completed);
                timings.push(result.elapsed_ms as f64 / 1000.0);
                accepted.push(result.job);
            }
            assert!(pool.take_failures().is_empty());
            if accepted.len() < 2 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert!(pool.idle());
        for (index, (candidate, eligibility)) in candidates.iter().enumerate() {
            let bytes = pool
                .root(*candidate, *eligibility, clock())
                .unwrap()
                .unwrap();
            verify_mutations(&jobs[index], &f.bootstrap.registry, &bytes);
            assert!(bytes.len() <= 2 << 20);
            fs::write(f.directory.join(format!("proof-{index}.bin")), bytes).unwrap();
        }
        pool.close(clock()).unwrap();
        let observed = observed.borrow();
        assert_eq!(
            (observed.dispatches, observed.results, observed.closes),
            (2, 2, 1)
        );
        assert_eq!(observed.contexts.len(), 2);
        assert_ne!(observed.contexts[0], observed.contexts[1]);
        println!("native_nonempty_pool accepted=2 roots=2 contexts=2 real_local_adapter=true reservations_held_until_exit=true");
    }
    for (index, job) in jobs.iter().enumerate() {
        verify_mutations(
            job,
            &f.bootstrap.registry,
            &read(&f.directory.join(format!("proof-{index}.bin"))),
        );
    }
    assert_ne!(
        read(&f.directory.join("proof-0.bin")),
        read(&f.directory.join("proof-1.bin"))
    );
    let log = fs::read_to_string(f.directory.join("worker.log")).unwrap();
    assert!(log.contains("rc=0 completed=2 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"));
    f.check_memory_reports(2);
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    if calibration_costs.is_some() {
        assert_eq!(calibration.len(), 2);
        fs::write(
            f.directory.join("calibration-summary.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "mode":mode, "wallets":wallet_indices(), "proofs":2,
                "lease_through_durable_verification":true,
                "complete_workflow_qualified":false, "calibration":calibration
            })).unwrap(),
        ).unwrap();
    }
    println!("native_nonempty_verified mode={mode} proofs=2 wallets={:?} archived_registry=true cpu_verified=true mutations_per_proof=4 wallet_policy_mutations=4 observed_exit=true reservations_released=true pool_finalizers={}", wallet_indices(), mode == 12);
}

#[test]
#[ignore = "independent CPU audit of saved native nonempty proofs after both coordinator and worker exit"]
fn native_nonempty_saved_results_verify_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let mode = mode();
    let (registry, selections, _) = fixture();
    let directory =
        PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap()).join("full-size");
    for (index, job) in targets(&selections, mode).iter().enumerate() {
        verify_mutations(
            job,
            &registry,
            &read(&directory.join(format!("proof-{index}.bin"))),
        );
    }
    println!("native_nonempty_saved_cpu_verified mode={mode} proofs=2 gpu_initialized=false mutations_per_proof=4");
}
