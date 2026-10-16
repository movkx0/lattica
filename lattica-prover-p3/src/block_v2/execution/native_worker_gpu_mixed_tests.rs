//! Different full-size proof keys in one live native worker, including reuse.
use super::*;

fn mixed_fixture() -> (Registry<12>, [Vec<Selection>; 2], PolicyContext, Vec<Job>) {
    let (registry, pairs, pair_context) = fixture_for([16, 20, 24, 28]);
    let (same_registry, roots, root_context) = fixture_for([0, 4, 8, 12]);
    assert_eq!(registry.id().unwrap(), same_registry.id().unwrap());
    let mut policies = Vec::new();
    for (selections, context) in [(&pairs, pair_context), (&roots, root_context)] {
        for job in selections[0].jobs() {
            for artifact in job.wallet_inputs() {
                if !policies.iter().any(|(previous, _)| previous == artifact) {
                    policies.push((*artifact, context.policy(*artifact).unwrap()));
                }
            }
        }
    }
    assert_eq!(policies.len(), 8);
    let pair_jobs = targets(&pairs, 1);
    let root_jobs = targets(&roots, 12);
    assert_eq!((pair_jobs.len(), root_jobs.len()), (2, 2));
    let jobs = match std::env::var("LATTICA_NATIVE_MIXED_ORDER")
        .unwrap()
        .as_str()
    {
        "pair-root-root" => vec![
            pair_jobs[0].clone(),
            root_jobs[0].clone(),
            root_jobs[1].clone(),
        ],
        "root-pair-pair" => vec![
            root_jobs[0].clone(),
            pair_jobs[0].clone(),
            pair_jobs[1].clone(),
        ],
        _ => panic!("unsupported mixed native order"),
    };
    assert!(jobs
        .iter()
        .enumerate()
        .all(|(i, job)| jobs[..i].iter().all(|previous| previous.id() != job.id())));
    (
        registry,
        [pairs, roots],
        PolicyContext::new([8; 32], policies).unwrap(),
        jobs,
    )
}

#[test]
#[ignore = "three full-size GPU proofs across a live native worker key switch under existing caps"]
fn native_service_switches_registered_keys_then_reuses_preprocessing() {
    let started = Instant::now();
    let clock = || u64::try_from(started.elapsed().as_millis()).unwrap();
    assert!(!gpu_hash::is_enabled());
    let (registry, selections, context, jobs) = mixed_fixture();
    let f = Fixture::with_registry(
        "full-size",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    let (mut owner, mut worker, mut launches) = f.owner();
    cache_prefix(&mut owner, &registry, &selections[0], 1);
    cache_prefix(&mut owner, &registry, &selections[1], 12);
    for (index, selection) in selections.iter().flatten().enumerate() {
        owner
            .attach(
                selection.root().id(),
                [index as u8 + 11; 32],
                600_000,
                clock(),
            )
            .unwrap();
    }
    let (peak, resources) = worker_budget::resources(&f.assignment).unwrap();
    let held = Resources { threads: 0, ..peak };
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    // Like the pool adapter, bind job policies through the live worker protocol.
    // The startup envelope need not hold every candidate's wallet context.
    worker.replace_context(&context).unwrap();
    let identity = worker.service_identity().unwrap().clone();
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(&identity).unwrap(),
    )
    .unwrap();
    let mut timings = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        assert!(started.elapsed() < Duration::from_secs(175));
        assert_eq!(owner.status(job.id()).unwrap(), JobStatus::Ready);
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
        let proving = Instant::now();
        let completed = worker.execute(&token, task).unwrap();
        timings.push(proving.elapsed().as_secs_f64());
        assert!(!worker.retirement_requested());
        assert_eq!(worker.service_identity().unwrap(), &identity);
        let revoked = launches.revoke(lease).unwrap();
        assert!(launches.try_idle(&revoked).unwrap().is_some());
        let output = completed.reconcile(&mut owner, clock()).unwrap();
        let expected = owner.begin_verification(lease, clock()).unwrap();
        assert_eq!(expected.id(), job.id());
        verify_mutations(&expected, &registry, output.bytes());
        let verified = VerifiedNode::verify_typed(&expected, &registry, output.bytes()).unwrap();
        let bytes = output.bytes().to_vec();
        assert_eq!(
            owner
                .finish_verification(lease, Some((verified, bytes.clone())), clock())
                .unwrap(),
            Completion::Accepted
        );
        fs::write(f.directory.join(format!("proof-{index}.bin")), bytes).unwrap();
        assert_eq!(
            worker.stats().unwrap(),
            CacheStats {
                setups: if index == 0 { 1 } else { 2 },
                hits: u64::from(index == 2)
            }
        );
        assert_eq!(owner.status(job.id()).unwrap(), JobStatus::Completed);
        assert_eq!(owner.resource_use().unwrap(), held);
    }
    worker.close(&mut owner, clock()).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    let bytes: Vec<_> = (0..3)
        .map(|index| read(&f.directory.join(format!("proof-{index}.bin"))))
        .collect();
    for (index, job) in jobs.iter().enumerate() {
        verify_mutations(job, &registry, &bytes[index]);
        assert!(bytes[..index]
            .iter()
            .all(|previous| previous != &bytes[index]));
    }
    let log = fs::read_to_string(f.directory.join("worker.log")).unwrap();
    assert!(log.contains("rc=0 completed=3 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"));
    f.check_memory_reports_with_setups(3, 2);
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    let modes: Vec<_> = jobs
        .iter()
        .map(|job| job.operation().proof_mode())
        .collect();
    fs::write(
        f.directory.join("mixed-summary.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "modes": modes, "proofs": 3, "setups": 2, "hits": 1,
            "same_worker_identity": true, "fresh_distinct_proofs": true,
            "pair_wallets": [16,20,24,28], "root_wallets": [0,4,8,12],
            "reservations_held_until_exit": true, "complete_lifetime_rss_admission": false
        }))
        .unwrap(),
    )
    .unwrap();
    println!("native_mixed_cache_verified modes={modes:?} proofs=3 setups=2 hits=1 same_worker_identity=true wallet_policy_mutations=8 public_mutations_per_proof=4");
}

#[test]
#[ignore = "saved mixed-key proofs; CPU only after worker and coordinator exit"]
fn native_mixed_saved_results_verify_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let (registry, _, _, jobs) = mixed_fixture();
    let directory =
        PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap()).join("full-size");
    for (index, job) in jobs.iter().enumerate() {
        verify_mutations(
            job,
            &registry,
            &read(&directory.join(format!("proof-{index}.bin"))),
        );
    }
    assert!(!gpu_hash::is_enabled());
    println!(
        "native_mixed_saved_cpu_verified proofs=3 gpu_initialized=false mutations_per_proof=4"
    );
}
