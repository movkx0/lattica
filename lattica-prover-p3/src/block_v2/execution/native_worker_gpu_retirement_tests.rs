//! Real GPU retirement under retained libc capacity, followed by a fresh worker.
use super::*;
use crate::block_v2::{execution::job::VerifiedWallet, typed_fixture, typed_recursive::Policy};

fn monotonic_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    u64::try_from(time.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(time.tv_nsec).unwrap()
}

fn read(path: &Path) -> Vec<u8> {
    assert!(fs::symlink_metadata(path).unwrap().is_file());
    assert!(fs::metadata(path).unwrap().len() <= crate::block_v2::profile::MAX_PROOF_BYTES as u64);
    fs::read(path).unwrap()
}

fn start(f: &Fixture, worker: &mut ProcessWorker, mode: &str) {
    let (launcher, args) = f.launcher(&f.bootstrap, mode);
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    if mode == "retained-heap" {
        let log = fs::read_to_string(f.directory.join("worker.log")).unwrap();
        assert!(
            log.contains("native_retained_heap_injected boundary=ready_header wrapped_send=true"),
            "retained-heap fixture did not inject after startup: {log}"
        );
    }
    assert!(worker
        .service_identity()
        .unwrap()
        .cgroup()
        .ends_with(&f.unit));
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(worker.service_identity().unwrap()).unwrap(),
    )
    .unwrap();
}

fn prove(
    f: &Fixture,
    owner: &mut DurableDag,
    worker: &mut ProcessWorker,
    launches: &mut LaunchStore,
    job: &Job,
    retiring: bool,
    now: u64,
) -> (Vec<u8>, f64) {
    let (peak, resources) = worker_budget::resources(&f.assignment).unwrap();
    let lease = owner
        .lease(job.id(), WorkerId(2), resources, 1, 1000, now)
        .unwrap();
    let task = worker.task(owner, lease, now).unwrap();
    let token = launches
        .issue_bound(
            owner,
            lease,
            &task.request().unwrap(),
            worker.execution_digest().unwrap(),
        )
        .unwrap();
    let started = std::time::Instant::now();
    let completed = worker.execute(&token, task).unwrap();
    let seconds = started.elapsed().as_secs_f64();
    assert_eq!(worker.retirement_requested(), retiring);
    if retiring {
        let held = owner.resource_use().unwrap();
        assert!(worker.task(owner, lease, now).is_err());
        assert_eq!(owner.resource_use().unwrap(), held);
    }
    let revoked = launches.revoke(lease).unwrap();
    assert!(launches.try_idle(&revoked).unwrap().is_some());
    let output = completed.reconcile(owner, now).unwrap();
    let expected = owner.begin_verification(lease, now).unwrap();
    assert!(!gpu_hash::is_enabled());
    let verified =
        VerifiedNode::verify_typed(&expected, &f.bootstrap.registry, output.bytes()).unwrap();
    let mut altered = codec::decode_node(output.bytes()).unwrap();
    altered.public[programs::COUNT] += crate::config::Val::ONE;
    assert!(VerifiedNode::verify_typed(
        &expected,
        &f.bootstrap.registry,
        &codec::encode_node(&altered).unwrap()
    )
    .is_err());
    let bytes = output.bytes().to_vec();
    fs::write(f.directory.join("proof-0.bin"), &bytes).unwrap();
    assert_eq!(
        owner
            .finish_verification(lease, Some((verified, bytes.clone())), now)
            .unwrap(),
        Completion::Accepted
    );
    assert_eq!(worker.stats().unwrap(), CacheStats { setups: 1, hits: 0 });
    assert_eq!(
        owner.resource_use().unwrap(),
        Resources { threads: 0, ..peak }
    );
    (bytes, seconds)
}

#[test]
#[ignore = "two full-size GPU proofs, retained-arena retirement and observed replacement under capped services"]
fn native_full_size_retirement_preserves_result_and_fences_replacement_until_exit() {
    let fixture = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let root = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let registry = Registry::<12> {
        height: serde_json::from_slice(&read(&fixture.join("height.json"))).unwrap(),
        caps: std::array::from_fn(|i| {
            let bytes = read(&fixture.join(format!("key.{}", i + 1)));
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    assert_eq!(registry.height, 1 << 18);
    let profile = registry.id().unwrap();
    let first = Fixture::with_registry("retirement", registry, profile, typed_fixture::CHAIN);
    let mut replacement = Fixture::with_registry(
        "replacement",
        first.bootstrap.registry.clone(),
        profile,
        typed_fixture::CHAIN,
    );
    // Launch admission is pinned by the durable coordinator, not by the
    // lifetime of one process. Replacement keeps that namespace and signs a
    // new worker execution digest within it.
    replacement.bootstrap.launches = first.bootstrap.launches.clone();
    let (mut owner, mut worker, mut launches) = first.owner();
    let pin = first.bootstrap.validate().unwrap().0.pin();
    let wallet_bytes = [0, 4].map(|i| read(&fixture.join(format!("wallet.{i}"))));
    let wallets = wallet_bytes.each_ref().map(|bytes| {
        VerifiedWallet::verify_typed(
            pin,
            &first.bootstrap.registry,
            typed_fixture::CHAIN,
            Policy::JoinSplit,
            bytes,
        )
        .unwrap()
    });
    let pair = Job::typed_pair(0, wallets[0], Some(wallets[1])).unwrap();
    let empty = Job::empty(pin, typed_fixture::CHAIN, 2, 1).unwrap();
    let merged = Job::merge(&pair, &empty).unwrap();
    owner.admit(pair.clone(), wallet_bytes.to_vec(), 0).unwrap();
    owner.admit(empty.clone(), vec![], 0).unwrap();
    owner.admit(merged.clone(), vec![], 0).unwrap();
    for (job, variable) in [
        (&pair, "LATTICA_FULL_SIZE_PAIR"),
        (&empty, "LATTICA_FULL_SIZE_EMPTY"),
        (&merged, "LATTICA_FULL_SIZE_MERGE"),
    ] {
        let bytes = read(&PathBuf::from(std::env::var_os(variable).unwrap()));
        let verified = VerifiedNode::verify_typed(job, &first.bootstrap.registry, &bytes).unwrap();
        owner.cache_node(verified, bytes, 0).unwrap();
    }
    let jobs = [
        Job::finalize(&pair).unwrap(),
        Job::finalize(&merged).unwrap(),
    ];
    assert_ne!(jobs[0].id(), jobs[1].id());
    assert_eq!(jobs[0].expected_public(), jobs[1].expected_public());
    for (index, job) in jobs.iter().enumerate() {
        owner.admit(job.clone(), vec![], 0).unwrap();
        owner
            .attach(job.id(), [index as u8 + 1; 32], 1000, 0)
            .unwrap();
    }
    let first_launch_ns = monotonic_ns();
    start(&first, &mut worker, "retained-heap");
    let first_pid = worker.pid().unwrap();
    let first_execution = worker.execution_digest().unwrap();
    let (first_proof, first_seconds) = prove(
        &first,
        &mut owner,
        &mut worker,
        &mut launches,
        &jobs[0],
        true,
        1,
    );
    let first_verified_ns = monotonic_ns();
    let held = owner.resource_use().unwrap();
    let premature = ProcessWorker::prepare(
        &mut owner,
        replacement
            .bootstrap
            .config(&replacement.assignment)
            .unwrap(),
        WorkerId(3),
        WorkerId(4),
        1,
    );
    let premature_error = premature
        .err()
        .expect("retiring worker still holds all worker RAM");
    assert_eq!(owner.resource_use().unwrap(), held);
    worker.close(&mut owner, 2).unwrap();
    let first_exit_ns = monotonic_ns();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    first.check_memory_reports(1);
    VerifiedNode::verify_typed(&jobs[0], &first.bootstrap.registry, &first_proof).unwrap();

    // The external observer must finish the first pidfd observation before
    // arming for a new process with the same executable in this fleet.
    fs::write(
        root.join("replacement-plan.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "first_exit_ns": first_exit_ns, "replacement_unit": replacement.unit,
        }))
        .unwrap(),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !root.join("replacement-observer-ready").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "replacement observer was not armed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut next = ProcessWorker::prepare(
        &mut owner,
        replacement
            .bootstrap
            .config(&replacement.assignment)
            .unwrap(),
        WorkerId(1),
        WorkerId(2),
        3,
    )
    .unwrap();
    assert_ne!(next.execution_digest().unwrap(), first_execution);
    let replacement_launch_ns = monotonic_ns();
    assert!(replacement_launch_ns > first_exit_ns);
    start(&replacement, &mut next, "ok");
    let replacement_pid = next.pid().unwrap();
    assert_ne!(replacement_pid, first_pid);
    let (second_proof, second_seconds) = prove(
        &replacement,
        &mut owner,
        &mut next,
        &mut launches,
        &jobs[1],
        false,
        4,
    );
    let replacement_verified_ns = monotonic_ns();
    next.close(&mut owner, 5).unwrap();
    let replacement_exit_ns = monotonic_ns();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    replacement.check_memory_reports(1);
    assert_ne!(first_proof, second_proof);
    for bytes in [&first_proof, &second_proof] {
        VerifiedNode::verify_typed(&jobs[0], &first.bootstrap.registry, bytes).unwrap();
    }
    for f in [&first, &replacement] {
        assert!(fs::read_to_string(f.directory.join("worker.log"))
            .unwrap()
            .contains("rc=0 completed=1 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"));
    }
    let summary = serde_json::json!({
        "first_pid": first_pid, "replacement_pid": replacement_pid,
        "first_launch_ns": first_launch_ns, "first_verified_ns": first_verified_ns,
        "first_exit_ns": first_exit_ns, "replacement_launch_ns": replacement_launch_ns,
        "replacement_verified_ns": replacement_verified_ns, "replacement_exit_ns": replacement_exit_ns,
        "premature_replacement_error": premature_error.to_string(),
        "fresh_execution_digest": true, "reservations_released_after_exit": true,
        "proof_sizes_bytes": [first_proof.len(), second_proof.len()],
        "timings": [first_seconds, second_seconds], "cpu_verified": true,
        "altered_rejected": 2, "post_exit_verified": true,
    });
    fs::write(
        root.join("retirement-summary.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
    println!("native_gpu_retirement_verified proofs=2 rows=262144 retired_after_result=true premature_replacement_rejected=true physical_exit_before_replacement=true cpu_verified=true altered_rejected=2 fresh_proof_bytes=true fresh_execution_digest=true reservations_released=true");
}
