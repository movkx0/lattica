//! Seeded calibration of every full-64 merge class; never a fresh-workflow claim.
use super::*;
use crate::block_v2::execution::{dag::Completion, scheduler::CostModel};
use p3_field::PrimeCharacteristicRing;

const SEEDS: usize = 33;
const COUNTS: [usize; 5] = [12, 11, 4, 2, 2];
const NATURAL_COMPLETED: [usize; 5] = [45, 56, 60, 62, 63];

fn root_only() -> bool {
    match std::env::var("LATTICA_NATIVE_ROOT_CALIBRATION") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => panic!("invalid standalone root calibration setting"),
    }
}

fn seed_count() -> usize {
    if root_only() {
        2
    } else {
        SEEDS
    }
}

fn retained_proofs(phase: usize) -> usize {
    if root_only() {
        assert_eq!(phase, 4);
        4
    } else {
        SEEDS + COUNTS[..=phase].iter().sum::<usize>()
    }
}

fn limits(peak: Resources, jobs: Resources) -> crate::block_v2::execution::dag::Limits {
    let mut limits = fixture64::limits(peak, jobs);
    limits.jobs = 2 * JOBS;
    limits.attempts = 64;
    // Two admitted orders can retain separate wallet and node bindings even
    // when immutable proof files are shared. This stays below the 512 MiB cap.
    limits.artifact_bytes = 2 * fixture64::artifact_bytes();
    limits
}

fn store_limits() -> StoreLimits {
    StoreLimits {
        bytes: (2 * fixture64::artifact_bytes() + crate::block_v2::profile::MAX_PROOF_BYTES) as u64,
        entries: 64 + 2 * JOBS + 1,
    }
}

fn is_seed(job: &Job) -> bool {
    if root_only() {
        job.expected().level == 5
    } else {
        job.expected().level == 1 || (job.expected().level == 2 && job.start() == 40)
    }
}

fn phase_jobs(selection: &Selection, phase: usize) -> Vec<&Job> {
    let mut jobs: Vec<_> = selection
        .jobs()
        .filter(|job| match phase {
            0 => job.expected().level == 2 && job.start() < 52 && !is_seed(job),
            1 => (job.expected().level == 2 && job.start() >= 52) || job.expected().level == 3,
            2 => job.expected().level == 4,
            3 => job.expected().level == 5,
            4 => job.expected().level == 6,
            _ => false,
        })
        .collect();
    jobs.sort_by_key(|job| {
        // Start phase one with a ready level-three job, giving that class a
        // genuine cold observation before finishing the remaining level twos.
        let first = phase == 1 && job.expected().level == 3 && job.start() == 0;
        (!first, job.expected().level, job.start())
    });
    assert_eq!(jobs.len(), COUNTS[phase] - usize::from(phase == 4));
    jobs
}

#[test]
#[ignore = "CPU verification of the 33 retained natural-order public seeds"]
fn native_sixty_four_calibration_seed_selection() {
    assert!(!gpu_hash::is_enabled());
    let (registry, selection, _) = full_fixture();
    let source = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SEED_SOURCE").unwrap());
    let output = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SEED_NODES").unwrap());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    let mut seen = std::collections::BTreeSet::new();
    for entry in fs::read_dir(source).unwrap() {
        let path = entry.unwrap().path();
        if !path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("n-")
        {
            continue;
        }
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
    if root_only() {
        assert!(selection
            .root()
            .dependencies()
            .iter()
            .all(|id| seen.contains(id)));
        println!("native_sixty_four_root_seeds nodes=2 cpu_verified=true gpu_initialized=false");
        return;
    }
    for phase in 0..COUNTS.len() {
        let jobs = phase_jobs(&selection, phase);
        assert_eq!(jobs[0].expected().level as usize, phase + 2);
        for job in jobs {
            assert!(job.dependencies().iter().all(|id| seen.contains(id)));
            assert!(seen.insert(job.id()));
        }
    }
    assert_eq!(seen.len(), JOBS);
    println!(
        "native_sixty_four_calibration_seeds nodes={SEEDS} cpu_verified=true gpu_initialized=false"
    );
}

fn import_seeds(owner: &mut DurableDag, registry: &Registry<12>, selection: &Selection) {
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
        let ticket = VerifiedNode::verify_typed(job, registry, &bytes).unwrap();
        owner.cache_node(ticket, bytes, now_ms()).unwrap();
    }
    assert_eq!(seen.len(), seed_count());
}

fn owner(
    directory: &Path,
    phase: usize,
    f: &Fixture,
    selection: &Selection,
    context: &PolicyContext,
    deadline: u64,
) -> (DurableDag, CandidateId) {
    let (peak, jobs) = worker_budget::resources(&f.assignment).unwrap();
    if phase == 0 || root_only() {
        if root_only() {
            assert_eq!(phase, 4);
        }
        let mut owner = DurableDag::create(
            &directory.join("journal"),
            journal_limits(),
            ArtifactStore::create(&directory.join("artifacts"), store_limits()).unwrap(),
            selection.root().pin(),
            typed_fixture::CHAIN,
            1,
            limits(peak, jobs),
        )
        .unwrap();
        let candidate = selection
            .attach(&mut owner, [41; 32], deadline, now_ms())
            .unwrap();
        owner.seal(candidate, [41; 32], now_ms()).unwrap();
        assert!(selection
            .jobs()
            .all(|job| owner.verified_node_bytes(job.id()).unwrap().is_none()));
        import_seeds(&mut owner, &f.bootstrap.registry, selection);
        (owner, candidate)
    } else {
        let recovery = DurableDag::recover_typed(
            &directory.join("journal"),
            journal_limits(),
            ArtifactStore::open(&directory.join("artifacts"), store_limits()).unwrap(),
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
        assert_eq!(previous.eligibility, [41; 32]);
        assert!(previous.sealed && !previous.cancelled);
        assert!(
            recovery.unresolved_attempts().is_empty()
                && recovery.unresolved_workspaces().is_empty()
        );
        let now = now_ms();
        let remaining = deadline.checked_sub(now).filter(|ms| *ms > 0).unwrap();
        let (owner, candidate) = recovery
            .resume_sealed_with_workspaces(
                |_| Err("unresolved calibration attempt".into()),
                |_| Err("unresolved calibration workspace".into()),
                || now,
                selection.root().id(),
                [41; 32],
                remaining,
            )
            .unwrap();
        assert_eq!(owner.resource_use().unwrap(), Resources::default());
        assert_eq!(
            selection
                .jobs()
                .filter(|job| owner.status(job.id()).unwrap() == JobStatus::Completed)
                .count(),
            NATURAL_COMPLETED[phase - 1]
        );
        (owner, candidate)
    }
}

fn rotated_fixture() -> (Registry<12>, Selection, PolicyContext) {
    let mut wallets = fixture64::WALLETS;
    wallets.rotate_left(32);
    fixture64::ordered_fixture(wallets)
}

#[test]
#[ignore = "31 GPU merge probes with 33 verified public seeds and two distinct count-64 roots"]
fn native_sixty_four_calibration_phase() {
    let started = Instant::now();
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < COUNTS.len());
    let deadline = setting("LATTICA_NATIVE_DAG_DEADLINE_MS");
    assert!(deadline > now_ms());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let (registry, selection, context) = full_fixture();
    let mut f = Fixture::with_registry(
        "full-size",
        registry.clone(),
        registry.id().unwrap(),
        typed_fixture::CHAIN,
    );
    f.bootstrap.launches = directory.join("launches");
    let (mut owner, natural_candidate) =
        owner(&directory, phase, &f, &selection, &context, deadline);
    let mut second = None;
    let mut rotated_candidate = None;
    if phase == 4 {
        let (other_registry, rotated, _) = rotated_fixture();
        assert_eq!(other_registry.id().unwrap(), registry.id().unwrap());
        assert_ne!(
            rotated.root().expected_public(),
            selection.root().expected_public()
        );
        let candidate = rotated
            .attach(&mut owner, [42; 32], deadline, now_ms())
            .unwrap();
        owner.seal(candidate, [42; 32], now_ms()).unwrap();
        // Only the two independently verified count-32 children are needed.
        // Their proofs bind the same subtrees at different selection positions.
        let children: Vec<_> = rotated
            .jobs()
            .filter(|job| job.expected().level == 5)
            .collect();
        assert_eq!(children.len(), 2);
        for child in children {
            let original = selection
                .jobs()
                .find(|job| job.expected_public() == child.expected_public())
                .unwrap();
            assert_ne!(original.id(), child.id());
            let bytes = owner
                .verified_node_bytes(original.id())
                .unwrap()
                .unwrap()
                .to_vec();
            let ticket = VerifiedNode::verify_typed(child, &registry, &bytes).unwrap();
            owner.cache_node(ticket, bytes, now_ms()).unwrap();
        }
        assert_eq!(owner.status(rotated.root().id()).unwrap(), JobStatus::Ready);
        second = Some(rotated);
        rotated_candidate = Some(candidate);
    }
    let preparation_ms = started.elapsed().as_millis();
    let (_, resources) = worker_budget::resources(&f.assignment).unwrap();
    let mut worker = ProcessWorker::prepare(
        &mut owner,
        f.bootstrap.config(&f.assignment).unwrap(),
        WorkerId(1),
        WorkerId(2),
        now_ms(),
    )
    .unwrap();
    let mut launches = if phase == 0 || root_only() {
        LaunchStore::create(&f.bootstrap.launches, LaunchLimits { records: 64 }).unwrap()
    } else {
        LaunchStore::open(&f.bootstrap.launches, LaunchLimits { records: 64 }).unwrap()
    };
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(worker.service_identity().unwrap()).unwrap(),
    )
    .unwrap();
    worker.replace_context(&context).unwrap();
    let cap = worker
        .scheduling_capabilities_with_timing(host_identity(&f))
        .unwrap();
    let mut costs = CostModel::new(180_000).unwrap();
    let mut jobs = phase_jobs(&selection, phase);
    if let Some(rotated) = &second {
        jobs.push(rotated.root());
    }
    assert_eq!(jobs.len(), COUNTS[phase]);
    let mut calibration = Vec::new();
    let mut timings = Vec::new();
    let mut observations = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        assert!(started.elapsed() < Duration::from_secs(150) && now_ms() < deadline);
        assert_eq!(owner.status(job.id()).unwrap(), JobStatus::Ready);
        let warm = index != 0;
        // A missing class keeps the original bootstrap. Once this exact class
        // has a verified cold observation, the normal warm fallback may use it.
        let (remaining, source) = costs.estimate_with_source(&cap, job, warm).unwrap();
        let proving = Instant::now();
        let issued = now_ms();
        let lease = owner
            .lease(job.id(), WorkerId(2), resources, remaining, 180_000, issued)
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
        let complete = worker.execute(&token, task).unwrap();
        assert!(!worker.retirement_requested());
        let revoked = launches.revoke(lease).unwrap();
        assert!(launches.try_idle(&revoked).unwrap().is_some());
        let output = complete.reconcile(&mut owner, now_ms()).unwrap();
        let expected = owner.begin_verification(lease, now_ms()).unwrap();
        assert_eq!(expected.id(), job.id());
        let verified = VerifiedNode::verify_typed(&expected, &registry, output.bytes()).unwrap();
        assert_eq!(
            owner
                .finish_verification(lease, Some((verified, output.bytes().to_vec())), now_ms())
                .unwrap(),
            Completion::Accepted
        );
        let elapsed = u64::try_from(proving.elapsed().as_millis()).unwrap().max(1);
        costs.observe(&cap, job, warm, elapsed).unwrap();
        calibration.push(save_calibration(
            &f.directory,
            index,
            costs.export_calibration(&cap, job, warm).unwrap(),
        ));
        timings.push(elapsed as f64 / 1000.0);
        observations.push(serde_json::json!({"job":job.id().to_bytes(),"level":job.expected().level,"count":job.expected().count,"warm":warm,"issued_ms":issued,"accepted_ms":now_ms(),"elapsed_ms":elapsed,"admission_ms":remaining,"estimate_source":format!("{source:?}")}));
        assert!(started.elapsed() < Duration::from_secs(150) && now_ms() < deadline);
    }
    assert_eq!(
        selection
            .jobs()
            .filter(|job| owner.status(job.id()).unwrap() == JobStatus::Completed)
            .count(),
        if root_only() {
            3
        } else {
            NATURAL_COMPLETED[phase]
        }
    );
    if let Some(rotated) = &second {
        assert_eq!(
            rotated
                .jobs()
                .filter(|job| owner.status(job.id()).unwrap() == JobStatus::Completed)
                .count(),
            3
        );
        for (index, candidate, eligibility) in [
            (0, natural_candidate, [41; 32]),
            (1, rotated_candidate.unwrap(), [42; 32]),
        ] {
            let bytes = owner
                .candidate_result(candidate, eligibility, now_ms())
                .unwrap()
                .unwrap();
            fs::write(f.directory.join(format!("root-{index}.bin")), bytes).unwrap();
        }
    } else {
        assert!(owner
            .verified_node_bytes(selection.root().id())
            .unwrap()
            .is_none());
    }
    worker.close(&mut owner, now_ms()).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(now_ms() < deadline);
    f.check_memory_reports(COUNTS[phase]);
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    fs::write(f.directory.join("phase-summary.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "phase":phase,"proofs":COUNTS[phase],"retained_proofs":retained_proofs(phase),
        "natural_completed":if root_only() {3} else {NATURAL_COMPLETED[phase]},
        "completed_bindings":if root_only() {6} else {NATURAL_COMPLETED[phase]+usize::from(phase==4)*3},
        "epoch":if root_only() {1} else {phase+1},"deadline_ms":deadline,"wallets":fixture64::WALLETS.as_slice(),"seed_nodes":seed_count(),
        "standalone_root_calibration":root_only(),
        "existing_recursive_proofs_imported":true,"fresh_recursive_dag":false,"uses_pool_coordinator":false,
        "durable_recovery":phase>0&&!root_only(),"reservations_held_until_exit":true,"root_available":phase==4,
        "root_count":if phase==4 {2} else {0},"preparation_ms":preparation_ms,
        "observations":observations,"calibration":calibration,
    })).unwrap()).unwrap();
    println!("native_sixty_four_calibration_verified phase={phase} proofs={} retained_proofs={} roots={} gpu_initialized_in_coordinator=false", COUNTS[phase], retained_proofs(phase), usize::from(phase==4)*2);
}

#[test]
#[ignore = "read-only independent CPU audit of the full retained calibration DAG after all workers exit"]
fn native_sixty_four_calibration_saved_dag_verifies_without_worker() {
    assert!(!gpu_hash::is_enabled());
    let phase = usize::try_from(setting("LATTICA_NATIVE_DAG_PHASE")).unwrap();
    assert!(phase < COUNTS.len());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let (registry, selection, context) = full_fixture();
    let budget: serde_json::Value =
        serde_json::from_slice(&fs::read(public.join("budget.json")).unwrap()).unwrap();
    let (peak, jobs) = worker_budget::resources(&budget).unwrap();
    let recovery = DurableDag::recover_typed(
        &directory.join("journal"),
        journal_limits(),
        ArtifactStore::open(&directory.join("artifacts"), store_limits()).unwrap(),
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        if root_only() { 2 } else { phase as u64 + 2 },
        limits(peak, jobs),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert_eq!(
        recovery.previous_epoch(),
        if root_only() { 1 } else { phase as u64 + 1 }
    );
    assert!(
        recovery.unresolved_attempts().is_empty() && recovery.unresolved_workspaces().is_empty()
    );
    assert_eq!(
        recovery.previous_candidates().len(),
        if phase == 4 { 2 } else { 1 }
    );
    assert!(recovery
        .previous_candidates()
        .iter()
        .all(|candidate| candidate.sealed && !candidate.cancelled));
    assert!(recovery
        .previous_candidates()
        .iter()
        .any(|candidate| candidate.root == selection.root().id()));
    if phase == 4 {
        let (_, rotated, _) = rotated_fixture();
        assert!(recovery
            .previous_candidates()
            .iter()
            .any(|candidate| candidate.root == rotated.root().id()));
        for (index, root) in [selection.root(), rotated.root()].into_iter().enumerate() {
            let bytes = read(&public.join(format!("full-size/root-{index}.bin")));
            VerifiedNode::verify_typed(root, &registry, &bytes).unwrap();
            let mut node = codec::decode_node(&bytes).unwrap();
            node.public[programs::COUNT] += crate::config::Val::ONE;
            assert!(VerifiedNode::verify_typed(
                root,
                &registry,
                &codec::encode_node(&node).unwrap()
            )
            .is_err());
        }
    }
    println!("native_sixty_four_calibration_saved_cpu_verified phase={phase} retained_proofs={} roots={} gpu_initialized=false unresolved_owners=0", retained_proofs(phase), usize::from(phase==4)*2);
}

#[test]
#[ignore = "read-only CPU verification of the failed calibration in its original inode-bound directory"]
fn native_sixty_four_calibration_failed_prefix_verifies_without_worker() {
    assert!(!gpu_hash::is_enabled() && !root_only());
    let directory = PathBuf::from(std::env::var_os("LATTICA_NATIVE_DAG_DIR").unwrap());
    let public = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
    let (registry, selection, context) = full_fixture();
    let budget: serde_json::Value =
        serde_json::from_slice(&fs::read(public.join("budget.json")).unwrap()).unwrap();
    let (peak, jobs) = worker_budget::resources(&budget).unwrap();
    let recovery = DurableDag::recover_typed(
        &directory.join("journal"),
        journal_limits(),
        ArtifactStore::open(&directory.join("artifacts"), store_limits()).unwrap(),
        selection.root().pin(),
        &registry,
        typed_fixture::CHAIN,
        6,
        limits(peak, jobs),
        |artifact| context.policy(artifact),
    )
    .unwrap();
    assert_eq!(recovery.previous_epoch(), 5);
    assert!(recovery.unresolved_attempts().is_empty());
    // Admission failed before issuing a lease. The prepared workspace remains
    // in the journal; this audit observes it without resuming or releasing it.
    assert_eq!(recovery.unresolved_workspaces().len(), 1);
    assert_eq!(recovery.previous_candidates().len(), 2);
    let (_, rotated, _) = rotated_fixture();
    for root in [selection.root(), rotated.root()] {
        assert!(recovery
            .previous_candidates()
            .iter()
            .any(|candidate| candidate.root == root.id()
                && candidate.sealed
                && !candidate.cancelled));
    }
    let nodes = fs::read_dir(directory.join("artifacts"))
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            let name = name.to_str().unwrap();
            name.starts_with("n-") && name.ends_with(".proof")
        })
        .count();
    assert_eq!(nodes, 62);
    assert!(
        !(public.join("full-size/root-0.bin").exists()
            || public.join("full-size/root-1.bin").exists())
    );
    println!("native_sixty_four_failed_prefix_cpu_verified retained_proofs=62 gpu_initialized=false unresolved_attempts=0 unresolved_workspaces=1 read_only=true");
}
