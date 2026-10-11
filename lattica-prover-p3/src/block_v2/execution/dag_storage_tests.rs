use super::*;
use crate::block_v2::execution::job::test_support::{node, pin, wallet};

fn limits() -> Limits {
    Limits {
        jobs: 256,
        candidates: 8,
        attempts: 256,
        artifact_bytes: 256 << 20,
        recovery_window_ms: 10,
        workers: Resources {
            ram_bytes: 400,
            vram_bytes: 40,
            scratch_bytes: 400,
            threads: 4,
        },
    }
}

fn request() -> Resources {
    Resources {
        ram_bytes: 100,
        vram_bytes: 10,
        scratch_bytes: 100,
        threads: 1,
    }
}

fn check(dag: &Dag) {
    let usage = dag.retained_storage().unwrap();
    let plan = dag.limits.retained_storage().unwrap();
    assert!(usage.metadata_bytes <= plan.metadata_bytes);
    assert_eq!(usage.artifact_bytes, dag.stored_bytes());
    assert!(usage.total_bytes().unwrap() <= plan.total_bytes().unwrap());
}

fn tree(dag: &mut Dag, start: u8, level: u8) -> Job {
    let (job, wallets) = if level == 0 {
        let bytes = vec![start + 1];
        (
            Job::wrap(start, wallet(u64::from(start) + 1, &bytes)).unwrap(),
            vec![bytes],
        )
    } else {
        let left = tree(dag, start, level - 1);
        let right = tree(dag, start + (1 << (level - 1)), level - 1);
        (Job::merge(&left, &right).unwrap(), vec![])
    };
    dag.admit(job.clone(), wallets, 0).unwrap();
    check(dag);
    job
}

#[test]
fn retained_wallets_discard_caller_capacity_before_ownership_transfer() {
    let mut dag = Dag::new(pin(), [9; 32], 1, limits()).unwrap();
    let mut bytes = Vec::with_capacity(1 << 20);
    bytes.push(1);
    let job = Job::wrap(0, wallet(1, &bytes)).unwrap();
    let mut wallets = Vec::with_capacity(4096);
    wallets.push(bytes);
    dag.admit(job.clone(), wallets, 0).unwrap();
    let record = &dag.jobs[&job.id()];
    assert_eq!(record.wallets.capacity(), 1);
    assert_eq!(record.wallets[0].len(), 1);
    assert_eq!(dag.retained_storage().unwrap().artifact_bytes, 1);
    let empty = Job::empty(pin(), [9; 32], 1, 0).unwrap();
    dag.admit(empty.clone(), Vec::with_capacity(4096), 0)
        .unwrap();
    assert_eq!(dag.jobs[&empty.id()].wallets.capacity(), 0);
    check(&dag);
}

#[test]
fn full_tree_candidate_and_retry_limits_keep_shared_inputs_within_retained_bound() {
    let mut dag = Dag::new(pin(), [9; 32], 1, limits()).unwrap();
    let root = tree(&mut dag, 0, DEPTH);
    let candidates: Vec<_> = (0..8)
        .map(|i| dag.attach(root.id(), [i; 32], 100_000, 0).unwrap())
        .collect();
    assert_eq!(dag.jobs.len(), 127);
    assert!(dag.attach(root.id(), [9; 32], 100_000, 0).is_err());
    assert!(dag.candidates.values().all(|c| c.closure.len() == 127));
    assert!(dag.jobs.values().all(|r| r.candidates.len() == 8));
    check(&dag);
    let leaf = Job::wrap(0, wallet(1, &[1])).unwrap();
    for i in 0..256 {
        let now = i * 3;
        let lease = dag
            .lease(leaf.id(), WorkerId(1), request(), 1, 100, now)
            .unwrap();
        let attempt = &dag.attempts[&lease.id()];
        assert_eq!(attempt.inputs.capacity(), 1);
        assert_eq!(attempt.manifest.capacity(), 1);
        assert!(Arc::ptr_eq(
            &attempt.inputs[0],
            &dag.jobs[&leaf.id()].wallets[0]
        ));
        check(&dag);
        dag.reject_worker(lease, now + 1).unwrap();
        assert_eq!(dag.prune(now + 1).unwrap(), 0);
        check(&dag);
        dag.worker_stopped(lease, now + 2).unwrap();
        assert!(dag.attempts[&lease.id()].inputs.is_empty());
        assert_eq!(dag.attempts[&lease.id()].inputs.capacity(), 1);
        check(&dag);
    }
    assert_eq!(dag.attempts.len(), 256);
    assert!(dag
        .lease(leaf.id(), WorkerId(1), request(), 1, 100, 768)
        .is_err());
    for id in candidates {
        dag.cancel(id, 769).unwrap();
    }
    assert_eq!(dag.prune(780).unwrap(), 127);
    assert_eq!(dag.stored_bytes(), 0);
    check(&dag); // empty retained BTree roots still have a storage allowance
}

#[test]
fn accepted_output_and_verifying_input_ownership_remain_in_separate_components() {
    let mut dag = Dag::new(pin(), [9; 32], 1, limits()).unwrap();
    let root = tree(&mut dag, 0, DEPTH);
    let candidate = dag.attach(root.id(), [1; 32], 100_000, 0).unwrap();
    let leaf = Job::wrap(0, wallet(1, &[1])).unwrap();
    let lease = dag
        .lease(leaf.id(), WorkerId(1), request(), 1, 100, 1)
        .unwrap();
    dag.worker_stopped(lease, 2).unwrap();
    dag.begin_verification(lease, 3).unwrap();
    check(&dag);
    assert_eq!(dag.retained_storage().unwrap().artifact_bytes, 64);
    let mut output = Vec::with_capacity(1 << 20);
    output.extend_from_slice(&[7, 8, 9]);
    let ticket = node(&leaf, &output);
    assert_eq!(
        dag.finish_verification(lease, Some((ticket, output)), 4)
            .unwrap(),
        Completion::Accepted
    );
    assert_eq!(dag.retained_storage().unwrap().artifact_bytes, 67);
    check(&dag);
    dag.cancel(candidate, 5).unwrap();
    assert_eq!(dag.prune(16).unwrap(), 127);
    assert_eq!(dag.retained_storage().unwrap().artifact_bytes, 0);
    check(&dag);
}

#[test]
fn retained_graph_component_requires_its_exact_cap_and_valid_limits() {
    for (name, limits) in [
        ("cli", limits()),
        (
            "hard",
            Limits {
                jobs: 4096,
                candidates: 256,
                attempts: 16384,
                artifact_bytes: 512 << 20,
                ..limits()
            },
        ),
    ] {
        let plan = limits.retained_storage().unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        println!("coordinator_retained_storage profile={name} metadata_bytes={} artifact_bytes={} total_bytes={total}", plan.metadata_bytes, plan.artifact_bytes);
    }
    for bad in [
        Limits {
            jobs: 4097,
            ..limits()
        },
        Limits {
            attempts: 0,
            ..limits()
        },
    ] {
        assert!(bad.retained_storage().is_err());
    }
    assert!(RetainedStorage {
        metadata_bytes: usize::MAX,
        artifact_bytes: 1
    }
    .total_bytes()
    .is_err());
}

#[test]
fn query_capacities_preserve_ready_order_through_a_full_tree_and_prune() {
    let mut dag = Dag::new(pin(), [9; 32], 1, limits()).unwrap();
    let root = tree(&mut dag, 0, DEPTH);
    let candidate = dag.attach(root.id(), [1; 32], 100_000, 0).unwrap();
    let bound = dag.limits.transition_storage().unwrap();
    let mut now = 0;
    let mut completed = 0;
    loop {
        let ready = dag.ready();
        let mut reference: Vec<_> = dag
            .jobs
            .iter()
            .filter(|(id, _)| matches!(dag.status(**id), Ok(JobStatus::Ready)))
            .map(|(id, record)| {
                (
                    dag.deadline(record),
                    std::cmp::Reverse(record.job.expected().level),
                    record.job.start(),
                    *id,
                )
            })
            .collect();
        reference.sort(); // frozen previous ordering policy
        assert_eq!(
            ready,
            reference
                .into_iter()
                .map(|(_, _, _, id)| id)
                .collect::<Vec<_>>()
        );
        let pending = dag.pending_stops();
        assert_eq!(ready.capacity(), ready.len());
        assert_eq!(pending.capacity(), pending.len());
        #[cfg(target_os = "linux")]
        {
            let artifacts = dag.retained_artifacts();
            assert_eq!(artifacts.capacity(), artifacts.len());
            let bytes = ready.capacity() * size_of::<JobId>()
                + pending.capacity() * size_of::<Lease>()
                + artifacts.capacity() * size_of::<ArtifactRef>();
            assert!(bytes <= bound.query_bytes);
        }
        let Some(id) = ready.first() else {
            break;
        };
        let lease = dag.lease(*id, WorkerId(1), request(), 1, 100, now).unwrap();
        let job = dag.leased_job(lease).unwrap().clone();
        now += 1;
        dag.worker_stopped(lease, now).unwrap();
        dag.begin_verification(lease, now).unwrap();
        now += 1;
        assert_eq!(
            dag.finish_verification(lease, Some((node(&job, &[42]), vec![42])), now)
                .unwrap(),
            Completion::Accepted
        );
        completed += 1;
    }
    assert_eq!(completed, 127);
    dag.cancel(candidate, now).unwrap();
    assert_eq!(dag.prune(now + 11).unwrap(), 127);
    check(&dag);
    for (name, configured) in [
        ("cli", limits()),
        (
            "hard",
            Limits {
                jobs: 4096,
                candidates: 256,
                attempts: 16384,
                artifact_bytes: 512 << 20,
                ..limits()
            },
        ),
    ] {
        let plan = configured.transition_storage().unwrap();
        println!(
            "bounded_dag_transitions profile={name} index_bytes={} query_bytes={} total_bytes={}",
            plan.index_bytes,
            plan.query_bytes,
            plan.total_bytes().unwrap()
        );
    }
}
