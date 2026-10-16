//! Structural admission tests. These do not fabricate live timing evidence.
use super::*;
use lattica_prover_p3::block_v2::execution::job::RegistryPin;
use p3_field::PrimeCharacteristicRing;

fn graph() -> Vec<Job> {
    let registry = lattica_prover_p3::block_v2::recursive::Registry {
        height: 8,
        caps: std::array::from_fn(|_| vec![[Val::ONE; 4]; 1 << profile::CAP_HEIGHT]),
    };
    let pin = RegistryPin::new(
        &registry,
        registry.id().unwrap(),
        lattica_prover_p3::block_v2::recursive::WrapperConstruction::SingleWallet,
    )
    .unwrap();
    let left = Job::empty(pin, [9; 32], 0, 0).unwrap();
    let right = Job::empty(pin, [9; 32], 1, 0).unwrap();
    let root = Job::merge(&left, &right).unwrap();
    vec![left, right, root]
}

fn request() -> Request {
    Request {
        schema_version: 1,
        identity: [[1; 32]; 5],
        jobs: graph().iter().map(|job| job.id().to_bytes()).collect(),
        seeds: vec![],
    }
}

fn plan() -> Plan {
    let mut plan = super::super::tests::plan();
    plan.workers.truncate(1);
    plan.pool_calibration = Some(request());
    let boot = "01234567-89ab-cdef-0123-456789abcdef".to_owned();
    plan.pool_workflow = Some(pool_timing::Workflow {
        schema_version: 1,
        boot_id: boot.clone(),
        started_monotonic_ms: 1,
        deadline_monotonic_ms: 600001,
    });
    plan.pool_scheduling = Some(pool_timing::Window {
        schema_version: 1,
        boot_id: boot,
        issued_monotonic_ms: 1,
        dispatch_deadline_monotonic_ms: 150001,
    });
    plan.coordinator_ram_bytes = 1 << 30;
    plan.coordinator_shared_bytes = storage::shared_reservation(1);
    plan.coordinator_threads = 4;
    plan.fleet_bytes = 4 << 30;
    plan.startup_fenced = true;
    plan.coordinator_bootstrap_guard = Some("/tmp/calibration-startup".into());
    let host = &mut plan.workers[0].assignment["host"];
    host["worker_bytes"] = json!(3u64 << 30);
    host["coordinator_bytes"] = json!(1u64 << 30);
    host["coordinator_shared_bytes"] = json!(plan.coordinator_shared_bytes);
    host["coordinator_job_bytes"] =
        json!(plan.coordinator_ram_bytes - plan.coordinator_shared_bytes);
    host["fleet_bytes"] = json!(4u64 << 30);
    plan
}

#[test]
fn calibration_has_one_bounded_worker_and_cannot_be_a_pool_or_retry() {
    let base = plan();
    validate_plan_shape(&base).unwrap();
    for change in 0..12 {
        let mut plan = base.clone();
        match change {
            0 => plan.pool_scheduling = None,
            1 => plan.pool_workflow = None,
            2 => plan.pool_requests = Some("/tmp/requests".into()),
            3 => plan.recover_from = Some("/tmp/old".into()),
            4 => plan.recover_cached_only = true,
            5 => plan.preseal_only = true,
            6 => plan.allow_worker_failover = true,
            7 => plan.reuse_preseal.push("/tmp/prefix".into()),
            8 => plan.startup_fenced = false,
            9 => plan.coordinator_bootstrap_guard = None,
            10 => plan.workers[0].pool_timing = Some("/tmp/approval".into()),
            _ => plan.workers.push(plan.workers[0].clone()),
        }
        assert!(validate_plan_shape(&plan).is_err(), "case {change}");
    }
}

#[test]
fn calibration_cannot_change_original_worker_or_cpu_limits() {
    for change in 0..3 {
        let mut plan = plan();
        match change {
            0 => plan.coordinator_threads = 3,
            1 => plan.workers[0].assignment["cpu"]["rayon_threads"] = json!(3),
            _ => plan.workers[0].assignment["host"]["worker_bytes"] = json!((3u64 << 30) + 1),
        }
        assert!(validate_plan_shape(&plan).is_err());
    }
}

#[test]
fn calibration_jobs_require_ordered_dependencies_or_explicit_seeds() {
    let graph = graph();
    request().ordered(graph.iter()).unwrap();
    let mut seeded = request();
    seeded.jobs = vec![graph[2].id().to_bytes()];
    for job in &graph[..2] {
        seeded.seeds.push(Seed {
            job: job.id().to_bytes(),
            path: "/tmp/seed".into(),
        });
    }
    assert_eq!(seeded.ordered(graph.iter()).unwrap().len(), 1);
    seeded.seeds.pop();
    assert!(seeded.ordered(graph.iter()).is_err());
    let mut unordered = request();
    unordered.jobs.reverse();
    assert!(unordered.ordered(graph.iter()).is_err());
}

#[test]
fn calibration_rejects_unknown_duplicate_unused_or_preproved_jobs() {
    let graph = graph();
    for change in 0..7 {
        let mut request = request();
        match change {
            0 => request.jobs[0] = [255; 32],
            1 => request.jobs.push(request.jobs[0]),
            2 => request.seeds.push(Seed {
                job: request.jobs[0],
                path: "/tmp/preproved".into(),
            }),
            3 => request.seeds.push(Seed {
                job: [255; 32],
                path: "/tmp/unknown".into(),
            }),
            4 => request.jobs.clear(),
            5 => request.identity[0] = [0; 32],
            _ => {
                request.jobs = vec![graph[1].id().to_bytes()];
                request.seeds.push(Seed {
                    job: graph[0].id().to_bytes(),
                    path: "/tmp/unused".into(),
                });
            }
        }
        assert!(request.ordered(graph.iter()).is_err(), "case {change}");
    }
}

#[test]
fn calibration_decoder_rejects_excess_inventory_before_nested_payload() {
    let base = serde_json::to_value(request()).unwrap();
    for field in ["jobs", "seeds"] {
        let mut value = base.clone();
        let (limit, element) = if field == "jobs" {
            (MAX_JOBS, json!(vec![1; 32]))
        } else {
            (MAX_SEEDS, json!({"job":vec![1; 32],"path":"/tmp/seed"}))
        };
        let mut entries = vec![element; limit];
        entries.push(json!({"untrusted_extra":[[[],[]]]}));
        value[field] = json!(entries);
        let error = serde_json::from_value::<Request>(value).err().unwrap();
        assert!(error.to_string().contains("preparation collection limit"));
    }
}

#[test]
fn calibration_window_rejects_equality_and_never_renews_workflow() {
    within(149999, 150000).unwrap();
    assert!(within(150000, 150000).is_err());
    assert!(within(180000, 180000).is_err());
    within(599999, 650000).unwrap();
    assert!(within(600000, 650000).is_err());
    assert!(within(u64::MAX, u64::MAX).is_err());
    assert!(storage_bytes() < 4 << 20);
}
