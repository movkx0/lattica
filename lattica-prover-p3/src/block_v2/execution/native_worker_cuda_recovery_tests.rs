//! Abrupt CUDA process loss followed by independently verified journal recovery.
//! Fault injection belongs to this parent test; the maintained CLI is unchanged.
use super::*;
use crate::block_v2::execution::{
    dag::Lease,
    job::JobId,
    launch::{self, WorkerGate},
    os_worker,
    startup::{self, Intent},
};
use std::{path::Path, time::Duration};

pub(super) struct Case {
    pub(super) out: PathBuf,
    pub(super) fixture: PathBuf,
    pub(super) bootstrap: Bootstrap,
    pub(super) policy: PolicyContext,
    pub(super) selection: Selection,
    pub(super) config: Config,
    pub(super) budget: Value,
    pub(super) owner: DurableDag,
    pub(super) worker: ProcessWorker,
    pub(super) launches: LaunchStore,
    pub(super) arguments: Vec<OsString>,
    pub(super) launch_arguments: Vec<OsString>,
    pub(super) intent: Intent,
    pub(super) peak: Resources,
    pub(super) jobs: Resources,
    pub(super) start: Instant,
}

fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn reports(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("proving_stage_report "))
        .map(|value| serde_json::from_str(value).unwrap())
        .collect()
}

fn observe(worker: &ProcessWorker) -> Value {
    let identity = serde_json::to_value(worker.service_identity().unwrap()).unwrap();
    let group = PathBuf::from("/sys/fs/cgroup")
        .join(identity["group"].as_str().unwrap().trim_start_matches('/'));
    let mut result = serde_json::Map::new();
    for key in [
        "memory.max",
        "memory.swap.max",
        "memory.peak",
        "memory.events",
        "cpu.max",
        "pids.max",
    ] {
        result.insert(
            key.into(),
            json!(fs::read_to_string(group.join(key)).unwrap().trim()),
        );
    }
    assert_eq!(result["memory.max"], (3u64 << 30).to_string());
    assert_eq!(result["memory.swap.max"], "0");
    assert!(
        result["memory.peak"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            <= 3u64 << 30
    );
    Value::Object(result)
}

impl Case {
    fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap()
    }

    fn dispatch(&mut self) -> (Lease, launch::Token, Vec<u8>) {
        let now = self.now();
        // Recovery cannot renew the experiment's original dispatch window.
        let remaining = 150_000u64.checked_sub(now).unwrap();
        assert!(remaining > 0);
        let job = self.owner.ready().unwrap()[0];
        let lease = self
            .owner
            .lease(job, WorkerId(2), self.jobs, remaining, remaining, now)
            .unwrap();
        let task = self.worker.task(&mut self.owner, lease, now).unwrap();
        let request = task.request().unwrap();
        let token = self
            .launches
            .issue_bound(
                &mut self.owner,
                lease,
                &request,
                self.worker.execution_digest().unwrap(),
            )
            .unwrap();
        self.worker.dispatch(&token, task).unwrap();
        (lease, token, request)
    }

    fn prove(&mut self) -> (JobId, Vec<u8>, Value) {
        let started = Instant::now();
        let (lease, _, _) = self.dispatch();
        let completed = loop {
            if let Some(completed) = self.worker.try_collect().unwrap() {
                break completed;
            }
            assert!(self.now() < 150_000, "original dispatch window elapsed");
            std::thread::sleep(Duration::from_millis(5));
        };
        let revoked = self.launches.revoke(lease).unwrap();
        assert!(self.launches.try_idle(&revoked).unwrap().is_some());
        let now = self.now();
        let output = completed.reconcile(&mut self.owner, now).unwrap();
        let job = self.owner.begin_verification(lease, now).unwrap();
        let verified =
            VerifiedNode::verify_typed(&job, &self.bootstrap.registry, output.bytes()).unwrap();
        let mut altered = codec::decode_node(output.bytes()).unwrap();
        altered.public[crate::block_v2::machine::programs::COUNT] += crate::config::Val::ONE;
        assert!(VerifiedNode::verify_typed(
            &job,
            &self.bootstrap.registry,
            &codec::encode_node(&altered).unwrap()
        )
        .is_err());
        let bytes = output.bytes().to_vec();
        assert_eq!(
            self.owner
                .finish_verification(lease, Some((verified, bytes.clone())), now)
                .unwrap(),
            Completion::Accepted
        );
        assert!(!self.worker.retirement_requested());
        assert_eq!(
            self.owner.resource_use().unwrap(),
            Resources {
                threads: 0,
                ..self.peak
            }
        );
        if job.id() == self.selection.root().id() {
            fs::write(self.out.join("root.bin"), &bytes).unwrap();
        }
        (
            job.id(),
            bytes,
            json!({"mode":job.operation().proof_mode(), "seconds":started.elapsed().as_secs_f64()}),
        )
    }
}

pub(super) fn run(mut case: Case) {
    let (first_job, first_proof, first_record) = case.prove();
    fs::write(case.out.join("accepted-before-failure.bin"), &first_proof).unwrap();
    let first_pid = case.worker.pid().unwrap();
    let first_execution = case.worker.execution_digest().unwrap();
    let first_identity = case.worker.service_identity().unwrap().clone();
    let old_log = case.out.join("worker.log");
    let before = reports(&old_log).len();
    let (failed_lease, failed_token, failed_request) = case.dispatch();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            case.worker.try_collect().unwrap().is_none(),
            "fault must precede result collection"
        );
        if reports(&old_log).iter().skip(before).any(|report| {
            report["entry_point"] == "cuda_typed_preprocessing" && report["succeeded"] == true
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CUDA preprocessing was not observed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    write(
        &case.out.join("interrupted-observation.json"),
        &observe(&case.worker),
    );
    let charged = case.owner.resource_use().unwrap();
    let now = case.now();
    assert!(ProcessWorker::prepare(
        &mut case.owner,
        case.config.clone(),
        WorkerId(3),
        WorkerId(4),
        now
    )
    .is_err());
    assert_eq!(case.owner.resource_use().unwrap(), charged);
    // Kill only the exact supervised qualification service after its identity
    // was authenticated. No production fault switch or worker hook is used.
    assert!(Command::new("systemctl")
        .args([
            "--user",
            "kill",
            "--kill-whom=all",
            "--signal=KILL",
            &case.intent.unit
        ])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while case.worker.try_collect().is_ok() {
        assert!(
            Instant::now() < deadline,
            "terminated CUDA worker did not close its socket"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        case.owner.resource_use().unwrap(),
        charged,
        "socket EOF cannot release reservations"
    );
    let start = case.start;
    case.worker
        .stop_failed_supervised(&mut case.owner, &mut case.launches, failed_lease, || {
            u64::try_from(start.elapsed().as_millis()).unwrap()
        })
        .unwrap();
    let reconciled_ms = case.now();
    assert!(os_worker::exited(&first_identity, &case.intent.unit).unwrap());
    assert_eq!(case.owner.resource_use().unwrap(), Resources::default());
    assert!(WorkerGate::enter(&case.bootstrap.launches, &failed_token, &failed_request).is_err());
    let old_fence = startup::reconcile(&case.out.join("startup"), &case.intent).unwrap();
    assert!(old_fence.future_start_fenced && old_fence.process_and_service_quiescent);
    assert!(startup::authorize(&case.out.join("startup"), &case.intent, first_execution).is_err());
    assert_eq!(
        case.owner.verified_node_bytes(first_job).unwrap().unwrap(),
        first_proof
    );
    drop(case.worker);
    drop(case.launches);
    drop(case.owner);

    let store = ArtifactStore::open(
        &case.out.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 64,
        },
    )
    .unwrap();
    let recovered = DurableDag::recover_typed(
        &case.out.join("journal"),
        JournalLimits {
            snapshot_bytes: 1 << 20,
        },
        store,
        case.selection.root().pin(),
        &case.bootstrap.registry,
        case.bootstrap.chain,
        2,
        Limits {
            jobs: 32,
            candidates: 4,
            attempts: 16,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 600_000,
            workers: Resources {
                ram_bytes: case.peak.ram_bytes + case.jobs.ram_bytes,
                ..case.peak
            },
        },
        |artifact| case.policy.policy(artifact),
    )
    .unwrap();
    assert!(recovered.unresolved_attempts().is_empty());
    assert!(recovered.unresolved_workspaces().is_empty());
    assert_eq!(
        recovered.verified_node_bytes(first_job).unwrap().unwrap(),
        first_proof
    );
    case.owner = recovered
        .resume(
            |_| Err("unexpected unresolved attempt".into()),
            || u64::try_from(start.elapsed().as_millis()).unwrap(),
        )
        .unwrap();
    let now = u64::try_from(start.elapsed().as_millis()).unwrap();
    case.owner
        .attach(case.selection.root().id(), [7; 32], 600_000, now)
        .unwrap();
    assert!(!case.owner.ready().unwrap().contains(&first_job));
    assert!(case.owner.begin_verification(failed_lease, now).is_err());
    case.launches =
        LaunchStore::open(&case.bootstrap.launches, LaunchLimits { records: 16 }).unwrap();

    let replacement = case.out.join("replacement");
    fs::create_dir(&replacement).unwrap();
    let scratch = replacement.join("scratch");
    fs::create_dir(&scratch).unwrap();
    let unit_digest =
        process::configuration_digest(replacement.as_os_str().as_encoded_bytes()).unwrap();
    let unit = format!(
        "lattica-v2-multi-persistent-{}.service",
        unit_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut budget = case.budget.clone();
    budget["unit"] = json!(unit);
    budget["host"]["scratch_path"] = json!(scratch);
    budget["host"]["scratch_device"] = json!(fs::metadata(&scratch).unwrap().dev());
    budget["startup_guard"] = json!(replacement.join("startup"));
    write(&replacement.join("budget.json"), &budget);
    let expected: Value =
        serde_json::from_slice(&fs::read(case.fixture.join("expected.json")).unwrap()).unwrap();
    let config = Config::from_assignment(
        case.bootstrap.registry.clone(),
        case.selection.root().pin(),
        case.bootstrap.chain,
        case.bootstrap.executable,
        process::configuration_digest(
            &serde_json::to_vec(&json!({"expected":expected,"assignment":budget})).unwrap(),
        )
        .unwrap(),
        &budget,
    )
    .unwrap();
    case.worker =
        ProcessWorker::prepare(&mut case.owner, config, WorkerId(1), WorkerId(2), now).unwrap();
    assert_ne!(case.worker.execution_digest().unwrap(), first_execution);
    let intent = Intent {
        schema_version: 1,
        unit: unit.clone(),
        executable: case.bootstrap.executable,
        arguments: case
            .arguments
            .iter()
            .map(|a| a.to_str().unwrap().to_owned())
            .collect(),
        assignment: budget,
    };
    startup::create(&replacement.join("startup"), &intent).unwrap();
    startup::authorize(
        &replacement.join("startup"),
        &intent,
        case.worker.execution_digest().unwrap(),
    )
    .unwrap();
    let log = fs::File::create(replacement.join("worker.log")).unwrap();
    let mut command = Command::new("/usr/bin/systemd-run");
    let substitutions = [
        ("--unit=", unit.clone()),
        ("--setenv=LATTICA_V2_ACCOUNTING_UNIT=", unit.clone()),
        (
            "--setenv=LATTICA_V2_WORKER_BUDGET=",
            replacement.join("budget.json").display().to_string(),
        ),
        ("--setenv=LATTICA_SPILL_DIR=", scratch.display().to_string()),
    ];
    for argument in &case.launch_arguments {
        if let Some((prefix, value)) = substitutions
            .iter()
            .find(|(prefix, _)| argument.to_str().is_some_and(|a| a.starts_with(prefix)))
        {
            command.arg(format!("{prefix}{value}"));
        } else {
            command.arg(argument);
        }
    }
    command
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    case.worker
        .start_supervised(command, &unit, &case.arguments)
        .unwrap();
    let replacement_started_ms = case.now();
    let replacement_pid = case.worker.pid().unwrap();
    assert_ne!(first_pid, replacement_pid);
    assert!(replacement_started_ms >= reconciled_ms);
    let mut records = vec![first_record];
    while records.len() < 4 {
        let (_, _, record) = case.prove();
        records.push(record);
    }
    let now = case.now();
    assert!(case.owner.begin_verification(failed_lease, now).is_err());
    assert_eq!(
        case.owner.verified_node_bytes(first_job).unwrap().unwrap(),
        first_proof
    );
    write(
        &replacement.join("worker-observations.json"),
        &observe(&case.worker),
    );
    case.worker.close(&mut case.owner, now).unwrap();
    assert_eq!(case.owner.resource_use().unwrap(), Resources::default());
    let fence = startup::reconcile(&replacement.join("startup"), &intent).unwrap();
    assert!(fence.future_start_fenced && fence.process_and_service_quiescent);
    let text = fs::read_to_string(replacement.join("worker.log")).unwrap();
    let receipt: Value = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["event"] == "typed_gpu_work_complete")
        .unwrap();
    assert_eq!(receipt["backend"], "cuda");
    assert_eq!(receipt["recursive_proofs"], 3);
    for key in [
        "live_bytes",
        "allocations",
        "modules",
        "pending_commands",
        "public_programs",
        "public_program_bytes",
    ] {
        assert_eq!(receipt["cuda"][key], 0, "{key}");
    }
    let all_reports = [reports(&old_log), reports(&replacement.join("worker.log"))].concat();
    assert_eq!(
        all_reports
            .iter()
            .filter(|r| r["capabilities"]["scope"] == "proof_request")
            .count(),
        4
    );
    for report in &all_reports {
        assert_eq!(report["succeeded"], true);
        assert_eq!(report["stage_coverage_complete"], true);
        assert_eq!(report["observation_errors"], 0);
        assert_eq!(report["policy"], "gpu_required");
        assert!(report["capabilities"]["stages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|stage| stage["backend"] == "cuda"));
    }
    write(
        &case.out.join("recovery-result.json"),
        &json!({
            "status":"passed", "first_pid":first_pid, "replacement_pid":replacement_pid,
            "interrupted_after_cuda_preprocessing":true, "signal":"SIGKILL", "accepted_before_failure":1,
            "fresh_proofs_after_recovery":3, "independent_cpu_verified":4, "tampered_statements_rejected":4,
            "retained_node_reverified_from_journal":true, "cached_node_unchanged":true,
            "old_attempt_and_launch_rejected":true, "fresh_execution_digest":true,
            "premature_replacement_rejected":true, "reservations_retained_through_socket_failure":true,
            "reconciled_exit_ms":reconciled_ms, "replacement_started_ms":replacement_started_ms,
            "original_dispatch_window_ms":150_000, "original_candidate_deadline_ms":600_000,
            "observed_exit":true, "workspace_released":true, "replacement_retirement":receipt,
            "jobs":records, "seconds_including_recovery":case.start.elapsed().as_secs_f64(),
            "completed_stage_reports":all_reports.len(), "full_host_node_recovery_qualified":false,
            "timing_approved":false, "production_ready":false,
        }),
    );
}
