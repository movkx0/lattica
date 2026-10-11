//! C service qualification. The small fixture registers only Empty proofs;
//! full-size finalizer tests use all twelve archived keys and verified inputs.
use super::*;
use crate::block_v2::execution::{
    artifact_store::{ArtifactStore, StoreLimits},
    dag::{Completion, Limits, WorkerId},
    job::{test_support::typed_wallet_for, Job, VerifiedNode},
    journal::{DurableDag, JournalLimits},
    launch::{LaunchLimits, LaunchStore},
    resources::Resources,
    worker::typed::process::ProcessWorker,
    worker_budget,
};
use crate::block_v2::{codec, gpu_hash, machine::programs, recursive::CacheStats};
use p3_field::PrimeCharacteristicRing;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

struct Fixture {
    directory: PathBuf,
    bootstrap: Bootstrap,
    assignment: serde_json::Value,
    environment: BTreeMap<String, String>,
    unit: String,
    binary: PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Self {
        let root = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
        let fixture: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("fixture.json")).unwrap()).unwrap();
        let registry: Registry<12> = serde_json::from_value(fixture["registry"].clone()).unwrap();
        let profile = serde_json::from_value(fixture["profile"].clone()).unwrap();
        Self::with_registry(case, registry, profile, [9; 32])
    }

    fn with_registry(
        case: &str,
        registry: Registry<12>,
        profile: [u8; 32],
        chain: [u8; 32],
    ) -> Self {
        assert!(!gpu_hash::is_enabled());
        let root = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_DIR").unwrap());
        let directory = root.join(case);
        fs::create_dir(&directory).unwrap();
        let binary = PathBuf::from(std::env::var_os("LATTICA_NATIVE_SERVICE_BINARY").unwrap());
        let digest =
            process::configuration_digest(directory.as_os_str().as_encoded_bytes()).unwrap();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let unit = format!("lattica-v2-multi-persistent-{hex}.service");
        let mut assignment: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("budget.json")).unwrap()).unwrap();
        assignment["unit"] = serde_json::json!(unit);
        fs::write(
            directory.join("budget.json"),
            serde_json::to_vec_pretty(&assignment).unwrap(),
        )
        .unwrap();
        let mut environment: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read(root.join("environment.json")).unwrap()).unwrap();
        environment.insert(
            "LATTICA_V2_WORKER_BUDGET".into(),
            directory.join("budget.json").to_str().unwrap().into(),
        );
        environment.insert("LATTICA_V2_ACCOUNTING_UNIT".into(), unit.clone());
        let bootstrap = Bootstrap::new(
            registry,
            profile,
            chain,
            transport::image_fingerprint(&binary).unwrap(),
            directory.join("launches"),
            &PolicyContext::new([8; 32], vec![]).unwrap(),
        )
        .unwrap();
        Self {
            directory,
            bootstrap,
            assignment,
            environment,
            unit,
            binary,
        }
    }

    fn owner(&self) -> (DurableDag, ProcessWorker, LaunchStore) {
        let (peak, jobs) = worker_budget::resources(&self.assignment).unwrap();
        let store = ArtifactStore::create(
            &self.directory.join("artifacts"),
            StoreLimits {
                bytes: 32 << 20,
                entries: 64,
            },
        )
        .unwrap();
        let mut owner = DurableDag::create(
            &self.directory.join("journal"),
            JournalLimits {
                snapshot_bytes: 1 << 20,
            },
            store,
            self.bootstrap.validate().unwrap().0.pin(),
            self.bootstrap.chain,
            1,
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
            },
        )
        .unwrap();
        let worker = ProcessWorker::prepare(
            &mut owner,
            self.bootstrap.config(&self.assignment).unwrap(),
            WorkerId(1),
            WorkerId(2),
            0,
        )
        .unwrap();
        let launches =
            LaunchStore::create(&self.bootstrap.launches, LaunchLimits { records: 16 }).unwrap();
        (owner, worker, launches)
    }

    fn launcher(&self, bootstrap: &Bootstrap, expected: &str) -> (Command, Vec<OsString>) {
        let path = self.directory.join("bootstrap.json");
        fs::write(&path, bootstrap.encode().unwrap()).unwrap();
        let args = vec![path.into_os_string(), OsString::from(expected)];
        let cpus = self.assignment["cpu"]["allowed_cpus"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args([
                "--user",
                "--pipe",
                "--wait",
                "--collect",
                "--quiet",
                "--service-type=exec",
                "--property=MemoryMax=3G",
                "--property=MemorySwapMax=0",
                "--property=CPUQuota=400%",
                "--property=RuntimeMaxSec=180",
                "--property=KillMode=control-group",
                "--property=LimitCORE=0",
            ])
            .arg(format!("--unit={}", self.unit))
            .arg(format!(
                "--slice={}",
                self.assignment["slice"].as_str().unwrap()
            ))
            .arg(format!("--property=AllowedCPUs={cpus}"))
            .arg(format!(
                "--property=BindsTo={}",
                std::env::var("LATTICA_NATIVE_SERVICE_OWNER").unwrap()
            ));
        for (name, value) in &self.environment {
            command.arg(format!("--setenv={name}={value}"));
        }
        let log = fs::File::create(self.directory.join("worker.log")).unwrap();
        command
            .arg(&self.binary)
            .args(&args)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        (command, args)
    }

    fn check_memory_reports(&self, jobs: usize) {
        let log = fs::read_to_string(self.directory.join("worker.log")).unwrap();
        let plans: Vec<serde_json::Value> = log
            .lines()
            .filter_map(|line| line.strip_prefix("bounded_gpu_lde_plan "))
            .map(|json| serde_json::from_str(json).unwrap())
            .collect();
        let assigned = self.assignment["host"]["worker_bytes"].as_u64().unwrap();
        let expected = assigned
            - crate::block_v2::execution::worker::typed::storage::HOST_BYTES
            - crate::block_v2::execution::worker::typed::storage::INPUT_HOST_BYTES
            - crate::block_v2::typed_recursive::storage::SESSION_HOST_BYTES;
        let partitions: Vec<serde_json::Value> = log
            .lines()
            .filter_map(|line| line.strip_prefix("bounded_registered_host_budget "))
            .map(|json| serde_json::from_str(json).unwrap())
            .collect();
        assert_eq!(partitions.len(), 1);
        let partition = &partitions[0];
        assert_eq!(partition["schema"], "lattica-registered-host-budget-v1");
        assert_eq!(partition["total_host_bytes"].as_u64(), Some(expected));
        let reserved = partition["reserved_host_bytes"].as_u64().unwrap();
        let pcs = partition["pcs_host_bytes"].as_u64().unwrap();
        assert!(reserved > 0 && pcs > 0);
        assert_eq!(reserved.checked_add(pcs), Some(expected));
        assert!(!plans.is_empty());
        assert!(plans
            .iter()
            .all(|plan| plan["host_budget_bytes"].as_u64() == Some(pcs)));
        eprintln!("native_worker_input_reservation assigned_bytes={assigned} decoded_input_bytes={} active_host_bytes={expected} reserved_host_bytes={reserved} pcs_host_bytes={pcs} lde_plans={}", crate::block_v2::execution::worker::typed::storage::INPUT_HOST_BYTES, plans.len());
        let reports: Vec<serde_json::Value> = fs::read_to_string(self.directory.join("worker.log"))
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix("typed_gpu_memory "))
            .map(|json| serde_json::from_str(json).unwrap())
            .collect();
        assert_eq!(reports.len(), jobs + 1);
        let identity: serde_json::Value = serde_json::from_slice(
            &fs::read(self.directory.join("service-identity.json")).unwrap(),
        )
        .unwrap();
        let mut previous_end = None;
        let mut cumulative_peak = 0;
        for (index, report) in reports.iter().enumerate() {
            assert_eq!(report["version"], 1);
            assert_eq!(report["pid"], identity["pid"]);
            let memory = &report["managed"];
            let number = |key| memory[key].as_u64().unwrap();
            let start = number("start_live_bytes");
            let end = number("end_live_bytes");
            let peak = number("peak_bytes");
            assert!(start <= peak && end <= peak);
            assert!(peak <= number("managed_limit_bytes"));
            assert_eq!(
                memory["managed_limit_bytes"],
                self.assignment["gpu"]["managed_bytes"]
            );
            assert!(number("max_new_allocation_bytes") <= number("allocation_limit_bytes"));
            assert!(
                number("allocation_limit_bytes")
                    <= self.assignment["gpu"]["max_allocation_bytes"]
                        .as_u64()
                        .unwrap()
            );
            assert!(number("retained_tree_bytes") + number("device_matrix_bytes") <= end);
            if let Some(previous_end) = previous_end {
                assert_eq!(
                    start, previous_end,
                    "cache stays charged across idle boundaries"
                );
                assert_eq!(number("cumulative_peak_bytes"), cumulative_peak.max(peak));
            }
            cumulative_peak = number("cumulative_peak_bytes");
            assert!(cumulative_peak >= peak);
            previous_end = Some(end);
            if index < jobs {
                assert_eq!(report["boundary"], "job_drained");
                assert_eq!(report["job_index"], index);
                assert!(number("allocations") > 0);
                assert!(number("retained_trees") > 0);
                assert!(number("device_matrices") > 0);
            } else {
                assert_eq!(report["boundary"], "shutdown");
                assert_eq!(report["completed_jobs"], jobs);
                assert_eq!(
                    end, 0,
                    "shutdown must release the entire managed allocation pool"
                );
                assert_eq!(number("retained_trees"), 0);
                assert_eq!(number("device_matrices"), 0);
            }
        }
        fs::write(
            self.directory.join("gpu-memory.json"),
            serde_json::to_vec_pretty(&reports).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "C service Empty jobs in an isolated capped GPU fleet; CPU verifies results"]
fn native_service_executes_pinned_jobs_and_releases_after_exit() {
    let f = Fixture::new("jobs");
    let (mut owner, mut worker, mut launches) = f.owner();
    let pin = f.bootstrap.validate().unwrap().0.pin();
    // A test-only candidate anchor makes the real Empty jobs schedulable.
    // No synthetic wallet bytes ever cross the worker socket.
    let wallet = typed_wallet_for(pin, 0, 1, &[1]);
    let mut root = Job::typed_pair(0, wallet, None).unwrap();
    owner
        .admit(root.clone(), vec![vec![1], vec![1]], 0)
        .unwrap();
    let mut empty_jobs = Vec::new();
    for level in 1..=5 {
        let empty = Job::empty(pin, f.bootstrap.chain, 1 << level, level).unwrap();
        owner.admit(empty.clone(), vec![], 0).unwrap();
        root = Job::merge(&root, &empty).unwrap();
        owner.admit(root.clone(), vec![], 0).unwrap();
        if level == 1 || level == 5 {
            empty_jobs.push(empty);
        }
    }
    owner.attach(root.id(), [7; 32], 1000, 0).unwrap();
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
    let identity = worker.service_identity().unwrap();
    assert!(identity.cgroup().ends_with(&f.unit));
    fs::write(
        f.directory.join("service-identity.json"),
        serde_json::to_vec_pretty(identity).unwrap(),
    )
    .unwrap();
    worker.heartbeat().unwrap();
    let (peak, jobs) = worker_budget::resources(&f.assignment).unwrap();
    for (index, job) in empty_jobs.iter().enumerate() {
        let now = index as u64 + 1;
        if index == 1 {
            let before = worker.execution_digest().unwrap();
            worker
                .replace_context(&PolicyContext::new([6; 32], vec![]).unwrap())
                .unwrap();
            assert_ne!(before, worker.execution_digest().unwrap());
        }
        let lease = owner
            .lease(job.id(), WorkerId(2), jobs, 1, 1000, now)
            .unwrap();
        let task = worker.task(&mut owner, lease, now).unwrap();
        let token = launches
            .issue_bound(
                &mut owner,
                lease,
                &task.request().unwrap(),
                worker.execution_digest().unwrap(),
            )
            .unwrap();
        let complete = worker.execute(&token, task).unwrap();
        let revoked = launches.revoke(lease).unwrap();
        assert!(launches.try_idle(&revoked).unwrap().is_some());
        let output = complete.reconcile(&mut owner, now).unwrap();
        let expected = owner.begin_verification(lease, now).unwrap();
        let verified =
            VerifiedNode::verify_typed(&expected, &f.bootstrap.registry, output.bytes()).unwrap();
        fs::write(
            f.directory
                .join(format!("proof-{}.bin", job.expected().level)),
            output.bytes(),
        )
        .unwrap();
        let mut altered = codec::decode_node(output.bytes()).unwrap();
        altered.public[programs::COUNT] += crate::config::Val::ONE;
        assert!(VerifiedNode::verify_typed(
            &expected,
            &f.bootstrap.registry,
            &codec::encode_node(&altered).unwrap()
        )
        .is_err());
        assert_eq!(
            owner
                .finish_verification(lease, Some((verified, output.bytes().to_vec())), now)
                .unwrap(),
            Completion::Accepted
        );
        assert_eq!(
            owner.resource_use().unwrap(),
            Resources { threads: 0, ..peak }
        );
    }
    assert_eq!(worker.stats().unwrap(), CacheStats { setups: 1, hits: 1 });
    worker.close(&mut owner, 3).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(fs::read_to_string(f.directory.join("worker.log"))
        .unwrap()
        .contains("rc=0 completed=2 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"));
    assert!(!gpu_hash::is_enabled());
    f.check_memory_reports(2);
    println!("native_public_service_verified proofs=2 rows=2048 levels=1,5 cpu_verified=true altered_rejected=2 setups=1 hits=1 context_rebound=true observed_exit=true reservations_released=true");
}

#[test]
#[ignore = "full-size C worker finalizers with archived pair/merge inputs and warm preprocessing reuse"]
fn native_service_full_size_finalizers_reuse_cache_and_verify_independently() {
    use crate::block_v2::{execution::job::VerifiedWallet, typed_fixture, typed_recursive::Policy};

    let fixture = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let read = |path: &Path| {
        assert!(fs::symlink_metadata(path).unwrap().is_file());
        assert!(
            fs::metadata(path).unwrap().len() <= crate::block_v2::profile::MAX_PROOF_BYTES as u64
        );
        fs::read(path).unwrap()
    };
    let registry = Registry::<12> {
        height: serde_json::from_slice(&read(&fixture.join("height.json"))).unwrap(),
        caps: std::array::from_fn(|index| {
            let bytes = read(&fixture.join(format!("key.{}", index + 1)));
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    assert_eq!(registry.height, 1 << 18);
    let profile = registry.id().unwrap();
    let f = Fixture::with_registry("full-size", registry, profile, typed_fixture::CHAIN);
    let (mut owner, mut worker, mut launches) = f.owner();
    let pin = f.bootstrap.validate().unwrap().0.pin();
    let wallet_bytes = [0, 4].map(|i| read(&fixture.join(format!("wallet.{i}"))));
    let wallets = wallet_bytes.each_ref().map(|bytes| {
        VerifiedWallet::verify_typed(
            pin,
            &f.bootstrap.registry,
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
        let verified = VerifiedNode::verify_typed(job, &f.bootstrap.registry, &bytes).unwrap();
        owner.cache_node(verified, bytes, 0).unwrap();
    }
    let jobs = [
        Job::finalize(&pair).unwrap(),
        Job::finalize(&merged).unwrap(),
    ];
    // Distinct dependency DAGs reach the same independently derived terminal
    // statement. Both must be executed; a cached result cannot stand in for
    // the second proof or its private randomness.
    assert_ne!(jobs[0].id(), jobs[1].id());
    assert_eq!(jobs[0].expected_public(), jobs[1].expected_public());
    for (index, job) in jobs.iter().enumerate() {
        owner.admit(job.clone(), vec![], 0).unwrap();
        owner
            .attach(job.id(), [index as u8 + 1; 32], 1000, 0)
            .unwrap();
    }
    let (launcher, args) = f.launcher(&f.bootstrap, "ok");
    worker.start_supervised(launcher, &f.unit, &args).unwrap();
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
    let (peak, job_resources) = worker_budget::resources(&f.assignment).unwrap();
    let mut outputs = Vec::new();
    let mut timings = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        let now = index as u64 + 1;
        let lease = owner
            .lease(job.id(), WorkerId(2), job_resources, 1, 1000, now)
            .unwrap();
        let task = worker.task(&mut owner, lease, now).unwrap();
        let token = launches
            .issue_bound(
                &mut owner,
                lease,
                &task.request().unwrap(),
                worker.execution_digest().unwrap(),
            )
            .unwrap();
        let start = std::time::Instant::now();
        let complete = worker.execute(&token, task).unwrap();
        timings.push(start.elapsed().as_secs_f64());
        let revoked = launches.revoke(lease).unwrap();
        assert!(launches.try_idle(&revoked).unwrap().is_some());
        let output = complete.reconcile(&mut owner, now).unwrap();
        let expected = owner.begin_verification(lease, now).unwrap();
        // The coordinator has no GPU context; it independently verifies every
        // response before accepting the artifact into the durable DAG.
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
        fs::write(f.directory.join(format!("proof-{index}.bin")), &bytes).unwrap();
        assert_eq!(
            owner
                .finish_verification(lease, Some((verified, bytes.clone())), now)
                .unwrap(),
            Completion::Accepted
        );
        outputs.push(bytes);
        assert_eq!(
            worker.stats().unwrap(),
            CacheStats {
                setups: 1,
                hits: index as u64
            }
        );
        assert_eq!(
            owner.resource_use().unwrap(),
            Resources { threads: 0, ..peak }
        );
    }
    assert_ne!(
        outputs[0], outputs[1],
        "fresh private randomness must not replay proof bytes"
    );
    assert_eq!(worker.stats().unwrap(), CacheStats { setups: 1, hits: 1 });
    worker.close(&mut owner, 3).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    assert!(fs::read_to_string(f.directory.join("worker.log"))
        .unwrap()
        .contains("rc=0 completed=2 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"));
    for bytes in &outputs {
        VerifiedNode::verify_typed(&jobs[0], &f.bootstrap.registry, bytes).unwrap();
    }
    fs::write(
        f.directory.join("timings.json"),
        serde_json::to_vec_pretty(&timings).unwrap(),
    )
    .unwrap();
    assert!(!gpu_hash::is_enabled());
    f.check_memory_reports(2);
    println!("native_full_size_finalizers_verified proofs=2 rows=262144 transactions=2 archived_registry=true cpu_verified=true altered_rejected=2 setups=1 hits=1 fresh_proof_bytes=true observed_exit=true reservations_released=true");
}

#[test]
#[ignore = "C service malformed configuration/job/disconnect cleanup under capped GPU admission"]
fn native_service_rejects_and_cleans_up_without_releasing_reservations() {
    for case in [
        "wrong-executable",
        "wrong-configuration",
        "disconnect",
        "malformed-job",
    ] {
        let f = Fixture::new(case);
        let (owner, worker, _launches) = f.owner();
        let reserved = owner.resource_use().unwrap();
        let mut bootstrap = f.bootstrap.clone();
        if case == "wrong-executable" {
            bootstrap.executable[0] ^= 1;
        }
        if case == "wrong-configuration" {
            bootstrap.policy_context = PolicyContext::new([2; 32], vec![]).unwrap().encode();
        }
        let (mut launcher, _) = f.launcher(&bootstrap, "reject");
        let (mut socket, child_socket) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(120)))
            .unwrap();
        let mut child = launcher
            .stdin(Stdio::from(OwnedFd::from(child_socket)))
            .spawn()
            .unwrap();
        drop(launcher);
        if case != "wrong-executable" {
            let hello = worker.session_bytes();
            socket.write_all(&[1]).unwrap();
            socket
                .write_all(&(hello.len() as u64).to_le_bytes())
                .unwrap();
            socket.write_all(hello).unwrap();
            if case != "wrong-configuration" {
                let mut ready = [0; 45];
                socket.read_exact(&mut ready).unwrap();
                assert_eq!(ready[0], 2);
                assert_eq!(u64::from_le_bytes(ready[1..9].try_into().unwrap()), 36);
                assert_eq!(&ready[13..], &worker.execution_digest().unwrap());
                if case == "malformed-job" {
                    socket.write_all(&[3, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
                }
            }
        }
        if case != "disconnect" {
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        }
        drop(socket);
        assert!(child.wait().unwrap().success(), "{case}");
        assert!(
            fs::read_to_string(f.directory.join("worker.log"))
                .unwrap()
                .contains("rc=1 completed=0 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"),
            "{case}"
        );
        assert_eq!(owner.resource_use().unwrap(), reserved);
        println!("native_public_service_rejected case={case} gpu_retired=true reservations_retained=true");
    }
}

#[test]
#[ignore = "requires pinned C service, OpenCL GPU and capped serial service"]
fn native_service_enforces_construction_allowance_before_witness_setup() {
    let mut f = Fixture::new("construction-limit");
    f.assignment["witness_bounds"]["program_host_bytes"] = serde_json::json!(1);
    let bounds: crate::block_v2::machine::gpu_backend::resources::Bounds =
        serde_json::from_value(f.assignment["witness_bounds"].clone()).unwrap();
    f.assignment["witness_reservation"] =
        serde_json::to_value(bounds.reservation(1).unwrap()).unwrap();
    fs::write(
        f.directory.join("budget.json"),
        serde_json::to_vec_pretty(&f.assignment).unwrap(),
    )
    .unwrap();
    let (mut owner, worker, mut launches) = f.owner();
    let pin = f.bootstrap.validate().unwrap().0.pin();
    let wallet = typed_wallet_for(pin, 0, 1, &[1]);
    let anchor = Job::typed_pair(0, wallet, None).unwrap();
    owner
        .admit(anchor.clone(), vec![vec![1], vec![1]], 0)
        .unwrap();
    let empty = Job::empty(pin, f.bootstrap.chain, 2, 1).unwrap();
    owner.admit(empty.clone(), vec![], 0).unwrap();
    let mut root = Job::merge(&anchor, &empty).unwrap();
    owner.admit(root.clone(), vec![], 0).unwrap();
    // The scheduler only attaches a complete depth-six candidate. The
    // additional branches remain metadata; only `empty` reaches the worker.
    for level in 2..=5 {
        let sibling = Job::empty(pin, f.bootstrap.chain, 1 << level, level).unwrap();
        owner.admit(sibling.clone(), vec![], 0).unwrap();
        root = Job::merge(&root, &sibling).unwrap();
        owner.admit(root.clone(), vec![], 0).unwrap();
    }
    owner.attach(root.id(), [7; 32], 1000, 0).unwrap();
    let (_, jobs) = worker_budget::resources(&f.assignment).unwrap();
    let lease = owner
        .lease(empty.id(), WorkerId(2), jobs, 1, 1000, 1)
        .unwrap();
    // This rejection test owns the raw socket and child. Encode the actual
    // scheduler assignment without the ProcessWorker-owned socket/task API.
    let request = crate::block_v2::execution::worker::packet::encode_request(
        &owner.assignment(lease).unwrap(),
    )
    .unwrap();
    let token = launches
        .issue_bound(
            &mut owner,
            lease,
            &request,
            worker.execution_digest().unwrap(),
        )
        .unwrap();
    let token = token.encode().unwrap();
    let mut packet = (token.len() as u64).to_le_bytes().to_vec();
    packet.extend(token);
    packet.extend(request);
    let reserved = owner.resource_use().unwrap();
    let (mut launcher, _) = f.launcher(&f.bootstrap, "reject");
    let (mut socket, child_socket) = UnixStream::pair().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let mut child = launcher
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .spawn()
        .unwrap();
    drop(launcher);
    let hello = worker.session_bytes();
    socket.write_all(&[1]).unwrap();
    socket
        .write_all(&(hello.len() as u64).to_le_bytes())
        .unwrap();
    socket.write_all(hello).unwrap();
    let mut ready = [0; 45];
    socket.read_exact(&mut ready).unwrap();
    assert_eq!(ready[0], 2);
    assert_eq!(&ready[13..], &worker.execution_digest().unwrap());
    socket.write_all(&[3]).unwrap();
    socket
        .write_all(&(packet.len() as u64).to_le_bytes())
        .unwrap();
    socket.write_all(&packet).unwrap();
    let mut byte = [0];
    assert_eq!(socket.read(&mut byte).unwrap(), 0);
    drop(socket);
    assert!(child.wait().unwrap().success());
    let log = fs::read_to_string(f.directory.join("worker.log")).unwrap();
    assert!(log.contains("bounded_program_construction phase=rejected limit_bytes=1 admitted_peak_bytes=0 live_bytes=0 rejected=true"));
    assert!(!log.contains("bounded_gpu_witness_program "));
    assert!(!log.contains("bounded_gpu_lde_plan "));
    assert!(log.contains("rc=1 completed=0 descriptor_preserved=1 gpu_retired=1 shutdown_ok=1"));
    assert_eq!(owner.resource_use().unwrap(), reserved);
    assert!(!gpu_hash::is_enabled());
    println!("native_construction_limit_rejected limit_bytes=1 completed=0 witness_setup=false gpu_retired=true reservations_retained=true");
}
