//! The unchanged native ABI, inherited socket, journal and single-use launches
//! carry real mixed-wallet jobs through a supervised CUDA worker. The parent
//! has no GPU runtime and independently verifies every returned proof.
use super::*;
use crate::block_v2::{
    codec,
    execution::{
        artifact_store::{ArtifactStore, StoreLimits},
        dag::{Completion, Limits, WorkerId},
        job::{RegistryPin, VerifiedNode, VerifiedWallet},
        journal::{DurableDag, JournalLimits},
        launch::{LaunchLimits, LaunchStore},
        resources::Resources,
        selection::{PublicInput, Selection},
        worker::typed::process::ProcessWorker,
    },
    typed_recursive::Policy as WalletPolicy,
};
use p3_field::PrimeCharacteristicRing;
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
    time::Instant,
};

#[test]
#[ignore = "child of the bounded native CUDA integration fixture"]
fn native_cuda_service_child() {
    let bootstrap = PathBuf::from(std::env::var_os("LATTICA_CUDA_BOOTSTRAP").unwrap());
    let bytes = fs::read(&bootstrap).unwrap();
    assert!(bytes.capacity() <= MAX_BOOTSTRAP_BYTES + 1);
    let before = crate::proving::cpu_witness_oracle_calls();
    let mut completed = u64::MAX;
    let rc = unsafe {
        crate::native_gpu::lattica_gpu_public_worker_serve(
            0,
            bytes.as_ptr(),
            bytes.len(),
            &mut completed,
        )
    };
    assert_eq!(rc, 0, "native CUDA service rejected");
    assert_eq!(completed, 4);
    assert_eq!(crate::proving::cpu_witness_oracle_calls(), before);
    // The ABI borrowed stdin; native service duplication must leave it open.
    assert!(unsafe { libc::fcntl(0, libc::F_GETFD) } >= 0);
    let membership = fs::read_to_string("/proc/self/cgroup").unwrap();
    let group =
        PathBuf::from("/sys/fs/cgroup").join(membership.trim().strip_prefix("0::/").unwrap());
    let mut observations = serde_json::Map::new();
    for key in [
        "memory.max",
        "memory.swap.max",
        "memory.peak",
        "memory.events",
        "cpu.max",
        "pids.max",
    ] {
        observations.insert(
            key.to_owned(),
            json!(fs::read_to_string(group.join(key)).unwrap().trim()),
        );
    }
    fs::write(
        bootstrap.parent().unwrap().join("worker-observations.json"),
        serde_json::to_vec_pretty(&observations).unwrap(),
    )
    .unwrap();
    eprintln!(
        "native_cuda_completed jobs={completed} cpu_witness_oracles=0 descriptor_preserved=true"
    );
}

#[test]
#[ignore = "pinned mixed-wallet fixture and isolated systemd fleet; run serially"]
fn native_cuda_service_proves_mixed_jobs_and_releases_after_observed_exit() {
    let out = PathBuf::from(std::env::var_os("LATTICA_CUDA_WORKER_TEST_DIR").unwrap());
    let fixture = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let expected: Value =
        serde_json::from_slice(&fs::read(fixture.join("expected.json")).unwrap()).unwrap();
    let chain = serde_json::from_value(expected["chain"].clone()).unwrap();
    let registry = Registry::<12> {
        height: serde_json::from_slice(&fs::read(fixture.join("height.json")).unwrap()).unwrap(),
        caps: std::array::from_fn(|i| {
            let bytes = fs::read(fixture.join(format!("key.{}", i + 1))).unwrap();
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    let approved = serde_json::from_value(expected["profile"].clone()).unwrap();
    let pin = RegistryPin::new_typed(&registry, approved).unwrap();
    assert_eq!(registry.height, 1 << 18);
    let policies = [
        WalletPolicy::JoinSplit,
        WalletPolicy::Htlc {
            expected_height: expected["block_height"].as_u64().unwrap(),
        },
        WalletPolicy::Htlc {
            expected_height: expected["block_height"].as_u64().unwrap(),
        },
        WalletPolicy::Issuance {
            authorized_mint: expected["authorized_issuance"]["3"].as_u64().unwrap(),
        },
    ];
    let inputs: Vec<_> = policies
        .iter()
        .enumerate()
        .map(|(i, &policy)| {
            let bytes = fs::read(fixture.join(format!("wallet.{i}"))).unwrap();
            let wallet =
                VerifiedWallet::verify_typed(pin, &registry, chain, policy, &bytes).unwrap();
            PublicInput::new(wallet, bytes).unwrap()
        })
        .collect();
    let selection = Selection::new(pin, chain, &inputs).unwrap();
    assert_eq!(selection.jobs().len(), 4);
    let policy = PolicyContext::new(
        [8; 32],
        inputs
            .iter()
            .zip(policies)
            .map(|(input, policy)| (input.ticket().artifact(), policy))
            .collect(),
    )
    .unwrap();
    let binary = std::env::current_exe().unwrap();
    let bootstrap = Bootstrap::new(
        registry,
        approved,
        chain,
        transport::image_fingerprint(&binary).unwrap(),
        out.join("launches"),
        &policy,
    )
    .unwrap();
    let mut budget = assignment();
    let unit = std::env::var("LATTICA_CUDA_WORKER_UNIT").unwrap();
    let slice = std::env::var("LATTICA_CUDA_WORKER_SLICE").unwrap();
    let scratch = out.join("scratch");
    fs::create_dir(&scratch).unwrap();
    budget["unit"] = json!(unit);
    budget["slice"] = json!(slice);
    budget["gpu"]["version"] = json!(1);
    budget["gpu"]["uuid"] = json!(std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap());
    budget["cpu"]["version"] = json!(1);
    budget["cpu"]["allowed_cpus"] = json!([0, 1, 2, 3]);
    budget["cpu"]["quota_percent"] = json!("400%");
    budget["host"]["version"] = json!(1);
    budget["host"]["fleet_bytes"] = json!(4u64 << 30);
    budget["host"]["scratch_path"] = json!(scratch);
    budget["host"]["scratch_device"] = json!(fs::metadata(&scratch).unwrap().dev());
    fs::write(
        out.join("budget.json"),
        serde_json::to_vec_pretty(&budget).unwrap(),
    )
    .unwrap();
    fs::write(out.join("bootstrap.json"), bootstrap.encode().unwrap()).unwrap();
    let (peak, jobs) = worker_budget::resources(&budget).unwrap();
    let store = ArtifactStore::create(
        &out.join("artifacts"),
        StoreLimits {
            bytes: 32 << 20,
            entries: 64,
        },
    )
    .unwrap();
    let mut owner = DurableDag::create(
        &out.join("journal"),
        JournalLimits {
            snapshot_bytes: 1 << 20,
        },
        store,
        pin,
        chain,
        1,
        Limits {
            jobs: 32,
            candidates: 4,
            attempts: 16,
            artifact_bytes: 32 << 20,
            recovery_window_ms: 600_000,
            workers: Resources {
                ram_bytes: peak.ram_bytes + jobs.ram_bytes,
                ..peak
            },
        },
    )
    .unwrap();
    selection.admit(&mut owner, 0).unwrap();
    owner
        .attach(selection.root().id(), [7; 32], 600_000, 0)
        .unwrap();
    let mut worker = ProcessWorker::prepare(
        &mut owner,
        bootstrap.config(&budget).unwrap(),
        WorkerId(1),
        WorkerId(2),
        0,
    )
    .unwrap();
    let mut launches =
        LaunchStore::create(&bootstrap.launches, LaunchLimits { records: 16 }).unwrap();
    let args: Vec<OsString> = [
        "--exact",
        "block_v2::execution::native_worker::cuda::tests::integration::native_cuda_service_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(OsString::from)
    .into();
    let log = fs::File::create(out.join("worker.log")).unwrap();
    let mut launch = Command::new("/usr/bin/systemd-run");
    launch
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
            "--property=AllowedCPUs=0-3",
            "--property=TasksMax=96",
            "--property=RuntimeMaxSec=600",
            "--property=KillMode=control-group",
            "--property=LimitCORE=0",
            "--property=LimitSTACK=8M",
        ])
        .arg(format!("--unit={unit}"))
        .arg(format!("--slice={slice}"))
        .arg(format!(
            "--property=BindsTo={}",
            std::env::var("LATTICA_CUDA_WORKER_OWNER").unwrap()
        ));
    for (name, value) in [
        (
            "LATTICA_CUDA_BOOTSTRAP",
            out.join("bootstrap.json").display().to_string(),
        ),
        (
            "LATTICA_V2_WORKER_BUDGET",
            out.join("budget.json").display().to_string(),
        ),
        ("LATTICA_V2_ACCOUNTING_UNIT", unit.clone()),
        (
            "LATTICA_GPU_DEVICE_UUID",
            budget["gpu"]["uuid"].as_str().unwrap().to_owned(),
        ),
        ("LATTICA_V2_GPU_MANAGED_BYTES", (7u64 << 30).to_string()),
        ("LATTICA_V2_GPU_CONTEXT_BYTES", (4u64 << 30).to_string()),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", (3u64 << 30).to_string()),
        ("LATTICA_SPILL_MAX_BYTES", (1u64 << 30).to_string()),
        ("LATTICA_SPILL_DIR", scratch.display().to_string()),
        ("RAYON_NUM_THREADS", "4".to_owned()),
        ("LATTICA_PROVING_POLICY", "gpu-required".to_owned()),
        ("LATTICA_PROVING_REPORT", "1".to_owned()),
        ("LD_LIBRARY_PATH", std::env::var("LD_LIBRARY_PATH").unwrap()),
    ] {
        launch.arg(format!("--setenv={name}={value}"));
    }
    launch
        .arg(&binary)
        .args(&args)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    let start = Instant::now();
    let now = || u64::try_from(start.elapsed().as_millis()).unwrap();
    worker.start_supervised(launch, &unit, &args).unwrap();
    fs::write(
        out.join("service-identity.json"),
        serde_json::to_vec_pretty(worker.service_identity().unwrap()).unwrap(),
    )
    .unwrap();
    worker.heartbeat().unwrap();
    let mut records = vec![];
    while records.len() < 4 {
        let ready = owner.ready().unwrap();
        assert!(!ready.is_empty());
        let lease = owner
            .lease(ready[0], WorkerId(2), jobs, 180_000, 180_000, now())
            .unwrap();
        let task = worker.task(&mut owner, lease, now()).unwrap();
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
        let elapsed = proving.elapsed().as_secs_f64();
        let revoked = launches.revoke(lease).unwrap();
        assert!(launches.try_idle(&revoked).unwrap().is_some());
        let output = completed.reconcile(&mut owner, now()).unwrap();
        let job = owner.begin_verification(lease, now()).unwrap();
        let verified =
            VerifiedNode::verify_typed(&job, &bootstrap.registry, output.bytes()).unwrap();
        let mut altered = codec::decode_node(output.bytes()).unwrap();
        altered.public[crate::block_v2::machine::programs::COUNT] += crate::config::Val::ONE;
        assert!(VerifiedNode::verify_typed(
            &job,
            &bootstrap.registry,
            &codec::encode_node(&altered).unwrap()
        )
        .is_err());
        let bytes = output.bytes().to_vec();
        if job.id() == selection.root().id() {
            fs::write(out.join("root.bin"), &bytes).unwrap();
        }
        records.push(json!({"mode": job.operation().proof_mode(), "seconds": elapsed}));
        assert_eq!(
            owner
                .finish_verification(lease, Some((verified, bytes)), now())
                .unwrap(),
            Completion::Accepted
        );
        assert!(
            !worker.retirement_requested(),
            "worker requested retirement; do not dispatch again"
        );
        assert_eq!(
            owner.resource_use().unwrap(),
            Resources { threads: 0, ..peak }
        );
    }
    worker.close(&mut owner, now()).unwrap();
    assert_eq!(owner.resource_use().unwrap(), Resources::default());
    let observations: Value =
        serde_json::from_slice(&fs::read(out.join("worker-observations.json")).unwrap()).unwrap();
    assert_eq!(observations["memory.max"], (3u64 << 30).to_string());
    assert_eq!(observations["memory.swap.max"], "0");
    assert!(
        observations["memory.peak"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            <= 3u64 << 30
    );
    let log = fs::read_to_string(out.join("worker.log")).unwrap();
    assert!(log
        .contains("native_cuda_completed jobs=4 cpu_witness_oracles=0 descriptor_preserved=true"));
    let shutdown: Value = serde_json::from_str(
        log.lines()
            .find_map(|line| line.strip_prefix("typed_cuda_shutdown "))
            .unwrap(),
    )
    .unwrap();
    for key in [
        "live_bytes",
        "allocations",
        "modules",
        "pending_commands",
        "public_programs",
        "public_program_bytes",
    ] {
        assert_eq!(shutdown[key], 0, "{key}");
    }
    fs::write(
        out.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "jobs": records, "seconds_including_startup_shutdown": start.elapsed().as_secs_f64(),
            "independent_parent_verified": 4, "altered_statements_rejected": 4,
            "observed_exit": true, "workspace_released": true, "shutdown": shutdown,
        }))
        .unwrap(),
    )
    .unwrap();
}
