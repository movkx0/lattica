//! Bounded trusted-local control plane for the persistent public-proof pool.
//! The native controller publishes requests atomically, audits the root in an
//! independent process, then rechecks and commits its native preparation.
use super::*;
use lattica_prover_p3::block_v2::execution::{
    policy_context::PolicyContext,
    pool::{local::LocalProcessEndpoint, PoolCoordinator, WorkerEndpoint},
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};

fn publish_json(path: &Path, value: &impl serde::Serialize) -> Result<(), Error> {
    let temporary = path.with_extension("json.pending");
    write_json(&temporary, value)?;
    if path.exists() {
        return Err("pool output already exists".into());
    }
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(path.parent().ok_or("pool output parent")?)?.sync_all()?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    fixture: PathBuf,
    expected: PathBuf,
    native_host: native::Binding,
    /// Absolute deadline in milliseconds since this service's start. Queueing,
    /// input verification, and proof verification all consume this deadline.
    deadline_ms: u64,
}

pub(super) fn serve(
    plan: &Plan,
    requests: &Path,
    initial: Prepared,
    owner: DurableDag,
    launches: LaunchStore,
    slots: Vec<Slot>,
    out: &Path,
    now: impl Fn() -> u64,
) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(requests)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("pool request directory must be a private local directory".into());
    }
    let binding = plan
        .native_host
        .as_ref()
        .ok_or("pool native authority missing")?;
    let launches = Arc::new(Mutex::new(launches));
    let mut identities = Vec::new();
    let mut endpoints: Vec<Box<dyn WorkerEndpoint>> = Vec::new();
    for slot in slots {
        identities
            .push(json!({"worker":slot.job_worker.0,"pid":slot.worker.pid(),"gpu_uuid":slot.uuid}));
        endpoints.push(Box::new(LocalProcessEndpoint::new(
            slot.worker,
            launches.clone(),
        )?));
    }
    let mut pool = PoolCoordinator::new(owner, initial.registry, endpoints, 300_000)?;
    drop(initial.selection);
    publish_json(
        &out.join("pool-ready.json"),
        &json!({"schema_version":1,
        "backend":"typed_local_pool_v1", "workers":identities,"ready_ms":now(),
        "max_requests":256,"native_application_required":true}),
    )?;
    let mut last_heartbeat = now();
    for sequence in 0..256u32 {
        let request_path = requests.join(format!("{sequence:06}.json"));
        while !request_path.exists() {
            if requests.join("stop").exists() {
                pool.close(now())?;
                publish_json(
                    &out.join("pool-stopped.json"),
                    &json!({"schema_version":1,
                    "completed_requests":sequence,"stopped_ms":now(),"workers_drained":true}),
                )?;
                return Ok(());
            }
            if now().saturating_sub(last_heartbeat) >= 30_000 {
                pool.heartbeat()?;
                last_heartbeat = now();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let meta = std::fs::symlink_metadata(&request_path)?;
        if !meta.file_type().is_file() || meta.len() > 1 << 20 {
            return Err("pool request type or size".into());
        }
        let request: Request = read_json(&request_path)?;
        if request.schema_version != 1
            || !request.fixture.is_absolute()
            || !request.expected.is_absolute()
            || request.deadline_ms <= now()
            || request.deadline_ms.saturating_sub(now()) > 3_600_000
        {
            return Err("pool request version, path, or deadline".into());
        }
        binding.check_pool_session(&request.native_host)?;
        let started = now();
        let prepared = prepare_for_backend(&request.fixture, &request.expected, true)?;
        let head = request.native_host.head_for(&prepared.expected)?;
        let context = PolicyContext::new(head, prepared.policies)?;
        let candidate = pool.submit(
            &prepared.selection,
            context,
            head,
            request.deadline_ms,
            now(),
        )?;
        pool.seal(candidate, head, now())?;
        let result_dir = out.join(format!("candidate-{sequence:06}"));
        std::fs::DirBuilder::new().mode(0o700).create(&result_dir)?;
        publish_json(&result_dir.join("expected.json"), &prepared.expected)?;
        let mut jobs = Vec::new();
        let mut failures = Vec::new();
        let root = loop {
            if requests.join(format!("{sequence:06}.cancel")).exists() {
                pool.retire(candidate, now())?;
                return Err(
                    "native controller cancelled pool candidate; restart after reconciliation"
                        .into(),
                );
            }
            for accepted in pool.step(now())? {
                jobs.push(
                    json!({"job":hex(&accepted.job.to_bytes()),"worker":accepted.worker.0,
                    "elapsed_ms":accepted.elapsed_ms,"proof_bytes":accepted.proof_bytes}),
                );
            }
            for (worker, reason) in pool.take_failures() {
                failures.push(json!({"worker":worker.0,"reason":reason}));
            }
            if let Some(root) = pool.root(candidate, head, now())? {
                break root;
            }
            if now().saturating_sub(last_heartbeat) >= 30_000 {
                pool.heartbeat()?;
                last_heartbeat = now();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        write_bytes(
            &result_dir.join("node.6.0"),
            &root,
            profile::MAX_PROOF_BYTES,
        )?;
        publish_json(&result_dir.join("execution-jobs.json"), &jobs)?;
        // Publish completion last. It is proof availability, never delivery.
        publish_json(
            &result_dir.join("result.json"),
            &json!({"schema_version":1,
            "status":"proved_cpu_audit_pending","root_file":"node.6.0",
            "fresh_proofs":jobs.len(),"reused_proofs":0,"started_ms":started,"completed_ms":now(),
            "worker_failures":failures,
            "native_host":request.native_host,"native_applied":false}),
        )?;
        pool.retire(candidate, now())?;
    }
    pool.close(now())?;
    publish_json(
        &out.join("pool-stopped.json"),
        &json!({"schema_version":1,
        "completed_requests":256,"stopped_ms":now(),"workers_drained":true}),
    )?;
    Ok(())
}
