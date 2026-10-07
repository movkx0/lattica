//! Bounded inline proving through the typed DAG, packets and persistent worker.
//! The outer runner owns the device and cgroup admission for this process.

use super::*;
use lattica_prover_p3::block_v2::execution::{
    dag::{Completion, WorkerId},
    launch::{LaunchLimits, LaunchStore, WorkerGate},
    worker::typed::{
        cached::{CachedTypedWorker, Task},
        process::ProcessWorker,
    },
};
use std::collections::BTreeMap;

pub(super) fn resources(budget: u64, gpu: bool) -> Result<(Resources, Resources), Error> {
    if !gpu {
        return Err("typed DAG proving currently requires the admitted GPU runner".into());
    }
    let assignment: serde_json::Value =
        read_json(Path::new(&std::env::var("LATTICA_V2_WORKER_BUDGET")?))?;
    let (peak, jobs) = budget::resources(&assignment)?;
    if peak.ram_bytes != budget {
        return Err("typed DAG worker memory differs from admitted assignment".into());
    }
    Ok((peak, jobs))
}

pub(super) fn run(
    prepared: Prepared,
    out: &Path,
    budget: u64,
    gpu: bool,
    dispatch: Option<(&Path, &Path)>,
    mut before_shutdown: impl FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    let started = Instant::now();
    let (peak, job_resources) = resources(budget, gpu)?;
    let limits = budget::limits(peak, job_resources)?;
    std::fs::DirBuilder::new().mode(0o700).create(out)?;
    write_json(&out.join("expected.json"), &prepared.expected)?;
    write_json(&out.join("execution-plan.json"), &describe(&prepared))?;
    let runtime = out.join("execution");
    std::fs::DirBuilder::new().mode(0o700).create(&runtime)?;
    let store = ArtifactStore::create(
        &runtime.join("artifacts"),
        StoreLimits {
            bytes: budget::ARTIFACT_BYTES,
            entries: budget::ARTIFACT_ENTRIES,
        },
    )?;
    let mut owner = DurableDag::create(
        &runtime.join("journal"),
        JournalLimits {
            snapshot_bytes: budget::SNAPSHOT_BYTES,
        },
        store,
        prepared.pin,
        prepared.expected.chain,
        1,
        limits,
    )?;
    // This is a proof-only diagnostic selection. Native delivery must replace
    // this local eligibility value with its independently captured head token.
    let eligibility = prepared.expected.profile;
    let now = || started.elapsed().as_millis() as u64;
    let candidate = prepared
        .selection
        .attach(&mut owner, eligibility, now() + 3_600_000, now())?;
    owner.seal(candidate, eligibility, now())?;
    let mut launches =
        LaunchStore::create(&runtime.join("launches"), LaunchLimits { records: 256 })?;
    let mut inline = if dispatch.is_none() {
        Some(CachedTypedWorker::new(
            &mut owner,
            prepared.registry.clone(),
            prepared.pin,
            WorkerId(1),
            WorkerId(2),
            peak,
            job_resources,
            now(),
        )?)
    } else {
        None
    };
    let mut remote = if let Some((fixture, expected)) = dispatch {
        let config = process::config(&prepared, budget)?;
        let mut worker =
            ProcessWorker::prepare(&mut owner, config, WorkerId(1), WorkerId(2), now())?;
        write_bytes(
            &runtime.join("worker-session"),
            worker.session_bytes(),
            4096,
        )?;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command.args([
            "serve-process-gpu".as_ref(),
            fixture.as_os_str(),
            expected.as_os_str(),
            runtime.join("launches").as_os_str(),
            budget.to_string().as_ref(),
        ]);
        worker.start(command)?;
        write_json(
            &runtime.join("worker-start.json"),
            &json!({
                "schema_version":1,"worker_pid":worker.pid(),"coordinator_pid":std::process::id(),
                "execution_digest":hex(&worker.execution_digest()?),"workspace_reserved":true,
                "worker_memory_bytes":budget,"rayon_threads":peak.threads,
            }),
        )?;
        Some(worker)
    } else {
        None
    };
    let jobs: BTreeMap<_, _> = prepared
        .selection
        .jobs()
        .map(|job| (job.id(), job.clone()))
        .collect();
    let mut records = Vec::new();
    while records.len() < jobs.len() {
        let mut ready = owner.ready()?;
        ready.sort_by_key(|id| {
            let job = &jobs[id];
            let mode = job.expected_public()[programs::MODE].as_canonical_u64();
            task_priority(
                mode,
                job.expected().level,
                job.start() as usize >> job.expected().level,
            )
        });
        let id = *ready
            .first()
            .ok_or("typed DAG has no ready job before its root completed")?;
        let job = &jobs[&id];
        let mode = job.expected_public()[programs::MODE].as_canonical_u64();
        let lease = owner.lease(id, WorkerId(2), job_resources, 1, now() + 3_600_000, now())?;
        let task: Task = if let Some(worker) = remote.as_mut() {
            worker.task(&mut owner, lease, now())?
        } else {
            inline.as_ref().unwrap().task(&mut owner, lease, now())?
        };
        let request = task.request()?;
        let stem = format!(
            "node.{}.{}",
            job.expected().level,
            job.start() as usize >> job.expected().level
        );
        write_bytes(
            &runtime.join(format!("{stem}.request")),
            &request,
            lattica_prover_p3::block_v2::execution::launch::MAX_REQUEST_BYTES,
        )?;
        let stage = Instant::now();
        let completed = if let Some(worker) = remote.as_mut() {
            let token =
                launches.issue_bound(&mut owner, lease, &request, worker.execution_digest()?)?;
            worker.execute(&token, task)?
        } else {
            let token = launches.issue(&mut owner, lease, &request)?;
            let gate = WorkerGate::enter(&runtime.join("launches"), &token, &request)?;
            inline.as_mut().unwrap().execute(gate, task, |identity| {
                prepared
                    .policies
                    .iter()
                    .find(|(a, _)| *a == identity)
                    .map(|(_, p)| *p)
                    .ok_or_else(|| "wallet absent from independent host policy".into())
            })?
        };
        let revoked = launches.revoke(lease)?;
        let _idle = launches
            .try_idle(&revoked)?
            .ok_or("typed job launch still active after drain")?;
        let output = completed.reconcile(&mut owner, now())?;
        let expected = owner.begin_verification(lease, now())?;
        let ticket = VerifiedNode::verify_typed(&expected, &prepared.registry, output.bytes())?;
        if owner.finish_verification(lease, Some((ticket, output.bytes().to_vec())), now())?
            != Completion::Accepted
        {
            return Err("typed DAG did not accept independently verified worker result".into());
        }
        write_bytes(&out.join(&stem), output.bytes(), profile::MAX_PROOF_BYTES)?;
        let workspace = if let Some(worker) = remote.as_ref() {
            worker.workspace()?
        } else {
            inline.as_ref().unwrap().workspace()?
        };
        if owner.resource_use()? != workspace.resources() {
            return Err("typed job released or leaked workspace reservations".into());
        }
        let stats = output.stats();
        let times = output.timings();
        let record = json!({"event":"fresh_typed_node", "level":job.expected().level,
            "index":job.start() as usize >> job.expected().level, "mode":mode,
            "count":job.expected().count, "bytes":output.bytes().len(), "seconds":stage.elapsed().as_secs_f64(),
            "cache_setups":stats.setups,"cache_hits":stats.hits,
            "input_verification_ms":times.input_verification_ms,"proving_ms":times.proving_ms,
            "serialization_ms":times.serialization_ms});
        println!("{record}");
        records.push(record);
    }
    let root = bytes(&out.join("node.6.0"))?;
    if owner.candidate_result(candidate, eligibility, now())? != Some(root.as_slice()) {
        return Err("typed DAG root differs from published proof".into());
    }
    let stats = if let Some(worker) = remote.as_ref() {
        worker.stats()?
    } else {
        inline.as_ref().unwrap().stats()?
    };
    let worker_pid = remote.as_ref().and_then(ProcessWorker::pid);
    if let Some(worker) = remote.as_mut() {
        worker.close(&mut owner, now())?;
        write_json(
            &runtime.join("worker-exit.json"),
            &json!({
                "schema_version":1,"worker_pid":worker.pid(),"coordinator_pid":std::process::id(),
                "execution_digest":hex(&worker.execution_digest()?),"exit_code":0,
                "gpu_teardown_confirmed":true,"workspace_released":true,"fresh_proofs":records.len(),
            }),
        )?;
    } else {
        let worker = inline.as_mut().unwrap();
        worker.clear_cache(&owner)?;
        before_shutdown()?;
        worker.close(&mut owner, now())?;
    }
    if owner.resource_use()? != Resources::default() {
        return Err("typed workspace resources survived teardown".into());
    }
    write_json(
        &out.join("result.json"),
        &json!({"schema_version":1,"status":"proved_cpu_audit_pending",
        "count":prepared.expected.count,"construction":CONSTRUCTION,"registry_keys":KEY_COUNT,
        "fresh_proofs":records.len(),"seconds":started.elapsed().as_secs_f64(),
        "worker_memory_bytes":budget,"root_file":"node.6.0","backend":"gpu",
            "execution_backend":if dispatch.is_some() {"typed_process_dag_v1"} else {"typed_inline_dag_v1"},
            "worker_pid":worker_pid,"coordinator_pid":std::process::id(),
            "worker_process_exited":dispatch.is_some(),"cache_setups":stats.setups,"cache_hits":stats.hits,
        "workspace_released_after_gpu_teardown":true,"node_records":records,
        "arrival_backend_integrated":false,"durable_host_applied":false,"production_ready":false}),
    )
}
