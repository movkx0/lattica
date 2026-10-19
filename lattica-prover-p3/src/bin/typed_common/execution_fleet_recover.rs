//! Reopen one native fleet journal after exact old service reconciliation.
use super::*;
#[path = "execution_recovery_admission.rs"]
mod admission;
use lattica_prover_p3::block_v2::execution::{
    journal::PreviousAttempt, os_worker, resources::Resources, transport::image_fingerprint,
    workspace::WorkspaceLease,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    schema_version: u32,
    pub epoch: u64,
    pub durable_runtime: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinator {
    schema_version: u32,
    unit: String,
    identity: os_worker::Identity,
    executable: [u8; 32],
}

#[derive(serde::Deserialize)]
struct WorkerStart {
    worker_pid: u32,
    coordinator_pid: u32,
    unit: String,
    assignment: serde_json::Value,
    os_identity: os_worker::Identity,
    job_worker: u64,
    workspace_worker: u64,
}

struct PriorWorker {
    index: usize,
    start: Option<WorkerStart>,
    startup: Option<startup::Reconciled>,
    ready_record_present: bool,
}

fn prior_worker(
    source: &Path,
    previous: &Plan,
    old: &Coordinator,
    index: usize,
) -> Result<PriorWorker, Error> {
    let worker = &previous.workers[index];
    let record = source.join(format!("execution/worker-{index}-start.json"));
    let ready_record_present = record.exists();
    let startup = if previous.startup_fenced {
        let gate = source.join(format!("execution/worker-{index}-startup"));
        if worker.assignment["startup_guard"].as_str() != gate.to_str() {
            return Err("old worker startup gate differs from its admitted directory".into());
        }
        if gate.join("intent.json").exists() {
            let intent = startup_intent(worker)?;
            Some(startup::Reconciled {
                started: startup::inspect_started(&gate, &intent)?,
                observed_before_entry: None,
                intent,
                future_start_fenced: false,
                process_and_service_quiescent: false,
            })
        } else {
            if ready_record_present {
                return Err("started worker lacks its durable startup intent".into());
            }
            None
        }
    } else {
        None
    };
    let id = (index as u64 + 1) * 2;
    let start: Option<WorkerStart> = if ready_record_present || !previous.startup_fenced {
        Some(read_json(&record)?)
    } else {
        startup
            .as_ref()
            .and_then(|receipt| receipt.started.as_ref())
            .map(|started| WorkerStart {
                worker_pid: started.identity.pid(),
                coordinator_pid: old.identity.pid(),
                unit: worker.assignment["unit"].as_str().unwrap().to_owned(),
                assignment: worker.assignment.clone(),
                os_identity: started.identity.clone(),
                job_worker: id,
                workspace_worker: id - 1,
            })
    };
    if let Some(start) = &start {
        if start.unit != worker.assignment["unit"]
            || start.assignment != worker.assignment
            || start.worker_pid != start.os_identity.pid()
            || start.coordinator_pid != old.identity.pid()
            || start.job_worker != id
            || start.workspace_worker != id - 1
        {
            return Err("old worker identity differs from its durable assignment".into());
        }
        if previous.startup_fenced
            && startup
                .as_ref()
                .and_then(|receipt| receipt.started.as_ref())
                .is_none_or(|entry| entry.identity != start.os_identity)
        {
            return Err("worker READY record differs from its independent startup identity".into());
        }
    }
    Ok(PriorWorker {
        index,
        start,
        startup,
        ready_record_present,
    })
}

pub(super) fn initial(runtime: &Path) -> State {
    State {
        schema_version: 1,
        epoch: 1,
        durable_runtime: runtime.to_owned(),
    }
}

pub(super) fn record(plan: &Plan, state: &State, out: &Path) -> Result<(), Error> {
    let coordinator = Coordinator {
        schema_version: 1,
        unit: plan.coordinator_unit.clone(),
        identity: os_worker::capture_coordinator(&plan.coordinator_unit)?,
        executable: image_fingerprint(&std::env::current_exe()?)?,
    };
    write_json(&out.join("coordinator.json"), &coordinator)?;
    write_json(&out.join("fleet-plan.json"), plan)?;
    write_json(&out.join("recovery-state.json"), state)
}

fn stable_assignment(assignment: &serde_json::Value) -> serde_json::Value {
    let mut gpu = assignment["gpu"].clone();
    if let Some(fields) = gpu.as_object_mut() {
        fields.remove("available_bytes");
    }
    let mut result = json!({"cpu":assignment["cpu"],"host":assignment["host"],"gpu":gpu,
        "drivers":[assignment["detected_gpu"]["nvidia"]["driver"],
                   assignment["detected_gpu"]["opencl"]["driver"]]});
    result["slice"] = assignment
        .get("slice")
        .cloned()
        .unwrap_or_else(|| json!("lattica-v2-multi.slice"));
    if assignment["backend"] == "cuda" {
        result["backend"] = json!("cuda");
        result["cuda"] = assignment["cuda"].clone();
        result["cuda_runtime"] = assignment["cuda_runtime"].clone();
        result["drivers"] = json!([
            assignment["detected_gpu"]["nvidia"]["driver"],
            assignment["detected_gpu"]["cuda"]["driver_api"]
        ]);
    }
    result
}

fn compatible(previous: &Plan, current: &Plan) -> Result<(), Error> {
    if previous.pool_calibration.is_some()
        || current.pool_calibration.is_some()
        || previous.preseal_only != current.preseal_only
        || previous.pool_prefix_handoff != current.pool_prefix_handoff
        || previous.reuse_preseal != current.reuse_preseal
        || previous.native_host.is_none()
        || serde_json::to_value(&previous.native_host)?
            != serde_json::to_value(&current.native_host)?
        || previous.coordinator_unit == current.coordinator_unit
        || previous.coordinator_threads != current.coordinator_threads
        || previous.coordinator_ram_bytes != current.coordinator_ram_bytes
        || previous.coordinator_shared_bytes != current.coordinator_shared_bytes
        || previous.fleet_bytes != current.fleet_bytes
        || previous.pool_scheduling.is_some() != current.pool_scheduling.is_some()
        || previous.pool_workflow != current.pool_workflow
        || previous.pool_requests.is_some() != current.pool_requests.is_some()
        || validate_plan_shape(previous)? != validate_plan(current)?
        || previous
            .workers
            .iter()
            .zip(&current.workers)
            .any(|(old, new)| {
                stable_assignment(&old.assignment) != stable_assignment(&new.assignment)
                    || old.assignment["unit"] == new.assignment["unit"]
            })
    {
        return Err("coordinator recovery requires the same native candidate and original resource assignments with new services".into());
    }
    Ok(())
}

pub(super) fn restore(
    source: &Path,
    plan: &Plan,
    prepared: &Prepared,
    head: [u8; 32],
    now: impl Fn() -> u64,
    out: &Path,
) -> Result<
    (
        DurableDag,
        State,
        lattica_prover_p3::block_v2::execution::dag::CandidateId,
    ),
    Error,
> {
    if !source.is_absolute() || source == out {
        return Err("recovery requires a distinct absolute prior owner proofs directory".into());
    }
    TypedRegistryContext::admit_recovery_storage(
        plan.coordinator_ram_bytes
            .checked_sub(plan.coordinator_shared_bytes)
            .ok_or("recovery shared RAM exceeds coordinator assignment")?,
    )?;
    let origin = admission::trace(
        source,
        plan,
        &prepared.expected,
        prepared.selection.root().id(),
    )?;
    let previous = &origin.plan;
    let state = &origin.state;
    let old = &origin.coordinator;
    let worker_source = &origin.worker_source;
    let assignments = validate_plan_shape(previous)?;
    let mut starts = Vec::new();
    for index in (0..previous.workers.len()).filter(|_| !previous.recover_cached_only) {
        starts.push(prior_worker(worker_source, previous, old, index)?);
    }
    let next = State {
        schema_version: 1,
        epoch: state
            .epoch
            .checked_add(1)
            .ok_or("recovery epoch exhausted")?,
        durable_runtime: state.durable_runtime.clone(),
    };
    // No journal or launch mutation is allowed before this atomic admission.
    // If interrupted before publication, the prior source is still authoritative.
    record(plan, &next, out)?;
    admission::publish(source, &next, out)?;
    let store = ArtifactStore::open(
        &state.durable_runtime.join("artifacts"),
        StoreLimits {
            bytes: budget::ARTIFACT_BYTES,
            entries: budget::ARTIFACT_ENTRIES,
        },
    )?;
    let mut limits = budget::fleet_limits(&assignments)?;
    if plan.pool_requests.is_some() {
        pool_service::configure_limits(&mut limits, true);
    }
    let recovery = DurableDag::recover_typed(
        &state.durable_runtime.join("journal"),
        JournalLimits {
            snapshot_bytes: budget::SNAPSHOT_BYTES,
        },
        store,
        prepared.pin,
        &prepared.registry,
        prepared.expected.chain,
        next.epoch,
        limits,
        |identity| {
            prepared
                .policies
                .iter()
                .find(|(artifact, _)| *artifact == identity)
                .map(|(_, policy)| *policy)
                .ok_or_else(|| "recovery wallet absent from independent native policy".into())
        },
    )?;
    let journal_previous_epoch = recovery.previous_epoch();
    origin.check_checkpoint(&recovery)?;
    let prior_candidate = recovery
        .previous_candidates()
        .iter()
        .find(|candidate| {
            candidate.root == prepared.selection.root().id()
                && candidate.eligibility == head
                && candidate.sealed != plan.preseal_only
                && !candidate.cancelled
        })
        .ok_or("recovery has no candidate with the current native head and scope")?;
    if plan.pool_workflow.is_some()
        && (recovery.previous_candidates().len() != 1
            || prior_candidate.deadline_ms != pool_timing::CANDIDATE_MS)
    {
        return Err("bounded pool recovery candidate or original deadline changed".into());
    }
    let prior_candidate = prior_candidate.id;
    let mut launches = LaunchStore::open(
        &state.durable_runtime.join("launches"),
        LaunchLimits { records: 256 },
    )?;
    let mut revocations = Vec::new();
    let mut attempts = Vec::new();
    for attempt in recovery.unresolved_attempts() {
        let prior = starts
            .iter()
            .find(|prior| {
                prior
                    .start
                    .as_ref()
                    .is_some_and(|start| start.job_worker == attempt.lease.worker().0)
            })
            .ok_or("unresolved attempt has an unknown worker")?;
        let start = prior
            .start
            .as_ref()
            .ok_or("dispatched attempt lacks startup identity")?;
        if attempt.resources != assignments[prior.index].1 {
            return Err("unresolved attempt resource assignment changed".into());
        }
        revocations.push(launches.revoke_recovered(attempt)?);
        attempts.push(json!({"job":hex(&attempt.lease.job().to_bytes()),
            "lease_key":hex(&attempt.lease.process_key()?),"worker_pid":start.worker_pid,
            "verification_was_active":attempt.verification_active}));
    }
    for prior in &mut starts {
        if let Some(observed) = &prior.startup {
            let receipt = startup::reconcile(
                &worker_source.join(format!("execution/worker-{}-startup", prior.index)),
                &observed.intent,
            )?;
            if prior.start.is_none() {
                let id = (prior.index as u64 + 1) * 2;
                prior.start = receipt.started.as_ref().map(|started| WorkerStart {
                    worker_pid: started.identity.pid(),
                    coordinator_pid: old.identity.pid(),
                    unit: receipt.intent.unit.clone(),
                    assignment: receipt.intent.assignment.clone(),
                    os_identity: started.identity.clone(),
                    job_worker: id,
                    workspace_worker: id - 1,
                });
            } else if receipt
                .started
                .as_ref()
                .is_none_or(|started| started.identity != prior.start.as_ref().unwrap().os_identity)
            {
                return Err("startup identity changed during reconciliation".into());
            }
            prior.startup = Some(receipt);
        }
    }
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    for start in starts.iter().filter_map(|prior| prior.start.as_ref()) {
        if !os_worker::exited(&start.os_identity, &start.unit)? {
            os_worker::request_stop(&start.os_identity, &start.unit)?;
        }
        while !os_worker::exited(&start.os_identity, &start.unit)? {
            if Instant::now() >= deadline {
                return Err(
                    "old worker did not become quiescent during coordinator recovery".into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    let mut gates = Vec::new();
    for revoked in &revocations {
        gates.push(
            launches
                .try_idle(revoked)?
                .ok_or("old revoked launch remains in use")?,
        );
    }
    let unresolved_workspaces = recovery.unresolved_workspaces().len();
    let reconcile_attempt = |attempt: &PreviousAttempt| {
        if !revocations
            .iter()
            .any(|revoked| revoked.lease() == attempt.lease)
        {
            return Err("unreconciled old lease".into());
        }
        Ok(())
    };
    let reconcile_workspace = |workspace: &WorkspaceLease| {
        let prior = starts
            .iter()
            .find(|prior| (prior.index as u64 + 1) * 2 - 1 == workspace.worker().0)
            .ok_or("unresolved workspace has an unknown worker")?;
        if workspace.resources() != workspace_resources(assignments[prior.index].0) {
            return Err("old workspace resource assignment differs".into());
        }
        if previous.startup_fenced {
            let fence = prior
                .startup
                .as_ref()
                .ok_or("reserved workspace lacks its startup fence")?;
            if !fence.future_start_fenced || !fence.process_and_service_quiescent {
                return Err("old workspace startup was not reconciled".into());
            }
        }
        match &prior.start {
            Some(start) if os_worker::exited(&start.os_identity, &start.unit)? => {}
            None if previous.startup_fenced && prior.startup.is_some() => {}
            _ => return Err("old workspace lacks exact process/cgroup reconciliation".into()),
        }
        Ok(())
    };
    let (owner, candidate) = if plan.pool_workflow.is_some() && plan.preseal_only {
        recovery.resume_prefix_candidate_with_workspaces(
            reconcile_attempt,
            reconcile_workspace,
            now,
            prior_candidate,
            prepared.selection.root().id(),
            head,
        )?
    } else if plan.pool_workflow.is_some() {
        recovery.resume_sealed_candidate_with_workspaces(
            reconcile_attempt,
            reconcile_workspace,
            now,
            prior_candidate,
            prepared.selection.root().id(),
            head,
        )?
    } else {
        recovery.resume_sealed_with_workspaces(
            reconcile_attempt,
            reconcile_workspace,
            now,
            prepared.selection.root().id(),
            head,
            3_600_000,
        )?
    };
    if owner.resource_use()? != Resources::default() {
        return Err("old reservations survived coordinator reconciliation".into());
    }
    write_json(
        &out.join("coordinator-recovery.json"),
        &json!({
            "schema_version":1,"source":source,"durable_runtime":next.durable_runtime,
            "previous_epoch":state.epoch,"recovery_epoch":next.epoch,
            "previous_coordinator_pid":origin.previous_coordinator_pid,"coordinator_pid":std::process::id(),
            "journal_previous_epoch":journal_previous_epoch,"reconciled_worker_source":worker_source,
            "interrupted_recovery_epochs":origin.interrupted_epochs,
            "old_coordinator_quiescent":true,"old_workers_quiescent":true,
            "old_launches_revoked":true,"old_workspace_reservations_released":true,
            "reconciled_attempts":attempts,"reconciled_workspaces":unresolved_workspaces,
            "worker_pids":starts.iter().filter_map(|prior| prior.start.as_ref().map(|start| start.worker_pid)).collect::<Vec<_>>(),
            "startup_fenced":previous.startup_fenced,
            "worker_startups":starts.iter().map(|prior| json!({
                "index":prior.index,"ready_record_present":prior.ready_record_present,
                "startup":prior.startup,
            })).collect::<Vec<_>>(),
            "original_resource_assignments_preserved":true,
            "original_workflow_deadline_preserved":plan.pool_workflow.is_some(),
            "preseal_only":plan.preseal_only,
        }),
    )?;
    Ok((owner, next, candidate))
}

pub(super) fn export(
    owner: &DurableDag,
    prepared: &Prepared,
    state: &State,
    out: &Path,
) -> Result<Vec<serde_json::Value>, Error> {
    let registry = TypedRegistryContext::new(&prepared.registry, prepared.pin.profile())?;
    let mut reused = Vec::new();
    for job in prepared.selection.jobs() {
        if let Some(proof) = owner.verified_node_bytes(job.id())? {
            registry.verify_node(job, proof)?;
            write_bytes(
                &out.join(preseal::name(job)),
                proof,
                profile::MAX_PROOF_BYTES,
            )?;
            reused.push(json!({"job":hex(&job.id().to_bytes()),"level":job.expected().level,
                "index":job.start() as usize >> job.expected().level,"bytes":proof.len(),
                "source":state.durable_runtime,"cpu_reverified":true,"recovered_from_journal":true}));
        }
    }
    Ok(reused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuda_recovery_binds_construction_runtime_driver_and_fleet() {
        let value = json!({"backend":"cuda", "cuda":{"input_values":1048576},
            "cuda_runtime":{"libraries":{"nvrtc":"first"}}, "slice":"lattica-v2-multi-cuda-test.slice",
            "gpu":{"available_bytes":10}, "detected_gpu":{"nvidia":{"driver":"first"},
                "cuda":{"driver_api":12090}}});
        let original = stable_assignment(&value);
        for (pointer, changed) in [
            ("/backend", json!("opencl")),
            ("/cuda/input_values", json!(100)),
            ("/cuda_runtime/libraries/nvrtc", json!("second")),
            ("/detected_gpu/cuda/driver_api", json!(13000)),
            ("/slice", json!("lattica-v2-multi.slice")),
        ] {
            let mut altered = value.clone();
            *altered.pointer_mut(pointer).unwrap() = changed;
            assert_ne!(stable_assignment(&altered), original, "{pointer}");
        }
        let mut live = value;
        live["gpu"]["available_bytes"] = json!(20);
        assert_eq!(stable_assignment(&live), original);
    }

    #[test]
    fn startup_identity_can_precede_ready_without_losing_assignment_binding() {
        let directory = std::env::temp_dir().join(format!(
            "lattica-fleet-startup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(directory.join("execution")).unwrap();
        let mut plan = native_plan();
        plan.startup_fenced = true;
        let gate = directory.join("execution/worker-0-startup");
        plan.workers[0].assignment["startup_guard"] = json!(gate);
        plan.workers[0].assignment["unit"] = json!(format!(
            "lattica-v2-multi-persistent-{}.service",
            "a".repeat(64)
        ));
        plan.workers[0].arguments = vec!["serve-shared-process-gpu".into()];
        let identity = |pid| {
            serde_json::from_value::<os_worker::Identity>(json!({
            "boot":vec![1u8;16],"invocation":vec![2u8;16],"pid":pid,"start_ticks":3,
            "group":"/test","device":4,"inode":5}))
            .unwrap()
        };
        let coordinator = Coordinator {
            schema_version: 1,
            unit: plan.coordinator_unit.clone(),
            identity: identity(10),
            executable: image_fingerprint(&std::env::current_exe().unwrap()).unwrap(),
        };
        let intent = startup_intent(&plan.workers[0]).unwrap();
        startup::create(&gate, &intent).unwrap();
        startup::authorize(&gate, &intent, [7; 32]).unwrap();
        let pending = prior_worker(&directory, &plan, &coordinator, 0).unwrap();
        assert!(pending.start.is_none() && !pending.ready_record_present);
        assert!(!pending.startup.unwrap().future_start_fenced);
        write_json(
            &gate.join("started.json"),
            &startup::Started {
                identity: identity(20),
                execution_digest: [7; 32],
            },
        )
        .unwrap();
        let before_ready = prior_worker(&directory, &plan, &coordinator, 0).unwrap();
        assert!(!before_ready.ready_record_present);
        let started = before_ready.start.unwrap();
        assert_eq!(
            (
                started.worker_pid,
                started.coordinator_pid,
                started.job_worker,
                started.workspace_worker
            ),
            (20, 10, 2, 1)
        );
        plan.workers[0].assignment["gpu"]["managed_bytes"] = json!(123);
        assert!(prior_worker(&directory, &plan, &coordinator, 0).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn native_plan() -> Plan {
        let mut plan = super::super::tests::plan();
        let binding = json!({"schema_version":1,"head_token":vec![1u8;32],"generation":0,
            "configuration_sha256":vec![2u8;32],"complete_body_sha256":vec![3u8;32],
            "preparation_sha256":vec![4u8;32],"expected":{"schema_version":1,
            "profile":vec![5u8;32],"chain":vec![6u8;32],"root":[7,7,7,7],"count":4,
            "block_height":10,"authorized_issuance":{"3":7}}});
        plan.native_host = Some(serde_json::from_value(binding.clone()).unwrap());
        for worker in &mut plan.workers {
            worker.assignment["native_host"] = binding.clone();
        }
        plan
    }

    #[test]
    fn bounded_recovery_keeps_the_workflow_and_accepts_a_new_service_window() {
        let now = {
            let mut value = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(
                unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) },
                0
            );
            value.tv_sec as u64 * 1000 + value.tv_nsec as u64 / 1_000_000
        };
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let start = now.saturating_sub(200_000);
        let mut old = native_plan();
        old.pool_requests = Some("/old-requests".into());
        old.pool_workflow = Some(pool_timing::Workflow {
            schema_version: 1,
            boot_id: boot.trim().into(),
            started_monotonic_ms: start,
            deadline_monotonic_ms: start + pool_timing::CANDIDATE_MS,
        });
        old.pool_scheduling = Some(pool_timing::Window {
            schema_version: 1,
            boot_id: boot.trim().into(),
            issued_monotonic_ms: start,
            dispatch_deadline_monotonic_ms: start + pool_timing::DISPATCH_MS,
        });
        for worker in &mut old.workers {
            worker.pool_timing = Some("/host-approved.json".into());
        }
        validate_plan_shape(&old).unwrap();
        let mut new = old.clone();
        new.pool_requests = Some("/next-requests".into());
        new.recover_from = Some("/old-proofs".into());
        new.coordinator_unit = "lattica-v2-multi-owner-next.service".into();
        for (index, worker) in new.workers.iter_mut().enumerate() {
            worker.assignment["unit"] = json!(format!("next-worker-{index}"));
        }
        let window = new.pool_scheduling.as_mut().unwrap();
        window.issued_monotonic_ms = now;
        window.dispatch_deadline_monotonic_ms = now + pool_timing::DISPATCH_MS;
        compatible(&old, &new).unwrap();
        // Prefix recovery keeps its native scope and never becomes a sealed
        // candidate. Final candidate recovery keeps the exact imported paths.
        let mut old_prefix = old.clone();
        let mut new_prefix = new.clone();
        for plan in [&mut old_prefix, &mut new_prefix] {
            plan.preseal_only = true;
            let mut binding = serde_json::to_value(&plan.native_host).unwrap();
            binding["scope"] = json!("prefix");
            plan.native_host = Some(serde_json::from_value(binding.clone()).unwrap());
            for worker in &mut plan.workers {
                worker.assignment["native_host"] = binding.clone();
            }
        }
        compatible(&old_prefix, &new_prefix).unwrap();
        assert!(compatible(&old, &new_prefix).is_err());
        assert!(compatible(&old_prefix, &new).is_err());
        new_prefix.reuse_preseal.push("/prefix-cache".into());
        assert!(validate_plan(&new_prefix).is_err());
        let mut old_import = old.clone();
        let mut new_import = new.clone();
        old_import.reuse_preseal.push("/original-cache".into());
        new_import.reuse_preseal = old_import.reuse_preseal.clone();
        compatible(&old_import, &new_import).unwrap();
        new_import.reuse_preseal[0] = "/another-cache".into();
        assert!(compatible(&old_import, &new_import).is_err());
        let mut changed = new.clone();
        let workflow = changed.pool_workflow.as_mut().unwrap();
        workflow.started_monotonic_ms += 1;
        workflow.deadline_monotonic_ms += 1;
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new.clone();
        changed.pool_workflow = None;
        assert!(validate_plan(&changed).is_err());
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new;
        changed.pool_workflow.as_mut().unwrap().boot_id =
            "00000000-0000-0000-0000-000000000000".into();
        assert!(compatible(&old, &changed).is_err());
    }

    #[test]
    fn cached_continuation_requires_a_sealed_native_recovery_plan() {
        let mut plan = native_plan();
        plan.recover_cached_only = true;
        assert!(validate_plan(&plan).is_err());
        plan.recover_from = Some("/previous/proofs".into());
        validate_plan(&plan).unwrap();
        let mut prefix = plan.clone();
        prefix.preseal_only = true;
        assert!(validate_plan(&prefix).is_err());
        plan.native_host = None;
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn recovery_preserves_candidate_resources_and_replaces_service_instances() {
        let old = native_plan();
        let mut new = old.clone();
        new.coordinator_unit = "lattica-v2-multi-owner-new.service".into();
        for (index, worker) in new.workers.iter_mut().enumerate() {
            worker.assignment["unit"] = json!(format!("new-worker-{index}"));
        }
        compatible(&old, &new).unwrap();
        let mut changed = new.clone();
        changed.workers[0].assignment["gpu"]["uuid"] = json!("GPU-other");
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new.clone();
        changed.coordinator_shared_bytes += 1;
        for worker in &mut changed.workers {
            let host = &mut worker.assignment["host"];
            host["coordinator_shared_bytes"] = json!(changed.coordinator_shared_bytes);
        }
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new.clone();
        changed.workers[0].assignment["gpu"]["context_bytes"] = json!(1u64 << 29);
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new.clone();
        changed.workers[0].assignment["host"]["worker_bytes"] = json!(3u64 << 30);
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new.clone();
        let mut binding = serde_json::to_value(&changed.native_host).unwrap();
        binding["generation"] = json!(1);
        changed.native_host = Some(serde_json::from_value(binding).unwrap());
        assert!(compatible(&old, &changed).is_err());
        let mut changed = new.clone();
        changed.workers[0].assignment["unit"] = old.workers[0].assignment["unit"].clone();
        assert!(compatible(&old, &changed).is_err());
    }

    #[test]
    fn recovery_requires_native_binding_even_when_resources_match() {
        let old = super::super::tests::plan();
        let mut new = old.clone();
        new.coordinator_unit = "lattica-v2-multi-owner-new.service".into();
        assert!(compatible(&old, &new).is_err()); // No native binding.
    }
}
