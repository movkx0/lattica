//! Reopen one native fleet journal after exact old service reconciliation.
use super::*;
#[path = "execution_recovery_admission.rs"]
mod admission;
use lattica_prover_p3::block_v2::execution::{
    os_worker, resources::Resources, transport::image_fingerprint,
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
    json!({"cpu":assignment["cpu"],"host":assignment["host"],"gpu":gpu,
        "drivers":[assignment["detected_gpu"]["nvidia"]["driver"],
                   assignment["detected_gpu"]["opencl"]["driver"]]})
}

fn compatible(previous: &Plan, current: &Plan) -> Result<(), Error> {
    if previous.preseal_only
        || !previous.reuse_preseal.is_empty()
        || previous.native_host.is_none()
        || serde_json::to_value(&previous.native_host)?
            != serde_json::to_value(&current.native_host)?
        || previous.coordinator_unit == current.coordinator_unit
        || previous.coordinator_threads != current.coordinator_threads
        || previous.coordinator_ram_bytes != current.coordinator_ram_bytes
        || previous.fleet_bytes != current.fleet_bytes
        || validate_plan(previous)? != validate_plan(current)?
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
    let origin = admission::trace(source, plan, &prepared.expected)?;
    let previous = &origin.plan;
    let state = &origin.state;
    let old = &origin.coordinator;
    let worker_source = &origin.worker_source;
    let assignments = validate_plan(&previous)?;
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
        budget::fleet_limits(&assignments)?,
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
    if !recovery.previous_candidates().iter().any(|candidate| {
        candidate.root == prepared.selection.root().id()
            && candidate.eligibility == head
            && candidate.sealed
            && !candidate.cancelled
    }) {
        return Err("recovery has no sealed candidate for the current native head".into());
    }
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
    let (owner, candidate) = recovery.resume_sealed_with_workspaces(
        |attempt| {
            if !revocations
                .iter()
                .any(|revoked| revoked.lease() == attempt.lease)
            {
                return Err("unreconciled old lease".into());
            }
            Ok(())
        },
        |workspace| {
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
        },
        now,
        prepared.selection.root().id(),
        head,
        3_600_000,
    )?;
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
    let mut reused = Vec::new();
    for job in prepared.selection.jobs() {
        if let Some(proof) = owner.verified_node_bytes(job.id())? {
            VerifiedNode::verify_typed(job, &prepared.registry, proof)?;
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
