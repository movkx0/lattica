//! Bounded trusted-local control plane for the persistent public-proof pool.
//! The native controller publishes requests atomically, audits the root in an
//! independent process, then rechecks and commits its native preparation.
use super::*;
#[path = "execution_pool_report.rs"]
mod report;

pub(super) fn report_storage_bytes(workers: usize) -> Result<usize, Error> {
    report::Report::storage_plan(2 * commitment::CAPACITY - 1, workers)?
        .total_bytes()?
        .checked_add(preseal::pool_output_storage_bytes())
        .ok_or_else(|| "pool prefix report storage overflow".into())
}

/// Bounded phases use the ordinary durable limits (256 jobs/attempts, eight
/// candidates). Long-lived historical sessions need their larger actual model.
pub(super) fn configure_limits(limits: &mut Limits, bounded: bool) {
    if !bounded {
        limits.jobs = 4096;
        limits.candidates = 256;
        limits.attempts = 16384;
        limits.artifact_bytes = 512usize << 20;
    }
    limits.recovery_window_ms = 0;
}

pub(super) fn store_limits(bounded: bool) -> StoreLimits {
    StoreLimits {
        bytes: if bounded {
            budget::ARTIFACT_BYTES
        } else {
            512 << 20
        },
        entries: if bounded {
            budget::ARTIFACT_ENTRIES
        } else {
            4096
        },
    }
}

pub(super) fn journal_limits(bounded: bool) -> JournalLimits {
    JournalLimits {
        snapshot_bytes: if bounded {
            budget::SNAPSHOT_BYTES
        } else {
            8 << 20
        },
    }
}
use lattica_prover_p3::block_v2::execution::pool::{
    local::LocalProcessEndpoint, PoolCoordinator, WorkerEndpoint,
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(super) fn publish_json(path: &Path, value: &impl serde::Serialize) -> Result<(), Error> {
    let temporary = path.with_extension("json.pending");
    write_bytes(&temporary, &report::encode(value)?, JSON_LIMIT)?;
    if path.exists() {
        return Err("pool output already exists".into());
    }
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(path.parent().ok_or("pool output parent")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(prefix: bool) -> (Plan, Request) {
        let mut plan = super::super::tests::plan();
        let binding = json!({"schema_version":1,"scope":if prefix {"prefix"} else {"candidate"},
            "head_token":vec![1u8;32],"generation":0,"configuration_sha256":vec![2u8;32],
            "complete_body_sha256":vec![3u8;32],"preparation_sha256":vec![4u8;32],
            "expected":{"schema_version":1,"profile":vec![5u8;32],"chain":vec![6u8;32],
                "root":[7,7,7,7],"count":4,"block_height":10,"authorized_issuance":{"3":7}}});
        plan.native_host = Some(serde_json::from_value(binding).unwrap());
        plan.preseal_only = prefix;
        plan.pool_workflow = Some(pool_timing::Workflow {
            schema_version: 1,
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            started_monotonic_ms: 100,
            deadline_monotonic_ms: 100 + pool_timing::CANDIDATE_MS,
        });
        let request = Request {
            schema_version: 1,
            fixture: "/fixture".into(),
            expected: "/fixture/expected.json".into(),
            native_host: plan.native_host.clone().unwrap(),
            deadline_ms: pool_timing::CANDIDATE_MS,
            pool_seal: None,
            arrival_selection: None,
        };
        (plan, request)
    }

    #[test]
    fn bounded_request_reuses_only_the_same_native_preparation_and_input_paths() {
        let inputs = (Path::new("/fixture"), Path::new("/fixture/expected.json"));
        for prefix in [false, true] {
            let (plan, request) = request(prefix);
            request.validate(&plan, inputs, 1).unwrap();
            assert!(request
                .validate(&plan, (Path::new("/copy"), inputs.1), 1)
                .is_err());
            assert!(request
                .validate(&plan, (inputs.0, Path::new("/copy.json")), 1)
                .is_err());
            for field in [
                "head_token",
                "generation",
                "complete_body_sha256",
                "preparation_sha256",
                "scope",
            ] {
                let (_, mut changed) = self::request(prefix);
                let mut binding = serde_json::to_value(&changed.native_host).unwrap();
                match field {
                    "generation" => binding[field] = json!(1),
                    "scope" => binding[field] = json!(if prefix { "candidate" } else { "prefix" }),
                    _ => binding[field][0] = json!(9),
                }
                changed.native_host = serde_json::from_value(binding).unwrap();
                assert!(changed.validate(&plan, inputs, 1).is_err(), "{field}");
            }
        }
    }

    #[test]
    fn bounded_preparation_does_not_extend_or_revive_a_request_deadline() {
        let inputs = (Path::new("/fixture"), Path::new("/fixture/expected.json"));
        for prefix in [false, true] {
            let (plan, request) = request(prefix);
            request
                .validate(&plan, inputs, pool_timing::CANDIDATE_MS - 1)
                .unwrap();
            for now in [
                pool_timing::CANDIDATE_MS,
                pool_timing::CANDIDATE_MS + 1,
                u64::MAX,
            ] {
                assert!(request.validate(&plan, inputs, now).is_err());
            }
            for deadline in [
                0,
                pool_timing::CANDIDATE_MS - 1,
                pool_timing::CANDIDATE_MS + 1,
                u64::MAX,
            ] {
                let (_, mut changed) = self::request(prefix);
                changed.deadline_ms = deadline;
                assert!(changed.validate(&plan, inputs, 1).is_err());
            }
        }
    }

    #[test]
    fn historical_requests_still_require_valid_paths_and_native_session() {
        let (mut plan, mut request) = request(false);
        plan.pool_workflow = None;
        let inputs = (Path::new("/startup"), Path::new("/startup/expected.json"));
        request.validate(&plan, inputs, 1).unwrap();
        request.fixture = "relative".into();
        assert!(request.validate(&plan, inputs, 1).is_err());
        request.fixture = "/next".into();
        request.expected = "relative.json".into();
        assert!(request.validate(&plan, inputs, 1).is_err());
        request.expected = "/next/expected.json".into();
        request.schema_version = 2;
        assert!(request.validate(&plan, inputs, 1).is_err());
        request.schema_version = 1;
        let mut binding = serde_json::to_value(&request.native_host).unwrap();
        binding["configuration_sha256"][0] = json!(9);
        request.native_host = serde_json::from_value(binding).unwrap();
        assert!(request.validate(&plan, inputs, 1).is_err());
    }

    #[test]
    fn handoff_requires_explicit_scope_selection_and_both_original_clocks() {
        let (mut plan, _) = request(true);
        plan.pool_prefix_handoff = true;
        plan.pool_scheduling = Some(pool_timing::Window {
            schema_version: 1,
            boot_id: plan.pool_workflow.as_ref().unwrap().boot_id.clone(),
            issued_monotonic_ms: 100,
            dispatch_deadline_monotonic_ms: 150100,
        });
        let (_, mut next) = request(false);
        next.fixture = "/final".into();
        next.expected = "/final/expected.json".into();
        next.arrival_selection = Some("ab".repeat(32));
        next.pool_seal = Some(
            serde_json::from_value(json!({"schema_version":1,
            "pool_workflow":plan.pool_workflow,"sealed_monotonic_ms":200,
            "deadline_monotonic_ms":180200}))
            .unwrap(),
        );
        assert_eq!(next.validate_extension(&plan, 101).unwrap(), 180100);
        for now in [99, 180100, pool_timing::CANDIDATE_MS] {
            assert!(next.validate_extension(&plan, now).is_err());
        }
        for change in 0..7 {
            let mut bad = next.clone();
            let mut changed_plan = plan.clone();
            match change {
                0 => changed_plan.pool_prefix_handoff = false,
                1 => changed_plan.preseal_only = false,
                2 => bad.arrival_selection = None,
                3 => bad.arrival_selection = Some("a".repeat(63)),
                4 => bad.pool_seal = None,
                5 => bad.deadline_ms -= 1,
                _ => bad.native_host = plan.native_host.clone().unwrap(),
            }
            assert!(
                bad.validate_extension(&changed_plan, 101).is_err(),
                "{change}"
            );
        }
        assert!(next
            .validate(
                &plan,
                (Path::new("/final"), Path::new("/final/expected.json")),
                101
            )
            .is_err());
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    schema_version: u32,
    fixture: PathBuf,
    expected: PathBuf,
    pub(super) native_host: native::Binding,
    #[serde(default)]
    pool_seal: Option<pool_transition::Seal>,
    #[serde(default)]
    arrival_selection: Option<String>,
    /// Deadline since service start for historical sessions, or since the
    /// immutable workflow origin for bounded phases. Queueing and all checks
    /// consume that same original horizon.
    deadline_ms: u64,
}

impl Request {
    pub(super) fn validate_extension(&self, plan: &Plan, now_ms: u64) -> Result<u64, Error> {
        if !plan.pool_prefix_handoff
            || !plan.preseal_only
            || plan.pool_scheduling.is_none()
            || self.schema_version != 1
            || !self.fixture.is_absolute()
            || !self.expected.is_absolute()
            || self.deadline_ms != pool_timing::CANDIDATE_MS
            || self.arrival_selection.as_ref().is_none_or(|id| {
                id.len() != 64
                    || !id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        {
            return Err("pool handoff requires one bounded native sealed selection".into());
        }
        plan.native_host
            .as_ref()
            .ok_or("pool original native binding")?
            .check_prefix_extension(&self.native_host)?;
        self.pool_seal
            .as_ref()
            .ok_or("pool handoff original seal clock")?
            .deadline(
                plan.pool_workflow
                    .as_ref()
                    .ok_or("pool handoff original workflow")?,
                now_ms,
            )
    }

    fn validate(
        &self,
        plan: &Plan,
        initial_inputs: (&Path, &Path),
        now_ms: u64,
    ) -> Result<(), Error> {
        let maximum_candidate_ms = if plan.pool_scheduling.is_some() {
            pool_timing::CANDIDATE_MS
        } else {
            3_600_000
        };
        if self.schema_version != 1
            || self.pool_seal.is_some()
            || self.arrival_selection.is_some()
            || !self.fixture.is_absolute()
            || !self.expected.is_absolute()
            || self.deadline_ms <= now_ms
            || self.deadline_ms.saturating_sub(now_ms) > maximum_candidate_ms
        {
            return Err("pool request version, path, or deadline".into());
        }
        let binding = plan
            .native_host
            .as_ref()
            .ok_or("pool native authority missing")?;
        if plan.pool_workflow.is_some() {
            binding.check_phase(&self.native_host, plan.preseal_only)?;
            if self.deadline_ms != pool_timing::CANDIDATE_MS {
                return Err("bounded pool request changed the original workflow deadline".into());
            }
            // The request selects the immutable, verified startup snapshot.
            // Equal public roots do not authorize another fixture or policy file.
            if self.fixture.as_os_str() != initial_inputs.0.as_os_str()
                || self.expected.as_os_str() != initial_inputs.1.as_os_str()
            {
                return Err("bounded pool request changed its prepared input paths".into());
            }
        } else {
            binding.check_pool_session(&self.native_host)?;
        }
        Ok(())
    }
}

pub(super) fn serve(
    plan: &Plan,
    requests: &Path,
    initial_inputs: (&Path, &Path),
    initial: Prepared,
    owner: DurableDag,
    initial_candidate: Option<lattica_prover_p3::block_v2::execution::dag::CandidateId>,
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
    let qualified = plan.pool_workflow.is_some();
    binding.check_scope(plan.preseal_only)?;
    if plan.preseal_only && !qualified {
        return Err("pool prefix requires the original bounded workflow".into());
    }
    // A bounded service belongs to one native candidate and its original
    // workflow. Subsequent candidates get their own phase lineage and budget.
    let max_requests = if plan.pool_prefix_handoff {
        2
    } else if qualified {
        1
    } else {
        256
    };
    let launches = Arc::new(Mutex::new(launches));
    let mut identities = Vec::new();
    let mut endpoints: Vec<Box<dyn WorkerEndpoint>> = Vec::new();
    let mut timings = Vec::with_capacity(slots.len());
    for slot in slots {
        identities
            .push(json!({"worker":slot.job_worker.0,"pid":slot.worker.pid(),"gpu_uuid":slot.uuid}));
        let mut endpoint = LocalProcessEndpoint::new(slot.worker, launches.clone())?;
        if let Some(timing) = slot.pool_timing {
            endpoint = endpoint
                .with_dispatch_deadline(
                    slot.dispatch_deadline_ms
                        .ok_or("pool dispatch window missing")?,
                )?
                .with_timing_identity(timing.identity)?
                .with_retention_forecast()?;
            timings.push((slot.job_worker, timing));
        }
        endpoints.push(Box::new(endpoint));
    }
    let bootstrap_ms = if plan.pool_scheduling.is_some() {
        pool_timing::SERVICE_MS
    } else {
        300_000
    };
    let (registry, prepared) = initial.into_pool_parts();
    // One bounded phase accepts one exact startup preparation. Historical
    // sessions still release it and independently prepare each later request.
    // The retained selection replaces the former second preparation, and is
    // consumed before any pool.step() can dispatch proving work.
    let mut initial_preparation = qualified.then_some(prepared);
    let mut pool = PoolCoordinator::new(owner, registry, endpoints, bootstrap_ms)?;
    for (worker, timing) in timings {
        timing.install(&mut pool, worker)?;
    }
    publish_json(
        &out.join("pool-ready.json"),
        &json!({"schema_version":1,
        "backend":"typed_local_pool_v1", "workers":identities,"ready_ms":now(),
        "max_requests":max_requests,"native_application_required":true,
        "pool_workflow":plan.pool_workflow,
        "recovered_candidate":plan.recover_from.is_some(),
        "preseal_only":plan.preseal_only,"imported_prefix":!plan.reuse_preseal.is_empty(),
        "candidate_deadline_ms":if qualified {Some(pool_timing::CANDIDATE_MS)} else {None},
        "host_timing_approved":plan.pool_scheduling.is_some(),"bootstrap_ms":bootstrap_ms}),
    )?;
    let mut last_heartbeat = now();
    let mut retained_prefix = None;
    for sequence in 0..max_requests {
        let transition = plan.pool_prefix_handoff && sequence == 1;
        let prefix_only = plan.preseal_only && !transition;
        let request_path = requests.join(format!("{sequence:06}.json"));
        while !request_path.exists() {
            if plan.pool_scheduling.is_some() {
                pool.retire_idle_workers(now())?;
                if pool.workers_closed() {
                    publish_json(
                        &out.join("pool-stopped.json"),
                        &json!({
                        "schema_version":1,"completed_requests":sequence,"stopped_ms":now(),
                        "workers_drained":true,"reason":"dispatch_window_closed"}),
                    )?;
                    return Ok(());
                }
            }
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
        let deadline = if transition {
            request.validate_extension(plan, now())?
        } else {
            request.validate(plan, initial_inputs, now())?;
            request.deadline_ms
        };
        let started = now();
        let prepared = if qualified && !transition {
            initial_preparation
                .take()
                .ok_or("bounded pool preparation already consumed")?
        } else {
            prepare_for_backend(&request.fixture, &request.expected, true)?
                .into_pool_parts()
                .1
        };
        let head = request.native_host.head_for(&prepared.expected)?;
        let root_id = prepared.root();
        let preparation::Submitted {
            candidate,
            expected,
            jobs,
        } = if transition {
            if !pool.idle() || pool.workers_closed() {
                return Err("pool handoff lost its idle live workers".into());
            }
            let (candidate, prefix_root) = retained_prefix
                .take()
                .ok_or("pool handoff lacks completed prefix")?;
            let record = pool_transition::Transition::begin(
                plan,
                &request,
                prefix_root,
                root_id,
                now(),
                out,
            )?;
            let submitted = prepared.seal_prefix_to_pool(&mut pool, candidate, head, now())?;
            record.commit(out)?;
            submitted
        } else if let Some(candidate) = initial_candidate {
            prepared.adopt_to_pool(&mut pool, candidate, head, now(), prefix_only)?
        } else {
            let submitted = prepared.submit_to_pool(
                &mut pool,
                head,
                request.deadline_ms,
                now(),
                prefix_only,
            )?;
            if !prefix_only {
                pool.seal(submitted.candidate, head, now())?;
            }
            submitted
        };
        let result_dir = out.join(format!("candidate-{sequence:06}"));
        std::fs::DirBuilder::new().mode(0o700).create(&result_dir)?;
        publish_json(&result_dir.join("expected.json"), &expected)?;
        drop(expected);
        let mut report = report::Report::new(jobs, plan.workers.len())?;
        let mut prefix_nodes = preseal::pool_output(prefix_only, jobs)?;
        let mut prefix_complete = false;
        let root = loop {
            if requests.join(format!("{sequence:06}.cancel")).exists() {
                pool.retire(candidate, now())?;
                return Err(
                    "native controller cancelled pool candidate; restart after reconciliation"
                        .into(),
                );
            }
            for accepted in pool.step_before(now(), deadline)? {
                report.accepted(accepted)?;
            }
            for (worker, reason) in pool.take_failures() {
                report.failed(worker, reason)?;
            }
            if prefix_only {
                prefix_complete =
                    pool.visit_complete_prefix(candidate, head, now(), |job, proof| {
                        write_bytes(
                            &result_dir.join(preseal::name(job)),
                            proof,
                            profile::MAX_PROOF_BYTES,
                        )?;
                        prefix_nodes.push(preseal::describe(job, proof)?);
                        Ok(())
                    })?;
                if prefix_complete {
                    break None;
                }
            } else if let Some(root) = pool.root(candidate, head, now())? {
                break Some(root);
            }
            if plan.pool_scheduling.is_some() && pool.workers_closed() {
                break None;
            }
            if now().saturating_sub(last_heartbeat) >= 30_000 {
                pool.heartbeat()?;
                last_heartbeat = now();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        report.retained_storage_bytes()?;
        publish_json(&result_dir.join("execution-jobs.json"), &report.jobs())?;
        if root.is_none() && !prefix_complete {
            publish_json(
                &result_dir.join("phase.json"),
                &json!({
                    "schema_version":1,"status":"partial","fresh_proofs":report.jobs().len(),
                    "started_ms":started,"stopped_ms":now(),"deadline_ms":request.deadline_ms,
                    "pool_workflow":plan.pool_workflow,"native_host":request.native_host,
                    "preseal_only":prefix_only,
                    "worker_failures":report.failures(),"workers_drained":true,
                    "candidate_journaled":true,"native_applied":false,
                }),
            )?;
            publish_json(
                &out.join("pool-stopped.json"),
                &json!({
                    "schema_version":1,"completed_requests":0,"stopped_ms":now(),
                    "workers_drained":true,"partial_candidate":true,
                    "reason":"dispatch_window_closed",
                }),
            )?;
            return Ok(());
        }
        let hold_workers = plan.pool_prefix_handoff && prefix_only && prefix_complete;
        if qualified && !hold_workers {
            pool.close(now())?;
            if now() >= deadline {
                return Err("pool workflow expired while draining completed workers".into());
            }
        }
        if let Some(root) = &root {
            write_bytes(
                &result_dir.join(format!("node.{}.0", profile::TREE_DEPTH)),
                root,
                profile::MAX_PROOF_BYTES,
            )?;
        }
        // Publish completion last. It is proof availability, never delivery.
        if qualified && now() >= deadline {
            return Err("pool workflow expired before completion publication".into());
        }
        if prefix_complete {
            if prefix_nodes.len() != jobs
                || result_dir
                    .join(format!("node.{}.0", profile::TREE_DEPTH))
                    .exists()
            {
                return Err("pool prefix output differs from its complete subtrees".into());
            }
            publish_json(
                &result_dir.join("result.json"),
                &report::PrefixCompletion {
                    schema_version: 1,
                    status: "preseal_verified",
                    preseal_only: true,
                    stable_nodes: &prefix_nodes,
                    fresh_proofs: report.jobs().len(),
                    reused_proofs: jobs - report.jobs().len(),
                    started_ms: started,
                    completed_ms: now(),
                    worker_failures: report.failures(),
                    native_host: &request.native_host,
                    pool_workflow: plan
                        .pool_workflow
                        .as_ref()
                        .ok_or("pool prefix workflow missing")?,
                    native_applied: false,
                },
            )?;
        } else {
            publish_json(
                &result_dir.join("result.json"),
                &report.completion(&request.native_host, started, now()),
            )?;
        }
        // A bounded phase publishes proof availability, not application. Keep
        // the sealed candidate and every accepted artifact for independent
        // audit and interrupted delivery recovery under the original deadline.
        if !qualified {
            pool.retire(candidate, now())?;
        }
        if hold_workers {
            if !pool.idle() || pool.workers_closed() {
                return Err("pool prefix completion did not retain idle live workers".into());
            }
            retained_prefix = Some((candidate, root_id));
        }
    }
    pool.close(now())?;
    publish_json(
        &out.join("pool-stopped.json"),
        &json!({"schema_version":1,
        "completed_requests":max_requests,"stopped_ms":now(),"workers_drained":true}),
    )?;
    Ok(())
}
