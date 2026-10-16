//! One durable candidate DAG dispatching to separately bounded GPU services.
use super::*;
#[path = "execution_bootstrap.rs"]
mod bootstrap;
#[path = "execution_native.rs"]
mod native;
#[path = "execution_pool_calibration.rs"]
mod pool_calibration;
#[path = "execution_pool_service.rs"]
mod pool_service;
#[path = "execution_pool_timing.rs"]
mod pool_timing;
#[path = "execution_pool_transition.rs"]
mod pool_transition;
#[path = "execution_preseal.rs"]
mod preseal;
#[path = "execution_fleet_recover.rs"]
mod recovery;
#[path = "execution_fleet_storage.rs"]
mod storage;

pub(super) fn coordinator_storage_probe() -> Result<(), Error> {
    storage::probe()
}
use lattica_prover_p3::block_v2::execution::{
    dag::{Completion, Lease, WorkerId},
    job::JobId,
    launch::{LaunchLimits, LaunchStore, MAX_REQUEST_BYTES},
    scheduler::{CostModel, WorkerCapabilities},
    startup,
    transport::image_fingerprint,
    worker::typed::process::ProcessWorker,
};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::OpenOptions,
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    #[serde(default)]
    pool_calibration: Option<pool_calibration::Request>,
    #[serde(default)]
    pool_requests: Option<PathBuf>,
    #[serde(default)]
    pool_scheduling: Option<pool_timing::Window>,
    #[serde(default)]
    pool_workflow: Option<pool_timing::Workflow>,
    #[serde(default)]
    coordinator_bootstrap_guard: Option<PathBuf>,
    #[serde(default)]
    startup_fenced: bool,
    #[serde(default)]
    allow_worker_failover: bool,
    #[serde(default)]
    recover_from: Option<PathBuf>,
    #[serde(default)]
    recover_cached_only: bool,
    #[serde(default)]
    preseal_only: bool,
    #[serde(default)]
    pool_prefix_handoff: bool,
    #[serde(default)]
    reuse_preseal: Vec<PathBuf>,
    schema_version: u32,
    coordinator_unit: String,
    coordinator_ram_bytes: u64,
    coordinator_shared_bytes: u64,
    coordinator_threads: u32,
    fleet_bytes: u64,
    workers: Vec<Worker>,
    #[serde(default)]
    native_host: Option<native::Binding>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Worker {
    #[serde(default)]
    pool_timing: Option<PathBuf>,
    assignment: serde_json::Value,
    launcher: Vec<String>,
    arguments: Vec<String>,
    log: PathBuf,
}

struct Slot {
    pool_timing: Option<pool_timing::Loaded>,
    dispatch_deadline_ms: Option<u64>,
    index: usize,
    worker: ProcessWorker,
    peak: Resources,
    jobs: Resources,
    job_worker: WorkerId,
    uuid: String,
    unit: String,
    active: Option<(JobId, Lease, Instant)>,
    resident_mode: Option<u64>,
}

fn startup_intent(worker: &Worker) -> Result<startup::Intent, Error> {
    Ok(startup::Intent {
        schema_version: 1,
        unit: worker.assignment["unit"]
            .as_str()
            .ok_or("startup worker unit missing")?
            .to_owned(),
        executable: image_fingerprint(&std::env::current_exe()?)?,
        arguments: worker.arguments.clone(),
        assignment: worker.assignment.clone(),
    })
}

fn validate_plan(plan: &Plan) -> Result<Vec<(Resources, Resources)>, Error> {
    let resources = validate_plan_shape(plan)?;
    if let Some(window) = &plan.pool_scheduling {
        window.deadline(0)?;
    }
    if let Some(workflow) = &plan.pool_workflow {
        workflow.validate_live()?;
    }
    Ok(resources)
}

// Historical service windows are normally expired at recovery. Their shape
// and immutable workflow binding remain mandatory; only the new launch is live.
fn validate_plan_shape(plan: &Plan) -> Result<Vec<(Resources, Resources)>, Error> {
    let calibration = plan.pool_calibration.is_some();
    let bounded = plan.pool_scheduling.is_some();
    let qualified = bounded && !calibration;
    if plan.pool_prefix_handoff
        && (!qualified
            || !plan.preseal_only
            || plan.pool_requests.is_none()
            || plan.recover_cached_only
            || !plan.reuse_preseal.is_empty())
    {
        return Err("prefix handoff requires one bounded native prefix pool".into());
    }
    if bounded != plan.pool_workflow.is_some()
        || (qualified && plan.pool_requests.is_none())
        || plan
            .workers
            .iter()
            .any(|w| w.pool_timing.is_some() != qualified)
        || plan
            .workers
            .iter()
            .filter_map(|w| w.pool_timing.as_ref())
            .any(|p| !p.is_absolute())
    {
        return Err(
            "pool scheduling requires one host timing approval per worker and a pool session"
                .into(),
        );
    }
    if let Some(request) = &plan.pool_calibration {
        request.validate()?;
        if !bounded
            || plan.workers.len() != 1
            || plan.pool_requests.is_some()
            || plan.recover_from.is_some()
            || plan.recover_cached_only
            || plan.preseal_only
            || !plan.reuse_preseal.is_empty()
            || plan.allow_worker_failover
            || !plan.startup_fenced
            || plan.coordinator_bootstrap_guard.is_none()
            || plan.coordinator_threads != 4
        {
            return Err("calibration requires one fresh bounded startup-fenced worker without recovery, pooling or failover".into());
        }
    }
    if let Some(window) = &plan.pool_scheduling {
        plan.pool_workflow.as_ref().unwrap().check_window(window)?;
    }
    if let Some(requests) = &plan.pool_requests {
        if !requests.is_absolute()
            || plan.native_host.is_none()
            || (plan.recover_from.is_some() && !qualified)
            || plan.recover_cached_only
            || ((plan.preseal_only || !plan.reuse_preseal.is_empty()) && !qualified)
            || (plan.preseal_only && !plan.reuse_preseal.is_empty())
        {
            return Err(
                "pool requires a native binding; only bounded phases support recovery".into(),
            );
        }
    }

    if plan.recover_cached_only && plan.recover_from.is_none() {
        return Err("cached-only continuation requires coordinator recovery".into());
    }
    if let Some(source) = &plan.recover_from {
        if !source.is_absolute()
            || plan.native_host.is_none()
            || ((plan.preseal_only || !plan.reuse_preseal.is_empty()) && !qualified)
        {
            return Err("coordinator recovery requires the original native scope and an absolute prior owner directory; prefixes require bounded pooling".into());
        }
    }
    if plan.allow_worker_failover && (plan.native_host.is_none() || plan.workers.len() < 2) {
        return Err(
            "worker failover requires a native binding and at least two assigned GPUs".into(),
        );
    }
    if (plan.preseal_only || !plan.reuse_preseal.is_empty()) && plan.native_host.is_none() {
        return Err("pre-seal work requires a verified native head".into());
    }
    if plan.reuse_preseal.len() > 64 || plan.reuse_preseal.iter().any(|p| !p.is_absolute()) {
        return Err("invalid bounded pre-seal cache paths".into());
    }
    if let Some(binding) = &plan.native_host {
        binding.check_scope(plan.preseal_only)?;
    }
    if plan.schema_version != 2 || plan.coordinator_threads == 0 {
        return Err("shared typed coordinator plan version or CPU assignment".into());
    }
    let known = if plan.pool_requests.is_some() && !qualified {
        storage::KnownShared::persistent(plan.workers.len())?
    } else {
        storage::KnownShared::new(plan.workers.len())?
    };
    known.admit(plan.coordinator_shared_bytes)?;
    let mut devices = BTreeSet::new();
    let mut services = BTreeSet::new();
    let mut resources = Vec::new();
    for worker in &plan.workers {
        let a = &worker.assignment;
        if a.get("native_host").unwrap_or(&serde_json::Value::Null)
            != &serde_json::to_value(&plan.native_host)?
        {
            return Err("worker assignment differs from the native host snapshot".into());
        }
        let uuid = a["gpu"]["uuid"]
            .as_str()
            .ok_or("shared typed worker GPU UUID missing")?;
        let unit = a["unit"]
            .as_str()
            .ok_or("shared typed worker service missing")?;
        if !devices.insert(uuid)
            || !services.insert(unit)
            || a["host"]["coordinator_bytes"].as_u64() != Some(plan.coordinator_ram_bytes)
            || a["host"]["coordinator_shared_bytes"].as_u64() != Some(plan.coordinator_shared_bytes)
            || a["host"]["fleet_bytes"].as_u64() != Some(plan.fleet_bytes)
            || worker.launcher.is_empty()
            || !Path::new(&worker.launcher[0]).is_absolute()
            || !worker.log.is_absolute()
        {
            return Err("shared typed worker identity or host assignment differs".into());
        }
        resources.push(budget::resources(a)?);
    }
    if calibration
        && resources
            .iter()
            .any(|(peak, _)| peak.ram_bytes > 3 << 30 || peak.threads != 4)
    {
        return Err("calibration requires the original worker RAM and four-thread limits".into());
    }
    let limits = budget::fleet_limits(&resources)?;
    let packet_bytes = resources.iter().try_fold(0u64, |sum, (_, jobs)| {
        sum.checked_add(jobs.ram_bytes)
            .ok_or("shared packet RAM overflow")
    })?;
    let total_fleet_bytes = limits
        .workers
        .ram_bytes
        .checked_add(plan.coordinator_shared_bytes)
        .ok_or("shared fleet RAM overflow")?;
    let total_coordinator_bytes = packet_bytes
        .checked_add(plan.coordinator_shared_bytes)
        .ok_or("shared coordinator RAM overflow")?;
    if total_fleet_bytes > plan.fleet_bytes || total_coordinator_bytes != plan.coordinator_ram_bytes
    {
        return Err("shared typed packet/workspace reservations differ from physical fleet".into());
    }
    Ok(resources)
}

fn coordinator_fleet_parent(parent: &Path, bounded: bool) -> Result<&Path, Error> {
    if !bounded {
        return Ok(parent);
    }
    if parent.file_name().and_then(|v| v.to_str()) != Some("lattica-v2-multi-coordinator.slice")
        || std::fs::read_to_string(parent.join("memory.max"))?.trim() != (1u64 << 30).to_string()
        || std::fs::read_to_string(parent.join("memory.swap.max"))?.trim() != "0"
    {
        return Err(
            "bounded controller and coordinator must share the original 1 GiB allowance".into(),
        );
    }
    let fleet = parent
        .parent()
        .ok_or("bounded coordinator fleet slice missing")?;
    for group in [parent, fleet] {
        let cpu = std::fs::read_to_string(group.join("cpu.max"))?;
        let fields = cpu.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2
            || fields[0].parse::<u64>()?
                != fields[1]
                    .parse::<u64>()?
                    .checked_mul(4)
                    .ok_or("CPU limit overflow")?
        {
            return Err("bounded native fleet requires four aggregate CPU threads".into());
        }
    }
    Ok(fleet)
}

fn require_coordinator(plan: &Plan) -> Result<(), Error> {
    if plan.pool_workflow.is_some()
        && (plan.coordinator_ram_bytes != 1 << 30 || plan.fleet_bytes != 4 << 30)
    {
        return Err(
            "bounded native host assignment differs from the original 1/4 GiB limits".into(),
        );
    }
    require_cpu_limit(plan.coordinator_ram_bytes)?;
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = membership
        .trim()
        .strip_prefix("0::")
        .ok_or("shared coordinator cgroup v2 required")?;
    let group = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let parent = group
        .parent()
        .ok_or("shared coordinator fleet slice missing")?;
    let fleet = coordinator_fleet_parent(parent, plan.pool_workflow.is_some())?;
    if !plan.coordinator_unit.starts_with("lattica-v2-multi-owner-")
        || !plan.coordinator_unit.ends_with(".service")
        || group.file_name().and_then(|v| v.to_str()) != Some(plan.coordinator_unit.as_str())
        || fleet.file_name().and_then(|v| v.to_str()) != Some("lattica-v2-multi.slice")
        || std::fs::read_to_string(fleet.join("memory.max"))?
            .trim()
            .parse::<u64>()?
            != plan.fleet_bytes
        || std::fs::read_to_string(fleet.join("memory.swap.max"))?.trim() != "0"
        || rayon::current_num_threads() != plan.coordinator_threads as usize
    {
        return Err("shared coordinator physical assignment differs".into());
    }
    let cpu = std::fs::read_to_string(group.join("cpu.max"))?;
    let values: Vec<_> = cpu.split_whitespace().collect();
    if values.len() != 2
        || values[0].parse::<u64>()?
            != values[1]
                .parse::<u64>()?
                .checked_mul(u64::from(plan.coordinator_threads))
                .ok_or("coordinator CPU overflow")?
    {
        return Err("shared coordinator CPU quota differs".into());
    }
    Ok(())
}

fn workspace_resources(peak: Resources) -> Resources {
    Resources { threads: 0, ..peak }
}

fn expected_usage(slots: &[Slot]) -> Result<Resources, Error> {
    let mut usage = Resources::default();
    for slot in slots {
        usage = budget::add_resources(usage, workspace_resources(slot.peak))?;
        if slot.active.is_some() {
            usage = budget::add_resources(usage, slot.jobs)?;
        }
    }
    Ok(usage)
}

pub(in super::super) fn audit_preseal(
    dir: &Path,
    pinned: &Path,
    nodes: &Path,
    out: &Path,
) -> Result<(), Error> {
    preseal::audit(dir, pinned, nodes, out)
}

pub(in super::super) fn audit_pool_calibration(
    dir: &Path,
    pinned: &Path,
    request: &Path,
    nodes: &Path,
    out: &Path,
) -> Result<(), Error> {
    pool_calibration::audit::run(dir, pinned, request, nodes, out)
}

fn start_fleet(
    plan: &Plan,
    prepared: &Prepared,
    owner: &mut DurableDag,
    durable_runtime: &Path,
    runtime: &Path,
    dir: &Path,
    pinned: &Path,
    out: &Path,
    bootstrap: Option<bootstrap::Entry>,
    now: impl Fn() -> u64,
) -> Result<(LaunchStore, Vec<Slot>), Error> {
    let assignments = validate_plan(plan)?;
    let dispatch_deadline_ms = plan
        .pool_scheduling
        .as_ref()
        .map(|w| w.deadline(now()))
        .transpose()?;
    let timing_executable = if plan.pool_scheduling.is_some() && plan.pool_calibration.is_none() {
        Some(image_fingerprint(&std::env::current_exe()?)?)
    } else {
        None
    };
    let launch_directory = durable_runtime.join("launches");
    let launches = if plan.recover_from.is_some() {
        LaunchStore::open(
            &launch_directory,
            LaunchLimits {
                records: if plan.pool_requests.is_some() {
                    16384
                } else {
                    256
                },
            },
        )?
    } else {
        LaunchStore::create(
            &launch_directory,
            LaunchLimits {
                records: if plan.pool_requests.is_some() {
                    16384
                } else {
                    256
                },
            },
        )?
    };
    let mut slots = Vec::new();
    if plan.startup_fenced && !plan.recover_cached_only {
        for (index, worker) in plan.workers.iter().enumerate() {
            let gate = runtime.join(format!("worker-{index}-startup"));
            if worker.assignment["startup_guard"].as_str() != gate.to_str() {
                return Err("worker startup gate differs from the admitted owner directory".into());
            }
            startup::create(&gate, &startup_intent(worker)?)?;
        }
    }
    if let Some(bootstrap) = bootstrap {
        bootstrap.complete(out)?;
    }
    for (index, (spec, &(peak, jobs))) in plan
        .workers
        .iter()
        .zip(&assignments)
        .enumerate()
        .filter(|_| !plan.recover_cached_only)
    {
        let unit = spec.assignment["unit"].as_str().unwrap();
        let expected = vec![
            OsString::from("serve-shared-process-gpu"),
            dir.as_os_str().to_owned(),
            pinned.as_os_str().to_owned(),
            launch_directory.as_os_str().to_owned(),
            OsString::from(peak.ram_bytes.to_string()),
        ];
        let arguments: Vec<OsString> = spec.arguments.iter().map(OsString::from).collect();
        if arguments != expected {
            return Err("shared worker command differs from owner inputs".into());
        }
        let id = u64::try_from(index + 1)? * 2;
        let job_worker = WorkerId(id);
        let config = process::assigned_config(prepared, &spec.assignment)?;
        let mut worker =
            ProcessWorker::prepare(owner, config, WorkerId(id - 1), job_worker, now())?;
        let timing = match (&spec.pool_timing, timing_executable) {
            (Some(path), Some(executable)) => {
                let timing = pool_timing::Loaded::load(
                    path,
                    executable,
                    spec.assignment["gpu"]["uuid"].as_str().unwrap(),
                )?;
                timing.check(&worker)?;
                Some(timing)
            }
            (None, None) => None,
            _ => return Err("pool timing launch configuration mismatch".into()),
        };
        write_bytes(
            &runtime.join(format!("worker-{index}.session")),
            worker.session_bytes(),
            4096,
        )?;
        if plan.startup_fenced {
            startup::authorize(
                &runtime.join(format!("worker-{index}-startup")),
                &startup_intent(spec)?,
                worker.execution_digest()?,
            )?;
        }
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&spec.log)?;
        let mut launcher = Command::new(&spec.launcher[0]);
        launcher
            .args(&spec.launcher[1..])
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        worker.start_supervised(launcher, unit, &arguments)?;
        let identity = worker
            .service_identity()
            .ok_or("shared worker identity absent")?;
        write_json(
            &runtime.join(format!("worker-{index}-start.json")),
            &json!({
                "schema_version":1,"worker_pid":worker.pid(),"coordinator_pid":std::process::id(),
                "os_identity":identity,"job_worker":id,"workspace_worker":id-1,
                "unit":unit,"cgroup":identity.cgroup(),"invocation":hex(&identity.invocation()),
                "boot_id":hex(&identity.boot_id()),"start_ticks":identity.start_ticks(),
                "cgroup_device":identity.cgroup_device(),"cgroup_inode":identity.cgroup_inode(),
                "execution_digest":hex(&worker.execution_digest()?),
                "workspace_reserved":true,"assignment":spec.assignment,
            }),
        )?;
        slots.push(Slot {
            pool_timing: timing,
            dispatch_deadline_ms,
            index,
            worker,
            peak,
            jobs,
            job_worker,
            uuid: spec.assignment["gpu"]["uuid"].as_str().unwrap().to_owned(),
            unit: unit.to_owned(),
            active: None,
            resident_mode: None,
        });
    }
    Ok((launches, slots))
}

pub(in super::super) fn prove(
    dir: &Path,
    pinned: &Path,
    plan_path: &Path,
    out: &Path,
) -> Result<(), Error> {
    if !PAIRED {
        return Err("shared typed execution requires paired construction".into());
    }
    let started = Instant::now();
    let plan: Plan = read_json(plan_path)?;
    let assignments = validate_plan(&plan)?;
    require_coordinator(&plan)?;
    let bootstrap = bootstrap::enter(&plan, plan_path, out)?;
    let clock = pool_timing::Clock::new(plan.pool_workflow.as_ref(), started)?;
    let now = || clock.now();
    let prepared = prepare_for_backend(dir, pinned, true)?;
    if plan.pool_workflow.is_some() && now() >= pool_timing::CANDIDATE_MS {
        return Err("pool workflow expired during preparation".into());
    }
    let mut limits = budget::fleet_limits(&assignments)?;
    if plan.pool_requests.is_some() || plan.pool_calibration.is_some() {
        pool_service::configure_limits(&mut limits, plan.pool_scheduling.is_some());
    }
    std::fs::DirBuilder::new().mode(0o700).create(out)?;
    write_json(&out.join("expected.json"), &prepared.expected)?;
    write_json(&out.join("execution-plan.json"), &describe(&prepared))?;
    let runtime = out.join("execution");
    std::fs::DirBuilder::new().mode(0o700).create(&runtime)?;
    // Fixture qualification only. Native intake must supply a verified head token.
    let head = match &plan.native_host {
        Some(binding) => binding.head_for(&prepared.expected)?,
        None => prepared.expected.profile,
    };
    let (mut owner, recovery_state, recovered_candidate) = if let Some(source) = &plan.recover_from
    {
        let (owner, state, candidate) =
            recovery::restore(source, &plan, &prepared, head, now, out)?;
        (owner, state, Some(candidate))
    } else {
        let store = ArtifactStore::create(
            &runtime.join("artifacts"),
            pool_service::store_limits(
                plan.pool_requests.is_none() || plan.pool_scheduling.is_some(),
            ),
        )?;
        (
            DurableDag::create(
                &runtime.join("journal"),
                pool_service::journal_limits(
                    plan.pool_requests.is_none() || plan.pool_scheduling.is_some(),
                ),
                store,
                prepared.pin,
                prepared.expected.chain,
                1,
                limits,
            )?,
            recovery::initial(&runtime),
            None,
        )
    };
    if let Some(request) = &plan.pool_calibration {
        recovery::record(&plan, &recovery_state, out)?;
        let candidate =
            prepared
                .selection
                .attach(&mut owner, head, pool_timing::CANDIDATE_MS, now())?;
        owner.seal(candidate, head, now())?;
        request.prepare(&prepared, &mut owner, now)?;
        let (launches, slots) = start_fleet(
            &plan,
            &prepared,
            &mut owner,
            &recovery_state.durable_runtime,
            &runtime,
            dir,
            pinned,
            out,
            bootstrap,
            now,
        )?;
        return pool_calibration::run(&plan, request, prepared, owner, launches, slots, out, now);
    }
    if let Some(requests) = &plan.pool_requests {
        if recovered_candidate.is_none() {
            recovery::record(&plan, &recovery_state, out)?;
        }
        let initial_candidate = if recovered_candidate.is_none() && !plan.reuse_preseal.is_empty() {
            let workflow = plan
                .pool_workflow
                .as_ref()
                .ok_or("prefix import requires a bounded pool")?;
            let candidate =
                prepared
                    .selection
                    .attach(&mut owner, head, pool_timing::CANDIDATE_MS, now())?;
            owner.seal(candidate, head, now())?;
            let reused = preseal::import(
                &plan.reuse_preseal,
                plan.native_host.as_ref(),
                &prepared,
                &mut owner,
                out,
                now,
                Some(workflow),
            )?;
            write_json(&out.join("execution-reused.json"), &reused)?;
            Some(candidate)
        } else {
            recovered_candidate
        };
        let (launches, slots) = start_fleet(
            &plan,
            &prepared,
            &mut owner,
            &recovery_state.durable_runtime,
            &runtime,
            dir,
            pinned,
            out,
            bootstrap,
            now,
        )?;
        return pool_service::serve(
            &plan,
            requests,
            (dir, pinned),
            prepared,
            owner,
            initial_candidate,
            launches,
            slots,
            out,
            now,
        );
    }
    let candidate = if let Some(candidate) = recovered_candidate {
        candidate
    } else {
        recovery::record(&plan, &recovery_state, out)?;
        let candidate = prepared
            .selection
            .attach(&mut owner, head, now() + 3_600_000, now())?;
        if !plan.preseal_only {
            owner.seal(candidate, head, now())?;
        } else if !prepared.selection.jobs().any(preseal::stable) {
            return Err("no complete subtrees are available for pre-seal proving".into());
        }
        candidate
    };
    let reused = if plan.recover_from.is_some() {
        recovery::export(&owner, &prepared, &recovery_state, out)?
    } else {
        preseal::import(
            &plan.reuse_preseal,
            plan.native_host.as_ref(),
            &prepared,
            &mut owner,
            out,
            now,
            None,
        )?
    };
    write_json(&out.join("execution-reused.json"), &reused)?;
    let all_cached = reused.len()
        == prepared
            .selection
            .jobs()
            .filter(|job| !plan.preseal_only || preseal::stable(job))
            .count();
    if plan.recover_cached_only && !all_cached {
        return Err("cached-only recovery has missing proofs; no GPU worker was started".into());
    }
    if all_cached && !plan.recover_cached_only {
        return Err("all requested subtrees are already cached; no GPU phase is needed".into());
    }
    let (mut launches, mut slots) = start_fleet(
        &plan,
        &prepared,
        &mut owner,
        &recovery_state.durable_runtime,
        &runtime,
        dir,
        pinned,
        out,
        bootstrap,
        now,
    )?;
    let jobs: BTreeMap<_, _> = prepared
        .selection
        .jobs()
        .filter(|job| !plan.preseal_only || preseal::stable(job))
        .map(|job| (job.id(), job.clone()))
        .collect();
    let mut records = Vec::new();
    let mut retired = Vec::new();
    let mut maximum_active = 0;
    // Conservative bootstrap assumptions, not measured qualification. Costs are
    // scoped to this exact binary/profile/fleet and learned from accepted jobs.
    let mut costs = CostModel::new(300_000)?;
    while records.len() + reused.len() < jobs.len() {
        let mut progress = false;
        loop {
            let idle: Vec<_> = slots
                .iter()
                .filter(|s| s.active.is_none())
                .map(|s| WorkerCapabilities {
                    worker: s.job_worker,
                    profile: prepared.pin.profile(),
                    resources: s.jobs,
                    resident_mode: s.resident_mode,
                    timing_identity: None,
                    forecast_retained_mode: false,
                    dispatch_deadline_ms: None,
                })
                .collect();
            if idle.is_empty() {
                break;
            }
            let mut ready = owner.ready()?;
            ready.retain(|id| jobs.contains_key(id));
            let deadlines = ready
                .iter()
                .map(|id| Ok((*id, owner.job_deadline(*id)?)))
                .collect::<Result<BTreeMap<_, _>, Error>>()?;
            let Some(choice) = costs.select(&jobs, &ready, &idle, &deadlines, now())? else {
                break;
            };
            let slot = slots
                .iter_mut()
                .find(|s| s.job_worker == choice.worker)
                .ok_or("scheduler selected absent worker")?;
            let id = choice.job;
            let job = &jobs[&id];
            let lease = owner.lease(
                id,
                slot.job_worker,
                slot.jobs,
                choice.remaining_path_ms,
                choice.service_ms.saturating_mul(2).clamp(30_000, 600_000),
                now(),
            )?;
            let task = slot.worker.task(&mut owner, lease, now())?;
            let request = task.request()?;
            let stem = format!(
                "node.{}.{}",
                job.expected().level,
                job.start() as usize >> job.expected().level
            );
            write_bytes(
                &runtime.join(format!("{stem}.{}.request", hex(&lease.process_key()?))),
                &request,
                MAX_REQUEST_BYTES,
            )?;
            let token = launches.issue_bound(
                &mut owner,
                lease,
                &request,
                slot.worker.execution_digest()?,
            )?;
            slot.worker.dispatch(&token, task)?;
            slot.active = Some((id, lease, Instant::now()));
            println!(
                "{}",
                json!({"event":"shared_typed_job_dispatched","job":hex(&id.to_bytes()),
                "worker_pid":slot.worker.pid(),"gpu_uuid":slot.uuid,"level":job.expected().level,
                    "index":job.start() as usize >> job.expected().level,"coordinator_pid":std::process::id(),
                "dispatched_ms":now(),"estimated_service_ms":choice.service_ms,
                "estimated_remaining_path_ms":choice.remaining_path_ms,
                "estimate_measured":choice.measured,"estimated_cache_hit":choice.warm})
            );
            progress = true;
        }
        maximum_active =
            maximum_active.max(slots.iter().filter(|slot| slot.active.is_some()).count());
        let mut failed_slots = Vec::new();
        for slot in &mut slots {
            let collected = match slot.worker.try_collect() {
                Ok(value) => value,
                Err(error) if plan.allow_worker_failover => {
                    let (job, lease, _) = slot
                        .active
                        .ok_or("failed worker has no active assignment")?;
                    let stats = slot.worker.stop_failed_supervised(
                        &mut owner,
                        &mut launches,
                        lease,
                        now,
                    )?;
                    let record = json!({"schema_version":1,"worker_failed":true,
                        "worker_pid":slot.worker.pid(),"coordinator_pid":std::process::id(),
                        "gpu_uuid":slot.uuid,"unit":slot.unit,"exit_code":null,
                        "gpu_teardown_confirmed":true,"teardown_method":"process_and_cgroup_exit",
                        "forced_stop_confirmed":true,"launch_revoked":true,
                        "workspace_released":true,"process_and_cgroup_quiescent":true,
                        "cache_setups":stats.setups,"cache_hits":stats.hits,
                        "failed_job":hex(&job.to_bytes()),"lease_key":hex(&lease.process_key()?),
                        "reconciled_ms":now(),"failure":error.to_string().chars().take(2048).collect::<String>()});
                    write_json(
                        &runtime.join(format!("worker-{}-exit.json", slot.index)),
                        &record,
                    )?;
                    println!(
                        "{}",
                        json!({"event":"shared_typed_worker_failed","record":record})
                    );
                    slot.active = None;
                    failed_slots.push(slot.index);
                    retired.push(record);
                    progress = true;
                    None
                }
                Err(error) => return Err(error),
            };
            let Some(completed) = collected else {
                continue;
            };
            let (id, lease, stage) = slot
                .active
                .take()
                .ok_or("shared worker returned an unassigned result")?;
            if completed.lease() != lease {
                return Err("shared worker lease substitution".into());
            }
            let revoked = launches.revoke(lease)?;
            let _idle = launches
                .try_idle(&revoked)?
                .ok_or("shared worker launch active after response")?;
            let output = completed.reconcile(&mut owner, now())?;
            let expected = owner.begin_verification(lease, now())?;
            let ticket = VerifiedNode::verify_typed(&expected, &prepared.registry, output.bytes())?;
            if owner.finish_verification(lease, Some((ticket, output.bytes().to_vec())), now())?
                != Completion::Accepted
            {
                return Err("shared DAG rejected independently verified worker output".into());
            }
            let job = &jobs[&id];
            let stem = format!(
                "node.{}.{}",
                job.expected().level,
                job.start() as usize >> job.expected().level
            );
            write_bytes(&out.join(&stem), output.bytes(), profile::MAX_PROOF_BYTES)?;
            let stats = output.stats();
            let timing = output.timings();
            costs.observe(
                &WorkerCapabilities {
                    worker: slot.job_worker,
                    profile: prepared.pin.profile(),
                    resources: slot.jobs,
                    resident_mode: slot.resident_mode,
                    timing_identity: None,
                    forecast_retained_mode: false,
                    dispatch_deadline_ms: None,
                },
                job,
                stats.hits == 1,
                u64::try_from(stage.elapsed().as_millis())?.max(1),
            )?;
            slot.resident_mode = Some(job.expected_public()[programs::MODE].as_canonical_u64());
            let record = json!({"event":"fresh_typed_node","job":hex(&id.to_bytes()),
                "worker_pid":slot.worker.pid(),"gpu_uuid":slot.uuid,"level":job.expected().level,
                "index":job.start() as usize >> job.expected().level,"count":job.expected().count,
                "mode":job.expected_public()[programs::MODE].as_canonical_u64(),
                "bytes":output.bytes().len(),"seconds":stage.elapsed().as_secs_f64(),"accepted_ms":now(),
                "cache_setups":stats.setups,"cache_hits":stats.hits,
                "input_verification_ms":timing.input_verification_ms,"proving_ms":timing.proving_ms,
                "serialization_ms":timing.serialization_ms});
            println!("{record}");
            records.push(record);
            progress = true;
        }
        slots.retain(|slot| !failed_slots.contains(&slot.index));
        if slots.is_empty() {
            return Err("no surviving GPU workers; failed work remains unproved".into());
        }
        if owner.resource_use()? != expected_usage(&slots)? {
            return Err("shared DAG workspace or in-flight reservation mismatch".into());
        }
        if !progress {
            if slots.iter().all(|slot| slot.active.is_none()) {
                return Err("shared typed DAG has no executable work".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    if slots.iter().any(|slot| slot.active.is_some()) {
        return Err("shared DAG finished with active work".into());
    }
    if !plan.preseal_only {
        let root = bytes(&out.join(profile::ROOT_FILE))?;
        if owner.candidate_result(candidate, head, now())?.as_deref() != Some(root.as_slice()) {
            return Err("shared DAG root differs from accepted proof".into());
        }
    } else if out.join(profile::ROOT_FILE).exists() {
        return Err("unsealed subtree work unexpectedly exported a candidate root".into());
    }
    let mut workers = Vec::new();
    for slot in &mut slots {
        let stats = slot.worker.stats()?;
        slot.worker.close(&mut owner, now())?;
        let record = json!({"schema_version":1,"worker_pid":slot.worker.pid(),
            "coordinator_pid":std::process::id(),"gpu_uuid":slot.uuid,"unit":slot.unit,
            "exit_code":0,"gpu_teardown_confirmed":true,"workspace_released":true,
            "process_and_cgroup_quiescent":true,"cache_setups":stats.setups,"cache_hits":stats.hits});
        write_json(
            &runtime.join(format!("worker-{}-exit.json", slot.index)),
            &record,
        )?;
        workers.push(record);
    }
    if owner.resource_use()? != Resources::default() {
        return Err("shared workspace reservation survived teardown".into());
    }
    write_json(&out.join("execution-jobs.json"), &records)?;
    let failed_workers = retired.len();
    workers.extend(retired);
    write_json(
        &out.join("result.json"),
        &json!({"schema_version":1,"status":if plan.preseal_only {"preseal_verified"} else {"proved_cpu_audit_pending"},
            "allow_worker_failover":plan.allow_worker_failover,"failed_workers":failed_workers,
            "cached_native_continuation":plan.recover_cached_only,
            "gpu_workers_started":workers.len(),
            "recovery_epoch":recovery_state.epoch,"coordinator_recovery":if plan.recover_from.is_some() {
                Some(read_json::<serde_json::Value>(&out.join("coordinator-recovery.json"))?)
            } else {None},
            "preseal_only":plan.preseal_only,"reused_proofs":reused.len(),
            "reused_nodes":reused,"stable_nodes":if plan.preseal_only {
                jobs.values().map(|job| preseal::describe(job, &bytes(&out.join(preseal::name(job)))?))
                    .collect::<Result<Vec<_>, Error>>()?
            } else {Vec::new()},
        "execution_backend":"typed_shared_process_dag_v1","shared_dag_owner":true,
        "native_host_bound":plan.native_host.is_some(),"native_host":plan.native_host,
        "coordinator_pid":std::process::id(),"workers":workers,"maximum_active_jobs":maximum_active,
        "count":prepared.expected.count,"construction":CONSTRUCTION,"registry_keys":KEY_COUNT,
        "fresh_proofs":records.len(),"cpu_verified_nodes":records.len(),"seconds":started.elapsed().as_secs_f64(),
            "root_file":if plan.preseal_only {None} else {Some(profile::ROOT_FILE)},
            "backend":if plan.recover_cached_only {"cpu"} else {"gpu"},"worker_processes_exited":true,
        "workspace_released_after_gpu_teardown":true,"arrival_backend_integrated":false,
        "durable_host_applied":false,"production_ready":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_control_processes_share_one_host_and_cpu_allowance() {
        let directory =
            std::env::temp_dir().join(format!("lattica-native-budget-{}", std::process::id()));
        let fleet = directory.join("lattica-v2-multi.slice");
        let controls = fleet.join("lattica-v2-multi-coordinator.slice");
        std::fs::create_dir_all(&controls).unwrap();
        std::fs::write(controls.join("memory.max"), (1u64 << 30).to_string()).unwrap();
        std::fs::write(controls.join("memory.swap.max"), "0").unwrap();
        for group in [&controls, &fleet] {
            std::fs::write(group.join("cpu.max"), "400000 100000").unwrap();
        }
        assert_eq!(coordinator_fleet_parent(&controls, true).unwrap(), fleet);
        assert_eq!(coordinator_fleet_parent(&fleet, false).unwrap(), fleet);
        assert!(coordinator_fleet_parent(&fleet, true).is_err());
        std::fs::write(controls.join("memory.max"), (2u64 << 30).to_string()).unwrap();
        assert!(coordinator_fleet_parent(&controls, true).is_err());
        std::fs::write(controls.join("memory.max"), (1u64 << 30).to_string()).unwrap();
        std::fs::write(controls.join("memory.swap.max"), "1").unwrap();
        assert!(coordinator_fleet_parent(&controls, true).is_err());
        std::fs::write(controls.join("memory.swap.max"), "0").unwrap();
        for group in [&controls, &fleet] {
            std::fs::write(group.join("cpu.max"), "max 100000").unwrap();
            assert!(coordinator_fleet_parent(&controls, true).is_err());
            std::fs::write(group.join("cpu.max"), "400000 100000").unwrap();
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    pub(super) fn plan() -> Plan {
        let workers = (0..2)
            .map(|index| Worker {
                pool_timing: None,
                assignment: json!({"gpu":{"uuid":format!("GPU-{index}"),"managed_bytes":1u64 << 30},
                "host":{"worker_bytes":4u64 << 30,"spill_bytes":2u64 << 30,
                "coordinator_bytes":2u64 << 30,"coordinator_job_bytes":((2u64 << 30) - storage::shared_reservation(2)) / 2,
                "coordinator_shared_bytes":storage::shared_reservation(2),"fleet_bytes":10u64 << 30},
                "cpu":{"rayon_threads":4-index},"unit":format!("worker-{index}")}),
                launcher: vec!["/usr/bin/python3".into()],
                arguments: vec![],
                log: format!("/tmp/worker-{index}.log").into(),
            })
            .collect();
        Plan {
            pool_calibration: None,
            pool_requests: None,
            pool_scheduling: None,
            pool_workflow: None,
            coordinator_bootstrap_guard: None,
            startup_fenced: false,
            allow_worker_failover: false,
            recover_from: None,
            recover_cached_only: false,
            schema_version: 2,
            coordinator_unit: "lattica-v2-multi-owner-test.service".into(),
            coordinator_ram_bytes: 2 << 30,
            coordinator_shared_bytes: storage::shared_reservation(2),
            coordinator_threads: 1,
            fleet_bytes: 10 << 30,
            workers,
            native_host: None,
            preseal_only: false,
            pool_prefix_handoff: false,
            reuse_preseal: Vec::new(),
        }
    }

    #[test]
    fn fleet_preserves_distinct_cpu_assignments_and_one_coordinator_allowance() {
        let plan = plan();
        let assignments = validate_plan(&plan).unwrap();
        assert_eq!(assignments[0].1.threads, 4);
        assert_eq!(assignments[1].1.threads, 3);
        let limits = budget::fleet_limits(&assignments).unwrap();
        assert_eq!(
            limits.workers.ram_bytes + plan.coordinator_shared_bytes,
            plan.fleet_bytes
        );
        assert_eq!(limits.workers.threads, 7);
    }

    #[test]
    fn coordinator_shared_partition_is_required_and_cannot_overlap_jobs() {
        let base = plan();
        let mut bad = base.clone();
        bad.schema_version = 1;
        assert!(validate_plan(&bad).is_err());
        let mut missing = serde_json::to_value(&base).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("coordinator_shared_bytes");
        assert!(serde_json::from_value::<Plan>(missing).is_err());

        for shared in [
            0,
            512 << 20,
            storage::COORDINATOR_SHARED_BYTES - 1,
            u64::MAX,
        ] {
            let mut bad = base.clone();
            bad.coordinator_shared_bytes = shared;
            for worker in &mut bad.workers {
                worker.assignment["host"]["coordinator_shared_bytes"] = json!(shared);
            }
            assert!(validate_plan(&bad).is_err());
        }
        for shared in [
            serde_json::Value::Null,
            json!(true),
            json!(-1),
            json!("536870912"),
            json!(768u64 << 20),
        ] {
            let mut bad = base.clone();
            bad.workers[0].assignment["host"]["coordinator_shared_bytes"] = shared;
            assert!(validate_plan(&bad).is_err());
        }
        let mut bad = base.clone();
        bad.workers[0].assignment["host"]
            .as_object_mut()
            .unwrap()
            .remove("coordinator_shared_bytes");
        assert!(validate_plan(&bad).is_err());

        let mut bad = base;
        for worker in &mut bad.workers {
            worker.assignment["host"]["coordinator_job_bytes"] = json!(1u64 << 30);
        }
        assert!(validate_plan(&bad).is_err());
    }

    #[test]
    fn fleet_cap_includes_shared_storage_once_and_rejects_overflow() {
        let mut short = plan();
        short.fleet_bytes -= short.coordinator_shared_bytes;
        for worker in &mut short.workers {
            worker.assignment["host"]["fleet_bytes"] = json!(short.fleet_bytes);
        }
        assert!(validate_plan(&short).is_err());

        let mut overflow = plan();
        overflow.fleet_bytes = u64::MAX;
        let job_bytes = overflow.workers[0].assignment["host"]["coordinator_job_bytes"]
            .as_u64()
            .unwrap();
        let other_worker_bytes = overflow.workers[1].assignment["host"]["worker_bytes"]
            .as_u64()
            .unwrap();
        // Worker and job reservations fit in u64; adding the shared owner does not.
        overflow.workers[0].assignment["host"]["worker_bytes"] =
            json!(u64::MAX - other_worker_bytes - 2 * job_bytes);
        for worker in &mut overflow.workers {
            worker.assignment["host"]["fleet_bytes"] = json!(u64::MAX);
        }
        assert!(validate_plan(&overflow).is_err());
    }

    #[test]
    fn duplicate_devices_services_or_packet_ram_cannot_gain_admission() {
        let base = plan();
        let mut bad = base.clone();
        bad.workers[1].assignment["gpu"]["uuid"] = bad.workers[0].assignment["gpu"]["uuid"].clone();
        assert!(validate_plan(&bad).is_err());
        bad = base.clone();
        bad.workers[1].assignment["unit"] = bad.workers[0].assignment["unit"].clone();
        assert!(validate_plan(&bad).is_err());
        bad = base.clone();
        bad.workers[0].assignment["host"]["coordinator_job_bytes"] = json!(1u64 << 30);
        assert!(validate_plan(&bad).is_err());
        bad = base.clone();
        bad.coordinator_ram_bytes += 1;
        assert!(validate_plan(&bad).is_err());
        bad = base;
        bad.workers.clear();
        assert!(validate_plan(&bad).is_err());
    }

    #[test]
    fn failover_cannot_be_enabled_without_a_native_binding() {
        let mut plan = plan();
        plan.allow_worker_failover = true;
        assert!(validate_plan(&plan)
            .unwrap_err()
            .to_string()
            .contains("native binding"));
    }

    #[test]
    fn unused_rounded_fleet_headroom_is_preserved() {
        let mut plan = plan();
        plan.fleet_bytes += 256 << 20;
        for worker in &mut plan.workers {
            worker.assignment["host"]["fleet_bytes"] = json!(plan.fleet_bytes);
        }
        let resources = validate_plan(&plan).unwrap();
        assert!(budget::fleet_limits(&resources).unwrap().workers.ram_bytes < plan.fleet_bytes);
    }

    #[test]
    fn native_snapshot_cannot_be_injected_into_one_worker_assignment() {
        let mut plan = plan();
        plan.workers[0].assignment["native_host"] = json!({"head_token": "unbound"});
        assert!(validate_plan(&plan).is_err());
    }

    #[test]
    fn every_worker_must_bind_the_identical_native_snapshot() {
        let mut plan = plan();
        let binding = json!({"schema_version":1,"head_token":vec![1u8;32],"generation":0,
            "configuration_sha256":vec![2u8;32],"complete_body_sha256":vec![3u8;32],
            "preparation_sha256":vec![4u8;32],"expected":{"schema_version":1,
            "profile":vec![5u8;32],"chain":vec![6u8;32],"root":[7,7,7,7],"count":4,
            "block_height":10,"authorized_issuance":{"3":7}}});
        plan.native_host = Some(serde_json::from_value(binding.clone()).unwrap());
        assert!(validate_plan(&plan).is_err());
        for worker in &mut plan.workers {
            worker.assignment["native_host"] = binding.clone();
        }
        validate_plan(&plan).unwrap();
        plan.workers[1].assignment["native_host"]["generation"] = json!(1);
        assert!(validate_plan(&plan).is_err());
    }
}
