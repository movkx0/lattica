//! Explicit calibration experiments, never scheduled native delivery.
//! Missing timing classes keep the full bootstrap. A successful experiment must
//! finish all work within the original dispatch window and drain its worker.
use super::*;
use lattica_prover_p3::block_v2::execution::{
    dag::JobStatus,
    job::Job,
    scheduler::{TimingCalibration, TimingIdentity},
    worker::typed::process::configuration_digest,
};

pub(super) const MAX_JOBS: usize = 16;
const MAX_SEEDS: usize = 127;

#[path = "execution_pool_calibration_audit.rs"]
pub(super) mod audit;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    schema_version: u32,
    identity: [[u8; 32]; 5],
    #[serde(deserialize_with = "jobs")]
    jobs: Vec<[u8; 32]>,
    #[serde(deserialize_with = "seeds")]
    seeds: Vec<Seed>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    job: [u8; 32],
    path: PathBuf,
}

fn jobs<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
    input::bounded::<D, [u8; 32], MAX_JOBS>(d)
}

fn seeds<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Seed>, D::Error> {
    input::bounded::<D, Seed, MAX_SEEDS>(d)
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        let jobs = self.jobs.iter().collect::<BTreeSet<_>>();
        let seeds = self
            .seeds
            .iter()
            .map(|seed| &seed.job)
            .collect::<BTreeSet<_>>();
        if self.schema_version != 1
            || self.identity.contains(&[0; 32])
            || self.jobs.is_empty()
            || self.jobs.len() > MAX_JOBS
            || self.seeds.len() > MAX_SEEDS
            || jobs.len() != self.jobs.len()
            || seeds.len() != self.seeds.len()
            || !jobs.is_disjoint(&seeds)
            || self
                .seeds
                .iter()
                .any(|seed| !seed.path.is_absolute() || seed.path.as_os_str().len() > 4096)
        {
            return Err("calibration request identity, inventory or seed path".into());
        }
        Ok(())
    }

    fn ordered<'a>(&self, available: impl Iterator<Item = &'a Job>) -> Result<Vec<&'a Job>, Error> {
        self.validate()?;
        let map = available
            .map(|job| (job.id().to_bytes(), job))
            .collect::<BTreeMap<_, _>>();
        let mut ready = self
            .seeds
            .iter()
            .map(|seed| seed.job)
            .collect::<BTreeSet<_>>();
        if ready.iter().any(|id| !map.contains_key(id)) {
            return Err("calibration seed is outside the prepared selection".into());
        }
        let mut ordered = input::exact(self.jobs.len())?;
        let mut used_seeds = BTreeSet::new();
        for id in &self.jobs {
            let job = *map
                .get(id)
                .ok_or("calibration job is outside the prepared selection")?;
            for dependency in job.dependencies() {
                let id = dependency.to_bytes();
                if !ready.contains(&id) {
                    return Err("calibration job order lacks a verified dependency".into());
                }
                if self.seeds.iter().any(|seed| seed.job == id) {
                    used_seeds.insert(id);
                }
            }
            ordered.push(job);
            ready.insert(*id);
        }
        if used_seeds.len() != self.seeds.len() {
            return Err("calibration has an unused seed proof".into());
        }
        Ok(ordered)
    }

    pub fn prepare(
        &self,
        prepared: &Prepared,
        owner: &mut DurableDag,
        now: impl Fn() -> u64,
    ) -> Result<(), Error> {
        self.ordered(prepared.selection.jobs())?;
        for seed in &self.seeds {
            let job = prepared
                .selection
                .jobs()
                .find(|job| job.id().to_bytes() == seed.job)
                .ok_or("calibration seed disappeared")?;
            let proof = bytes(&seed.path)?;
            let ticket = VerifiedNode::verify_typed(job, &prepared.registry, &proof)?;
            owner.cache_node(ticket, proof, now())?;
        }
        Ok(())
    }
}

// The existing shared model already reserves the durable DAG, selection,
// scheduler and process endpoint. Add bounded request/report/seed ingress here.
pub(super) fn storage_bytes() -> u64 {
    (JSON_LIMIT
        + profile::MAX_PROOF_BYTES
        + MAX_SEEDS * (4096 + std::mem::size_of::<Seed>())
        + MAX_JOBS * (4096 + TimingCalibration::ENCODED_BYTES)) as u64
}

fn within(now: u64, end: u64) -> Result<(), Error> {
    if now >= end || now >= pool_timing::CANDIDATE_MS {
        return Err("calibration exhausted its original work or workflow window".into());
    }
    Ok(())
}

pub(super) fn run(
    plan: &Plan,
    request: &Request,
    prepared: Prepared,
    mut owner: DurableDag,
    mut launches: LaunchStore,
    mut slots: Vec<Slot>,
    out: &Path,
    now: impl Fn() -> u64,
) -> Result<(), Error> {
    if slots.len() != 1 {
        return Err("calibration requires exactly one supervised worker".into());
    }
    let slot = &mut slots[0];
    let deadline = slot
        .dispatch_deadline_ms
        .ok_or("calibration work window missing")?;
    within(now(), deadline)?;
    let executable = image_fingerprint(&std::env::current_exe()?)?;
    let [backend, kernels, device, driver, settings] = request.identity;
    let identity = TimingIdentity::new(backend, kernels, executable, device, driver, settings)?;
    let capabilities = slot.worker.scheduling_capabilities_with_timing(identity)?;
    let jobs = request.ordered(prepared.selection.jobs())?;
    let mut costs = CostModel::new(pool_timing::SERVICE_MS)?;
    let mut observations = input::exact(jobs.len())?;
    let mut classes = BTreeMap::new();
    let started = now();
    for job in &jobs {
        within(now(), deadline)?;
        if owner.status(job.id())? != JobStatus::Ready {
            return Err("calibration requested job is not fresh and ready".into());
        }
        let mode = job.expected_public()[programs::MODE].as_canonical_u64();
        let warm = slot.resident_mode == Some(mode);
        let (estimate, source) = costs.estimate_with_source(&capabilities, job, warm)?;
        let measured = Instant::now();
        let issued = now();
        let lease = owner.lease(
            job.id(),
            slot.job_worker,
            slot.jobs,
            estimate,
            pool_timing::SERVICE_MS,
            issued,
        )?;
        let task = slot.worker.task(&mut owner, lease, now())?;
        let token = launches.issue_bound(
            &mut owner,
            lease,
            &task.request()?,
            slot.worker.execution_digest()?,
        )?;
        slot.worker.dispatch(&token, task)?;
        let complete = loop {
            if let Err(error) = within(now(), deadline) {
                slot.worker
                    .stop_failed_supervised(&mut owner, &mut launches, lease, &now)?;
                return Err(error);
            }
            match slot.worker.try_collect() {
                Ok(Some(result)) => break result,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(error) => {
                    slot.worker
                        .stop_failed_supervised(&mut owner, &mut launches, lease, &now)?;
                    return Err(error);
                }
            }
        };
        if complete.lease() != lease || slot.worker.retirement_requested() {
            return Err(
                "calibration result substituted a lease or exhausted worker retention".into(),
            );
        }
        let revoked = launches.revoke(lease)?;
        let _idle = launches
            .try_idle(&revoked)?
            .ok_or("calibration launch remained active")?;
        let output = complete.reconcile(&mut owner, now())?;
        let expected = owner.begin_verification(lease, now())?;
        if expected.id() != job.id() {
            return Err("calibration verification job changed".into());
        }
        let ticket = VerifiedNode::verify_typed(&expected, &prepared.registry, output.bytes())?;
        if owner.finish_verification(lease, Some((ticket, output.bytes().to_vec())), now())?
            != Completion::Accepted
        {
            return Err("calibration proof was not durably accepted".into());
        }
        within(now(), deadline)?;
        // Only a verified, durably accepted fresh proof contributes a sample.
        let elapsed = u64::try_from(measured.elapsed().as_millis())?.max(1);
        costs.observe(&capabilities, job, warm, elapsed)?;
        slot.resident_mode = Some(mode);
        classes.insert(
            (mode, job.expected().level, job.expected().count, warm),
            *job,
        );
        let filename = format!(
            "node.{}.{}",
            job.expected().level,
            job.start() as usize >> job.expected().level
        );
        write_bytes(
            &out.join(&filename),
            output.bytes(),
            profile::MAX_PROOF_BYTES,
        )?;
        observations.push(
            json!({"job":job.id().to_bytes(),"file":filename,"level":job.expected().level,
            "count":job.expected().count,"mode":mode,"warm":warm,"issued_ms":issued,
            "accepted_ms":now(),"elapsed_ms":elapsed,"estimate_ms":estimate,
            "estimate_source":format!("{source:?}"),"proof_bytes":output.bytes().len()}),
        );
        within(now(), deadline)?;
    }
    let completed = now();
    within(completed, deadline)?;
    slot.worker.close(&mut owner, now())?;
    if owner.resource_use()? != Resources::default() {
        return Err("calibration reservations survived physical worker shutdown".into());
    }
    let stopped = now();
    within(
        stopped,
        deadline
            .checked_add(pool_timing::SHUTDOWN_MS)
            .ok_or("calibration service deadline overflow")?,
    )?;
    let mut records = input::exact(classes.len())?;
    for ((_, _, _, warm), job) in classes {
        let encoded = costs.export_calibration(&capabilities, job, warm)?.encode();
        let path = out.join(format!("timing-{:03}.bin", records.len()));
        write_bytes(&path, &encoded, TimingCalibration::ENCODED_BYTES)?;
        records.push(json!({"path":path,"content_identity":configuration_digest(&encoded)?}));
    }
    within(
        now(),
        deadline
            .checked_add(pool_timing::SHUTDOWN_MS)
            .ok_or("calibration service deadline overflow")?,
    )?;
    write_json(
        &out.join("calibration-result.json"),
        &json!({
            "schema_version":1,"status":"calibrated_cpu_audit_pending","approved_for_pool_import":false,
            "fresh_proofs":observations.len(),"seed_proofs":request.seeds.len(),"observations":observations,
            "records":records,"executable":executable,"identity":request.identity,"gpu_uuid":slot.uuid,
            "pool_workflow":plan.pool_workflow,"native_host":plan.native_host,"native_applied":false,
            "started_ms":started,"completed_ms":completed,"stopped_ms":stopped,
            "dispatch_deadline_ms":deadline,"bootstrap_ms":pool_timing::SERVICE_MS,
            "workers_drained":true,"workspace_released":true,"scheduled_throughput_admitted":false,
        "independent_complete_audit_pending":true,"fresh_recursive_dag":false,
        "existing_recursive_proofs_imported":!request.seeds.is_empty()
        }),
    )
}

#[cfg(test)]
#[path = "execution_pool_calibration_tests.rs"]
mod tests;
