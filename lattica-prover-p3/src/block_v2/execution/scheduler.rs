//! Transport-independent, bounded scheduling costs for public proof jobs.
//!
//! Estimates are observations, not qualification, proof validity, or resource
//! reservations. The durable DAG and the local/remote worker adapter retain
//! those authorities. A worker has one active proof; device memory is never
//! pooled across devices or hosts.

use std::collections::{BTreeMap, VecDeque};

use super::{
    dag::WorkerId,
    job::{Job, JobId},
    resources::Resources,
};
use crate::block_v2::recursive::Error;

const MAX_CLASSES: usize = 4096;
const MAX_SAMPLES: usize = 64;
const MAX_JOBS: usize = 4096;
const MAX_WORKERS: usize = 256;

mod continuation;

#[path = "scheduler_storage.rs"]
mod storage;
pub use storage::SchedulerStorage;

mod calibration;
pub use calibration::{EstimateSource, TimingCalibration, TimingIdentity};

#[derive(Clone, Debug)]
pub struct WorkerCapabilities {
    pub worker: WorkerId,
    /// Registry/program identity, not a worker-selected verification key.
    pub profile: [u8; 32],
    pub resources: Resources,
    /// Host-approved immutable timing qualification, never worker self-report.
    /// Unqualified workers retain session-local observations only.
    pub timing_identity: Option<TimingIdentity>,
    /// Only the adapter knows which immutable preprocessing remains resident.
    pub resident_mode: Option<u64>,
    /// Host-approved permission to forecast retained preprocessing after a
    /// successful same-mode job on this physical worker. Requires a timing
    /// identity; never infer it from a current cache hit or worker self-report.
    /// This is an estimate, not a reservation or a promise of worker survival.
    pub forecast_retained_mode: bool,
    /// Host deadline for finishing the next service, in the coordinator's
    /// monotonic clock. The adapter reserves shutdown time before this cutoff.
    /// This changing availability is not part of a measured timing class, and
    /// admits neither downstream work nor an extension of the OS lifetime.
    pub dispatch_deadline_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CostKey {
    worker: u64,
    profile: [u8; 32],
    identity: Option<TimingIdentity>,
    mode: u64,
    level: u8,
    count: u8,
    ram_bytes: u64,
    vram_bytes: u64,
    scratch_bytes: u64,
    threads: u32,
    warm: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Choice {
    pub worker: WorkerId,
    pub job: JobId,
    pub service_ms: u64,
    pub remaining_path_ms: u64,
    pub warm: bool,
    pub measured: bool,
    pub source: EstimateSource,
}

#[derive(Default)]
struct History {
    samples: VecDeque<u64>,
    /// Fingerprint of the host-approved calibration evidence; None is live.
    evidence: Option<[u8; 32]>,
}

/// Rolling nearest-rank p95 costs. Qualified identities and every resource
/// dimension isolate observations; unqualified workers require a new model
/// after backend, binary, driver or geometry changes. Cold and warm
/// observations stay separate. An unmeasured warm class may provisionally use
/// its matching cold history, never another worker, profile, mode, level or
/// thread allocation. This fallback is an estimate, not a measured warm cost.
pub struct CostModel {
    bootstrap_ms: u64,
    samples: BTreeMap<CostKey, History>,
    insertion_order: VecDeque<CostKey>,
}

impl CostModel {
    /// A replacement may have a different runtime, device, or cache residency.
    /// Do not carry optimistic observations across that physical session change.
    pub fn forget_worker(&mut self, worker: WorkerId) {
        self.samples.retain(|key, _| key.worker != worker.0);
        self.insertion_order.retain(|key| key.worker != worker.0);
    }
    /// Explicit conservative bootstrap estimate; never a measured speed claim.
    pub fn new(bootstrap_ms: u64) -> Result<Self, Error> {
        if !(1..=7_200_000).contains(&bootstrap_ms) {
            return Err("scheduler bootstrap cost outside bounds".into());
        }
        Ok(Self {
            bootstrap_ms,
            samples: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        })
    }

    fn key(worker: &WorkerCapabilities, job: &Job, warm: bool) -> Result<CostKey, Error> {
        worker.resources.validate_request()?;
        if worker.worker.0 == 0 || worker.profile != job.pin().profile() {
            return Err("scheduler worker/profile mismatch".into());
        }
        Ok(CostKey {
            worker: worker.worker.0,
            profile: worker.profile,
            identity: worker.timing_identity,
            mode: job.operation().proof_mode(),
            level: job.expected().level,
            count: job.expected().count,
            ram_bytes: worker.resources.ram_bytes,
            vram_bytes: worker.resources.vram_bytes,
            scratch_bytes: worker.resources.scratch_bytes,
            threads: worker.resources.threads,
            warm,
        })
    }

    pub fn observe(
        &mut self,
        worker: &WorkerCapabilities,
        job: &Job,
        warm: bool,
        elapsed_ms: u64,
    ) -> Result<(), Error> {
        if elapsed_ms == 0 || elapsed_ms > 7_200_000 {
            return Err("scheduler observation outside bounds".into());
        }
        let key = Self::key(worker, job, warm)?;
        self.admit_class(key)?;
        let history = self.samples.entry(key).or_default();
        // Fresh CPU-verified/durably accepted observations replace the seed;
        // imported samples never become live measurements through mixing.
        if history.evidence.take().is_some() {
            history.samples.clear();
        }
        let samples = &mut history.samples;
        if samples.len() == MAX_SAMPLES {
            samples.pop_front();
        }
        samples.push_back(elapsed_ms);
        Ok(())
    }

    fn admit_class(&mut self, key: CostKey) -> Result<(), Error> {
        if !self.samples.contains_key(&key) {
            if self.samples.len() == MAX_CLASSES {
                let oldest = self
                    .insertion_order
                    .pop_front()
                    .ok_or("scheduler cost index invariant")?;
                self.samples.remove(&oldest);
            }
            self.insertion_order.push_back(key);
        }
        Ok(())
    }

    pub fn estimate(
        &self,
        worker: &WorkerCapabilities,
        job: &Job,
        warm: bool,
    ) -> Result<(u64, bool), Error> {
        let (ms, source) = self.estimate_with_source(worker, job, warm)?;
        Ok((ms, source == EstimateSource::Live))
    }

    pub fn estimate_with_source(
        &self,
        worker: &WorkerCapabilities,
        job: &Job,
        warm: bool,
    ) -> Result<(u64, EstimateSource), Error> {
        let key = Self::key(worker, job, warm)?;
        let (history, exact) = match self.samples.get(&key) {
            Some(history) => (history, true),
            None if warm => match self.samples.get(&CostKey { warm: false, ..key }) {
                Some(history) => (history, false),
                None => return Ok((self.bootstrap_ms, EstimateSource::Bootstrap)),
            },
            None => return Ok((self.bootstrap_ms, EstimateSource::Bootstrap)),
        };
        let source = match (history.evidence, exact) {
            (None, true) => EstimateSource::Live,
            (None, false) => EstimateSource::ColdLive,
            (Some(evidence), true) => EstimateSource::Calibration(evidence),
            (Some(evidence), false) => EstimateSource::ColdCalibration(evidence),
        };
        let samples = &history.samples;
        let mut ordered = [0; MAX_SAMPLES];
        for (out, sample) in ordered.iter_mut().zip(samples) {
            *out = *sample;
        }
        let ordered = &mut ordered[..samples.len()];
        ordered.sort_unstable();
        let rank = (ordered.len() * 95).div_ceil(100) - 1;
        // Include a 10% execution/verification margin. This is not a p95
        // end-to-end guarantee: correlated downstream work can take longer.
        let estimate = ordered[rank]
            .checked_add(ordered[rank].div_ceil(10))
            .ok_or("scheduler cost overflow")?;
        Ok((estimate, source))
    }

    /// Choose among idle, already resource-admitted workers. `jobs` contains the
    /// candidate closures, including waiting parents. `deadlines` must come from
    /// the coordinator, never the worker. No lease is issued by this function.
    pub fn select(
        &self,
        jobs: &BTreeMap<JobId, Job>,
        ready: &[JobId],
        workers: &[WorkerCapabilities],
        deadlines: &BTreeMap<JobId, u64>,
        now_ms: u64,
    ) -> Result<Option<Choice>, Error> {
        if jobs.len() > MAX_JOBS || ready.len() > MAX_JOBS || workers.len() > MAX_WORKERS {
            return Err("scheduler input bounds".into());
        }
        for (index, worker) in workers.iter().enumerate() {
            if workers[..index]
                .iter()
                .any(|other| other.worker == worker.worker)
            {
                return Err("scheduler duplicate worker".into());
            }
        }
        let mut parents: BTreeMap<JobId, Vec<JobId>> = BTreeMap::new();
        for (id, job) in jobs {
            if *id != job.id() {
                return Err("scheduler job identity mismatch".into());
            }
            if job.dependencies().len() > 2 {
                return Err("scheduler dependency bound".into());
            }
            for child in job.dependencies() {
                if !jobs.contains_key(child) {
                    return Err("scheduler missing dependency".into());
                }
                parents.entry(*child).or_default().push(*id);
            }
        }
        // Job constructors enforce increasing levels. Check explicitly here so
        // cost propagation cannot recurse through malformed graphs.
        for (child, next) in &parents {
            for parent in next {
                if jobs[parent].expected().level <= jobs[child].expected().level {
                    return Err("scheduler dependency cycle/level".into());
                }
            }
        }
        let mut order = Vec::with_capacity(jobs.len());
        order.extend(jobs.keys().copied());
        // The previous stable sort began in JobId order. Include that tie-break
        // explicitly so in-place sorting preserves the same traversal.
        order.sort_unstable_by_key(|id| (std::cmp::Reverse(jobs[id].expected().level), *id));
        let downstream =
            continuation::RemainingPaths::build(self, jobs, &parents, &order, workers)?;
        let fastest = |id: &JobId| -> Result<Option<Choice>, Error> {
            let job = jobs.get(id).ok_or("scheduler unknown ready job")?;
            let deadline = *deadlines.get(id).ok_or("scheduler missing deadline")?;
            let mut fastest: Option<Choice> = None;
            for (wi, worker) in workers
                .iter()
                .enumerate()
                .filter(|(_, w)| w.profile == job.pin().profile())
            {
                let warm = worker.resident_mode == Some(job.operation().proof_mode());
                let (service_ms, source) = self.estimate_with_source(worker, job, warm)?;
                let service_finish = now_ms
                    .checked_add(service_ms)
                    .ok_or("scheduler time overflow")?;
                if worker
                    .dispatch_deadline_ms
                    .is_some_and(|limit| service_finish > limit)
                {
                    continue;
                }
                let remaining_path_ms = service_ms
                    .checked_add(downstream.at(*id, wi))
                    .ok_or("scheduler path overflow")?;
                let finish = now_ms
                    .checked_add(remaining_path_ms)
                    .ok_or("scheduler time overflow")?;
                if finish > deadline {
                    continue;
                }
                let choice = Choice {
                    worker: worker.worker,
                    job: *id,
                    service_ms,
                    remaining_path_ms,
                    warm,
                    measured: source == EstimateSource::Live,
                    source,
                };
                if fastest.as_ref().is_none_or(|old| {
                    (service_ms, worker.worker.0) < (old.service_ms, old.worker.0)
                }) {
                    fastest = Some(choice);
                }
            }
            Ok(fastest)
        };
        // Urgency belongs to the job using its best eligible placement.
        // Ranking every pair by slack would prefer a *slower* worker.
        let rank = |choice: Choice| -> Result<_, Error> {
            let deadline = deadlines[&choice.job];
            let finish = now_ms
                .checked_add(choice.remaining_path_ms)
                .ok_or("scheduler time overflow")?;
            Ok((
                deadline - finish,
                now_ms
                    .checked_add(choice.service_ms)
                    .ok_or("scheduler time overflow")?,
                deadline,
                choice.job,
                choice.worker.0,
            ))
        };
        let mut best: Option<((u64, u64, u64, JobId, u64), Choice)> = None;
        for id in ready {
            if let Some(choice) = fastest(id)? {
                let priority = rank(choice)?;
                if best.as_ref().is_none_or(|(old, _)| priority < *old) {
                    best = Some((priority, choice));
                }
            }
        }
        let Some((urgent_rank, urgent)) = best else {
            return Ok(None);
        };
        let worker = workers.iter().find(|w| w.worker == urgent.worker).unwrap();
        if urgent.warm || worker.timing_identity.is_none() || !worker.forecast_retained_mode {
            return Ok(Some(urgent));
        }
        // Cold setup makes an uncached sibling appear more urgent. Repeatedly
        // following that signal can evict the useful mode on every dispatch.
        // Reuse it only on this same fastest placement, for the same deadline,
        // with exact observations showing a saving. The warm service must fit
        // in the smallest ready-job slack, so delaying the original selection
        // cannot make any currently eligible fastest path miss its estimate.
        // No residency changes during that delay: the chosen mode stays warm.
        // This is a bounded second scan with no additional heap allocation;
        // it is not an aggregate-work guarantee or a process lifetime extension.
        let mut retained = None;
        for id in ready {
            let job = &jobs[id];
            if deadlines[id] != urgent_rank.2
                || worker.resident_mode != Some(job.operation().proof_mode())
            {
                continue;
            }
            let Some(choice) = fastest(id)? else {
                continue;
            };
            if choice.worker != urgent.worker
                || !choice.warm
                || choice.service_ms > urgent_rank.0
                || !matches!(
                    choice.source,
                    EstimateSource::Live | EstimateSource::Calibration(_)
                )
            {
                continue;
            }
            let (cold_ms, cold_source) = self.estimate_with_source(worker, job, false)?;
            if cold_ms <= choice.service_ms
                || !matches!(
                    cold_source,
                    EstimateSource::Live | EstimateSource::Calibration(_)
                )
            {
                continue;
            }
            let priority = rank(choice)?;
            if retained.as_ref().is_none_or(|(old, _)| priority < *old) {
                retained = Some((priority, choice));
            }
        }
        Ok(Some(retained.map_or(urgent, |(_, choice)| choice)))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod depth_tests;

#[cfg(test)]
mod retention_tests;

#[cfg(test)]
mod cache_tests;
