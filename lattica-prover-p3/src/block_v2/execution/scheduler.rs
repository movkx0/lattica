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

#[derive(Clone, Debug)]
pub struct WorkerCapabilities {
    pub worker: WorkerId,
    /// Registry/program identity, not a worker-selected verification key.
    pub profile: [u8; 32],
    pub resources: Resources,
    /// Only the adapter knows which immutable preprocessing remains resident.
    pub resident_mode: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CostKey {
    worker: u64,
    profile: [u8; 32],
    mode: u64,
    level: u8,
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
}

/// Rolling nearest-rank p95 costs. Construct a new model after a backend,
/// binary, driver, geometry, or resource assignment change. Cold and warm
/// observations and different thread allocations cannot contaminate each other.
pub struct CostModel {
    bootstrap_ms: u64,
    samples: BTreeMap<CostKey, VecDeque<u64>>,
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
            mode: job.operation().proof_mode(),
            level: job.expected().level,
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
        let samples = self.samples.entry(key).or_default();
        if samples.len() == MAX_SAMPLES {
            samples.pop_front();
        }
        samples.push_back(elapsed_ms);
        Ok(())
    }

    pub fn estimate(
        &self,
        worker: &WorkerCapabilities,
        job: &Job,
        warm: bool,
    ) -> Result<(u64, bool), Error> {
        let key = Self::key(worker, job, warm)?;
        let Some(samples) = self.samples.get(&key) else {
            return Ok((self.bootstrap_ms, false));
        };
        let mut ordered: Vec<_> = samples.iter().copied().collect();
        ordered.sort_unstable();
        let rank = (ordered.len() * 95).div_ceil(100) - 1;
        // Include a 10% execution/verification margin. This is not a p95
        // end-to-end guarantee: correlated downstream work can take longer.
        let estimate = ordered[rank]
            .checked_add(ordered[rank].div_ceil(10))
            .ok_or("scheduler cost overflow")?;
        Ok((estimate, true))
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
        if jobs.len() > MAX_JOBS || ready.len() > MAX_JOBS || workers.len() > 256 {
            return Err("scheduler input bounds".into());
        }
        let mut parents: BTreeMap<JobId, Vec<JobId>> = BTreeMap::new();
        for (id, job) in jobs {
            if *id != job.id() {
                return Err("scheduler job identity mismatch".into());
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
        let mut order: Vec<_> = jobs.keys().copied().collect();
        order.sort_by_key(|id| std::cmp::Reverse(jobs[id].expected().level));
        let mut downstream: BTreeMap<JobId, u64> = BTreeMap::new();
        for id in order {
            let mut longest = 0;
            for parent in parents.get(&id).into_iter().flatten() {
                let job = &jobs[parent];
                let mut fastest = None;
                for worker in workers.iter().filter(|w| w.profile == job.pin().profile()) {
                    let cost = self.estimate(worker, job, false)?.0;
                    fastest = Some(fastest.map_or(cost, |v: u64| v.min(cost)));
                }
                let cost = fastest.unwrap_or(self.bootstrap_ms);
                longest = longest.max(
                    cost.checked_add(downstream[parent])
                        .ok_or("scheduler path overflow")?,
                );
            }
            downstream.insert(id, longest);
        }
        let mut best: Option<((u64, u64, u64, JobId, u64), Choice)> = None;
        for id in ready {
            let job = jobs.get(id).ok_or("scheduler unknown ready job")?;
            let deadline = *deadlines.get(id).ok_or("scheduler missing deadline")?;
            let mut fastest: Option<Choice> = None;
            for worker in workers.iter().filter(|w| w.profile == job.pin().profile()) {
                let warm = worker.resident_mode == Some(job.operation().proof_mode());
                let (service_ms, measured) = self.estimate(worker, job, warm)?;
                let remaining_path_ms = service_ms
                    .checked_add(downstream[id])
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
                    measured,
                };
                if fastest.as_ref().is_none_or(|old| {
                    (service_ms, worker.worker.0) < (old.service_ms, old.worker.0)
                }) {
                    fastest = Some(choice);
                }
            }
            if let Some(choice) = fastest {
                // Urgency belongs to the job using its best eligible placement.
                // Ranking every pair by slack would prefer a *slower* worker.
                let finish = now_ms
                    .checked_add(choice.remaining_path_ms)
                    .ok_or("scheduler time overflow")?;
                let rank = (
                    deadline - finish,
                    now_ms
                        .checked_add(choice.service_ms)
                        .ok_or("scheduler time overflow")?,
                    deadline,
                    *id,
                    choice.worker.0,
                );
                if best.as_ref().is_none_or(|(old, _)| rank < *old) {
                    best = Some((rank, choice));
                }
            }
        }
        Ok(best.map(|(_, choice)| choice))
    }
}

#[cfg(test)]
mod tests;
