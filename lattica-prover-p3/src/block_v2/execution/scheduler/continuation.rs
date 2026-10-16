//! Critical-path estimates indexed by the worker that just completed a job.
//! These paths do not reserve sibling work or promise worker survival. Every
//! migration is cold; only explicitly qualified same-mode continuations can
//! reuse preprocessing. Actual adapters, leases and deadlines remain binding.

use super::*;

pub(super) struct RemainingPaths {
    rows: BTreeMap<JobId, usize>,
    values: Vec<u64>,
    width: usize,
}

impl RemainingPaths {
    pub(super) fn build(
        model: &CostModel,
        jobs: &BTreeMap<JobId, Job>,
        parents: &BTreeMap<JobId, Vec<JobId>>,
        order: &[JobId],
        workers: &[WorkerCapabilities],
    ) -> Result<Self, Error> {
        // The extra column represents an unknown predecessor placement. It
        // preserves the bootstrap path when no worker supports a parent.
        let width = workers.len() + 1;
        let mut result = Self {
            rows: order
                .iter()
                .enumerate()
                .map(|(row, id)| (*id, row))
                .collect(),
            values: vec![
                0;
                order
                    .len()
                    .checked_mul(width)
                    .ok_or("scheduler table overflow")?
            ],
            width,
        };
        for id in order {
            let row = result.rows[id] * width;
            for parent in parents.get(id).into_iter().flatten() {
                let job = &jobs[parent];
                // Two minima let each worker exclude its own cold placement
                // when its same-mode continuation necessarily uses the cache.
                // This avoids an O(workers^2) search for every dependency edge.
                let mut first: Option<(u64, usize)> = None;
                let mut second: Option<(u64, usize)> = None;
                for (wi, worker) in workers.iter().enumerate() {
                    if worker.profile != job.pin().profile() {
                        continue;
                    }
                    let cost = model
                        .estimate(worker, job, false)?
                        .0
                        .checked_add(result.at(*parent, wi))
                        .ok_or("scheduler path overflow")?;
                    let candidate = (cost, wi);
                    if first.is_none_or(|old| candidate < old) {
                        second = first;
                        first = Some(candidate);
                    } else if second.is_none_or(|old| candidate < old) {
                        second = Some(candidate);
                    }
                }
                let cold = match first {
                    Some((cost, _)) => cost,
                    None => model
                        .bootstrap_ms
                        .checked_add(result.at(*parent, workers.len()))
                        .ok_or("scheduler path overflow")?,
                };
                result.values[row + workers.len()] = result.values[row + workers.len()].max(cold);
                for (wi, worker) in workers.iter().enumerate() {
                    let can_continue = worker.forecast_retained_mode
                        && worker.timing_identity.is_some()
                        && worker.profile == jobs[id].pin().profile()
                        && worker.profile == job.pin().profile()
                        && jobs[id].operation().proof_mode() == job.operation().proof_mode();
                    let cost = if can_continue {
                        let warm = model
                            .estimate(worker, job, true)?
                            .0
                            .checked_add(result.at(*parent, wi))
                            .ok_or("scheduler path overflow")?;
                        let migration = first.filter(|(_, index)| *index != wi).or(second);
                        migration.map_or(warm, |(cold, _)| cold.min(warm))
                    } else {
                        cold
                    };
                    result.values[row + wi] = result.values[row + wi].max(cost);
                }
            }
        }
        Ok(result)
    }

    pub(super) fn at(&self, job: JobId, worker: usize) -> u64 {
        self.values[self.rows[&job] * self.width + worker]
    }
}
