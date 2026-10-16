//! Cost-history backing and one scheduling pass. Input jobs, deadlines and
//! capabilities belong to the caller; allocator/OS costs are separate.

use super::*;
use crate::block_v2::execution::storage_bound::{add, btree, growing_vector, mul, vector};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerStorage {
    pub retained_bytes: usize,
    pub selection_bytes: usize,
    /// One fixed calibration record and its codec/control temporaries.
    /// Caller-retained collections of records need separate admission.
    pub calibration_bytes: usize,
}

impl SchedulerStorage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        add(
            self.retained_bytes,
            add(self.selection_bytes, self.calibration_bytes)?,
        )
    }
}

impl CostModel {
    pub fn storage_plan() -> Result<SchedulerStorage, Error> {
        let retained_bytes = [
            size_of::<CostModel>(),
            btree::<CostKey, History>(MAX_CLASSES)?,
            mul(MAX_CLASSES, growing_vector::<u64>(MAX_SAMPLES)?)?,
            growing_vector::<CostKey>(MAX_CLASSES)?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        // Each job has at most two dependency edges. A parent's Vec per child
        // needs at most twice its edge count or the eight-element startup
        // allowance. Charge their sum, including the worst fanout distribution.
        let edge_backing = vector::<JobId>(mul(12, MAX_JOBS)?)?;
        let selection_bytes = [
            btree::<JobId, Vec<JobId>>(MAX_JOBS)?,
            edge_backing,
            btree::<JobId, usize>(MAX_JOBS)?,
            vector::<u64>(mul(MAX_JOBS, MAX_WORKERS + 1)?)?,
            vector::<JobId>(MAX_JOBS)?,
            vector::<u64>(MAX_SAMPLES)?, // stack-only p95 sorting scratch
            size_of::<BTreeMap<JobId, Vec<JobId>>>()
                + size_of::<continuation::RemainingPaths>()
                + size_of::<Vec<JobId>>(),
        ]
        .into_iter()
        .try_fold(0, add)?;
        Ok(SchedulerStorage {
            retained_bytes,
            selection_bytes,
            calibration_bytes: 4
                * (size_of::<TimingCalibration>() + TimingCalibration::ENCODED_BYTES),
        })
    }

    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let mut bytes = [
            size_of::<CostModel>(),
            btree::<CostKey, History>(self.samples.len())?,
            vector::<CostKey>(self.insertion_order.capacity())?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        for history in self.samples.values() {
            let samples = &history.samples;
            if samples.is_empty()
                || samples.len() > MAX_SAMPLES
                || vector::<u64>(samples.capacity())? > growing_vector::<u64>(MAX_SAMPLES)?
            {
                return Err("scheduler sample storage invariant".into());
            }
            bytes = add(bytes, vector::<u64>(samples.capacity())?)?;
        }
        if self.samples.len() > MAX_CLASSES
            || self.insertion_order.len() != self.samples.len()
            || vector::<CostKey>(self.insertion_order.capacity())?
                > growing_vector::<CostKey>(MAX_CLASSES)?
            || bytes > Self::storage_plan()?.retained_bytes
        {
            return Err("scheduler retained storage invariant".into());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "scheduler_storage_tests.rs"]
mod tests;
