//! Pool-owned metadata and composition with the durable shared component.
//! Endpoint backing, caller-owned selections/results, job verification
//! and opaque allocator/OS/runtime costs still need separate reservations.

use super::*;
use crate::block_v2::execution::{
    job::ArtifactRef,
    journal::DurableStorage,
    scheduler::SchedulerStorage,
    storage_bound::{add, btree, growing_vector, mul, vector},
};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolBookkeepingStorage {
    pub retained_bytes: usize,
    pub transition_bytes: usize,
    pub scheduler: SchedulerStorage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStorage {
    pub durable: DurableStorage,
    pub bookkeeping: PoolBookkeepingStorage,
    pub registry_bytes: usize,
}

fn job_heap() -> Result<usize, Error> {
    add(vector::<JobId>(2)?, vector::<ArtifactRef>(2)?)
}

impl PoolBookkeepingStorage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        add(
            add(self.retained_bytes, self.transition_bytes)?,
            self.scheduler.total_bytes()?,
        )
    }
}

impl PoolStorage {
    pub fn new(durable: DurableStorage) -> Result<Self, Error> {
        Ok(Self {
            durable,
            bookkeeping: PoolCoordinator::bookkeeping_storage()?,
            registry_bytes: Registry::<12>::STORAGE_LIMIT_BYTES,
        })
    }

    pub fn total_bytes(self) -> Result<usize, Error> {
        add(
            add(self.durable.total_bytes()?, self.bookkeeping.total_bytes()?)?,
            self.registry_bytes,
        )
    }

    /// Check this shared component without admitting external owners or an
    /// incomplete worker phase profile, and without increasing physical caps.
    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("pool shared storage component admission".into());
        }
        Ok(())
    }
}

impl PoolCoordinator {
    pub fn bookkeeping_storage() -> Result<PoolBookkeepingStorage, Error> {
        let retained_bytes = [
            size_of::<PoolCoordinator>(),
            btree::<JobId, Job>(MAX_JOBS)?,
            mul(MAX_JOBS, job_heap()?)?,
            btree::<CandidateId, Candidate>(MAX_CANDIDATES)?,
            mul(MAX_CANDIDATES, vector::<JobId>(MAX_SELECTION_JOBS)?)?,
            vector::<Slot>(MAX_WORKERS)?,
            growing_vector::<(WorkerId, String)>(MAX_FAILURES)?,
            mul(MAX_FAILURES, 4 * MAX_FAILURE_CHARS)?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        let transition_bytes = [
            vector::<Job>(MAX_SELECTION_JOBS)?,
            mul(MAX_SELECTION_JOBS, job_heap()?)?,
            vector::<JobId>(MAX_SELECTION_JOBS)?,
            vector::<WorkerCapabilities>(MAX_WORKERS)?,
            vector::<AcceptedJob>(MAX_WORKERS)?,
            btree::<JobId, u64>(MAX_JOBS)?, // explicit deadline insertion
            vector::<Box<dyn WorkerEndpoint>>(MAX_WORKERS)?,
            btree::<WorkerId, ()>(MAX_WORKERS)?, // constructor identity check
            4 * MAX_FAILURE_CHARS,               // failure being formatted before insertion
            6 * size_of::<Vec<JobId>>() + 2 * size_of::<BTreeMap<JobId, u64>>(),
        ]
        .into_iter()
        .try_fold(0, add)?;
        // ready()/pending_stops() backing is already charged by DurableStorage.
        // Returned accepted/failure lists become caller-owned after return.
        Ok(PoolBookkeepingStorage {
            retained_bytes,
            transition_bytes,
            scheduler: CostModel::storage_plan()?,
        })
    }

    pub fn storage_plan(&self) -> Result<PoolStorage, Error> {
        self.registry.storage_bytes()?;
        PoolStorage::new(self.owner.storage_plan()?)
    }

    /// Pool-owned retained backing, excluding separately composed scheduler,
    /// durable owner, registry and concrete endpoint heap allocations.
    pub fn bookkeeping_storage_bytes(&self) -> Result<usize, Error> {
        let mut bytes = [
            size_of::<PoolCoordinator>(),
            btree::<JobId, Job>(self.jobs.len())?,
            btree::<CandidateId, Candidate>(self.candidates.len())?,
            vector::<Slot>(self.slots.capacity())?,
            vector::<(WorkerId, String)>(self.failures.capacity())?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        for job in self.jobs.values() {
            let heap = job.owned_heap_bytes()?;
            if heap > job_heap()? {
                return Err("pool job backing invariant".into());
            }
            bytes = add(bytes, heap)?;
        }
        for candidate in self.candidates.values() {
            if candidate.jobs.capacity() > MAX_SELECTION_JOBS {
                return Err("pool candidate backing invariant".into());
            }
            bytes = add(bytes, vector::<JobId>(candidate.jobs.capacity())?)?;
        }
        for (_, message) in &self.failures {
            if message.capacity() > 4 * MAX_FAILURE_CHARS {
                return Err("pool failure backing invariant".into());
            }
            bytes = add(bytes, message.capacity())?;
        }
        if self.jobs.len() > MAX_JOBS
            || self.candidates.len() > MAX_CANDIDATES
            || self.slots.capacity() > MAX_WORKERS
            || self.failures.len() > MAX_FAILURES
            || bytes > Self::bookkeeping_storage()?.retained_bytes
        {
            return Err("pool retained backing invariant".into());
        }
        self.costs.retained_storage_bytes()?;
        Ok(bytes)
    }
}
