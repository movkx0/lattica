//! Retained graph backing only. Transitions, snapshot/recovery indexes, caller
//! buffers, durable/store owners, queues and allocator/OS storage are separate.
use super::*;
use crate::block_v2::execution::storage_bound::{add, btree, mul, vector};
use core::mem::size_of;

const INPUTS: usize = 2;
const CLOSURE: usize = crate::block_v2::profile::MAX_DAG_NODES;
// Arc<[u8]> owns two usize counters and byte data, padded to usize alignment.
const ARC_OVERHEAD: usize = 3 * size_of::<usize>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedStorage {
    /// Collection backing, inline Dag, Arc headers and tail padding.
    pub metadata_bytes: usize,
    /// Immutable wallet/output bytes retained by records, not extra Arc handles.
    pub artifact_bytes: usize,
}

impl RetainedStorage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        add(self.metadata_bytes, self.artifact_bytes)
    }

    /// Component admission only; the caller must reserve every other owner
    /// separately. This neither increases a physical cap nor admits a worker.
    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("execution retained graph storage admission".into());
        }
        Ok(())
    }
}

fn maps(
    jobs: usize,
    candidates: usize,
    attempts: usize,
    workspaces: usize,
) -> Result<usize, Error> {
    [
        size_of::<Dag>(),
        btree::<JobId, Record>(jobs)?,
        btree::<CandidateId, Candidate>(candidates)?,
        btree::<AttemptId, Attempt>(attempts)?,
        btree::<WorkspaceId, WorkspaceLease>(workspaces)?,
    ]
    .into_iter()
    .try_fold(0, add)
}

pub(super) fn job_heap_limit() -> Result<usize, Error> {
    add(vector::<JobId>(INPUTS)?, vector::<ArtifactRef>(INPUTS)?)
}

impl Limits {
    /// Worst retained graph component at these cardinality and artifact limits.
    /// The Rust BTree layout is pinned; this is requested backing, not RSS.
    pub fn retained_storage(self) -> Result<RetainedStorage, Error> {
        self.validate()?;
        let record = [
            job_heap_limit()?,
            vector::<Arc<[u8]>>(INPUTS)?,
            btree::<CandidateId, ()>(self.candidates)?,
            mul(INPUTS + 1, ARC_OVERHEAD)?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        let attempt = add(vector::<ArtifactRef>(INPUTS)?, vector::<Arc<[u8]>>(INPUTS)?)?;
        let metadata_bytes = [
            maps(self.jobs, self.candidates, self.attempts, self.attempts)?,
            mul(self.jobs, record)?,
            mul(self.candidates, btree::<JobId, ()>(CLOSURE)?)?,
            mul(self.attempts, attempt)?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        Ok(RetainedStorage {
            metadata_bytes,
            artifact_bytes: self.artifact_bytes,
        })
    }
}

impl Dag {
    /// Capacity census of retained ownership. Shared attempt/assignment input
    /// handles do not add payload backing: pruning is fenced until all attempts
    /// release, and release clears input Arcs. Count all Vec *capacities*.
    pub fn retained_storage(&self) -> Result<RetainedStorage, Error> {
        let mut metadata = maps(
            self.jobs.len(),
            self.candidates.len(),
            self.attempts.len(),
            self.workspaces.len(),
        )?;
        let mut artifacts = 0;
        for record in self.jobs.values() {
            metadata = add(metadata, record.job.owned_heap_bytes()?)?;
            metadata = add(metadata, vector::<Arc<[u8]>>(record.wallets.capacity())?)?;
            metadata = add(metadata, btree::<CandidateId, ()>(record.candidates.len())?)?;
            for bytes in record
                .wallets
                .iter()
                .chain(record.output.iter().map(|(_, b)| b))
            {
                artifacts = add(artifacts, bytes.len())?;
                metadata = add(metadata, ARC_OVERHEAD)?;
            }
        }
        for candidate in self.candidates.values() {
            metadata = add(metadata, btree::<JobId, ()>(candidate.closure.len())?)?;
        }
        for attempt in self.attempts.values() {
            metadata = add(
                metadata,
                vector::<ArtifactRef>(attempt.manifest.capacity())?,
            )?;
            metadata = add(metadata, vector::<Arc<[u8]>>(attempt.inputs.capacity())?)?;
        }
        let plan = self.limits.retained_storage()?;
        if artifacts != self.stored_bytes
            || artifacts > plan.artifact_bytes
            || metadata > plan.metadata_bytes
        {
            return Err("execution retained graph storage invariant".into());
        }
        Ok(RetainedStorage {
            metadata_bytes: metadata,
            artifact_bytes: artifacts,
        })
    }
}

#[cfg(test)]
#[path = "dag_storage_tests.rs"]
mod tests;
