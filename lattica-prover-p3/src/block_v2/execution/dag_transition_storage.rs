//! Index backing for ordinary graph transitions and one result from each query.
//! Job construction, assignments, proof/caller buffers and allocator/OS costs
//! have separate per-job/runtime allowances.
use super::*;
use crate::block_v2::execution::storage_bound::{add, btree, growing_vector, mul, vector};
use core::mem::size_of;

pub(super) type ReadyKey = (u64, std::cmp::Reverse<u8>, u8, JobId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionStorage {
    pub index_bytes: usize,
    pub query_bytes: usize,
}
impl TransitionStorage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        add(self.index_bytes, self.query_bytes)
    }
}

impl Limits {
    pub fn transition_storage(self) -> Result<TransitionStorage, Error> {
        self.validate()?;
        let index_bytes = [
            // Charge cancellation lists together even where scopes are disjoint.
            growing_vector::<CandidateId>(self.candidates)?,
            mul(2, growing_vector::<AttemptId>(self.attempts)?)?,
            btree::<JobId, ()>(crate::block_v2::profile::MAX_DAG_NODES + 1)?, // attachment closure before insertion
            growing_vector::<JobId>(add(mul(2, self.jobs)?, 1)?)?,
            mul(2, btree::<JobId, ()>(self.jobs)?)?, // prune removable/keep sets
            vector::<JobId>(self.jobs)?,             // exact-capacity prune stack
            growing_vector::<ReadyKey>(self.jobs)?,
            8 * size_of::<Vec<JobId>>() + 3 * size_of::<BTreeSet<JobId>>(),
        ]
        .into_iter()
        .try_fold(0, add)?;
        let query_bytes = [
            vector::<JobId>(self.jobs)?,
            vector::<Lease>(self.attempts)?,
            vector::<ArtifactRef>(mul(3, self.jobs)?)?,
            3 * size_of::<Vec<JobId>>(),
        ]
        .into_iter()
        .try_fold(0, add)?;
        Ok(TransitionStorage {
            index_bytes,
            query_bytes,
        })
    }
}
