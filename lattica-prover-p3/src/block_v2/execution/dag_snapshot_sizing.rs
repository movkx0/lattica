//! Persistence/recovery metadata backing, separate from payloads and verification.
use super::*;
use crate::block_v2::execution::storage_bound::{add, btree, growing_vector, mul, vector};
use core::mem::size_of;

fn vec_bytes<T>(capacity: usize) -> Result<usize, Error> {
    add(size_of::<Vec<T>>(), vector::<T>(capacity)?)
}
fn map_bytes<K, V>(entries: usize) -> Result<usize, Error> {
    add(size_of::<BTreeMap<K, V>>(), btree::<K, V>(entries)?)
}
fn set_bytes<K>(entries: usize) -> Result<usize, Error> {
    add(size_of::<BTreeSet<K>>(), btree::<K, ()>(entries)?)
}

/// Requested metadata backing. Includes conservative inline headers, not
/// allocator/OS overhead, input/output payloads, proof decoding or verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotStorage {
    pub encode_metadata_bytes: usize,
    pub recover_metadata_bytes: usize,
}

impl Limits {
    pub fn snapshot_storage(self) -> Result<SnapshotStorage, Error> {
        self.validate()?;
        let (j, c, a) = (self.jobs, self.candidates, self.attempts);
        let encode_metadata_bytes =
            add(vec_bytes::<&Record>(j)?, vec_bytes::<WorkerId>(mul(2, a)?)?)?;
        // Charge all parse/validation owners together, even where scopes are
        // disjoint. Recovery's returned arrays can then coexist with encoding
        // during resume, so consumers must ADD the two metadata components.
        let recover_metadata_bytes = [
            size_of::<Restored>(),
            size_of::<Reader<'_>>(),
            vec_bytes::<RawWorkspace>(a)?,
            vec_bytes::<WorkspaceLease>(a)?,
            vec_bytes::<RawJob>(j)?,
            mul(
                j,
                add(vec_bytes::<ArtifactRef>(2)?, vec_bytes::<JobId>(2)?)?,
            )?,
            map_bytes::<JobId, usize>(j)?, // seen
            vec_bytes::<PreviousCandidate>(c)?,
            set_bytes::<u64>(c)?,
            vec_bytes::<PreviousAttempt>(a)?,
            mul(a, vec_bytes::<ArtifactRef>(2)?)?,
            set_bytes::<u64>(a)?, // attempt ids
            set_bytes::<WorkerId>(mul(2, a)?)?,
            set_bytes::<JobId>(j)?,          // active
            map_bytes::<u64, usize>(a)?,     // launch indices
            set_bytes::<JobId>(j)?,          // owned
            set_bytes::<JobId>(j.min(128))?, // candidate validation closure
            add(
                size_of::<Vec<JobId>>(),
                growing_vector::<JobId>(add(mul(2, j)?, 1)?)?,
            )?,
            vec_bytes::<ArtifactRef>(2)?, // expected input manifest
            vec_bytes::<VerifiedWallet>(2)?,
            vec_bytes::<Vec<u8>>(2)?, // proof backing has a separate allowance
        ]
        .into_iter()
        .try_fold(0, add)?;
        Ok(SnapshotStorage {
            encode_metadata_bytes,
            recover_metadata_bytes,
        })
    }
}

/// One metadata index shared by both the count and write passes. Sorting is in
/// place; attempt and launch records are streamed directly from their maps.
pub(super) struct Index<'a> {
    pub jobs: Vec<&'a Record>,
    workers: Vec<WorkerId>,
}

impl<'a> Index<'a> {
    pub fn new(dag: &'a Dag) -> Result<Self, Error> {
        dag.limits.validate()?;
        if dag.jobs.len() > dag.limits.jobs
            || dag.candidates.len() > dag.limits.candidates
            || dag.attempts.len() > dag.limits.attempts
            || dag.workspaces.len() > dag.limits.attempts
        {
            return Err("checkpoint graph cardinality".into());
        }
        let mut jobs = Vec::with_capacity(dag.jobs.len());
        jobs.extend(dag.jobs.values());
        jobs.sort_unstable_by_key(|r| (r.job.expected().level, r.job.start(), r.job.id()));
        let mut workers = Vec::new();
        if !dag.workspaces.is_empty() {
            let active = dag.attempts.values().filter(|a| !a.released);
            workers = Vec::with_capacity(add(active.clone().count(), dag.workspaces.len())?);
            workers.extend(active.map(|a| a.lease.worker));
            workers.extend(dag.workspaces.values().map(|w| w.worker));
            workers.sort_unstable();
            if workers.windows(2).any(|w| w[0] == w[1]) {
                return Err("checkpoint duplicate workspace/attempt worker".into());
            }
        }
        let index = Self { jobs, workers };
        if index.bytes()? > dag.limits.snapshot_storage()?.encode_metadata_bytes {
            return Err("checkpoint encoding metadata admission".into());
        }
        Ok(index)
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        add(
            vec_bytes::<&Record>(self.jobs.capacity())?,
            vec_bytes::<WorkerId>(self.workers.capacity())?,
        )
    }
}

/// Check actual retained capacities before entering expensive proof recovery.
/// This census does not allocate and includes BTree layouts conservatively.
#[derive(Default)]
pub(super) struct Census(usize);
impl Census {
    pub fn vector<T>(&mut self, value: &Vec<T>) -> Result<(), Error> {
        self.0 = add(self.0, vec_bytes::<T>(value.capacity())?)?;
        Ok(())
    }
    pub fn map<K, V>(&mut self, value: &BTreeMap<K, V>) -> Result<(), Error> {
        self.0 = add(self.0, map_bytes::<K, V>(value.len())?)?;
        Ok(())
    }
    pub fn set<K>(&mut self, value: &BTreeSet<K>) -> Result<(), Error> {
        self.0 = add(self.0, set_bytes::<K>(value.len())?)?;
        Ok(())
    }
    pub fn admit(self, limits: Limits) -> Result<(), Error> {
        if self.0 > limits.snapshot_storage()?.recover_metadata_bytes {
            return Err("checkpoint recovery metadata admission".into());
        }
        #[cfg(test)]
        RECOVERY_CENSUS.with(|n| n.set(self.0));
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    pub(super) static RECOVERY_CENSUS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}
