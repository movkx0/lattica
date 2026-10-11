//! One caller-owned step batch, failure drain and returned root. Retaining
//! multiple batches or root copies requires a separate reservation for each.

use super::*;
use crate::block_v2::execution::storage_bound::{add, growing_vector, mul, vector};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolOutputStorage {
    pub accepted_bytes: usize,
    pub failure_bytes: usize,
    pub root_bytes: usize,
}

impl PoolOutputStorage {
    pub const ACCEPTED_LIMIT: usize = MAX_WORKERS;
    pub const FAILURE_LIMIT: usize = MAX_FAILURES;
    pub const FAILURE_BYTES: usize = 4 * MAX_FAILURE_CHARS;
    pub const ROOT_LIMIT: usize = crate::block_v2::profile::MAX_PROOF_BYTES;

    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            accepted_bytes: add(
                size_of::<Vec<AcceptedJob>>(),
                vector::<AcceptedJob>(MAX_WORKERS)?,
            )?,
            failure_bytes: [
                size_of::<Vec<(WorkerId, String)>>(),
                growing_vector::<(WorkerId, String)>(MAX_FAILURES)?,
                mul(MAX_FAILURES, Self::FAILURE_BYTES)?,
            ]
            .into_iter()
            .try_fold(0, add)?,
            root_bytes: add(size_of::<Vec<u8>>(), Self::ROOT_LIMIT)?,
        })
    }

    pub fn total_bytes(self) -> Result<usize, Error> {
        add(
            add(self.accepted_bytes, self.failure_bytes)?,
            self.root_bytes,
        )
    }

    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("pool returned output storage admission".into());
        }
        Ok(())
    }

    // Vec references are deliberate: the census includes spare capacity.
    pub fn accepted_storage_bytes(values: &Vec<AcceptedJob>) -> Result<usize, Error> {
        if values.capacity() > Self::ACCEPTED_LIMIT {
            return Err("pool returned accepted capacity".into());
        }
        add(
            size_of::<Vec<AcceptedJob>>(),
            vector::<AcceptedJob>(values.capacity())?,
        )
    }

    pub fn failure_storage_bytes(values: &Vec<(WorkerId, String)>) -> Result<usize, Error> {
        let backing = vector::<(WorkerId, String)>(values.capacity())?;
        if values.len() > Self::FAILURE_LIMIT
            || backing > growing_vector::<(WorkerId, String)>(Self::FAILURE_LIMIT)?
        {
            return Err("pool returned failure capacity".into());
        }
        let mut bytes = add(size_of::<Vec<(WorkerId, String)>>(), backing)?;
        for (_, message) in values {
            if message.capacity() > Self::FAILURE_BYTES {
                return Err("pool returned failure message capacity".into());
            }
            bytes = add(bytes, message.capacity())?;
        }
        Ok(bytes)
    }

    pub fn root_storage_bytes(bytes: &Vec<u8>) -> Result<usize, Error> {
        if bytes.capacity() > Self::ROOT_LIMIT {
            return Err("pool returned root capacity".into());
        }
        add(size_of::<Vec<u8>>(), bytes.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_batches_count_spare_capacity_and_independent_root_copies() {
        let plan = PoolOutputStorage::new().unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        let mut accepted = Vec::with_capacity(MAX_WORKERS);
        for i in 0..MAX_WORKERS {
            accepted.push(AcceptedJob {
                job: JobId::from_bytes([0; 32]).unwrap(),
                worker: WorkerId(i as u64),
                proof_bytes: PoolOutputStorage::ROOT_LIMIT,
                elapsed_ms: i as u64,
            });
        }
        let mut failures = Vec::new();
        for i in 0..MAX_FAILURES {
            failures.push((
                WorkerId(i as u64),
                failure_message(&"\u{1f680}".repeat(MAX_FAILURE_CHARS)),
            ));
        }
        let retained_accepted = PoolOutputStorage::accepted_storage_bytes(&accepted).unwrap();
        let retained_failures = PoolOutputStorage::failure_storage_bytes(&failures).unwrap();
        let root = vec![0x5a; PoolOutputStorage::ROOT_LIMIT];
        let copy = root.clone();
        assert_ne!(root.as_ptr(), copy.as_ptr());
        let retained_root = PoolOutputStorage::root_storage_bytes(&root).unwrap();
        assert_eq!(
            PoolOutputStorage::root_storage_bytes(&copy).unwrap(),
            retained_root
        );
        assert_eq!(retained_accepted, plan.accepted_bytes);
        assert!(retained_failures <= plan.failure_bytes);
        assert_eq!(retained_root, plan.root_bytes);
        accepted.clear();
        assert_eq!(
            PoolOutputStorage::accepted_storage_bytes(&accepted).unwrap(),
            retained_accepted
        );
        let drained = std::mem::take(&mut failures);
        assert_eq!(
            PoolOutputStorage::failure_storage_bytes(&drained).unwrap(),
            retained_failures
        );
        assert_eq!(
            PoolOutputStorage::failure_storage_bytes(&failures).unwrap(),
            size_of::<Vec<(WorkerId, String)>>()
        );
        eprintln!("bounded_pool_outputs accepted_bytes={} failure_bytes={} root_bytes={} total_bytes={total} failure_census_bytes={retained_failures} independent_roots=2", plan.accepted_bytes, plan.failure_bytes, plan.root_bytes);
    }

    #[test]
    fn returned_output_admission_rejects_spare_capacity_and_message_overflow() {
        assert!(
            PoolOutputStorage::accepted_storage_bytes(&Vec::with_capacity(MAX_WORKERS + 1))
                .is_err()
        );
        assert!(
            PoolOutputStorage::failure_storage_bytes(&Vec::with_capacity(2 * MAX_FAILURES + 1))
                .is_err()
        );
        let oversized = vec![(
            WorkerId(1),
            String::with_capacity(PoolOutputStorage::FAILURE_BYTES + 1),
        )];
        assert!(PoolOutputStorage::failure_storage_bytes(&oversized).is_err());
        let too_many: Vec<_> = (0..=MAX_FAILURES)
            .map(|i| (WorkerId(i as u64), String::new()))
            .collect();
        assert!(PoolOutputStorage::failure_storage_bytes(&too_many).is_err());
        assert!(PoolOutputStorage::root_storage_bytes(&Vec::with_capacity(
            PoolOutputStorage::ROOT_LIMIT + 1
        ))
        .is_err());
    }
}
