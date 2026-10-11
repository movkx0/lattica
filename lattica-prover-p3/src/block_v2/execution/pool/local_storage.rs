//! One shared local launch store and bounded persistent local endpoints.
//! Pool polling is sequential; only one control/observation pass is charged.

use super::*;
use crate::block_v2::execution::{
    launch::{LaunchLimits, LaunchStorage},
    os_worker, policy_context,
    storage_bound::{add, mul},
};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalPoolStorage {
    pub launch: LaunchStorage,
    pub endpoint_bytes: usize,
    pub control_bytes: usize,
}
impl LocalPoolStorage {
    pub fn new(limits: LaunchLimits, workers: usize) -> Result<Self, Error> {
        if !(1..=super::super::MAX_WORKERS).contains(&workers) {
            return Err("local endpoint storage worker count".into());
        }
        let process = ProcessWorker::storage_plan()?;
        Ok(Self {
            launch: limits.storage_plan()?,
            endpoint_bytes: mul(workers, LocalProcessEndpoint::retained_storage_bound()?)?,
            control_bytes: add(
                process.control_bytes,
                add(
                    os_worker::observation_storage()?.control_bytes,
                    8 * size_of::<std::sync::MutexGuard<'_, LaunchStore>>(),
                )?,
            )?,
        })
    }
    pub fn total_bytes(self) -> Result<usize, Error> {
        add(
            self.launch.total_bytes()?,
            add(self.endpoint_bytes, self.control_bytes)?,
        )
    }
    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("local endpoint storage component admission".into());
        }
        Ok(())
    }
}
impl LocalProcessEndpoint {
    fn retained_storage_bound() -> Result<usize, Error> {
        let outer = size_of::<Self>()
            .checked_sub(size_of::<ProcessWorker>())
            .ok_or("local endpoint layout invariant")?;
        add(
            outer,
            add(
                ProcessWorker::storage_plan()?.retained_bytes,
                policy_context::MAX_BYTES,
            )?,
        )
    }
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let context = self.context.as_ref().map_or(0, Vec::capacity);
        if context > policy_context::MAX_BYTES {
            return Err("local context backing invariant".into());
        }
        let bytes = add(
            size_of::<Self>() - size_of::<ProcessWorker>(),
            add(self.worker.persistent_storage_bytes()?, context)?,
        )?;
        if bytes > Self::retained_storage_bound()? {
            return Err("local endpoint retained storage invariant".into());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_component_shares_control_work_and_counts_each_endpoint() {
        for workers in 1..=16 {
            let plan = LocalPoolStorage::new(LaunchLimits { records: 16384 }, workers).unwrap();
            let total = plan.total_bytes().unwrap();
            plan.admit(total).unwrap();
            assert!(plan.admit(total - 1).is_err());
            let single = LocalPoolStorage::new(LaunchLimits { records: 16384 }, 1).unwrap();
            assert_eq!(plan.endpoint_bytes, workers * single.endpoint_bytes);
            assert_eq!(plan.control_bytes, single.control_bytes);
            if workers == 1 || workers == 16 {
                eprintln!("bounded_local_pool workers={workers} launch_bytes={} endpoint_bytes={} control_bytes={} total_bytes={total}",
                    plan.launch.total_bytes().unwrap(), plan.endpoint_bytes, plan.control_bytes);
            }
        }
        assert!(LocalPoolStorage::new(LaunchLimits { records: 256 }, 0).is_err());
        assert!(LocalPoolStorage::new(LaunchLimits { records: 256 }, 17).is_err());
    }
}
