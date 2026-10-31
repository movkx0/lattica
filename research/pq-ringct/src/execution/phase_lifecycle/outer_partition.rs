//! Source-derived original startup/wrapper/PCS split shared by outer preissue
//! and dispatch. Reports, source compiler and independent verifier claims are
//! additive categories in the enclosing source facts, never recategorized.
use super::*;
use crate::opencl::{Limits, WorkflowRuntimePlan};
use lattica_prover_p3::proving::proof_storage::outer_ocl::FixedOuterOclStorage;

pub(in crate::execution) struct OuterRuntimePartitionPlan {
    startup: WorkflowRuntimePlan,
    startup_requirement: Requirements,
    wrappers: Requirements,
    pcs: Requirements,
    complete: Requirements,
    operation_host: usize,
}

impl OuterRuntimePartitionPlan {
    pub(in crate::execution) fn new(limits: Limits, backend: Bytes) -> Result<Self, Error> {
        let startup = WorkflowRuntimePlan::outer_host_v1(limits)
            .map_err(|_| Error::IncompleteOwnedPartition)?;
        let startup_requirement = startup.requirement().map_err(|_| Error::IncompleteOwnedPartition)?;
        let startup_bytes = startup_requirement.get(Category::PhaseScratch);
        let wrapper_host = u64::try_from(FixedOuterOclStorage::fixed()
            .map_err(|_| Error::IncompleteOwnedPartition)?.required_host_bytes())
            .map_err(|_| Error::IncompleteOwnedPartition)?;
        if backend.host == 0 || backend.host > limits.host_bytes
            || backend.device != limits.device_bytes || backend.device != 8 << 30
        {
            return Err(Error::IncompleteOwnedPartition);
        }
        let operation_host = backend.host.checked_sub(startup_bytes.host)
            .and_then(|host| host.checked_sub(wrapper_host))
            .filter(|host| *host > 0).ok_or(Error::IncompleteOwnedPartition)?
            .min(24 << 30);
        let wrappers = Requirements::single(Category::PhaseScratch, Bytes { host: wrapper_host, device: 0 });
        let pcs = Requirements::single(Category::PhaseScratch, Bytes {
            host: operation_host,
            device: backend.device.checked_sub(startup_bytes.device).ok_or(Error::IncompleteOwnedPartition)?,
        });
        let mut complete = startup_requirement;
        complete.add(Category::PhaseScratch, wrappers.get(Category::PhaseScratch))?;
        complete.add(Category::PhaseScratch, pcs.get(Category::PhaseScratch))?;
        Ok(Self { startup, startup_requirement, wrappers, pcs, complete,
            operation_host: usize::try_from(operation_host).map_err(|_| Error::IncompleteOwnedPartition)? })
    }

    pub(in crate::execution) fn startup_requirement(&self) -> Requirements { self.startup_requirement }
    pub(in crate::execution) fn wrapper_requirement(&self) -> Requirements { self.wrappers }
    pub(in crate::execution) fn pcs_requirement(&self) -> Requirements { self.pcs }
    pub(in crate::execution) fn complete_requirement(&self) -> Requirements { self.complete }
    pub(in crate::execution) fn operation_host(&self) -> usize { self.operation_host }
    pub(in crate::execution) fn into_startup_plan(self) -> WorkflowRuntimePlan { self.startup }
}

pub(in crate::execution) fn bookkeeping_bytes() -> usize {
    4 * core::mem::size_of::<OuterRuntimePartitionPlan>()
        + 4 * core::mem::size_of::<Result<OuterRuntimePartitionPlan, Error>>()
        + 8 * core::mem::size_of::<Requirements>()
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;

    #[test]
    fn host_tree_and_wrappers_reduce_pcs_within_the_same_complete_backend() {
        let limits = Limits { host_bytes: 32 << 30, device_bytes: 8 << 30, max_rows: 1 << 20 };
        let backend = Bytes { host: 24 << 30, device: 8 << 30 };
        let plan = OuterRuntimePartitionPlan::new(limits, backend).unwrap();
        assert_eq!(plan.complete_requirement().total().unwrap(), backend);
        assert!(plan.startup_requirement().get(Category::PhaseScratch).host >= 8 << 30);
        assert!(plan.operation_host() < 16 << 30);
        assert_eq!(plan.wrapper_requirement().get(Category::PhaseScratch).device, 0);
        assert_eq!(plan.pcs_requirement().get(Category::PhaseScratch).host, plan.operation_host() as u64);
        assert!(OuterRuntimePartitionPlan::new(limits, Bytes { host: 8 << 30, ..backend }).is_err());
        assert!(OuterRuntimePartitionPlan::new(limits, Bytes { device: (8 << 30) - 1, ..backend }).is_err());
    }
}
