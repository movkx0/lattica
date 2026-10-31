//! Numeric capacity of the actual original unattempted host-profile owner.
use super::*;
use lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::StartupPlan;

/// Copyable numbers only. Neither this declaration nor any altered copy can
/// construct, restore, reserve, retarget or dispatch a phase owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OuterContinuationCapacity {
    pub startup: Bytes,
    pub pcs: Bytes,
    pub retained_tree_host_bytes: u64,
}

pub(super) fn additional_host_bytes() -> usize {
    3 * size_of::<OuterContinuationCapacity>()
        + 2 * size_of::<Result<OuterContinuationCapacity>>()
        + 2 * size_of::<Bytes>()
        + 2 * size_of::<StartupPlan>()
        + 2 * size_of::<lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::Footprint>()
}

impl PreparedNativeSingleton<'_> {
    /// Inspect exact original capacity before dispatch without admitting or
    /// extracting anything. All later phases still require their original
    /// preissued owners and genuine compiled-source conformance.
    pub(crate) fn outer_continuation_capacity(&self) -> Result<OuterContinuationCapacity> {
        if !self.owner.belongs_to(&self.ledger)
            || !self
                .preparation
                .is_for(self.owner, self.index, &self.ledger)
            || !self.runtime.belongs_to(&self.ledger)
            || self.runtime.reserved_tree_host_bytes() != 8 << 30
            || !self.verification.belongs_to(&self.ledger)
            || self.verification.requirements() != VerificationPlan::component_requirement()
            || !self.bookkeeping.belongs_to(&self.ledger)
            || self.bookkeeping.requirements() != bookkeeping_requirement()?
        {
            return Err(Error::Authority);
        }
        let startup = self.runtime.reserved_bytes();
        let core = StartupPlan::outer_host_v1()
            .map_err(|_| Error::Runtime)?
            .footprint();
        if startup.host < core.requested_host_bytes as u64
            || startup.device != core.managed_device_bytes as u64
            || core.retained_tree_host_bytes != 8 << 30
        {
            return Err(Error::Authority);
        }
        let pcs = self
            .phase
            .original_outer_pcs_bytes(&self.ledger)
            .map_err(|_| Error::Phase)?;
        if startup.device.checked_add(pcs.device) != Some(DEVICE_BYTES) {
            return Err(Error::Authority);
        }
        Ok(OuterContinuationCapacity {
            startup,
            pcs,
            retained_tree_host_bytes: self.runtime.reserved_tree_host_bytes(),
        })
    }
}
