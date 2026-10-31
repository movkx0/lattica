//! Actual original pre-native capacity for later source feasibility planning.
//! Numbers are diagnostics only: they cannot reserve, restore or dispatch.
use super::*;
use lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::{
    Error as StartupError, Footprint, StartupPlan,
};

pub(super) fn additional_host_bytes() -> Result<usize> {
    let parts = [
        checked_frames::<OuterContinuationCapacity>(8)?,
        checked_frames::<Result<OuterContinuationCapacity>>(8)?,
        checked_frames::<StartupPlan>(8)?,
        checked_frames::<core::result::Result<StartupPlan, StartupError>>(8)?,
        checked_frames::<Footprint>(8)?,
        checked_frames::<Requirements>(8)?,
        checked_frames::<Bytes>(8)?,
        checked_frames::<Result<Bytes>>(8)?,
        checked_frames::<Option<&PreparedNativeSegment<'static>>>(8)?,
        checked_frames::<Option<&PreissuedNativeSegment<'static>>>(8)?,
        // Fixed source/caller, diagnostic, iterator/return and scalar frames.
        8 * 4096,
    ];
    parts
        .iter()
        .try_fold(size_of_val(&parts) * 8, |sum, &part| {
            sum.checked_add(part).ok_or(Error::Overflow)
        })
}

impl PreparedNativeHashx<'_> {
    /// Inspect only the actual first unattempted phase and its original startup.
    /// All compiler/source/output/report/planner claims must already be held
    /// before `prepare`, so they reduce this immutable PCS assignment. Later
    /// source checks must use their own preclaimed storage; these numbers grant
    /// no new allowance, phase owner, original token, or complete-request permit.
    /// A future native-to-outer transition must still bind its exact opaque
    /// backend plan to the original core attempt and successful terminal owner.
    pub(crate) fn outer_continuation_capacity(&self) -> Result<OuterContinuationCapacity> {
        source(self.owner, &self.ledger)?;
        check_bookkeeping(&self.bookkeeping, &self.ledger)?;
        let current = self.current.as_ref().ok_or(Error::Authority)?;
        if current.index != 0
            || !core::ptr::eq(current.owner, self.owner)
            || !current.preparation.is_for(self.owner, 0, &self.ledger)
            || !current.runtime.belongs_to(&self.ledger)
            || current.runtime.reserved_tree_host_bytes() != 8 << 30
            || !current.verification.belongs_to(&self.ledger)
            || current.verification.requirements() != VerificationPlan::component_requirement()
            || !current.retained.belongs_to(&self.ledger)
            || current.retained.requirements() != retained_requirement()?
            || self.attachments.iter().any(Option::is_none)
        {
            return Err(Error::Authority);
        }
        for (slot, successor) in self.successors.iter().enumerate() {
            let successor = successor.as_ref().ok_or(Error::Authority)?;
            let index = slot + 1;
            if successor.index != index
                || !core::ptr::eq(successor.owner, self.owner)
                || !successor.preparation.is_for(self.owner, index)
                || successor.preparation.requirements() != current.preparation.plan.requirements
                || !successor.retained.belongs_to(&self.ledger)
                || successor.retained.requirements() != retained_requirement()?
            {
                return Err(Error::Authority);
            }
        }
        let startup = current.runtime.reserved_bytes();
        let planned = StartupPlan::outer_host_v1()
            .map_err(|_| Error::Runtime)?
            .footprint();
        let pcs = current
            .phase
            .original_pcs_bytes(&self.ledger)
            .map_err(|_| Error::Phase)?;
        if planned.retained_tree_host_bytes != 8 << 30
            || startup.host < planned.requested_host_bytes as u64
            || startup.device != planned.managed_device_bytes as u64
            || pcs.host == 0
            || pcs.host > 24 << 30
            || startup.device.checked_add(pcs.device) != Some(DEVICE_BYTES)
        {
            return Err(Error::Authority);
        }
        Ok(OuterContinuationCapacity {
            startup,
            pcs,
            retained_tree_host_bytes: current.runtime.reserved_tree_host_bytes(),
        })
    }
}
