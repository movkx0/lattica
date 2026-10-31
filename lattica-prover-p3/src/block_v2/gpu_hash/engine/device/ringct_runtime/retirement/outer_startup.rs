//! Consume a genuine host runtime's sealed original after all phase bindings.
use super::*;
use crate::ringct_research_quota::Bytes;

pub(super) fn additional_host_bytes() -> usize {
    // Original/moved owners, validation frames and both result branches stay
    // covered by the original startup claim. No stack reuse is credited.
    2 * size_of::<RetiredRuntime>()
        + 2 * size_of::<core::result::Result<Reservation, (Error, RetiredRuntime)>>()
        + 2 * size_of::<Requirements>()
        + 2 * size_of::<StartupPlan>()
        + 2 * size_of::<core::result::Result<StartupPlan, Error>>()
        + 2 * size_of::<Footprint>()
        + 2 * size_of::<Bytes>()
        + 2 * size_of::<core::result::Result<(), Error>>()
        + size_of::<&Ledger>()
        + 4 * size_of::<bool>()
}

impl RetiredRuntime {
    /// Read-only accounting, never a replacement owner or dispatch authority.
    pub fn startup_requirements(&self) -> Requirements {
        self.original.requirements()
    }

    pub fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger)
    }

    /// Release only the actual original startup reservation of a retired
    /// OuterHostV1 runtime that had no other phase binding at retirement.
    /// The caller still has to validate its exact enclosing startup census.
    /// No raw reservation, copied receipt or numeric declaration can enter.
    /// Refusal preserves this complete sealed owner, including its binding.
    pub fn into_outer_host_original(
        self,
        ledger: &Ledger,
    ) -> core::result::Result<Reservation, (Error, Self)> {
        let checked = (|| -> core::result::Result<(), Error> {
            if !self.sole_binding_at_retirement
                || !self.binding.is_retired()
                || self.receipt.managed_live_bytes != 0
                || self.receipt.host_tree_live_bytes != 0
                || !self.receipt.lease_released
            {
                return Err(Error::Lifecycle);
            }
            let expected = StartupPlan::outer_host_v1()?.footprint();
            if self.footprint != expected {
                return Err(Error::Resource);
            }
            let original = self.original.requirements();
            let bytes = original.get(Category::PhaseScratch);
            if !self.original.belongs_to(ledger)
                || original != Requirements::single(Category::PhaseScratch, bytes)
                || bytes.host < expected.requested_host_bytes as u64
                || bytes.device != expected.managed_device_bytes as u64
            {
                return Err(Error::Resource);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error, self));
        }
        // This destroys the last binding before exposing its original quota.
        // No environment/device selection, admission or dispatch takes place.
        Ok(self.into_original())
    }
}
