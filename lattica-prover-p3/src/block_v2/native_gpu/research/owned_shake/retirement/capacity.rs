//! Read original host-profile PCS capacity before the first native attempt.
use super::*;

pub(super) fn additional_host_bytes() -> usize {
    4 * size_of::<Bytes>()
        + 2 * size_of::<core::result::Result<Bytes, Error>>()
        + 2 * size_of::<Requirements>()
        + size_of::<NativeShakePcsFootprint>()
        + 2 * size_of::<StartupPlan>()
        + 2 * size_of::<crate::block_v2::gpu_hash::device::ringct_runtime::Footprint>()
}

impl NativeShakePhase {
    /// Numeric declaration of this exact original PCS claim. It creates no
    /// reservation, moves no token and grants no outer dispatch authority.
    /// A source-closed caller must separately retain the original startup,
    /// compiler, output, report and verifier owners before the first attempt.
    pub fn original_outer_pcs_bytes(&self, ledger: &Ledger) -> Result<Bytes> {
        check_ledger(ledger)?;
        if self.attempted || self.retirement_binding.is_some() {
            return Err(Error::AlreadyAttempted);
        }
        if self.tree_profile != TreeProfile::OuterHostV1
            || !self.pcs_owner.belongs_to(&self.ledger)
            || !self.wrappers.belongs_to(&self.ledger)
        {
            return Err(Error::Authority);
        }
        self.output
            .as_ref()
            .ok_or(Error::Output)?
            .check(self.preparation, ledger)
            .map_err(|_| Error::Output)?;
        let startup = StartupPlan::outer_host_v1()
            .map_err(|_| Error::Runtime)?
            .footprint();
        let footprint = self.pcs.footprint();
        self.tree_profile.check_plan(footprint)?;
        if only(&self.wrappers, Category::PhaseScratch, ledger)?
            != (Bytes {
                host: self.tree_profile.phase_wrapper_host_bytes()? as u64,
                device: 0,
            })
        {
            return Err(Error::Authority);
        }
        let original = only(&self.pcs_owner, Category::PhaseScratch, ledger)?;
        if original
            != (Bytes {
                host: footprint.operation_host_budget_bytes as u64,
                device: MANAGED_DEVICE
                    .checked_sub(startup.managed_device_bytes as u64)
                    .ok_or(Error::Authority)?,
            })
        {
            return Err(Error::Authority);
        }
        Ok(original)
    }
}
