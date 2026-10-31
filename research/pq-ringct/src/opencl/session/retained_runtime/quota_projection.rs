//! Borrow the real pending startup without inspecting physical selection.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::NativeShakeQuotaProjection;

impl PendingRuntime {
    pub(crate) fn project_native_hashx_quota<'startup>(
        &'startup self,
        ledger: &Ledger,
    ) -> Result<NativeShakeQuotaProjection<'startup>, RuntimeError> {
        fixed_limits(self.limits)?;
        if self.selection.is_some()
            || !self.belongs_to(ledger)
            || self.reserved_tree_host_bytes() != 8 << 30
            || self.reserved_bytes() != requested(&self.plan)?
        {
            return Err(RuntimeError::WrongLedger);
        }
        NativeShakeQuotaProjection::reserve_outer_host_v1(&self.reservation, ledger)
            .map_err(|_| RuntimeError::Admission)
    }
}
