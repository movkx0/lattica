//! Report-only CPU quota projection for the exact immutable pending source.
use super::*;
use crate::opencl::RuntimeError;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::{
    Error as PhaseError, NativeShakeQuotaProjection,
};

/// Numbers from a source-only reservation, deliberately distinct from the
/// actual prepared phase's OuterContinuationCapacity. No token is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProjectedHashxQuota {
    pub startup: Bytes,
    pub phase_wrappers: Bytes,
    pub pcs: Bytes,
    pub retained_tree_host_bytes: u64,
}

/// Charged in the original pending bookkeeping before either projected or
/// actual preparation, so inspection never obtains an older, larger capacity.
pub(super) fn additional_host_bytes() -> Result<usize> {
    let parts = [
        checked_frames::<ProjectedHashxQuota>(8)?,
        checked_frames::<Result<ProjectedHashxQuota>>(8)?,
        checked_frames::<PendingRuntime>(8)?,
        checked_frames::<core::result::Result<PendingRuntime, RuntimeError>>(8)?,
        checked_frames::<NativeShakeQuotaProjection<'static>>(8)?,
        checked_frames::<core::result::Result<NativeShakeQuotaProjection<'static>, RuntimeError>>(
            8,
        )?,
        checked_frames::<core::result::Result<NativeShakeQuotaProjection<'static>, PhaseError>>(8)?,
        checked_frames::<Snapshot>(8)?,
        checked_frames::<Bytes>(16)?,
        checked_frames::<Option<Bytes>>(8)?,
        checked_frames::<Requirements>(8)?,
        checked_frames::<Result<()>>(8)?,
        checked_frames::<&PendingNativeHashx<'static>>(8)?,
        checked_frames::<&ReservedShakeRequest>(8)?,
        checked_frames::<&Ledger>(8)?,
        NativeShakeQuotaProjection::additional_host_bytes(),
        // Full fixed identity, source, quota, iterator and diagnostic frames.
        8 * 4096,
    ];
    parts
        .iter()
        .try_fold(size_of_val(&parts) * 8, |sum, &part| {
            sum.checked_add(part).ok_or(Error::Overflow)
        })
}

fn add_bytes(left: Bytes, right: Bytes) -> Result<Bytes> {
    Ok(Bytes {
        host: left.host.checked_add(right.host).ok_or(Error::Overflow)?,
        device: left
            .device
            .checked_add(right.device)
            .ok_or(Error::Overflow)?,
    })
}

impl PendingNativeHashx<'_> {
    /// Hold all B source/compiler/output/caller claims before calling. The
    /// exact pending source remains immutable and reusable for real prepare.
    /// Temporary genuine startup/wrapper/PCS quota is destroyed before return.
    /// No environment, driver, PCS planner, context, proof, or phase is used.
    /// Success establishes projected quota fit only; actual prepare and all
    /// physical/native/outer admission remain mandatory on the GPU path.
    pub(crate) fn project_outer_quota(
        &self,
        expected: &ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<ProjectedHashxQuota> {
        if !core::ptr::eq(self.owner, expected) || !self.owner.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        source(expected, ledger)?;
        check_bookkeeping(&self.bookkeeping, ledger)?;
        outer::check_bridge(self.outer_bridge.as_ref().ok_or(Error::Authority)?, ledger)?;
        if !self.preparation.is_for(expected, 0, ledger)
            || !self.verification.belongs_to(ledger)
            || self.verification.requirements() != VerificationPlan::component_requirement()
            || self.future[0].is_some()
            || self.future[1..].iter().any(Option::is_none)
            || self.outputs.iter().any(Option::is_none)
            || self.verifiers.iter().any(Option::is_none)
            || self.retained.iter().any(Option::is_none)
            || self.attachments.iter().any(Option::is_none)
        {
            return Err(Error::Authority);
        }
        let before = ledger.snapshot();
        let runtime =
            PendingRuntime::reserve_outer_host_v1(ledger, limits()).map_err(|_| Error::Runtime)?;
        let quota = runtime
            .project_native_hashx_quota(ledger)
            .map_err(|_| Error::Phase)?;
        let report = ProjectedHashxQuota {
            startup: runtime.reserved_bytes(),
            phase_wrappers: quota.wrapper_bytes(),
            pcs: quota.pcs_bytes(),
            retained_tree_host_bytes: runtime.reserved_tree_host_bytes(),
        };
        let expected_current = add_bytes(
            add_bytes(
                add_bytes(before.current, report.startup)?,
                report.phase_wrappers,
            )?,
            report.pcs,
        )?;
        if ledger.snapshot().current != expected_current
            || expected_current.device != DEVICE_BYTES
            || report.retained_tree_host_bytes != 8 << 30
        {
            return Err(Error::Authority);
        }
        drop(quota);
        drop(runtime);
        if ledger.snapshot().current != before.current {
            return Err(Error::Authority);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
