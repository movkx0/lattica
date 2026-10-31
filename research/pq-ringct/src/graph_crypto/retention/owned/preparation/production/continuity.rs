//! Opt-in actual runtime retirement retaining the original sequential claims.
//! The existing standalone `produce` path keeps its behavior.
use super::*;
use crate::execution::retained_resources::Snapshot;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::RetiredNativeReservations;

/// Native proof/report and the three original retired phase claims. The entire
/// verified owner remains intact and is destroyed before this scratch owner.
pub(crate) struct VerifiedNativeSingletonWithOriginals<'request> {
    verified: VerifiedNativeSingleton<'request>,
    originals: RetiredNativeReservations,
}

impl<'request> VerifiedNativeSingletonWithOriginals<'request> {
    pub(crate) fn into_parts(
        self,
    ) -> (VerifiedNativeSingleton<'request>, RetiredNativeReservations) {
        (self.verified, self.originals)
    }
}

pub(super) fn additional_host_bytes() -> usize {
    2 * size_of::<VerifiedNativeSingletonWithOriginals<'static>>()
        + 2 * size_of::<Result<VerifiedNativeSingletonWithOriginals<'static>>>()
        + 2 * size_of::<RetiredNativeReservations>()
        + 3 * size_of::<Requirements>()
        + 4 * size_of::<Snapshot>()
        + capacity::additional_host_bytes()
        + successor::additional_host_bytes()
}

impl<'request> PreparedNativeSingleton<'request> {
    /// Preserve actual startup/wrapper/PCS owners through native production,
    /// exact consuming runtime retirement and independent CPU verification.
    /// Their later use still requires the closed source-preissued whole graph.
    ///
    /// # Safety
    /// The same immutable-process and exclusive-device contract as `produce`
    /// must hold through all original runtime destruction. No retries/fallback.
    pub(crate) unsafe fn produce_retaining_originals(
        mut self,
    ) -> Result<VerifiedNativeSingletonWithOriginals<'request>> {
        if !self.owner.belongs_to(&self.ledger)
            || !self
                .preparation
                .is_for(self.owner, self.index, &self.ledger)
            || !self.runtime.belongs_to(&self.ledger)
            || !self.verification.belongs_to(&self.ledger)
            || self.verification.requirements() != VerificationPlan::component_requirement()
            || !self.bookkeeping.belongs_to(&self.ledger)
            || self.bookkeeping.requirements() != bookkeeping_requirement()?
        {
            return Err(Error::Authority);
        }
        let Payload::Shake(input) = &self.owner.request().payload else {
            return Err(Error::Source);
        };
        let expected_geometry = self.preparation.census().geometry();
        // SAFETY: inherited unchanged sealed-process contract.
        let session = unsafe { self.runtime.start() }.map_err(|_| Error::Runtime)?;
        let attempted = (|| {
            let checked = session
                .check_reserved_runtime(&self.ledger)
                .map_err(|_| Error::Runtime)?;
            let runtime = checked.borrow_core().map_err(|_| Error::Runtime)?;
            let recording = self
                .preparation
                .record(&self.ledger)
                .map_err(|_| Error::Preparation)?;
            // SAFETY: original immutable source plus original complete owners
            // are retained exactly as in the default one-shot native producer.
            unsafe {
                self.phase.produce(
                    recording,
                    input,
                    runtime.runtime(),
                    runtime.reservation(),
                    &self.verification,
                )
            }
            .map_err(|_| Error::Phase)
        })();
        let before_retirement = self.ledger.snapshot();
        let retired = session
            .finish_reserved_with_owner(&self.ledger)
            .map_err(|_| Error::Runtime)?;
        if self.ledger.snapshot() != before_retirement {
            return Err(Error::Retirement);
        }
        let retirement = retired.receipt();
        if !retirement_is_complete(retirement) {
            std::process::abort();
        }
        let before_extraction = self.ledger.snapshot();
        let originals = match self.phase.into_retired_reservations(retired, &self.ledger) {
            Ok(originals) => originals,
            Err((_, phase, retired)) => {
                // This can include a pre-bind failure. Preserve fail-closed
                // behavior; there is no generic idle marker or retry.
                drop(phase);
                drop(retired);
                return Err(Error::Retirement);
            }
        };
        if self.ledger.snapshot() != before_extraction {
            return Err(Error::Retirement);
        }
        drop(self.preparation);
        if !originals.belongs_to(&self.ledger)
            || originals.retirement() != retirement
            || retirement.managed_peak_bytes == 0
            || retirement.managed_peak_bytes as u64 > DEVICE_BYTES
        {
            return Err(Error::Retirement);
        }
        let output = attempted?;
        if !output.belongs_to(&self.ledger) || output.geometry() != expected_geometry {
            return Err(Error::Authority);
        }
        let air = self
            .owner
            .request()
            .shake_partition()
            .and_then(|partition| partition.segments().get(self.index))
            .ok_or(Error::Source)?;
        let verification = verify_output(
            self.verifier,
            air,
            &output,
            self.verification,
            &self.bookkeeping,
            &self.ledger,
        )?;
        Ok(VerifiedNativeSingletonWithOriginals {
            verified: VerifiedNativeSingleton {
                output,
                owner: self.owner,
                index: self.index,
                verification,
                retirement,
                bookkeeping: self.bookkeeping,
            },
            originals,
        })
    }
}

#[cfg(test)]
mod tests;

mod capacity;
pub(crate) use capacity::OuterContinuationCapacity;

#[cfg(test)]
mod rejection;

mod successor;
pub(crate) use successor::{
    FutureNativeSingleton, NativeCompletionError, NativeSuccessorError, ReadyNativeSingleton,
};
