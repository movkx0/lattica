//! Match actual original runtime retirement before releasing native scratch.
use super::*;
use crate::block_v2::gpu_hash::device::ringct_runtime::{RetiredRuntime, Retirement};
pub(super) use crate::block_v2::gpu_hash::engine::owned_runtime::RuntimeBinding;

/// Original reservations after runtime payload and identity markers have been
/// destroyed. The immutable inline PCS plan survives for a source-preissued
/// successor; it owns no device state and cannot dispatch by itself.
#[must_use = "retain these original claims for the closed sequential phase planner"]
pub struct RetiredNativeReservations {
    retirement: Retirement,
    preparation: TranscriptPreparationPlan,
    pcs_plan: NativeTranscriptPcsPlan,
    succeeded: bool,
    pending_output: Option<PendingTranscriptOutput>,
    startup: Reservation,
    wrappers: Reservation,
    pcs: Reservation,
}

impl RetiredNativeReservations {
    pub fn retirement(&self) -> Retirement {
        self.retirement
    }

    pub fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.startup.belongs_to(ledger)
            && self.wrappers.belongs_to(ledger)
            && self.pcs.belongs_to(ledger)
    }

    /// Source diagnostic for exact host runtime restoration. Copying this
    /// request does not expose or replace the sealed original startup owner.
    pub fn startup_requirements(&self) -> Requirements {
        self.startup.requirements()
    }

    /// All three are the original non-Clone claims. No marker remains that
    /// could retain startup backing after one of these tokens is dropped.
    pub fn into_originals(self) -> (Reservation, Reservation, Reservation) {
        let Self {
            pcs_plan,
            pending_output,
            startup,
            wrappers,
            pcs,
            ..
        } = self;
        drop(pcs_plan);
        drop(pending_output);
        (startup, wrappers, pcs)
    }

    /// Used by the complete workflow's original slot issuer. A refused proof
    /// returns its still-empty output originals as well; successful proof
    /// output stays with OwnedTranscriptProof until its actual payload is destroyed.
    pub fn into_originals_and_output(self) -> (
        Reservation, Reservation, Reservation, Option<(Reservation, Reservation)>,
    ) {
        let Self { pcs_plan, pending_output, startup, wrappers, pcs, .. } = self;
        drop(pcs_plan);
        let output = pending_output.map(PendingTranscriptOutput::into_originals);
        (startup, wrappers, pcs, output)
    }

}

pub(super) fn additional_wrapper_host_bytes() -> usize {
    2 * size_of::<RetiredNativeReservations>()
        + 2 * size_of::<RuntimeBinding>()
        + 2 * size_of::<core::result::Result<
            RetiredNativeReservations,
            (Error, NativeTranscriptPhase, RetiredRuntime),
        >>()
        + 4 * size_of::<Reservation>()
        + 2 * size_of::<Requirements>()
        + 2 * size_of::<(&NativeTranscriptPhase, &RetiredRuntime, &Ledger)>()
        + 2 * size_of::<Result<()>>()
        // The phase Weak can outlive a dropped refused runtime owner. Cover
        // that retained Arc control block independently until this phase dies.
        + RuntimeBinding::retained_allocation_bytes()
        + 2 * size_of::<Result<OwnedTranscriptProof>>()
}

impl NativeTranscriptPhase {
    /// Borrowed authentication keeps every original in its guarded phase
    /// during all fallible checks. This receipt is issued only by real runtime
    /// destruction; it cannot be constructed from a quota or telemetry record.
    pub fn check_retired_originals(&self, runtime: &RetiredRuntime, ledger: &Ledger) -> Result<()> {
        check_ledger(ledger)?;
        if !self.attempted
            || !self
                .retirement_binding
                .as_ref()
                .is_some_and(|binding| runtime.matches(binding))
        {
            return Err(Error::Runtime);
        }
        let expected = match self.tree_profile {
            TreeProfile::Device => StartupPlan::new(),
            TreeProfile::OuterHostV1 => StartupPlan::outer_host_v1(),
        }
        .map_err(|_| Error::Runtime)?
        .footprint();
        if runtime.footprint() != expected {
            return Err(Error::Runtime);
        }
        let baseline = self
            .tree_profile
            .check_startup(runtime.original(), ledger)?;
        let footprint = self.pcs.footprint();
        self.tree_profile.check_plan(footprint)?;
        if only(&self.wrappers, Category::PhaseScratch, ledger)?
            != (Bytes {
                host: self.tree_profile.phase_wrapper_host_bytes()? as u64,
                device: 0,
            })
            || only(&self.pcs_owner, Category::PhaseScratch, ledger)?
                != (Bytes {
                    host: footprint.operation_host_budget_bytes as u64,
                    device: MANAGED_DEVICE
                        .checked_sub(baseline as u64)
                        .ok_or(Error::Authority)?,
                })
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
    /// Consume the native phase only after a sealed marker from the same
    /// original runtime has completed retirement. Refusal preserves both
    /// complete owners; it does not release quota or authorize another attempt.
    pub fn into_retired_reservations(
        self,
        runtime: RetiredRuntime,
        ledger: &Ledger,
    ) -> core::result::Result<RetiredNativeReservations, (Error, Self, RetiredRuntime)> {
        let checked = self.check_retired_originals(&runtime, ledger);
        if let Err(error) = checked {
            return Err((error, self, runtime));
        }
        let Self {
            tree_profile: _,
            preparation,
            pcs,
            trace: _,
            output,
            attempted: _,
            succeeded,
            retirement_binding,
            ledger: phase_ledger,
            wrappers,
            pcs_owner,
        } = self;
        // On a refused proof, the empty output slot still owns its originals.
        // Preserve it for the enclosing issuer after this exact runtime epoch
        // and every runtime identity marker have been destroyed.
        drop(retirement_binding);
        drop(phase_ledger);
        let retirement = runtime.receipt();
        let startup = runtime.into_original();
        Ok(RetiredNativeReservations {
            retirement,
            preparation,
            pcs_plan: pcs,
            succeeded,
            pending_output: output,
            startup,
            wrappers,
            pcs: pcs_owner,
        })
    }
}
