//! Explicit host-tree singleton component. This entry selects the original
//! host runtime before preflight; it never changes the process environment.
//! Full native-to-recursive workflows need their own preissued phase owners.
use super::{
    DEVICE_BYTES, Error, HOST_BYTES, Ledger, Limits, MAX_ROWS, NativeShakePhase, PendingRuntime,
    PreparedNativeSingleton, ReservedShakeRequest, Result, SourcePlan,
};

const HOST_TREE_BYTES: u64 = 8 << 30;

impl<'request> PreparedNativeSingleton<'request> {
    /// Prepare one native singleton using the explicitly selected
    /// `outer_host_v1` tree profile. The original 8 GiB host-tree quota is
    /// additive inside the existing worker ledger; the core phase derives its
    /// PCS assignment from the actual remainder, capped at 24 GiB.
    ///
    /// This is component admission only. A combined workflow must retain all
    /// preissued child, compiler, recursive output and verifier claims before
    /// calling this entry. No later phase may rely on a post-proof admission
    /// succeeding after the native PCS owner has retired.
    ///
    /// # Safety
    /// The dedicated coordinator guard must hold the exact immutable
    /// `outer_host_v1` environment and exclude unrelated GPU work/startup/
    /// shutdown from this preflight through produce/retirement, or destruction
    /// without dispatch. This entry must be chosen before any proof attempt;
    /// it is never a device-profile retry or fallback.
    pub(crate) unsafe fn new_outer_host_v1(
        owner: &'request ReservedShakeRequest,
        index: usize,
        ledger: &Ledger,
    ) -> Result<Self> {
        if !owner.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let source = SourcePlan::new(owner, index)?;
        let original = ledger
            .admit_phase(source.requirements)
            .map_err(|_| Error::Admission)?;
        let claimed = source.claim_for(owner, index, original, ledger)?;
        let mut runtime = PendingRuntime::reserve_outer_host_v1(
            ledger,
            Limits {
                host_bytes: HOST_BYTES,
                device_bytes: DEVICE_BYTES,
                max_rows: MAX_ROWS,
            },
        )
        .map_err(|_| Error::Runtime)?;
        if !runtime.belongs_to(ledger) || runtime.reserved_tree_host_bytes() != HOST_TREE_BYTES {
            return Err(Error::Authority);
        }
        // SAFETY: the exact host runtime and its complete original claim were
        // selected above under this entry's sealed-process contract.
        let preflight = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        // Preparation, proof/report, verifier, bookkeeping, host startup and
        // any future workflow owners are already retained in this ledger.
        // The core phase binds the same fixed tree profile, charges its OCL
        // wrappers and uses only the remaining PCS allowance before startup.
        let phase = unsafe {
            NativeShakePhase::new_outer_host_v1(
                claimed.preparation.census(),
                claimed.preparation.reservation(),
                preflight.reservation(),
                claimed.output,
                &claimed.verification,
                ledger,
            )
        }
        .map_err(|_| Error::Phase)?;
        drop(preflight);
        Ok(Self {
            owner: claimed.owner,
            index: claimed.index,
            phase,
            preparation: claimed.preparation,
            runtime,
            verifier: claimed.verifier,
            verification: claimed.verification,
            ledger: ledger.clone(),
            bookkeeping: claimed.bookkeeping,
        })
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;
