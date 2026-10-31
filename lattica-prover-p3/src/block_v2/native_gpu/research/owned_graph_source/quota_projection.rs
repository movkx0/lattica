//! Pure source quota projection. This owner has no PCS plan or dispatch API.
use super::*;

/// Holds real wrapper/PCS quota while borrowing the original pure startup
/// claim. It cannot be converted into a native phase, preflight, or backend.
#[must_use = "the projected claims exist only while this owner is retained"]
pub struct NativeGraphSourceQuotaProjection<'startup> {
    _startup: &'startup Reservation,
    wrappers: Reservation,
    pcs: Reservation,
}

/// Shared with the actual native constructor. No environment or driver access.
pub(super) fn reserve_wrappers(profile: TreeProfile, ledger: &Ledger) -> Result<Reservation> {
    let host = u64::try_from(profile.phase_wrapper_host_bytes()?).map_err(|_| Error::Admission)?;
    ledger
        .reserve(Category::PhaseScratch, Bytes { host, device: 0 })
        .map_err(|_| Error::Admission)
}

/// Shared with the actual native constructor after its physical PCS planning.
pub(super) fn pcs_request(startup_device: usize, operation_host: usize) -> Result<Bytes> {
    if operation_host == 0 || operation_host > NATIVE_HOST {
        return Err(Error::Admission);
    }
    Ok(Bytes {
        host: u64::try_from(operation_host).map_err(|_| Error::Admission)?,
        device: MANAGED_DEVICE
            .checked_sub(u64::try_from(startup_device).map_err(|_| Error::Admission)?)
            .ok_or(Error::Admission)?,
    })
}

impl<'startup> NativeGraphSourceQuotaProjection<'startup> {
    /// Caller storage for the pure projection before its wrapper claim exists.
    pub const fn additional_host_bytes() -> usize {
        additional_host_bytes()
    }

    /// The startup claim must remain borrowed throughout this source-only
    /// projection. This calls neither selection/preflight nor the PCS planner.
    /// Successful quota reservation does not establish native or outer fit.
    pub fn reserve_outer_host_v1(startup: &'startup Reservation, ledger: &Ledger) -> Result<Self> {
        check_ledger(ledger)?;
        let startup_device = TreeProfile::OuterHostV1.check_startup(startup, ledger)?;
        let wrappers = reserve_wrappers(TreeProfile::OuterHostV1, ledger)?;
        let operation_host = operation_host_budget(ledger)?;
        let pcs = ledger
            .reserve(
                Category::PhaseScratch,
                pcs_request(startup_device, operation_host)?,
            )
            .map_err(|_| Error::Admission)?;
        Ok(Self {
            _startup: startup,
            wrappers,
            pcs,
        })
    }

    pub fn wrapper_bytes(&self) -> Bytes {
        self.wrappers.requirements().get(Category::PhaseScratch)
    }

    pub fn pcs_bytes(&self) -> Bytes {
        self.pcs.requirements().get(Category::PhaseScratch)
    }
}

/// Additive to both actual and projected phase wrapper accounting. Covers the
/// complete source-only owner/result plus the shared helper forwarding frames.
/// No payload is allocated beyond the original ledger reservation counters.
pub(super) const fn additional_host_bytes() -> usize {
    8 * (size_of::<NativeGraphSourceQuotaProjection<'static>>()
        + size_of::<Result<NativeGraphSourceQuotaProjection<'static>>>()
        + size_of::<Reservation>()
        + size_of::<Result<Reservation>>()
        + size_of::<Bytes>()
        + size_of::<Result<Bytes>>()
        + size_of::<Requirements>()
        + size_of::<StartupPlan>()
        + size_of::<Result<StartupPlan>>()
        + size_of::<
            core::result::Result<
                StartupPlan,
                crate::block_v2::gpu_hash::device::ringct_runtime::Error,
            >,
        >()
        + size_of::<crate::block_v2::gpu_hash::device::ringct_runtime::Footprint>()
        + size_of::<TreeProfile>()
        + size_of::<&Reservation>()
        + size_of::<&Ledger>()
        + 4 * size_of::<usize>()
        + 4 * size_of::<u64>())
        + 4096
}
