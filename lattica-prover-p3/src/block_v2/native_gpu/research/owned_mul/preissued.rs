//! Move original complete-workflow claims into the native phase. Numeric
//! source facts never create a runtime, reservation, or proof authority.
use super::*;
mod packet;
pub use packet::PreissuedNativeMulPlan;

/// Pure source plan used by the enclosing issuer before splitting originals.
/// Selection and physical inspection occur only after all claims are present.
#[derive(Clone, Copy)]
pub struct NativeMulReservationPlan {
    preparation: MulPreparationPlan,
    profile: TreeProfile,
    operation_host: usize,
    startup: Requirements,
    wrappers: Requirements,
    pcs: Requirements,
}

impl NativeMulReservationPlan {
    pub fn device(preparation: MulPreparationPlan, operation_host: usize) -> Result<Self> {
        Self::new(preparation, TreeProfile::Device, operation_host)
    }

    pub fn outer_host_v1(preparation: MulPreparationPlan, operation_host: usize) -> Result<Self> {
        Self::new(preparation, TreeProfile::OuterHostV1, operation_host)
    }

    fn new(preparation: MulPreparationPlan, profile: TreeProfile, operation_host: usize) -> Result<Self> {
        if preparation.geometry().kind().count() > MAX_VERIFIER_COUNT { return Err(Error::Geometry); }
        let startup = match profile {
            TreeProfile::Device => StartupPlan::new(),
            TreeProfile::OuterHostV1 => StartupPlan::outer_host_v1(),
        }.map_err(|_| Error::Runtime)?.footprint();
        if startup.driver_context_reserve as u64 != CONTEXT_DEVICE {
            return Err(Error::Admission);
        }
        let wrappers = Requirements::single(Category::PhaseScratch, Bytes {
            host: u64::try_from(profile.phase_wrapper_host_bytes()?).map_err(|_| Error::Admission)?,
            device: 0,
        });
        let pcs = Requirements::single(Category::PhaseScratch,
            quota_projection::pcs_request(startup.managed_device_bytes, operation_host)?);
        let startup = Requirements::single(Category::PhaseScratch, Bytes {
            host: u64::try_from(startup.requested_host_bytes).map_err(|_| Error::Admission)?,
            device: u64::try_from(startup.managed_device_bytes).map_err(|_| Error::Admission)?,
        });
        Ok(Self { preparation, profile, operation_host, startup, wrappers, pcs })
    }

    pub fn preparation(self) -> MulPreparationPlan { self.preparation }
    /// Minimum startup claim. The source runtime wrapper's own host frames may
    /// be additive, but its device claim must remain exactly this baseline.
    pub fn startup_requirement(self) -> Requirements { self.startup }
    pub fn wrapper_requirement(self) -> Requirements { self.wrappers }
    pub fn pcs_requirement(self) -> Requirements { self.pcs }

    pub fn preparation_requirement(self) -> Result<Requirements> {
        let host = self.preparation.host();
        let symbolic = host.prepared_partition_bytes().map_err(|_| Error::Preparation)?;
        let other = host.required_host_bytes().checked_sub(symbolic)
            .and_then(|bytes| bytes.checked_add(super::super::mul_recording::additional_host_bytes()))
            .ok_or(Error::Preparation)?;
        let mut requirement = Requirements::single(Category::SymbolicCompiler, Bytes {
            host: u64::try_from(symbolic).map_err(|_| Error::Preparation)?, device: 0,
        });
        requirement.add(Category::PhaseScratch, Bytes {
            host: u64::try_from(other).map_err(|_| Error::Preparation)?, device: 0,
        }).map_err(|_| Error::Preparation)?;
        Ok(requirement)
    }

}

impl NativeMulPhase {
    /// Return untouched constructor originals after a terminal refusal before
    /// this phase ever attempted production. This is not runtime retirement
    /// evidence or a retry permit. Any separately started runtime still owns
    /// its original startup claim and must be retired by the enclosing issuer.
    pub fn into_unstarted_originals(self) -> core::result::Result<
        (PendingMulOutput, Reservation, Reservation), Self,
    > {
        if self.attempted || self.retirement_binding.is_some() || self.succeeded || self.output.is_none() {
            return Err(self);
        }
        let Self { pcs, output, wrappers, pcs_owner, .. } = self;
        drop(pcs);
        Ok((output.expect("checked untouched output"), wrappers, pcs_owner))
    }

}

// Every copied plan/result frame is additive to the existing native wrapper
// inventory. No heap or runtime selection is constructed by this arithmetic.
pub(super) const fn additional_wrapper_host_bytes() -> usize {
    8 * (size_of::<NativeMulReservationPlan>()
        + size_of::<PreissuedNativeMulPlan>()
        + size_of::<Result<PreissuedNativeMulPlan>>()
        + size_of::<NativeMulPcsFootprint>()
        + size_of::<NativeMulTraceFootprint>()
        + size_of::<core::result::Result<NativeMulPhase,
            (Error, PendingMulOutput, Reservation, Reservation)>>()
        + 3 * size_of::<Requirements>())
}
