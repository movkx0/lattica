//! Move original complete-workflow claims into the native phase. Numeric
//! source facts never create a runtime, reservation, or proof authority.
use super::*;
mod packet;
pub use packet::PreissuedNativeShakePlan;

/// Pure source plan used by the enclosing issuer before splitting originals.
/// Selection and physical inspection occur only after all claims are present.
#[derive(Clone, Copy)]
pub struct NativeShakeReservationPlan {
    preparation: ShakePreparationPlan,
    profile: TreeProfile,
    operation_host: usize,
    startup: Requirements,
    wrappers: Requirements,
    pcs: Requirements,
}

impl NativeShakeReservationPlan {
    pub fn device(preparation: ShakePreparationPlan, operation_host: usize) -> Result<Self> {
        Self::new(preparation, TreeProfile::Device, operation_host)
    }

    pub fn outer_host_v1(preparation: ShakePreparationPlan, operation_host: usize) -> Result<Self> {
        Self::new(preparation, TreeProfile::OuterHostV1, operation_host)
    }

    fn new(preparation: ShakePreparationPlan, profile: TreeProfile, operation_host: usize) -> Result<Self> {
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

    pub fn preparation(self) -> ShakePreparationPlan { self.preparation }
    /// Minimum startup claim. The source runtime wrapper's own host frames may
    /// be additive, but its device claim must remain exactly this baseline.
    pub fn startup_requirement(self) -> Requirements { self.startup }
    pub fn wrapper_requirement(self) -> Requirements { self.wrappers }
    pub fn pcs_requirement(self) -> Requirements { self.pcs }

    pub fn preparation_requirement(self) -> Result<Requirements> {
        let host = self.preparation.host();
        let symbolic = host.prepared_partition_bytes().map_err(|_| Error::Preparation)?;
        let other = host.required_host_bytes().checked_sub(symbolic)
            .and_then(|bytes| bytes.checked_add(super::super::shake_recording::additional_host_bytes()))
            .ok_or(Error::Preparation)?;
        let mut requirement = Requirements::single(Category::SymbolicCompiler, Bytes {
            host: u64::try_from(symbolic).map_err(|_| Error::Preparation)?, device: 0,
        });
        requirement.add(Category::PhaseScratch, Bytes {
            host: u64::try_from(other).map_err(|_| Error::Preparation)?, device: 0,
        }).map_err(|_| Error::Preparation)?;
        Ok(requirement)
    }

    pub fn verifier_requirement(self) -> Requirements {
        Requirements::single(Category::IndependentVerifier, Bytes { host: VERIFIER_HOST, device: 0 })
    }
}

impl NativeShakePhase {
    /// Return untouched constructor originals after a terminal refusal before
    /// this phase ever attempted production. This is not runtime retirement
    /// evidence or a retry permit. Any separately started runtime still owns
    /// its original startup claim and must be retired by the enclosing issuer.
    pub fn into_unstarted_originals(self) -> core::result::Result<
        (PendingShakeOutput, Reservation, Reservation), Self,
    > {
        if self.attempted || self.retirement_binding.is_some() || self.succeeded || self.output.is_none() {
            return Err(self);
        }
        let Self { pcs, output, wrappers, pcs_owner, .. } = self;
        drop(pcs);
        Ok((output.expect("checked untouched output"), wrappers, pcs_owner))
    }

    /// Consume the actual preissued wrapper and PCS claims, reserving no bytes.
    /// The caller must recover them only after exact runtime retirement.
    ///
    /// # Safety
    /// The closed issuer retains original request/preparation/startup/verifier
    /// owners and a serialized immutable-process guard from this inspection
    /// through destruction of the exact runtime. A legacy Session or a copied
    /// runtime receipt is not an original Runtime/startup pair. `plan` must be
    /// derived for the same immutable source segment as that preparation.
    pub unsafe fn from_originals(
        plan: NativeShakeReservationPlan,
        preparation_owner: &Reservation,
        pending_runtime_owner: &Reservation,
        output: PendingShakeOutput,
        verifier: &Reservation,
        wrappers: Reservation,
        pcs_owner: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<Self, (Error, PendingShakeOutput, Reservation, Reservation)> {
        let checked = (|| -> Result<NativeShakePcsPlan> {
        check_ledger(ledger)?;
        check_preparation(plan.preparation, preparation_owner, ledger)?;
        check_verifier(verifier, ledger)?;
        output.check(plan.preparation, ledger).map_err(|_| Error::Output)?;
        let startup_device = plan.profile.check_startup(pending_runtime_owner, ledger)?;
        if !wrappers.belongs_to(ledger) || wrappers.requirements() != plan.wrappers
            || !pcs_owner.belongs_to(ledger) || pcs_owner.requirements() != plan.pcs
            || startup_device as u64 != plan.startup.get(Category::PhaseScratch).device
        {
            return Err(Error::Authority);
        }
        let limits = RegisteredGpuLimits::new(WORKER_HOST, MANAGED_DEVICE, CONTEXT_DEVICE, MAX_ROWS)
            .map_err(|_| Error::Planner)?;
        let geometry = plan.preparation.geometry();
        let pcs = NativeShakePcsPlan::new(geometry.rows(), geometry.width(), plan.operation_host, limits)
            .map_err(|_| Error::Planner)?;
        let footprint = pcs.footprint();
        plan.profile.check_plan(footprint)?;
        if !footprint.maintained_device_plan_complete
            || footprint.fresh_runtime_baseline_bytes != startup_device
            || footprint.managed_phase_ceiling_bytes as u64 != MANAGED_DEVICE
            || footprint.required_pcs_host_bytes > plan.operation_host
        {
            return Err(Error::Admission);
        }
        Ok(pcs)
        })();
        let pcs = match checked {
            Ok(value) => value,
            Err(error) => return Err((error, output, wrappers, pcs_owner)),
        };
        Ok(Self {
            tree_profile: plan.profile,
            preparation: plan.preparation,
            pcs,
            output: Some(output),
            attempted: false,
            succeeded: false,
            retirement_binding: None,
            ledger: ledger.clone(),
            wrappers,
            pcs_owner,
        })
    }
}

// Every copied plan/result frame is additive to the existing native wrapper
// inventory. No heap or runtime selection is constructed by this arithmetic.
pub(super) const fn additional_wrapper_host_bytes() -> usize {
    8 * (size_of::<NativeShakeReservationPlan>()
        + size_of::<PreissuedNativeShakePlan>()
        + size_of::<Result<PreissuedNativeShakePlan>>()
        + size_of::<NativeShakePcsFootprint>()
        + size_of::<core::result::Result<NativeShakePhase,
            (Error, PendingShakeOutput, Reservation, Reservation)>>()
        + 3 * size_of::<Requirements>())
}

#[cfg(test)]
mod tests;
