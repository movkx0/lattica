//! Closed pre-native source plan. The immutable original allowance and every
//! native geometry are inspected before the enclosing workflow attempts proof0.
use super::*;

/// A non-clone source packet, not a runtime or quota owner. The enclosing
/// source plan retains a separately charged metadata original for its lifetime.
pub struct PreissuedNativeAffinePlan {
    plan: NativeAffineReservationPlan,
    pcs: NativeAffinePcsPlan,
    trace: NativeAffineTraceFootprint,
    ledger: Ledger,
}

fn originals(plan: NativeAffineReservationPlan, preparation: &Reservation,
    startup: &Reservation, verifier: &Reservation, wrappers: &Reservation,
    pcs: &Reservation, ledger: &Ledger) -> Result<usize> {
    check_ledger(ledger)?;
    check_preparation(plan.preparation, preparation, ledger)?;
    check_verifier(verifier, ledger)?;
    let startup_device = plan.profile.check_startup(startup, ledger)?;
    if !wrappers.belongs_to(ledger) || wrappers.requirements() != plan.wrappers
        || !pcs.belongs_to(ledger) || pcs.requirements() != plan.pcs
        || startup_device as u64 != plan.startup.get(Category::PhaseScratch).device {
        return Err(Error::Authority);
    }
    Ok(startup_device)
}

impl NativeAffineReservationPlan {
    /// Retained packet plus construction/refusal/move frames. The complete
    /// source owner charges this separately for every future native segment.
    pub fn preissue_metadata_host_bytes() -> Result<usize> {
        let frames = [size_of::<PreissuedNativeAffinePlan>(),
            size_of::<Option<PreissuedNativeAffinePlan>>(),
            size_of::<Result<PreissuedNativeAffinePlan>>(),
            size_of::<NativeAffineReservationPlan>(), size_of::<NativeAffinePcsFootprint>(),
            size_of::<Ledger>(), 8 * size_of::<&Reservation>(),
            4 * size_of::<Requirements>(), size_of::<RegisteredGpuLimits>()];
        frames.into_iter().try_fold(64usize << 10, |sum, bytes|
            bytes.checked_mul(8).and_then(|bytes| sum.checked_add(bytes)).ok_or(Error::Admission))
    }

    /// Inspect under borrowed complete originals; this creates no quota,
    /// Runtime or proof authority and performs no native attempt.
    ///
    /// # Safety
    /// The closed issuer owns the complete source/output/planner metadata,
    /// these exact originals, and the immutable exclusive process guard before
    /// proof0. The packet's metadata stays charged through consumption/drop.
    pub unsafe fn preissue_from_originals(self, preparation: &Reservation,
        startup: &Reservation, verifier: &Reservation, wrappers: &Reservation,
        pcs_owner: &Reservation, ledger: &Ledger) -> Result<PreissuedNativeAffinePlan> {
        let startup_device = originals(self, preparation, startup, verifier, wrappers, pcs_owner, ledger)?;
        let limits = RegisteredGpuLimits::new(WORKER_HOST, MANAGED_DEVICE, CONTEXT_DEVICE, MAX_ROWS)
            .map_err(|_| Error::Planner)?;
        let geometry = self.preparation.geometry();
        let pcs = NativeAffinePcsPlan::new(geometry, self.operation_host, limits)
            .map_err(|_| Error::Planner)?;
        let footprint = pcs.footprint();
        self.profile.check_plan(footprint)?;
        let trace = NativeAffineTraceFootprint::for_plan(self.preparation, footprint)?;
        if !footprint.maintained_device_plan_complete
            || footprint.fresh_runtime_baseline_bytes != startup_device
            || footprint.managed_phase_ceiling_bytes as u64 != MANAGED_DEVICE
            || footprint.required_pcs_host_bytes > self.operation_host {
            return Err(Error::Admission);
        }
        Ok(PreissuedNativeAffinePlan { plan: self, pcs, trace, ledger: ledger.clone() })
    }
}

impl PreissuedNativeAffinePlan {
    pub fn reservation_plan(&self) -> NativeAffineReservationPlan { self.plan }
    pub fn preparation(&self) -> AffinePreparationPlan { self.plan.preparation }
    pub fn footprint(&self) -> NativeAffinePcsFootprint { self.pcs.footprint() }
    pub fn trace_footprint(&self) -> NativeAffineTraceFootprint { self.trace }
    pub fn uses_outer_host_v1(&self) -> bool { self.plan.profile == TreeProfile::OuterHostV1 }
    pub fn check_execution_selection(&self) -> Result<()> {
        self.pcs.check_execution_selection().map_err(|_| Error::Planner)
    }
}

impl NativeAffinePhase {
    /// Consume the previously inspected exact source plan. Only original
    /// identity/profile and captured execution selection are rechecked; no
    /// memory planner, reservation, wider allowance or retry is introduced.
    ///
    /// # Safety
    /// The same source-closed exclusive guard and original owners established
    /// before proof0 remain valid through this phase's actual runtime retirement.
    pub unsafe fn from_preissued_originals(packet: PreissuedNativeAffinePlan,
        preparation: &Reservation, startup: &Reservation, output: PendingAffineOutput,
        verifier: &Reservation, wrappers: Reservation, pcs_owner: Reservation,
        ledger: &Ledger) -> core::result::Result<Self,
        (Error, PendingAffineOutput, Reservation, Reservation)> {
        let checked = (|| -> Result<()> {
            if !preparation.belongs_to(&packet.ledger) { return Err(Error::Authority); }
            originals(packet.plan, preparation, startup, verifier, &wrappers, &pcs_owner, ledger)?;
            output.check(packet.plan.preparation, ledger).map_err(|_| Error::Output)?;
            packet.check_execution_selection()?;
            Ok(())
        })();
        if let Err(error) = checked { return Err((error, output, wrappers, pcs_owner)); }
        Ok(Self {
            tree_profile: packet.plan.profile,
            preparation: packet.plan.preparation,
            pcs: packet.pcs,
            trace: packet.trace,
            output: Some(output), attempted: false, succeeded: false, retirement_binding: None,
            ledger: packet.ledger, wrappers, pcs_owner,
        })
    }
}
