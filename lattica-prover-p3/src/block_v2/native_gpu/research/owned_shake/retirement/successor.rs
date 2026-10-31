//! Source-preissued singleton continuation through actual native retirement.
//! No runtime, reservation or PCS plan is created after a proof attempt.
use super::*;
use crate::block_v2::native_gpu::shake_preparation::{ShakeLaneLayout, ShakePreparationGeometry};

/// Issued only while the actual first host-profile native phase is unattempted.
/// The future source/output/verifier claims must already be owned by its caller.
pub struct NativeShakeSuccessor {
    preparation: ShakePreparationPlan,
    original_pcs: Bytes,
    output: PendingShakeOutput,
    ledger: Ledger,
}

/// The actual original startup claim after consuming a successful native
/// retirement and a compatible preissued successor. There is no public issuer.
pub struct SealedNativeStartup {
    retirement: Retirement,
    startup: Reservation,
}

impl SealedNativeStartup {
    pub fn retirement(&self) -> Retirement {
        self.retirement
    }

    pub fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.startup.belongs_to(ledger)
    }

    pub fn startup_requirements(&self) -> Requirements {
        self.startup.requirements()
    }

    /// Ownership extraction only. Research can restore a PendingRuntime only
    /// through its closed sealed-startup consumer, never a raw-token input.
    pub fn into_original(self) -> Reservation {
        self.startup
    }
}

fn geometry_follows(
    previous: ShakePreparationGeometry,
    next: ShakePreparationGeometry,
    consecutive: bool,
) -> Result<()> {
    for geometry in [previous, next] {
        if geometry.layout() != ShakeLaneLayout::Singleton
            || geometry.permutations() != 1
            || geometry.rows() != 4096
            || geometry.width() != 517
            || geometry.public_values() != 216
            || geometry.periodic_columns() != 42
            || geometry.periodic_length() != 128
        {
            return Err(Error::Geometry);
        }
    }
    let distance = next
        .first_permutation()
        .checked_sub(previous.first_permutation())
        .ok_or(Error::Geometry)?;
    if previous.input_len() != next.input_len()
        || previous.output_len() != next.output_len()
        || !(1..=2).contains(&distance)
        || (consecutive && distance != 1)
    {
        return Err(Error::Geometry);
    }
    Ok(())
}

pub(super) fn additional_host_bytes() -> usize {
    // At most two future singleton owners. Count complete owning result and
    // refusal slots, not only references to the owners inside those slots.
    4 * size_of::<NativeShakeSuccessor>()
        + 4 * size_of::<SealedNativeStartup>()
        + 4 * size_of::<core::result::Result<NativeShakeSuccessor, (Error, PendingShakeOutput)>>()
        + 4 * size_of::<
            core::result::Result<
                (NativeShakePhase, SealedNativeStartup),
                (Error, NativeShakeSuccessor, RetiredNativeReservations),
            >,
        >()
        + 4 * size_of::<NativeShakePcsPlan>()
        + 4 * size_of::<ShakePreparationPlan>()
        + 4 * size_of::<ShakePreparationGeometry>()
        + 4 * size_of::<Bytes>()
        + 4 * size_of::<Ledger>()
        + 4 * size_of::<Requirements>()
        + 4 * size_of::<Result<()>>()
}

impl NativeShakePhase {
    /// Validate a next singleton while this actual first phase still owns its
    /// unattempted original PCS plan. This neither allocates nor admits quota,
    /// reads environment/device state, nor dispatches a proof.
    pub fn preissue_outer_host_successor(
        &self,
        preparation: ShakePreparationPlan,
        preparation_owner: &Reservation,
        output: PendingShakeOutput,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<NativeShakeSuccessor, (Error, PendingShakeOutput)> {
        let checked = (|| -> Result<Bytes> {
            let original_pcs = self.original_outer_pcs_bytes(ledger)?;
            geometry_follows(self.preparation.geometry(), preparation.geometry(), false)?;
            check_preparation(preparation, preparation_owner, ledger)?;
            check_verifier(verifier, ledger)?;
            output
                .check(preparation, ledger)
                .map_err(|_| Error::Output)?;
            Ok(original_pcs)
        })();
        let original_pcs = match checked {
            Ok(bytes) => bytes,
            Err(error) => return Err((error, output)),
        };
        Ok(NativeShakeSuccessor {
            preparation,
            original_pcs,
            output,
            ledger: ledger.clone(),
        })
    }
}

impl NativeShakeSuccessor {
    /// Transfer only the actual retired original claims and immutable PCS plan.
    /// Refusal returns both complete inputs. The research caller additionally
    /// requires its sealed independently verified predecessor from the same
    /// immutable request and exact next index before calling this method.
    pub fn restore(
        self,
        originals: RetiredNativeReservations,
        preparation_owner: &Reservation,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<
        (NativeShakePhase, SealedNativeStartup),
        (Error, Self, RetiredNativeReservations),
    > {
        let checked = (|| -> Result<()> {
            check_ledger(ledger)?;
            if !originals.succeeded
                || !originals.belongs_to(ledger)
                || !originals.belongs_to(&self.ledger)
                || originals.retirement.managed_live_bytes != 0
                || originals.retirement.host_tree_live_bytes != 0
                || !originals.retirement.lease_released
                || originals.retirement.managed_peak_bytes == 0
                || originals.retirement.managed_peak_bytes as u64 > MANAGED_DEVICE
            {
                return Err(Error::Runtime);
            }
            geometry_follows(
                originals.preparation.geometry(),
                self.preparation.geometry(),
                true,
            )?;
            check_preparation(self.preparation, preparation_owner, ledger)?;
            check_verifier(verifier, ledger)?;
            self.output
                .check(self.preparation, ledger)
                .map_err(|_| Error::Output)?;
            let profile = TreeProfile::OuterHostV1;
            let baseline = profile.check_startup(&originals.startup, ledger)?;
            let footprint = originals.pcs_plan.footprint();
            profile.check_plan(footprint)?;
            if !footprint.maintained_device_plan_complete
                || footprint.rows != self.preparation.geometry().rows()
                || footprint.main_width != self.preparation.geometry().width()
                || footprint.operation_host_budget_bytes as u64 != self.original_pcs.host
                || footprint.required_pcs_host_bytes > footprint.operation_host_budget_bytes
                || footprint.fresh_runtime_baseline_bytes != baseline
                || footprint.managed_phase_ceiling_bytes as u64 != MANAGED_DEVICE
                || only(&originals.pcs, Category::PhaseScratch, ledger)? != self.original_pcs
                || self.original_pcs.device
                    != MANAGED_DEVICE
                        .checked_sub(baseline as u64)
                        .ok_or(Error::Authority)?
                || only(&originals.wrappers, Category::PhaseScratch, ledger)?
                    != (Bytes {
                        host: profile.phase_wrapper_host_bytes()? as u64,
                        device: 0,
                    })
            {
                return Err(Error::Authority);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error, self, originals));
        }
        let RetiredNativeReservations {
            retirement,
            startup,
            wrappers,
            pcs,
            pcs_plan,
            ..
        } = originals;
        let Self {
            preparation,
            output,
            ledger,
            ..
        } = self;
        Ok((
            NativeShakePhase {
                tree_profile: TreeProfile::OuterHostV1,
                preparation,
                pcs: pcs_plan,
                output: Some(output),
                attempted: false,
                succeeded: false,
                retirement_binding: None,
                ledger,
                wrappers,
                pcs_owner: pcs,
            },
            SealedNativeStartup {
                retirement,
                startup,
            },
        ))
    }
}

#[cfg(test)]
mod tests;
