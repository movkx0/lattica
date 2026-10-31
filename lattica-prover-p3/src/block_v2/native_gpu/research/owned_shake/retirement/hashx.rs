//! Original-attempt-bound active HashX successors, preissued before native zero.
use super::*;
use crate::block_v2::native_gpu::shake_preparation::{ShakeLaneLayout, ShakePreparationGeometry};
use std::rc::Rc;

mod outer;
pub use outer::{
    BoundHashxOuterBackend, HashxOuterBackend, HashxOuterScratch, HashxOuterSuccessors,
    PreissuedHashxOuterBackend, RetiredHashxOuterBackend,
};

// This allocation exists only under the enclosing source-preclaimed metadata.
// Its pointer, never a caller-supplied number, identifies one original sequence.
struct Attempt(u8);

pub struct NativeHashxPhase {
    phase: NativeShakePhase,
    attempt: Rc<Attempt>,
}

pub struct RetiredHashxReservations {
    originals: RetiredNativeReservations,
    attempt: Rc<Attempt>,
}

pub struct NativeHashxSuccessor {
    preparation: ShakePreparationPlan,
    pcs: NativeShakePcsPlan,
    original_pcs: Bytes,
    output: PendingShakeOutput,
    ledger: Ledger,
    attempt: Rc<Attempt>,
}

/// Only successful correlated restoration issues this original startup owner.
pub struct SealedHashxStartup {
    startup: Reservation,
}
impl SealedHashxStartup {
    pub fn into_original(self) -> Reservation {
        self.startup
    }
}

impl RetiredHashxReservations {
    pub fn retirement(&self) -> Retirement {
        self.originals.retirement()
    }
    pub fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.originals.belongs_to(ledger)
    }
    pub fn startup_requirements(&self) -> Requirements {
        self.originals.startup_requirements()
    }
}

fn index(geometry: ShakePreparationGeometry) -> Result<usize> {
    if geometry.input_len() != 16_416
        || geometry.output_len() != 137
        || geometry.public_values() != 216
        || geometry.periodic_columns() != 42
        || geometry.periodic_length() != 128
    {
        return Err(Error::Geometry);
    }
    let first = geometry.first_permutation();
    let (index, permutations, rows, width, layout) = if first < 112 && first % 16 == 0 {
        (
            first / 16,
            16,
            65_536,
            518,
            ShakeLaneLayout::HomogeneousBatch,
        )
    } else if first == 112 {
        (7, 8, 32_768, 518, ShakeLaneLayout::HomogeneousBatch)
    } else if matches!(first, 120 | 121) {
        (first - 112, 1, 4096, 517, ShakeLaneLayout::Singleton)
    } else {
        return Err(Error::Geometry);
    };
    if (
        geometry.permutations(),
        geometry.rows(),
        geometry.width(),
        geometry.layout(),
    ) != (permutations, rows, width, layout)
    {
        return Err(Error::Geometry);
    }
    Ok(index)
}

fn consecutive(previous: ShakePreparationGeometry, next: ShakePreparationGeometry) -> Result<()> {
    if index(previous)?.checked_add(1) != Some(index(next)?)
        || previous
            .first_permutation()
            .checked_add(previous.permutations())
            != Some(next.first_permutation())
    {
        return Err(Error::Geometry);
    }
    Ok(())
}

impl NativeHashxPhase {
    /// Consume the actual unattempted first phase; no raw extractor exists.
    /// The original caller metadata must preclaim the complete additional census.
    pub fn new(
        first: NativeShakePhase,
        metadata: &Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<Self, (Error, NativeShakePhase)> {
        let checked = (|| -> Result<()> {
            first.original_outer_pcs_bytes(ledger)?;
            if index(first.preparation.geometry())? != 0
                || !metadata.belongs_to(ledger)
                || metadata.requirements().get(Category::PhaseScratch).host
                    < Self::additional_host_bytes()? as u64
            {
                return Err(Error::Authority);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error, first));
        }
        Ok(Self {
            phase: first,
            attempt: Rc::new(Attempt(0)),
        })
    }

    /// Numeric source diagnostic only; it does not expose the original token.
    pub fn original_pcs_bytes(&self, ledger: &Ledger) -> Result<Bytes> {
        self.phase.original_outer_pcs_bytes(ledger)
    }

    pub fn pcs_footprint(&self) -> NativeShakePcsFootprint {
        self.phase.footprint()
    }

    /// All future geometry plans use this actual first captured selector/capacity.
    pub fn preissue_successor(
        &self,
        preparation: ShakePreparationPlan,
        preparation_owner: &Reservation,
        output: PendingShakeOutput,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<NativeHashxSuccessor, (Error, PendingShakeOutput)> {
        let planned = (|| -> Result<(Bytes, NativeShakePcsPlan)> {
            let original_pcs = self.phase.original_outer_pcs_bytes(ledger)?;
            if index(self.phase.preparation.geometry())? != 0 || index(preparation.geometry())? == 0
            {
                return Err(Error::Geometry);
            }
            check_preparation(preparation, preparation_owner, ledger)?;
            check_verifier(verifier, ledger)?;
            output
                .check(preparation, ledger)
                .map_err(|_| Error::Output)?;
            let geometry = preparation.geometry();
            let next = self
                .phase
                .pcs
                .preissue_original_capacity(geometry.rows(), geometry.width())
                .map_err(|_| Error::Planner)?;
            TreeProfile::OuterHostV1.check_plan(next.footprint())?;
            if !next.same_original_capacity(&self.phase.pcs) {
                return Err(Error::Authority);
            }
            Ok((original_pcs, next))
        })();
        match planned {
            Err(error) => Err((error, output)),
            Ok((original_pcs, pcs)) => Ok(NativeHashxSuccessor {
                preparation,
                pcs,
                original_pcs,
                output,
                ledger: ledger.clone(),
                attempt: Rc::clone(&self.attempt),
            }),
        }
    }

    /// # Safety
    /// The original source, complete claims and immutable exclusive-device
    /// guard must survive actual runtime retirement on success and failure.
    pub unsafe fn produce(
        &mut self,
        prepared: PreparedShake<'_>,
        input: &[u8],
        runtime: &Runtime,
        runtime_owner: &Reservation,
        verifier: &Reservation,
    ) -> Result<OwnedShakeProof> {
        // SAFETY: unchanged original closed native contract, retained by caller.
        unsafe {
            self.phase
                .produce(prepared, input, runtime, runtime_owner, verifier)
        }
    }

    pub fn into_retired_reservations(
        self,
        runtime: RetiredRuntime,
        ledger: &Ledger,
    ) -> core::result::Result<RetiredHashxReservations, (Error, Self, RetiredRuntime)> {
        let Self { phase, attempt } = self;
        match phase.into_retired_reservations(runtime, ledger) {
            Ok(originals) => Ok(RetiredHashxReservations { originals, attempt }),
            Err((error, phase, runtime)) => Err((error, Self { phase, attempt }, runtime)),
        }
    }

    /// Complete core source/caller/result owners, added to existing native
    /// wrappers by the closed request before the original first phase is made.
    pub fn additional_host_bytes() -> Result<usize> {
        // Source planner diagnostics and one private Rc allocation (including
        // both counters, padding and payload) remain under this original claim.
        let mut bytes = (4096usize * 8)
            .checked_add(8 * size_of::<usize>())
            .ok_or(Error::Admission)?;
        for item in [
            8 * size_of::<[Option<NativeHashxSuccessor>; 9]>(),
            8 * size_of::<NativeHashxSuccessor>(),
            8 * size_of::<Self>(),
            8 * size_of::<RetiredHashxReservations>(),
            8 * size_of::<Rc<Attempt>>(),
            8 * size_of::<NativeShakePcsPlan>(),
            8 * size_of::<core::result::Result<NativeShakePcsPlan, String>>(),
            8 * size_of::<Result<(Bytes, NativeShakePcsPlan)>>(),
            8 * size_of::<(Bytes, NativeShakePcsPlan)>(),
            8 * size_of::<core::result::Result<Self, (Error, NativeShakePhase)>>(),
            8 * size_of::<core::result::Result<NativeHashxSuccessor, (Error, PendingShakeOutput)>>(
            ),
            8 * size_of::<
                core::result::Result<
                    (Self, SealedHashxStartup),
                    (Error, NativeHashxSuccessor, RetiredHashxReservations),
                >,
            >(),
            8 * size_of::<
                core::result::Result<RetiredHashxReservations, (Error, Self, RetiredRuntime)>,
            >(),
            8 * size_of::<RetiredNativeReservations>(),
            8 * size_of::<SealedHashxStartup>(),
            8 * size_of::<ShakePreparationGeometry>(),
            8 * size_of::<NativeShakePcsFootprint>(),
            8 * size_of::<Requirements>(),
            8 * size_of::<Bytes>(),
            8 * size_of::<Ledger>(),
            8 * size_of::<Result<()>>(),
            32 * size_of::<usize>(),
        ] {
            bytes = bytes.checked_add(item).ok_or(Error::Admission)?;
        }
        Ok(bytes)
    }
}

impl NativeHashxSuccessor {
    /// Failure returns both complete original owners before any transfer.
    pub fn restore(
        self,
        retired: RetiredHashxReservations,
        preparation_owner: &Reservation,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<
        (NativeHashxPhase, SealedHashxStartup),
        (Error, Self, RetiredHashxReservations),
    > {
        let checked = (|| -> Result<()> {
            check_ledger(ledger)?;
            let originals = &retired.originals;
            if !Rc::ptr_eq(&self.attempt, &retired.attempt)
                || !originals.succeeded
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
            consecutive(
                originals.preparation.geometry(),
                self.preparation.geometry(),
            )?;
            check_preparation(self.preparation, preparation_owner, ledger)?;
            check_verifier(verifier, ledger)?;
            self.output
                .check(self.preparation, ledger)
                .map_err(|_| Error::Output)?;
            let profile = TreeProfile::OuterHostV1;
            let baseline = profile.check_startup(&originals.startup, ledger)?;
            let footprint = self.pcs.footprint();
            profile.check_plan(footprint)?;
            profile.check_plan(originals.pcs_plan.footprint())?;
            if !self.pcs.same_original_capacity(&originals.pcs_plan)
                || !footprint.maintained_device_plan_complete
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
            return Err((error, self, retired));
        }
        let RetiredHashxReservations {
            originals,
            attempt: prior_attempt,
        } = retired;
        let RetiredNativeReservations {
            startup,
            wrappers,
            pcs: pcs_owner,
            pcs_plan: old_plan,
            ..
        } = originals;
        let Self {
            preparation,
            pcs,
            output,
            ledger,
            attempt,
            ..
        } = self;
        // Plans and identity were issued before native zero. No planner,
        // selector query, runtime startup or reservation occurs at restoration.
        drop(old_plan);
        drop(prior_attempt);
        let phase = NativeShakePhase {
            tree_profile: TreeProfile::OuterHostV1,
            preparation,
            pcs,
            output: Some(output),
            attempted: false,
            succeeded: false,
            retirement_binding: None,
            ledger,
            wrappers,
            pcs_owner,
        };
        Ok((
            NativeHashxPhase { phase, attempt },
            SealedHashxStartup { startup },
        ))
    }
}

#[cfg(test)]
mod tests;
