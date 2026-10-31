//! Exact original native-attempt to preissued outer-backend ownership.
//! No raw reservations or public cap constructors cross this seam.
use super::*;
use crate::block_v2::machine::{
    program::Val, OuterBackendAdmission, OuterSourceFootprint, PreissuedOuterBackend, Program,
};
use std::sync::Arc;

pub struct PreissuedHashxOuterBackend {
    backend: PreissuedOuterBackend,
    attempt: Rc<Attempt>,
    startup: Requirements,
    pcs: Bytes,
    ledger: Ledger,
}

pub struct RetiredHashxOuterBackend {
    backend: PreissuedOuterBackend,
    originals: RetiredHashxReservations,
    startup: Requirements,
    pcs: Bytes,
}

pub struct BoundHashxOuterBackend<'inputs> {
    backend: OuterBackendAdmission<'inputs>,
    originals: RetiredHashxReservations,
    startup: Requirements,
    pcs: Bytes,
}

/// The original PCS/native-wrapper claims stay opaque through outer retirement.
/// Only the same sealed startup moves into the enclosing runtime adapter.
pub struct HashxOuterBackend<'inputs> {
    backend: OuterBackendAdmission<'inputs>,
    scratch: HashxOuterScratch,
}

/// Contains no compiler, Program, public or witness borrow after outer finish.
pub struct HashxOuterScratch {
    preparation: ShakePreparationPlan,
    attempt: Rc<Attempt>,
    startup: Requirements,
    pcs_bytes: Bytes,
    outer_step: usize,
    wrappers: Reservation,
    pcs: Reservation,
}

fn check_footprint(footprint: OuterSourceFootprint, startup: Bytes, pcs: Bytes) -> Result<()> {
    if startup.host < 8 << 30
        || pcs.host == 0
        || pcs.host > 24 << 30
        || startup.device.checked_add(pcs.device) != Some(MANAGED_DEVICE)
        || footprint.backend_scope_host_bytes.checked_sub(8 << 30) != Some(pcs.host)
        || footprint.complete_device_phase_ceiling != MANAGED_DEVICE
        || footprint.context_reserve_bytes != 4 << 30
        || footprint.minimum_pcs_host_budget_bytes > pcs.host
        || !footprint.source_phase_bounds_complete
        || footprint.enclosing_ownership_bound_complete
        || footprint.workflow_dispatch_authority
    {
        return Err(Error::Authority);
    }
    Ok(())
}

fn final_source(geometry: ShakePreparationGeometry) -> Result<()> {
    if index(geometry)? != 9 {
        return Err(Error::Geometry);
    }
    Ok(())
}

impl NativeHashxPhase {
    /// Called only while the actual first phase is unattempted. The caller's
    /// full compiler/output/planner claims already reduced its PCS capacity.
    pub fn prebind_outer_backend(
        &self,
        backend: PreissuedOuterBackend,
        startup: &Reservation,
        preparation: &Reservation,
        verifier: &Reservation,
        metadata: &Reservation,
        ledger: &Ledger,
    ) -> Result<PreissuedHashxOuterBackend> {
        check_ledger(ledger)?;
        let pcs = self.phase.original_outer_pcs_bytes(ledger)?;
        if index(self.phase.preparation.geometry())? != 0
            || !metadata.belongs_to(ledger)
            || metadata.requirements().get(Category::PhaseScratch).host
                < additional_host_bytes()? as u64
        {
            return Err(Error::Authority);
        }
        check_preparation(self.phase.preparation, preparation, ledger)?;
        check_verifier(verifier, ledger)?;
        TreeProfile::OuterHostV1.check_startup(startup, ledger)?;
        let original_startup = only(startup, Category::PhaseScratch, ledger)?;
        check_footprint(backend.footprint(), original_startup, pcs)?;
        self.phase
            .pcs
            .check_execution_selection()
            .map_err(|_| Error::Planner)?;
        backend
            .check_execution_selection()
            .map_err(|_| Error::Planner)?;
        Ok(PreissuedHashxOuterBackend {
            backend,
            attempt: Rc::clone(&self.attempt),
            startup: startup.requirements(),
            pcs,
            ledger: ledger.clone(),
        })
    }
}

impl PreissuedHashxOuterBackend {
    pub fn additional_host_bytes() -> Result<usize> {
        additional_host_bytes()
    }

    pub fn check_first(&self, first: &NativeHashxPhase, ledger: &Ledger) -> Result<()> {
        if !Rc::ptr_eq(&self.attempt, &first.attempt)
            || index(first.phase.preparation.geometry())? != 0
            || first.phase.original_outer_pcs_bytes(ledger)? != self.pcs
        {
            return Err(Error::Authority);
        }
        first
            .phase
            .pcs
            .check_execution_selection()
            .map_err(|_| Error::Planner)?;
        self.backend
            .check_execution_selection()
            .map_err(|_| Error::Planner)?;
        Ok(())
    }
    /// The final phase can exist only after all nine original consecutive
    /// successors. Matching geometry or ledger alone is insufficient.
    pub fn complete(
        self,
        originals: RetiredHashxReservations,
        preparation: &Reservation,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<RetiredHashxOuterBackend, (Error, Self, RetiredHashxReservations)>
    {
        let checked = (|| -> Result<()> {
            check_ledger(ledger)?;
            let native = &originals.originals;
            let retirement = native.retirement();
            if !Rc::ptr_eq(&self.attempt, &originals.attempt)
                || !native.succeeded
                || !originals.belongs_to(ledger)
                || !originals.belongs_to(&self.ledger)
                || retirement.managed_live_bytes != 0
                || retirement.host_tree_live_bytes != 0
                || !retirement.lease_released
                || retirement.managed_peak_bytes == 0
                || retirement.managed_peak_bytes as u64 > MANAGED_DEVICE
                || native.startup.requirements() != self.startup
                || only(&native.pcs, Category::PhaseScratch, ledger)? != self.pcs
                || only(&native.wrappers, Category::PhaseScratch, ledger)?
                    != (Bytes {
                        host: TreeProfile::OuterHostV1.phase_wrapper_host_bytes()? as u64,
                        device: 0,
                    })
            {
                return Err(Error::Authority);
            }
            final_source(native.preparation.geometry())?;
            check_preparation(native.preparation, preparation, ledger)?;
            check_verifier(verifier, ledger)?;
            TreeProfile::OuterHostV1.check_startup(&native.startup, ledger)?;
            TreeProfile::OuterHostV1.check_plan(native.pcs_plan.footprint())?;
            check_footprint(
                self.backend.footprint(),
                self.startup.get(Category::PhaseScratch),
                self.pcs,
            )
        })();
        if let Err(error) = checked {
            return Err((error, self, originals));
        }
        let Self {
            backend,
            startup,
            pcs,
            ..
        } = self;
        Ok(RetiredHashxOuterBackend {
            backend,
            originals,
            startup,
            pcs,
        })
    }
}

impl RetiredHashxOuterBackend {
    /// Bind the exact preissued source/idle selection. Failure destroys this
    /// complete owner; there is no fallback plan or post-native readmission.
    pub fn bind<'inputs>(
        self,
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
    ) -> Result<BoundHashxOuterBackend<'inputs>> {
        let Self {
            backend,
            originals,
            startup,
            pcs,
        } = self;
        let backend = backend
            .bind(program, public, witness)
            .map_err(|_| Error::Planner)?;
        Ok(BoundHashxOuterBackend {
            backend,
            originals,
            startup,
            pcs,
        })
    }
}

impl<'inputs> BoundHashxOuterBackend<'inputs> {
    pub fn startup_requirements(&self) -> Requirements {
        self.startup
    }
    pub fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.originals.belongs_to(ledger)
    }

    /// Only the private runtime adapter consumes this sealed startup. The
    /// returned backend retains its actual PCS and wrapper reservations.
    pub fn restore_startup(
        self,
        ledger: &Ledger,
    ) -> core::result::Result<(SealedHashxStartup, HashxOuterBackend<'inputs>), (Error, Self)> {
        let checked = (|| -> Result<()> {
            let native = &self.originals.originals;
            if !self.belongs_to(ledger)
                || native.startup.requirements() != self.startup
                || only(&native.pcs, Category::PhaseScratch, ledger)? != self.pcs
            {
                return Err(Error::Authority);
            }
            TreeProfile::OuterHostV1.check_startup(&native.startup, ledger)?;
            final_source(native.preparation.geometry())?;
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((error, self));
        }
        let Self {
            backend,
            originals,
            startup: startup_requirement,
            pcs: pcs_bytes,
        } = self;
        let RetiredHashxReservations { originals, attempt } = originals;
        let RetiredNativeReservations {
            preparation,
            pcs_plan,
            startup,
            wrappers,
            pcs,
            ..
        } = originals;
        drop(pcs_plan);
        Ok((
            SealedHashxStartup { startup },
            HashxOuterBackend {
                backend,
                scratch: HashxOuterScratch {
                    preparation,
                    attempt,
                    startup: startup_requirement,
                    pcs_bytes,
                    outer_step: 0,
                    wrappers,
                    pcs,
                },
            },
        ))
    }
}

impl<'inputs> HashxOuterBackend<'inputs> {
    pub fn backend(&self) -> &OuterBackendAdmission<'inputs> {
        &self.backend
    }
    pub fn scratch(&self) -> &HashxOuterScratch {
        &self.scratch
    }
    pub fn into_retired_scratch(self) -> HashxOuterScratch {
        let Self { backend, scratch } = self;
        drop(backend);
        scratch
    }
}

impl HashxOuterScratch {
    /// Ordinal only; this is neither proof success nor graph acceptance.
    pub fn outer_step(&self) -> usize {
        self.outer_step
    }

    pub fn startup_requirements(&self) -> Requirements {
        self.startup
    }
    pub fn check_originals(
        &self,
        preparation: &Reservation,
        verifier: &Reservation,
        ledger: &Ledger,
    ) -> Result<()> {
        if self.outer_step > succession::SUCCESSORS {
            return Err(Error::Authority);
        }
        final_source(self.preparation.geometry())?;
        check_preparation(self.preparation, preparation, ledger)?;
        check_verifier(verifier, ledger)?;
        if only(&self.pcs, Category::PhaseScratch, ledger)? != self.pcs_bytes
            || only(&self.wrappers, Category::PhaseScratch, ledger)?
                != (Bytes {
                    host: TreeProfile::OuterHostV1.phase_wrapper_host_bytes()? as u64,
                    device: 0,
                })
        {
            return Err(Error::Authority);
        }
        Ok(())
    }
}

pub(super) fn additional_host_bytes() -> Result<usize> {
    let parts = [
        8 * size_of::<PreissuedHashxOuterBackend>(),
        8 * size_of::<RetiredHashxOuterBackend>(),
        8 * size_of::<BoundHashxOuterBackend<'static>>(),
        8 * size_of::<HashxOuterBackend<'static>>(),
        8 * size_of::<HashxOuterScratch>(),
        8 * size_of::<RetiredHashxReservations>(),
        8 * size_of::<RetiredNativeReservations>(),
        8 * size_of::<NativeShakePcsPlan>(),
        8 * size_of::<ShakePreparationPlan>(),
        8 * size_of::<ShakePreparationGeometry>(),
        8 * size_of::<SealedHashxStartup>(),
        8 * size_of::<(SealedHashxStartup, HashxOuterBackend<'static>)>(),
        8 * size_of::<(Error, BoundHashxOuterBackend<'static>)>(),
        8 * size_of::<(Error, PreissuedHashxOuterBackend, RetiredHashxReservations)>(),
        8 * size_of::<Result<PreissuedHashxOuterBackend>>(),
        8 * size_of::<Result<BoundHashxOuterBackend<'static>>>(),
        8 * size_of::<
            core::result::Result<
                RetiredHashxOuterBackend,
                (Error, PreissuedHashxOuterBackend, RetiredHashxReservations),
            >,
        >(),
        8 * size_of::<
            core::result::Result<
                (SealedHashxStartup, HashxOuterBackend<'static>),
                (Error, BoundHashxOuterBackend<'static>),
            >,
        >(),
        8 * size_of::<OuterBackendAdmission<'static>>(),
        8 * size_of::<OuterSourceFootprint>(),
        8 * size_of::<PreissuedOuterBackend>(),
        8 * size_of::<core::result::Result<OuterBackendAdmission<'static>, String>>(),
        8 * size_of::<core::result::Result<(), String>>(),
        8 * size_of::<&PreissuedOuterBackend>(),
        8 * size_of::<Retirement>(),
        8 * size_of::<Requirements>(),
        8 * size_of::<Reservation>(),
        8 * size_of::<Ledger>(),
        8 * size_of::<Rc<Attempt>>(),
        8 * size_of::<Result<()>>(),
        8 * size_of::<Result<Bytes>>(),
        8 * size_of::<Result<usize>>(),
        8 * size_of::<Bytes>(),
        8 * size_of::<usize>(),
        32 << 10,
    ];
    let helpers = core::mem::size_of_val(&parts)
        .checked_mul(8)
        .ok_or(Error::Admission)?;
    parts.into_iter().try_fold(helpers, |sum, bytes| {
        sum.checked_add(bytes).ok_or(Error::Admission)
    })
}

#[cfg(test)]
mod tests;

mod succession;
pub use succession::HashxOuterSuccessors;
