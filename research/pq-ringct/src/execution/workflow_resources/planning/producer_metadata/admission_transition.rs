//! Preflight the already implemented source-to-runtime ownership transition.
//! Live originals are untouched. Only runtime drops construction scratch, and
//! only actual Session retirement transfers the authenticated startup original.
use super::*;
use crate::execution::{phase_lifecycle::{PhaseCapability, PlanningStartupAdmission},
    retained_resources::{Snapshot, WorkerAllowance}};

/// Issued only after the one-shot complete-constructor and exact case checks.
/// The borrow keeps the actual construction original and capability immutable.
pub(crate) struct PlanningAdmissionTransition<'claims, 'context> {
    scratch: &'claims Reservation,
    capability: &'claims PhaseCapability<'context>,
    case: &'claims CaseRetirementState,
    metadata: *const (),
    scope: *const (),
    scratch_requirements: Requirements,
}

/// An opaque observation retained by the successfully closed plan. Retaining
/// the same startup owner and Ledger handle does not create a second allowance.
/// The runtime must revalidate this observation before changing any claim.
pub(crate) struct PlanningAdmissionProjection {
    ledger: Ledger,
    startup: PlanningStartupAdmission,
    metadata: *const (),
    scope: *const (),
    case: *const (),
    context: *const ProvingContext,
    source: [u8; 32],
    compiled_source: [u8; 32],
    enclosing: Bytes,
    allowance: WorkerAllowance,
    planning_scratch: Requirements,
    observed: Requirements,
    projected: Requirements,
}

fn current_requirements(snapshot: Snapshot) -> Result<Requirements, WorkflowError> {
    let mut result = Requirements::default();
    for category in Category::ALL {
        result.add(category, snapshot.categories[category as usize].current)?;
    }
    if result.total()? != snapshot.current { return Err(WorkflowError::Identity); }
    Ok(result)
}

fn subtract(have: Requirements, part: Requirements) -> Result<Requirements, WorkflowError> {
    let mut result = Requirements::default();
    for category in Category::ALL {
        let have = have.get(category); let part = part.get(category);
        result.add(category, Bytes {
            host: have.host.checked_sub(part.host).ok_or(WorkflowError::Enclosing)?,
            device: have.device.checked_sub(part.device).ok_or(WorkflowError::Enclosing)?,
        })?;
    }
    Ok(result)
}

fn validate_census(ledger: &Ledger, scratch: &Reservation, expected_scratch: Requirements,
    expected_current: Requirements, allowance: WorkerAllowance) -> Result<Snapshot, WorkflowError>
{
    if !scratch.belongs_to(ledger) || scratch.requirements() != expected_scratch {
        return Err(WorkflowError::Identity);
    }
    let snapshot = ledger.snapshot();
    if snapshot.allowance != allowance || current_requirements(snapshot)? != expected_current {
        return Err(WorkflowError::Identity);
    }
    Ok(snapshot)
}

impl<'claims, 'context> PlanningAdmissionTransition<'claims, 'context> {
    // The original controller is a temporary validation borrow; it remains
    // independently splittable after this exact scratch/capability borrow.
    pub(in crate::execution::workflow_resources::planning) fn new(
        scratch: &'claims Reservation, capability: &'claims PhaseCapability<'context>,
        plan: &'claims SourceMetadataPlanningPlan<'_>, case: &'claims CaseRetirementState,
        installed: &Installation, original: &GuardedPlanningOriginal<'_>,
    ) -> Result<Self, WorkflowError> {
        if !installed.matches(plan) || !installed.closed || !installed.final_source || !installed.final_plan
            || !installed.sealed.is_null() || installed.case != case as *const _ as *const ()
            || !original.is_pinned_to(case) || !original.belongs_to(capability.ledger())
            || !scratch.belongs_to(capability.ledger()) || !plan.belongs_to(capability.ledger())
            || !capability.belongs_to(plan.context())
            || capability.status() != crate::execution::phase_lifecycle::Status::Ready
            || scratch.requirements() != plan.planning_scratch_requirements()
            || scratch.requirements().total()?.device != 0
            || plan.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint()
        { return Err(WorkflowError::Identity); }
        Ok(Self { scratch, capability, case, metadata: plan as *const _ as *const (),
            scope: plan.scope() as *const _ as *const (), scratch_requirements: scratch.requirements() })
    }

    pub(crate) fn matches_metadata(&self, plan: &SourceMetadataPlanningPlan<'_>) -> bool {
        self.metadata == plan as *const _ as *const ()
            && self.scope == plan.scope() as *const _ as *const ()
            && self.scratch_requirements == plan.planning_scratch_requirements()
            && self.capability.belongs_to(plan.context()) && plan.belongs_to(self.capability.ledger())
    }

    pub(crate) fn project(&self, scope: &SourcePlanningPlan<'_>, ledger: &Ledger)
        -> Result<PlanningAdmissionProjection, WorkflowError>
    {
        if self.scope != scope as *const _ as *const () || !self.capability.belongs_to(scope.context())
            || !self.scratch.belongs_to(ledger) || !self.scratch.belongs_to(self.capability.ledger())
            || self.scratch.requirements() != self.scratch_requirements
        { return Err(WorkflowError::Identity); }
        let startup = self.capability.planning_startup_admission()?;
        startup.validate(self.capability)?;
        let snapshot = ledger.snapshot();
        let observed = current_requirements(snapshot)?;
        let projected = subtract(subtract(observed, self.scratch_requirements)?, startup.requirements())?;
        // The device prefix is the sole allowed transfer. Every other retained
        // owner remains charged; an unexpected retained device owner refuses.
        if snapshot.allowance != (WorkerAllowance { host: scope.context().host_profile().worker_bytes(), device: 8 << 30 })
            || projected.total()?.device != 0
        { return Err(WorkflowError::Enclosing); }
        Ok(PlanningAdmissionProjection { ledger: ledger.clone(), startup, metadata: self.metadata,
            scope: self.scope, case: self.case as *const _ as *const (), context: scope.context(),
            source: scope.source_fingerprint(), compiled_source: scope.compiled_source_fingerprint(),
            enclosing: scope.enclosing_bytes(), allowance: snapshot.allowance,
            planning_scratch: self.scratch_requirements, observed, projected })
    }

    pub(in crate::execution::workflow_resources::planning) fn frame_bytes() -> Result<usize, WorkflowError> {
        let bytes = [size_of::<Self>(), size_of::<Result<Self, WorkflowError>>(),
            size_of::<PlanningAdmissionProjection>(), size_of::<Result<PlanningAdmissionProjection, WorkflowError>>(),
            size_of::<Snapshot>(), size_of::<[Requirements; 8]>(), size_of::<[Bytes; 8]>(),
            size_of::<Ledger>(), size_of::<Result<(), WorkflowError>>(),
            PlanningStartupAdmission::frame_bytes(),
        ].into_iter().try_fold(0usize, usize::checked_add).and_then(|n| n.checked_mul(8))
            .ok_or(WorkflowError::Overflow)?;
        Ok(bytes)
    }
}

impl PlanningAdmissionProjection {
    pub(crate) fn observed_retained(&self) -> Bytes { self.observed.total().expect("validated original census") }
    pub(crate) fn released_planning_scratch(&self) -> Requirements { self.planning_scratch }
    pub(crate) fn transferred_startup(&self) -> Requirements { self.startup.requirements() }
    pub(crate) fn projected_retained(&self) -> Bytes { self.projected.total().expect("validated projected census") }

    pub(in crate::execution) fn validate_for_admission(&self, planning: &WorkflowPlanning<'_>,
        closed: &ClosedWorkflowPlan<'_>, runtime: Requirements) -> Result<(), WorkflowError>
    {
        let installed = planning.producer_metadata.as_ref().ok_or(WorkflowError::Identity)?;
        if planning.failed || !planning.closure_reserved || planning.failed_source_pool.is_some()
            || !installed.matches_closed(closed) || !installed.closed
            || installed.plan != self.metadata || installed.scope != self.scope || installed.case != self.case
            || !core::ptr::eq(planning.context, self.context) || !core::ptr::eq(closed.context(), self.context)
            || planning.source != self.source || planning.compiled_source != self.compiled_source
            || planning.enclosing != self.enclosing || closed.source_fingerprint() != self.source
            || closed.compiled_source_fingerprint() != self.compiled_source || closed.enclosing_bytes() != self.enclosing
            || !closed.admission_projection().is_some_and(|known| core::ptr::eq(known, self))
            || !closed.belongs_to(&self.ledger) || !planning.original.belongs_to(&self.ledger)
            || !planning.original.is_pinned() || !planning.scratch.belongs_to(&self.ledger)
            || planning.scratch.requirements() != self.planning_scratch
        { return Err(WorkflowError::Identity); }
        self.startup.validate(&planning.capability)?;
        let snapshot = validate_census(&self.ledger, &planning.scratch,
            self.planning_scratch, self.observed, self.allowance)?;
        let observed = current_requirements(snapshot)?;
        if subtract(subtract(observed, self.planning_scratch)?, self.startup.requirements())? != self.projected
            || runtime.get(Category::PhaseScratch).device != 8 << 30
        { return Err(WorkflowError::Identity); }
        // Mirror the real order: drop only construction scratch, admit only
        // the closed residual, then retain the startup original until shutdown.
        let retained_before_transfer = subtract(observed, self.planning_scratch)?;
        let residual = subtract(runtime, self.startup.requirements())?;
        let active = super::super::super::types::combine(retained_before_transfer, residual)?.total()?;
        if active.host > snapshot.allowance.host || active.device > snapshot.allowance.device {
            return Err(WorkflowError::Enclosing);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_projection_keeps_live_originals_and_counts_the_startup_once() {
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
        let retained = ledger.reserve(Category::RegisteredMetadata, Bytes { host: 1 << 30, device: 0 }).unwrap();
        let scratch = ledger.reserve(Category::PhaseScratch, Bytes { host: 3 << 30, device: 0 }).unwrap();
        let startup = ledger.reserve(Category::PhaseScratch, Bytes { host: 0, device: (64 << 20) + 752 }).unwrap();
        let before = ledger.snapshot();
        let observed = current_requirements(before).unwrap();
        let projected = subtract(subtract(observed, scratch.requirements()).unwrap(), startup.requirements()).unwrap();
        assert_eq!(projected, retained.requirements());
        assert_eq!(ledger.snapshot(), before);
        let full = Requirements::single(Category::PhaseScratch, Bytes { host: 4 << 30, device: 8 << 30 });
        assert!(ledger.admit_phase(full).is_err());
        // This test does not fabricate Session retirement or transfer proof.
        let residual = subtract(full, startup.requirements()).unwrap();
        drop(scratch);
        let runtime = ledger.admit_phase(residual).unwrap();
        assert_eq!(ledger.snapshot().current.device, 8 << 30);
        drop(runtime); drop(startup); drop(retained);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn invalid_category_projection_never_releases_the_reserved_owners() {
        let ledger = Ledger::new(WorkerAllowance { host: 1024, device: 1024 });
        let held = ledger.reserve(Category::PhaseScratch, Bytes { host: 64, device: 32 }).unwrap();
        let before = ledger.snapshot();
        for request in [Requirements::single(Category::SymbolicCompiler, Bytes { host: 1, device: 0 }),
            Requirements::single(Category::PhaseScratch, Bytes { host: 65, device: 0 }),
            Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: 33 })] {
            assert!(subtract(current_requirements(before).unwrap(), request).is_err());
            assert_eq!(ledger.snapshot(), before);
            assert_eq!(held.requirements().total().unwrap(), before.current);
        }
    }

    #[test]
    fn equal_numeric_census_on_a_different_ledger_is_not_the_original() {
        let allowance = WorkerAllowance { host: 1024, device: 1024 };
        let ledger = Ledger::new(allowance); let other = Ledger::new(allowance);
        let scratch = ledger.reserve(Category::PhaseScratch, Bytes { host: 64, device: 0 }).unwrap();
        let wrong = other.reserve(Category::PhaseScratch, Bytes { host: 64, device: 0 }).unwrap();
        let observed = current_requirements(ledger.snapshot()).unwrap();
        assert_eq!(ledger.snapshot(), other.snapshot());
        assert!(validate_census(&ledger, &scratch, scratch.requirements(), observed, allowance).is_ok());
        assert!(validate_census(&ledger, &wrong, scratch.requirements(), observed, allowance).is_err());
        assert_eq!(ledger.snapshot().current, scratch.requirements().total().unwrap());
        assert_eq!(other.snapshot().current, wrong.requirements().total().unwrap());
    }

    #[test]
    fn stale_category_census_and_changed_scratch_refuse_without_releasing_live_claims() {
        let allowance = WorkerAllowance { host: 1024, device: 1024 };
        let ledger = Ledger::new(allowance);
        let mut scratch = ledger.reserve(Category::PhaseScratch, Bytes { host: 64, device: 0 }).unwrap();
        let expected = scratch.requirements();
        let observed = current_requirements(ledger.snapshot()).unwrap();
        let extra = ledger.reserve(Category::RegisteredMetadata, Bytes { host: 8, device: 0 }).unwrap();
        let changed = ledger.snapshot();
        assert!(validate_census(&ledger, &scratch, expected, observed, allowance).is_err());
        assert_eq!(ledger.snapshot(), changed);
        drop(extra);
        let split = scratch.split(Requirements::single(Category::PhaseScratch, Bytes { host: 1, device: 0 })).unwrap();
        assert_eq!(current_requirements(ledger.snapshot()).unwrap(), observed);
        assert!(validate_census(&ledger, &scratch, expected, observed, allowance).is_err());
        assert_eq!(ledger.snapshot().current.host, 64);
        drop(split); drop(scratch);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
