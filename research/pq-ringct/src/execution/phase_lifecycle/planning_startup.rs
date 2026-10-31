//! Named same-ledger adoption and retirement-time transfer for an authentic
//! freshly generated case. There is no numeric ledger-injection constructor.
use super::*;
use crate::execution::generation_terminal::planning_startup::{
    FreshPlanningContext, OriginalPlanningStartup,
};
use crate::opencl::RetiredSourceSession;
use std::rc::Rc;

/// A source-closure observation of the exact still-live startup original.
/// This keeps its owner alive but grants neither retirement nor admission.
/// Only the existing retired-Session path can transfer the original itself.
pub(in crate::execution) struct PlanningStartupAdmission {
    owner: Rc<OriginalPlanningStartup>,
    context: *const ProvingContext,
    session: u64,
    generation: u64,
    requirements: Requirements,
}

impl PlanningStartupAdmission {
    pub(in crate::execution) fn requirements(&self) -> Requirements { self.requirements }

    pub(in crate::execution) fn validate(&self, capability: &PhaseCapability<'_>) -> Result<(), Error> {
        let context = capability.context;
        let owner = context.phases.planning_startup.get().ok_or(Error::EnclosingAllowance)?;
        let state = context.phases.state.try_borrow().map_err(|_| Error::ContextBusy)?;
        if !Rc::ptr_eq(owner, &self.owner) || !core::ptr::eq(context, self.context)
            || context.session_id != self.session || owner.session_id() != Some(self.session)
            || context.policy() != lattica_prover_p3::proving::Policy::GpuRequired
            || !context.session.as_ref().is_some_and(|session| session.limits().device_bytes == 8 << 30)
            || !owner.capability_issued.get() || owner.closed_requirements.get().is_some()
            || state.status != Status::Ready || state.generation != self.generation
            || state.held.is_some() || state.partition.is_some()
            || owner.current_requirements().map_err(|_| Error::EnclosingAllowance)? != self.requirements
        { return Err(Error::EnclosingAllowance); }
        Ok(())
    }

    pub(in crate::execution) fn frame_bytes() -> usize {
        use core::mem::size_of;
        // Capture and revalidation are serial, allocation-free borrowed calls.
        8 * (size_of::<Self>() + size_of::<Result<Self, Error>>()
            + size_of::<Rc<OriginalPlanningStartup>>() + size_of::<std::cell::Ref<'static, State>>()
            + size_of::<Requirements>() + size_of::<Bytes>() + size_of::<Result<(), Error>>())
    }
}

fn subtract(have: Requirements, part: Requirements) -> Result<Requirements, Error> {
    let mut result = Requirements::default();
    for category in Category::ALL {
        let a = have.get(category); let b = part.get(category);
        result.add(category, Bytes {
            host: a.host.checked_sub(b.host).ok_or(Error::EnclosingAllowance)?,
            device: a.device.checked_sub(b.device).ok_or(Error::EnclosingAllowance)?,
        })?;
    }
    Ok(result)
}

impl ProvingContext {
    pub(in crate::execution) fn bind_original_planning_startup(&self,
        owned: &FreshPlanningContext<'_>) -> Result<(), Error>
    {
        if self.diagnostics.has_work_attempted() { return Err(Error::WorkAlreadyStarted); }
        let owner = owned.adoption_owner(self).map_err(|_| Error::EnclosingAllowance)?;
        let mut state = self.phases.state.try_borrow_mut().map_err(|_| Error::ContextBusy)?;
        if self.phases.ledger.get().is_some() || self.phases.planning_startup.get().is_some()
            || state.status != Status::Unbound || state.generation != 0
            || state.held.is_some() || state.partition.is_some()
            || owner.ledger().snapshot().allowance != (WorkerAllowance { host: self.host_profile.worker_bytes(), device: 8 << 30 })
            || self.host_bytes != self.host_profile.worker_bytes()
            || owner.session_id() != Some(self.session_id)
        { return Err(Error::AlreadyBound); }
        // Rc clone preserves the exact generation ledger and all its original
        // live counters. No Ledger::new call or allowance subtraction occurs.
        let ledger = owner.ledger().clone();
        self.phases.planning_startup.set(owner).map_err(|_| Error::AlreadyBound)?;
        self.phases.ledger.set(ledger).map_err(|_| Error::AlreadyBound)?;
        state.status = Status::Ready;
        Ok(())
    }
    pub(in crate::execution) fn validate_adopted_planning_startup(&self,
        expected: &Rc<OriginalPlanningStartup>) -> Result<(), Error>
    {
        let state = self.phases.state.try_borrow().map_err(|_| Error::ContextBusy)?;
        let actual = self.phases.planning_startup.get().ok_or(Error::EnclosingAllowance)?;
        if !Rc::ptr_eq(actual, expected) || expected.session_id() != Some(self.session_id)
            || state.status != Status::Ready || state.generation != 0
            || state.held.is_some() || state.partition.is_some()
            || self.diagnostics.has_work_attempted()
        { return Err(Error::WorkAlreadyStarted); }
        Ok(())
    }
    pub(in crate::execution) fn issue_original_planning_capability(&self,
        expected: &Rc<OriginalPlanningStartup>) -> Result<PhaseCapability<'_>, Error>
    {
        self.validate_adopted_planning_startup(expected)?;
        if expected.capability_issued.replace(true) { return Err(Error::AlreadyBound); }
        Ok(PhaseCapability { context: self })
    }
}

impl ContextPhases {
    pub(in crate::execution) fn planning_startup_requirement(&self) -> Result<Requirements, Error> {
        self.planning_startup.get().map_or(Ok(Requirements::default()), |owner|
            owner.current_requirements().map_err(|_| Error::EnclosingAllowance))
    }
    /// Called only after retire_source_session has drained/shut down this
    /// exact Session. Its nonconstructible borrowed owner is checked again.
    pub(in crate::execution) fn transfer_retired_planning_startup(&self,
        generation: u64, source: &RetiredSourceSession<'_>, context: &ProvingContext)
        -> Result<(), Error>
    {
        let Some(owner) = self.planning_startup.get() else { return Ok(()); };
        if !core::ptr::eq(self, &context.phases) { return Err(Error::EnclosingAllowance); }
        let expected = owner.closed_requirements.get().ok_or(Error::EnclosingAllowance)?;
        let startup = owner.current_requirements().map_err(|_| Error::EnclosingAllowance)?;
        let mut state = self.state.try_borrow_mut().map_err(|_| Error::ContextBusy)?;
        Self::check_active(&state, generation)?;
        Self::check_no_partition(&state)?;
        let held = state.held.as_ref().ok_or(Error::EmptyPhase)?;
        let mut complete = held.requirements();
        for category in Category::ALL { complete.add(category, startup.get(category))?; }
        // Output/failure originals have already moved into the closed pool.
        // Their host bytes must not be reclaimed; all backend device bytes
        // remain in this PhaseScratch claim and must now equal the full plan.
        if complete.get(Category::PhaseScratch).device != 8 << 30
            || expected.get(Category::PhaseScratch).device != 8 << 30
            || !Category::ALL.into_iter().all(|category| {
                let a = complete.get(category); let b = expected.get(category);
                a.host <= b.host && a.device <= b.device
            })
        { return Err(Error::EnclosingAllowance); }
        let original = owner.take_after_retirement(source, context)
            .map_err(|_| Error::EnclosingAllowance)?;
        let held = state.held.take().expect("checked active original");
        match held.reunite(original) {
            Ok(combined) => {
                if combined.requirements() != complete {
                    core::mem::forget(combined); state.status = Status::Poisoned;
                    return Err(Error::EnclosingAllowance);
                }
                state.held = Some(combined);
                owner.closed_requirements.set(None);
                Ok(())
            }
            Err((error, held, original)) => {
                state.held = Some(held);
                owner.restore_refused_original(original);
                state.status = Status::Poisoned;
                Err(Error::Reservation(error))
            }
        }
    }
}

impl<'context> PhaseCapability<'context> {
    /// Observe the authenticated owner while source planning is still Ready.
    /// The returned value never takes, splits, releases, or reunites a claim.
    pub(in crate::execution) fn planning_startup_admission(&self) -> Result<PlanningStartupAdmission, Error> {
        let context = self.context;
        let owner = context.phases.planning_startup.get().ok_or(Error::EnclosingAllowance)?;
        let state = context.phases.state.try_borrow().map_err(|_| Error::ContextBusy)?;
        let requirements = owner.current_requirements().map_err(|_| Error::EnclosingAllowance)?;
        let bytes = requirements.total()?;
        if context.policy() != lattica_prover_p3::proving::Policy::GpuRequired
            || !context.session.as_ref().is_some_and(|session| session.limits().device_bytes == 8 << 30)
            || owner.session_id() != Some(context.session_id) || !owner.capability_issued.get()
            || owner.closed_requirements.get().is_some() || state.status != Status::Ready
            || state.held.is_some() || state.partition.is_some()
            || bytes.host != 0 || bytes.device == 0 || bytes.device >= 8 << 30
            || requirements.get(Category::PhaseScratch) != bytes
        { return Err(Error::EnclosingAllowance); }
        Ok(PlanningStartupAdmission { owner: Rc::clone(owner), context, session: context.session_id,
            generation: state.generation, requirements })
    }

    pub(in crate::execution) fn uses_original_generation_ledger(&self) -> bool {
        self.context.phases.planning_startup.get().is_some_and(|owner|
            owner.session_id() == Some(self.context.session_id) && owner.capability_issued.get())
    }
    /// Source-preparation scratch shares the real initial runtime with its
    /// preclaimed startup storage. Later closed native phases have the whole
    /// 8 GiB original after actual source retirement and reunion.
    pub(in crate::execution) fn source_bootstrap_device_bytes(&self) -> Result<u64, Error> {
        if self.context.policy() != lattica_prover_p3::proving::Policy::GpuRequired
            || !self.context.session.as_ref().is_some_and(|session| session.limits().device_bytes == 8 << 30)
        { return Err(Error::EnclosingAllowance); }
        let startup = self.context.phases.planning_startup_requirement()?.total()?;
        if startup.host != 0 { return Err(Error::EnclosingAllowance); }
        (8u64 << 30).checked_sub(startup.device).filter(|n| *n != 0)
            .ok_or(Error::EnclosingAllowance)
    }
    /// The complete closed plan is preclaimed before source retirement: its
    /// authentic startup original already exists on this same ledger. The
    /// residual admitted here reunites with that original only after shutdown.
    pub(in crate::execution) fn admit_owned_with_planning_startup(self,
        requirements: Requirements) -> Result<OwnedPhase<'context>, Error>
    {
        let Some(owner) = self.context.phases.planning_startup.get() else {
            return self.admit_owned(requirements);
        };
        if owner.closed_requirements.get().is_some() { return Err(Error::AlreadyBound); }
        let startup = owner.current_requirements().map_err(|_| Error::EnclosingAllowance)?;
        let bytes = startup.total()?;
        if bytes.host != 0 || bytes.device == 0 || bytes.device >= 8 << 30
            || requirements.get(Category::PhaseScratch).device != 8 << 30
        { return Err(Error::EnclosingAllowance); }
        let residual = subtract(requirements, startup)?;
        let generation = self.context.phases.admit(residual)?;
        owner.closed_requirements.set(Some(requirements));
        Ok(OwnedPhase { capability: self, generation, completed: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_reference_context_cannot_issue_a_startup_transfer_projection() {
        let context = ProvingContext::cpu(1024).unwrap();
        let capability = context.phase_capability(Bytes::ZERO).unwrap();
        let before = capability.ledger().snapshot();
        assert!(capability.planning_startup_admission().is_err());
        assert_eq!(capability.ledger().snapshot(), before);
        assert_eq!(capability.status(), Status::Ready);
    }

    #[test]
    fn startup_and_closed_residual_are_preclaimed_without_double_charging_device() {
        let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
        let startup = Requirements::single(Category::PhaseScratch,
            Bytes { host: 0, device: 64 << 20 });
        let full = Requirements::single(Category::PhaseScratch,
            Bytes { host: 24 << 30, device: 8 << 30 });
        let original = ledger.admit_phase(startup).unwrap();
        assert!(ledger.admit_phase(full).is_err());
        let residual = ledger.admit_phase(subtract(full, startup).unwrap()).unwrap();
        let before = ledger.snapshot();
        // Exercise real original-token reunion arithmetic. The production
        // transfer additionally requires the actual retired Session borrow.
        let combined = residual.reunite(original).unwrap_or_else(|_| panic!("same ledger originals"));
        assert_eq!(combined.requirements(), full);
        let after = ledger.snapshot();
        assert_eq!(after.current, before.current);
        assert_eq!(after.peak, before.peak);
        drop(combined);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn startup_subtraction_cannot_cross_categories_or_exceed_closed_claim() {
        let full = Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: 512 });
        let wrong_category = Requirements::single(Category::NativeProof, Bytes { host: 0, device: 1 });
        let excessive = Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: 513 });
        assert_eq!(subtract(full, wrong_category), Err(Error::EnclosingAllowance));
        assert_eq!(subtract(full, excessive), Err(Error::EnclosingAllowance));
        assert_eq!(subtract(full, full).unwrap().total().unwrap(), Bytes::ZERO);
    }
}
