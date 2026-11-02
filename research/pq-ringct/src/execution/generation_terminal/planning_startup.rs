//! The next pristine planning context retains the SAME original generation
//! ledger. Only actual source retirement can transfer its startup original
//! into the preclaimed closed workflow; no release/recharge path exists.
use super::*;
use std::{cell::{Cell, RefCell}, rc::Rc};

#[cfg(test)]
mod fixture;
#[cfg(test)]
pub(crate) use fixture::FixturePlanningContext;
mod memory;
mod cleanup;
pub(crate) use cleanup::PlanningCleanupReceipt;
#[cfg(test)]
mod tests;

pub(crate) struct PlanningStartupPlan {
    permanent: Requirements,
    startup: Requirements,
}

/// Private to the named generation-to-planning handoff. This is not a generic
/// ledger injection or a caller supplied numeric startup credit.
pub(in crate::execution) struct OriginalPlanningStartup {
    ledger: Ledger,
    original: RefCell<Option<Reservation>>,
    requirements: Requirements,
    session_id: Cell<Option<u64>>,
    pub(in crate::execution) closed_requirements: Cell<Option<Requirements>>,
    pub(in crate::execution) capability_issued: Cell<bool>,
    armed: Cell<bool>,
}

pub(crate) struct FreshPlanningContext<'terminal> {
    // Rust context payload dies before the permanent original. On uncertain
    // cleanup both are deliberately retained, including all phase originals.
    context: Option<ProvingContext>,
    terminal: &'terminal NativeGenerationTerminal,
    startup: Rc<OriginalPlanningStartup>,
    permanent: Option<Reservation>,
    cleanup_confirmed: Cell<bool>,
}

impl PlanningStartupPlan {
    pub(crate) fn new() -> GenerationResult<Self> {
        if cfg!(debug_assertions) { return Err(GenerationError::Authority); }
        let (permanent, startup) = memory::requirements()?;
        Ok(Self { permanent, startup })
    }
    pub(crate) fn requirements(&self) -> GenerationResult<Requirements> {
        super::memory::combine(self.permanent, self.startup)
    }
    pub(crate) fn permanent_requirements(&self) -> Requirements { self.permanent }
    pub(crate) fn startup_requirements(&self) -> Requirements { self.startup }
    pub(crate) fn start<'terminal>(self, terminal: &'terminal NativeGenerationTerminal,
        mut original: Reservation, ledger: &Ledger) -> GenerationResult<FreshPlanningContext<'terminal>>
    {
        if !original.belongs_to(ledger) || !terminal.belongs_to(ledger)
            || original.requirements() != self.requirements()?
            || crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(ledger.snapshot().allowance.host).is_err()
            || ledger.snapshot().allowance.device != 8 << 30
            || !matches!(terminal.spend_count(), 3 | 4)
        { return Err(GenerationError::Authority); }
        let transient = original.split(self.startup).map_err(|_| GenerationError::Resource)?;
        if original.requirements() != self.permanent { return Err(GenerationError::Authority); }
        // Both same-ledger originals precede Rc/context/identity allocation.
        let startup = Rc::new(OriginalPlanningStartup { ledger: ledger.clone(),
            original: RefCell::new(Some(transient)), requirements: self.startup,
            session_id: Cell::new(None), closed_requirements: Cell::new(None),
            capability_issued: Cell::new(false), armed: Cell::new(true) });
        let context = match ProvingContext::opencl_with_host_profile(Limits {
            host_bytes: ledger.snapshot().allowance.host, device_bytes: 8 << 30, max_rows: 1 << 20,
        }, crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(ledger.snapshot().allowance.host)
            .map_err(|_| GenerationError::Authority)?) {
            Ok(context) => context,
            Err(error) => {
                eprintln!("owned_planning_startup_refused detail={:.512}", error);
                drop(error);
                // The ordinary constructor cannot return proof of cleanup.
                // Its global engine may still retain host and device storage.
                core::mem::forget(original);
                return Err(GenerationError::Startup);
            }
        };
        startup.session_id.set(Some(context.session_id));
        let owned = FreshPlanningContext { context: Some(context), terminal,
            startup, permanent: Some(original), cleanup_confirmed: Cell::new(false) };
        terminal.validate_planning_context(owned.context())?;
        let actual = owned.context().workflow_enclosing_footprint()
            .map_err(|_| GenerationError::Authority)?;
        let permanent = owned.permanent.as_ref().expect("planning permanent original").requirements();
        if actual.managed_device_bytes != 8 << 30
            || actual.enclosing_host_bytes > permanent.total().map_err(|_| GenerationError::Resource)?.host
            || permanent.get(Category::RegisteredMetadata).host < PUBLIC_METADATA_LIMIT_BYTES as u64
        { return Err(GenerationError::Authority); }
        // Install before exposing a borrowed context. The legacy capability
        // constructor now sees an already-bound scope and cannot manufacture
        // a second spendable ledger from this fresh planning context.
        owned.context().bind_original_planning_startup(&owned)
            .map_err(|_| GenerationError::Authority)?;
        Ok(owned)
    }
}

impl FreshPlanningContext<'_> {
    pub(crate) fn context(&self) -> &ProvingContext {
        self.context.as_ref().expect("live original-owned planning context")
    }
    /// Exact retained original provenance, never a copied numeric allowance.
    pub(crate) fn belongs_to_original_generation(&self, ledger: &Ledger, generation_session: u64) -> bool {
        self.permanent.as_ref().is_some_and(|original| original.belongs_to(ledger))
            && self.terminal.belongs_to(ledger)
            && self.terminal.session_id() == generation_session
            && self.belongs_to_generation(self.terminal)
    }
    pub(crate) fn belongs_to_generation(&self, terminal: &NativeGenerationTerminal) -> bool {
        core::ptr::eq(self.terminal, terminal) && terminal.belongs_to(&self.startup.ledger)
            && self.context().session_id > terminal.session_id()
    }
    pub(crate) fn original_requirements(&self) -> GenerationResult<Requirements> {
        super::memory::combine(self.permanent.as_ref().ok_or(GenerationError::Authority)?.requirements(),
            self.startup.current_requirements()?)
    }
    /// Consume and report actual cleanup once all source/phase borrows ended.
    /// This is cleanup evidence only, not a workflow-completion claim.
    pub(crate) fn finish(mut self) -> GenerationResult<()> { self.cleanup() }
    pub(crate) fn source_backend_device_bytes(&self) -> GenerationResult<u64> {
        (8u64 << 30).checked_sub(self.startup.current_requirements()?.total()
            .map_err(|_| GenerationError::Resource)?.device).filter(|n| *n != 0)
            .ok_or(GenerationError::Resource)
    }
    /// The named fresh source route may validate immediately before or after
    /// same-ledger adoption. The latter checks the exact installed owner and
    /// still-pristine Ready state, without calling the legacy unbound census.
    pub(crate) fn validate_source_entry(&self) -> GenerationResult<()> {
        if !self.belongs_to_generation(self.terminal)
            || self.context().diagnostics.has_work_attempted()
            || self.startup.current_requirements()? != self.startup.requirements
        { return Err(GenerationError::Authority); }
        if self.context().phases.workflow_census_is_unbound().map_err(|_| GenerationError::Busy)? {
            self.terminal.validate_planning_context(self.context())
        } else {
            self.context().validate_adopted_planning_startup(&self.startup)
                .map_err(|_| GenerationError::Authority)
        }
    }
    pub(in crate::execution) fn adopt_capability(&self)
        -> GenerationResult<super::super::phase_lifecycle::PhaseCapability<'_>>
    {
        self.validate_source_entry()?;
        self.context().issue_original_planning_capability(&self.startup)
            .map_err(|_| GenerationError::Authority)
    }
    pub(in crate::execution) fn adoption_owner(&self, context: &ProvingContext)
        -> GenerationResult<Rc<OriginalPlanningStartup>>
    {
        if !core::ptr::eq(self.context(), context)
            || !self.belongs_to_generation(self.terminal)
            || !self.permanent.as_ref().is_some_and(|held| held.belongs_to(&self.startup.ledger))
            || self.startup.session_id.get() != Some(context.session_id)
            || self.startup.current_requirements()? != self.startup.requirements
        { return Err(GenerationError::Authority); }
        Ok(Rc::clone(&self.startup))
    }
}

impl OriginalPlanningStartup {
    pub(in crate::execution) fn ledger(&self) -> &Ledger { &self.ledger }
    pub(in crate::execution) fn session_id(&self) -> Option<u64> { self.session_id.get() }
    pub(in crate::execution) fn current_requirements(&self) -> GenerationResult<Requirements> {
        let original = self.original.try_borrow().map_err(|_| GenerationError::Busy)?;
        match original.as_ref() {
            Some(original) if original.belongs_to(&self.ledger)
                && original.requirements() == self.requirements => Ok(self.requirements),
            Some(_) => Err(GenerationError::Authority),
            None => Ok(Requirements::default()),
        }
    }
    /// Only the phase-lifecycle child calls this after exact Session identity
    /// and real retirement validation. Refusal restores the same original.
    pub(in crate::execution) fn take_after_retirement(&self,
        source: &crate::opencl::RetiredSourceSession<'_>, context: &ProvingContext)
        -> GenerationResult<Reservation>
    {
        if self.session_id.get() != Some(context.session_id)
            || !context.session.as_ref().is_some_and(|session| source.belongs_to(session))
        { return Err(GenerationError::Authority); }
        let mut original = self.original.try_borrow_mut().map_err(|_| GenerationError::Busy)?;
        let held = original.take().ok_or(GenerationError::Authority)?;
        if !held.belongs_to(&self.ledger) || held.requirements() != self.requirements {
            *original = Some(held); return Err(GenerationError::Authority);
        }
        Ok(held)
    }
    pub(in crate::execution) fn restore_refused_original(&self, held: Reservation) {
        if !held.belongs_to(&self.ledger) || held.requirements() != self.requirements {
            core::mem::forget(held); return;
        }
        match self.original.try_borrow_mut() {
            Ok(mut slot) if slot.is_none() => *slot = Some(held),
            _ => core::mem::forget(held),
        }
    }
}

impl Drop for OriginalPlanningStartup {
    fn drop(&mut self) {
        if let Some(original) = self.original.get_mut().take() {
            if self.armed.get() { core::mem::forget(original); }
            // An unarmed owner has never attempted context construction.
        }
    }
}

impl Drop for FreshPlanningContext<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl FreshPlanningContext<'_> {
    fn cleanup(&mut self) -> GenerationResult<()> {
        let Some(mut context) = self.context.take() else { return Ok(()); };
        let closed = context.session.take().ok_or(GenerationError::Authority)
            .and_then(|session| session.retire_original_planning_context());
        if closed.is_err() {
            // Keep every phase/registry owner if actual shutdown is uncertain.
            core::mem::forget(context);
            if let Some(permanent) = self.permanent.take() { core::mem::forget(permanent); }
            return Err(GenerationError::Shutdown);
        }
        // This local branch follows consumption and closure of the actual
        // Session. If source retirement already transferred the device token,
        // the startup owner is empty and the closed phase owns that original.
        let released = match self.startup.original.try_borrow_mut() {
            Ok(mut slot) => { drop(slot.take()); true }
            Err(_) => false,
        };
        if !released {
            core::mem::forget(context);
            if let Some(permanent) = self.permanent.take() { core::mem::forget(permanent); }
            return Err(GenerationError::Busy);
        }
        drop(context);
        drop(self.permanent.take());
        Ok(())
    }
}
