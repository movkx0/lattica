//! Test-only source startup. This owner has no native-generation terminal and
//! cannot certify fresh inputs or complete a workflow.
use super::*;

pub(crate) struct FixturePlanningContext {
    context: Option<ProvingContext>,
    startup: Rc<OriginalPlanningStartup>,
    permanent: Option<Reservation>,
}

impl PlanningStartupPlan {
    pub(crate) fn start_fixture(self, mut original: Reservation, ledger: &Ledger)
        -> GenerationResult<FixturePlanningContext>
    {
        if cfg!(debug_assertions) || !original.belongs_to(ledger)
            || original.requirements() != self.requirements()?
            || ledger.snapshot().allowance.host != 32 << 30
            || ledger.snapshot().allowance.device != 8 << 30
        { return Err(GenerationError::Authority); }
        let transient = original.split(self.startup).map_err(|_| GenerationError::Resource)?;
        let startup = Rc::new(OriginalPlanningStartup { ledger: ledger.clone(),
            original: RefCell::new(Some(transient)), requirements: self.startup,
            session_id: Cell::new(None), closed_requirements: Cell::new(None),
            capability_issued: Cell::new(false), armed: Cell::new(true) });
        let context = match ProvingContext::opencl(Limits {
            host_bytes: 32 << 30, device_bytes: 8 << 30, max_rows: 1 << 20,
        }) {
            Ok(context) => context,
            Err(_) => { core::mem::forget(original); return Err(GenerationError::Startup); }
        };
        startup.session_id.set(Some(context.session_id));
        let owned = FixturePlanningContext { context: Some(context), startup, permanent: Some(original) };
        let footprint = owned.context().workflow_enclosing_footprint().map_err(|_| GenerationError::Authority)?;
        if footprint.managed_device_bytes != 8 << 30
            || footprint.enclosing_host_bytes > owned.permanent.as_ref().unwrap().requirements()
                .total().map_err(|_| GenerationError::Resource)?.host
        { return Err(GenerationError::Authority); }
        owned.context().bind_planning_owner(Rc::clone(&owned.startup)).map_err(|_| GenerationError::Authority)?;
        Ok(owned)
    }
}

impl FixturePlanningContext {
    pub(crate) fn context(&self) -> &ProvingContext { self.context.as_ref().expect("live fixture context") }
    pub(crate) fn ledger(&self) -> &Ledger { self.startup.ledger() }
    pub(crate) fn source_backend_device_bytes(&self) -> GenerationResult<u64> {
        (8u64 << 30).checked_sub(self.startup.current_requirements()?.total()
            .map_err(|_| GenerationError::Resource)?.device).ok_or(GenerationError::Resource)
    }
    pub(in crate::execution) fn adopt_capability(&self)
        -> GenerationResult<crate::execution::phase_lifecycle::PhaseCapability<'_>>
    {
        self.context().issue_original_planning_capability(&self.startup).map_err(|_| GenerationError::Authority)
    }
}
impl Drop for FixturePlanningContext {
    fn drop(&mut self) {
        // Dedicated metadata process exits with incomplete case owners. Do not
        // turn context destruction into a successful workflow cleanup receipt.
        if let Some(context) = self.context.take() { core::mem::forget(context); }
        if let Some(original) = self.permanent.take() { core::mem::forget(original); }
    }
}
