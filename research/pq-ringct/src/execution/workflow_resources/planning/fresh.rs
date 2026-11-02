//! Named bootstrap for the authentic generation ledger. The legacy synthetic
//! source route keeps its original enclosing-subtraction constructor.
use super::*;
use crate::execution::generation_terminal::planning_startup::FreshPlanningContext;

impl<'context> WorkflowPlanning<'context> {
    pub(crate) fn admit_fresh(plan: &SourcePlanningPlan<'context>,
        fresh: &'context FreshPlanningContext<'_>) -> Result<Self, WorkflowError>
    {
        let context = fresh.context();
        if !core::ptr::eq(context, plan.context()) || plan.enclosing_bytes() != Bytes::ZERO
            || context.policy() != Policy::GpuRequired || context.host_bytes() != context.host_profile().worker_bytes()
        { return Err(WorkflowError::Identity); }
        fresh.validate_source_entry().map_err(|_| WorkflowError::Identity)?;
        let compiled_source = plan.compiled_source_fingerprint();
        if compiled_source != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(WorkflowError::Source);
        }
        let capability = fresh.adopt_capability().map_err(|_| WorkflowError::Planning)?;
        if !capability.uses_original_generation_ledger()
            || capability.ledger().snapshot().allowance.host != context.host_bytes()
            || capability.ledger().snapshot().allowance.device != MAX_DEVICE_BYTES
            || plan.source_backend_allowance().device != capability.source_bootstrap_device_bytes()?
        { return Err(WorkflowError::BackendAllowance); }
        let requirements = plan.planning_requirements();
        let scratch_requirements = plan.planning_scratch_requirements();
        if requirements.total()? == Bytes::ZERO || scratch_requirements.total()? == Bytes::ZERO
            || requirements.get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < super::super::controller_bytes(2)?
        { return Err(WorkflowError::Planning); }
        // This is the first new source metadata admission; generation, input,
        // registry and startup originals are already booked on this ledger.
        let mut original = capability.ledger().admit_phase(requirements)?;
        let scratch = original.split(scratch_requirements)?;
        Ok(Self { original: GuardedPlanningOriginal::new(original), scratch, capability, context,
            source: plan.source_fingerprint(), compiled_source, enclosing: Bytes::ZERO,
            managed_device: MAX_DEVICE_BYTES, failed: false, closure_reserved: false,
            #[cfg(not(debug_assertions))]
            producer_metadata: None,
            native_session: Default::default(),
            failed_source_pool: None })
    }
    #[cfg(test)]
    pub(crate) fn admit_fixture(plan: &SourcePlanningPlan<'context>,
        fresh: &'context crate::execution::generation_terminal::planning_startup::FixturePlanningContext) -> Result<Self, WorkflowError>
    {
        let context = fresh.context();
        if !core::ptr::eq(context, plan.context()) || plan.enclosing_bytes() != Bytes::ZERO
            || context.policy() != Policy::GpuRequired || context.host_bytes() != context.host_profile().worker_bytes()
        { return Err(WorkflowError::Identity); }
        if plan.fixture_context().is_none_or(|owner| !core::ptr::eq(owner, fresh)) { return Err(WorkflowError::Identity); }
        let compiled_source = plan.compiled_source_fingerprint();
        if compiled_source != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(WorkflowError::Source);
        }
        let capability = fresh.adopt_capability().map_err(|_| WorkflowError::Planning)?;
        if !capability.uses_original_generation_ledger()
            || capability.ledger().snapshot().allowance.host != context.host_bytes()
            || capability.ledger().snapshot().allowance.device != MAX_DEVICE_BYTES
            || plan.source_backend_allowance().device != capability.source_bootstrap_device_bytes()?
        { return Err(WorkflowError::BackendAllowance); }
        let requirements = plan.planning_requirements();
        let scratch_requirements = plan.planning_scratch_requirements();
        if requirements.total()? == Bytes::ZERO || scratch_requirements.total()? == Bytes::ZERO
            || requirements.get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < super::super::controller_bytes(2)?
        { return Err(WorkflowError::Planning); }
        // This is the first new source metadata admission; generation, input,
        // registry and startup originals are already booked on this ledger.
        let mut original = capability.ledger().admit_phase(requirements)?;
        let scratch = original.split(scratch_requirements)?;
        Ok(Self { original: GuardedPlanningOriginal::new(original), scratch, capability, context,
            source: plan.source_fingerprint(), compiled_source, enclosing: Bytes::ZERO,
            managed_device: MAX_DEVICE_BYTES, failed: false, closure_reserved: false,
            #[cfg(not(debug_assertions))]
            producer_metadata: None,
            native_session: Default::default(),
            failed_source_pool: None })
    }
}
