//! Shared context transition used only by the admitted complete workflow.
//! Source pointers stay stable; the ordinary GPU Session is actually retired
//! before any originally owned native/outer Runtime is constructed.
use super::{ContextPhases, OwnedPhase, Category, ProvingContext};
use crate::opencl::{RetiredSourceSession, SourceRetirement, TransitionError};
use lattica_prover_p3::{block_v2::gpu_hash, proving::Policy};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkflowTransitionError {
    Policy,
    Lifecycle,
    BackendOwner,
    Busy,
    QueueDrain,
    Session(TransitionError),
}

/// An exact context and its nonconstructible real source-session retirement.
/// Retaining this value creates neither a backend claim nor dispatch authority.
pub(in crate::execution) struct RetiredWorkflowContext<'context> {
    context: &'context ProvingContext,
    source: RetiredSourceSession<'context>,
}

impl<'context> OwnedPhase<'context> {
    pub(in crate::execution) fn retire_source_session(
        &self,
    ) -> Result<RetiredWorkflowContext<'context>, WorkflowTransitionError> {
        let context = self.capability.context;
        if context.policy() != Policy::GpuRequired {
            return Err(WorkflowTransitionError::Policy);
        }
        let session = context.session.as_ref().ok_or(WorkflowTransitionError::Policy)?;
        {
            let state = context.phases.state.try_borrow().map_err(|_| WorkflowTransitionError::Busy)?;
            ContextPhases::check_active(&state, self.generation)
                .map_err(|_| WorkflowTransitionError::Lifecycle)?;
            ContextPhases::check_no_partition(&state)
                .map_err(|_| WorkflowTransitionError::Lifecycle)?;
            let backend = state.held.as_ref().ok_or(WorkflowTransitionError::BackendOwner)?
                .requirements().get(Category::PhaseScratch);
            let startup = context.phases.planning_startup_requirement()
                .map_err(|_| WorkflowTransitionError::BackendOwner)?;
            if backend.host == 0 || backend.device.checked_add(startup.get(Category::PhaseScratch).device)
                != Some(session.limits().device_bytes) {
                return Err(WorkflowTransitionError::BackendOwner);
            }
        }
        // The exclusive registry borrow prevents transition inside any live
        // registered/native callback and keeps its prepared owner stable.
        let mut registry = context.registry.try_borrow_mut().map_err(|_| WorkflowTransitionError::Busy)?;
        let retiring = session.begin_workflow_retirement().map_err(WorkflowTransitionError::Session)?;
        gpu_hash::drain().map_err(|_| WorkflowTransitionError::QueueDrain)?;
        registry.release(crate::execution::telemetry::ReleaseReason::SessionRetired);
        let source = retiring.retire().map_err(WorkflowTransitionError::Session)?;
        context.phases.transfer_retired_planning_startup(self.generation, &source, context)
            .map_err(|_| WorkflowTransitionError::BackendOwner)?;
        Ok(RetiredWorkflowContext { context, source })
    }
}

impl<'context> RetiredWorkflowContext<'context> {
    pub(in crate::execution) fn source(&self) -> &RetiredSourceSession<'context> { &self.source }

    pub(in crate::execution) fn belongs_to(&self, context: &ProvingContext) -> bool {
        core::ptr::eq(self.context, context)
            && context.session.as_ref().is_some_and(|session| self.source.belongs_to(session))
    }

    pub(in crate::execution) fn retirement(&self) -> SourceRetirement { self.source.retirement() }
}

pub(in crate::execution) fn additional_host_bytes() -> usize {
    4 * core::mem::size_of::<RetiredWorkflowContext<'static>>()
        + 4 * core::mem::size_of::<Result<RetiredWorkflowContext<'static>, WorkflowTransitionError>>()
}
