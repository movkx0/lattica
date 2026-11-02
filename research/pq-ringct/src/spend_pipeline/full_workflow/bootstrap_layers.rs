//! Concrete source stages shared by the fixed N3 and N4 fresh-case drivers.
//! Callers claim each owning dependency layer before deriving SourcePlanningPlan.
//! Full constructor/phase results enter those slots before any error inspection.
use super::{SourcePlanningPlan, SourceGraphPlan, SourcePreparationPlan,
    SourcePreparationError, PreparedGraphSources, PreparedWorkflowSources};
use super::fresh_generation::{FreshGenerationError, case_lifetime::{CaseOwnerSlot, FixedCaseOwnerSlots}};
use crate::execution::generation_terminal::planning_startup::FreshPlanningContext;
use crate::execution::workflow_resources::{WorkflowPlanning, SourceRetained, SourcePhaseFailure};

type Result<T> = core::result::Result<T, FreshGenerationError>;
pub(crate) type GraphPlanResult<'a> = core::result::Result<SourceGraphPlan<'a>, SourcePreparationError>;
pub(crate) type GraphSourceResult = core::result::Result<SourceRetained<PreparedGraphSources>,
    SourcePhaseFailure<PreparedGraphSources>>;
pub(crate) type PreparationPlanResult<'a> = core::result::Result<SourcePreparationPlan<'a>, SourcePreparationError>;
pub(crate) type PreparedSourceResult<'a> = core::result::Result<SourceRetained<PreparedWorkflowSources<'a>>,
    SourcePhaseFailure<PreparedWorkflowSources<'a>>>;

fn failure(message: &'static str) -> FreshGenerationError { FreshGenerationError::Resource(message) }

// Each table owns its payload independently of the planning capability's
// context borrow. Invariant output slots must retain only their source/graph
// dependencies, never a borrow of the table that contains the descriptor.
pub(crate) fn prepare_graph_layer<'scope, 'context, const N: usize>(
    scope: &'scope SourcePlanningPlan<'scope>,
    planning: &mut WorkflowPlanning<'context>,
    startup: &crate::spend_pipeline::full_workflow::fresh_generation::case_lifetime::MetadataOwner<'_, '_, '_>,
    plans: &FixedCaseOwnerSlots<'_, GraphPlanResult<'scope>, N>,
    outputs: &FixedCaseOwnerSlots<'_, GraphSourceResult, N>,
) -> Result<()> {
    let case = startup.metadata_case_state(scope, planning.ledger())?;
    plans.check_case(case)?;
    outputs.check_case(case)?;
    if !matches!(N, 3 | 4) || scope.natives().len() != N {
        return Err(failure("graph source layer case mismatch"));
    }
    // Refuse an already-used or partially used table before any source phase.
    for ordinal in 0..N {
        if plans.get(ordinal)?.get().is_ok() || outputs.get(ordinal)?.get().is_ok() {
            return Err(failure("graph source layer already populated"));
        }
    }
    for (ordinal, native) in scope.natives().iter().enumerate() {
        let plan_slot = plans.get(ordinal)?;
        plan_slot.install(SourceGraphPlan::new(scope, native))?;
        let plan = plan_slot.get()?.as_ref()
            .map_err(|_| failure("graph source descriptor refused"))?;
        let output_slot = outputs.get(ordinal)?;
        output_slot.install(planning.prepare_graph(plan.operation()))?;
        output_slot.get()?.as_ref()
            .map_err(|_| failure("graph source preparation refused"))?;
    }
    Ok(())
}

pub(crate) fn prepare_source_layer<'source: 'graph, 'graph, 'context, const N: usize>(
    scope: &SourcePlanningPlan<'source>,
    planning: &mut WorkflowPlanning<'context>,
    startup: &crate::spend_pipeline::full_workflow::fresh_generation::case_lifetime::MetadataOwner<'_, '_, '_>,
    graphs: &'graph FixedCaseOwnerSlots<'_, GraphSourceResult, N>,
    plans: &FixedCaseOwnerSlots<'_, PreparationPlanResult<'graph>, N>,
    outputs: &FixedCaseOwnerSlots<'_, PreparedSourceResult<'graph>, N>,
) -> Result<()> {
    let case = startup.metadata_case_state(scope, planning.ledger())?;
    graphs.check_case(case)?;
    plans.check_case(case)?;
    outputs.check_case(case)?;
    if !matches!(N, 3 | 4) || scope.natives().len() != N {
        return Err(failure("prepared source layer case mismatch"));
    }
    for ordinal in 0..N {
        if plans.get(ordinal)?.get().is_ok() || outputs.get(ordinal)?.get().is_ok() {
            return Err(failure("prepared source layer already populated"));
        }
        graphs.get(ordinal)?.get()?.as_ref()
            .map_err(|_| failure("prepared source layer lacks graph"))?;
    }
    for (ordinal, native) in scope.natives().iter().enumerate() {
        let graph = graphs.get(ordinal)?.get()?.as_ref()
            .map_err(|_| failure("prepared source layer lacks graph"))?;
        let plan_slot = plans.get(ordinal)?;
        plan_slot.install(SourcePreparationPlan::new(scope, graph, native))?;
        let plan = plan_slot.get()?.as_ref()
            .map_err(|_| failure("prepared source descriptor refused"))?;
        let output_slot = outputs.get(ordinal)?;
        output_slot.install(planning.prepare_sources(plan.operation()))?;
        output_slot.get()?.as_ref()
            .map_err(|_| failure("prepared source phase refused"))?;
    }
    Ok(())
}
