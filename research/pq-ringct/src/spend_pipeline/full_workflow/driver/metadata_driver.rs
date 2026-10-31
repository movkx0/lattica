//! Scoped construction of every concrete complete-workflow owner.
//! Each named transfer result stays in its declaring scope through the one
//! concrete execution continuation and terminal case completion. Parent levels
//! use nested stack scopes; only sealed, borrowed projections cross them.
use super::{case_report::CompletedCaseSummary, crypto_runtime::{ShakeRuntime, AesRuntime},
    native_layers::{self, NativePlanTables, BlueprintTables, NativeCompilerInputs,
        CompilerPlanTables, OuterPlanTables},
    native_runtime::{NativeRuntime, NativeOutputs, NativePackets, CompiledOutputs,
        OuterOutputs, OuterPackets},
    graph_layers::{self, DirectDependencies, DirectPlanTables, LeafViews, PriorParentLevels},
    graph_runtime::{FixedRuntime, ParametersRuntime, AuxiliaryRuntime, EqualityRuntime,
        ParentRuntime, ParentRuntimes, DirectInputs, GraphOutputs},
    runtime_dispatch::{StepRuntime, RuntimeSet, ParametersDispatch, AuxiliaryDispatch},
    final_runtime::FinalRuntime};
use super::super::{
    closed_plan::{CompleteProducerTables, producer_tables as views},
    fresh_generation::{FreshGenerationBatch, FreshGenerationError,
        case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState}},
    metadata_planning::{ProducerCounts, ProducerFamily, SourceMetadataPlanningPlan},
    metadata_tables::{crypto as crypto_tables, graph as graph_tables},
};
use crate::{
    execution::{generation_terminal::planning_startup::FreshPlanningContext,
        workflow_resources::{WorkflowPlanning, WorkflowError, TableTransferResult}},
    graph_crypto::{ProofCache, OuterProofCache, RequestDescriptor},
    graph_tree::owned_parent::GraphChildSource,
};
type Result<T> = core::result::Result<T, WorkflowError>;

mod construct;
mod crypto;
mod parents;
mod final_stage;
mod projections;
mod frames;
mod stage;
pub(crate) use stage::{DriverAction, DriverStage, RuntimeAction};
pub(crate) use stage::frame_bytes as stage_frame_bytes;
pub(crate) use stage::runtime_frame_bytes as runtime_stage_frame_bytes;
use projections::{LeafPlanTables, OrdinaryRuntimes};
pub(crate) use construct::run;
pub(crate) use frames::retained_requirements;

/// This owns the original planning value; it creates no replacement claim.
/// Any partial-construction error or unwind poisons before original teardown.
struct PlanningGuard<'context> { planning: Option<WorkflowPlanning<'context>> }
impl<'context> PlanningGuard<'context> {
    fn new(planning: WorkflowPlanning<'context>) -> Self { Self { planning: Some(planning) } }
    fn get(&mut self) -> Result<&mut WorkflowPlanning<'context>> {
        self.planning.as_mut().ok_or(WorkflowError::Poisoned)
    }
    fn into_inner(mut self) -> Result<WorkflowPlanning<'context>> {
        self.planning.take().ok_or(WorkflowError::Poisoned)
    }
}
impl Drop for PlanningGuard<'_> {
    fn drop(&mut self) {
        if let Some(planning) = self.planning.as_mut() { planning.poison_metadata_driver(); }
    }
}

/// Inspect only by borrowing the complete result, which remains a named local.
fn table<'view, 'case, T>(result: &'view TableTransferResult<'case, T>)
    -> Result<&'view CaseOwnerTable<'case, T>>
{
    result.as_ref().map_err(|_| WorkflowError::Planning)
}
fn successful<'view, T, E>(table: &'view CaseOwnerTable<'_, core::result::Result<T, E>>,
    ordinal: usize) -> Result<&'view T>
{
    let slot = table.slots().get(ordinal).ok_or(WorkflowError::Slot)?;
    if !slot.is_initialized() { return Err(WorkflowError::Empty); }
    slot.get().map_err(|_| WorkflowError::Sequence)?.as_ref().map_err(|_| WorkflowError::Source)
}
fn install<T, E>(slot: &CaseOwnerSlot<'_, core::result::Result<T, E>>,
    result: core::result::Result<T, E>) -> Result<()>
{
    slot.install(result).map_err(|_| WorkflowError::Sequence)?;
    slot.get().map_err(|_| WorkflowError::Sequence)?.as_ref().map_err(|_| WorkflowError::Source)?;
    Ok(())
}
fn empty_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count
        || table.slots().iter().any(CaseOwnerSlot::is_initialized)
    { return Err(WorkflowError::Identity); }
    Ok(())
}
