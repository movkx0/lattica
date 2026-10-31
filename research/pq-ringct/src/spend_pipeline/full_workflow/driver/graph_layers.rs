//! Concrete fixed/direct/parent table construction under the original case.
//! Only borrowed projections erase per-level borrow lifetimes. Actual owning
//! tables remain separate, and the original graph lifetime stays independent.
use crate::{execution::{retained_resources::{Bytes, Category, Ledger, Requirements},
        workflow_resources::{WorkflowError, WorkflowPlanning}},
    graph_crypto::{OuterProofCache, OwnedAesRequestPlan, PairedRequestPlan, Request},
    graph_tree::{LeafKind, OperationFamily,
        owned_parent::{GraphChildSource, AuxiliaryGraphSources, AuxiliaryPreparedInventory, AuxiliaryGraphKind}},
    spend_pipeline::full_workflow::{SourceOperationPlan, PreparedWorkflowSources,
        metadata_planning::{MetadataMember, ProducerFamily, SourceMetadataPlanningPlan},
        metadata_tables::{graph as table, native as native_table, crypto as crypto_table},
        fresh_generation::case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState}}};
use super::metadata_driver::{DriverStage, DriverAction, stage_frame_bytes};
use core::mem::size_of;
type Result<T> = core::result::Result<T, WorkflowError>;
mod fixed;
mod direct;
mod parents;
mod views;
mod frames;
pub(crate) use fixed::{fill_fixed_sources, fill_fixed_outer};
pub(crate) use direct::{DirectDependencies, DirectPlanTables, fill_direct_leaves};
pub(crate) use parents::fill_parent_level;
pub(crate) use views::{LeafViews, PriorParentLevels, ParentChildren};
pub(crate) use frames::requirements;

fn checked_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize, empty: bool) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count
        || (empty && table.slots().iter().any(CaseOwnerSlot::is_initialized))
    { return Err(WorkflowError::Identity); }
    Ok(())
}
fn successful<'view, T, E>(table: &'view CaseOwnerTable<'_, core::result::Result<T, E>>,
    ordinal: usize) -> Result<&'view T>
{
    table.get(ordinal).map_err(|_| WorkflowError::Identity)?.get()
        .map_err(|_| WorkflowError::Planning)?.as_ref().map_err(|_| WorkflowError::Source)
}
fn populated<T, E>(table: &CaseOwnerTable<'_, core::result::Result<T, E>>) -> Result<()> {
    for ordinal in 0..table.slots().len() { let _ = successful(table, ordinal)?; }
    Ok(())
}
fn install<T, E>(slot: &CaseOwnerSlot<'_, core::result::Result<T, E>>,
    result: core::result::Result<T, E>) -> Result<()>
{
    slot.install(result).map_err(|_| WorkflowError::Planning)?;
    slot.get().map_err(|_| WorkflowError::Planning)?.as_ref().map_err(|_| WorkflowError::Source)?;
    Ok(())
}
fn position<'a>(plan: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
    family: ProducerFamily, ordinal: usize) -> Result<usize>
{
    plan.source_position(member, family, ordinal).map_err(|_| WorkflowError::Identity)
}
struct Guard<'borrow, 'workflow> { planning: &'borrow mut WorkflowPlanning<'workflow>, complete: bool }
impl Drop for Guard<'_, '_> {
    fn drop(&mut self) { if !self.complete { self.planning.poison_metadata_driver(); } }
}
fn run<'workflow>(planning: &mut WorkflowPlanning<'workflow>, plan: &SourceMetadataPlanningPlan<'_>,
    case: &CaseRetirementState, build: impl FnOnce(&mut WorkflowPlanning<'workflow>) -> Result<()>) -> Result<()>
{
    planning.validate_metadata_driver(plan, case)?;
    let mut guard = Guard { planning, complete: false };
    let result = build(&mut *guard.planning);
    if result.is_ok() {
        guard.planning.validate_metadata_driver(plan, case)?;
        guard.complete = true;
    }
    result
}
