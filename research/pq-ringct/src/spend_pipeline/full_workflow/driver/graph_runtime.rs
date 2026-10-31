//! Concrete graph runtime tables replay the authenticated complete schedule.
//! All outputs retain their full Results in original-backed cells.
use super::super::{
    closed_plan::{CryptoFamily, CryptoOutput, DirectFamily, GraphPhase, LeafFamily,
        NativeFamily, ProducerRoute, StepDispatch, ValidatedCompleteInventory},
    fresh_generation::case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState},
    metadata_planning::{ProducerCounts, ProducerFamily, SourceMetadataPlanningPlan},
    metadata_tables::{graph::*, crypto::*, native::*},
    SourceOperationPlan,
};
use crate::{
    execution::workflow_resources::{PhaseBinding, WorkflowAdmission, WorkflowError, WorkflowPlanning},
    graph_tree::owned_parent::{FixedLeafOuterPlan, ParametersPpGraphPlan, AuxiliaryGraphPlan,
        AuxiliaryGraphSources, EqualityGraphPlan, GraphParentPlan},
};
use std::cell::{RefCell, RefMut};
use super::runtime_inputs::{input_edge, check_owner};

mod outputs;
mod fixed;
mod parameters;
mod equality;
mod auxiliary;
mod parents;
mod frames;
pub(crate) use outputs::GraphOutputs;
pub(crate) use fixed::FixedRuntime;
pub(crate) use parameters::ParametersRuntime;
pub(crate) use equality::EqualityRuntime;
pub(crate) use auxiliary::{AuxiliaryRuntime, DirectInputs};
pub(crate) use parents::{ParentRuntime, ParentRuntimeDriver, ParentRuntimes};
pub(crate) use frames::retained_requirements;

type Result<T> = core::result::Result<T, WorkflowError>;
struct InitGuard<'run, 'context> { planning: &'run mut WorkflowPlanning<'context>, completed: bool }
impl Drop for InitGuard<'_, '_> {
    fn drop(&mut self) { if !self.completed { self.planning.poison_metadata_driver(); } }
}
struct DriverGuard<'run, 'plan, 'context> {
    workflow: &'run mut WorkflowAdmission<'plan, 'context>, completed: bool,
}
impl Drop for DriverGuard<'_, '_, '_> {
    fn drop(&mut self) { if !self.completed { self.workflow.poison_driver(); } }
}
fn slot<'table, 'case, T>(table: &'table CaseOwnerTable<'case, T>, ordinal: usize)
    -> Result<&'table CaseOwnerSlot<'case, T>>
{ table.slots().get(ordinal).ok_or(WorkflowError::Slot) }
fn value<'table, T>(slot: &'table CaseOwnerSlot<'_, T>) -> Result<&'table T> {
    if !slot.is_initialized() { return Err(WorkflowError::Empty); }
    slot.get().map_err(|_| WorkflowError::Sequence)
}
fn plan<'table, T, E>(table: &'table CaseOwnerTable<'_, core::result::Result<T, E>>, ordinal: usize)
    -> Result<&'table T>
{ value(slot(table, ordinal)?)?.as_ref().map_err(|_| WorkflowError::Source) }
fn cell<'table, T, E>(table: &'table CaseOwnerTable<'_, RefCell<Option<core::result::Result<T, E>>>>,
    ordinal: usize) -> Result<&'table RefCell<Option<core::result::Result<T, E>>>>
{ value(slot(table, ordinal)?) }
fn write<T, E>(cell: &RefCell<Option<core::result::Result<T, E>>>)
    -> Result<RefMut<'_, Option<core::result::Result<T, E>>>>
{ cell.try_borrow_mut().map_err(|_| WorkflowError::SlotBusy) }
fn ready<T, E>(value: &Option<core::result::Result<T, E>>) -> Result<&T> {
    value.as_ref().ok_or(WorkflowError::Empty)?.as_ref().map_err(|_| WorkflowError::Poisoned)
}
fn empty<T, E>(value: &Option<core::result::Result<T, E>>) -> Result<()> {
    if value.is_some() { return Err(WorkflowError::SlotBusy); } Ok(())
}
fn take_ready<T, E>(value: &mut Option<core::result::Result<T, E>>) -> Result<T> {
    match value.take() {
        Some(Ok(owner)) => Ok(owner),
        Some(Err(error)) => { *value = Some(Err(error)); Err(WorkflowError::Poisoned) }
        None => Err(WorkflowError::Empty),
    }
}
fn original_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count
        || table.slots().iter().any(|slot| !slot.is_initialized())
    { return Err(WorkflowError::Identity); } Ok(())
}
fn uninitialized_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count
        || table.slots().iter().any(CaseOwnerSlot::is_initialized)
    { return Err(WorkflowError::Identity); } Ok(())
}
fn initialize_table<T, E>(table: &CaseOwnerTable<'_, RefCell<Option<core::result::Result<T, E>>>>)
    -> Result<()>
{
    for slot in table.slots() {
        slot.install(RefCell::new(None)).map_err(|_| WorkflowError::Sequence)?;
    } Ok(())
}
fn empty_table<T, E>(table: &CaseOwnerTable<'_, RefCell<Option<core::result::Result<T, E>>>>,
    case: &CaseRetirementState, count: usize) -> Result<()>
{
    original_table(table, case, count)?;
    for slot in table.slots() {
        let contents = value(slot)?.try_borrow().map_err(|_| WorkflowError::SlotBusy)?;
        empty(&contents)?;
    } Ok(())
}
fn same_binding(actual: PhaseBinding, expected: PhaseBinding) -> Result<()> {
    if actual != expected { return Err(WorkflowError::Identity); } Ok(())
}
fn shape(dispatch: &StepDispatch, count: usize, consumed: usize) -> Result<()> {
    if dispatch.inputs().len() != count || dispatch.consume_count() != consumed {
        return Err(WorkflowError::Sequence);
    } Ok(())
}
fn input(dispatch: &StepDispatch, index: usize) -> Result<ProducerRoute> {
    dispatch.inputs().get(index).copied().flatten().ok_or(WorkflowError::Sequence)
}
fn require_input(dispatch: &StepDispatch, index: usize, expected: ProducerRoute) -> Result<()> {
    if input(dispatch, index)? != expected { return Err(WorkflowError::Identity); } Ok(())
}
fn direct_route(dispatch: &StepDispatch, expected: DirectFamily) -> Result<(usize, GraphPhase)> {
    match dispatch.producer() {
        ProducerRoute::Direct { family, ordinal, phase } if family == expected => Ok((ordinal, phase)),
        _ => Err(WorkflowError::Identity),
    }
}
fn increment(count: &mut usize) -> Result<()> {
    *count = count.checked_add(1).ok_or(WorkflowError::Overflow)?; Ok(())
}

fn expected_edges(inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
    dispatch: &StepDispatch, bindings: &[Option<PhaseBinding>], count: usize, consumed: usize)
    -> Result<()>
{
    shape(dispatch, count, consumed)?;
    if count > bindings.len() || bindings[count..].iter().any(Option::is_some) {
        return Err(WorkflowError::Sequence);
    }
    for (index, expected) in bindings[..count].iter().enumerate() {
        same_binding(input_edge(inventory, closed_ordinal, index)?.0,
            expected.ok_or(WorkflowError::Identity)?)?;
    }
    Ok(())
}
