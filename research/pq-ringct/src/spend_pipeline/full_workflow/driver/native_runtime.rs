//! Concrete native/leaf dispatch over the authenticated complete schedule.
//! All stable result cells are installed before seal; complete producer Results
//! reach those cells before inspection. Borrowed descriptors never own proofs.
use super::native_layers::{NativePlanTables, CompilerPlanTables, OuterPlanTables};
use crate::{
    execution::{retained_resources::{Bytes, Category, Requirements},
        workflow_resources::{PhaseBinding, PhaseStep, SlotId, WorkflowAdmission,
            WorkflowError, WorkflowPlanning}},
    spend_pipeline::full_workflow::{
        closed_plan::{GraphPhase, LeafFamily, NativeFamily, ProducerRoute,
            StepDispatch, ValidatedCompleteInventory},
        fresh_generation::case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState},
        metadata_planning::{ProducerFamily, SourceMetadataPlanningPlan},
        metadata_tables::{RuntimeTable, native as native_tables,
            algebra as algebra_tables, graph as graph_tables},
    },
};
use core::mem::size_of;
use std::cell::{Ref, RefCell, RefMut};

mod tables;
mod planning;
mod execute;
mod frames;
pub(crate) use tables::{NativeOutputs, NativePackets, CompiledOutputs, OuterOutputs, OuterPackets};
pub(crate) use frames::retained_requirements;

type Result<T> = core::result::Result<T, WorkflowError>;
type Outcome<T, E> = core::result::Result<T, E>;

/// Table borrows and plan borrows are independent. Invariant owning tables
/// retain their original case/source lifetimes instead of being shortened.
pub(crate) struct NativeRuntime<'tables, 'case, 'plans, 'source, 'native, 'a> {
    pub(crate) plans: NativePlanTables<'plans, 'case, 'native>,
    pub(crate) compilers: CompilerPlanTables<'plans, 'case, 'a>,
    pub(crate) outer_plans: OuterPlanTables<'plans, 'case, 'source, 'a>,
    pub(crate) native: NativeOutputs<'tables, 'case, 'a>,
    pub(crate) native_packets: NativePackets<'tables, 'case, 'plans, 'a>,
    pub(crate) compiled: CompiledOutputs<'tables, 'case, 'a>,
    pub(crate) outer: OuterOutputs<'tables, 'case, 'a>,
    pub(crate) outer_packets: OuterPackets<'tables, 'case, 'plans, 'source, 'a>,
}

struct InitGuard<'run, 'workflow> {
    planning: &'run mut WorkflowPlanning<'workflow>,
    completed: bool,
}
impl Drop for InitGuard<'_, '_> {
    fn drop(&mut self) {
        if !self.completed { self.planning.poison_metadata_driver(); }
    }
}
struct DriverGuard<'run, 'plan, 'context> {
    workflow: &'run mut WorkflowAdmission<'plan, 'context>,
    completed: bool,
}
impl Drop for DriverGuard<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed { self.workflow.poison_driver(); }
    }
}

fn original_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count {
        return Err(WorkflowError::Identity);
    }
    Ok(())
}
fn uninitialized_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    original_table(table, case, count)?;
    if table.slots().iter().any(CaseOwnerSlot::is_initialized) {
        return Err(WorkflowError::Sequence);
    }
    Ok(())
}
fn original<'view, T, E>(table: &'view CaseOwnerTable<'_, Outcome<T, E>>,
    ordinal: usize) -> Result<&'view T>
{
    let slot = table.slots().get(ordinal).ok_or(WorkflowError::Slot)?;
    if !slot.is_initialized() { return Err(WorkflowError::Empty); }
    slot.get().map_err(|_| WorkflowError::Sequence)?.as_ref().map_err(|_| WorkflowError::Source)
}
fn populated<T, E>(table: &CaseOwnerTable<'_, Outcome<T, E>>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    original_table(table, case, count)?;
    for ordinal in 0..count { let _ = original(table, ordinal)?; }
    Ok(())
}
fn cell<'view, T>(table: &'view RuntimeTable<'_, T>, ordinal: usize)
    -> Result<&'view RefCell<Option<T>>>
{
    let slot = table.slots().get(ordinal).ok_or(WorkflowError::Slot)?;
    if !slot.is_initialized() { return Err(WorkflowError::Empty); }
    slot.get().map_err(|_| WorkflowError::Sequence)
}
fn read<T>(value: &RefCell<T>) -> Result<Ref<'_, T>> {
    value.try_borrow().map_err(|_| WorkflowError::SlotBusy)
}
fn write<T>(value: &RefCell<T>) -> Result<RefMut<'_, T>> {
    value.try_borrow_mut().map_err(|_| WorkflowError::SlotBusy)
}
fn empty<T>(value: &Option<T>) -> Result<()> {
    if value.is_some() { return Err(WorkflowError::SlotBusy); }
    Ok(())
}
fn ready<T, E>(value: &Option<Outcome<T, E>>) -> Result<&T> {
    value.as_ref().ok_or(WorkflowError::Empty)?.as_ref().map_err(|_| WorkflowError::Poisoned)
}
/// Unexpected error extraction restores the complete original-bearing error.
/// Callers already hold every input/output/packet borrow before this operation.
fn take_ready<T, E>(value: &mut Option<Outcome<T, E>>) -> Result<T> {
    match value.take() {
        Some(Ok(owner)) => Ok(owner),
        Some(Err(error)) => {
            *value = Some(Err(error));
            Err(WorkflowError::Poisoned)
        }
        None => Err(WorkflowError::Empty),
    }
}
fn initialize_table<T>(table: &RuntimeTable<'_, T>) -> Result<()> {
    for slot in table.slots() {
        slot.install(RefCell::new(None)).map_err(|_| WorkflowError::Sequence)?;
    }
    Ok(())
}
fn empty_table<T>(table: &RuntimeTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    original_table(table, case, count)?;
    for ordinal in 0..count {
        let value = read(cell(table, ordinal)?)?;
        empty(&value)?;
    }
    Ok(())
}
fn same_binding(actual: PhaseBinding, expected: PhaseBinding) -> Result<()> {
    if actual != expected { return Err(WorkflowError::Identity); }
    Ok(())
}
/// Check the phase-specific invariant only after authenticating the exact
/// closed dispatch and producer binding. Outer placeholders have already been
/// replaced by close_memory's admitted residual; generic workflow preflight
/// separately checks the actual context allowance and combined scratch.
/// This numerical check creates no source, reservation or execution authority.
pub(in crate::spend_pipeline::full_workflow) fn check_leaf_backend(
    phase: GraphPhase, backend: Bytes) -> Result<()>
{
    let valid = match phase {
        GraphPhase::Compile => backend == Bytes::ZERO,
        GraphPhase::Outer => backend.host > 0 && backend.host <= 32 << 30
            && backend.device == 8 << 30,
    };
    if !valid { return Err(WorkflowError::BackendAllowance); }
    Ok(())
}
fn shape(dispatch: &StepDispatch, scheduled: &PhaseStep, expected: &[ProducerRoute]) -> Result<()> {
    if dispatch.inputs().len() != expected.len() || dispatch.consume_count() != expected.len()
        || scheduled.input_count != expected.len() || scheduled.consume_count != expected.len()
        || !dispatch.inputs().iter().zip(expected).all(|(actual, expected)| *actual == Some(*expected))
    { return Err(WorkflowError::Sequence); }
    Ok(())
}
fn step<'view>(inventory: &'view ValidatedCompleteInventory<'_, '_>, ordinal: usize)
    -> Result<&'view PhaseStep>
{
    inventory.closed_plan().steps().get(ordinal).ok_or(WorkflowError::Sequence)
}
/// Resolve the exact prior producing route, including the sealed original slot.
/// Equal resource geometry or a same-family foreign owner is insufficient.
fn prior_input(inventory: &ValidatedCompleteInventory<'_, '_>, ordinal: usize,
    index: usize, producer: ProducerRoute) -> Result<(PhaseBinding, SlotId)>
{
    let dispatch = inventory.closed_plan().dispatch().get(ordinal).ok_or(WorkflowError::Sequence)?;
    if dispatch.inputs().get(index).copied().flatten() != Some(producer) {
        return Err(WorkflowError::Identity);
    }
    super::runtime_inputs::input_edge(inventory, ordinal, index)
}
fn next_count(count: &mut usize, ordinal: usize) -> Result<()> {
    if *count != ordinal { return Err(WorkflowError::Sequence); }
    *count = count.checked_add(1).ok_or(WorkflowError::Overflow)?;
    Ok(())
}
fn native_index(family: NativeFamily) -> usize {
    match family {
        NativeFamily::Source => 0, NativeFamily::Uniform => 1, NativeFamily::Sparse => 2,
        NativeFamily::Transcript => 3, NativeFamily::Affine => 4, NativeFamily::Ntt => 5,
        NativeFamily::Mul => 6, NativeFamily::GBound => 7, NativeFamily::Permutation => 8,
        NativeFamily::LinearMap => 9,
    }
}
fn leaf_index(family: LeafFamily) -> usize {
    match family {
        LeafFamily::Source => 0, LeafFamily::Affine => 1, LeafFamily::Ntt => 2,
        LeafFamily::Mul => 3, LeafFamily::GBound => 4, LeafFamily::Permutation => 5,
        LeafFamily::LinearMap => 6,
    }
}

#[cfg(test)]
mod tests;
