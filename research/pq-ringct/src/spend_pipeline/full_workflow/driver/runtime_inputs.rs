//! Immutable route/slot correspondence checked before an owning input moves.
//! These observations grant no execution or memory-admission authority.
use super::super::closed_plan::{ClosedWorkflowPlan, StepDispatch, ProducerRoute, ValidatedCompleteInventory};
use crate::execution::{workflow_resources::{PhaseBinding, PhaseStep, SlotId, Retained, WorkflowError},
    retained_resources::{Bytes, Category, Requirements}};
type Result<T> = core::result::Result<T, WorkflowError>;

pub(crate) fn input_edge(inventory: &ValidatedCompleteInventory<'_, '_>, before: usize, index: usize)
    -> Result<(PhaseBinding, SlotId)>
{
    let plan = inventory.closed_plan();
    let dispatch = plan.dispatch().get(before).ok_or(WorkflowError::Sequence)?;
    let step = plan.steps().get(before).ok_or(WorkflowError::Sequence)?;
    if dispatch.inputs().len() != step.input_count || dispatch.consume_count() != step.consume_count
        || index >= step.input_count { return Err(WorkflowError::Sequence); }
    let route = dispatch.inputs().get(index).copied().flatten().ok_or(WorkflowError::Sequence)?;
    let position = step.input_start.checked_add(index).ok_or(WorkflowError::Overflow)?;
    let slot = *plan.inputs().get(position).ok_or(WorkflowError::Sequence)?;
    let mut found = None;
    for (ordinal, prior) in plan.dispatch()[..before].iter().enumerate() {
        if prior.producer() != route { continue; }
        if found.is_some() { return Err(WorkflowError::Identity); }
        let producer = plan.steps().get(ordinal).ok_or(WorkflowError::Sequence)?;
        if producer.output != slot { return Err(WorkflowError::Identity); }
        found = Some((producer.binding, slot));
    }
    found.ok_or(WorkflowError::Identity)
}

pub(crate) fn check_owner<T>(owner: &Retained<T>, inventory: &ValidatedCompleteInventory<'_, '_>,
    before: usize, index: usize) -> Result<()>
{
    let (binding, slot) = input_edge(inventory, before, index)?;
    if owner.binding() != binding || owner.slot_id() != slot { return Err(WorkflowError::Identity); }
    Ok(())
}

pub(crate) fn retained_requirements() -> Result<Requirements> {
    use core::mem::size_of;
    let host = [size_of::<Result<(PhaseBinding, SlotId)>>(), size_of::<Option<(PhaseBinding, SlotId)>>(),
        size_of::<StepDispatch>(), size_of::<PhaseStep>(), size_of::<ProducerRoute>(),
        size_of::<crate::spend_pipeline::full_workflow::metadata_planning::ProducerCounts>(),
        size_of::<Result<()>>(), size_of::<[usize; 8]>(), size_of::<&ClosedWorkflowPlan<'static>>(),
    ].into_iter().try_fold(0usize, |a, b| a.checked_add(b)).and_then(|n| n.checked_mul(8))
        .ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(host).map_err(|_| WorkflowError::Overflow)?, device: 0 }))
}
