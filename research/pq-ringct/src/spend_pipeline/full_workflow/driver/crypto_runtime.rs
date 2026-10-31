//! Exact SHAKE/AES table borrows for immutable complete-schedule replay.
//! Every original-backed cell is initialized before admission.
//! No temporary packet vector, erased owning union, or request-wide executor
//! participates in this path.
use super::super::{
    closed_plan::{CryptoFamily, CryptoOutput, ProducerRoute, StepDispatch, ValidatedCompleteInventory},
    fresh_generation::case_lifetime::{CaseOwnerSlot, CaseOwnerTable, CaseRetirementState},
    metadata_tables::crypto::*,
    metadata_planning::{ProducerCounts, ProducerFamily, SourceMetadataPlanningPlan},
};
use crate::{
    execution::workflow_resources::{PhaseBinding, SlotId, WorkflowAdmission, WorkflowError, WorkflowPlanning},
    graph_crypto::{OuterProofCache, ProofCache},
    proof_cache_policy::ProofCachePolicy,
};
use std::cell::{Ref, RefCell, RefMut};
use std::time::Instant;

mod shake;
mod aes;
pub(crate) use shake::ShakeRuntime;
pub(crate) use aes::AesRuntime;

type Result<T> = core::result::Result<T, WorkflowError>;

struct InitGuard<'run, 'context> {
    planning: &'run mut WorkflowPlanning<'context>,
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

fn slot<'table, 'case, T>(table: &'table CaseOwnerTable<'case, T>, ordinal: usize)
    -> Result<&'table CaseOwnerSlot<'case, T>>
{
    table.slots().get(ordinal).ok_or(WorkflowError::Slot)
}

fn value<'table, T>(slot: &'table CaseOwnerSlot<'_, T>) -> Result<&'table T> {
    if !slot.is_initialized() { return Err(WorkflowError::Empty); }
    slot.get().map_err(|_| WorkflowError::Sequence)
}

fn cell<'table, T, E>(table: &'table CaseOwnerTable<'_, RefCell<Option<core::result::Result<T, E>>>>,
    ordinal: usize) -> Result<&'table RefCell<Option<core::result::Result<T, E>>>>
{
    value(slot(table, ordinal)?)
}

fn ready<T, E>(value: &Option<core::result::Result<T, E>>) -> Result<&T> {
    value.as_ref().ok_or(WorkflowError::Empty)?.as_ref().map_err(|_| WorkflowError::Poisoned)
}

fn empty<T, E>(value: &Option<core::result::Result<T, E>>) -> Result<()> {
    if value.is_some() { return Err(WorkflowError::SlotBusy); }
    Ok(())
}

/// Called only after acquiring all input/output borrows and checking every
/// input. Even an unexpected refusal leaves the complete original Err in place.
fn take_ready<T, E>(value: &mut Option<core::result::Result<T, E>>) -> Result<T> {
    match value.take() {
        Some(Ok(output)) => Ok(output),
        Some(Err(error)) => { *value = Some(Err(error)); Err(WorkflowError::Poisoned) }
        None => Err(WorkflowError::Empty),
    }
}

fn read<T, E>(cell: &RefCell<Option<core::result::Result<T, E>>>)
    -> Result<Ref<'_, Option<core::result::Result<T, E>>>>
{
    cell.try_borrow().map_err(|_| WorkflowError::SlotBusy)
}

fn write<T, E>(cell: &RefCell<Option<core::result::Result<T, E>>>)
    -> Result<RefMut<'_, Option<core::result::Result<T, E>>>>
{
    cell.try_borrow_mut().map_err(|_| WorkflowError::SlotBusy)
}

fn original_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count
        || table.slots().iter().any(|slot| !slot.is_initialized())
    { return Err(WorkflowError::Identity); }
    Ok(())
}

fn uninitialized_table<T>(table: &CaseOwnerTable<'_, T>, case: &CaseRetirementState,
    count: usize) -> Result<()>
{
    if !table.belongs_to_case(case) || table.slots().len() != count
        || table.slots().iter().any(CaseOwnerSlot::is_initialized)
    { return Err(WorkflowError::Identity); }
    Ok(())
}

fn initialize_table<T, E>(table: &CaseOwnerTable<'_, RefCell<Option<core::result::Result<T, E>>>>)
    -> Result<()>
{
    for slot in table.slots() {
        slot.install(RefCell::new(None)).map_err(|_| WorkflowError::Sequence)?;
    }
    Ok(())
}

fn empty_table<T, E>(table: &CaseOwnerTable<'_, RefCell<Option<core::result::Result<T, E>>>>,
    case: &CaseRetirementState, count: usize) -> Result<()>
{
    original_table(table, case, count)?;
    for slot in table.slots() { empty(&*read(value(slot)?)?)?; }
    Ok(())
}

fn route(dispatch: &StepDispatch, family: CryptoFamily) -> Result<(usize, usize, CryptoOutput)> {
    match dispatch.producer() {
        ProducerRoute::Crypto { family: actual, request, step, output } if actual == family =>
            Ok((request, step, output)),
        _ => Err(WorkflowError::Identity),
    }
}

fn input(dispatch: &StepDispatch, index: usize, family: CryptoFamily, request: usize)
    -> Result<(usize, CryptoOutput)>
{
    match dispatch.inputs().get(index).copied().flatten() {
        Some(ProducerRoute::Crypto { family: actual, request: member, step, output })
            if actual == family && member == request => Ok((step, output)),
        _ => Err(WorkflowError::Identity),
    }
}

fn input_shape(dispatch: &StepDispatch, count: usize, consumed: usize) -> Result<()> {
    if dispatch.inputs().len() != count || dispatch.consume_count() != consumed {
        return Err(WorkflowError::Sequence);
    }
    Ok(())
}

fn fresh_caches(native: &ProofCache, outer: &OuterProofCache) -> Result<()> {
    if native.policy() != ProofCachePolicy::FreshOnly || outer.policy() != ProofCachePolicy::FreshOnly {
        return Err(WorkflowError::Policy);
    }
    Ok(())
}

fn plus(total: &mut usize, count: usize) -> Result<()> {
    *total = total.checked_add(count).ok_or(WorkflowError::Overflow)?;
    Ok(())
}

fn same_binding(actual: PhaseBinding, expected: PhaseBinding) -> Result<()> {
    if actual != expected { return Err(WorkflowError::Identity); }
    Ok(())
}

/// Check the actual original before it can leave its source cell. The shared
/// helper authenticates the route's unique prior producer and sealed input slot.
fn original_input(binding: PhaseBinding, slot: SlotId,
    inventory: &ValidatedCompleteInventory<'_, '_>, closed_ordinal: usize,
    input_index: usize) -> Result<()>
{
    let (expected_binding, expected_slot) = super::runtime_inputs::input_edge(
        inventory, closed_ordinal, input_index)?;
    if binding != expected_binding || slot != expected_slot { return Err(WorkflowError::Identity); }
    Ok(())
}

/// Fixed caller/borrow/result shells, in addition to actual immutable request
/// originals and concrete CaseOwnerTables. The coordinator adds this once to
/// the metadata original retained in WorkflowAdmission throughout execution.
pub(crate) fn retained_requirements() -> Result<crate::execution::retained_resources::Requirements> {
    use crate::execution::retained_resources::{Bytes, Category, Requirements};
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(forwarding_host_bytes()?).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

fn forwarding_host_bytes() -> Result<usize> {
    use core::mem::size_of;
    let fixed = [
        size_of::<DriverGuard<'static, 'static, 'static>>(), size_of::<Result<()>>(),
        size_of::<InitGuard<'static, 'static>>(),
        size_of::<Result<PhaseBinding>>(), size_of::<Result<(usize, usize, CryptoOutput)>>(),
        size_of::<Result<(usize, CryptoOutput)>>(), size_of::<StepDispatch>(),
        size_of::<SlotId>(), size_of::<Result<(PhaseBinding, SlotId)>>(),
        size_of::<bool>(), size_of::<ProducerCounts>(),
        size_of::<Instant>(), size_of::<[usize; 4]>(), size_of::<WorkflowError>(),
        size_of::<crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError>(),
        size_of::<core::result::Result<(), crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError>>(),
        size_of::<std::cell::BorrowError>(), size_of::<std::cell::BorrowMutError>(),
    ].into_iter().try_fold(0usize, |sum, part|
        sum.checked_add(part.checked_mul(8).ok_or(WorkflowError::Overflow)?).ok_or(WorkflowError::Overflow))?;
    fixed.checked_add(shake::forwarding_host_bytes()?).ok_or(WorkflowError::Overflow)?
        .checked_add(aes::forwarding_host_bytes()?).ok_or(WorkflowError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Bytes, Category, Ledger, Requirements, WorkerAllowance};

    #[test]
    fn failed_producer_peek_and_take_preserve_the_original_error_owner() {
        let ledger = Ledger::new(WorkerAllowance { host: 4096, device: 0 });
        let requirement = Requirements::single(Category::Report, Bytes { host: 512, device: 0 });
        let original = ledger.admit_phase(requirement).unwrap();
        let mut slot: Option<core::result::Result<(), _>> = Some(Err(original));
        assert!(matches!(ready(&slot), Err(WorkflowError::Poisoned)));
        assert!(matches!(take_ready(&mut slot), Err(WorkflowError::Poisoned)));
        assert!(slot.as_ref().unwrap().as_ref().unwrap_err().belongs_to(&ledger));
        assert_eq!(ledger.snapshot().current, Bytes { host: 512, device: 0 });
        drop(slot);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn occupied_output_and_conflicting_borrow_leave_owned_payload_in_place() {
        let ledger = Ledger::new(WorkerAllowance { host: 4096, device: 0 });
        let original = ledger.admit_phase(Requirements::single(Category::Report,
            Bytes { host: 512, device: 0 })).unwrap();
        let slot = RefCell::new(Some(Ok::<_, WorkflowError>(original)));
        let shared = read(&slot).unwrap();
        assert!(matches!(empty(&shared), Err(WorkflowError::SlotBusy)));
        assert!(matches!(write(&slot), Err(WorkflowError::SlotBusy)));
        assert_eq!(ledger.snapshot().current, Bytes { host: 512, device: 0 });
        drop(shared);
        let owner = take_ready(&mut *write(&slot).unwrap()).unwrap();
        assert!(owner.belongs_to(&ledger));
        drop(owner);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
