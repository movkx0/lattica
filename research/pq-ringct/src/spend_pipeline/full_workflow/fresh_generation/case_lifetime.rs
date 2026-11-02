//! Whole-case owners survive every exit until exact workflow cleanup seals.
//!
//! Slots must contain actual owning values/tables, never substitute borrowed
//! references. Dependency layers are declared separately so later layers may
//! borrow stable earlier slots without making a self-referential container.
use super::{FreshGenerationBatch, FreshGenerationError, Result, source, combine};
use crate::execution::{
    generation_terminal::planning_startup::{FreshPlanningContext, PlanningCleanupReceipt},
    retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    workflow_resources::WorkflowCompletionReceipt,
};
use crate::spend_pipeline::full_workflow::{ClosedWorkflowPlan, ClosureError};
use std::cell::{Cell, OnceCell, RefCell};
use core::mem::size_of;
mod metadata_source;
mod metadata_owner;
pub(crate) use metadata_owner::MetadataOwner;
mod metadata_seal;
mod runtime_identity;
mod planning_residual;
mod metadata_original;
mod metadata_table;
mod bootstrap_slots;
pub(crate) use bootstrap_slots::FixedCaseOwnerSlots;
pub(crate) use metadata_table::{CaseOwnerTable, CaseOwnerTableFailure};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Prepared, Armed, Sealed, Completed, Finalizing, Poisoned }

pub(crate) struct CaseRetirementState {
    state: Cell<State>,
    ledger: Ledger,
    generation_session: u64,
    #[cfg(test)]
    fixture_context: Option<*const crate::execution::ProvingContext>,
    transactions: usize,
    batch_identity: Cell<*const ()>,
    sealed_plan: Cell<*const ()>,
    sealed_context: Cell<*const ()>,
    sealed_source: Cell<([u8; 32], [u8; 32])>,
    batch_original: RefCell<Option<Reservation>>,
    planning_original: RefCell<Option<Reservation>>,
    planning_residual_issued: Cell<bool>,
    planning_residual: Cell<Option<Reservation>>,
    original: Option<Reservation>,
}

/// Preclaimed stable slot; the backing original follows the actual owner.
pub(crate) struct CaseOwnerSlot<'case, T> {
    owner: OnceCell<T>,
    state: &'case CaseRetirementState,
    original: Option<Reservation>,
    // Table slots cannot escape their frozen Vec. Their table keeps the
    // shared sequential install/destruction frames alive, including unwind.
    shared_table_frames: bool,
}

fn frames(parts: &[usize]) -> Result<Requirements> {
    let bytes = parts.iter().try_fold(0usize, |sum, part| sum.checked_add(*part))
        .and_then(|sum| sum.checked_mul(8)).ok_or_else(|| source("case owner frame overflow"))?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(bytes).map_err(|_| source("case owner census width"))?, device: 0,
    }))
}

fn state_requirements() -> Result<Requirements> {
    frames(&[size_of::<CaseRetirementState>(), size_of::<Result<CaseRetirementState>>(),
        size_of::<Ledger>(), size_of::<Requirements>(), size_of::<Reservation>(),
        size_of::<Result<()>>(), size_of::<[Bytes; 4]>(),
        size_of::<Cell<Option<Reservation>>>(), size_of::<Option<Reservation>>(),
        size_of::<Option<&CaseRetirementState>>(), size_of::<Cell<bool>>(),
        size_of::<[&Reservation; 2]>(), size_of::<[Requirements; 2]>()])
}

fn slot_requirements<T>() -> Result<Requirements> {
    frames(&[size_of::<CaseOwnerSlot<'static, T>>(),
        size_of::<Result<CaseOwnerSlot<'static, T>>>(), size_of::<Result<T>>(),
        size_of::<core::result::Result<CaseOwnerSlot<'static, T>,
            (FreshGenerationError, Reservation)>>(),
        size_of::<(FreshGenerationError, Reservation)>(), size_of::<Result<()>>(),
        size_of::<Requirements>(), size_of::<Reservation>()])
}

impl CaseRetirementState {
    /// Check pristine generation first, then claim precisely the state,
    /// batch slot, and planning-result slot. Startup checks their exact sum.
    pub(crate) fn prepare<const N: usize>(batch: &FreshGenerationBatch<N>) -> Result<Self> {
        batch.original_enclosing_bytes()?;
        if batch.planning_started.get() { return Err(source("case already entered planning")); }
        let state = state_requirements()?;
        let slot = slot_requirements::<FreshGenerationBatch<N>>()?;
        let planning = slot_requirements::<Result<FreshPlanningContext<'static>>>()?;
        let mut original = batch.ledger.admit_phase(combine(combine(state, slot)?, planning)?)
            .map_err(|_| source("case owner backing admission failed"))?;
        let batch_original = original.split(slot).map_err(|_| source("case batch split failed"))?;
        let planning_original = original.split(planning).map_err(|_| source("case planning split failed"))?;
        if original.requirements() != state { return Err(source("case state original mismatch")); }
        Ok(Self {
            state: Cell::new(State::Prepared), ledger: batch.ledger.clone(),
            generation_session: batch.terminal.session_id(), transactions: N,
            #[cfg(test)] fixture_context: None,
            batch_identity: Cell::new(core::ptr::null()),
            sealed_plan: Cell::new(core::ptr::null()),
            sealed_context: Cell::new(core::ptr::null()),
            sealed_source: Cell::new(([0; 32], [0; 32])),
            batch_original: RefCell::new(Some(batch_original)),
            planning_original: RefCell::new(Some(planning_original)),
            planning_residual_issued: Cell::new(false), planning_residual: Cell::new(None),
            original: Some(original),
        })
    }

    pub(crate) fn install_batch<const N: usize>(&self, batch: FreshGenerationBatch<N>)
        -> Result<CaseOwnerSlot<'_, FreshGenerationBatch<N>>>
    {
        if self.state.get() != State::Prepared || self.transactions != N
            || self.generation_session != batch.terminal.session_id()
            || !batch.terminal.belongs_to(&self.ledger)
        { return Err(source("case batch does not match generation")); }
        let original = self.batch_original.borrow_mut().take()
            .ok_or_else(|| source("case batch slot already issued"))?;
        let slot = CaseOwnerSlot { shared_table_frames: false, owner: OnceCell::new(), state: self, original: Some(original) };
        slot.install(batch)?;
        Ok(slot)
    }

    /// Claim before producing T or allocating its owning table. Store the
    /// full Result<T,E> when E may own claims/payloads; inspect the installed
    /// result by borrowing, without a `?` before installation. Payload and
    /// table allocations need their own existing census/originals as well.
    pub(crate) fn preclaim<T>(&self) -> Result<CaseOwnerSlot<'_, T>> {
        if self.state.get() != State::Armed { return Err(source("case owner slot outside active case")); }
        let original = self.ledger.admit_phase(slot_requirements::<T>()?)
            .map_err(|_| source("case owner slot admission failed"))?;
        Ok(CaseOwnerSlot { shared_table_frames: false, owner: OnceCell::new(), state: self, original: Some(original) })
    }

    fn retaining(&self) -> bool { matches!(self.state.get(), State::Armed | State::Sealed | State::Finalizing | State::Poisoned) }

    /// Freeze the actual guarded closed plan and all owner-slot admission
    /// before proof zero. Already preclaimed result slots may be populated
    /// during execution; no new case-owner backing is admitted after this.
    pub(crate) fn seal<const N: usize>(&self,
        batch_slot: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>,
        planning: &FreshPlanningContext<'_>,
        plan_slot: &CaseOwnerSlot<'_, core::result::Result<ClosedWorkflowPlan<'_>, ClosureError>>,
    ) -> Result<()> {
        let batch = batch_slot.get()?;
        let closed = plan_slot.get()?.as_ref().map_err(|_| source("case cannot seal a refused plan"))?;
        let original = plan_slot.original.as_ref().ok_or_else(|| source("missing closed plan slot original"))?;
        if self.state.get() != State::Armed || !core::ptr::eq(batch_slot.state, self)
            || !core::ptr::eq(plan_slot.state, self)
            || self.batch_identity.get() != batch as *const FreshGenerationBatch<N> as *const ()
            || self.transactions != N || self.generation_session != batch.terminal.session_id()
            || !batch.terminal.belongs_to(&self.ledger)
            || !planning.belongs_to_generation(&batch.terminal)
            || !core::ptr::eq(closed.context(), planning.context())
            || !original.belongs_to(&self.ledger) || !closed.belongs_to(&self.ledger)
            || !closed.fresh_only()
        { return Err(source("case closed-plan identity mismatch")); }
        self.sealed_plan.set(closed as *const ClosedWorkflowPlan<'_> as *const ());
        self.sealed_context.set(closed.context() as *const _ as *const ());
        self.sealed_source.set((closed.source_fingerprint(), closed.compiled_source_fingerprint()));
        self.state.set(State::Sealed);
        Ok(())
    }

    /// The only production disarm. Neither a numeric receipt nor a prior
    /// phase's retirement can release these enclosing owners.
    pub(crate) fn complete<const N: usize>(&self,
        batch_slot: &CaseOwnerSlot<'_, FreshGenerationBatch<N>>,
        planning: &FreshPlanningContext<'_>, closed: &ClosedWorkflowPlan<'_>,
        completed: &WorkflowCompletionReceipt<'_>, cleanup: &PlanningCleanupReceipt<'_, '_>,
    ) -> Result<()> {
        let batch = batch_slot.get()?;
        if self.state.get() != State::Sealed || !core::ptr::eq(batch_slot.state, self)
            || self.batch_identity.get() != batch as *const FreshGenerationBatch<N> as *const ()
            || self.transactions != N || self.generation_session != batch.terminal.session_id()
            || !batch.terminal.belongs_to(&self.ledger)
            || !planning.belongs_to_generation(&batch.terminal)
            || !cleanup.belongs_to(planning) || !cleanup.belongs_to_generation(&batch.terminal)
            || !completed.matches_plan(closed)
            || self.sealed_plan.get() != closed as *const ClosedWorkflowPlan<'_> as *const ()
            || self.sealed_context.get() != planning.context() as *const _ as *const ()
            || self.sealed_source.get() != (closed.source_fingerprint(), closed.compiled_source_fingerprint())
        { return Err(source("complete case cleanup identity mismatch")); }
        completed.validate_for(planning.context(), &self.ledger)
            .map_err(|_| source("case lacks authenticated workflow completion"))?;
        self.state.set(State::Completed);
        Ok(())
    }
}

impl<const N: usize> CaseOwnerSlot<'_, FreshGenerationBatch<N>> {
    /// Arms at the batch's stable address before any source-context startup,
    /// including an error or unwind from that startup.
    pub(crate) fn begin_planning(&self) -> Result<CaseOwnerSlot<'_, Result<FreshPlanningContext<'_>>>> {
        let batch = self.get()?;
        if self.state.state.get() != State::Prepared || batch.planning_started.get()
            || self.state.transactions != N
            || self.state.generation_session != batch.terminal.session_id()
            || !batch.terminal.belongs_to(&self.state.ledger)
            || self.state.batch_original.borrow().is_some()
        { return Err(source("case startup identity mismatch")); }
        let state_original = self.state.original.as_ref().ok_or_else(|| source("missing case state original"))?;
        let slot_original = self.original.as_ref().ok_or_else(|| source("missing case batch original"))?;
        let planning_claim = self.state.planning_original.borrow();
        let planning_original = planning_claim.as_ref().ok_or_else(|| source("missing case planning original"))?;
        if !state_original.belongs_to(&batch.ledger) || !slot_original.belongs_to(&batch.ledger)
            || !planning_original.belongs_to(&batch.ledger)
            || state_original.requirements() != state_requirements()?
            || slot_original.requirements() != slot_requirements::<FreshGenerationBatch<N>>()?
            || planning_original.requirements() != slot_requirements::<Result<FreshPlanningContext<'static>>>()?
        { return Err(source("case startup backing mismatch")); }
        let owners = combine(combine(state_original.requirements(), slot_original.requirements())?, planning_original.requirements())?
            .total().map_err(|_| source("case owner total overflow"))?;
        let generated = batch.owned_generation_bytes()?;
        let exact = Bytes {
            host: generated.host.checked_add(owners.host)
                .ok_or_else(|| source("case startup host total overflow"))?,
            device: generated.device.checked_add(owners.device)
                .ok_or_else(|| source("case startup device total overflow"))?,
        };
        if exact != batch.ledger.snapshot().current {
            return Err(source("case startup ledger has unrelated originals"));
        }
        // End the RefCell read before moving the original into the stable
        // planning-result slot. This slot is armed before invoking startup.
        drop(planning_claim);
        let original = self.state.planning_original.borrow_mut().take()
            .ok_or_else(|| source("case planning slot already issued"))?;
        let slot = CaseOwnerSlot { shared_table_frames: false, owner: OnceCell::new(), state: self.state, original: Some(original) };
        self.state.batch_identity.set(batch as *const FreshGenerationBatch<N> as *const ());
        self.state.state.set(State::Armed);
        slot.install(batch.start_planning())?;
        Ok(slot)
    }
}

impl<T> CaseOwnerSlot<'_, T> {
    pub(crate) fn install(&self, owner: T) -> Result<()> {
        if self.state.state.get() == State::Completed {
            return Err(source("case owner installation after completion"));
        }
        if matches!(self.state.state.get(), State::Finalizing | State::Poisoned) {
            core::mem::forget(owner);
            return Err(source("case owner installation after failure or finalization"));
        }
        if let Err(owner) = self.owner.set(owner) {
            if self.state.retaining() {
                self.state.state.set(State::Poisoned);
                core::mem::forget(owner);
            }
            return Err(source("case owner slot already initialized"));
        }
        Ok(())
    }
    pub(crate) fn get(&self) -> Result<&T> {
        self.owner.get().ok_or_else(|| source("case owner slot is empty"))
    }

    /// Authenticate the installed owner before moving it out of its slot.
    /// Taking this receiver by value would move the inner context before its
    /// address check. This private operation never returns an extracted owner.
    fn finish_in_place(
        &mut self,
        identity: impl FnOnce(&T) -> Result<*const ()>,
        finish: impl FnOnce(T) -> Result<()>,
    ) -> Result<()> {
        if self.state.state.get() != State::Completed {
            return Err(source("case planning owner lacks completed cleanup"));
        }
        self.state.state.set(State::Finalizing);
        if self.state.sealed_context.get() != identity(self.get()?)? {
            return Err(source("case planning finish context mismatch"));
        }
        // Keep the slot original through finish, including failure or unwind.
        let owner = self.owner.take().ok_or_else(|| source("case planning slot empty"))?;
        match finish(owner) {
            Ok(()) => { self.state.state.set(State::Completed); Ok(()) }
            Err(error) => {
                self.state.state.set(State::Poisoned);
                Err(error)
            }
        }
    }
}

impl CaseOwnerSlot<'_, Result<FreshPlanningContext<'_>>> {
    /// Drop dependent plan/receipt borrows first. No generic extraction API
    /// can release slot backing while an extracted owning table survives.
    pub(crate) fn finish_planning(&mut self) -> Result<()> {
        self.finish_in_place(
            |owner| {
                let context = owner.as_ref().map_err(|_| source("case planning startup failed"))?;
                Ok(context.context() as *const _ as *const ())
            },
            |owner| owner?.finish().map_err(FreshGenerationError::Context),
        )
    }
}

impl<T> Drop for CaseOwnerSlot<'_, T> {
    fn drop(&mut self) {
        if self.state.retaining() {
            if let Some(owner) = self.owner.take() { core::mem::forget(owner); }
            if let Some(original) = self.original.take() { core::mem::forget(original); }
        }
    }
}
impl Drop for CaseRetirementState {
    fn drop(&mut self) {
        if self.retaining() {
            if let Some(original) = self.planning_residual.get_mut().take() { core::mem::forget(original); }
            if let Some(original) = self.original.take() { core::mem::forget(original); }
            if let Some(original) = self.batch_original.get_mut().take() { core::mem::forget(original); }
            if let Some(original) = self.planning_original.get_mut().take() { core::mem::forget(original); }
        }
    }
}

#[cfg(test)]
mod tests;
