//! One-way driver failure and exact sealed-case/step checks. These helpers
//! never admit storage, issue phases, or reset a failed execution.
use super::*;
use crate::spend_pipeline::full_workflow::{
    closed_plan::{StepDispatch, ValidatedCompleteInventory},
    fresh_generation::case_lifetime::CaseRetirementState,
};
use core::mem::size_of;

/// Fixed caller/controller frames remain inside _planning_original throughout
/// execution, then move with that exact residual to the outer case until all
/// nested caller scopes end. Dynamic allocations retain their phase claims.
pub(crate) fn driver_retained_requirements() -> Result<Requirements, WorkflowError> {
    let bytes = [
        super::verification_receipts::frame_bytes()?,
        size_of::<StepDispatch>(), size_of::<Result<StepDispatch, WorkflowError>>(),
        size_of::<ValidatedCompleteInventory<'static, 'static>>(),
        size_of::<Result<(), WorkflowError>>(), size_of::<Result<Requirements, WorkflowError>>(),
        size_of::<[Requirements; 2]>(), size_of::<[&(); 8]>(), size_of::<[usize; 4]>(),
        size_of::<[([u8; 32], [u8; 32]); 4]>(),
    ].into_iter().try_fold(0usize, |sum, n| sum.checked_add(n))
        .and_then(|n| n.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

impl WorkflowAdmission<'_, '_> {
    pub(crate) fn poison_driver(&mut self) {
        self.failed = true;
        self.pool.poison();
    }

    pub(crate) fn validate_driver(&mut self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState) -> Result<(), WorkflowError>
    {
        let checked = (|| {
            if self.failed || self.completed { return Err(WorkflowError::Poisoned); }
            let phase = self.phase.as_ref().ok_or(WorkflowError::Retired)?;
            if !core::ptr::eq(inventory.closed_plan(), self.plan)
                || !case.matches_runtime_plan(self.plan, self.context, phase.ledger())
                || !self._planning_original.belongs_to(phase.ledger())
                || !self._planning_original.is_pinned_to(case)
                || !contains(self._planning_original.requirements(), driver_retained_requirements()?)
            { return Err(WorkflowError::Identity); }
            Ok(())
        })();
        if checked.is_err() { self.poison_driver(); }
        checked
    }

    pub(crate) fn validate_driver_step(&mut self, inventory: &ValidatedCompleteInventory<'_, '_>,
        case: &CaseRetirementState, ordinal: usize) -> Result<StepDispatch, WorkflowError>
    {
        self.validate_driver(inventory, case)?;
        let checked = (|| {
            if ordinal != self.next { return Err(WorkflowError::Sequence); }
            self.plan.dispatch().get(ordinal).copied().ok_or(WorkflowError::Sequence)
        })();
        if checked.is_err() { self.poison_driver(); }
        checked
    }
}
