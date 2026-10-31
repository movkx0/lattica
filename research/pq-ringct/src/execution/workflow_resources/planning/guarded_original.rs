//! The same planning original follows moves into execution, then the outer
//! case. Dropping an inner controller must not release live caller frames.
use super::super::types::WorkflowError;
use crate::execution::retained_resources::{Error, Ledger, Requirements, Reservation};
#[cfg(not(debug_assertions))]
use crate::spend_pipeline::full_workflow::fresh_generation::case_lifetime::CaseRetirementState;

pub(crate) struct GuardedPlanningOriginal<'case> {
    // Some until Drop; no extraction or general replacement API is exposed.
    original: Option<Reservation>,
    #[cfg(not(debug_assertions))]
    case: Option<&'case CaseRetirementState>,
    _case: core::marker::PhantomData<&'case ()>,
}

impl<'case> GuardedPlanningOriginal<'case> {
    pub(crate) fn new(original: Reservation) -> Self {
        Self { original: Some(original),
            #[cfg(not(debug_assertions))]
            case: None,
            _case: core::marker::PhantomData }
    }

    fn original(&self) -> &Reservation {
        self.original.as_ref().expect("guard owns its original until Drop")
    }

    pub(crate) fn requirements(&self) -> Requirements { self.original().requirements() }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.original().belongs_to(ledger) }
    pub(crate) fn split(&mut self, requirements: Requirements) -> Result<Reservation, Error> {
        self.original.as_mut().expect("guard owns its original until Drop").split(requirements)
    }

    /// Only source-envelope replacement can reach this while the old claim is
    /// exactly empty. The guard and its case identity never move or reset.
    pub(crate) fn replace_depleted(&mut self, replacement: Reservation, ledger: &Ledger)
        -> Result<(), WorkflowError>
    {
        if self.requirements() != Requirements::default()
            || !self.belongs_to(ledger) || !replacement.belongs_to(ledger)
        {
            // An impossible ownership mismatch may not release either claim.
            #[cfg(not(debug_assertions))]
            if let Some(case) = self.case { case.poison_planning_residual(); }
            core::mem::forget(replacement);
            return Err(WorkflowError::Identity);
        }
        self.original = Some(replacement);
        Ok(())
    }

    #[cfg(not(debug_assertions))]
    pub(crate) fn pin_case(&mut self, case: &'case CaseRetirementState) -> Result<(), WorkflowError> {
        if self.case.is_some() { return Err(WorkflowError::Identity); }
        case.claim_planning_residual(self.original()).map_err(|_| WorkflowError::Identity)?;
        self.case = Some(case);
        Ok(())
    }

    #[cfg(not(debug_assertions))]
    pub(crate) fn is_pinned(&self) -> bool { self.case.is_some() }

    #[cfg(not(debug_assertions))]
    pub(crate) fn is_pinned_to(&self, case: &CaseRetirementState) -> bool {
        self.case.is_some_and(|known| core::ptr::eq(known, case))
    }
}

impl Drop for GuardedPlanningOriginal<'_> {
    fn drop(&mut self) {
        #[cfg(not(debug_assertions))]
        if let Some(case) = self.case {
            if let Some(original) = self.original.take() {
                // Allocation-free and infallible. Failure quarantines the
                // exact token; no admission, recredit or retry occurs here.
                case.retain_planning_residual(original);
            }
        }
    }
}
