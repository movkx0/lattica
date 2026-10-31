//! Fixed receipt transport for exact planned and actually completed dispatches.
//! Inventory is never proof credit. Original driver/phase/owner gates are kept.
use super::*;
use crate::execution::report_transport::{self, FixedPayload};
use crate::spend_pipeline::full_workflow::{
    closed_plan::{DispatchVerificationIdentity, ValidatedCompleteInventory, verification_identity_frame_bytes},
    metadata_planning::SourceMetadataPlanningPlan,
    fresh_generation::case_lifetime::CaseRetirementState,
};

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage { Inventory, Attempt, Complete }

#[derive(serde::Serialize)]
struct Entry {
    schema: &'static str,
    stage: Stage,
    session_id: u64,
    identity: DispatchVerificationIdentity,
}
// Scalar enums, fixed arrays and compile-time source-kind strings only.
impl FixedPayload for Entry {}

pub(super) fn frame_bytes() -> Result<usize, WorkflowError> {
    use core::mem::size_of;
    [verification_identity_frame_bytes().map_err(|_| WorkflowError::Planning)?,
        verification_binding_frame_bytes()?, report_transport::required_host_bytes(),
        size_of::<Entry>(), size_of::<Stage>(), size_of::<Option<usize>>(),
        size_of::<Result<DispatchVerificationIdentity, crate::spend_pipeline::full_workflow::ClosureError>>(),
        size_of::<Result<(), report_transport::Error>>(), size_of::<Result<(), WorkflowError>>(),
        size_of::<[&(); 16]>(), size_of::<[usize; 16]>()]
        .into_iter().try_fold(0usize, |sum, part| sum.checked_add(part)).ok_or(WorkflowError::Overflow)
}

impl WorkflowAdmission<'_, '_> {
    fn emit_dispatch_verification(&mut self, inventory: &ValidatedCompleteInventory<'_, '_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState,
        ordinal: usize, stage: Stage) -> Result<(), WorkflowError>
    {
        self.validate_driver(inventory, case)?;
        let checked = (|| {
            if !inventory.matches_metadata(metadata) || !core::ptr::eq(metadata.context(), self.context)
                || self.context.policy() != lattica_prover_p3::proving::Policy::GpuRequired
                || !self.plan.fresh_only()
            { return Err(WorkflowError::Identity); }
            let expected_next = match stage {
                Stage::Inventory => 0,
                Stage::Attempt => ordinal,
                Stage::Complete => ordinal.checked_add(1).ok_or(WorkflowError::Overflow)?,
            };
            if self.next != expected_next { return Err(WorkflowError::Sequence); }
            let identity = inventory.verification_identity(metadata, ordinal).map_err(|_| WorkflowError::Identity)?;
            report_transport::emit(b"owned_dispatch_verification ", &Entry {
                schema: "ringct-owned-dispatch-verification-v1", stage,
                session_id: self.context.session_id, identity,
            }).map_err(|_| WorkflowError::Planning)
        })();
        // Report failures are terminal and preserve the existing failure path.
        // No discarded write, fallback, alternate layout, or dispatch retry.
        if checked.is_err() { self.poison_driver(); }
        checked
    }

    pub(crate) fn emit_verification_inventory(&mut self, inventory: &ValidatedCompleteInventory<'_, '_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<(), WorkflowError>
    {
        for ordinal in 0..inventory.closed_plan().steps().len() {
            self.emit_dispatch_verification(inventory, metadata, case, ordinal, Stage::Inventory)?;
        }
        Ok(())
    }

    pub(crate) fn emit_verification_attempt(&mut self, inventory: &ValidatedCompleteInventory<'_, '_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState, ordinal: usize)
        -> Result<(), WorkflowError>
    {
        self.emit_dispatch_verification(inventory, metadata, case, ordinal, Stage::Attempt)
    }

    pub(crate) fn emit_verification_complete(&mut self, inventory: &ValidatedCompleteInventory<'_, '_>,
        metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState, ordinal: usize)
        -> Result<(), WorkflowError>
    {
        // Concrete execute_step has already installed its original owner and
        // incremented next only after successful phase cleanup. This checked
        // observation cannot advance next or create an owner on its own.
        self.emit_dispatch_verification(inventory, metadata, case, ordinal, Stage::Complete)
    }
}
