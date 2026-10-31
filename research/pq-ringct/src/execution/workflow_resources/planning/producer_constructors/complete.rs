//! Original complete-result slot transfer and the authenticated final closure.
use super::*;
use crate::{execution::generation_terminal::planning_startup::FreshPlanningContext,
    graph_crypto::{OuterProofCache, ProofCache},
    spend_pipeline::full_workflow::{ClosedWorkflowPlan, ClosureError,
        closed_plan::{CompleteProducerTables, CompleteScheduleResult, ParentTables,
            complete_metadata_requirements, complete_slot_requirements, complete_inspection_requirements},
        fresh_generation::{FreshGenerationError,
            case_lifetime::{CaseOwnerSlot, CaseRetirementState}}}};

pub(crate) enum CompleteSlotFailure {
    Admission(WorkflowError),
    Transfer(FreshGenerationError, Reservation),
}
pub(crate) type CompleteSlotResult<'case, 'a> =
    Result<CaseOwnerSlot<'case, CompleteScheduleResult<'a>>, CompleteSlotFailure>;

pub(super) fn requirements() -> Result<Requirements, WorkflowError> {
    scratch_frames(&[size_of::<CompleteSlotResult<'static, 'static>>(),
        size_of::<CompleteSlotFailure>(), size_of::<CompleteScheduleResult<'static>>(),
        size_of::<Result<CompleteScheduleResult<'static>, WorkflowError>>(),
        size_of::<Result<CaseOwnerSlot<'static, CompleteScheduleResult<'static>>, (FreshGenerationError, Reservation)>>(),
        size_of::<Result<&CaseRetirementState, FreshGenerationError>>(),
        size_of::<ParentTables<'static>>(), size_of::<Result<ParentTables<'static>, ClosureError>>(),
        size_of::<CompleteProducerTables<'static>>(), size_of::<[Requirements; 8]>(),
        size_of::<[Reservation; 2]>(), size_of::<Result<Requirements, ClosureError>>(),
        size_of::<Result<Requirements, WorkflowError>>(),
        size_of::<Result<Reservation, crate::execution::retained_resources::Error>>(),
        super::super::PlanningAdmissionTransition::frame_bytes()?,
        size_of::<[usize; 8]>(), size_of::<[&SourceMetadataPlanningPlan<'static>; 8]>()])
}

impl WorkflowPlanning<'_> {
    /// The exact closed Result slot is funded by the installed envelope; this
    /// never calls the legacy case preclaim method or admits another original.
    pub(crate) fn metadata_complete_slot<'case, 'a>(&mut self,
        plan: &SourceMetadataPlanningPlan<'_>, case: &'case CaseRetirementState)
        -> CompleteSlotResult<'case, 'a>
    {
        self.begin_metadata_table(plan, case, 111).map_err(CompleteSlotFailure::Admission)?;
        let required = complete_slot_requirements()
            .map_err(|_| CompleteSlotFailure::Admission(WorkflowError::Planning))?;
        if !super::super::super::types::contains(self.scratch.requirements(), requirements()
            .map_err(CompleteSlotFailure::Admission)?) {
            return Err(CompleteSlotFailure::Admission(WorkflowError::Planning));
        }
        let original = self.original.split(required)
            .map_err(|error| CompleteSlotFailure::Admission(error.into()))?;
        match case.preclaim_from_original::<CompleteScheduleResult<'a>>(original) {
            Ok(slot) => { self.finish_metadata_table_success(); Ok(slot) }
            Err((error, original)) => Err(CompleteSlotFailure::Transfer(error, original)),
        }
    }

    /// Fixed borrowed parent adapters are constructed under the admitted
    /// inspection scratch. They carry no new proof owner or admission token.
    pub(crate) fn plan_metadata_parent_tables<'a>(&mut self,
        plan: &'a SourceMetadataPlanningPlan<'a>) -> Result<ParentTables<'a>, ClosureError>
    {
        let checked = self.check_metadata(plan).map_err(|_| ClosureError::Identity);
        self.failed = true;
        checked?;
        let required = sum(complete_inspection_requirements().map_err(|_| ClosureError::Resource)?,
            requirements().map_err(|_| ClosureError::Resource)?).map_err(|_| ClosureError::Resource)?;
        if !super::super::super::types::contains(self.scratch.requirements(), required) {
            return Err(ClosureError::Resource);
        }
        let result = ParentTables::new(plan, &self.scratch);
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        result
    }

    pub(crate) fn derive_metadata_complete<'a>(&mut self,
        plan: &'a SourceMetadataPlanningPlan<'a>,
        planning_slot: &CaseOwnerSlot<'_, Result<FreshPlanningContext<'_>, FreshGenerationError>>,
        tables: &'a CompleteProducerTables<'a>, native_cache: &'a ProofCache,
        outer_cache: &'a OuterProofCache)
        -> Result<CompleteScheduleResult<'a>, WorkflowError>
    {
        self.begin_metadata_final(plan, 2)?;
        let case = planning_slot.metadata_case_state(plan.scope(), self.capability.ledger())
            .map_err(|_| WorkflowError::Identity)?;
        if !self.metadata_case_matches(case) { return Err(WorkflowError::Identity); }
        let scratch = sum(complete_inspection_requirements().map_err(|_| WorkflowError::Planning)?,
            requirements()?)?;
        if !super::super::super::types::contains(self.scratch.requirements(), scratch) {
            return Err(WorkflowError::Planning);
        }
        let required = complete_metadata_requirements(plan).map_err(|_| WorkflowError::Planning)?;
        let transition = super::super::PlanningAdmissionTransition::new(&self.scratch, &self.capability,
            plan, case, self.producer_metadata.as_ref().ok_or(WorkflowError::Identity)?, &self.original)?;
        let original = self.original.split(required)?;
        let result = ClosedWorkflowPlan::derive_complete_pre_reserved(plan, planning_slot, tables,
            original, &self.scratch, &transition, native_cache, outer_cache);
        drop(transition);
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }
}
