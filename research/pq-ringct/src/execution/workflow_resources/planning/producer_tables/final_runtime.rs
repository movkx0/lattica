//! Stable final root and the exact bounded constructor refusal.
use super::*;
impl WorkflowPlanning<'_> {
    pub(crate) fn metadata_final_root<'case, 'a>(&mut self, plan: &SourceMetadataPlanningPlan,
        case: &'case CaseRetirementState) -> TableTransferResult<'case, final_aggregation::FinalOuterResult<'a>>
    { self.transfer_metadata_table(plan, case, 115, TableCount::One) }
    pub(crate) fn metadata_final_driver_failure<'case>(&mut self, plan: &SourceMetadataPlanningPlan,
        case: &'case CaseRetirementState) -> TableTransferResult<'case, RefCell<Option<crate::ordered_aggregation::owned_final::FinalFailure>>>
    { self.transfer_metadata_table(plan, case, 116, TableCount::One) }
}
pub(super) fn forwarding_requirements() -> Result<Requirements, WorkflowError> {
    let mut total = transfer_frames::<final_aggregation::FinalOuterResult<'static>>()?;
    add_frames(&mut total, transfer_frames::<RefCell<Option<crate::ordered_aggregation::owned_final::FinalFailure>>>()?)?;
    Ok(total)
}
