//! Original-backed fixed request counters, populated from actual step reports.
use super::*;

impl WorkflowPlanning<'_> {
    pub(crate) fn metadata_shake_reports<'case>(&mut self, plan: &SourceMetadataPlanningPlan,
        case: &'case CaseRetirementState) -> TableTransferResult<'case, RefCell<crate::graph_crypto::PairedRequestReport>>
    {
        self.transfer_metadata_table(plan, case, 113, TableCount::Family(ProducerFamily::Shake))
    }

    pub(crate) fn metadata_aes_reports<'case>(&mut self, plan: &SourceMetadataPlanningPlan,
        case: &'case CaseRetirementState) -> TableTransferResult<'case, RefCell<crate::graph_crypto::OwnedAesRequestReport>>
    {
        self.transfer_metadata_table(plan, case, 114, TableCount::Family(ProducerFamily::Aes))
    }
}

pub(super) fn forwarding_requirements() -> Result<Requirements, WorkflowError> {
    let mut total = transfer_frames::<RefCell<crate::graph_crypto::PairedRequestReport>>()?;
    add_frames(&mut total, transfer_frames::<RefCell<crate::graph_crypto::OwnedAesRequestReport>>()?)?;
    Ok(total)
}
