//! Named SHAKE/AES construction consumes the installed metadata originals.
//! A failed consuming constructor leaves the workflow permanently poisoned.
use crate::{
    execution::{retained_resources::{Bytes, Category, Requirements, Reservation},
        workflow_resources::{WorkflowPlanning, WorkflowError}},
    graph_crypto::{OwnedAesRequestPlan, PairedRequestPlan, RequestDescriptor},
    graph_tree::GraphContext,
    spend_pipeline::full_workflow::{
        metadata_planning::{MetadataMember, ProducerFamily, SourceMetadataPlanningPlan},
        metadata_tables::crypto::{AesPlanResult, ShakePlanResult},
    },
};
use core::mem::size_of;

type Result<T> = core::result::Result<T, WorkflowError>;

/// Wrapper frames coexist with the inner constructor's entire scratch claim.
pub(super) fn requirements() -> Result<Requirements> {
    let bytes = [
        size_of::<Result<ShakePlanResult<'static>>>(), size_of::<Result<AesPlanResult<'static>>>(),
        size_of::<ShakePlanResult<'static>>(), size_of::<AesPlanResult<'static>>(),
        size_of::<&mut WorkflowPlanning<'static>>(), size_of::<&SourceMetadataPlanningPlan<'static>>(),
        size_of::<MetadataMember<'static, 'static>>(), size_of::<GraphContext>(),
        size_of::<[Requirements; 3]>(), size_of::<Reservation>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<[usize; 4]>(), size_of::<Result<()>>(),
    ].into_iter().try_fold(0usize, |sum, n| sum.checked_add(n))
        .and_then(|n| n.checked_mul(8)).ok_or(WorkflowError::Overflow)?;
    super::sum(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }), crate::execution::workflow_resources::source_endpoints::metadata_endpoint_query_requirements()?)
}

fn with_frames(mut scratch: Requirements) -> Result<Requirements> {
    let frames = requirements()?;
    for category in Category::ALL { scratch.add(category, frames.get(category))?; }
    Ok(scratch)
}

impl WorkflowPlanning<'_> {
    pub(crate) fn derive_metadata_shake<'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        ordinal: usize,
    ) -> Result<ShakePlanResult<'a>> {
        self.begin_metadata_constructor(inventory, member, ProducerFamily::Shake, ordinal, 0)?;
        let prepared = member.prepared().get();
        let request = prepared.crypto().requests().get(ordinal).ok_or(WorkflowError::Planning)?;
        if !matches!(request.descriptor(), RequestDescriptor::Shake(_)) {
            return Err(WorkflowError::Identity);
        }
        let layout = inventory.scope().layout();
        let metadata = PairedRequestPlan::planning_requirements(request, layout)
            .map_err(|_| WorkflowError::Planning)?;
        let scratch = with_frames(PairedRequestPlan::planning_scratch_requirements(request, layout)
            .map_err(|_| WorkflowError::Planning)?)?;
        if !super::super::super::types::contains(self.scratch.requirements(), scratch) {
            return Err(WorkflowError::Planning);
        }
        let original = self.original.split(metadata)?;
        let outcome = PairedRequestPlan::derive_pre_reserved(request, prepared.context().clone(),
            layout, original, &self.scratch, self.capability.ledger())
            .and_then(|plan| plan.with_identity_limits(inventory.scope().identity_limits()));
        if outcome.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(outcome)
    }

    pub(crate) fn derive_metadata_aes<'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        ordinal: usize,
    ) -> Result<AesPlanResult<'a>> {
        self.begin_metadata_constructor(inventory, member, ProducerFamily::Aes, ordinal, 0)?;
        let prepared = member.prepared().get();
        let request = prepared.crypto().requests().get(ordinal).ok_or(WorkflowError::Planning)?;
        if !matches!(request.descriptor(), RequestDescriptor::Aes(_)) {
            return Err(WorkflowError::Identity);
        }
        let metadata = OwnedAesRequestPlan::planning_requirements(request)
            .map_err(|_| WorkflowError::Planning)?;
        let scratch = with_frames(OwnedAesRequestPlan::planning_scratch_requirements(request)
            .map_err(|_| WorkflowError::Planning)?)?;
        if !super::super::super::types::contains(self.scratch.requirements(), scratch) {
            return Err(WorkflowError::Planning);
        }
        let original = self.original.split(metadata)?;
        let outcome = OwnedAesRequestPlan::derive_pre_reserved(request, prepared.context().clone(),
            original, &self.scratch, self.capability.ledger());
        if outcome.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(outcome)
    }
}
