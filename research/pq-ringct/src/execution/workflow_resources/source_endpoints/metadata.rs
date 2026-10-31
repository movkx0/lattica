//! Endpoint preparation from the actual case-owned metadata plan. Installation
//! precedes every GPU operation; refusal and unwind cannot drop that owner.
use super::*;
use crate::{
    graph_crypto::{OwnedAesRequestPlan, PairedFailure, Request, RequestDescriptor},
    spend_pipeline::full_workflow::{
        fresh_generation::{FreshGenerationError,
            case_lifetime::{CaseOwnerSlot, CaseRetirementState}},
        metadata_planning::{MetadataMember, ProducerFamily, SourceMetadataPlanningPlan},
        metadata_tables::crypto::{AesPlanResult, AesPlanTable, ShakePlanResult, ShakePlanTable},
    },
};
use core::mem::size_of;
use lattica_prover_p3::proving::operation_storage::RawPreparationReportStorage;

/// Compile-time census: the fixed entry original holds this before the source
/// descriptor asks any metadata/endpoint query to size its later reservations.
/// No runtime query is called to fund its own stack. All values are fixed types;
/// compile-time arithmetic overflow is rejected by Rust.
pub(crate) const METADATA_ENDPOINT_QUERY_FRAME_BYTES: usize = 8 * (
        size_of::<[Requirements; 8]>()
        + size_of::<[Bytes; 4]>()
        + size_of::<[usize; 24]>()
        + size_of::<[bool; 8]>()
        + size_of::<[ProducerFamily; 4]>()
        + size_of::<&mut WorkflowPlanning<'static>>()
        + size_of::<&CaseRetirementState>()
        + size_of::<&SourceMetadataPlanningPlan<'static>>()
        + size_of::<MetadataMember<'static, 'static>>()
        + size_of::<&ShakePlanTable<'static, 'static>>()
        + size_of::<&AesPlanTable<'static, 'static>>()
        + size_of::<&CaseOwnerSlot<'static, ShakePlanResult<'static>>>()
        + size_of::<&CaseOwnerSlot<'static, AesPlanResult<'static>>>()
        + size_of::<Result<&CaseOwnerSlot<'static, ShakePlanResult<'static>>, FreshGenerationError>>()
        + size_of::<Result<&CaseOwnerSlot<'static, AesPlanResult<'static>>, FreshGenerationError>>()
        + size_of::<Result<&ShakePlanResult<'static>, FreshGenerationError>>()
        + size_of::<Result<&AesPlanResult<'static>, FreshGenerationError>>()
        + size_of::<&ShakePlanResult<'static>>()
        + size_of::<&AesPlanResult<'static>>()
        + size_of::<Result<&PairedRequestPlan<'static>, &PairedFailure>>()
        + size_of::<Result<&OwnedAesRequestPlan<'static>, &PairedFailure>>()
        + size_of::<&PairedRequestPlan<'static>>()
        + size_of::<&OwnedAesRequestPlan<'static>>()
        + size_of::<&Request>()
        + size_of::<RequestDescriptor>()
        + size_of::<&crate::graph_tree::GraphContext>()
        + size_of::<Result<(Requirements, Bytes), PairedFailure>>()
        + size_of::<Result<(Requirements, Requirements), WorkflowError>>()
        + size_of::<Result<(), WorkflowError>>()
        + size_of::<Result<(), PairedFailure>>()
        + size_of::<Result<usize, WorkflowError>>()
        + size_of::<Result<u64, WorkflowError>>()
        + size_of::<Result<Requirements, PairedFailure>>()
        + size_of::<RawPreparationReportStorage>()
        + size_of::<Result<RawPreparationReportStorage, lattica_prover_p3::proving::Error>>()
        + size_of::<SourceEndpointAccess<'static>>()
        + size_of::<PhaseLease<'static, 'static>>()
        + size_of::<std::cell::Ref<'static, Reservation>>()
        + size_of::<[usize; 40]>()
);

/// The same query/projection frames coexist in metadata scratch before the
/// additional endpoint phase is admitted. That phase separately owns its full
/// endpoint/report payload and independently charged backend.
pub(in crate::execution::workflow_resources) fn metadata_endpoint_query_requirements()
    -> Result<Requirements, WorkflowError>
{
    Ok(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(METADATA_ENDPOINT_QUERY_FRAME_BYTES).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}

impl WorkflowPlanning<'_> {
    pub(crate) fn prepare_metadata_shake_endpoints<'a>(
        &mut self, inventory: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        ordinal: usize, case: &CaseRetirementState, table: &ShakePlanTable<'_, 'a>,
    ) -> Result<(), WorkflowError> {
        // This retains all normal identity/poison checks, allowing only the
        // exact single constructor whose endpoint completion is still pending.
        let position = self.begin_metadata_endpoint(inventory, member, ProducerFamily::Shake, ordinal, case)?;
        if !table.belongs_to_case(case)
            || table.slots().len() != inventory.counts().family(ProducerFamily::Shake)
        { return Err(WorkflowError::Identity); }
        let plan = table.get(position).map_err(|_| WorkflowError::Slot)?
            .get().map_err(|_| WorkflowError::Slot)?.as_ref().map_err(|_| WorkflowError::Planning)?;
        let prepared = member.prepared().get();
        let request = prepared.crypto().requests().get(ordinal).ok_or(WorkflowError::Planning)?;
        if !core::ptr::eq(plan.request(), request) || !matches!(request.descriptor(), RequestDescriptor::Shake(_))
            || plan.graph_context() != prepared.context() || plan.layout() != inventory.scope().layout()
            || !plan.belongs_to(self.capability.ledger())
            || plan.compiled_source_fingerprint() != self.compiled_source
        { return Err(WorkflowError::Identity); }
        self.context.check_legacy_gpu_dispatch().map_err(|_| WorkflowError::Planning)?;
        let (scratch, backend) = plan.endpoint_preparation_requirements().map_err(|_| WorkflowError::Planning)?;
        if self.managed_device != 8 << 30 || backend.device != self.managed_device {
            return Err(WorkflowError::BackendAllowance);
        }
        let bootstrap_device = self.capability.source_bootstrap_device_bytes()?;
        let backend = Bytes { host: backend.host, device: bootstrap_device };
        let (scratch, requirements) = admission_requirements(scratch, backend, bootstrap_device)?;
        // Metadata scratch stays held. Admit every endpoint/report/backend byte
        // additively before allocation; do not borrow credit from that original.
        let phase = self.capability.admit(requirements)?;
        let result = {
            let original = phase.original_for_source()?;
            let access = SourceEndpointAccess { context: self.context,
                ledger: phase.ledger(), held: &original, scratch, backend };
            plan.prepare_endpoints_before_closure(&access).map_err(|_| WorkflowError::Planning)
        };
        // End the operation/report/claim borrows before actual source cleanup.
        // Both refusals leave the actual plan installed and metadata poisoned.
        phase.complete_after_cleanup()?;
        result?;
        self.finish_metadata_endpoint(ProducerFamily::Shake, position)
    }

    pub(crate) fn prepare_metadata_aes_endpoints<'a>(
        &mut self, inventory: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        ordinal: usize, case: &CaseRetirementState, table: &AesPlanTable<'_, 'a>,
    ) -> Result<(), WorkflowError> {
        let position = self.begin_metadata_endpoint(inventory, member, ProducerFamily::Aes, ordinal, case)?;
        if !table.belongs_to_case(case)
            || table.slots().len() != inventory.counts().family(ProducerFamily::Aes)
        { return Err(WorkflowError::Identity); }
        let plan = table.get(position).map_err(|_| WorkflowError::Slot)?
            .get().map_err(|_| WorkflowError::Slot)?.as_ref().map_err(|_| WorkflowError::Planning)?;
        let prepared = member.prepared().get();
        let request = prepared.crypto().requests().get(ordinal).ok_or(WorkflowError::Planning)?;
        if !core::ptr::eq(plan.request(), request) || !matches!(request.descriptor(), RequestDescriptor::Aes(_))
            || plan.graph_context() != prepared.context()
            || !plan.belongs_to(self.capability.ledger())
            || plan.compiled_source_fingerprint() != self.compiled_source
        { return Err(WorkflowError::Identity); }
        self.context.check_legacy_gpu_dispatch().map_err(|_| WorkflowError::Planning)?;
        let (scratch, backend) = plan.endpoint_preparation_requirements().map_err(|_| WorkflowError::Planning)?;
        if self.managed_device != 8 << 30 || backend.device != self.managed_device {
            return Err(WorkflowError::BackendAllowance);
        }
        let bootstrap_device = self.capability.source_bootstrap_device_bytes()?;
        let backend = Bytes { host: backend.host, device: bootstrap_device };
        let (scratch, requirements) = admission_requirements(scratch, backend, bootstrap_device)?;
        let phase = self.capability.admit(requirements)?;
        let result = {
            let original = phase.original_for_source()?;
            let access = SourceEndpointAccess { context: self.context,
                ledger: phase.ledger(), held: &original, scratch, backend };
            plan.prepare_endpoints_before_closure(&access).map_err(|_| WorkflowError::Planning)
        };
        phase.complete_after_cleanup()?;
        result?;
        self.finish_metadata_endpoint(ProducerFamily::Aes, position)
    }
}
