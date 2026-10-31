use super::*;

/// Build immutable requests in the exact captured member/request order. These
/// own only public plans; fresh proofs are produced later by named runtimes.
pub(super) fn fill<'case, 'request>(planning: &mut WorkflowPlanning<'_>,
    metadata: &SourceMetadataPlanningPlan<'request>, case: &CaseRetirementState,
    shake: &crypto_tables::ShakePlanTable<'case, 'request>,
    aes: &crypto_tables::AesPlanTable<'case, 'request>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_crypto_plans");
    planning.validate_metadata_driver(metadata, case)?;
    empty_table(shake, case, metadata.counts().family(ProducerFamily::Shake))?;
    empty_table(aes, case, metadata.counts().family(ProducerFamily::Aes))?;
    let mut shake_count = 0usize;
    let mut aes_count = 0usize;
    for member_ordinal in 0..metadata.members().len() {
        stage.member(member_ordinal);
        let member = metadata.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
        for (source_ordinal, request) in member.prepared().get().crypto().requests().iter().enumerate() {
            stage.ordinal(source_ordinal);
            match request.descriptor() {
                RequestDescriptor::Shake(_) => {
                    stage.source(ProducerFamily::Shake, source_ordinal);
                    let ordinal = metadata.source_position(member, ProducerFamily::Shake, source_ordinal)
                        .map_err(|_| WorkflowError::Identity)?;
                    stage.destination(ordinal);
                    if ordinal != shake_count { return Err(WorkflowError::Sequence); }
                    let slot = shake.slots().get(ordinal).ok_or(WorkflowError::Slot)?;
                    stage.action(DriverAction::Derive);
                    let result = planning.derive_metadata_shake(metadata, member, source_ordinal)?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                    stage.action(DriverAction::PrepareEndpoints);
                    planning.prepare_metadata_shake_endpoints(metadata, member, source_ordinal, case, shake)?;
                    shake_count = shake_count.checked_add(1).ok_or(WorkflowError::Overflow)?;
                }
                RequestDescriptor::Aes(_) => {
                    stage.source(ProducerFamily::Aes, source_ordinal);
                    let ordinal = metadata.source_position(member, ProducerFamily::Aes, source_ordinal)
                        .map_err(|_| WorkflowError::Identity)?;
                    stage.destination(ordinal);
                    if ordinal != aes_count { return Err(WorkflowError::Sequence); }
                    let slot = aes.slots().get(ordinal).ok_or(WorkflowError::Slot)?;
                    stage.action(DriverAction::Derive);
                    let result = planning.derive_metadata_aes(metadata, member, source_ordinal)?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                    stage.action(DriverAction::PrepareEndpoints);
                    planning.prepare_metadata_aes_endpoints(metadata, member, source_ordinal, case, aes)?;
                    aes_count = aes_count.checked_add(1).ok_or(WorkflowError::Overflow)?;
                }
            }
        }
    }
    stage.action(DriverAction::Finish);
    if shake_count != shake.slots().len() || aes_count != aes.slots().len() {
        return Err(WorkflowError::Sequence);
    }
    planning.validate_metadata_driver(metadata, case)
}
