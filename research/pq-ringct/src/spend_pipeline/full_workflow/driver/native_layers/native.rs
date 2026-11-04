use super::*;

/// Fill native plans in member order and original request/batch order.
pub(crate) fn fill_native_layer<'case, 'a>(
    planning: &mut WorkflowPlanning<'_>, inventory: &SourceMetadataPlanningPlan<'a>,
    case: &CaseRetirementState, tables: NativePlanTables<'_, 'case, 'a>,
    stage: &mut DriverStage, early_native: Option<crate::execution::workflow_resources::PreparedNativeBatch<'a>>,
) -> Result<()>
{
    stage.layer("fill_native_layer");
    run_layer(planning, inventory, case, |planning| {
        tables.validate_empty(inventory, case)?;
        planning.prepare_parallel_native(inventory)?;
    let mut numbers = match early_native { Some(numbers) => Some(numbers), None => planning.prepare_native_numbers(inventory)? };
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            macro_rules! produce {
                ($field:ident, $family:ident, $method:ident, $source:expr $(, $numbers:expr)?) => {{
                    stage.source(ProducerFamily::$family, $source);
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    stage.destination(ordinal);
                    let slot = tables.$field.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                    stage.action(DriverAction::Derive);
                    let result = crate::preparation_options::timed_constructor(ProducerFamily::$family as usize,
                        || planning.$method(inventory, member, $source $(, $numbers)?))?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                }};
            }
            for source_ordinal in 0..2 {
                produce!(source, Source, derive_metadata_source_native, source_ordinal);
            }
            for (source_ordinal, request) in member.prepared().get().auxiliary_factory().requests().iter().enumerate() {
                stage.ordinal(source_ordinal);
                match auxiliary_family(request)? {
                    ProducerFamily::Uniform => produce!(uniform, Uniform, derive_metadata_uniform_native, source_ordinal),
                    ProducerFamily::Sparse => produce!(sparse, Sparse, derive_metadata_sparse_native, source_ordinal),
                    ProducerFamily::Transcript => produce!(transcript, Transcript, derive_metadata_transcript_native, source_ordinal),
                    _ => return Err(WorkflowError::Identity),
                }
            }
            for (source_ordinal, batch) in member.prepared().get().algebra().batches().iter().enumerate() {
                stage.ordinal(source_ordinal);
                match algebra_family(batch) {
                    Some(ProducerFamily::Affine) => produce!(affine, Affine, derive_metadata_affine_native_resolved, source_ordinal, numbers.as_mut().map(|n| n.affine(member_ordinal, source_ordinal)).transpose()?.flatten()),
                    Some(ProducerFamily::Ntt) => produce!(ntt, Ntt, derive_metadata_ntt_native_resolved, source_ordinal, numbers.as_mut().map(|n| n.ntt(member_ordinal, source_ordinal)).transpose()?.flatten()),
                    Some(ProducerFamily::Mul) => produce!(mul, Mul, derive_metadata_mul_native_resolved, source_ordinal, numbers.as_mut().map(|n| n.mul(member_ordinal, source_ordinal)).transpose()?.flatten()),
                    Some(ProducerFamily::GBound) => produce!(g_bound, GBound, derive_metadata_g_bound_native_resolved, source_ordinal, numbers.as_mut().map(|n| n.g_bound(member_ordinal, source_ordinal)).transpose()?.flatten()),
                    Some(ProducerFamily::Permutation) => produce!(permutation, Permutation, derive_metadata_permutation_native_resolved, source_ordinal, numbers.as_mut().map(|n| n.permutation(member_ordinal, source_ordinal)).transpose()?.flatten()),
                    Some(ProducerFamily::LinearMap) => produce!(linear_map, LinearMap, derive_metadata_linear_map_native_resolved, source_ordinal, numbers.as_mut().map(|n| n.linear_map(member_ordinal, source_ordinal)).transpose()?.flatten()),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
