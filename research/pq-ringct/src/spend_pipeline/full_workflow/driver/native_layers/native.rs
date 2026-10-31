use super::*;

/// Fill native plans in member order and original request/batch order.
pub(crate) fn fill_native_layer<'case, 'a>(
    planning: &mut WorkflowPlanning<'_>, inventory: &SourceMetadataPlanningPlan<'a>,
    case: &CaseRetirementState, tables: NativePlanTables<'_, 'case, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_native_layer");
    run_layer(planning, inventory, case, |planning| {
        tables.validate_empty(inventory, case)?;
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            macro_rules! produce {
                ($field:ident, $family:ident, $method:ident, $source:expr) => {{
                    stage.source(ProducerFamily::$family, $source);
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    stage.destination(ordinal);
                    let slot = tables.$field.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                    stage.action(DriverAction::Derive);
                    let result = planning.$method(inventory, member, $source)?;
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
                    Some(ProducerFamily::Affine) => produce!(affine, Affine, derive_metadata_affine_native, source_ordinal),
                    Some(ProducerFamily::Ntt) => produce!(ntt, Ntt, derive_metadata_ntt_native, source_ordinal),
                    Some(ProducerFamily::Mul) => produce!(mul, Mul, derive_metadata_mul_native, source_ordinal),
                    Some(ProducerFamily::GBound) => produce!(g_bound, GBound, derive_metadata_g_bound_native, source_ordinal),
                    Some(ProducerFamily::Permutation) => produce!(permutation, Permutation, derive_metadata_permutation_native, source_ordinal),
                    Some(ProducerFamily::LinearMap) => produce!(linear_map, LinearMap, derive_metadata_linear_map_native, source_ordinal),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
