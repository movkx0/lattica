use super::*;

/// Outer plans borrow concrete compilers independently of the original source
/// lifetime. Every returned plan or refusal remains in its own stable table.
pub(crate) fn fill_outer_layer<'case, 'metadata, 'source, 'a>(
    planning: &mut WorkflowPlanning<'_>, inventory: &SourceMetadataPlanningPlan<'metadata>,
    case: &CaseRetirementState, compilers: CompilerPlanTables<'source, 'case, 'a>,
    cache: &'source OuterProofCache, tables: OuterPlanTables<'_, 'case, 'source, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_outer_layer");
    run_layer(planning, inventory, case, |planning| {
        compilers.validate(inventory, case)?;
        compilers.finish()?;
        tables.validate_empty(inventory, case)?;
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            macro_rules! outer {
                ($field:ident, $family:ident, $method:ident, $source:expr) => {{
                    stage.source(ProducerFamily::$family, $source);
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    stage.destination(ordinal);
                    let input = successful(compilers.$field, ordinal)?;
                    let slot = tables.$field.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                    stage.action(DriverAction::Derive);
                    let result = planning.$method(inventory, member, $source, input, cache)?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                }};
            }
            for source_ordinal in 0..2 {
                outer!(source, Source, derive_metadata_source_outer, source_ordinal);
            }
            for (source_ordinal, batch) in member.prepared().get().algebra().batches().iter().enumerate() {
                stage.ordinal(source_ordinal);
                match algebra_family(batch) {
                    Some(ProducerFamily::Affine) => outer!(affine, Affine, derive_metadata_affine_outer, source_ordinal),
                    Some(ProducerFamily::Ntt) => outer!(ntt, Ntt, derive_metadata_ntt_outer, source_ordinal),
                    Some(ProducerFamily::Mul) => outer!(mul, Mul, derive_metadata_mul_outer, source_ordinal),
                    Some(ProducerFamily::GBound) => outer!(g_bound, GBound, derive_metadata_g_bound_outer, source_ordinal),
                    Some(ProducerFamily::Permutation) => outer!(permutation, Permutation, derive_metadata_permutation_outer, source_ordinal),
                    Some(ProducerFamily::LinearMap) => outer!(linear_map, LinearMap, derive_metadata_linear_map_outer, source_ordinal),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
