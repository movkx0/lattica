use super::*;

/// Compiler plans borrow stable native and blueprint tables for their entire
/// data lifetime, matching the concrete unchanged compiler constructor APIs.
pub(crate) fn fill_compiler_layer<'case, 'a>(
    planning: &mut WorkflowPlanning<'_>, inventory: &SourceMetadataPlanningPlan<'a>,
    case: &CaseRetirementState, native: NativePlanTables<'a, 'case, 'a>,
    blueprints: BlueprintTables<'a, 'case, 'a>,
    tables: CompilerPlanTables<'_, 'case, 'a>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_compiler_layer");
    run_layer(planning, inventory, case, |planning| {
        native.validate(inventory, case)?;
        native.finish()?;
        blueprints.validate(inventory, case)?;
        blueprints.finish()?;
        tables.validate_empty(inventory, case)?;
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            macro_rules! compile {
                ($field:ident, $family:ident, $method:ident, $source:expr) => {{
                    stage.source(ProducerFamily::$family, $source);
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    stage.destination(ordinal);
                    let input = successful(native.$field, ordinal)?;
                    let blueprint = successful(blueprints.$field, ordinal)?;
                    let slot = tables.$field.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                    stage.action(DriverAction::Derive);
                    let result = planning.$method(inventory, member, $source, input, blueprint)?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                }};
            }
            for source_ordinal in 0..2 {
                compile!(source, Source, derive_metadata_source_compiler, source_ordinal);
            }
            for (source_ordinal, batch) in member.prepared().get().algebra().batches().iter().enumerate() {
                stage.ordinal(source_ordinal);
                match algebra_family(batch) {
                    Some(ProducerFamily::Affine) => compile!(affine, Affine, derive_metadata_affine_compiler, source_ordinal),
                    Some(ProducerFamily::Ntt) => compile!(ntt, Ntt, derive_metadata_ntt_compiler, source_ordinal),
                    Some(ProducerFamily::Mul) => compile!(mul, Mul, derive_metadata_mul_compiler, source_ordinal),
                    Some(ProducerFamily::GBound) => compile!(g_bound, GBound, derive_metadata_g_bound_compiler, source_ordinal),
                    Some(ProducerFamily::Permutation) => compile!(permutation, Permutation, derive_metadata_permutation_compiler, source_ordinal),
                    Some(ProducerFamily::LinearMap) => compile!(linear_map, LinearMap, derive_metadata_linear_map_compiler, source_ordinal),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
