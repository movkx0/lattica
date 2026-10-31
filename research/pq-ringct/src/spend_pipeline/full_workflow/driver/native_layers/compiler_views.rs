//! Scoped immutable projections preserve actual owning table lifetimes.
//! Existing sealed producer-table implementations alone can supply these views.
use super::*;
use crate::spend_pipeline::full_workflow::closed_plan::producer_tables as views;

#[derive(Clone, Copy)]
pub(crate) struct NativeCompilerInputs<'view> {
    pub(crate) source_native: &'view dyn views::SourceNativePlans,
    pub(crate) source_blueprint: &'view dyn views::SourceBlueprints,
    pub(crate) affine_native: &'view dyn views::AffineNativePlans,
    pub(crate) affine_blueprint: &'view dyn views::AffineBlueprints,
    pub(crate) ntt_native: &'view dyn views::NttNativePlans,
    pub(crate) ntt_blueprint: &'view dyn views::NttBlueprints,
    pub(crate) mul_native: &'view dyn views::MulNativePlans,
    pub(crate) mul_blueprint: &'view dyn views::MulBlueprints,
    pub(crate) g_bound_native: &'view dyn views::GBoundNativePlans,
    pub(crate) g_bound_blueprint: &'view dyn views::GBoundBlueprints,
    pub(crate) permutation_native: &'view dyn views::PermutationNativePlans,
    pub(crate) permutation_blueprint: &'view dyn views::PermutationBlueprints,
    pub(crate) linear_map_native: &'view dyn views::LinearMapNativePlans,
    pub(crate) linear_map_blueprint: &'view dyn views::LinearMapBlueprints,
}
impl NativeCompilerInputs<'_> {
    fn validate(&self, metadata: &SourceMetadataPlanningPlan<'_>, case: &CaseRetirementState) -> Result<()> {
        macro_rules! check {
            ($native:ident, $blueprint:ident, $family:ident) => {{
                let count = metadata.counts().family(ProducerFamily::$family);
                if !self.$native.owns_case(case) || !self.$blueprint.owns_case(case)
                    || self.$native.len() != count || self.$blueprint.len() != count
                { return Err(WorkflowError::Identity); }
                for ordinal in 0..count {
                    let _ = self.$native.plan(ordinal).map_err(|_| WorkflowError::Source)?;
                    let _ = self.$blueprint.plan(ordinal).map_err(|_| WorkflowError::Source)?;
                }
            }};
        }
        check!(source_native, source_blueprint, Source);
        check!(affine_native, affine_blueprint, Affine);
        check!(ntt_native, ntt_blueprint, Ntt);
        check!(mul_native, mul_blueprint, Mul);
        check!(g_bound_native, g_bound_blueprint, GBound);
        check!(permutation_native, permutation_blueprint, Permutation);
        check!(linear_map_native, linear_map_blueprint, LinearMap);
        Ok(())
    }
}

/// The input tables may contain plans whose data outlive this compiler layer.
/// Only immutable plan references are shortened to 'view. The invariant
/// CaseOwnerTables and all original reservations stay in their real scopes.
pub(crate) fn fill_compiler_views<'case, 'metadata, 'view>(
    planning: &mut WorkflowPlanning<'_>, inventory: &SourceMetadataPlanningPlan<'metadata>,
    case: &CaseRetirementState, inputs: NativeCompilerInputs<'view>,
    tables: CompilerPlanTables<'_, 'case, 'view>,
    stage: &mut DriverStage,
) -> Result<()>
{
    stage.layer("fill_compiler_views");
    run_layer(planning, inventory, case, |planning| {
        inputs.validate(inventory, case)?;
        tables.validate_empty(inventory, case)?;
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory.member(member_ordinal).map_err(|_| WorkflowError::Identity)?;
            macro_rules! compile {
                ($field:ident, $native:ident, $blueprint:ident, $family:ident, $method:ident, $source:expr) => {{
                    stage.source(ProducerFamily::$family, $source);
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    stage.destination(ordinal);
                    let input = inputs.$native.plan(ordinal).map_err(|_| WorkflowError::Source)?;
                    let blueprint = inputs.$blueprint.plan(ordinal).map_err(|_| WorkflowError::Source)?;
                    let slot = tables.$field.get(ordinal).map_err(|_| WorkflowError::Identity)?;
                    stage.action(DriverAction::Derive);
                    let result = planning.$method(inventory, member, $source, input, blueprint)?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                }};
            }
            for source_ordinal in 0..2 {
                compile!(source, source_native, source_blueprint, Source, derive_metadata_source_compiler, source_ordinal);
            }
            for (source_ordinal, batch) in member.prepared().get().algebra().batches().iter().enumerate() {
                stage.ordinal(source_ordinal);
                match algebra_family(batch) {
                    Some(ProducerFamily::Affine) => compile!(affine, affine_native, affine_blueprint, Affine, derive_metadata_affine_compiler, source_ordinal),
                    Some(ProducerFamily::Ntt) => compile!(ntt, ntt_native, ntt_blueprint, Ntt, derive_metadata_ntt_compiler, source_ordinal),
                    Some(ProducerFamily::Mul) => compile!(mul, mul_native, mul_blueprint, Mul, derive_metadata_mul_compiler, source_ordinal),
                    Some(ProducerFamily::GBound) => compile!(g_bound, g_bound_native, g_bound_blueprint, GBound, derive_metadata_g_bound_compiler, source_ordinal),
                    Some(ProducerFamily::Permutation) => compile!(permutation, permutation_native, permutation_blueprint, Permutation, derive_metadata_permutation_compiler, source_ordinal),
                    Some(ProducerFamily::LinearMap) => compile!(linear_map, linear_map_native, linear_map_blueprint, LinearMap, derive_metadata_linear_map_compiler, source_ordinal),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
