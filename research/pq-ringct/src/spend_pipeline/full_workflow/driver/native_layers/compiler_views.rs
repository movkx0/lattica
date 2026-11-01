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
    fn validate(
        &self,
        metadata: &SourceMetadataPlanningPlan<'_>,
        case: &CaseRetirementState,
    ) -> Result<()> {
        macro_rules! check {
            ($native:ident, $blueprint:ident, $family:ident) => {{
                let count = metadata.counts().family(ProducerFamily::$family);
                if !self.$native.owns_case(case)
                    || !self.$blueprint.owns_case(case)
                    || self.$native.len() != count
                    || self.$blueprint.len() != count
                {
                    return Err(WorkflowError::Identity);
                }
                for ordinal in 0..count {
                    let _ = self
                        .$native
                        .plan(ordinal)
                        .map_err(|_| WorkflowError::Source)?;
                    let _ = self
                        .$blueprint
                        .plan(ordinal)
                        .map_err(|_| WorkflowError::Source)?;
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
    planning: &mut WorkflowPlanning<'_>,
    inventory: &SourceMetadataPlanningPlan<'metadata>,
    case: &CaseRetirementState,
    inputs: NativeCompilerInputs<'view>,
    tables: CompilerPlanTables<'_, 'case, 'view>,
    stage: &mut DriverStage,
) -> Result<()> {
    stage.layer("fill_compiler_views");
    run_layer(planning, inventory, case, |planning| {
        inputs.validate(inventory, case)?;
        tables.validate_empty(inventory, case)?;
        macro_rules! native {
            (source, $ordinal:expr) => {
                inputs
                    .source_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (affine, $ordinal:expr) => {
                inputs
                    .affine_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (ntt, $ordinal:expr) => {
                inputs
                    .ntt_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (mul, $ordinal:expr) => {
                inputs
                    .mul_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (g_bound, $ordinal:expr) => {
                inputs
                    .g_bound_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (permutation, $ordinal:expr) => {
                inputs
                    .permutation_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (linear_map, $ordinal:expr) => {
                inputs
                    .linear_map_native
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
        }
        macro_rules! blueprint {
            (source, $ordinal:expr) => {
                inputs
                    .source_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (affine, $ordinal:expr) => {
                inputs
                    .affine_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (ntt, $ordinal:expr) => {
                inputs
                    .ntt_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (mul, $ordinal:expr) => {
                inputs
                    .mul_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (g_bound, $ordinal:expr) => {
                inputs
                    .g_bound_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (permutation, $ordinal:expr) => {
                inputs
                    .permutation_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
            (linear_map, $ordinal:expr) => {
                inputs
                    .linear_map_blueprint
                    .plan($ordinal)
                    .map_err(|_| WorkflowError::Source)?
            };
        }
        for member_ordinal in 0..inventory.members().len() {
            stage.member(member_ordinal);
            let member = inventory
                .member(member_ordinal)
                .map_err(|_| WorkflowError::Identity)?;
            // Resolve pending misses in groups before serial plan construction.
            // These are borrowed descriptors; all normal constructor checks and
            // original reservations below remain mandatory, even after a hit.
            use crate::component_tree::native_shape::{cohort, unchanged::OtherNativeDescriptor};
            let mut requests = [cohort::Request {
                descriptor: cohort::Descriptor::Other(OtherNativeDescriptor::PrivateProof),
                auxiliary: 0,
            }; cohort::MAX];
            let mut count = 0;
            macro_rules! queue {
                ($field:ident, $family:ident, $source:expr) => {{
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    requests[count] = blueprint!($field, ordinal).metadata_request();
                    count += 1;
                }};
            }
            for source in 0..2 {
                queue!(source, Source, source);
            }
            let mut resolved = planning.resolve_native_metadata(inventory, &requests[..count])?;
            let mut selected = 0;
            macro_rules! compile {
                ($field:ident, $family:ident, $method:ident, $source:expr) => {{
                    stage.source(ProducerFamily::$family, $source);
                    let ordinal = position(inventory, member, ProducerFamily::$family, $source)?;
                    stage.destination(ordinal);
                    let input = native!($field, ordinal);
                    let blueprint = blueprint!($field, ordinal);
                    let slot = tables
                        .$field
                        .get(ordinal)
                        .map_err(|_| WorkflowError::Identity)?;
                    stage.action(DriverAction::Derive);
                    let bound = resolved
                        .get_mut(selected)
                        .and_then(Option::take)
                        .ok_or(WorkflowError::Planning)?;
                    selected += 1;
                    let result =
                        planning.$method(inventory, member, $source, input, blueprint, bound)?;
                    stage.action(DriverAction::Install);
                    install(slot, result)?;
                }};
            }
            for source_ordinal in 0..2 {
                compile!(
                    source,
                    Source,
                    derive_metadata_source_compiler,
                    source_ordinal
                );
            }
            for (source_ordinal, batch) in member
                .prepared()
                .get()
                .algebra()
                .batches()
                .iter()
                .enumerate()
            {
                if source_ordinal % cohort::MAX == 0 {
                    if selected != count {
                        return Err(WorkflowError::Planning);
                    }
                    count = 0;
                    selected = 0;
                    for (offset, batch) in member.prepared().get().algebra().batches()
                        [source_ordinal..]
                        .iter()
                        .take(cohort::MAX)
                        .enumerate()
                    {
                        let source = source_ordinal + offset;
                        match algebra_family(batch) {
                            Some(ProducerFamily::Affine) => queue!(affine, Affine, source),
                            Some(ProducerFamily::Ntt) => queue!(ntt, Ntt, source),
                            Some(ProducerFamily::Mul) => queue!(mul, Mul, source),
                            Some(ProducerFamily::GBound) => queue!(g_bound, GBound, source),
                            Some(ProducerFamily::Permutation) => {
                                queue!(permutation, Permutation, source)
                            }
                            Some(ProducerFamily::LinearMap) => {
                                queue!(linear_map, LinearMap, source)
                            }
                            None => (),
                            _ => return Err(WorkflowError::Identity),
                        }
                    }
                    resolved = if count == 0 {
                        [None; cohort::MAX]
                    } else {
                        planning.resolve_native_metadata(inventory, &requests[..count])?
                    };
                }
                stage.ordinal(source_ordinal);
                match algebra_family(batch) {
                    Some(ProducerFamily::Affine) => compile!(
                        affine,
                        Affine,
                        derive_metadata_affine_compiler,
                        source_ordinal
                    ),
                    Some(ProducerFamily::Ntt) => {
                        compile!(ntt, Ntt, derive_metadata_ntt_compiler, source_ordinal)
                    }
                    Some(ProducerFamily::Mul) => {
                        compile!(mul, Mul, derive_metadata_mul_compiler, source_ordinal)
                    }
                    Some(ProducerFamily::GBound) => compile!(
                        g_bound,
                        GBound,
                        derive_metadata_g_bound_compiler,
                        source_ordinal
                    ),
                    Some(ProducerFamily::Permutation) => compile!(
                        permutation,
                        Permutation,
                        derive_metadata_permutation_compiler,
                        source_ordinal
                    ),
                    Some(ProducerFamily::LinearMap) => compile!(
                        linear_map,
                        LinearMap,
                        derive_metadata_linear_map_compiler,
                        source_ordinal
                    ),
                    None => (),
                    _ => return Err(WorkflowError::Identity),
                }
            }
            if selected != count {
                return Err(WorkflowError::Planning);
            }
        }
        stage.action(DriverAction::Finish);
        tables.finish()
    })
}
