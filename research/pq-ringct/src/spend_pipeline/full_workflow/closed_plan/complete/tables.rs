//! Immutable projections of exact, independently owned case tables. OnceCell
//! makes the owning table invariant; only the borrowed concrete plan is
//! shortened. There is no arbitrary binding/count attachment implementation.
use super::*;
use crate::spend_pipeline::full_workflow::{metadata_tables as tables,
    fresh_generation::case_lifetime::CaseOwnerTable};

mod sealed {
    pub trait FinalContracts {}
    pub trait SourceNativePlans {}
    pub trait UniformNativePlans {}
    pub trait SparseNativePlans {}
    pub trait TranscriptNativePlans {}
    pub trait AffineNativePlans {}
    pub trait NttNativePlans {}
    pub trait MulNativePlans {}
    pub trait GBoundNativePlans {}
    pub trait PermutationNativePlans {}
    pub trait LinearMapNativePlans {}
    pub trait SourceCompilerPlans {}
    pub trait AffineCompilerPlans {}
    pub trait NttCompilerPlans {}
    pub trait MulCompilerPlans {}
    pub trait GBoundCompilerPlans {}
    pub trait PermutationCompilerPlans {}
    pub trait LinearMapCompilerPlans {}
    pub trait FixedOuterPlans {}
    pub trait SourceOuterPlans {}
    pub trait AffineOuterPlans {}
    pub trait NttOuterPlans {}
    pub trait MulOuterPlans {}
    pub trait GBoundOuterPlans {}
    pub trait PermutationOuterPlans {}
    pub trait LinearMapOuterPlans {}
    pub trait ParametersPlans {}
    pub trait AuxiliaryPlans {}
    pub trait EqualityPlans {}
    pub trait ParentPlans {}
    pub trait FixedPlans {}
    pub trait ShakePlans {}
    pub trait AesPlans {}
    pub trait FinalSources {}
    pub trait FinalPlans {}
    pub trait SourceBlueprints {}
    pub trait AffineBlueprints {}
    pub trait NttBlueprints {}
    pub trait MulBlueprints {}
    pub trait GBoundBlueprints {}
    pub trait PermutationBlueprints {}
    pub trait LinearMapBlueprints {}
}

fn get<'view, T, E>(table: &'view CaseOwnerTable<'_, core::result::Result<T, E>>,
    ordinal: usize) -> Result<&'view T>
{
    // Missing-slot errors here are inline. The original CaseOwnerSlot::get's
    // bounded empty-slot String is included in inspection scratch before use.
    table.slots().get(ordinal).ok_or(ClosureError::Order)?
        .get().map_err(|_| ClosureError::Source)?
        .as_ref().map_err(|_| ClosureError::Source)
}

macro_rules! view {
    ($name:ident, [$($life:lifetime),+], $table:ty, $plan:ty) => {
        pub(crate) trait $name: sealed::$name {
            fn len(&self) -> usize;
            fn owns_case(&self, state: &CaseRetirementState) -> bool;
            fn plan(&self, ordinal: usize) -> Result<&$plan>;
        }
        impl<$($life),+> sealed::$name for $table {}
        impl<$($life),+> $name for $table {
            fn len(&self) -> usize { self.slots().len() }
            fn owns_case(&self, state: &CaseRetirementState) -> bool { self.belongs_to_case(state) }
            fn plan(&self, ordinal: usize) -> Result<&$plan> { get(self, ordinal) }
        }
    };
}

view!(SourceNativePlans, ['case, 'a],
    tables::native::SourcePlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::source_native::SourceNativeOperationPlan<'_>);

view!(UniformNativePlans, ['case, 'a],
    tables::native::UniformPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::uniform_native::UniformNativeOperationPlan<'_>);

view!(SparseNativePlans, ['case, 'a],
    tables::native::SparsePlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::sparse_native::SparseNativeOperationPlan<'_>);

view!(TranscriptNativePlans, ['case, 'a],
    tables::native::TranscriptPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::transcript_native::TranscriptNativeOperationPlan<'_>);

view!(AffineNativePlans, ['case, 'a],
    tables::native::AffinePlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::affine_native::AffineNativeOperationPlan<'_>);

view!(NttNativePlans, ['case, 'a],
    tables::native::NttPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::ntt_native::NttNativeOperationPlan<'_>);

view!(MulNativePlans, ['case, 'a],
    tables::native::MulPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::mul_native::MulNativeOperationPlan<'_>);

view!(GBoundNativePlans, ['case, 'a],
    tables::native::GBoundPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::g_bound_native::GBoundNativeOperationPlan<'_>);

view!(PermutationNativePlans, ['case, 'a],
    tables::native::PermutationPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::permutation_native::PermutationNativeOperationPlan<'_>);

view!(LinearMapNativePlans, ['case, 'a],
    tables::native::LinearMapPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperationPlan<'_>);

view!(SourceCompilerPlans, ['case, 'a],
    tables::graph::SourceCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompilePlan<'_>);

view!(AffineCompilerPlans, ['case, 'a],
    tables::algebra::AffineCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompilePlan<'_>);

view!(NttCompilerPlans, ['case, 'a],
    tables::algebra::NttCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompilePlan<'_>);

view!(MulCompilerPlans, ['case, 'a],
    tables::algebra::MulCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompilePlan<'_>);

view!(GBoundCompilerPlans, ['case, 'a],
    tables::algebra::GBoundCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompilePlan<'_>);

view!(PermutationCompilerPlans, ['case, 'a],
    tables::algebra::PermutationCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompilePlan<'_>);

view!(LinearMapCompilerPlans, ['case, 'a],
    tables::algebra::LinearMapCompilerPlanTable<'case, 'a>,
    crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompilePlan<'_>);

view!(FixedOuterPlans, ['case, 'source, 'a],
    tables::graph::FixedOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::FixedLeafOuterPlan<'_, '_>);

view!(SourceOuterPlans, ['case, 'source, 'a],
    tables::graph::SourceOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::NativeLeafOuterPlan<'_, '_>);

view!(AffineOuterPlans, ['case, 'source, 'a],
    tables::algebra::AffineOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::AffineLeafOuterPlan<'_, '_>);

view!(NttOuterPlans, ['case, 'source, 'a],
    tables::algebra::NttOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::NttLeafOuterPlan<'_, '_>);

view!(MulOuterPlans, ['case, 'source, 'a],
    tables::algebra::MulOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::MulLeafOuterPlan<'_, '_>);

view!(GBoundOuterPlans, ['case, 'source, 'a],
    tables::algebra::GBoundOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::GBoundLeafOuterPlan<'_, '_>);

view!(PermutationOuterPlans, ['case, 'source, 'a],
    tables::algebra::PermutationOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::PermutationLeafOuterPlan<'_, '_>);

view!(LinearMapOuterPlans, ['case, 'source, 'a],
    tables::algebra::LinearMapOuterPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::LinearMapLeafOuterPlan<'_, '_>);

view!(ParametersPlans, ['case, 'source, 'a],
    tables::graph::ParametersPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::ParametersPpGraphPlan<'_, '_>);

view!(AuxiliaryPlans, ['case, 'source, 'a],
    tables::graph::AuxiliaryPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::AuxiliaryGraphPlan<'_, '_>);

view!(EqualityPlans, ['case, 'source, 'a],
    tables::graph::EqualityPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::EqualityGraphPlan<'_, '_>);

view!(ParentPlans, ['case, 'source, 'a],
    tables::graph::ParentPlanTable<'case, 'source, 'a>,
    crate::graph_tree::owned_parent::GraphParentPlan<'_, '_>);

view!(FixedPlans, ['case, 'a],
    tables::graph::FixedPlanTable<'case, 'a>,
    SourceOperationPlan<'_>);

view!(ShakePlans, ['case, 'a],
    tables::crypto::ShakePlanTable<'case, 'a>,
    PairedRequestPlan<'_>);

view!(AesPlans, ['case, 'a],
    tables::crypto::AesPlanTable<'case, 'a>,
    OwnedAesRequestPlan<'_>);

view!(FinalSources, ['case, 'a],
    tables::final_aggregation::FinalSourceTable<'case, 'a>,
    FinalAggregationPlan<'_>);

view!(FinalPlans, ['case, 'a],
    tables::final_aggregation::FinalPlanTable<'case, 'a>,
    FinalPhasePlan<'_>);

view!(SourceBlueprints, ['case, 'a, 'graph],
    tables::graph::SourceBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::native_sources::NativeSourceBlueprint<'_, '_>);

view!(AffineBlueprints, ['case, 'a, 'graph],
    tables::algebra::AffineBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::affine_sources::AffineLeafBlueprint<'_, '_>);

view!(NttBlueprints, ['case, 'a, 'graph],
    tables::algebra::NttBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::ntt_sources::NttLeafBlueprint<'_, '_>);

view!(MulBlueprints, ['case, 'a, 'graph],
    tables::algebra::MulBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::mul_sources::MulLeafBlueprint<'_, '_>);

view!(GBoundBlueprints, ['case, 'a, 'graph],
    tables::algebra::GBoundBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::g_bound_sources::GBoundLeafBlueprint<'_, '_>);

view!(PermutationBlueprints, ['case, 'a, 'graph],
    tables::algebra::PermutationBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::permutation_sources::PermutationLeafBlueprint<'_, '_>);

view!(LinearMapBlueprints, ['case, 'a, 'graph],
    tables::algebra::LinearMapBlueprintTable<'case, 'a, 'graph>,
    crate::graph_tree::linear_map_sources::LinearMapLeafBlueprint<'_, '_>);

view!(FinalContracts, ['case, 'a],
    crate::execution::workflow_resources::FinalContractTable<'case, 'a>,
    crate::execution::workflow_resources::OwnedFinalContract<'_>);
