//! Native compiler wrappers preserve the complete original-bearing refusal.
//! The supplied producer is checked against the exact inventory member and ordinal.
use super::*;
use crate::{
    graph_tree::native_sources::NativeSourceBlueprint,
    spend_pipeline::full_workflow::{
        source_native::SourceNativeOperationPlan, source_native_compile::SourceNativeCompilePlan,
        metadata_tables::{graph as graph_table, algebra as table},
        affine_native::AffineNativeOperationPlan, affine_native_compile::AffineNativeCompilePlan,
        ntt_native::NttNativeOperationPlan, ntt_native_compile::NttNativeCompilePlan,
        mul_native::MulNativeOperationPlan, mul_native_compile::MulNativeCompilePlan,
        g_bound_native::GBoundNativeOperationPlan, g_bound_native_compile::GBoundNativeCompilePlan,
        permutation_native::PermutationNativeOperationPlan, permutation_native_compile::PermutationNativeCompilePlan,
        linear_map_native::LinearMapNativeOperationPlan, linear_map_native_compile::LinearMapNativeCompilePlan,
    },
    graph_tree::affine_sources::AffineLeafBlueprint,
    graph_tree::ntt_sources::NttLeafBlueprint,
    graph_tree::mul_sources::MulLeafBlueprint,
    graph_tree::g_bound_sources::GBoundLeafBlueprint,
    graph_tree::permutation_sources::PermutationLeafBlueprint,
    graph_tree::linear_map_sources::LinearMapLeafBlueprint,
};

macro_rules! compiler_constructor {
    ($method:ident, $family:ident, $native:ident, $blueprint:ident, $compiler:ident, $result:ident) => {
        pub(crate) fn $method<'metadata, 'a>(&mut self, inventory: &SourceMetadataPlanningPlan<'metadata>,
            member: MetadataMember<'_, 'metadata>, source_ordinal: usize,
            native: &'a $native<'a>, blueprint: &'a $blueprint<'a, 'a>)
            -> Result<table::$result<'a>, WorkflowError>
        {
            self.begin_metadata_constructor(inventory, member, ProducerFamily::$family, source_ordinal, 1)?;
            self.check_native_constructor_scratch(inventory, Requirements::default())?;
            let batch = member.prepared().get().algebra().batches()
                .get(source_ordinal).ok_or(WorkflowError::Identity)?;
            if !core::ptr::eq(native.sources(), member.prepared())
                || !core::ptr::eq(native.context(), inventory.context())
                || !core::ptr::eq(native.batch(), batch) || native.batch_ordinal() != source_ordinal
                || !native.belongs_to(self.capability.ledger())
            { return Err(WorkflowError::Identity); }
            let inner = $compiler::planning_requirements(blueprint).map_err(|_| WorkflowError::Planning)?;
            self.check_native_constructor_scratch(inventory, inner)?;
            let required = $compiler::metadata_requirements().map_err(|_| WorkflowError::Planning)?;
            let original = self.original.split(required)?;
            // The concrete compiler additionally authenticates the blueprint
            // against the same prepared graph, context, family and native source.
            let result = $compiler::new(native, blueprint, original, &self.scratch, self.capability.ledger());
            if result.is_ok() { self.finish_metadata_constructor_success(); }
            Ok(result)
        }
    };
}

impl WorkflowPlanning<'_> {
    pub(crate) fn derive_metadata_source_compiler<'metadata, 'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>,
        source_ordinal: usize, native: &'a SourceNativeOperationPlan<'a>,
        blueprint: &'a NativeSourceBlueprint<'a, 'a>)
        -> Result<graph_table::SourceCompilerPlanResult<'a>, WorkflowError>
    {
        self.begin_metadata_constructor(inventory, member, ProducerFamily::Source, source_ordinal, 1)?;
        self.check_native_constructor_scratch(inventory, Requirements::default())?;
        if !core::ptr::eq(native.sources(), member.prepared())
            || !core::ptr::eq(native.context(), inventory.context())
            || native.kind() != super::native::source_kind(source_ordinal)?
            || !native.belongs_to(self.capability.ledger())
        { return Err(WorkflowError::Identity); }
        let inner = SourceNativeCompilePlan::planning_requirements(blueprint).map_err(|_| WorkflowError::Planning)?;
        self.check_native_constructor_scratch(inventory, inner)?;
        let required = SourceNativeCompilePlan::metadata_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = SourceNativeCompilePlan::new(native, blueprint, original,
            &self.scratch, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    compiler_constructor!(derive_metadata_affine_compiler, Affine, AffineNativeOperationPlan,
        AffineLeafBlueprint, AffineNativeCompilePlan, AffineCompilerPlanResult);
    compiler_constructor!(derive_metadata_ntt_compiler, Ntt, NttNativeOperationPlan,
        NttLeafBlueprint, NttNativeCompilePlan, NttCompilerPlanResult);
    compiler_constructor!(derive_metadata_mul_compiler, Mul, MulNativeOperationPlan,
        MulLeafBlueprint, MulNativeCompilePlan, MulCompilerPlanResult);
    compiler_constructor!(derive_metadata_g_bound_compiler, GBound, GBoundNativeOperationPlan,
        GBoundLeafBlueprint, GBoundNativeCompilePlan, GBoundCompilerPlanResult);
    compiler_constructor!(derive_metadata_permutation_compiler, Permutation, PermutationNativeOperationPlan,
        PermutationLeafBlueprint, PermutationNativeCompilePlan, PermutationCompilerPlanResult);
    compiler_constructor!(derive_metadata_linear_map_compiler, LinearMap, LinearMapNativeOperationPlan,
        LinearMapLeafBlueprint, LinearMapNativeCompilePlan, LinearMapCompilerPlanResult);
}
