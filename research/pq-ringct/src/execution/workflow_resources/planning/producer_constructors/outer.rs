//! The outer wrappers bind the exact compiler chain to the authenticated source.
//! A refused inner constructor keeps this installation failed; there is no retry.
use super::*;
use crate::{graph_crypto::OuterProofCache,
    graph_tree::owned_parent::{NativeLeafOuterPlan, AffineLeafOuterPlan, NttLeafOuterPlan, MulLeafOuterPlan, GBoundLeafOuterPlan, PermutationLeafOuterPlan, LinearMapLeafOuterPlan},
    spend_pipeline::full_workflow::{source_native_compile::SourceNativeCompilePlan,
        metadata_tables::{graph as graph_table, algebra as table},
        affine_native_compile::AffineNativeCompilePlan,
        ntt_native_compile::NttNativeCompilePlan,
        mul_native_compile::MulNativeCompilePlan,
        g_bound_native_compile::GBoundNativeCompilePlan,
        permutation_native_compile::PermutationNativeCompilePlan,
        linear_map_native_compile::LinearMapNativeCompilePlan,
    },
};

macro_rules! outer_constructor {
    ($method:ident, $family:ident, $compiler:ident, $outer:ident, $result:ident) => {
        pub(crate) fn $method<'metadata, 'source, 'a>(&mut self, inventory: &SourceMetadataPlanningPlan<'metadata>,
            member: MetadataMember<'_, 'metadata>, source_ordinal: usize,
            compiler: &'source $compiler<'a>, cache: &'source OuterProofCache)
            -> Result<table::$result<'source, 'a>, WorkflowError>
        {
            self.begin_metadata_constructor(inventory, member, ProducerFamily::$family, source_ordinal, 2)?;
            self.check_native_constructor_scratch(inventory, Requirements::default())?;
            let batch = member.prepared().get().algebra().batches()
                .get(source_ordinal).ok_or(WorkflowError::Identity)?;
            let native = compiler.native_plan();
            if !core::ptr::eq(compiler.sources(), member.prepared())
                || !core::ptr::eq(compiler.context(), inventory.context())
                || !core::ptr::eq(native.batch(), batch) || native.batch_ordinal() != source_ordinal
                || !compiler.belongs_to(self.capability.ledger())
            { return Err(WorkflowError::Identity); }
            let required = $outer::planning_requirements().map_err(|_| WorkflowError::Planning)?;
            let original = self.original.split(required)?;
            let result = $outer::derive_pre_reserved(compiler, cache, original, self.capability.ledger());
            if result.is_ok() { self.finish_metadata_constructor_success(); }
            Ok(result)
        }
    };
}

impl WorkflowPlanning<'_> {
    pub(crate) fn derive_metadata_source_outer<'metadata, 'source, 'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'metadata>, member: MetadataMember<'_, 'metadata>,
        source_ordinal: usize, compiler: &'source SourceNativeCompilePlan<'a>,
        cache: &'source OuterProofCache)
        -> Result<graph_table::SourceOuterPlanResult<'source, 'a>, WorkflowError>
    {
        self.begin_metadata_constructor(inventory, member, ProducerFamily::Source, source_ordinal, 2)?;
        self.check_native_constructor_scratch(inventory, Requirements::default())?;
        if !core::ptr::eq(compiler.sources(), member.prepared())
            || !core::ptr::eq(compiler.context(), inventory.context())
            || compiler.native_plan().kind() != super::native::source_kind(source_ordinal)?
            || !compiler.belongs_to(self.capability.ledger())
        { return Err(WorkflowError::Identity); }
        let required = NativeLeafOuterPlan::planning_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = NativeLeafOuterPlan::derive_pre_reserved(compiler, cache, original, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    outer_constructor!(derive_metadata_affine_outer, Affine, AffineNativeCompilePlan,
        AffineLeafOuterPlan, AffineOuterPlanResult);
    outer_constructor!(derive_metadata_ntt_outer, Ntt, NttNativeCompilePlan,
        NttLeafOuterPlan, NttOuterPlanResult);
    outer_constructor!(derive_metadata_mul_outer, Mul, MulNativeCompilePlan,
        MulLeafOuterPlan, MulOuterPlanResult);
    outer_constructor!(derive_metadata_g_bound_outer, GBound, GBoundNativeCompilePlan,
        GBoundLeafOuterPlan, GBoundOuterPlanResult);
    outer_constructor!(derive_metadata_permutation_outer, Permutation, PermutationNativeCompilePlan,
        PermutationLeafOuterPlan, PermutationOuterPlanResult);
    outer_constructor!(derive_metadata_linear_map_outer, LinearMap, LinearMapNativeCompilePlan,
        LinearMapLeafOuterPlan, LinearMapOuterPlanResult);
}
