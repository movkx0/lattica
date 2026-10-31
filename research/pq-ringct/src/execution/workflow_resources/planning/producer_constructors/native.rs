//! Named native constructors consume only source-derived original metadata.
//! The full constructor Result, including a refused original, reaches its case slot.
use super::*;
use crate::{
    graph_proofs::{owned_ntt::NttSource, owned_mul::MulSource,
        owned_permutation::PermutationSource, owned_linear_map::LinearMapSource},
    spend_pipeline::full_workflow::{
        source_native::SourceNativeOperationPlan, uniform_native::UniformNativeOperationPlan,
        sparse_native::SparseNativeOperationPlan, transcript_native::TranscriptNativeOperationPlan,
        affine_native::AffineNativeOperationPlan, ntt_native::NttNativeOperationPlan,
        mul_native::MulNativeOperationPlan, g_bound_native::GBoundNativeOperationPlan,
        permutation_native::PermutationNativeOperationPlan, linear_map_native::LinearMapNativeOperationPlan,
        metadata_tables::native as table,
    },
};
use lattica_prover_p3::block_v2::native_gpu::graph_source_preparation::GraphSourceKind;

pub(super) fn source_kind(ordinal: usize) -> Result<GraphSourceKind, WorkflowError> {
    match ordinal {
        0 => Ok(GraphSourceKind::Statement),
        1 => Ok(GraphSourceKind::PrivateProof),
        _ => Err(WorkflowError::Identity),
    }
}

macro_rules! auxiliary_constructor {
    ($method:ident, $family:ident, $plan:ident, $result:ident) => {
        pub(crate) fn $method<'a>(&mut self, inventory: &SourceMetadataPlanningPlan<'a>,
            member: MetadataMember<'_, 'a>, source_ordinal: usize)
            -> Result<table::$result<'a>, WorkflowError>
        {
            self.begin_metadata_constructor(inventory, member, ProducerFamily::$family, source_ordinal, 0)?;
            self.check_native_constructor_scratch(inventory, Requirements::default())?;
            let request = member.prepared().get().auxiliary_factory().requests()
                .get(source_ordinal).ok_or(WorkflowError::Identity)?;
            let required = $plan::metadata_requirements().map_err(|_| WorkflowError::Planning)?;
            let original = self.original.split(required)?;
            let result = $plan::new(inventory.scope(), member.prepared(), request.operation_index(),
                request.role(), original, self.capability.ledger());
            if result.is_ok() { self.finish_metadata_constructor_success(); }
            Ok(result)
        }
    };
}

macro_rules! algebra_constructor {
    ($method:ident, $family:ident, $plan:ident, $result:ident) => {
        pub(crate) fn $method<'a>(&mut self, inventory: &SourceMetadataPlanningPlan<'a>,
            member: MetadataMember<'_, 'a>, source_ordinal: usize)
            -> Result<table::$result<'a>, WorkflowError>
        {
            self.begin_metadata_constructor(inventory, member, ProducerFamily::$family, source_ordinal, 0)?;
            self.check_native_constructor_scratch(inventory, Requirements::default())?;
            let required = $plan::metadata_requirements().map_err(|_| WorkflowError::Planning)?;
            let original = self.original.split(required)?;
            let result = $plan::new(inventory.scope(), member.prepared(), source_ordinal,
                original, self.capability.ledger());
            if result.is_ok() { self.finish_metadata_constructor_success(); }
            Ok(result)
        }
    };
}

macro_rules! recording_constructor {
    ($method:ident, $family:ident, $source:ident, $plan:ident, $result:ident) => {
        pub(crate) fn $method<'a>(&mut self, inventory: &SourceMetadataPlanningPlan<'a>,
            member: MetadataMember<'_, 'a>, source_ordinal: usize)
            -> Result<table::$result<'a>, WorkflowError>
        {
            self.begin_metadata_constructor(inventory, member, ProducerFamily::$family, source_ordinal, 0)?;
            // The allocation-free view and pure query frames are charged before
            // inspection. The recording split must leave every wrapper frame.
            self.check_native_constructor_scratch(inventory, Requirements::default())?;
            let source = $source::from_original(member.prepared(), source_ordinal)
                .map_err(|_| WorkflowError::Identity)?;
            let recording = $plan::verification_planning_requirements(source.kind())
                .map_err(|_| WorkflowError::Planning)?;
            self.check_native_constructor_scratch(inventory, recording)?;
            let required = $plan::metadata_requirements().map_err(|_| WorkflowError::Planning)?;
            let original = self.original.split(required)?;
            let result = self.with_metadata_recording(recording, |recording, _remaining, ledger|
                $plan::new(inventory.scope(), member.prepared(), source_ordinal, original, recording, ledger))?;
            // An inner error owns the exact original. Never flatten that error
            // into WorkflowError or clear the failed constructor cursor.
            if result.is_ok() { self.finish_metadata_constructor_success(); }
            Ok(result)
        }
    };
}

impl WorkflowPlanning<'_> {
    pub(crate) fn derive_metadata_source_native<'a>(&mut self,
        inventory: &SourceMetadataPlanningPlan<'a>, member: MetadataMember<'_, 'a>,
        source_ordinal: usize) -> Result<table::SourcePlanResult<'a>, WorkflowError>
    {
        self.begin_metadata_constructor(inventory, member, ProducerFamily::Source, source_ordinal, 0)?;
        self.check_native_constructor_scratch(inventory, Requirements::default())?;
        let kind = source_kind(source_ordinal)?;
        let required = SourceNativeOperationPlan::metadata_requirements().map_err(|_| WorkflowError::Planning)?;
        let original = self.original.split(required)?;
        let result = SourceNativeOperationPlan::new(inventory.scope(), member.prepared(), kind,
            original, self.capability.ledger());
        if result.is_ok() { self.finish_metadata_constructor_success(); }
        Ok(result)
    }

    auxiliary_constructor!(derive_metadata_uniform_native, Uniform, UniformNativeOperationPlan, UniformPlanResult);
    auxiliary_constructor!(derive_metadata_sparse_native, Sparse, SparseNativeOperationPlan, SparsePlanResult);
    auxiliary_constructor!(derive_metadata_transcript_native, Transcript, TranscriptNativeOperationPlan, TranscriptPlanResult);
    algebra_constructor!(derive_metadata_affine_native, Affine, AffineNativeOperationPlan, AffinePlanResult);
    algebra_constructor!(derive_metadata_g_bound_native, GBound, GBoundNativeOperationPlan, GBoundPlanResult);
    recording_constructor!(derive_metadata_ntt_native, Ntt, NttSource, NttNativeOperationPlan, NttPlanResult);
    recording_constructor!(derive_metadata_mul_native, Mul, MulSource, MulNativeOperationPlan, MulPlanResult);
    recording_constructor!(derive_metadata_permutation_native, Permutation, PermutationSource,
        PermutationNativeOperationPlan, PermutationPlanResult);
    recording_constructor!(derive_metadata_linear_map_native, LinearMap, LinearMapSource,
        LinearMapNativeOperationPlan, LinearMapPlanResult);
}
