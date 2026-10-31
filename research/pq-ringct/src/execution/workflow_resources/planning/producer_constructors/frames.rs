//! Constructor forwarding frames overlap the active inner construction.
//! They remain PhaseScratch in the original remainder during verifier recording.
use super::*;
use crate::{
    graph_proofs::{owned_ntt::NttSource, owned_mul::MulSource,
        owned_permutation::PermutationSource, owned_linear_map::LinearMapSource},
    graph_tree::owned_parent::GraphParentFailure,
    spend_pipeline::full_workflow::{
        metadata_tables::{native as native_table, algebra as algebra_table, graph as graph_table},
        source_native::SourceNativeOperationFailure,
        uniform_native::UniformNativeOperationFailure,
        sparse_native::SparseNativeOperationFailure,
        transcript_native::TranscriptNativeOperationFailure,
        affine_native::AffineNativeOperationFailure,
        ntt_native::NttNativeOperationFailure,
        mul_native::MulNativeOperationFailure,
        g_bound_native::GBoundNativeOperationFailure,
        permutation_native::PermutationNativeOperationFailure,
        linear_map_native::LinearMapNativeOperationFailure,
        source_native_compile::SourceNativeCompileFailure,
        affine_native_compile::AffineNativeCompileFailure,
        ntt_native_compile::NttNativeCompileFailure,
        mul_native_compile::MulNativeCompileFailure,
        g_bound_native_compile::GBoundNativeCompileFailure,
        permutation_native_compile::PermutationNativeCompileFailure,
        linear_map_native_compile::LinearMapNativeCompileFailure,
    },
};

/// Fixed forwarding inventory is conservatively shared by every source plan.
/// Actual producer cardinality and constructor permission come only from the
/// authenticated inventory; no caller-supplied count changes this allowance.
pub(super) fn producer_native_constructor_frame_requirements(_plan: &SourceMetadataPlanningPlan<'_>)
    -> Result<Requirements, WorkflowError>
{
    native_frames()
}

fn native_frames() -> Result<Requirements, WorkflowError> {
    let mut total = scratch_frames(&[
        size_of::<MetadataMember<'static, 'static>>(), size_of::<ProducerFamily>(),
        size_of::<[usize; 256]>(), size_of::<[Requirements; 8]>(),
        size_of::<[Reservation; 4]>(), size_of::<[Bytes; 8]>(),
        size_of::<[&SourceMetadataPlanningPlan<'static>; 8]>(),
        size_of::<[&crate::spend_pipeline::full_workflow::PreparedWorkflowSources<'static>; 4]>(),
        size_of::<(Reservation, MetadataMember<'static, 'static>, usize)>(),
        size_of::<[&Ledger; 4]>(), size_of::<Result<(), WorkflowError>>(),
        size_of::<Result<Requirements, WorkflowError>>(),
        size_of::<Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<Result<lattica_prover_p3::block_v2::native_gpu::graph_source_preparation::GraphSourceKind, WorkflowError>>(),
        size_of::<Result<Requirements, GraphParentFailure>>(),
        size_of::<native_table::SourcePlanResult<'static>>(),
        size_of::<Result<native_table::SourcePlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, SourceNativeOperationFailure>>(),
        size_of::<native_table::UniformPlanResult<'static>>(),
        size_of::<Result<native_table::UniformPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, UniformNativeOperationFailure>>(),
        size_of::<native_table::SparsePlanResult<'static>>(),
        size_of::<Result<native_table::SparsePlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, SparseNativeOperationFailure>>(),
        size_of::<native_table::TranscriptPlanResult<'static>>(),
        size_of::<Result<native_table::TranscriptPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, TranscriptNativeOperationFailure>>(),
        size_of::<native_table::AffinePlanResult<'static>>(),
        size_of::<Result<native_table::AffinePlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, AffineNativeOperationFailure>>(),
        size_of::<native_table::NttPlanResult<'static>>(),
        size_of::<Result<native_table::NttPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, NttNativeOperationFailure>>(),
        size_of::<native_table::MulPlanResult<'static>>(),
        size_of::<Result<native_table::MulPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, MulNativeOperationFailure>>(),
        size_of::<native_table::GBoundPlanResult<'static>>(),
        size_of::<Result<native_table::GBoundPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, GBoundNativeOperationFailure>>(),
        size_of::<native_table::PermutationPlanResult<'static>>(),
        size_of::<Result<native_table::PermutationPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, PermutationNativeOperationFailure>>(),
        size_of::<native_table::LinearMapPlanResult<'static>>(),
        size_of::<Result<native_table::LinearMapPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, LinearMapNativeOperationFailure>>(),
        size_of::<graph_table::SourceCompilerPlanResult<'static>>(),
        size_of::<Result<graph_table::SourceCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, SourceNativeCompileFailure>>(),
        size_of::<graph_table::SourceOuterPlanResult<'static, 'static>>(),
        size_of::<Result<graph_table::SourceOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<algebra_table::AffineCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_table::AffineCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, AffineNativeCompileFailure>>(),
        size_of::<algebra_table::AffineOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_table::AffineOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<algebra_table::NttCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_table::NttCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, NttNativeCompileFailure>>(),
        size_of::<algebra_table::NttOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_table::NttOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<algebra_table::MulCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_table::MulCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, MulNativeCompileFailure>>(),
        size_of::<algebra_table::MulOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_table::MulOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<algebra_table::GBoundCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_table::GBoundCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, GBoundNativeCompileFailure>>(),
        size_of::<algebra_table::GBoundOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_table::GBoundOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<algebra_table::PermutationCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_table::PermutationCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, PermutationNativeCompileFailure>>(),
        size_of::<algebra_table::PermutationOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_table::PermutationOuterPlanResult<'static, 'static>, WorkflowError>>(),
        size_of::<algebra_table::LinearMapCompilerPlanResult<'static>>(),
        size_of::<Result<algebra_table::LinearMapCompilerPlanResult<'static>, WorkflowError>>(),
        size_of::<Result<Requirements, LinearMapNativeCompileFailure>>(),
        size_of::<algebra_table::LinearMapOuterPlanResult<'static, 'static>>(),
        size_of::<Result<algebra_table::LinearMapOuterPlanResult<'static, 'static>, WorkflowError>>(),
    ])?;
    // Each view's own pure inspection/query frames already include its
    // forwarding multiplier. Add them once, separately from recording scratch.
    for bytes in [NttSource::planning_view_host_bytes(), MulSource::planning_view_host_bytes(),
        PermutationSource::planning_view_host_bytes(), LinearMapSource::planning_view_host_bytes()]
    {
        total.add(Category::PhaseScratch, Bytes {
            host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
        })?;
    }
    Ok(total)
}

fn require_overlap(have: Requirements, inner: Requirements, forwarding: Requirements)
    -> Result<(), WorkflowError>
{
    let required = sum(inner, forwarding)?;
    if !super::super::super::types::contains(have, required) {
        return Err(WorkflowError::Planning);
    }
    Ok(())
}

impl WorkflowPlanning<'_> {
    pub(super) fn check_native_constructor_scratch(&self, inventory: &SourceMetadataPlanningPlan<'_>,
        inner: Requirements) -> Result<(), WorkflowError>
    {
        require_overlap(self.scratch.requirements(), inner,
            producer_native_constructor_frame_requirements(inventory)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;

    #[test]
    fn native_wrapper_frames_remain_after_exact_recording_split() {
        let forwarding = native_frames().unwrap();
        let bytes = forwarding.total().unwrap();
        assert!(bytes.host > 0);
        assert_eq!(bytes.device, 0);
        assert_eq!(forwarding.get(Category::PhaseScratch), bytes);
        let inner = Requirements::single(Category::PhaseScratch, Bytes { host: 4096, device: 64 });
        let combined = sum(inner, forwarding).unwrap();
        let total = combined.total().unwrap();
        let ledger = Ledger::new(WorkerAllowance { host: total.host, device: total.device });
        let mut scratch = ledger.admit_phase(combined).unwrap();
        assert!(require_overlap(scratch.requirements(), inner, forwarding).is_ok());
        let recording = scratch.split(inner).unwrap();
        assert_eq!(scratch.requirements(), forwarding);
        assert_eq!(recording.requirements(), inner);
        assert!(!super::super::super::super::types::contains(recording.requirements(), combined));
        assert_eq!(ledger.snapshot().current, total);
        drop(recording);
        drop(scratch);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn native_wrapper_scratch_refuses_each_overlapping_byte_shortfall() {
        let forwarding = native_frames().unwrap();
        let inner = Requirements::single(Category::PhaseScratch, Bytes { host: 4096, device: 64 });
        let total = sum(inner, forwarding).unwrap().total().unwrap();
        let short_host = Requirements::single(Category::PhaseScratch, Bytes { host: total.host - 1, device: total.device });
        let short_device = Requirements::single(Category::PhaseScratch, Bytes { host: total.host, device: total.device - 1 });
        assert!(require_overlap(short_host, inner, forwarding).is_err());
        assert!(require_overlap(short_device, inner, forwarding).is_err());
        let wrong_category = Requirements::single(Category::RegisteredMetadata, total);
        assert!(require_overlap(wrong_category, inner, forwarding).is_err());
        let overflow = Requirements::single(Category::PhaseScratch, Bytes { host: u64::MAX, device: 0 });
        assert!(require_overlap(overflow, overflow, forwarding).is_err());
    }
}
