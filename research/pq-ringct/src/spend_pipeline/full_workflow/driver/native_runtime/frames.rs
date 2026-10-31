use super::*;
use crate::execution::workflow_resources::{RetainedNative, RetainedOriginal};
use crate::graph_tree::owned_parent;

fn sum(parts: impl IntoIterator<Item = usize>) -> Result<usize> {
    parts.into_iter().try_fold(0usize, |sum, part| {
        sum.checked_add(part.checked_mul(8).ok_or(WorkflowError::Overflow)?)
            .ok_or(WorkflowError::Overflow)
    })
}
fn cell_frames<T: 'static>() -> Result<usize> {
    sum([
        size_of::<T>(), size_of::<Option<T>>(), size_of::<RefCell<Option<T>>>(),
        size_of::<Ref<'static, Option<T>>>(), size_of::<RefMut<'static, Option<T>>>(),
        size_of::<Option<Ref<'static, Option<T>>>>(), size_of::<Option<RefMut<'static, Option<T>>>>(),
        size_of::<Result<Ref<'static, Option<T>>>>(), size_of::<Result<RefMut<'static, Option<T>>>>(),
        size_of::<Result<&'static T>>(), size_of::<Result<&'static RefCell<Option<T>>>>(),
        size_of::<Result<T>>(),
    ])
}

/// Add to the source metadata envelope and retain in admission._planning_original.
/// These fixed caller/guard/result shells coexist with phase/pool-owned variable
/// payloads, compiler inputs and scratch. This grants no execution authority and
/// does not change any previously closed phase facts or residual allowance.
pub(crate) fn retained_requirements() -> Result<Requirements> {
    let bytes = forwarding_bytes()?;
    Ok(Requirements::single(Category::RegisteredMetadata, Bytes {
        host: u64::try_from(bytes).map_err(|_| WorkflowError::Overflow)?, device: 0,
    }))
}
fn forwarding_bytes() -> Result<usize> {
    let fixed = sum([
        size_of::<NativeRuntime<'static, 'static, 'static, 'static, 'static, 'static>>(),
        size_of::<NativePlanTables<'static, 'static, 'static>>(),
        size_of::<CompilerPlanTables<'static, 'static, 'static>>(),
        size_of::<OuterPlanTables<'static, 'static, 'static, 'static>>(),
        size_of::<NativeOutputs<'static, 'static, 'static>>(),
        size_of::<NativePackets<'static, 'static, 'static, 'static>>(),
        size_of::<CompiledOutputs<'static, 'static, 'static>>(),
        size_of::<OuterOutputs<'static, 'static, 'static>>(),
        size_of::<OuterPackets<'static, 'static, 'static, 'static, 'static>>(),
        size_of::<InitGuard<'static, 'static>>(), size_of::<DriverGuard<'static, 'static, 'static>>(),
        size_of::<[usize; 128]>(), size_of::<[Requirements; 4]>(),
        size_of::<[&CaseRetirementState; 8]>(),
        size_of::<[&ValidatedCompleteInventory<'static, 'static>; 8]>(),
        size_of::<[&graph_tables::SourceOuterOutputs<'static, 'static>; 8]>(),
        size_of::<PhaseStep>(), size_of::<StepDispatch>(), size_of::<ProducerRoute>(),
        size_of::<[ProducerRoute; 4]>(), size_of::<NativeFamily>(), size_of::<LeafFamily>(),
        size_of::<GraphPhase>(), size_of::<ProducerFamily>(), size_of::<PhaseBinding>(),
        // The phase-specific backend checker coexists with dispatch validation.
        size_of::<GraphPhase>(), size_of::<Bytes>(), size_of::<bool>(), size_of::<Result<()>>(),
        size_of::<crate::spend_pipeline::full_workflow::metadata_planning::ProducerCounts>(),
        size_of::<Result<&'static PhaseStep>>(), size_of::<Result<PhaseBinding>>(),
        size_of::<Result<(PhaseBinding, SlotId)>>(), size_of::<Result<()>>(), size_of::<Result<usize>>(),
        size_of::<WorkflowError>(), size_of::<std::cell::BorrowError>(),
        size_of::<std::cell::BorrowMutError>(), size_of::<owned_parent::GraphParentFailure>(),
        size_of::<crate::spend_pipeline::full_workflow::fresh_generation::FreshGenerationError>(),
        size_of::<String>(), 256,
        size_of::<crate::spend_pipeline::full_workflow::source_native::SourceNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::source_native::SourceNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::source_native::SourceNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::uniform_native::UniformNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::uniform_native::UniformNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::uniform_native::UniformNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::sparse_native::SparseNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::sparse_native::SparseNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::sparse_native::SparseNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::transcript_native::TranscriptNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::transcript_native::TranscriptNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::transcript_native::TranscriptNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::affine_native::AffineNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::affine_native::AffineNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::affine_native::AffineNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::ntt_native::NttNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::ntt_native::NttNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::ntt_native::NttNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::mul_native::MulNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::mul_native::MulNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::mul_native::MulNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::g_bound_native::GBoundNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::g_bound_native::GBoundNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::g_bound_native::GBoundNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::permutation_native::PermutationNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::permutation_native::PermutationNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::permutation_native::PermutationNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperation<'static, 'static>, crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperationFailure>>(),
        size_of::<crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::source_native::OwnedSourceNativeOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::source_native::OwnedSourceNativeOutput<'static>>)>(),
        size_of::<owned_parent::NativeLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::NativeLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::native_sources::OwnedCompiledSource<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::native_sources::OwnedCompiledSource<'static, 'static, 'static>>)>(),
        size_of::<crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::affine_native::OwnedAffineOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::affine_native::OwnedAffineOutput<'static>>)>(),
        size_of::<owned_parent::AffineLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::AffineLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::affine_sources::OwnedCompiledAffine<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::affine_sources::OwnedCompiledAffine<'static, 'static, 'static>>)>(),
        size_of::<crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::ntt_native::OwnedNttOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::ntt_native::OwnedNttOutput<'static>>)>(),
        size_of::<owned_parent::NttLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::NttLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::ntt_sources::OwnedCompiledNtt<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::ntt_sources::OwnedCompiledNtt<'static, 'static, 'static>>)>(),
        size_of::<crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::mul_native::OwnedMulOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::mul_native::OwnedMulOutput<'static>>)>(),
        size_of::<owned_parent::MulLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::MulLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::mul_sources::OwnedCompiledMul<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::mul_sources::OwnedCompiledMul<'static, 'static, 'static>>)>(),
        size_of::<crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::g_bound_native::OwnedGBoundOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::g_bound_native::OwnedGBoundOutput<'static>>)>(),
        size_of::<owned_parent::GBoundLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::GBoundLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::g_bound_sources::OwnedCompiledGBound<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::g_bound_sources::OwnedCompiledGBound<'static, 'static, 'static>>)>(),
        size_of::<crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::permutation_native::OwnedPermutationOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::permutation_native::OwnedPermutationOutput<'static>>)>(),
        size_of::<owned_parent::PermutationLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::PermutationLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::permutation_sources::OwnedCompiledPermutation<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::permutation_sources::OwnedCompiledPermutation<'static, 'static, 'static>>)>(),
        size_of::<crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompileOperation<'static, 'static>>(),
        size_of::<Outcome<crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompileOperation<'static, 'static>, (crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::linear_map_native::OwnedLinearMapOutput<'static>>)>>(),
        size_of::<(crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompileFailure, RetainedNative<crate::spend_pipeline::full_workflow::linear_map_native::OwnedLinearMapOutput<'static>>)>(),
        size_of::<owned_parent::LinearMapLeafOuterOperation<'static, 'static, 'static>>(),
        size_of::<Outcome<owned_parent::LinearMapLeafOuterOperation<'static, 'static, 'static>, (owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::linear_map_sources::OwnedCompiledLinearMap<'static, 'static, 'static>>)>>(),
        size_of::<(owned_parent::GraphParentFailure, RetainedOriginal<crate::graph_tree::linear_map_sources::OwnedCompiledLinearMap<'static, 'static, 'static>>)>(),
    ])?;
    let cells = [
        cell_frames::<native_tables::SourceNativeResult<'static>>()?,
        cell_frames::<native_tables::SourceNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::UniformNativeResult<'static>>()?,
        cell_frames::<native_tables::UniformNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::SparseNativeResult<'static>>()?,
        cell_frames::<native_tables::SparseNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::TranscriptNativeResult<'static>>()?,
        cell_frames::<native_tables::TranscriptNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::AffineNativeResult<'static>>()?,
        cell_frames::<native_tables::AffineNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::NttNativeResult<'static>>()?,
        cell_frames::<native_tables::NttNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::MulNativeResult<'static>>()?,
        cell_frames::<native_tables::MulNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::GBoundNativeResult<'static>>()?,
        cell_frames::<native_tables::GBoundNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::PermutationNativeResult<'static>>()?,
        cell_frames::<native_tables::PermutationNativePreissueResult<'static, 'static>>()?,
        cell_frames::<native_tables::LinearMapNativeResult<'static>>()?,
        cell_frames::<native_tables::LinearMapNativePreissueResult<'static, 'static>>()?,
        cell_frames::<graph_tables::SourceCompiledResult<'static>>()?,
        cell_frames::<graph_tables::SourceOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<algebra_tables::AffineCompiledResult<'static>>()?,
        cell_frames::<algebra_tables::AffineOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<algebra_tables::NttCompiledResult<'static>>()?,
        cell_frames::<algebra_tables::NttOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<algebra_tables::MulCompiledResult<'static>>()?,
        cell_frames::<algebra_tables::MulOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<algebra_tables::GBoundCompiledResult<'static>>()?,
        cell_frames::<algebra_tables::GBoundOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<algebra_tables::PermutationCompiledResult<'static>>()?,
        cell_frames::<algebra_tables::PermutationOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<algebra_tables::LinearMapCompiledResult<'static>>()?,
        cell_frames::<algebra_tables::LinearMapOuterPreissueResult<'static, 'static, 'static>>()?,
        cell_frames::<graph_tables::GraphOuterResult<'static>>()?,
    ].into_iter().try_fold(0usize, |total, bytes| total.checked_add(bytes).ok_or(WorkflowError::Overflow))?;
    fixed.checked_add(cells).ok_or(WorkflowError::Overflow)
}
