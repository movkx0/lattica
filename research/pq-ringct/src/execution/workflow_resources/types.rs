use super::super::{
    phase_lifecycle,
    retained_resources::{Bytes, Category, Error as QuotaError, Requirements},
};
use crate::graph_crypto::PairedRequestPlan;

pub(super) const REGISTRY_BYTES: u64 = 64 << 20;
pub(super) const MAX_HOST_BYTES: u64 = 32 << 30;
pub(super) const MAX_DEVICE_BYTES: u64 = 8 << 30;
pub(super) const MAX_NATIVE_BYTES: u64 = 24 << 30;

/// Closed source-operation families; these do not select a different protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) enum PhaseKind {
    EndpointPrepare,
    EndpointAttach,
    Native,
    GroupCompile,
    ParentCompile,
    OuterProve,
    GraphLeafCompile,
    GraphParentCompile,
    GraphProve,
    AggregateCompile,
    AggregateProve,
    IndependentVerify,
    SourceCompile,
    SourceNative,
    AffineNative,
    PermutationNative,
    LinearMapNative,
    GBoundNative,
    NttNative,
    MulNative,
    UniformNative,
    TranscriptNative,
    SparseNative,
    SourceNativeCompile,
    SourceOuter,
    AlgebraCompile,
    AlgebraOuter,
    AesNative,
    AesCompile,
    AesOuter,
    GraphNative,
    GraphCompile,
    GraphOuter,
    GraphMerge,
    FinalCompile,
    FinalOuter,
    FinalVerify,
}

impl PhaseKind {
    pub(super) fn is_native(self) -> bool {
        matches!(self, Self::Native | Self::AesNative | Self::GraphNative | Self::SourceNative | Self::UniformNative | Self::TranscriptNative | Self::AffineNative | Self::GBoundNative | Self::NttNative | Self::SparseNative | Self::MulNative | Self::PermutationNative | Self::LinearMapNative)
    }

    pub(super) fn is_preparation(self) -> bool {
        matches!(self, Self::EndpointPrepare | Self::GroupCompile | Self::FinalCompile)
    }

    pub(super) fn requires_gpu_backend(self) -> bool {
        self.is_native()
            || self.is_preparation()
            || matches!(
                self,
                Self::OuterProve
                    | Self::GraphProve
                    | Self::AggregateProve
                    | Self::SourceOuter
                    | Self::AlgebraOuter
                    | Self::AesOuter
                    | Self::GraphOuter
                    | Self::FinalOuter
            )
    }
}

/// Allocation-free source facts, never authority by themselves. Scratch is
/// NON-backend temporary storage; the independent engine allowance is carried
/// by PhaseStep.backend. Success and failure have independently reserved slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhaseFacts {
    pub(crate) kind: PhaseKind,
    pub(crate) compiled_source_fingerprint: [u8; 32],
    /// Exact immutable operation/request binding, distinct from code identity.
    pub(crate) source_fingerprint: [u8; 32],
    pub(crate) output: Requirements,
    pub(crate) failure: Requirements,
    pub(crate) scratch: Requirements,
}

/// Exact source-plan identity plus its frozen operation facts. The address is
/// compared, never dereferenced. ClosedWorkflowPlan retains the immutable plan
/// borrow, preventing address reuse during admission and all execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhaseBinding {
    owner: *const (),
    ordinal: usize,
    facts: PhaseFacts,
}

/// Fixed diagnostic identity copied from the exact immutable binding. This has
/// no owner pointer, reservation, or phase authority and cannot admit execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct VerificationBinding {
    pub(crate) kind: PhaseKind,
    pub(crate) ordinal: usize,
    pub(crate) source_fingerprint: [u8; 32],
    pub(crate) compiled_source_fingerprint: [u8; 32],
}

/// Additive caller/return/serde scalar frames for fixed binding observations.
/// Every native/outer issuer adds this before its first epoch operation.
pub(super) fn verification_binding_frame_bytes() -> Result<usize, WorkflowError> {
    use core::mem::size_of;
    [size_of::<VerificationBinding>(), size_of::<PhaseBinding>(), size_of::<PhaseFacts>(),
        size_of::<Option<u128>>(), size_of::<[&(); 8]>(), size_of::<[usize; 8]>(),
        size_of::<[u8; 32]>(), size_of::<Result<(), WorkflowError>>()]
        .into_iter().try_fold(0usize, |sum, part| sum.checked_add(part))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)
}

impl PhaseBinding {
    pub(crate) fn verification_binding(&self) -> VerificationBinding {
        VerificationBinding { kind: self.facts.kind, ordinal: self.ordinal,
            source_fingerprint: self.facts.source_fingerprint,
            compiled_source_fingerprint: self.facts.compiled_source_fingerprint }
    }
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_final(plan: &crate::ordered_aggregation::owned_final::FinalPhasePlan<'_>, ordinal: usize)
        -> Result<Self, WorkflowError>
    {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::ordered_aggregation::owned_final::FinalPhasePlan<'_> as *const (),
            ordinal, facts })
    }

    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_uniform_native(
        plan: &crate::spend_pipeline::full_workflow::uniform_native::UniformNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self {
            owner: plan as *const crate::spend_pipeline::full_workflow::uniform_native::UniformNativeOperationPlan<'_> as *const (),
            ordinal, facts,
        })
    }
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_transcript_native(
        plan: &crate::spend_pipeline::full_workflow::transcript_native::TranscriptNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self {
            owner: plan as *const crate::spend_pipeline::full_workflow::transcript_native::TranscriptNativeOperationPlan<'_> as *const (),
            ordinal, facts,
        })
    }
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_sparse_native(
        plan: &crate::spend_pipeline::full_workflow::sparse_native::SparseNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self {
            owner: plan as *const crate::spend_pipeline::full_workflow::sparse_native::SparseNativeOperationPlan<'_> as *const (),
            ordinal, facts,
        })
    }

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_fixed_leaf_outer(
        plan: &crate::graph_tree::owned_parent::FixedLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::FixedLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_auxiliary_graph(
        plan: &crate::graph_tree::owned_parent::AuxiliaryGraphPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::AuxiliaryGraphPlan<'_, '_> as *const (), ordinal, facts })
    }

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_equality_graph(
        plan: &crate::graph_tree::owned_parent::EqualityGraphPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::EqualityGraphPlan<'_, '_> as *const (), ordinal, facts })
    }

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_parameters_pp_graph(
        plan: &crate::graph_tree::owned_parent::ParametersPpGraphPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::ParametersPpGraphPlan<'_, '_> as *const (), ordinal, facts })
    }

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_source_native(plan: &crate::spend_pipeline::full_workflow::SourceNativeOperationPlan<'_>, ordinal: usize) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::SourceNativeOperationPlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_source_native_compile(plan: &crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompilePlan<'_>, ordinal: usize) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::source_native_compile::SourceNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_graph_parent(plan: &crate::graph_tree::owned_parent::GraphParentPlan<'_, '_>, ordinal: usize) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::GraphParentPlan<'_, '_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_native_leaf_outer(plan: &crate::graph_tree::owned_parent::NativeLeafOuterPlan<'_, '_>, ordinal: usize) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::NativeLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }

    pub(crate) fn for_aes(
        plan: &crate::graph_crypto::OwnedAesRequestPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self {
            owner: plan as *const crate::graph_crypto::OwnedAesRequestPlan<'_> as *const (),
            ordinal,
            facts,
        })
    }

    pub(crate) fn for_paired(
        plan: &PairedRequestPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self {
            owner: plan as *const PairedRequestPlan<'_> as *const (),
            ordinal,
            facts,
        })
    }

    pub(crate) fn kind(self) -> PhaseKind {
        self.facts.kind
    }

    pub(crate) fn for_source(
        plan: &crate::spend_pipeline::full_workflow::SourceOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self {
            owner: plan as *const crate::spend_pipeline::full_workflow::SourceOperationPlan<'_>
                as *const (),
            ordinal,
            facts,
        })
    }

    pub(crate) fn ordinal(self) -> usize {
        self.ordinal
    }

    pub(crate) fn facts(self) -> PhaseFacts {
        self.facts
    }

    #[cfg(test)]
    pub(super) fn fixture(kind: PhaseKind) -> Self {
        Self {
            owner: core::ptr::null(),
            ordinal: 0,
            facts: PhaseFacts {
                kind,
                compiled_source_fingerprint: [0; 32],
                source_fingerprint: [1; 32],
                output: Requirements::default(),
                failure: Requirements::default(),
                scratch: Requirements::default(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotId(usize);

impl SlotId {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

/// A fixed original reservation, reusable only after payload and backend death.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotSpec {
    pub(crate) requirements: Requirements,
}

/// An immutable source-derived lifetime edge in the complete graph. Inputs
/// index a flat preadmitted SlotId slice, not a newly allocated per-phase list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhaseStep {
    pub(crate) binding: PhaseBinding,
    pub(crate) output: SlotId,
    pub(crate) failure: SlotId,
    pub(crate) input_start: usize,
    pub(crate) input_count: usize,
    /// Prefix of the input range consumed by this operation. Remaining inputs
    /// are immutable borrows that must remain owned across the cleanup barrier.
    pub(crate) consume_count: usize,
    pub(crate) backend: Bytes,
}

/// Fixed inline errors: no diagnostic String or detached report escapes a
/// resource scope. Backend-owned diagnostics die while its scratch is charged.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WorkflowError {
    Policy,
    Source,
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    AuxiliarySource(crate::graph_tree::owned_parent::GraphParentFailure),
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    CompleteSource {
        stage: crate::spend_pipeline::full_workflow::closed_plan::CompleteStage,
        cause: crate::spend_pipeline::full_workflow::ClosureError,
    },
    Identity,
    Enclosing,
    Planning,
    Allocation,
    Empty,
    Slot,
    SlotBusy,
    SlotAuthority,
    Sequence,
    Incomplete,
    Retired,
    Poisoned,
    BackendAllowance,
    Overflow,
    Quota(QuotaError),
    Lifecycle(phase_lifecycle::Error),
}

impl From<QuotaError> for WorkflowError {
    fn from(value: QuotaError) -> Self {
        Self::Quota(value)
    }
}

impl From<phase_lifecycle::Error> for WorkflowError {
    fn from(value: phase_lifecycle::Error) -> Self {
        Self::Lifecycle(value)
    }
}

impl core::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "complete workflow resources: {self:?}")
    }
}

impl std::error::Error for WorkflowError {}

pub(super) fn combine(a: Requirements, b: Requirements) -> Result<Requirements, WorkflowError> {
    let mut result = a;
    for category in Category::ALL {
        result.add(category, b.get(category))?;
    }
    Ok(result)
}

pub(super) fn contains(envelope: Requirements, requested: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let limit = envelope.get(category);
        let bytes = requested.get(category);
        bytes.host <= limit.host && bytes.device <= limit.device
    })
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_affine_native(
        plan: &crate::spend_pipeline::full_workflow::affine_native::AffineNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::affine_native::AffineNativeOperationPlan<'_> as *const (),
            ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_affine_native_compile(
        plan: &crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompilePlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::affine_native_compile::AffineNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_affine_leaf_outer(
        plan: &crate::graph_tree::owned_parent::AffineLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::AffineLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_ntt_native(
        plan: &crate::spend_pipeline::full_workflow::ntt_native::NttNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::ntt_native::NttNativeOperationPlan<'_> as *const (),
            ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_ntt_native_compile(
        plan: &crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompilePlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::ntt_native_compile::NttNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_ntt_leaf_outer(
        plan: &crate::graph_tree::owned_parent::NttLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::NttLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_mul_native(
        plan: &crate::spend_pipeline::full_workflow::mul_native::MulNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::mul_native::MulNativeOperationPlan<'_> as *const (),
            ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_mul_native_compile(
        plan: &crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompilePlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::mul_native_compile::MulNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_mul_leaf_outer(
        plan: &crate::graph_tree::owned_parent::MulLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::MulLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_g_bound_native_compile(
        plan: &crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompilePlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::g_bound_native_compile::GBoundNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_g_bound_leaf_outer(
        plan: &crate::graph_tree::owned_parent::GBoundLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::GBoundLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_g_bound_native(
        plan: &crate::spend_pipeline::full_workflow::g_bound_native::GBoundNativeOperationPlan<'_>,
        ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::g_bound_native::GBoundNativeOperationPlan<'_> as *const (),
            ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_permutation_native(
        plan: &crate::spend_pipeline::full_workflow::permutation_native::PermutationNativeOperationPlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::permutation_native::PermutationNativeOperationPlan<'_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_permutation_native_compile(
        plan: &crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompilePlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_permutation_leaf_outer(
        plan: &crate::graph_tree::owned_parent::PermutationLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::PermutationLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_linear_map_native(
        plan: &crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperationPlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::linear_map_native::LinearMapNativeOperationPlan<'_> as *const (), ordinal, facts })
    }
}

impl PhaseBinding {
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_linear_map_native_compile(
        plan: &crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompilePlan<'_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::spend_pipeline::full_workflow::linear_map_native_compile::LinearMapNativeCompilePlan<'_> as *const (), ordinal, facts })
    }
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn for_linear_map_leaf_outer(
        plan: &crate::graph_tree::owned_parent::LinearMapLeafOuterPlan<'_, '_>, ordinal: usize,
    ) -> Result<Self, WorkflowError> {
        let facts = plan.phase_facts(ordinal).ok_or(WorkflowError::Source)?;
        Ok(Self { owner: plan as *const crate::graph_tree::owned_parent::LinearMapLeafOuterPlan<'_, '_> as *const (), ordinal, facts })
    }
}
