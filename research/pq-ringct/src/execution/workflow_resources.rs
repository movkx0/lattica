//! Resource ownership for the source-closed complete workflow.
//!
//! A source planning envelope is admitted before metadata allocation. Closing
//! that plan retains the same context ledger, preissues every reusable output
//! slot and the maximum simultaneous scratch envelope, and checks the complete
//! ordered lifetime schedule before any proving dispatch. Numeric facts alone
//! never construct an execution permit. There is no post-dispatch admission.
//!
//! Every returned payload and failure retains its original slot reservation.
//! Slots return to the pool only after payload destruction; slots returned
//! during an operation additionally wait for actual prepared release and queue
//! retirement. Cleanup failure poisons the pool and preserves original claims.
//! Reusable public preparation remains single-entry and is released at each
//! operation boundary. The existing combined64MiB registry allowance is charged
//! once, including its identity-receipt sublimit and bounded telemetry.

mod owners;
mod planning;
mod runtime;
mod source;
mod source_endpoints;
mod types;

pub(crate) use owners::{PhaseFailure, Retained, RetainedFailure, RetainedNative, RetainedOriginal};
pub(crate) use planning::WorkflowPlanning;
#[cfg(not(debug_assertions))]
pub(crate) use planning::{PlanningAdmissionTransition, PlanningAdmissionProjection};
#[cfg(all(test, not(debug_assertions)))]
pub(crate) use planning::GuardedPlanningOriginal;
#[cfg(not(debug_assertions))]
pub(crate) use planning::{producer_metadata_retained_requirements,
    producer_metadata_inspection_requirements, producer_constructor_requirements,
    producer_constructor_retained_requirements, CompleteSlotFailure, CompleteSlotResult,
    FinalContractResult, FinalContractTable, FinalContractFailure, OwnedFinalContract};
pub(crate) use runtime::WorkflowCompletionReceipt;
#[cfg(feature = "identity-batch-experiment")]
pub(crate) use runtime::PairedIdentityPeers;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{source_native_issuer_scratch_requirements, source_native_packet_metadata_host_bytes, PreissuedSourceNative, source_native_compile_issuer_scratch_requirements};
pub(crate) use runtime::{
    aes_native_issuer_scratch_requirements, aes_native_packet_metadata_host_bytes, PreissuedAesNative,
    group_issuer_scratch_requirements,
    native_issuer_scratch_requirements, paired_native_packet_metadata_host_bytes,
    ExecutionAccess, OuterPreissueAccess, PreissuedPairedNative, WorkflowAdmission, WorkflowPhase,
};
pub(crate) use source::{
    SourceFailure, SourcePhaseFailure, SourcePreparationAccess, SourceRetained,
};
pub(crate) use source_endpoints::SourceEndpointAccess;
#[cfg(not(debug_assertions))]
pub(crate) use source_endpoints::METADATA_ENDPOINT_QUERY_FRAME_BYTES;
pub(crate) use types::{
    PhaseBinding, PhaseFacts, PhaseKind, PhaseStep, SlotId, SlotSpec, WorkflowError, VerificationBinding,
};

/// Allocation-free lower bound for controller/pool backing and fixed transport
/// frames. Source graph, caller vectors, payload/failure frames and allocator
/// reserve are additional enclosing/source-plan duties; the registry64MiB is
/// charged separately once. No allowance or execution authority is returned.
pub(crate) fn controller_bytes(slots: usize) -> Result<u64, WorkflowError> {
    use super::retained_resources::{Ledger, Reservation, Snapshot};
    use core::mem::size_of;
    let completion_frames = runtime::completion_host_bytes()?;
    let fixed = [
        size_of::<WorkflowPlanning<'_>>(),
        size_of::<planning::GuardedPlanningOriginal<'_>>(),
        size_of::<Option<planning::GuardedPlanningOriginal<'_>>>(),
        size_of::<Result<planning::GuardedPlanningOriginal<'_>, WorkflowError>>(),
        size_of::<WorkflowAdmission<'_, '_>>(),
        size_of::<WorkflowPhase<'_, '_, '_>>(),
        size_of::<ExecutionAccess<'_>>(),
        size_of::<PhaseFacts>(),
        size_of::<PhaseStep>(),
        size_of::<WorkflowError>(),
        size_of::<owners::SlotClaim>(),
        size_of::<Reservation>(),
        size_of::<Ledger>(),
        size_of::<std::cell::RefCell<Snapshot>>() + 2 * size_of::<usize>(),
    ];
    let frames = fixed
        .into_iter()
        .try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|sum| sum.checked_mul(4))
        .and_then(|sum| sum.checked_add(4 * size_of::<[usize; 11]>()))
        .and_then(|sum| sum.checked_add(super::phase_lifecycle::owned_partition::bookkeeping_bytes()))
        .and_then(|sum| sum.checked_add(super::phase_lifecycle::outer_partition::bookkeeping_bytes()))
        .and_then(|sum| sum.checked_add(runtime::preissue::bookkeeping_bytes()))
        .and_then(|sum| sum.checked_add(8 * size_of::<[Option<Reservation>; 4]>()))
        .and_then(|sum| sum.checked_add(completion_frames))
        .ok_or(WorkflowError::Overflow)?;
    // SlotPool backing owns a separate original in the admitted phase. Keep
    // this allowance for the admission/controller frames only.
    let _ = owners::SlotPool::bookkeeping_bytes(slots)?;
    u64::try_from(frames).map_err(|_| WorkflowError::Overflow)
}

/// The same source-owned pool backing that runtime preflight actually admits.
/// This query conveys no slot owner or replacement reservation.
pub(crate) fn closed_pool_requirements(slots: usize)
    -> Result<super::retained_resources::Requirements, WorkflowError>
{
    owners::SlotPool::bookkeeping_requirements(slots)
}

/// Retained control backing of each source operation, in addition to the
/// concrete source payload. Its pool survives as long as either source or
/// failure owner does, so this belongs in retained metadata, not phase scratch.
pub(crate) fn source_retained_overhead_bytes() -> Result<u64, WorkflowError> {
    let inline = core::mem::size_of::<owners::SlotClaim>()
        .checked_add(2 * core::mem::size_of::<[u8; 32]>())
        .and_then(|bytes| bytes.checked_add(2 * core::mem::size_of::<usize>()))
        .ok_or(WorkflowError::Overflow)?;
    // The pool now owns its bookkeeping claim independently of this payload.
    u64::try_from(inline).map_err(|_| WorkflowError::Overflow)
}

#[cfg(test)]
mod tests;

pub(crate) use runtime::{OwnedOuterScope, OuterOwnedError, owned_outer_forwarding_host_bytes};

mod closure_source;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{uniform_native_issuer_scratch_requirements, uniform_native_packet_metadata_host_bytes, PreissuedUniformNative};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{transcript_native_issuer_scratch_requirements, transcript_native_packet_metadata_host_bytes, PreissuedTranscriptNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{affine_native_issuer_scratch_requirements, affine_native_packet_metadata_host_bytes, PreissuedAffineNative};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{sparse_native_issuer_scratch_requirements, sparse_native_packet_metadata_host_bytes, PreissuedSparseNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{final_compile_issuer_requirements, final_verify_issuer_requirements,
    final_outer_forwarding_host_bytes, final_report_transport_host_bytes};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::affine_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{ntt_native_issuer_scratch_requirements, ntt_native_packet_metadata_host_bytes, PreissuedNttNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::ntt_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{mul_native_issuer_scratch_requirements, mul_native_packet_metadata_host_bytes, PreissuedMulNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::mul_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{g_bound_native_issuer_scratch_requirements, g_bound_native_packet_metadata_host_bytes, PreissuedGBoundNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::g_bound_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{permutation_native_issuer_scratch_requirements, permutation_native_packet_metadata_host_bytes, PreissuedPermutationNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::permutation_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::{linear_map_native_issuer_scratch_requirements, linear_map_native_packet_metadata_host_bytes, PreissuedLinearMapNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use runtime::linear_map_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use planning::{producer_table_transfer_requirements, TableTransferFailure, TableTransferResult};
