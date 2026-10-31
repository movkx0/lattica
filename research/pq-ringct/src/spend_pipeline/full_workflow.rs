//! Immutable source inventory for the owned complete-workflow implementation.
//! This module currently issues no phase, proof or transaction acceptance.
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod source_native;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use source_native::SourceNativeOperationPlan;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod source_native_compile;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod fresh_generation;
mod source_footprint;
pub(crate) use source_footprint::InitialNativeSource;

#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
mod source_graph;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use source_graph::{SourcePreparationError, SourceGraphPlan, SourceGraphOperation, PreparedGraphSources};
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
mod source_preparation;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use source_preparation::{SourcePreparationPlan, SourcePreparationOperation, PreparedWorkflowSources};
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
mod source_operations;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use source_operations::{SourceOperationPlan, SourceCompileOperation, CompiledFixedSources};
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use crate::graph_tree::fixed_sources::FixedSourceFailure;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
mod source_planning;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use source_planning::SourcePlanningPlan;

#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
mod closure_planning;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod closed_plan;
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use closure_planning::{SourceClosurePlanningPlan, ClosureInspection, ClosureError, UnavailableProducers};
#[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
pub(crate) use closed_plan::{ClosedWorkflowPlan, CryptoRequestPlan};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use closed_plan::ValidatedCompleteInventory;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod uniform_native;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod transcript_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod affine_native;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod sparse_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod affine_native_compile;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod ntt_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod ntt_native_compile;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod mul_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod mul_native_compile;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod g_bound_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod g_bound_native_compile;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod permutation_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod permutation_native_compile;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod linear_map_native;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod linear_map_native_compile;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod metadata_tables;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod metadata_planning;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod bootstrap_layers;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) mod driver;
