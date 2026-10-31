//! Bounded consuming-graph adapter. Full source closure and the concrete graph
//! phase still belong to the enclosing workflow planner. This module exposes
//! no raw owner attachment, proof dispatch, or numeric admission constructor.
use super::*;
use crate::{
    execution::workflow_resources::ExecutionAccess,
    graph_crypto::{PairedRequestOutput, PairedRequestPlan},
};
use lattica_prover_p3::block_v2::machine::program::ConstructionLimits;

/// Borrow the actual retained request root only after checking its exact
/// original request plan, context and workflow pool. The consuming operation
/// owns `output` (and every other source proof) for this borrow's whole life.
pub(crate) fn shake_artifact<'a>(
    output: &'a PairedRequestOutput<'_>, request: &PairedRequestPlan<'_>,
    context: &GraphContext, access: &ExecutionAccess<'_>,
) -> Result<ShakeProof<'a>> {
    Ok(ShakeProof::BoundedTree(leaf::BoundedShakeTree::from_owned(output, request, context, access)?))
}

/// The AES family has a separate concrete source/owner check before exposing
/// the same bounded recursive verification relation to a consuming graph.
pub(crate) fn aes_artifact<'a>(
    output: &'a crate::graph_crypto::OwnedAesRequestOutput<'_>,
    request: &crate::graph_crypto::OwnedAesRequestPlan<'_>,
    context: &GraphContext, access: &ExecutionAccess<'_>,
) -> Result<AesProof<'a>> {
    Ok(AesProof::BoundedTree(leaf::BoundedAesTree::from_owned(output, request, context, access)?))
}

/// Reuses the maintained leaf compiler, including exact registered coverage,
/// SourceBinding and producer joins. The caller has already reserved compiler
/// inputs/temporary native verifier storage and owns the consumed artifacts.
/// Source-derived wire/input/program limits apply before each allocation.
pub(crate) fn compile_group(
    plan: &Plan, graph: &UnprovedRelationGraph, first: usize, context: &GraphContext,
    artifacts: Vec<LeafArtifact<'_>>, limits: ConstructionLimits, access: &ExecutionAccess<'_>,
) -> Result<CompiledNode> {
    if access.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired {
        return Err(Error("owned graph compilation requires GPU workflow admission".into()));
    }
    leaf::compile_group_bounded(plan, graph, first, context, artifacts, limits)
}
