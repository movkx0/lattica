use super::*;
use crate::component_tree::native_shape::framing;
pub(super) fn frames() -> OwnedResult<usize> {
    [bytes::<FixedLeafOuterPlan<'static, 'static>>(8)?,
        bytes::<FixedLeafOuterOperation<'static, 'static, 'static>>(8)?,
        bytes::<CompiledFixedSources<'static>>(8)?, bytes::<Retained<CompiledFixedSources<'static>>>(8)?,
        bytes::<(GraphParentFailure, Retained<CompiledFixedSources<'static>>)>(8)?,
        bytes::<core::result::Result<FixedLeafOuterOperation<'static, 'static, 'static>, (GraphParentFailure, Retained<CompiledFixedSources<'static>>)>>(8)?,
        bytes::<OwnedResult<FixedLeafOuterOperation<'static, 'static, 'static>>>(8)?,
        bytes::<core::result::Result<PreissuedFixedLeafOuter<'static, 'static, 'static>, crate::execution::workflow_resources::WorkflowError>>(8)?,
        bytes::<FixedSourceCompilePlan<'static>>(8)?, bytes::<FixedSourceCensus>(8)?,
        bytes::<GraphNodeSource<'static>>(8)?, bytes::<GraphNodeReport>(8)?,
        bytes::<GraphChildSource<'static, 'static>>(8)?, bytes::<OwnedGraphNode<'static>>(8)?,
        bytes::<Retained<OwnedGraphNode<'static>>>(8)?,
        bytes::<OwnedResult<FixedLeafOuterPlan<'static, 'static>>>(8)?,
        bytes::<OwnedResult<OwnedGraphNode<'static>>>(8)?, bytes::<Sha3_256>(8)?,
        bytes::<Requirements>(16)?, bytes::<PhaseFacts>(8)?, bytes::<PhaseBinding>(8)?,
        bytes::<[usize; 24]>(8)?,
    ].into_iter().try_fold(64 << 10, add)
}
// Private source construction only; the actual issuer must borrow the exact
// SourceOperationPlan and its retained PreparedWorkflowSources owner.
pub(super) fn derive<'a>(plan: &'a Plan, graph: &UnprovedRelationGraph, context: &'a GraphContext,
    census: FixedSourceCensus, compiler_source: [u8; 32], compiled_source_fingerprint: [u8; 32],
) -> OwnedResult<GraphNodeSource<'a>> {
    let leaf = plan.leaves().first().ok_or(GraphParentFailure::Coverage)?;
    if leaf.kind() != &LeafKind::FixedSources || !leaf.operation_indices().is_empty() {
        return Err(GraphParentFailure::Coverage);
    }
    let fixed_roots = add(leaf.polynomial_indices().len(), leaf.byte_indices().len())?;
    let operations = framing::source_binding_initialization(graph.polynomials().len(), graph.bytes().len())
        .and_then(|n| n.with_overhead(framing::GRAPH_HEADER))
        .and_then(|n| n.with_overhead(framing::fixed_sources(fixed_roots)?))
        .map_err(|_| GraphParentFailure::Source)?;
    let maximum_active_rows = operations.active_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_wires = add(PUBLIC_VALUES, add(operations.scalar, mul(8, operations.poseidon)?)?)?;
    let maximum_inputs = mul(4, add(graph.polynomials().len(), graph.bytes().len())?)?;
    if maximum_padded_rows > super::super::source::MAX_ROWS || maximum_wires > census.construction.max_wires
        || maximum_inputs != census.construction.max_input_values || maximum_inputs > super::super::source::INPUT_VALUES
    { return Err(GraphParentFailure::Capacity); }
    let span = GraphSpan { first: 0, count: 1, level: 0 };
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/owned-fixed-source-graph-leaf/v1");
    hash.update(compiler_source); hash.update(compiled_source_fingerprint);
    hash.update(plan.label()); hash.update(context.context);
    for value in context.statement.into_iter().chain(context.node_manifest) { hash.update(value.as_canonical_u64().to_le_bytes()); }
    for value in [operations.scalar, operations.cubic, operations.poseidon, maximum_active_rows,
        maximum_padded_rows, maximum_wires, maximum_inputs, census.construction.max_requested_program_bytes]
    { hash.update(u64::try_from(value).map_err(|_| GraphParentFailure::Overflow)?.to_le_bytes()); }
    Ok(GraphNodeSource { plan, context, span, operations, maximum_active_rows, maximum_padded_rows,
        maximum_wires, maximum_inputs, maximum_hint_words: 0,
        source_fingerprint: hash.finalize().into(), compiled_source_fingerprint })
}
#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod tests;
