use super::*;
use crate::component_tree::native_shape::framing;
pub(super) fn frames() -> OwnedResult<usize> {
    [bytes::<EqualityGraphPlan<'static, 'static>>(8)?, bytes::<OwnedResult<EqualityGraphPlan<'static, 'static>>>(8)?,
        bytes::<EqualityCompileOperation<'static, 'static, 'static>>(8)?,
        bytes::<EqualityOuterOperation<'static, 'static, 'static>>(8)?,
        bytes::<(GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>(8)?,
        bytes::<core::result::Result<EqualityOuterOperation<'static, 'static, 'static>, (GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>>(8)?,
        bytes::<core::result::Result<PreissuedEqualityOuter<'static, 'static, 'static>, crate::execution::workflow_resources::WorkflowError>>(8)?,
        bytes::<Option<EqualityOuterOperation<'static, 'static, 'static>>>(8)?,
        bytes::<EqualityDependencies>(8)?, bytes::<OwnedResult<EqualityDependencies>>(8)?,
        bytes::<FixedSourceCensus>(8)?, bytes::<OwnedResult<FixedSourceCensus>>(8)?,
        bytes::<GraphNodeSource<'static>>(8)?, bytes::<GraphChildSource<'static, 'static>>(8)?,
        bytes::<OwnedGraphNode<'static>>(8)?, bytes::<Option<OwnedGraphNode<'static>>>(8)?,
        bytes::<OwnedGraphCompiled<'static>>(8)?, bytes::<OwnedResult<OwnedGraphCompiled<'static>>>(8)?,
        bytes::<Retained<OwnedGraphCompiled<'static>>>(8)?, bytes::<PhaseFacts>(8)?,
        bytes::<PhaseBinding>(8)?, bytes::<Requirements>(16)?, bytes::<Sha3_256>(8)?,
        bytes::<SourceBinding<'static, 'static, 'static>>(8)?, bytes::<operations::WipedInputs>(8)?,
        super::super::memory::caller_frames()?,
    ].into_iter().try_fold(64 << 10, add)
}
pub(super) fn validate_leaf(tree: &Plan, graph: &UnprovedRelationGraph, ordinal: usize) -> OwnedResult<usize> {
    let leaf = tree.leaves().get(ordinal).ok_or(GraphParentFailure::Coverage)?;
    if leaf.kind() != &LeafKind::Operations(OperationFamily::Equality) || leaf.operation_indices().len() != 1
        || !leaf.polynomial_indices().is_empty() { return Err(GraphParentFailure::Coverage); }
    let operation = leaf.operation_indices()[0];
    if !matches!(graph.operations().get(operation), Some(Operation::EqualBytes { .. } | Operation::EqualSigned { .. }))
        || graph.polynomials().iter().any(|node| matches!(node.source, Source::Derived { operation: owner } if owner == operation))
        || graph.bytes().iter().any(|node| matches!(node.source, Source::Derived { operation: owner } if owner == operation))
        || !leaf.byte_indices().iter().copied().eq(graph.bytes().iter().enumerate().filter_map(|(i, node)|
            matches!(node.source, Source::Context | Source::StatementSeed).then_some(i))) {
        return Err(GraphParentFailure::Coverage);
    }
    Ok(operation)
}
pub(super) fn compiler_requirements(census: FixedSourceCensus) -> OwnedResult<(Requirements, Requirements)> {
    let scratch = [census.source_scratch_bytes, census.frame_bytes, frames()?].into_iter().try_fold(0, add)?;
    if scratch > super::super::source::AUXILIARY_BYTES { return Err(GraphParentFailure::Capacity); }
    Ok((combine(&[
        requirement(Category::SymbolicCompiler, add(census.construction.max_requested_program_bytes,
            bytes::<OwnedGraphCompiled<'static>>(8)?)?)?,
        requirement(Category::CompilerInputs, add(census.input_bytes, bytes::<Val>(2 * PUBLIC_VALUES)?)?)?,
    ])?, requirement(Category::PhaseScratch, scratch)?))
}
pub(super) fn derive<'a>(plan: &'a Plan, graph: &UnprovedRelationGraph, context: &'a GraphContext,
    ordinal: usize, workflow: [u8; 32], compiled_source_fingerprint: [u8; 32]) -> OwnedResult<GraphNodeSource<'a>> {
    let operation = validate_leaf(plan, graph, ordinal)?;
    let operations = framing::source_binding_initialization(graph.polynomials().len(), graph.bytes().len())
        .and_then(|n| n.with_overhead(framing::GRAPH_HEADER))
        .and_then(|n| n.with_overhead(framing::EQUALITY)).map_err(|_| GraphParentFailure::Source)?;
    let maximum_active_rows = operations.active_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_wires = add(PUBLIC_VALUES, add(operations.scalar, mul(8, operations.poseidon)?)?)?;
    let maximum_inputs = mul(4, add(graph.polynomials().len(), graph.bytes().len())?)?;
    if maximum_padded_rows > super::super::source::MAX_ROWS || maximum_wires > MAX_WIRES
        || maximum_inputs > super::super::source::INPUT_VALUES { return Err(GraphParentFailure::Capacity); }
    let span = GraphSpan { first: u32::try_from(ordinal).map_err(|_| GraphParentFailure::Overflow)?, count: 1, level: 0 };
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/owned-equality-graph-source/v1"); hash.update(workflow);
    hash.update(compiled_source_fingerprint); hash.update(plan.label()); hash.update(context.context);
    for value in context.statement.into_iter().chain(context.node_manifest) { hash.update(value.as_canonical_u64().to_le_bytes()); }
    for value in [ordinal, operation, operations.scalar, operations.poseidon,
        maximum_active_rows, maximum_padded_rows, maximum_wires, maximum_inputs]
    { hash.update(u64::try_from(value).map_err(|_| GraphParentFailure::Overflow)?.to_le_bytes()); }
    Ok(GraphNodeSource { plan, context, span, operations, maximum_active_rows, maximum_padded_rows,
        maximum_wires, maximum_inputs, maximum_hint_words: 0, source_fingerprint: hash.finalize().into(), compiled_source_fingerprint })
}

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod tests;
