use super::*;
use crate::component_tree::native_shape::framing;
const PUBLICS: usize = 46;
const PREFIX: usize = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".len() + 32;
fn child_shape(height: usize) -> OwnedResult<RegisteredChildShape> {
    let mut shape = super::super::source::registered_shape(height)?;
    shape.public_values = PUBLICS;
    Ok(shape)
}
pub(super) fn frames() -> OwnedResult<usize> {
    [bytes::<ParametersPpGraphPlan<'static, 'static>>(8)?,
        bytes::<ParametersPpCompileOperation<'static, 'static, 'static>>(8)?,
        bytes::<ParametersPpOuterOperation<'static, 'static, 'static>>(8)?,
        bytes::<(GraphParentFailure, PairedRequestOutput<'static>)>(8)?,
        bytes::<core::result::Result<ParametersPpCompileOperation<'static, 'static, 'static>, (GraphParentFailure, PairedRequestOutput<'static>)>>(8)?,
        bytes::<(GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>(8)?,
        bytes::<core::result::Result<ParametersPpOuterOperation<'static, 'static, 'static>, (GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>>(8)?,
        bytes::<core::result::Result<PreissuedParametersPpOuter<'static, 'static, 'static>, crate::execution::workflow_resources::WorkflowError>>(8)?,
        bytes::<PairedRequestOutput<'static>>(8)?, bytes::<OwnedGraphCompiled<'static>>(8)?,
        bytes::<OwnedGraphNode<'static>>(8)?, bytes::<GraphNodeSource<'static>>(8)?,
        bytes::<GraphChildSource<'static, 'static>>(8)?, bytes::<GraphNodeReport>(8)?,
        bytes::<Retained<OwnedGraphCompiled<'static>>>(8)?, bytes::<Retained<OwnedGraphNode<'static>>>(8)?,
        bytes::<OwnedResult<OwnedGraphCompiled<'static>>>(8)?, bytes::<OwnedResult<OwnedGraphNode<'static>>>(8)?,
        bytes::<OwnedResult<ParametersPpGraphPlan<'static, 'static>>>(8)?,
        bytes::<Requirements>(16)?, bytes::<Sha3_256>(8)?, bytes::<PhaseFacts>(8)?,
        bytes::<PhaseBinding>(8)?, bytes::<PlanningStorage>(8)?, bytes::<FixedSourceCensus>(8)?,
        bytes::<crate::graph_tree::LeafArtifact<'static>>(8)?, bytes::<[usize; 24]>(8)?,
    ].into_iter().try_fold(64 << 10, add)
}
pub(super) fn planning_scratch_requirements() -> OwnedResult<Requirements> {
    let storage = PlanningStorage::for_children(0,
        &[child_shape(super::super::source::MAX_ROWS)?], super::super::source::construction())
        .map_err(|_| GraphParentFailure::Source)?;
    if storage.auxiliary_peak_bytes > super::super::source::AUXILIARY_BYTES {
        return Err(GraphParentFailure::Capacity);
    }
    requirement(Category::PhaseScratch, add(super::super::source::PROGRAM_BYTES,
        add(storage.auxiliary_peak_bytes, frames()?)?)?)
}
pub(super) fn validate_coverage(prepared: &PreparedWorkflowSources<'_>,
    request: &PairedRequestPlan<'_>, ordinal: usize,
) -> OwnedResult<()> {
    validate_request_leaf(prepared.plan(), prepared.graph(), prepared.crypto(), request.request(), ordinal)
}
fn validate_request_leaf(tree: &Plan, graph: &UnprovedRelationGraph,
    crypto: &crate::graph_crypto::Plan, actual: &crate::graph_crypto::Request, ordinal: usize,
) -> OwnedResult<()> {
    let operation = actual.operation_index();
    let leaf = tree.leaves().get(ordinal).ok_or(GraphParentFailure::Coverage)?;
    if !crypto.requests().iter().any(|known| core::ptr::eq(known, actual))
        || actual.subrequest() != 0
        || !matches!(actual.descriptor(), RequestDescriptor::Shake(value)
            if value.input_len == PREFIX + 32 && value.output_len == 32)
        || !matches!(graph.operations().get(operation), Some(Operation::ParametersPp { .. }))
        || leaf.kind() != &LeafKind::Operations(OperationFamily::ParametersPp)
        || leaf.operation_indices() != [operation]
        || !leaf.polynomial_indices().is_empty()
        || !leaf.byte_indices().iter().copied().eq(graph.bytes().iter().enumerate().filter_map(|(i, node)| {
            (matches!(node.source, Source::Context | Source::StatementSeed)
                || matches!(node.source, Source::Derived { operation: owner } if owner == operation)).then_some(i)
        }))
    { return Err(GraphParentFailure::Coverage); }
    Ok(())
}
pub(super) fn compiler_requirements(prepared: &PreparedWorkflowSources<'_>)
    -> OwnedResult<(Requirements, Requirements)>
{
    let storage = PlanningStorage::for_children(PUBLIC_VALUES,
        &[child_shape(super::super::source::MAX_ROWS)?], super::super::source::construction())
        .map_err(|_| GraphParentFailure::Source)?;
    let fixed = FixedSourceCensus::from_graph(prepared.graph()).map_err(|_| GraphParentFailure::Source)?;
    let graph = prepared.graph();
    let coverage = add(add(graph.polynomials().len(), graph.bytes().len())?, graph.operations().len())?;
    // group_coverage flags and geometrically grown ordered index vectors can
    // coexist with SourceBinding's own root/coverage backing. The single artifact
    // Vec, public prefix/context/digest bytes and byte-wire bridges are additive.
    let group = add(mul(coverage, add(2 * size_of::<bool>(), 4 * size_of::<usize>())?)?,
        bytes::<Vec<usize>>(16)?)?;
    let byte_count = mul(4, add(PREFIX, 64)?)?;
    let dynamic = [group, bytes::<lattica_prover_p3::block_v2::machine::pq_bytes::Byte>(byte_count)?,
        bytes::<u8>(byte_count)?, bytes::<Wire>(byte_count)?,
        bytes::<Vec<crate::graph_tree::LeafArtifact<'static>>>(8)?,
        bytes::<crate::graph_tree::LeafArtifact<'static>>(2)?, frames()?]
        .into_iter().try_fold(0, add)?;
    let auxiliary = [storage.auxiliary_peak_bytes, fixed.source_scratch_bytes, fixed.frame_bytes, dynamic]
        .into_iter().try_fold(0, add)?;
    if auxiliary > super::super::source::AUXILIARY_BYTES { return Err(GraphParentFailure::Capacity); }
    Ok((combine(&[
        requirement(Category::SymbolicCompiler, add(super::super::source::PROGRAM_BYTES,
            bytes::<OwnedGraphCompiled<'static>>(8)?)?)?,
        requirement(Category::CompilerInputs, add(storage.input_backing_bytes,
            bytes::<Val>(2 * PUBLIC_VALUES)?)?)?,
    ])?, requirement(Category::PhaseScratch, auxiliary)?))
}
pub(super) fn derive<'a>(prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    request: &PairedRequestPlan<'a>, ordinal: usize,
) -> OwnedResult<GraphNodeSource<'a>> {
    let root = request.root_source();
    if root.public_values != PUBLICS || root.maximum_padded_rows > super::super::source::MAX_ROWS {
        return Err(GraphParentFailure::Source);
    }
    let envelope = shape::verifier_height_envelope(PUBLICS, root.maximum_padded_rows,
        super::super::source::construction(), super::super::source::AUXILIARY_BYTES)
        .map_err(|_| GraphParentFailure::Source)?;
    let graph = prepared.get().graph();
    let framing = framing::source_binding_initialization(graph.polynomials().len(), graph.bytes().len())
        .and_then(|n| n.with_overhead(framing::GRAPH_HEADER))
        .and_then(|n| n.with_overhead(framing::parameters_pp_consumer()?))
        .map_err(|_| GraphParentFailure::Source)?;
    let operations = envelope.operations.with_overhead(framing).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_active_rows = operations.active_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_wires = add(envelope.wire_upper_bound,
        add(PUBLIC_VALUES, add(framing.scalar, mul(8, framing.poseidon)?)?)?)?;
    let roots = mul(4, add(graph.polynomials().len(), graph.bytes().len())?)?;
    // ParametersPp opens exactly32 context and32 digest bytes. The envelope
    // additionally counts opaque cap Inputs that real trusted caps may replace.
    let maximum_inputs = add(envelope.input_values_upper_bound, add(roots, 64)?)?;
    if maximum_padded_rows > super::super::source::MAX_ROWS || maximum_wires > MAX_WIRES
        || maximum_inputs > super::super::source::INPUT_VALUES
    { return Err(GraphParentFailure::Capacity); }
    let plan = prepared.get().plan(); let context = prepared.get().context();
    let span = GraphSpan { first: u32::try_from(ordinal).map_err(|_| GraphParentFailure::Overflow)?, count: 1, level: 0 };
    let compiled_source_fingerprint = prepared.compiled_source_fingerprint();
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/owned-parameters-pp-graph-source/v1");
    hash.update(compiled_source_fingerprint); hash.update(prepared.source_fingerprint());
    hash.update(prepared.get().native_identity()); hash.update(request.source_fingerprint());
    hash.update(plan.label()); hash.update(context.context);
    for value in context.statement.into_iter().chain(context.node_manifest) { hash.update(value.as_canonical_u64().to_le_bytes()); }
    for value in [ordinal, root.maximum_padded_rows, operations.scalar, operations.cubic, operations.poseidon,
        maximum_active_rows, maximum_padded_rows, maximum_wires, maximum_inputs,
        envelope.selection_hint_words_upper_bound]
    { hash.update(u64::try_from(value).map_err(|_| GraphParentFailure::Overflow)?.to_le_bytes()); }
    Ok(GraphNodeSource { plan, context, span, operations, maximum_active_rows, maximum_padded_rows,
        maximum_wires, maximum_inputs, maximum_hint_words: envelope.selection_hint_words_upper_bound,
        source_fingerprint: hash.finalize().into(), compiled_source_fingerprint })
}

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod tests;
