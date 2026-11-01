//! Complete closed-source compiler bounds, before any template allocation.
use super::*;
use crate::component_tree::native_shape::{self, framing, NativePlanningStorage, NativeCoreBound, NativeDescriptor};
const REQUEST_PUBLICS: usize = crate::component_tree::HEADER + 8;
fn sum(parts: impl IntoIterator<Item = usize>) -> OwnedResult<usize> { parts.into_iter().try_fold(0, add) }
fn child_shape(height: usize) -> OwnedResult<RegisteredChildShape> {
    let mut shape = super::super::source::registered_shape(height)?;
    shape.public_values = REQUEST_PUBLICS;
    Ok(shape)
}
/// Include the pure compiler helper's forwarding/result frames both in the
/// bootstrap inspection reservation and in the eventual compiler scratch.
fn compiler_requirement_frame_bytes() -> OwnedResult<usize> {
    sum([
        bytes::<&UnprovedRelationGraph>(8)?, bytes::<&FixedSourceCensus>(8)?,
        bytes::<FixedSourceCensus>(8)?, bytes::<AuxiliaryGraphKind>(8)?,
        bytes::<OwnedResult<(Requirements, Requirements)>>(8)?,
        bytes::<[usize; 16]>(8)?, bytes::<Requirements>(8)?,
    ])
}
pub(super) fn frames() -> OwnedResult<usize> {
    [bytes::<AuxiliaryGraphPlan<'static, 'static>>(8)?,
        bytes::<AuxiliaryPreparedInventory<'static>>(8)?,
        bytes::<OwnedResult<AuxiliaryPreparedInventory<'static>>>(8)?,
        bytes::<[Option<&crate::graph_crypto::Request>; 2]>(8)?,
        bytes::<[Option<&crate::graph_auxiliary::AuxiliaryRequest>; 2]>(8)?,
        bytes::<[Option<NativeDescriptor<'static>>; 2]>(8)?,
        bytes::<[native_shape::cohort::Descriptor<'static>; 2]>(8)?,
        bytes::<[Option<NativeCoreBound>; native_shape::cohort::MAX]>(8)?,
        bytes::<OwnedResult<[Option<NativeDescriptor<'static>>; 2]>>(8)?,
        bytes::<OwnedResult<&crate::graph_crypto::Request>>(8)?,
        bytes::<OwnedResult<&crate::graph_auxiliary::AuxiliaryRequest>>(8)?,
        bytes::<OwnedResult<Requirements>>(8)?,
        bytes::<AuxiliaryGraphSources<'static, 'static>>(8)?,
        bytes::<AuxiliaryGraphOutputs<'static>>(8)?, bytes::<Option<AuxiliaryGraphOutputs<'static>>>(8)?,
        bytes::<AuxiliaryCompileOperation<'static, 'static, 'static>>(8)?,
        bytes::<(GraphParentFailure, AuxiliaryGraphOutputs<'static>)>(8)?,
        bytes::<core::result::Result<AuxiliaryCompileOperation<'static, 'static, 'static>, (GraphParentFailure, AuxiliaryGraphOutputs<'static>)>>(8)?,
        bytes::<(GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>(8)?,
        bytes::<core::result::Result<AuxiliaryOuterOperation<'static, 'static, 'static>, (GraphParentFailure, Retained<OwnedGraphCompiled<'static>>)>>(8)?,
        bytes::<core::result::Result<PreissuedAuxiliaryOuter<'static, 'static, 'static>, crate::execution::workflow_resources::WorkflowError>>(8)?,
        bytes::<(GraphParentFailure, OwnedAesRequestOutput<'static>, RetainedNative<OwnedUniformOutput<'static>>)>(8)?,
        bytes::<core::result::Result<AuxiliaryCompileOperation<'static, 'static, 'static>, (GraphParentFailure, OwnedAesRequestOutput<'static>, RetainedNative<OwnedUniformOutput<'static>>)>>(8)?,
        bytes::<(GraphParentFailure, OwnedAesRequestOutput<'static>, RetainedNative<OwnedUniformOutput<'static>>, OwnedAesRequestOutput<'static>, RetainedNative<OwnedSparseOutput<'static>>)>(8)?,
        bytes::<core::result::Result<AuxiliaryCompileOperation<'static, 'static, 'static>, (GraphParentFailure, OwnedAesRequestOutput<'static>, RetainedNative<OwnedUniformOutput<'static>>, OwnedAesRequestOutput<'static>, RetainedNative<OwnedSparseOutput<'static>>)>>(8)?,
        bytes::<(GraphParentFailure, PairedRequestOutput<'static>, RetainedNative<OwnedTranscriptOutput<'static>>)>(8)?,
        bytes::<core::result::Result<AuxiliaryCompileOperation<'static, 'static, 'static>, (GraphParentFailure, PairedRequestOutput<'static>, RetainedNative<OwnedTranscriptOutput<'static>>)>>(8)?,
        bytes::<(GraphParentFailure, PairedRequestOutput<'static>, RetainedNative<OwnedTranscriptOutput<'static>>, RetainedNative<OwnedSparseOutput<'static>>)>(8)?,
        bytes::<core::result::Result<AuxiliaryCompileOperation<'static, 'static, 'static>, (GraphParentFailure, PairedRequestOutput<'static>, RetainedNative<OwnedTranscriptOutput<'static>>, RetainedNative<OwnedSparseOutput<'static>>)>>(8)?,
        bytes::<AuxiliaryOuterOperation<'static, 'static, 'static>>(8)?,
        bytes::<Option<AuxiliaryOuterOperation<'static, 'static, 'static>>>(8)?,
        bytes::<OwnedAesRequestOutput<'static>>(16)?, bytes::<PairedRequestOutput<'static>>(8)?,
        bytes::<RetainedNative<OwnedUniformOutput<'static>>>(8)?, bytes::<RetainedNative<OwnedSparseOutput<'static>>>(8)?,
        bytes::<RetainedNative<OwnedTranscriptOutput<'static>>>(8)?,
        bytes::<OwnedGraphCompiled<'static>>(8)?, bytes::<OwnedGraphNode<'static>>(8)?,
        bytes::<Option<OwnedGraphNode<'static>>>(8)?, bytes::<GraphNodeSource<'static>>(8)?,
        bytes::<GraphChildSource<'static, 'static>>(8)?, bytes::<GraphNodeReport>(8)?,
        bytes::<Retained<OwnedGraphCompiled<'static>>>(8)?, bytes::<Retained<OwnedGraphNode<'static>>>(8)?,
        bytes::<OwnedResult<OwnedGraphCompiled<'static>>>(8)?, bytes::<OwnedResult<OwnedGraphNode<'static>>>(8)?,
        bytes::<OwnedResult<AuxiliaryGraphPlan<'static, 'static>>>(8)?,
        bytes::<Requirements>(16)?, bytes::<Sha3_256>(8)?, bytes::<PhaseFacts>(8)?, bytes::<PhaseBinding>(8)?,
        bytes::<AuxiliaryDependencies>(8)?, bytes::<OwnedResult<AuxiliaryDependencies>>(8)?,
        bytes::<[Option<PhaseBinding>; 6]>(8)?,
        bytes::<PlanningStorage>(8)?, bytes::<NativePlanningStorage>(16)?, bytes::<NativeCoreBound>(16)?,
        bytes::<FixedSourceCensus>(8)?, bytes::<RegisteredChildShape>(16)?,
        bytes::<crate::graph_tree::LeafArtifact<'static>>(8)?,
        bytes::<crate::graph_tree::leaf::BoundedAuxiliaryLeaf<'static>>(8)?,
        bytes::<[usize; 24]>(8)?, bytes::<[SlotId; 6]>(8)?,
        bytes::<[Option<sources::NativeSource<'static, 'static>>; 2]>(8)?,
        bytes::<[Option<sources::RequestSource<'static, 'static>>; 2]>(8)?,
        super::super::memory::caller_frames()?, compiler_requirement_frame_bytes()?,
    ].into_iter().try_fold(64 << 10, add)
}
// These helpers return before the next core is entered: request verify_impl,
// owned Uniform/Sparse/Transcript joins, and native_core_bound. Their periodic
// Numeric metadata may split this original envelope across joined workers.
// Materialized verifier cores remain serial: their
// columns, symbolic recordings, public/cap vectors and planner templates are
// local destructible owners, so only the largest complete core scope can be
// active. The Program and complete accumulated ProofInputs survive every core;
// they have separate compiler/input claims. Each scope also charges the full
// global input/wire backing allowance, and source roots/bridge buffers/caller
// frames are added below. This uses source lifetimes, not allocator reuse.
fn core_storage_parts(requests: usize, natives: [Option<NativeDescriptor<'_>>; 2], outer_publics: usize)
    -> OwnedResult<(usize, usize)> {
    if REQUEST_PUBLICS != 46 || !(1..=2).contains(&requests) { return Err(GraphParentFailure::Source); }
    let shapes = [child_shape(super::super::source::MAX_ROWS)?; 2];
    let storage = PlanningStorage::for_children(outer_publics, &shapes[..requests], super::super::source::construction())
        .map_err(|_| GraphParentFailure::Source)?;
    let mut auxiliary = storage.auxiliary_peak_bytes;
    for descriptor in natives.into_iter().flatten() {
        let storage = NativePlanningStorage::for_descriptor(descriptor, super::super::source::construction())
            .map_err(|_| GraphParentFailure::Source)?;
        auxiliary = auxiliary.max(storage.auxiliary_peak_bytes);
    }
    Ok((auxiliary, storage.input_backing_bytes))
}
fn core_storage(sources: AuxiliaryGraphSources<'_, '_>, outer_publics: usize)
    -> OwnedResult<(usize, usize)> {
    core_storage_parts(sources.requests().into_iter().flatten().count(),
        sources.natives().map(|native| native.map(|native| native.descriptor())), outer_publics)
}
fn construction_scratch(auxiliary: usize) -> OwnedResult<Requirements> {
    let auxiliary = add(auxiliary, frames()?)?;
    if auxiliary > super::super::source::AUXILIARY_BYTES { return Err(GraphParentFailure::Capacity); }
    requirement(Category::PhaseScratch, add(super::super::source::PROGRAM_BYTES, auxiliary)?)
}
pub(super) fn planning_scratch_requirements(sources: AuxiliaryGraphSources<'_, '_>) -> OwnedResult<Requirements> {
    construction_scratch(core_storage(sources, 0)?.0)
}
pub(super) fn prepared_planning_scratch_requirements(source: AuxiliaryPreparedInventory<'_>) -> OwnedResult<Requirements> {
    construction_scratch(core_storage_parts(source.requests().into_iter().flatten().count(), source.descriptors()?, 0)?.0)
}
pub(super) fn compiler_requirements(prepared: &PreparedWorkflowSources<'_>, sources: AuxiliaryGraphSources<'_, '_>)
    -> OwnedResult<(Requirements, Requirements)> {
    let (cores, input_backing) = core_storage(sources, PUBLIC_VALUES)?;
    let fixed = FixedSourceCensus::from_graph(prepared.graph()).map_err(|_| GraphParentFailure::Source)?;
    compiler_requirements_from_census(prepared.graph(), sources.kind(), sources.transcript_parts(),
        cores, input_backing, &fixed)
}

/// Pure source arithmetic only, with no owner, proof or dispatch capability.
/// Each registered/native verifier core retains the existing 512 MiB ceiling.
/// Core temporaries are serial as documented above; fixed source, coverage,
/// byte bridges and caller frames remain live alongside that core and are
/// fully additive in the returned whole-phase scratch declaration.
fn compiler_requirements_from_census(graph: &UnprovedRelationGraph, kind: AuxiliaryGraphKind,
    transcript_parts: usize, cores: usize, input_backing: usize, fixed: &FixedSourceCensus,
) -> OwnedResult<(Requirements, Requirements)> {
    if cores > super::super::source::AUXILIARY_BYTES { return Err(GraphParentFailure::Capacity); }
    let coverage = sum([graph.polynomials().len(), graph.bytes().len(), graph.operations().len()])?;
    let group = add(mul(coverage, 2 * size_of::<bool>() + 4 * size_of::<usize>())?, bytes::<Vec<usize>>(16)?)?;
    // Bound simultaneous key openings, request byte copies/growth, descriptor
    // metadata and digest openings. Direct ExpandAlpha performs two complete
    // key openings; the producer-branch single-opening census is inapplicable.
    let (keys, digests) = match kind {
        AuxiliaryGraphKind::SampleG => (1, 0), AuxiliaryGraphKind::ExpandAlpha => (2, 0),
        AuxiliaryGraphKind::HashAlpha => (0, 1), AuxiliaryGraphKind::HashX => (0, 0),
    };
    let byte_count = mul(4, add(mul(keys, 32 + 52 + 20)?, mul(digests, 64)?)?)?;
    let roots = mul(4, transcript_parts.max(4))?;
    let dynamic = sum([group,
        bytes::<lattica_prover_p3::block_v2::machine::pq_bytes::Byte>(byte_count)?,
        bytes::<u8>(byte_count)?, bytes::<Wire>(byte_count)?, bytes::<Val>(byte_count)?,
        bytes::<[Wire; 4]>(roots)?, bytes::<Vec<[Wire; 4]>>(16)?,
        bytes::<Vec<crate::graph_tree::LeafArtifact<'static>>>(8)?,
        bytes::<crate::graph_tree::LeafArtifact<'static>>(2)?, frames()?])?;
    let auxiliary = sum([cores, fixed.source_scratch_bytes, fixed.frame_bytes, dynamic])?;
    Ok((combine(&[
        requirement(Category::SymbolicCompiler, add(super::super::source::PROGRAM_BYTES, bytes::<OwnedGraphCompiled<'static>>(8)?)?)?,
        requirement(Category::CompilerInputs, add(input_backing, bytes::<Val>(2 * PUBLIC_VALUES)?)?)?,
    ])?, requirement(Category::PhaseScratch, auxiliary)?))
}
fn ops(scalar: usize, poseidon: usize) -> OperationCounts { OperationCounts { scalar, cubic: 0, poseidon } }
fn joined(a: OperationCounts, b: OperationCounts) -> OwnedResult<OperationCounts> {
    a.with_overhead(b).map_err(|_| GraphParentFailure::Overflow)
}
fn key_and_request() -> OwnedResult<OperationCounts> {
    let key = framing::byte_commitment(32).map_err(|_| GraphParentFailure::Overflow)?;
    let request = framing::byte_commitment(52).map_err(|_| GraphParentFailure::Overflow)?;
    // BYTE_INPUT = Input + eight Bit + eight Boolean + 25 to_wire + Equal.
    joined(joined(key, request)?, ops(32 * (1 + 8 + 8 + 25 + 1) + 4 + 20 * 8, 0))
}
fn transcript_bundle(parts: usize) -> OwnedResult<OperationCounts> {
    if !(1..=256).contains(&parts) { return Err(GraphParentFailure::Source); }
    Ok(ops(add(4, mul(6, parts)?)?, mul(2, parts)?))
}
fn consumer(kind: AuxiliaryGraphKind, parts: usize) -> OwnedResult<OperationCounts> {
    match kind {
        AuxiliaryGraphKind::SampleG => framing::sample_g_consumer().map_err(|_| GraphParentFailure::Source),
        AuxiliaryGraphKind::ExpandAlpha => {
            // Two stream-root openings, 2*28 request Equals, Uniform's four
            // bundle Constants/two absorbs, and 2*8 sampler-root Equals.
            joined(joined(key_and_request()?, key_and_request()?)?, ops(8 + 56 + 4 + 16, 2))
        }
        AuxiliaryGraphKind::HashAlpha => framing::hash_alpha_consumer(parts).map_err(|_| GraphParentFailure::Source),
        AuxiliaryGraphKind::HashX => {
            // Two four-root openings; eight Transcript joins; 28 SHAKE
            // request Equals; all eight Sparse input/output-root Equals.
            joined(transcript_bundle(parts)?, ops(8 + 8 + 28 + 8, 0))
        }
    }
}
fn extra_inputs(kind: AuxiliaryGraphKind) -> usize {
    match kind { AuxiliaryGraphKind::SampleG => 32 + 4, AuxiliaryGraphKind::ExpandAlpha => 2 * (32 + 4),
        AuxiliaryGraphKind::HashAlpha => 4 + 32, AuxiliaryGraphKind::HashX => 4 + 4 }
}
pub(super) fn derive<'a>(prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    sources: AuxiliaryGraphSources<'_, 'a>, ordinal: usize) -> OwnedResult<GraphNodeSource<'a>> {
    let graph = prepared.get().graph();
    let framing = framing::source_binding_initialization(graph.polynomials().len(), graph.bytes().len())
        .and_then(|n| n.with_overhead(framing::GRAPH_HEADER)).map_err(|_| GraphParentFailure::Source)?;
    let framing = joined(framing, consumer(sources.kind(), sources.transcript_parts())?)?;
    let mut operations = framing;
    let mut maximum_wires = sum([PUBLIC_VALUES, framing.scalar, mul(8, framing.poseidon)?])?;
    let mut maximum_inputs = add(mul(4, add(graph.polynomials().len(), graph.bytes().len())?)?, extra_inputs(sources.kind()))?;
    let mut maximum_hint_words = 0;
    for request in sources.requests().into_iter().flatten() {
        let root = request.root();
        if root.public_values != REQUEST_PUBLICS || root.maximum_padded_rows > super::super::source::MAX_ROWS {
            return Err(GraphParentFailure::Source);
        }
        let envelope = shape::verifier_height_envelope(REQUEST_PUBLICS, root.maximum_padded_rows,
            super::super::source::construction(), super::super::source::AUXILIARY_BYTES)
            .map_err(|_| GraphParentFailure::Source)?;
        operations = joined(operations, envelope.operations)?;
        maximum_wires = add(maximum_wires, envelope.wire_upper_bound)?;
        maximum_inputs = add(maximum_inputs, envelope.input_values_upper_bound)?;
        maximum_hint_words = add(maximum_hint_words, envelope.selection_hint_words_upper_bound)?;
    }
    let mut descriptors = [native_shape::cohort::Descriptor::Other(
        native_shape::unchanged::OtherNativeDescriptor::PrivateProof); 2];
    let mut count = 0;
    for native in sources.natives().into_iter().flatten() {
        descriptors[count] = native_shape::cohort::Descriptor::Native(native.descriptor());
        count += 1;
    }
    let cores = if count == 0 { [None; native_shape::cohort::MAX] } else {
        native_shape::cohort::bounds(&descriptors[..count], super::super::source::construction(),
            super::super::source::AUXILIARY_BYTES).map_err(|_| GraphParentFailure::Source)?
    };
    for core in cores[..count].iter().flatten() {
        if core.counts.quotient_chunks != 16 { return Err(GraphParentFailure::Source); }
        operations = joined(operations, core.counts.operations)?;
        maximum_wires = add(maximum_wires, core.counts.wires)?;
        maximum_inputs = add(maximum_inputs, core.counts.input_values)?;
        maximum_hint_words = add(maximum_hint_words, core.counts.selection_hint_words)?;
    }
    let maximum_active_rows = operations.active_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
    if maximum_padded_rows > super::super::source::MAX_ROWS || maximum_wires > MAX_WIRES
        || maximum_inputs > super::super::source::INPUT_VALUES { return Err(GraphParentFailure::Capacity); }
    let plan = prepared.get().plan(); let context = prepared.get().context();
    let span = GraphSpan { first: u32::try_from(ordinal).map_err(|_| GraphParentFailure::Overflow)?, count: 1, level: 0 };
    let compiled_source_fingerprint = prepared.compiled_source_fingerprint();
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/owned-auxiliary-graph-source/v1"); hash.update([sources.kind().tag()]);
    hash.update(compiled_source_fingerprint); hash.update(prepared.source_fingerprint());
    hash.update(prepared.get().native_identity()); hash.update(plan.label()); hash.update(context.context);
    for request in sources.requests().into_iter().flatten() { hash.update(request.fingerprint()); }
    for native in sources.natives().into_iter().flatten() { hash.update(native.fingerprint()); }
    for value in context.statement.into_iter().chain(context.node_manifest) { hash.update(value.as_canonical_u64().to_le_bytes()); }
    for value in [ordinal, sources.operation_index(), sources.transcript_parts(), operations.scalar, operations.cubic,
        operations.poseidon, maximum_active_rows, maximum_padded_rows, maximum_wires, maximum_inputs, maximum_hint_words]
    { hash.update(u64::try_from(value).map_err(|_| GraphParentFailure::Overflow)?.to_le_bytes()); }
    Ok(GraphNodeSource { plan, context, span, operations, maximum_active_rows, maximum_padded_rows,
        maximum_wires, maximum_inputs, maximum_hint_words, source_fingerprint: hash.finalize().into(), compiled_source_fingerprint })
}

#[cfg(test)]
mod tests;
