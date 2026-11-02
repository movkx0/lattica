use super::*;
pub(super) const MAX_ROWS: usize = 1 << 20;
pub(super) const PROGRAM_BYTES: usize = 2 << 30;
pub(super) const INPUT_VALUES: usize = 1 << 20;
pub(super) const AUXILIARY_BYTES: usize = 512 << 20;
pub(super) fn construction() -> ConstructionLimits {
    ConstructionLimits { max_requested_program_bytes: PROGRAM_BYTES,
        max_wires: MAX_WIRES, max_input_values: INPUT_VALUES }
}
pub(super) fn registered_shape(height: usize) -> OwnedResult<RegisteredChildShape> {
    if !(8..=MAX_ROWS).contains(&height) || !height.is_power_of_two() {
        return Err(GraphParentFailure::Source);
    }
    use lattica_prover_p3::block_v2::profile;
    Ok(RegisteredChildShape { public_values: PUBLIC_VALUES, height,
        preprocessing_cap_roots: 1usize << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP)
            .min(profile::CAP_HEIGHT) })
}
pub(super) fn planning_scratch_requirements() -> OwnedResult<Requirements> {
    let storage = PlanningStorage::for_children(0, &[registered_shape(MAX_ROWS)?], construction())
        .map_err(|_| GraphParentFailure::Source)?;
    if storage.auxiliary_peak_bytes > AUXILIARY_BYTES { return Err(GraphParentFailure::Capacity); }
    requirement(Category::PhaseScratch, add(add(PROGRAM_BYTES, storage.auxiliary_peak_bytes)?,
        memory::planning_frames()?)?)
}
impl<'graph> GraphNodeSource<'graph> {
    pub(super) fn parent(left: &Self, right: &Self) -> OwnedResult<Self> {
        if !core::ptr::eq(left.plan, right.plan) || !core::ptr::eq(left.context, right.context)
            || left.compiled_source_fingerprint != right.compiled_source_fingerprint
            || left.compiled_source_fingerprint != crate::graph_proofs::compiled_source_fingerprint()
            || left.maximum_padded_rows > MAX_ROWS || right.maximum_padded_rows > MAX_ROWS
        { return Err(GraphParentFailure::Authority); }
        let span = GraphSpan::merge(left.span, right.span, left.plan.leaves().len())?;
        // Enumerate every supported child height before any child proof exists.
        // Source graphs use28 publics; the46-public component census is inapplicable.
        let envelope = shape::verifier_height_envelope(PUBLIC_VALUES, left.maximum_padded_rows,
            construction(), AUXILIARY_BYTES).map_err(|_| GraphParentFailure::Source)?;
        let right_envelope = shape::verifier_height_envelope(PUBLIC_VALUES, right.maximum_padded_rows,
            construction(), AUXILIARY_BYTES).map_err(|_| GraphParentFailure::Source)?;
        if PUBLIC_VALUES != 28 || envelope.heights_enumerated != left.maximum_padded_rows.ilog2() as usize - 2
            || right_envelope.heights_enumerated != right.maximum_padded_rows.ilog2() as usize - 2 {
            return Err(GraphParentFailure::Source);
        }
        // Exact existing public_wires + bind_merge framing: eight32-bit
        // context decompositions, twelve fixed header words, shared fields,
        // first-leaf equality, adjacent interval and summed count.
        let framing = OperationCounts { scalar: 8 * 162 + (8 + 4) * 2
            + 2 * (PUBLIC_VALUES - 3) + 5, cubic: 0, poseidon: 0 };
        let operations = envelope.operations.with_overhead(right_envelope.operations)
            .and_then(|n| n.with_overhead(framing)).map_err(|_| GraphParentFailure::Overflow)?;
        let maximum_active_rows = operations.active_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
        let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Overflow)?;
        let maximum_wires = add(PUBLIC_VALUES, add(add(envelope.wire_upper_bound, right_envelope.wire_upper_bound)?, framing.scalar)?)?;
        let maximum_inputs = add(envelope.input_values_upper_bound, right_envelope.input_values_upper_bound)?;
        let maximum_hint_words = add(envelope.selection_hint_words_upper_bound, right_envelope.selection_hint_words_upper_bound)?;
        if maximum_padded_rows > MAX_ROWS || maximum_wires > MAX_WIRES || maximum_inputs > INPUT_VALUES {
            return Err(GraphParentFailure::Capacity);
        }
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/owned-graph-parent-source/v1");
        hash.update(left.compiled_source_fingerprint);
        hash.update(left.source_fingerprint); hash.update(right.source_fingerprint);
        hash.update(left.plan.label()); hash.update(left.context.context);
        for value in left.context.statement.into_iter().chain(left.context.node_manifest) {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        for value in [span.first, span.count, span.level] { hash.update(value.to_le_bytes()); }
        Ok(Self { plan: left.plan, context: left.context, span, operations,
            maximum_active_rows, maximum_padded_rows, maximum_wires, maximum_inputs,
            maximum_hint_words, source_fingerprint: hash.finalize().into(),
            compiled_source_fingerprint: left.compiled_source_fingerprint })
    }
    pub(crate) fn outer_shape(self) -> OwnedResult<OuterSourceShape> {
        OuterSourceShape::registered_graph_bounds(PUBLIC_VALUES, self.operations,
            self.maximum_wires, self.maximum_inputs, self.maximum_hint_words)
            .map_err(|_| GraphParentFailure::Source)
    }
    pub(crate) fn span(self) -> GraphSpan { self.span }
    pub(crate) fn graph_plan(self) -> &'graph Plan { self.plan }
    pub(crate) fn context(self) -> &'graph GraphContext { self.context }
    pub(crate) fn source_fingerprint(self) -> [u8; 32] { self.source_fingerprint }
    pub(crate) fn compiled_source_fingerprint(self) -> [u8; 32] { self.compiled_source_fingerprint }
    pub(crate) fn maximum_height(self) -> usize { self.maximum_padded_rows }
    pub(super) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.plan, other.plan) && core::ptr::eq(self.context, other.context)
            && self.span == other.span && self.operations == other.operations
            && self.maximum_active_rows == other.maximum_active_rows
            && self.maximum_padded_rows == other.maximum_padded_rows
            && self.maximum_wires == other.maximum_wires && self.maximum_inputs == other.maximum_inputs
            && self.maximum_hint_words == other.maximum_hint_words
            && self.source_fingerprint == other.source_fingerprint
            && self.compiled_source_fingerprint == other.compiled_source_fingerprint
    }
    pub(super) fn check_public(self, public: &[Val]) -> bool {
        public.len() == PUBLIC_VALUES
            && public[..8] == words(&self.plan.label())
            && public[CONTEXT..CONTEXT + 8] == words(&self.context.context)
            && public[STATEMENT..STATEMENT + 4] == self.context.statement
            && public[NODE_MANIFEST..NODE_MANIFEST + 4] == self.context.node_manifest
            && public[FIRST] == Val::from_u32(self.span.first)
            && public[COUNT] == Val::from_u32(self.span.count)
            && public[LEVEL] == Val::from_u32(self.span.level)
            && public[TOTAL] == Val::from_usize(self.plan.leaves().len())
    }
    pub(super) fn retained_program_host_bytes(self) -> OwnedResult<usize> {
        self.operations.retained_program_host_ceiling(PUBLIC_VALUES, self.maximum_wires, self.maximum_hint_words)
            .map_err(|_| GraphParentFailure::Capacity)
    }
    pub(super) fn check_compiled(self, node: &CompiledNode) -> OwnedResult<()> {
        let program = &node.program; let actual = OperationCounts::from_program(program);
        let hints = shape::selection_hint_words(program).map_err(|_| GraphParentFailure::Source)?;
        if !self.plan.matches_final_inner(&node.spec.plan) || !self.span.agrees(&node.spec)
            || !self.check_public(&node.public) || program.public_values() != PUBLIC_VALUES
            || program.active_rows() > self.maximum_active_rows || program.height() > self.maximum_padded_rows
            || program.wire_count() > self.maximum_wires || program.witness_values() > self.maximum_inputs
            || node.witness.len() != program.witness_values()
            || hints > self.maximum_hint_words || program.construction_host_bytes() > PROGRAM_BYTES
            || program.retained_host_bytes().map_err(|_| GraphParentFailure::Capacity)? > self.retained_program_host_bytes()?
            || actual.scalar > self.operations.scalar || actual.cubic > self.operations.cubic
            || actual.poseidon > self.operations.poseidon
        { return Err(GraphParentFailure::Source); }
        Ok(())
    }
    pub(crate) fn output_requirements(self) -> OwnedResult<(Requirements, Requirements)> {
        let footprint = self.outer_shape()?.output_footprint().map_err(|_| GraphParentFailure::Resource)?;
        let owners = bytes::<OwnedGraphNode<'static>>(8)?;
        let proof = usize::try_from(footprint.proof_backing_ceiling_host_bytes)
            .map_err(|_| GraphParentFailure::Overflow)?;
        let key = footprint.verifier_metadata_retained_host_bytes
            .checked_add(footprint.copied_key_cap_host_bytes).ok_or(GraphParentFailure::Overflow)?;
        Ok((combine(&[
            requirement(Category::RecursiveProof, add(add(proof, bytes::<Val>(2 * PUBLIC_VALUES)?)?, owners)?)?,
            requirement(Category::RegisteredMetadata, add(usize::try_from(key)
                .map_err(|_| GraphParentFailure::Overflow)?, owners)?)?,
        ])?, Requirements::single(Category::IndependentVerifier, Bytes {
            host: footprint.verifier_lifecycle_peak_host_bytes, device: 0,
        })))
    }
}
