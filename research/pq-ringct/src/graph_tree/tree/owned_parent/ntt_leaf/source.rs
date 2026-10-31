use super::*;


impl<'data> GraphNodeSource<'data> {
    /// This constructor is private to the concrete leaf adapter. Numeric source
    /// facts cannot enter through a public API or an observed proof header.
    pub(super) fn from_ntt_compile(
        plan: &NttLeafCompiler<'_, 'data, '_>,
    ) -> OwnedResult<Self> {
        let blueprint = plan.blueprint();
        let facts = plan.facts();
        let ordinal = blueprint.ordinal();
        let crate::graph_proofs::ComponentKind::Ntt { modulus } = blueprint.source().batch().kind()
            else { return Err(GraphParentFailure::Source); };
        let expected = LeafKind::Operations(crate::graph_tree::OperationFamily::Ntt { modulus: *modulus });
        if blueprint.graph_plan().leaves().get(ordinal).is_none_or(|leaf|
            leaf.kind() != &expected || leaf.operation_indices() != blueprint.source().operation_indices())
            || facts.maximum_active_rows != facts.operations.active_rows(PUBLIC_VALUES)
                .map_err(|_| GraphParentFailure::Source)?
            || facts.maximum_padded_rows != facts.operations.padded_rows(PUBLIC_VALUES)
                .map_err(|_| GraphParentFailure::Source)?
            || facts.maximum_padded_rows > super::super::source::MAX_ROWS
            || facts.maximum_wires > MAX_WIRES
            || facts.input_values > super::super::source::INPUT_VALUES
        { return Err(GraphParentFailure::Source); }
        let graph = blueprint.graph_plan();
        let context = blueprint.context();
        let compiled_source_fingerprint = crate::graph_proofs::compiled_source_fingerprint();
        let span = GraphSpan { first: ordinal as u32, count: 1, level: 0 };
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/owned-ntt-graph-leaf-source/v1");
        hash.update(compiled_source_fingerprint);
        hash.update(graph.label()); hash.update(context.context);
        for value in context.statement.into_iter().chain(context.node_manifest) {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        for word in [ordinal, facts.operations.scalar, facts.operations.cubic,
            facts.operations.poseidon, facts.maximum_active_rows, facts.maximum_padded_rows,
            facts.maximum_wires, facts.input_values, facts.selection_hint_words]
        {
            hash.update(u64::try_from(word).map_err(|_| GraphParentFailure::Overflow)?.to_le_bytes());
        }
        Ok(Self { plan: graph, context, span, operations: facts.operations,
            maximum_active_rows: facts.maximum_active_rows,
            maximum_padded_rows: facts.maximum_padded_rows,
            maximum_wires: facts.maximum_wires, maximum_inputs: facts.input_values,
            maximum_hint_words: facts.selection_hint_words,
            source_fingerprint: hash.finalize().into(), compiled_source_fingerprint })
    }
}
