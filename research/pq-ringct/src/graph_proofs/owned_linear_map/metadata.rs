//! Immutable, exactly bound worker inputs and funded native preparation data.
use super::*;
use crate::rust_verify::committed_backend::UnprovedRelationGraph;

#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    graph: &'a UnprovedRelationGraph,
    batch: &'a super::super::PlannedBatch,
    ordinal: usize,
    kind: &'a crate::linear_map_air::LinearMapDescriptor,
    expected: &'a [Val],
}
#[derive(Clone, Copy)]
pub(crate) struct Data<'a> {
    source: View<'a>, preparation: LinearMapPreparationPlan, output: LinearMapOutputPlan,
}
pub(crate) struct Prepared<'a> {
    data: Data<'a>, raw: WipedRaw, compiled: [u8; 32],
}
impl<'a> LinearMapSource<'a> {
    pub(crate) fn metadata_view(self) -> View<'a> {
        let crate::graph_proofs::ComponentKind::LinearMap { descriptor } = self.batch.kind() else {
            unreachable!("validated immutable linear-map batch")
        };
        View { graph: self.sources.get().graph(), batch: self.batch, ordinal: self.ordinal,
            kind: descriptor, expected: self.expected }
    }
}
impl<'a> View<'a> {
    pub(crate) fn kind(self) -> LinearMapDescriptor {
        self.kind.owned_descriptor().expect("validated immutable linear-map descriptor")
    }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn ordinal(self) -> usize { self.ordinal }
    pub(crate) fn matches(self, source: LinearMapSource<'a>) -> bool {
        let expected: &[Val] = source.expected;
        core::ptr::eq(self.graph, source.sources.get().graph())
            && core::ptr::eq(self.batch, source.batch) && core::ptr::eq(self.expected, expected)
            && self.ordinal == source.ordinal && self.kind() == source.kind
    }
    fn air(self) -> LinearMapAir {
        air_for_descriptor(self.kind())
        }
    fn serialize(self) -> Result<WipedRaw> {
        let words = LinearMapGeometry::for_kind(self.kind()).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| LinearMapFailure::Resource)?;
        if raw.0.capacity() != words { return Err(LinearMapFailure::Resource); }

        let [index] = self.batch.indices.as_slice() else { return Err(LinearMapFailure::Source); };
        let inputs = match self.graph.operations().get(*index) {
            Some(Operation::CanonicalMap {inputs,..}) | Some(Operation::SignedMap {inputs,..}) => inputs,
            _ => return Err(LinearMapFailure::Source),
        };
        if inputs.len()!=self.kind().inputs() { return Err(LinearMapFailure::Source); }
        for (id, kind) in inputs.iter().zip(self.kind().kinds()) {
            let node = self.graph.polynomial(*id);
            serialize_input(&mut raw.0, &node.kind, &node.values, *kind)?;
        }
        if raw.0.len() != words { return Err(LinearMapFailure::Source); }
        Ok(raw)
        }
    pub(crate) fn prepare(self, admitted: usize) -> Result<Prepared<'a>> {
        if admitted != LinearMapProofPlan::metadata_worker_host_bytes() { return Err(LinearMapFailure::Resource); }
        let preparation = LinearMapPreparationPlan::new(self.kind()).map_err(|_| LinearMapFailure::Resource)?;
        let output = LinearMapOutputPlan::new(preparation).map_err(|_| LinearMapFailure::Resource)?;
        let geometry = preparation.geometry(); let air = self.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height(), air.width(), air.num_public_values(), air.num_periodic_columns())
            || air.max_constraint_degree().is_some()
        { return Err(LinearMapFailure::Geometry); }
        let raw = self.serialize()?;
        Ok(Prepared { data: Data { source: self, preparation, output }, raw,
            compiled: crate::graph_proofs::compiled_source_fingerprint() })
    }
}
impl<'a> Data<'a> {
    pub(crate) fn source(self) -> View<'a> { self.source }
    pub(crate) fn preparation(self) -> LinearMapPreparationPlan { self.preparation }
    pub(crate) fn output_plan(self) -> LinearMapOutputPlan { self.output }
}
impl<'a> Prepared<'a> {
    pub(crate) fn data(&self) -> Data<'a> { self.data }
    pub(super) fn into_plan(self, source: LinearMapSource<'a>) -> Result<LinearMapProofPlan<'a>> {
        if !self.data.source.matches(source) || self.compiled != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(LinearMapFailure::Source);
        }
        #[cfg(test)]
        if crate::preparation_options::metadata_reference_check() {
            let reference = source.serialize()?;
            if reference.0 != self.raw.0 { return Err(LinearMapFailure::Source); }
            let mut wrong = self.data.source;
            wrong.ordinal = wrong.ordinal.wrapping_add(1);
            if wrong.matches(source) { return Err(LinearMapFailure::Source); }
            crate::preparation_options::record_metadata_reference_check(5);
        }
        Ok(LinearMapProofPlan { source, preparation: self.data.preparation, output: self.data.output, raw: self.raw })
    }
}
impl<'a> LinearMapProofPlan<'a> {
    pub(crate) fn metadata_data(&self) -> Data<'a> {
        Data { source: self.source.metadata_view(), preparation: self.preparation, output: self.output }
    }
}
