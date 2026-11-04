//! Immutable, exactly bound worker inputs and funded native preparation data.
use super::*;
use crate::rust_verify::committed_backend::UnprovedRelationGraph;

#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    graph: &'a UnprovedRelationGraph,
    batch: &'a super::super::PlannedBatch,
    ordinal: usize,
    kind: GBoundDescriptor,
    expected: &'a [Val],
}
#[derive(Clone, Copy)]
pub(crate) struct Data<'a> {
    source: View<'a>, preparation: GBoundPreparationPlan, output: GBoundOutputPlan,
}
pub(crate) struct Prepared<'a> {
    data: Data<'a>, raw: WipedRaw, compiled: [u8; 32],
}
impl<'a> GBoundSource<'a> {
    pub(crate) fn metadata_view(self) -> View<'a> {
        View { graph: self.sources.get().graph(), batch: self.batch, ordinal: self.ordinal,
            kind: self.kind, expected: self.expected }
    }
}
impl<'a> View<'a> {
    pub(crate) fn kind(self) -> GBoundDescriptor { self.kind }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn ordinal(self) -> usize { self.ordinal }
    pub(crate) fn matches(self, source: GBoundSource<'a>) -> bool {
        let expected: &[Val] = source.expected;
        core::ptr::eq(self.graph, source.sources.get().graph())
            && core::ptr::eq(self.batch, source.batch) && core::ptr::eq(self.expected, expected)
            && self.ordinal == source.ordinal && self.kind == source.kind
    }
    fn air(self) -> GBoundAir {
        GBoundAir::new(self.kind.g_bound()).expect("validated GBOUND source")
        }
    fn serialize(self) -> Result<WipedRaw> {
        let words = GBoundGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| GBoundFailure::Resource)?;
        if raw.0.capacity() != words { return Err(GBoundFailure::Resource); }

        for &index in &self.batch.indices {
            let Operation::GBound { f, x, bound } = self.graph.operations()[index]
                else { return Err(GBoundFailure::Source); };
            if bound != self.kind.g_bound() { return Err(GBoundFailure::Source); }
            for (id, input_bound) in [(f, self.kind.f_bound()), (x, 1)] {
                let node = self.graph.polynomial(id);
                serialize_signed_input(&mut raw.0, &node.kind, &node.values, input_bound)?;
            }
        }
        if raw.0.len() != words { return Err(GBoundFailure::Source); }
        Ok(raw)
        }
    pub(crate) fn prepare(self, admitted: usize) -> Result<Prepared<'a>> {
        if admitted != GBoundProofPlan::metadata_worker_host_bytes() { return Err(GBoundFailure::Resource); }
        let preparation = GBoundPreparationPlan::new(self.kind).map_err(|_| GBoundFailure::Resource)?;
        let output = GBoundOutputPlan::new(preparation).map_err(|_| GBoundFailure::Resource)?;
        let geometry = preparation.geometry(); let air = self.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (crate::g_bound_air::HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(GBoundFailure::Geometry); }
        let raw = self.serialize()?;
        Ok(Prepared { data: Data { source: self, preparation, output }, raw,
            compiled: crate::graph_proofs::compiled_source_fingerprint() })
    }
}
impl<'a> Data<'a> {
    pub(crate) fn source(self) -> View<'a> { self.source }
    pub(crate) fn preparation(self) -> GBoundPreparationPlan { self.preparation }
    pub(crate) fn output_plan(self) -> GBoundOutputPlan { self.output }
}
impl<'a> Prepared<'a> {
    pub(crate) fn data(&self) -> Data<'a> { self.data }
    pub(super) fn into_plan(self, source: GBoundSource<'a>) -> Result<GBoundProofPlan<'a>> {
        if !self.data.source.matches(source) || self.compiled != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(GBoundFailure::Source);
        }
        #[cfg(test)]
        if crate::preparation_options::metadata_reference_check() {
            let reference = source.serialize()?;
            if reference.0 != self.raw.0 { return Err(GBoundFailure::Source); }
            let mut wrong = self.data.source;
            wrong.ordinal = wrong.ordinal.wrapping_add(1);
            if wrong.matches(source) { return Err(GBoundFailure::Source); }
            crate::preparation_options::record_metadata_reference_check(3);
        }
        Ok(GBoundProofPlan { source, preparation: self.data.preparation, output: self.data.output, raw: self.raw })
    }
}
impl<'a> GBoundProofPlan<'a> {
    pub(crate) fn metadata_data(&self) -> Data<'a> {
        Data { source: self.source.metadata_view(), preparation: self.preparation, output: self.output }
    }
}
