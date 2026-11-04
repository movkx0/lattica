//! Immutable, exactly bound worker inputs and funded native preparation data.
use super::*;
use crate::rust_verify::committed_backend::UnprovedRelationGraph;

#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    graph: &'a UnprovedRelationGraph,
    batch: &'a super::super::PlannedBatch,
    ordinal: usize,
    kind: NttDescriptor,
    expected: &'a [Val],
}
#[derive(Clone, Copy)]
pub(crate) struct Data<'a> {
    source: View<'a>, preparation: NttPreparationPlan, output: NttOutputPlan,
}
pub(crate) struct Prepared<'a> {
    data: Data<'a>, raw: WipedRaw, compiled: [u8; 32],
}
impl<'a> NttSource<'a> {
    pub(crate) fn metadata_view(self) -> View<'a> {
        View { graph: self.sources.get().graph(), batch: self.batch, ordinal: self.ordinal,
            kind: self.kind, expected: self.expected }
    }
}
impl<'a> View<'a> {
    pub(crate) fn kind(self) -> NttDescriptor { self.kind }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn ordinal(self) -> usize { self.ordinal }
    pub(crate) fn matches(self, source: NttSource<'a>) -> bool {
        let expected: &[Val] = source.expected;
        core::ptr::eq(self.graph, source.sources.get().graph())
            && core::ptr::eq(self.batch, source.batch) && core::ptr::eq(self.expected, expected)
            && self.ordinal == source.ordinal && self.kind == source.kind
    }
    fn air(self) -> NttAir {
        NttAir::new(self.kind.modulus(), self.kind.count()).expect("validated NTT source")
        }
    fn serialize(self) -> Result<WipedRaw> {
        let words = NttGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| NttFailure::Resource)?;
        if raw.0.capacity() != words { return Err(NttFailure::Resource); }

        for &index in &self.batch.indices {
            let Operation::Ntt { modulus, input, .. } = self.graph.operations()[index]
                else { return Err(NttFailure::Source); };
            if modulus != self.kind.modulus() { return Err(NttFailure::Source); }
            let node = self.graph.polynomial(input);
            if node.kind != (crate::rust_verify::committed_backend::PolynomialKind::Canonical { modulus }) {
                return Err(NttFailure::Source);
            }
            let crate::rust_verify::committed_backend::PolynomialValues::Canonical(values) = &node.values
                else { return Err(NttFailure::Source); };
            if values.iter().any(|&word| word >= modulus) { return Err(NttFailure::Source); }
            raw.0.extend_from_slice(values);
        }
        if raw.0.len() != words { return Err(NttFailure::Source); }
        Ok(raw)
        }
    pub(crate) fn prepare(self, admitted: usize) -> Result<Prepared<'a>> {
        if admitted != NttProofPlan::metadata_worker_host_bytes() { return Err(NttFailure::Resource); }
        let preparation = NttPreparationPlan::new(self.kind).map_err(|_| NttFailure::Resource)?;
        let output = NttOutputPlan::new(preparation).map_err(|_| NttFailure::Resource)?;
        let geometry = preparation.geometry(); let air = self.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(NttFailure::Geometry); }
        let raw = self.serialize()?;
        Ok(Prepared { data: Data { source: self, preparation, output }, raw,
            compiled: crate::graph_proofs::compiled_source_fingerprint() })
    }
}
impl<'a> Data<'a> {
    pub(crate) fn source(self) -> View<'a> { self.source }
    pub(crate) fn preparation(self) -> NttPreparationPlan { self.preparation }
    pub(crate) fn output_plan(self) -> NttOutputPlan { self.output }
}
impl<'a> Prepared<'a> {
    pub(crate) fn data(&self) -> Data<'a> { self.data }
    pub(super) fn into_plan(self, source: NttSource<'a>) -> Result<NttProofPlan<'a>> {
        if !self.data.source.matches(source) || self.compiled != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(NttFailure::Source);
        }
        #[cfg(test)]
        if crate::preparation_options::metadata_reference_check() {
            let reference = source.serialize()?;
            if reference.0 != self.raw.0 { return Err(NttFailure::Source); }
            let mut wrong = self.data.source;
            wrong.ordinal = wrong.ordinal.wrapping_add(1);
            if wrong.matches(source) { return Err(NttFailure::Source); }
            crate::preparation_options::record_metadata_reference_check(1);
        }
        Ok(NttProofPlan { source, preparation: self.data.preparation, output: self.data.output, raw: self.raw })
    }
}
impl<'a> NttProofPlan<'a> {
    pub(crate) fn metadata_data(&self) -> Data<'a> {
        Data { source: self.source.metadata_view(), preparation: self.preparation, output: self.output }
    }
}
