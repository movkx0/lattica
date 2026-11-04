//! Immutable, exactly bound worker inputs and funded native preparation data.
use super::*;
use crate::rust_verify::committed_backend::UnprovedRelationGraph;

#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    graph: &'a UnprovedRelationGraph,
    batch: &'a super::super::PlannedBatch,
    ordinal: usize,
    kind: MulDescriptor,
    expected: &'a [Val],
}
#[derive(Clone, Copy)]
pub(crate) struct Data<'a> {
    source: View<'a>, preparation: MulPreparationPlan, output: MulOutputPlan,
}
pub(crate) struct Prepared<'a> {
    data: Data<'a>, raw: WipedRaw, compiled: [u8; 32],
}
impl<'a> MulSource<'a> {
    pub(crate) fn metadata_view(self) -> View<'a> {
        View { graph: self.sources.get().graph(), batch: self.batch, ordinal: self.ordinal,
            kind: self.kind, expected: self.expected }
    }
}
impl<'a> View<'a> {
    pub(crate) fn kind(self) -> MulDescriptor { self.kind }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn ordinal(self) -> usize { self.ordinal }
    pub(crate) fn matches(self, source: MulSource<'a>) -> bool {
        let expected: &[Val] = source.expected;
        core::ptr::eq(self.graph, source.sources.get().graph())
            && core::ptr::eq(self.batch, source.batch) && core::ptr::eq(self.expected, expected)
            && self.ordinal == source.ordinal && self.kind == source.kind
    }
    fn air(self) -> MulAir {
        MulAir::new(self.kind.modulus(), self.kind.count()).expect("validated MUL source")
        }
    fn serialize(self) -> Result<WipedRaw> {
        let words = MulGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| MulFailure::Resource)?;
        if raw.0.capacity() != words { return Err(MulFailure::Resource); }

        for &index in &self.batch.indices {
            let Operation::Mul { modulus, left, right, .. } = self.graph.operations()[index]
                else { return Err(MulFailure::Source); };
            if modulus != self.kind.modulus() { return Err(MulFailure::Source); }
            for id in [left, right] {
                let node = self.graph.polynomial(id);
                if node.kind != (crate::rust_verify::committed_backend::PolynomialKind::Canonical { modulus }) {
                    return Err(MulFailure::Source);
                }
                let crate::rust_verify::committed_backend::PolynomialValues::Canonical(values) = &node.values
                    else { return Err(MulFailure::Source); };
                if values.iter().any(|&word| word >= modulus) { return Err(MulFailure::Source); }
                raw.0.extend_from_slice(values);
            }
        }
        if raw.0.len() != words { return Err(MulFailure::Source); }
        Ok(raw)
        }
    pub(crate) fn prepare(self, admitted: usize) -> Result<Prepared<'a>> {
        if admitted != MulProofPlan::metadata_worker_host_bytes() { return Err(MulFailure::Resource); }
        let preparation = MulPreparationPlan::new(self.kind).map_err(|_| MulFailure::Resource)?;
        let output = MulOutputPlan::new(preparation).map_err(|_| MulFailure::Resource)?;
        let geometry = preparation.geometry(); let air = self.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(MulFailure::Geometry); }
        let raw = self.serialize()?;
        Ok(Prepared { data: Data { source: self, preparation, output }, raw,
            compiled: crate::graph_proofs::compiled_source_fingerprint() })
    }
}
impl<'a> Data<'a> {
    pub(crate) fn source(self) -> View<'a> { self.source }
    pub(crate) fn preparation(self) -> MulPreparationPlan { self.preparation }
    pub(crate) fn output_plan(self) -> MulOutputPlan { self.output }
}
impl<'a> Prepared<'a> {
    pub(crate) fn data(&self) -> Data<'a> { self.data }
    pub(super) fn into_plan(self, source: MulSource<'a>) -> Result<MulProofPlan<'a>> {
        if !self.data.source.matches(source) || self.compiled != crate::graph_proofs::compiled_source_fingerprint() {
            return Err(MulFailure::Source);
        }
        #[cfg(test)]
        if crate::preparation_options::metadata_reference_check() {
            let reference = source.serialize()?;
            if reference.0 != self.raw.0 { return Err(MulFailure::Source); }
            let mut wrong = self.data.source;
            wrong.ordinal = wrong.ordinal.wrapping_add(1);
            if wrong.matches(source) { return Err(MulFailure::Source); }
            crate::preparation_options::record_metadata_reference_check(2);
        }
        Ok(MulProofPlan { source, preparation: self.data.preparation, output: self.data.output, raw: self.raw })
    }
}
impl<'a> MulProofPlan<'a> {
    pub(crate) fn metadata_data(&self) -> Data<'a> {
        Data { source: self.source.metadata_view(), preparation: self.preparation, output: self.output }
    }
}
