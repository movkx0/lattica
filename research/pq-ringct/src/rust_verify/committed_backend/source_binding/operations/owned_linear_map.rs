//! Join one exact retained planned descriptor; do not reconstruct expression DAGs.
use super::*;
use crate::graph_proofs::owned_linear_map::LinearMapSource;
use lattica_prover_p3::block_v2::native_linear_map_proof::NativeLinearMapProof;
impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_linear_map_batch_owned(&mut self, source: LinearMapSource<'_>, artifact: &NativeLinearMapProof) -> Result<()> {
        if !core::ptr::eq(self.graph,source.sources().get().graph()) || source.kind()!=artifact.kind
            || source.expected_public_values()!=artifact.public_values() {
            return Err(error("linear-map original source mismatch"));
        }
        let [index] = source.operation_indices() else { return Err(error("linear-map must contain one operation")); };
        let crate::graph_proofs::ComponentKind::LinearMap {descriptor} = source.batch().kind()
            else { return Err(error("linear-map original descriptor missing")); };
        // The source constructor is private and accepts only the immutable
        // already-classified original batch. Its exact descriptor, including all
        // coefficient arrays, is checked against the proof's closed descriptor.
        if descriptor.owned_descriptor().map_err(|_| error("linear-map source descriptor"))? != artifact.kind {
            return Err(error("linear-map source descriptor drift"));
        }
        let (ids,output) = match self.pending(*index)? {
            Operation::CanonicalMap {inputs,output,..} | Operation::SignedMap {inputs,output,..} => (inputs,*output),
            _ => return Err(error("linear-map original operation mismatch")),
        };
        if ids.len()!=descriptor.inputs().len() { return Err(error("linear-map original input order")); }
        let input_commitments = ids.iter().zip(descriptor.inputs()).map(|(&id,&kind)|self.typed_root(id,kind))
            .collect::<Result<Vec<_>>>()?;
        let output_commitment = self.output_root(*index,output,descriptor.output())?;
        let request = PendingLinearMap {descriptor:descriptor.clone(),input_commitments,output_commitment};
        RegisteredLinearMapAir::new(request.descriptor.clone())
            .compile_join_owned(self.builder,self.inputs,&request,artifact).map_err(component_error)?;
        self.operation_bound[*index] = true;
        self.polynomial_bound[output.index()] = true;
        Ok(())
    }
}
