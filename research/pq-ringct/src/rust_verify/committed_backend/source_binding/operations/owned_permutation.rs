//! Mark exact permutation coverage only after the complete ordered-root join.
use super::*;
use lattica_prover_p3::block_v2::native_permutation_proof::NativePermutationProof;
impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_permutation_batch_owned(&mut self, indices: &[usize], artifact: &NativePermutationProof) -> Result<()> {
        let [index] = indices else { return Err(error("permutation must contain exactly one operation")); };
        let (request, output) = self.permutation_request(*index)?;
        RegisteredPermutationAir::new(request.kind)
            .compile_join_owned(self.builder, self.inputs, &request, artifact).map_err(component_error)?;
        self.operation_bound[*index] = true;
        self.polynomial_bound[output] = true;
        Ok(())
    }
}
