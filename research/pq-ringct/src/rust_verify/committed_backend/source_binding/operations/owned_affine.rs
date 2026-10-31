//! Exact operation coverage only after the complete borrowed native verifier.
use super::*;
use lattica_prover_p3::block_v2::native_affine_proof::NativeAffineProof;

impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_affine_batch_owned(&mut self, indices: &[usize], artifact: &NativeAffineProof) -> Result<()> {
        let (kind, modulus, requests, outputs) = self.affine_requests(indices)?;
        let key = RegisteredAffineAir::new(kind, modulus, indices.len()).map_err(component_error)?;
        key.compile_join_owned(self.builder, self.inputs, &requests, artifact).map_err(component_error)?;
        for &index in indices { self.operation_bound[index] = true; }
        for index in outputs { self.polynomial_bound[index] = true; }
        Ok(())
    }
}
