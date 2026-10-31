//! Exact operation coverage is marked only after the complete product join.
use super::*;
use lattica_prover_p3::block_v2::native_mul_proof::NativeMulProof;

impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_mul_batch_owned(&mut self, indices: &[usize], artifact: &NativeMulProof) -> Result<()> {
        let (modulus, requests, outputs) = self.mul_requests(indices)?;
        let key = RegisteredMulAir::new(modulus, indices.len()).map_err(component_error)?;
        key.compile_root_join_owned(self.builder, self.inputs, &requests, artifact).map_err(component_error)?;
        for &index in indices { self.operation_bound[index] = true; }
        for index in outputs { self.polynomial_bound[index] = true; }
        Ok(())
    }
}
