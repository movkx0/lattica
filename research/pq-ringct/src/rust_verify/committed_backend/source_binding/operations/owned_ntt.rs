//! Atomic exact operation coverage after the complete bounded NTT verifier.
use super::*;
use lattica_prover_p3::block_v2::native_ntt_proof::NativeNttProof;

impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_ntt_batch_owned(&mut self, indices: &[usize], artifact: &NativeNttProof) -> Result<()> {
        let (modulus, requests, outputs) = self.ntt_requests(indices)?;
        let key = RegisteredNttAir::new(modulus, indices.len()).map_err(component_error)?;
        key.compile_root_join_owned(self.builder, self.inputs, &requests, artifact).map_err(component_error)?;
        for &index in indices { self.operation_bound[index] = true; }
        for index in outputs { self.polynomial_bound[index] = true; }
        Ok(())
    }
}
