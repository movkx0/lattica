//! Complete ExpandAlpha coverage after both original sampler proofs verify.
use super::*;
use lattica_prover_p3::block_v2::{native_sparse_proof::NativeSparseProof,
    native_uniform_proof::NativeUniformProof};
impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_expand_alpha_owned<'a>(
        &mut self,
        index: usize,
        uniform_aes: impl Into<AesRequest<'a>>,
        uniform: &NativeUniformProof,
        sparse_aes: impl Into<AesRequest<'a>>,
        sparse: &NativeSparseProof,
    ) -> Result<()> {
        let Operation::ExpandAlpha {
            seed,
            canonical,
            signed,
        } = *self.pending(index)?
        else {
            return Err(error("operation is not ExpandAlpha"));
        };
        let seed_value = self.graph.byte_string(seed).values;
        let roots = [
            self.output_root(
                index,
                canonical[0],
                PolynomialKind::Canonical { modulus: Q },
            )?,
            self.output_root(
                index,
                canonical[1],
                PolynomialKind::Canonical { modulus: Q },
            )?,
        ];
        let signed_root = self.output_root(index, signed, PolynomialKind::Signed { bound: 1 })?;
        sampler_bridge::owned_sparse::verify_expand_alpha(
            self.builder,
            self.inputs,
            &self.byte_roots[seed.index()],
            &seed_value,
            &roots,
            &signed_root,
            uniform_aes,
            uniform,
            sparse_aes,
            sparse,
        )
        .map_err(component_error)?;
        self.operation_bound[index] = true;
        for id in canonical {
            self.polynomial_bound[id.index()] = true;
        }
        self.polynomial_bound[signed.index()] = true;
        Ok(())
    }
}
