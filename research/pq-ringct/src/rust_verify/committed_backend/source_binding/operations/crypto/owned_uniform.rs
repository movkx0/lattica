//! Complete SampleG operation using retained AES and Uniform proof borrows.
//! The graph source owner remains responsible for their exact request identity;
//! this relation checks both complete verifiers and every unchanged root join.
use super::*;
use lattica_prover_p3::block_v2::native_uniform_proof::NativeUniformProof;
impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_sample_g_owned<'a>(&mut self, index: usize,
        aes: impl Into<AesRequest<'a>>, sampler: &NativeUniformProof) -> Result<()>
    {
        let Operation::SampleG { seed, output } = *self.pending(index)? else {
            return Err(error("operation is not SampleG"));
        };
        let seed_value = self.graph.byte_string(seed).values;
        let mut roots = Vec::with_capacity(4);
        for id in output { roots.push(self.output_root(index, id, PolynomialKind::Canonical { modulus: Q })?); }
        let roots = roots.try_into().map_err(|_| error("SampleG output width"))?;
        sampler_bridge::owned_uniform::verify_sample_g(self.builder, self.inputs,
            &self.byte_roots[seed.index()], &seed_value, &roots, aes, sampler).map_err(component_error)?;
        self.operation_bound[index] = true;
        for id in output { self.polynomial_bound[id.index()] = true; }
        Ok(())
    }
}
