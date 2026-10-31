//! Complete unchanged product STARK/FRI verifier over original native borrows.
use super::*;
use p3_air::BaseAir;
use lattica_prover_p3::block_v2::{native_mul_proof::NativeMulProof,
    native_gpu::mul_preparation::MulDescriptor};

impl RegisteredMulAir {
    pub(crate) fn compile_root_join_owned(&self, b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs, requests: &[MulRootRequest], artifact: &NativeMulProof)
        -> Result<(), Error>
    {
        let descriptor = MulDescriptor::new(self.air.modulus, self.air.count)
            .map_err(|_| Error::Descriptor)?;
        if artifact.kind != descriptor
            || artifact.proof.degree_bits != self.air.height.ilog2() as usize + 1
            || requests.len() != self.air.count
            || requests.iter().any(|request| request.modulus != self.air.modulus)
            || artifact.public_values().len() != self.air.public_values()
        { return Err(Error::Shape("owned product registration/request mismatch")); }
        let public = inputs.bases(b, artifact.public_values())?;
        let columns = self.air.periodic_columns();
        verifier::uni::verify_bounded(b, inputs, &self.air, self.air.height, &public, &artifact.proof,
            &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
        for (index, request) in requests.iter().enumerate() {
            for (which, commitment) in [request.left_commitment, request.right_commitment,
                request.output_commitment].into_iter().enumerate() {
                for lane in 0..4 {
                    b.assert_equal(public[12 * index + 4 * which + lane], commitment[lane]);
                }
            }
        }
        Ok(())
    }
}
