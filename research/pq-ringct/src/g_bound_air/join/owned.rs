//! Complete unchanged GBound STARK/FRI verifier over original native borrows.
use super::*;
use p3_air::BaseAir;
use lattica_prover_p3::block_v2::{native_g_bound_proof::NativeGBoundProof,
    native_gpu::g_bound_preparation::GBoundDescriptor};

impl RegisteredGBoundAir {
    pub(crate) fn compile_root_join_owned(&self, b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs, f_root: &[Wire; 4], x_root: &[Wire; 4], artifact: &NativeGBoundProof)
        -> Result<(), Error>
    {
        let descriptor = GBoundDescriptor::new(self.air.g_bound()).map_err(|_| Error::Descriptor)?;
        if artifact.kind != descriptor
            || artifact.proof.degree_bits != HEIGHT.ilog2() as usize + 1
            || artifact.public_values().len() != PUBLIC_VALUES
        { return Err(Error::Shape("owned GBound registration/request mismatch")); }
        let public = inputs.bases(b, artifact.public_values())?;
        let columns = self.air.periodic_columns();
        verifier::uni::verify_bounded(b, inputs, &self.air, HEIGHT, &public, &artifact.proof,
            &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
        for lane in 0..4 {
            b.assert_equal(public[lane], f_root[lane]);
            b.assert_equal(public[4 + lane], x_root[lane]);
        }
        Ok(())
    }
}
