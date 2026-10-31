//! Complete unchanged linear-map STARK/FRI join over original native borrows.
use super::*;
use p3_air::BaseAir;
use lattica_prover_p3::block_v2::native_linear_map_proof::NativeLinearMapProof;
impl RegisteredLinearMapAir {
    pub(crate) fn compile_join_owned(&self, b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs, request: &PendingLinearMap, artifact: &NativeLinearMapProof)
        -> Result<(), JoinError>
    {
        let descriptor = self.air.descriptor.owned_descriptor().map_err(|_| JoinError::Descriptor)?;
        if request.descriptor != self.air.descriptor || request.input_commitments.len() != self.air.inputs()
            || artifact.kind != descriptor || artifact.proof.degree_bits != self.air.height().ilog2() as usize + 1
            || artifact.public_values().len() != self.air.public_values()
            || artifact.public_values[self.air.public_values()..].iter().any(|v| *v != Val::ZERO)
        { return Err(JoinError::Shape("owned linear-map registration/request mismatch")); }
        let public = inputs.bases(b, artifact.public_values())?;
        let columns = self.air.periodic_columns();
        verifier::uni::verify_bounded(b, inputs, &self.air, self.air.height(), &public, &artifact.proof,
            &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
        for (which,root) in request.input_commitments.iter().chain(core::iter::once(&request.output_commitment)).enumerate() {
            for lane in 0..4 { b.assert_equal(public[4*which+lane],root[lane]); }
        }
        Ok(())
    }
}
