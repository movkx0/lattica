//! Complete unchanged permutation STARK/FRI join over original native borrows.
use super::*;
use p3_air::BaseAir;
use lattica_prover_p3::block_v2::native_permutation_proof::NativePermutationProof;
impl RegisteredPermutationAir {
    pub(crate) fn compile_join_owned(&self, b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs, request: &PendingPermutation, artifact: &NativePermutationProof)
        -> Result<(), JoinError>
    {
        let descriptor = crate::graph_proofs::owned_permutation::descriptor_for_kind(self.air.kind());
        if request.kind != self.air.kind() || artifact.kind != descriptor
            || artifact.proof.degree_bits != HEIGHT.ilog2() as usize + 1
            || artifact.public_values().len() != PUBLIC_VALUES
        { return Err(JoinError::Shape("owned permutation registration/request mismatch")); }
        let public = inputs.bases(b, artifact.public_values())?;
        let columns = self.air.periodic_columns();
        verifier::uni::verify_bounded(b, inputs, &self.air, HEIGHT, &public, &artifact.proof,
            &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
        for lane in 0..4 {
            b.assert_equal(public[lane], request.input_commitment[lane]);
            b.assert_equal(public[4 + lane], request.output_commitment[lane]);
        }
        Ok(())
    }
}
