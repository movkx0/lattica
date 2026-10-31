//! Full unchanged affine STARK/FRI relation with bounded compiler storage.
//! The caller retains the native proof's original owner through its final read.
use super::*;
use lattica_prover_p3::block_v2::{native_affine_proof::NativeAffineProof,
    native_gpu::affine_preparation::{AffineDescriptor, AffineOperation}};

impl RegisteredAffineAir {
    pub(crate) fn compile_join_owned(&self, b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs, requests: &[PendingAffine], artifact: &NativeAffineProof)
        -> Result<(), JoinError>
    {
        let operation = match self.air.kind {
            AffineKind::Add => AffineOperation::Add,
            AffineKind::Sub => AffineOperation::Subtract,
            AffineKind::SignedToCanonical { bound } => AffineOperation::SignedToCanonical { bound },
        };
        let descriptor = AffineDescriptor::new(operation, self.air.modulus, self.air.count)
            .map_err(|_| JoinError::Descriptor)?;
        if artifact.kind != descriptor || artifact.proof.degree_bits != self.air.height.ilog2() as usize + 1
            || requests.len() != self.air.count || requests.iter().any(|request| {
                request.kind != self.air.kind || request.modulus != self.air.modulus
                    || request.right_commitment.is_some() == self.air.kind.is_conversion()
            })
        { return Err(JoinError::Shape("owned affine registration/request mismatch")); }
        let public = inputs.bases(b, &artifact.public_values)?;
        let columns = self.air.periodic_columns();
        verifier::uni::verify_bounded(b, inputs, &self.air, self.air.height, &public, &artifact.proof,
            &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
        let mut state = self.air.bundle_initial().map(|value| b.constant(value));
        for request in requests {
            let roots = [Some(request.left_commitment), request.right_commitment, Some(request.output_commitment)];
            for root in roots.into_iter().flatten() {
                let mut message = [state[0]; 8];
                message[..4].copy_from_slice(&state);
                message[4..].copy_from_slice(&root);
                state.copy_from_slice(&b.poseidon(message)[..4]);
            }
        }
        for lane in 0..4 { b.assert_equal(state[lane], public[lane]); }
        Ok(())
    }
}
