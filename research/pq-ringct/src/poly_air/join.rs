//! Typed recursive verification for the fixed four-coefficient NTT-ring product predicate.
use super::MulAir;
use crate::{crypto_join::Error, rust_verify::constraints_poly::PendingMul};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};
use p3_uni_stark::Proof;

/// An artifact is untrusted until verified against its source-specific registration.
pub struct MulBatchProof {
    pub public_values: Vec<Val>,
    pub proof: Proof<Config>,
}

/// Root-only edge request; construction proves nothing about its operands.
pub struct MulRootRequest {
    pub modulus: u64,
    pub left_commitment: [Wire; 4],
    pub right_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}

/// The private AIR is constructed only from an allowed modulus and exact batch size.
/// Callers cannot substitute an unrelated predicate or unauthenticated schedule.
pub struct RegisteredMulAir {
    air: MulAir,
}
impl RegisteredMulAir {
    pub fn new(modulus: u64, count: usize) -> Result<Self, Error> {
        Ok(Self {
            air: MulAir::new(modulus, count).map_err(|_| Error::Descriptor)?,
        })
    }
    pub fn air(&self) -> &MulAir {
        &self.air
    }
    pub fn prove(&self, left: &[[u64; 256]], right: &[[u64; 256]]) -> Result<MulBatchProof, Error> {
        let witness = self
            .air
            .generate(left, right)
            .map_err(|_| Error::Descriptor)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &self.air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = MulBatchProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn verify(&self, artifact: &MulBatchProof) -> Result<(), Error> {
        if artifact.public_values.len() != self.air.public_values() {
            return Err(Error::Shape("serial polynomial product public width"));
        }
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            &self.air,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(|error| Error::Compile(CompileError::Backend(format!("{error:?}"))))
    }
    /// Emit the actual STARK/FRI verifier and bind every ordered polynomial root.
    /// Native acceptance is neither queried nor used as a circuit input.
    pub fn compile_join(
        &self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        requests: &[&PendingMul],
        artifact: &MulBatchProof,
    ) -> Result<(), Error> {
        let roots: Vec<_> = requests
            .iter()
            .map(|request| MulRootRequest {
                modulus: request.modulus,
                left_commitment: request.left_commitment,
                right_commitment: request.right_commitment,
                output_commitment: request.output_commitment,
            })
            .collect();
        self.compile_root_join(b, inputs, &roots, artifact)
    }

    /// Same complete verifier, without manufacturing coefficient-level values
    /// when a graph coordinator owns only canonical polynomial roots.
    pub fn compile_root_join(
        &self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        requests: &[MulRootRequest],
        artifact: &MulBatchProof,
    ) -> Result<(), Error> {
        if requests.len() != self.air.count
            || requests
                .iter()
                .any(|request| request.modulus != self.air.modulus)
            || artifact.public_values.len() != self.air.public_values()
        {
            return Err(Error::Shape(
                "serial polynomial product registration/request/public shape",
            ));
        }
        let public = inputs.bases(b, &artifact.public_values)?;
        verifier::uni::verify(
            b,
            inputs,
            &self.air,
            self.air.height,
            &public,
            &artifact.proof,
        )?;
        for (polynomial, request) in requests.iter().enumerate() {
            for (which, commitment) in [
                request.left_commitment,
                request.right_commitment,
                request.output_commitment,
            ]
            .into_iter()
            .enumerate()
            {
                for lane in 0..4 {
                    b.assert_equal(public[12 * polynomial + 4 * which + lane], commitment[lane]);
                }
            }
        }
        Ok(())
    }
}
