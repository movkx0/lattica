//! Typed recursive verification for the fixed serial NTT predicate.
use super::NttAir;
use crate::{crypto_join::Error, rust_verify::constraints_ntt::PendingNtt};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};
use p3_uni_stark::Proof;

/// An artifact is untrusted until verified against its source-specific registration.
pub struct NttBatchProof {
    pub public_values: Vec<Val>,
    pub proof: Proof<Config>,
}

/// Root-only edge request; construction proves nothing about its operands.
pub struct NttRootRequest {
    pub modulus: u64,
    pub input_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}

/// The private AIR is constructed only from an allowed modulus and exact batch size.
/// Callers cannot substitute an unrelated predicate or unauthenticated schedule.
pub struct RegisteredNttAir {
    air: NttAir,
}
impl RegisteredNttAir {
    pub fn new(modulus: u64, count: usize) -> Result<Self, Error> {
        Ok(Self {
            air: NttAir::new(modulus, count).map_err(|_| Error::Descriptor)?,
        })
    }
    pub fn air(&self) -> &NttAir {
        &self.air
    }
    pub fn prove(&self, input: &[[u64; 256]]) -> Result<NttBatchProof, Error> {
        let witness = self.air.generate(input).map_err(|_| Error::Descriptor)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &self.air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = NttBatchProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn verify(&self, artifact: &NttBatchProof) -> Result<(), Error> {
        if artifact.public_values.len() != self.air.public_values() {
            return Err(Error::Shape("serial NTT public width"));
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
        requests: &[&PendingNtt],
        artifact: &NttBatchProof,
    ) -> Result<(), Error> {
        let roots: Vec<_> = requests
            .iter()
            .map(|request| NttRootRequest {
                modulus: request.modulus,
                input_commitment: request.input_commitment,
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
        requests: &[NttRootRequest],
        artifact: &NttBatchProof,
    ) -> Result<(), Error> {
        if requests.len() != self.air.count
            || requests
                .iter()
                .any(|request| request.modulus != self.air.modulus)
            || artifact.public_values.len() != self.air.public_values()
        {
            return Err(Error::Shape("serial NTT registration/request/public shape"));
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
            for lane in 0..4 {
                b.assert_equal(
                    public[8 * polynomial + lane],
                    request.input_commitment[lane],
                );
                b.assert_equal(
                    public[8 * polynomial + 4 + lane],
                    request.output_commitment[lane],
                );
            }
        }
        Ok(())
    }
}
