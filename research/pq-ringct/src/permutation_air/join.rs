use super::*;
use crate::crypto_join::Error as JoinError;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};
pub struct PermutationProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
#[derive(Clone, Debug)]
pub struct PendingPermutation {
    pub kind: PermutationKind,
    pub input_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}
pub struct RegisteredPermutationAir {
    air: PermutationAir,
}
impl RegisteredPermutationAir {
    pub fn new(kind: PermutationKind) -> Self {
        Self {
            air: PermutationAir::new(kind),
        }
    }
    pub fn air(&self) -> &PermutationAir {
        &self.air
    }
    pub fn prove(&self, input: &PermutationInput) -> Result<PermutationProof, JoinError> {
        let witness = self
            .air
            .generate(input)
            .map_err(|_| JoinError::Descriptor)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &self.air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = PermutationProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn verify(&self, artifact: &PermutationProof) -> Result<(), JoinError> {
        if artifact.proof.degree_bits != HEIGHT.ilog2() as usize + 1 {
            return Err(JoinError::Shape("permutation proof height"));
        }
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            &self.air,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(|error| JoinError::Compile(CompileError::Backend(format!("{error:?}"))))
    }
    pub fn compile_join(
        &self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        request: &PendingPermutation,
        artifact: &PermutationProof,
    ) -> Result<(), JoinError> {
        if request.kind != self.air.kind {
            return Err(JoinError::Shape("permutation predicate mismatch"));
        }
        let public = inputs.bases(b, &artifact.public_values)?;
        verifier::uni::verify(b, inputs, &self.air, HEIGHT, &public, &artifact.proof)?;
        for lane in 0..4 {
            b.assert_equal(public[lane], request.input_commitment[lane]);
            b.assert_equal(public[4 + lane], request.output_commitment[lane]);
        }
        Ok(())
    }
}
