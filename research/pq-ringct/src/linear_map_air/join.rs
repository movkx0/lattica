use super::*;
use crate::crypto_join::Error as JoinError;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};
pub struct LinearMapProof {
    pub public_values: Vec<Val>,
    pub proof: p3_uni_stark::Proof<Config>,
}
#[derive(Clone, Debug)]
pub struct PendingLinearMap {
    pub descriptor: LinearMapDescriptor,
    pub input_commitments: Vec<[Wire; 4]>,
    pub output_commitment: [Wire; 4],
}
pub struct RegisteredLinearMapAir {
    air: LinearMapAir,
}
impl RegisteredLinearMapAir {
    pub fn new(descriptor: LinearMapDescriptor) -> Self {
        Self {
            air: LinearMapAir::new(descriptor),
        }
    }
    pub fn air(&self) -> &LinearMapAir {
        &self.air
    }
    pub fn prove(&self, inputs: &[LinearMapInput]) -> Result<LinearMapProof, JoinError> {
        let witness = self
            .air
            .generate(inputs)
            .map_err(|_| JoinError::Descriptor)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &self.air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = LinearMapProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn verify(&self, artifact: &LinearMapProof) -> Result<(), JoinError> {
        if artifact.proof.degree_bits != self.air.height().ilog2() as usize + 1
            || artifact.public_values.len() != self.air.public_values()
        {
            return Err(JoinError::Shape("linear map proof shape"));
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
        request: &PendingLinearMap,
        artifact: &LinearMapProof,
    ) -> Result<(), JoinError> {
        if request.descriptor != self.air.descriptor
            || request.input_commitments.len() != self.air.inputs()
            || artifact.public_values.len() != self.air.public_values()
        {
            return Err(JoinError::Shape("linear map registered descriptor/roots"));
        }
        let public = inputs.bases(b, &artifact.public_values)?;
        verifier::uni::verify(
            b,
            inputs,
            &self.air,
            self.air.height(),
            &public,
            &artifact.proof,
        )?;
        for (which, root) in request
            .input_commitments
            .iter()
            .chain(std::iter::once(&request.output_commitment))
            .enumerate()
        {
            for lane in 0..4 {
                b.assert_equal(public[4 * which + lane], root[lane]);
            }
        }
        Ok(())
    }
}
