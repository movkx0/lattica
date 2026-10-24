//! Exact descriptor registration and binding of ordered committed graph edges.
use super::*;
use crate::crypto_join::Error as JoinError;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};

pub struct AffineBatchProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
/// Machine roots supplied by the coordinator, which must also bind source and
/// operation inventory. Constructing a pending edge proves no relation.
#[derive(Clone, Debug)]
pub struct PendingAffine {
    pub kind: AffineKind,
    pub modulus: u64,
    pub left_commitment: [Wire; 4],
    pub right_commitment: Option<[Wire; 4]>,
    pub output_commitment: [Wire; 4],
}
pub struct RegisteredAffineAir {
    air: AffineAir,
}
impl RegisteredAffineAir {
    pub fn new(kind: AffineKind, modulus: u64, count: usize) -> Result<Self, JoinError> {
        Ok(Self {
            air: AffineAir::new(kind, modulus, count).map_err(|_| JoinError::Descriptor)?,
        })
    }
    pub fn air(&self) -> &AffineAir {
        &self.air
    }
    pub fn prove(&self, inputs: &[AffineInput]) -> Result<AffineBatchProof, JoinError> {
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
        let artifact = AffineBatchProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn verify(&self, artifact: &AffineBatchProof) -> Result<(), JoinError> {
        // The fixed hiding profile extends the logical trace by one degree bit.
        // Short periodic columns alone do not pin the number of repetitions.
        if artifact.proof.degree_bits != self.air.height.ilog2() as usize + 1 {
            return Err(JoinError::Shape("affine proof height"));
        }
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            &self.air,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(|error| JoinError::Compile(CompileError::Backend(format!("{error:?}"))))
    }
    /// Emits the full STARK/FRI verifier and a bundle of every ordered graph
    /// edge. No native equality or native proof-acceptance bit is consumed.
    pub fn compile_join(
        &self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        requests: &[PendingAffine],
        artifact: &AffineBatchProof,
    ) -> Result<(), JoinError> {
        if requests.len() != self.air.count
            || requests.iter().any(|request| {
                request.kind != self.air.kind
                    || request.modulus != self.air.modulus
                    || request.right_commitment.is_some() == self.air.kind.is_conversion()
            })
        {
            return Err(JoinError::Shape("affine registration/request mismatch"));
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
        let mut state = self.air.bundle_initial().map(|value| b.constant(value));
        for request in requests {
            let roots = [
                Some(request.left_commitment),
                request.right_commitment,
                Some(request.output_commitment),
            ];
            for root in roots.into_iter().flatten() {
                let mut message = [state[0]; 8];
                message[..4].copy_from_slice(&state);
                message[4..].copy_from_slice(&root);
                state.copy_from_slice(&b.poseidon(message)[..4]);
            }
        }
        for lane in 0..4 {
            b.assert_equal(state[lane], public[lane]);
        }
        Ok(())
    }
}
