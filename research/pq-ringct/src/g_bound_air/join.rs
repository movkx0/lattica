//! Registered native and recursive verification of a GBound obligation.
use super::{GBoundAir, HEIGHT, PUBLIC_VALUES};
use crate::crypto_join::Error;
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};

pub struct GBoundArtifact {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
pub struct RegisteredGBoundAir {
    air: GBoundAir,
}
impl RegisteredGBoundAir {
    pub fn new(bound: u32) -> Result<Self, Error> {
        Ok(Self {
            air: GBoundAir::new(bound).map_err(|_| Error::Descriptor)?,
        })
    }
    pub fn air(&self) -> &GBoundAir {
        &self.air
    }
    pub fn prove(&self, f: &[i64; 256], x: &[i64; 256]) -> Result<GBoundArtifact, Error> {
        let witness = self.air.generate(f, x).map_err(|_| Error::Descriptor)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &self.air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = GBoundArtifact {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn verify(&self, artifact: &GBoundArtifact) -> Result<(), Error> {
        // The unchanged hiding profile extends the logical trace by one bit.
        if artifact.proof.degree_bits != HEIGHT.ilog2() as usize + 1 {
            return Err(Error::Shape("GBound proof height"));
        }
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            &self.air,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(|error| Error::Compile(CompileError::Backend(format!("{error:?}"))))
    }
    /// The bound is fixed when registering this component. Every graph consumer
    /// must join both ordered roots; this does not establish f0's derivation.
    pub fn compile_join(
        &self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        f_root: &[Wire; 4],
        x_root: &[Wire; 4],
        artifact: &GBoundArtifact,
    ) -> Result<(), Error> {
        let public = inputs.bases(b, &artifact.public_values)?;
        verifier::uni::verify(b, inputs, &self.air, HEIGHT, &public, &artifact.proof)?;
        for i in 0..4 {
            b.assert_equal(public[i], f_root[i]);
            b.assert_equal(public[4 + i], x_root[i]);
        }
        Ok(())
    }
}
