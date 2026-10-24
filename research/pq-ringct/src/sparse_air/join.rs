//! Typed recursive verification of the exact sampler and both ordered roots.
use super::{Kind, SparseAir, HEIGHT, PUBLIC_VALUES};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::Config,
};
pub struct SparseArtifact {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
/// Standalone component verification with the logical height pinned explicitly.
/// The fixed hiding profile adds one degree bit to the committed trace.
pub fn verify_native(
    kind: Kind,
    artifact: &SparseArtifact,
) -> Result<(), crate::crypto_join::Error> {
    use crate::crypto_join::Error;
    if artifact.proof.degree_bits != HEIGHT.ilog2() as usize + 1 {
        return Err(Error::Shape("sparse logical trace height"));
    }
    p3_uni_stark::verify(
        &lattica_prover_p3::block_v2::profile::make_cpu_config(),
        &SparseAir::new(kind),
        &artifact.proof,
        &artifact.public_values,
    )
    .map_err(|e| Error::Compile(CompileError::Backend(format!("{e:?}"))))
}
/// This proves only the specified byte-to-polynomial sampler. The caller must
/// verify and connect the AES/SHAKE producer of `input_root` and every consumer
/// of `polynomial_root` in the same circuit.
pub fn verify_sampler(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    kind: Kind,
    input_root: &[Wire; 4],
    polynomial_root: &[Wire; 4],
    artifact: &SparseArtifact,
) -> Result<(), CompileError> {
    let public = inputs.bases(b, &artifact.public_values)?;
    verifier::uni::verify(
        b,
        inputs,
        &SparseAir::new(kind),
        HEIGHT,
        &public,
        &artifact.proof,
    )?;
    for i in 0..4 {
        b.assert_equal(public[i], input_root[i]);
        b.assert_equal(public[4 + i], polynomial_root[i]);
    }
    Ok(())
}
