//! Full recursive proof verifier and ordered private-proof bundle binding.
use super::{initial_bundle, ProofAir, HEIGHT, POLYNOMIALS};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::Config,
};
pub struct ProofArtifact {
    pub public_values: [Val; 4],
    pub proof: p3_uni_stark::Proof<Config>,
}
/// Returns constrained bundle root wires. All roots must also feed the actual
/// transaction relation; this component alone does not prove a valid spend.
pub fn verify_bundle(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    roots: &[[Wire; 4]; POLYNOMIALS],
    alpha: &[Wire; 8],
    artifact: &ProofArtifact,
) -> Result<[Wire; 4], CompileError> {
    let public = inputs.bases(b, &artifact.public_values)?;
    verifier::uni::verify(b, inputs, &ProofAir, HEIGHT, &public, &artifact.proof)?;
    let mut state = initial_bundle().map(|v| b.constant(v));
    for chunk in roots
        .iter()
        .copied()
        .chain(alpha.chunks_exact(4).map(|c| c.try_into().unwrap()))
    {
        let mut input = [state[0]; 8];
        input[..4].copy_from_slice(&state);
        input[4..].copy_from_slice(&chunk);
        state.copy_from_slice(&b.poseidon(input)[..4]);
    }
    for i in 0..4 {
        b.assert_equal(state[i], public[i]);
    }
    Ok(state)
}
