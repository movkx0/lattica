//! Unchanged private proof bundle relation with the bounded native verifier.
use super::*;
use lattica_prover_p3::block_v2::native_graph_source_proof::NativePrivateProof;
use p3_air::BaseAir;

pub(crate) fn verify_bounded(
    b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    roots: &[[Wire; 4]; POLYNOMIALS], alpha: &[Wire; 8], artifact: &NativePrivateProof,
) -> Result<[Wire; 4], CompileError> {
    let public = inputs.bases(b, &artifact.public_values)?;
    let air = ProofAir;
    let columns = air.periodic_columns();
    verifier::uni::verify_bounded(b, inputs, &air, HEIGHT, &public,
        &artifact.proof, &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
    let mut state = initial_bundle().map(|value| b.constant(value));
    for chunk in roots.iter().copied().chain(
        alpha.chunks_exact(4).map(|chunk| chunk.try_into().unwrap()),
    ) {
        let mut input = [state[0]; 8];
        input[..4].copy_from_slice(&state);
        input[4..].copy_from_slice(&chunk);
        state.copy_from_slice(&b.poseidon(input)[..4]);
    }
    for i in 0..4 { b.assert_equal(state[i], public[i]); }
    Ok(state)
}
