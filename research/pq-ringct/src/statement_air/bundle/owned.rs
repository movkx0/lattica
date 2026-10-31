//! Unchanged statement bundle relation with the bounded native verifier.
use super::*;
use lattica_prover_p3::block_v2::native_graph_source_proof::NativeStatementProof;
use p3_air::BaseAir;

pub(crate) fn verify_bounded(
    b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    setup_seed: [u8; 32], expected_statement: [Wire; 4],
    polynomial_roots: &[[Wire; 4]; POLYNOMIALS], serial_words: &[Wire; 16],
    artifact: &NativeStatementProof,
) -> Result<(), CompileError> {
    let public = inputs.bases(b, &artifact.public_values)?;
    let air = StatementAir { setup_seed };
    let columns = air.periodic_columns();
    verifier::uni::verify_bounded(b, inputs, &air, HEIGHT, &public,
        &artifact.proof, &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
    for i in 0..4 { b.assert_equal(public[i], expected_statement[i]); }
    let mut state = initial(&setup_seed).map(|value| b.constant(value));
    for chunk in polynomial_roots.iter().copied().chain(
        serial_words.chunks_exact(4).map(|chunk| chunk.try_into().unwrap()),
    ) {
        let mut input = [state[0]; 8];
        input[..4].copy_from_slice(&state);
        input[4..].copy_from_slice(&chunk);
        state.copy_from_slice(&b.poseidon(input)[..4]);
    }
    for i in 0..4 { b.assert_equal(state[i], public[4 + i]); }
    Ok(())
}
