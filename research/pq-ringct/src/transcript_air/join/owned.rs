//! Bounded unchanged transcript relation, borrowing the original native proof.
use super::*;
use p3_air::BaseAir;
use lattica_prover_p3::block_v2::native_transcript_proof::NativeTranscriptProof;

pub(crate) fn verify_bounded(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    air: &TranscriptAir, roots: &[[Wire; 4]], shake_input: &[Wire; 4], artifact: &NativeTranscriptProof)
    -> Result<(), CompileError>
{
    let layout = crate::graph_auxiliary::owned_transcript::layout_for_air(air)
        .map_err(|_| CompileError::Shape("owned transcript source layout"))?;
    if artifact.kind != layout || artifact.proof.degree_bits != air.height().ilog2() as usize + 1
        || roots.len() != layout.part_count() {
        return Err(CompileError::Shape("owned transcript source geometry"));
    }
    let public = inputs.bases(b, &artifact.public_values)?;
    let columns = air.periodic_columns();
    verifier::uni::verify_bounded(b, inputs, air, air.height(), &public, &artifact.proof,
        &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
    let state = bundle_wires(b, air, roots)?;
    for i in 0..4 {
        b.assert_equal(public[i], state[i]);
        b.assert_equal(public[4 + i], shake_input[i]);
    }
    Ok(())
}
