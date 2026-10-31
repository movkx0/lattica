//! Unchanged sparse sampler relation using a borrowed original native proof.
use super::*;
use lattica_prover_p3::block_v2::{native_sparse_proof::NativeSparseProof,
    native_gpu::sparse_preparation::SparseKind};
use p3_air::BaseAir;

pub(crate) fn verify_bounded(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    kind: Kind, input_root: &[Wire; 4], polynomial_root: &[Wire; 4], artifact: &NativeSparseProof)
    -> Result<(), CompileError>
{
    let expected = match kind { Kind::AlphaPrime39 => SparseKind::AlphaPrime39,
        Kind::ChallengeX44 => SparseKind::ChallengeX44 };
    if artifact.kind != expected || artifact.proof.degree_bits != HEIGHT.ilog2() as usize + 1 {
        return Err(CompileError::Shape("owned sparse source geometry"));
    }
    let air = SparseAir::new(kind);
    let public = inputs.bases(b, &artifact.public_values)?;
    let columns = air.periodic_columns();
    verifier::uni::verify_bounded(b, inputs, &air, HEIGHT, &public, &artifact.proof,
        &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
    for i in 0..4 {
        b.assert_equal(public[i], input_root[i]);
        b.assert_equal(public[4 + i], polynomial_root[i]);
    }
    Ok(())
}
