//! Same uniform STARK and ordered polynomial-root join, with bounded symbolic
//! storage. The caller retains its exact native proof owner throughout reads.
use super::*;
use lattica_prover_p3::block_v2::{native_uniform_proof::NativeUniformProof,
    native_gpu::uniform_preparation::UniformKind};
use p3_air::BaseAir;
pub(crate) fn verify_bounded(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    kind: Kind, input_root: &[Wire; 4], polynomial_roots: &[[Wire; 4]], artifact: &NativeUniformProof)
    -> Result<(), CompileError>
{
    let expected = match kind { Kind::SampleG4 => UniformKind::SampleG4,
        Kind::ExpandAlpha2 => UniformKind::ExpandAlpha2 };
    let air = UniformAir::new(kind);
    if artifact.kind != expected || polynomial_roots.len() != kind.polynomials()
        || artifact.proof.degree_bits != air.height().ilog2() as usize + 1
    { return Err(CompileError::Shape("owned uniform source geometry")); }
    let public = inputs.bases(b, &artifact.public_values)?;
    let columns = air.periodic_columns();
    verifier::uni::verify_bounded(b, inputs, &air, air.height(), &public, &artifact.proof,
        &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED)?;
    let state = bundle_wires(b, kind, polynomial_roots)?;
    for i in 0..4 {
        b.assert_equal(public[i], input_root[i]);
        b.assert_equal(public[4 + i], state[i]);
    }
    Ok(())
}
