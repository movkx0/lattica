//! Complete recursive verifier of stream-to-ordered-root sampling only.
use super::{Kind, UniformAir};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::Config,
};
pub struct UniformArtifact {
    pub public_values: [Val; 8],
    pub proof: p3_uni_stark::Proof<Config>,
}
pub fn verify_native(
    kind: Kind,
    artifact: &UniformArtifact,
) -> Result<(), crate::crypto_join::Error> {
    use crate::crypto_join::Error;
    let air = UniformAir::new(kind);
    if artifact.proof.degree_bits != air.height().ilog2() as usize + 1 {
        return Err(Error::Shape("uniform logical trace height"));
    }
    p3_uni_stark::verify(
        &lattica_prover_p3::block_v2::profile::make_cpu_config(),
        &air,
        &artifact.proof,
        &artifact.public_values,
    )
    .map_err(|e| Error::Compile(CompileError::Backend(format!("{e:?}"))))
}
pub fn verify_sampler(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    kind: Kind,
    input_root: &[Wire; 4],
    polynomial_roots: &[[Wire; 4]],
    artifact: &UniformArtifact,
) -> Result<(), CompileError> {
    let air = UniformAir::new(kind);
    let public = inputs.bases(b, &artifact.public_values)?;
    verifier::uni::verify(b, inputs, &air, air.height(), &public, &artifact.proof)?;
    let state = bundle_wires(b, kind, polynomial_roots)?;
    for i in 0..4 {
        b.assert_equal(public[i], input_root[i]);
        b.assert_equal(public[4 + i], state[i]);
    }
    Ok(())
}
/// Ordered output bundle shared by direct and typed-branch consumers.
pub(crate) fn bundle_wires(
    b: &mut ScopedProgramBuilder<'_>,
    kind: Kind,
    polynomial_roots: &[[Wire; 4]],
) -> Result<[Wire; 4], CompileError> {
    if polynomial_roots.len() != kind.polynomials() {
        return Err(CompileError::Shape("fixed sampler output count"));
    }
    let air = UniformAir::new(kind);
    let mut state = air.bundle_initial().map(|v| b.constant(v));
    for root in polynomial_roots {
        let mut data = [state[0]; 8];
        data[..4].copy_from_slice(&state);
        data[4..].copy_from_slice(root);
        state.copy_from_slice(&b.poseidon(data)[..4]);
    }
    Ok(state)
}
