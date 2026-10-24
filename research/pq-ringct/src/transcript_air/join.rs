//! Fixed descriptor, ordered source-root bundle, and exact SHAKE input root join.
use super::{TranscriptAir, PUBLIC_VALUES};
use lattica_prover_p3::block_v2::{
    machine::{
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, CompileError, ProofInputs},
    },
    profile::{self, Config},
};
use p3_field::PrimeCharacteristicRing;
pub struct TranscriptArtifact {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
pub fn verify_native(
    air: &TranscriptAir,
    artifact: &TranscriptArtifact,
) -> Result<(), crate::crypto_join::Error> {
    use crate::crypto_join::Error;
    if artifact.proof.degree_bits != air.height().ilog2() as usize + 1 {
        return Err(Error::Shape("transcript logical trace height"));
    }
    p3_uni_stark::verify(
        &profile::make_cpu_config(),
        air,
        &artifact.proof,
        &artifact.public_values,
    )
    .map_err(|e| Error::Compile(CompileError::Backend(format!("{e:?}"))))
}
pub fn verify_serialization(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    air: &TranscriptAir,
    roots: &[[Wire; 4]],
    shake_input: &[Wire; 4],
    artifact: &TranscriptArtifact,
) -> Result<(), CompileError> {
    let public = inputs.bases(b, &artifact.public_values)?;
    verifier::uni::verify(b, inputs, air, air.height(), &public, &artifact.proof)?;
    let state = bundle_wires(b, air, roots)?;
    for i in 0..4 {
        b.assert_equal(public[i], state[i]);
        b.assert_equal(public[4 + i], shake_input[i]);
    }
    Ok(())
}
/// Domain-separated metadata and source roots, in exact transcript order.
pub(crate) fn bundle_wires(
    b: &mut ScopedProgramBuilder<'_>,
    air: &TranscriptAir,
    roots: &[[Wire; 4]],
) -> Result<[Wire; 4], CompileError> {
    if roots.len() != air.parts().len() {
        return Err(CompileError::Shape("transcript ordered root count"));
    }
    let mut state = air.bundle_initial().map(|v| b.constant(v));
    for (index, (&kind, root)) in air.parts().iter().zip(roots).enumerate() {
        let metadata = TranscriptAir::metadata(kind, index).map(|v| b.constant(v));
        for chunk in [metadata, *root] {
            let mut data = [b.constant(Val::ZERO); 8];
            data[..4].copy_from_slice(&state);
            data[4..].copy_from_slice(&chunk);
            state.copy_from_slice(&b.poseidon(data)[..4]);
        }
    }
    Ok(state)
}
