//! Complete typed hash-operation joins over committed transcript roots.
//! Direct requests verify every child segment; recursive requests verify an
//! authenticated complete component tree with the same exact endpoint roots.
//! Neither path accepts an omitted child using a native verification result.
use crate::{
    crypto_join::Error,
    request_bridge::{verify_shake_request, ShakeRequest},
    rust_verify::{committed_backend::BYTES32_DOMAIN, primitives, Q, QHAT},
    shake_air::{
        lane::{batch::ShakeBatchPartition, LaneShakeProof},
        Descriptor,
    },
    sparse_air::{self, join::SparseArtifact},
    transcript_air::{join::TranscriptArtifact, TranscriptAir},
};
use lattica_prover_p3::block_v2::machine::{
    pq_bytes::{poseidon_commit_bytes, Byte, SHAKE_INPUT_DOMAIN, SHAKE_OUTPUT_DOMAIN},
    program::{ScopedProgramBuilder, Val, Wire},
    verifier::ProofInputs,
};
use p3_field::PrimeCharacteristicRing;
pub struct ShakeArtifacts<'a> {
    pub partition: &'a ShakeBatchPartition,
    pub proofs: &'a [LaneShakeProof],
}
fn bytes32(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    bytes: &[u8; 32],
) -> Result<Vec<Byte>, Error> {
    Ok(inputs
        .bases(b, &bytes.map(Val::from_u8))?
        .into_iter()
        .map(|w| Byte::from_wire(b, w))
        .collect())
}
fn assert_root(b: &mut ScopedProgramBuilder<'_>, left: [Wire; 4], right: &[Wire; 4]) {
    for i in 0..4 {
        b.assert_equal(left[i], right[i]);
    }
}
/// A32-byte opening is constrained under both domain-separated commitments.
/// This is a framing bridge; verification of the producing SHAKE remains vital.
pub fn bridge_digest32(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    bytes: &[u8; 32],
    graph_root: &[Wire; 4],
) -> Result<[Wire; 4], Error> {
    let bytes = bytes32(b, inputs, bytes)?;
    let root = poseidon_commit_bytes(b, BYTES32_DOMAIN, &bytes);
    assert_root(b, root, graph_root);
    Ok(poseidon_commit_bytes(b, SHAKE_OUTPUT_DOMAIN, &bytes))
}
/// Native evaluation here is solely compilation of authenticated fixed setup
/// constants. `setup_seed` must come from the trusted registered network setup.
fn pp_prefix(setup_seed: &[u8; 32]) -> Vec<u8> {
    let mut setup = setup_seed.to_vec();
    setup.extend([64, 4, 4, 4, 5, 5]);
    setup.extend(256u16.to_le_bytes());
    setup.extend((Q as u32).to_le_bytes());
    setup.extend((QHAT as u32).to_le_bytes());
    setup.push(44);
    let mut prefix = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".to_vec();
    prefix.extend(primitives::shake(&setup, 32));
    prefix
}
pub fn pp_input_bytes(setup_seed: &[u8; 32], context: &[u8; 32]) -> Vec<u8> {
    let mut data = pp_prefix(setup_seed);
    data.extend(context);
    data
}
#[allow(clippy::too_many_arguments)]
pub fn verify_parameters_pp<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    setup_seed: &[u8; 32],
    context_root: &[Wire; 4],
    context: &[u8; 32],
    pp_root: &[Wire; 4],
    pp: &[u8; 32],
    shake: impl Into<ShakeRequest<'a>>,
) -> Result<(), Error> {
    let context_bytes = bytes32(b, inputs, context)?;
    let root = poseidon_commit_bytes(b, BYTES32_DOMAIN, &context_bytes);
    assert_root(b, root, context_root);
    let mut data: Vec<_> = pp_prefix(setup_seed)
        .into_iter()
        .map(|v| Byte::constant(b, v))
        .collect();
    data.extend(context_bytes);
    let input_root = poseidon_commit_bytes(b, SHAKE_INPUT_DOMAIN, &data);
    let output_root = bridge_digest32(b, inputs, pp, pp_root)?;
    verify_shake_request(
        b,
        inputs,
        Descriptor {
            input_len: data.len(),
            output_len: 32,
        },
        &input_root,
        &output_root,
        shake.into(),
    )
}
#[allow(clippy::too_many_arguments)]
pub fn verify_hash_alpha<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    air: &TranscriptAir,
    ordered_roots: &[[Wire; 4]],
    transcript: &TranscriptArtifact,
    output_root: &[Wire; 4],
    output: &[u8; 32],
    shake: impl Into<ShakeRequest<'a>>,
) -> Result<(), Error> {
    let input_root: [Wire; 4] = inputs
        .bases(b, &transcript.public_values[4..])?
        .try_into()
        .unwrap();
    crate::transcript_air::join::verify_serialization(
        b,
        inputs,
        air,
        ordered_roots,
        &input_root,
        transcript,
    )?;
    let output_root = bridge_digest32(b, inputs, output, output_root)?;
    verify_shake_request(
        b,
        inputs,
        Descriptor {
            input_len: air.byte_len(),
            output_len: 32,
        },
        &input_root,
        &output_root,
        shake.into(),
    )
}
#[allow(clippy::too_many_arguments)]
pub fn verify_hash_x<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    air: &TranscriptAir,
    ordered_roots: &[[Wire; 4]],
    transcript: &TranscriptArtifact,
    output_root: &[Wire; 4],
    shake: impl Into<ShakeRequest<'a>>,
    sampler: &SparseArtifact,
) -> Result<(), Error> {
    let input_root: [Wire; 4] = inputs
        .bases(b, &transcript.public_values[4..])?
        .try_into()
        .unwrap();
    crate::transcript_air::join::verify_serialization(
        b,
        inputs,
        air,
        ordered_roots,
        &input_root,
        transcript,
    )?;
    let stream_root: [Wire; 4] = inputs
        .bases(b, &sampler.public_values[..4])?
        .try_into()
        .unwrap();
    verify_shake_request(
        b,
        inputs,
        Descriptor {
            input_len: air.byte_len(),
            output_len: 137,
        },
        &input_root,
        &stream_root,
        shake.into(),
    )?;
    sparse_air::join::verify_sampler(
        b,
        inputs,
        sparse_air::Kind::ChallengeX44,
        &stream_root,
        output_root,
        sampler,
    )?;
    Ok(())
}
#[cfg(test)]
mod tests;
