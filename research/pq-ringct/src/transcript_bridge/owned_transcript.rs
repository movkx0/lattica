//! Unchanged complete SHAKE/digest/sparse joins over original proof borrows.
use super::*;
use lattica_prover_p3::block_v2::{native_transcript_proof::NativeTranscriptProof,
    native_sparse_proof::NativeSparseProof};
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_hash_alpha<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    air: &TranscriptAir,
    ordered_roots: &[[Wire; 4]],
    transcript: &NativeTranscriptProof,
    output_root: &[Wire; 4],
    output: &[u8; 32],
    shake: impl Into<ShakeRequest<'a>>,
) -> Result<(), Error> {
    let input_root: [Wire; 4] = inputs
        .bases(b, &transcript.public_values[4..])?
        .try_into()
        .unwrap();
    crate::transcript_air::join::owned::verify_bounded(
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
pub(crate) fn verify_hash_x<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    air: &TranscriptAir,
    ordered_roots: &[[Wire; 4]],
    transcript: &NativeTranscriptProof,
    output_root: &[Wire; 4],
    shake: impl Into<ShakeRequest<'a>>,
    sampler: &NativeSparseProof,
) -> Result<(), Error> {
    let input_root: [Wire; 4] = inputs
        .bases(b, &transcript.public_values[4..])?
        .try_into()
        .unwrap();
    crate::transcript_air::join::owned::verify_bounded(
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
    sparse_air::join::owned::verify_bounded(
        b,
        inputs,
        sparse_air::Kind::ChallengeX44,
        &stream_root,
        output_root,
        sampler,
    )?;
    Ok(())
}
