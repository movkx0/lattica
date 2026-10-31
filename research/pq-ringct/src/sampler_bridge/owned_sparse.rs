//! Atomic ExpandAlpha relation with original Uniform and Sparse proof borrows.
use super::*;
use lattica_prover_p3::block_v2::{native_sparse_proof::NativeSparseProof,
    native_uniform_proof::NativeUniformProof};

pub(crate) fn verify_alpha_prime<'a>(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    seed_root: &[Wire; 4], seed: &[u8; 32], output_root: &[Wire; 4],
    aes: impl Into<AesRequest<'a>>, sampler: &NativeSparseProof) -> Result<(), Error>
{
    // Preserve the reference call boundary: 2572 bytes consume 161 blocks,
    // leaving four discarded bytes before this 127-byte sparse request.
    let descriptor = Descriptor { domain: 0x4368, start_counter: 161, output_len: 127 };
    let input_root = bind_key_request(b, inputs, seed_root, seed, descriptor)?;
    let stream_root: [Wire; 4] = inputs.bases(b, &sampler.public_values[..4])?.try_into().unwrap();
    verify_aes_request(b, inputs, descriptor, &input_root, &stream_root, aes.into())?;
    sparse_air::join::owned::verify_bounded(b, inputs, sparse_air::Kind::AlphaPrime39,
        &stream_root, output_root, sampler)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_expand_alpha<'a>(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    seed_root: &[Wire; 4], seed: &[u8; 32], alpha_roots: &[[Wire; 4]; 2],
    alpha_prime_root: &[Wire; 4], uniform_aes: impl Into<AesRequest<'a>>,
    uniform: &NativeUniformProof, sparse_aes: impl Into<AesRequest<'a>>, sparse: &NativeSparseProof)
    -> Result<(), Error>
{
    super::owned_uniform::verify_uniform(b, inputs, uniform_air::Kind::ExpandAlpha2,
        seed_root, seed, alpha_roots, uniform_aes, uniform)?;
    verify_alpha_prime(b, inputs, seed_root, seed, alpha_prime_root, sparse_aes, sparse)
}
