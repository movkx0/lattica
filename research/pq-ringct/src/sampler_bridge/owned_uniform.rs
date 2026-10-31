//! Native-owned uniform adapter. AES descriptor, stream root, ordered output
//! bundle and all constraints are identical to the existing sampler bridge.
use super::*;
use lattica_prover_p3::block_v2::native_uniform_proof::NativeUniformProof;
pub(crate) fn verify_uniform<'a>(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    kind: uniform_air::Kind, key_root: &[Wire; 4], key: &[u8; 32], output_roots: &[[Wire; 4]],
    aes: impl Into<AesRequest<'a>>, sampler: &NativeUniformProof) -> Result<(), Error>
{
    if output_roots.len() != kind.polynomials() { return Err(Error::Shape("uniform output root count")); }
    let descriptor = Descriptor { domain: if kind == uniform_air::Kind::SampleG4 { 0 } else { 0x4368 },
        start_counter: 0, output_len: kind.draws() * 4 };
    let input_root = bind_key_request(b, inputs, key_root, key, descriptor)?;
    let output_root: [Wire; 4] = inputs.bases(b, &sampler.public_values[..4])?.try_into().unwrap();
    verify_aes_request(b, inputs, descriptor, &input_root, &output_root, aes.into())?;
    uniform_air::join::owned::verify_bounded(b, inputs, kind, &output_root, output_roots, sampler)?;
    Ok(())
}
pub(crate) fn verify_sample_g<'a>(b: &mut ScopedProgramBuilder<'_>, inputs: &mut ProofInputs,
    seed_root: &[Wire; 4], seed: &[u8; 32], output_roots: &[[Wire; 4]; 4],
    aes: impl Into<AesRequest<'a>>, sampler: &NativeUniformProof) -> Result<(), Error>
{
    verify_uniform(b, inputs, uniform_air::Kind::SampleG4, seed_root, seed, output_roots, aes, sampler)
}
