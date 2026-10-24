//! Typed AES-to-sampler joins without constructing whole stream byte wires.
//! The seed opening is range constrained and bound to the graph's BYTES32 root.
//! The complete AES request and sampler STARK are verified in one builder.
//! The AES proof can be direct segments or an authenticated component tree.
//! These are component relations, not complete transaction acceptance.
use crate::{
    aes_lane_air::{
        join::{AesLanePartition, AesLaneSegmentProof},
        Descriptor,
    },
    crypto_join::Error,
    request_bridge::{verify_aes_request, AesRequest},
    rust_verify::{committed_backend::BYTES32_DOMAIN, constraints_crypto::AES_INPUT_DOMAIN},
    sparse_air::{self, join::SparseArtifact},
    uniform_air::{self, join::UniformArtifact},
};
use lattica_prover_p3::block_v2::machine::{
    pq_bytes::{poseidon_commit_bytes, Byte},
    program::{ScopedProgramBuilder, Val, Wire},
    verifier::ProofInputs,
};
use p3_field::PrimeCharacteristicRing;

pub struct AesArtifacts<'a> {
    pub partition: &'a AesLanePartition,
    pub proofs: &'a [AesLaneSegmentProof],
}
/// The native key supplies witnesses only. Both key-root equality and the exact
/// key||domain-le64||counter-le32||length-le64 request hash are constrained.
pub fn bind_key_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    key_root: &[Wire; 4],
    key: &[u8; 32],
    descriptor: Descriptor,
) -> Result<[Wire; 4], Error> {
    let bytes = bind_key_bytes(b, inputs, key_root, key)?;
    Ok(key_request_root(b, &bytes, descriptor))
}

/// Two independently typed requests share one range-constrained key opening.
/// Each request still commits its complete domain, counter, and output length.
pub(crate) fn bind_key_request_pair(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    key_root: &[Wire; 4],
    key: &[u8; 32],
    descriptors: [Descriptor; 2],
) -> Result<[[Wire; 4]; 2], Error> {
    let bytes = bind_key_bytes(b, inputs, key_root, key)?;
    Ok(descriptors.map(|descriptor| key_request_root(b, &bytes, descriptor)))
}

fn bind_key_bytes(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    key_root: &[Wire; 4],
    key: &[u8; 32],
) -> Result<Vec<Byte>, Error> {
    let wires = inputs.bases(b, &key.map(Val::from_u8))?;
    let bytes: Vec<_> = wires
        .into_iter()
        .map(|wire| Byte::from_wire(b, wire))
        .collect();
    let root = poseidon_commit_bytes(b, BYTES32_DOMAIN, &bytes);
    for i in 0..4 {
        b.assert_equal(root[i], key_root[i]);
    }
    Ok(bytes)
}

fn key_request_root(
    b: &mut ScopedProgramBuilder<'_>,
    bytes: &[Byte],
    descriptor: Descriptor,
) -> [Wire; 4] {
    let mut request = bytes.to_vec();
    let metadata: Vec<_> = descriptor
        .domain
        .to_le_bytes()
        .into_iter()
        .chain(descriptor.start_counter.to_le_bytes())
        .chain((descriptor.output_len as u64).to_le_bytes())
        .collect();
    request.extend(metadata.into_iter().map(|v| Byte::constant(b, v)));
    poseidon_commit_bytes(b, AES_INPUT_DOMAIN, &request)
}
fn verify_uniform<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    kind: uniform_air::Kind,
    key_root: &[Wire; 4],
    key: &[u8; 32],
    output_roots: &[[Wire; 4]],
    aes: impl Into<AesRequest<'a>>,
    sampler: &UniformArtifact,
) -> Result<(), Error> {
    if output_roots.len() != kind.polynomials() {
        return Err(Error::Shape("uniform output root count"));
    }
    let descriptor = Descriptor {
        domain: if kind == uniform_air::Kind::SampleG4 {
            0
        } else {
            0x4368
        },
        start_counter: 0,
        output_len: kind.draws() * 4,
    };
    let input_root = bind_key_request(b, inputs, key_root, key, descriptor)?;
    let output_root: [Wire; 4] = inputs
        .bases(b, &sampler.public_values[..4])?
        .try_into()
        .unwrap();
    verify_aes_request(b, inputs, descriptor, &input_root, &output_root, aes.into())?;
    uniform_air::join::verify_sampler(b, inputs, kind, &output_root, output_roots, sampler)?;
    Ok(())
}
pub fn verify_sample_g<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    seed_root: &[Wire; 4],
    seed: &[u8; 32],
    output_roots: &[[Wire; 4]; 4],
    aes: impl Into<AesRequest<'a>>,
    sampler: &UniformArtifact,
) -> Result<(), Error> {
    verify_uniform(
        b,
        inputs,
        uniform_air::Kind::SampleG4,
        seed_root,
        seed,
        output_roots,
        aes,
        sampler,
    )
}
pub fn verify_alpha_prime<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    seed_root: &[Wire; 4],
    seed: &[u8; 32],
    output_root: &[Wire; 4],
    aes: impl Into<AesRequest<'a>>,
    sampler: &SparseArtifact,
) -> Result<(), Error> {
    // 2572 bytes consume161 full AES blocks; the following127-byte call begins
    // at byte2576. The four discarded bytes must never shift this counter.
    let descriptor = Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 127,
    };
    let input_root = bind_key_request(b, inputs, seed_root, seed, descriptor)?;
    let stream_root: [Wire; 4] = inputs
        .bases(b, &sampler.public_values[..4])?
        .try_into()
        .unwrap();
    verify_aes_request(b, inputs, descriptor, &input_root, &stream_root, aes.into())?;
    sparse_air::join::verify_sampler(
        b,
        inputs,
        sparse_air::Kind::AlphaPrime39,
        &stream_root,
        output_root,
        sampler,
    )?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn verify_expand_alpha<'a>(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    seed_root: &[Wire; 4],
    seed: &[u8; 32],
    alpha_roots: &[[Wire; 4]; 2],
    alpha_prime_root: &[Wire; 4],
    uniform_aes: impl Into<AesRequest<'a>>,
    uniform: &UniformArtifact,
    sparse_aes: impl Into<AesRequest<'a>>,
    sparse: &SparseArtifact,
) -> Result<(), Error> {
    verify_uniform(
        b,
        inputs,
        uniform_air::Kind::ExpandAlpha2,
        seed_root,
        seed,
        alpha_roots,
        uniform_aes,
        uniform,
    )?;
    verify_alpha_prime(
        b,
        inputs,
        seed_root,
        seed,
        alpha_prime_root,
        sparse_aes,
        sparse,
    )
}
#[cfg(test)]
mod tests;
