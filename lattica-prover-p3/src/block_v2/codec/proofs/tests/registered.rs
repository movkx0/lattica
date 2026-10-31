use super::*;
use crate::block_v2::codec::{
    decode_registered_proof_bounded, encode_registered_proof_into, REGISTERED_PROOF_MAGIC,
    REGISTERED_PROOF_STORAGE_LIMIT_BYTES,
};

fn encoded(proof: &p3_batch_stark::BatchProof<profile::Config>) -> Vec<u8> {
    let mut output = vec![0; profile::MAX_PROOF_BYTES];
    let len = encode_registered_proof_into(proof, &mut output)
        .unwrap()
        .len();
    output.truncate(len);
    output
}

#[test]
fn registered_schema_round_trip_preserves_exact_cumulative_quota() {
    let proof = template_node().proof;
    let bytes = encoded(&proof);
    assert_eq!(&bytes[..8], REGISTERED_PROOF_MAGIC);
    let storage = Storage::new(REGISTERED_PROOF_STORAGE_LIMIT_BYTES);
    let decoded = storage.registered(&bytes).unwrap();
    assert_eq!(encoded(&decoded), bytes);
    let required = storage.vector_bytes.get() + storage.canonical_bytes.get();
    assert!(storage.vector_bytes.get() > 0);
    assert_eq!(storage.canonical_bytes.get(), bytes.len() - 8);
    assert!(decode_registered_proof_bounded(&bytes, required).is_ok());
    assert!(decode_registered_proof_bounded(&bytes, required - 1).is_err());
    let short = Storage::new(required - 1);
    assert!(short.registered(&bytes).is_err());
    assert!(short.rejected.get());
    assert_eq!(short.canonical_bytes.get(), 0);
    let zero = Storage::new(0);
    assert!(zero.registered(&bytes).is_err());
    assert_eq!(zero.allocations.get(), 0);
}

#[test]
fn registered_envelope_and_vector_refusals_precede_allocation() {
    let proof = template_node().proof;
    let bytes = encoded(&proof);
    let mut malformed = Vec::new();
    for len in 0..8 {
        malformed.push(bytes[..len].to_vec());
    }
    let mut wrong_kind = bytes.clone();
    wrong_kind[..8].copy_from_slice(super::super::super::NODE_MAGIC);
    malformed.push(wrong_kind);
    let mut wrong_layout = bytes.clone();
    wrong_layout[7] = if REGISTERED_PROOF_MAGIC[7] == b'1' {
        b'2'
    } else {
        b'1'
    };
    malformed.push(wrong_layout);
    let mut oversized = bytes.clone();
    oversized.resize(profile::MAX_PROOF_BYTES + 1, 0);
    malformed.push(oversized);
    // The first untrusted sequence is the first commitment's roots. An
    // excessive length must fail before its storage or scalar visitors exist.
    let mut count = REGISTERED_PROOF_MAGIC.to_vec();
    count.extend_from_slice(&[0xff; 9]);
    count.push(1);
    count.extend_from_slice(&bytes[9..]);
    malformed.push(count);
    for candidate in malformed {
        let storage = Storage::new(REGISTERED_PROOF_STORAGE_LIMIT_BYTES);
        assert!(storage.registered(&candidate).is_err());
        assert_eq!(storage.allocations.get(), 0);
        assert_eq!(storage.vector_bytes.get(), 0);
    }
}

#[test]
fn registered_decoder_rejects_noncanonical_field_trailing_and_truncated_data() {
    let bytes = encoded(&template_node().proof);
    // The first root-count is a single canonical varint (the pinned cap has
    // 64 roots), followed by its first Goldilocks coordinate.
    assert_eq!(bytes[8], 1 << profile::CAP_HEIGHT);
    let invalid = 0xffff_ffff_0000_0001_u64;
    let replacement = match NODE_ENCODING {
        Encoding::Legacy => postcard::to_allocvec(&invalid).unwrap(),
        Encoding::FixedU64 => invalid.to_le_bytes().to_vec(),
    };
    let old_width = match NODE_ENCODING {
        Encoding::Legacy => 1, // Template's first coordinate is zero.
        Encoding::FixedU64 => 8,
    };
    let mut noncanonical = bytes[..9].to_vec();
    noncanonical.extend_from_slice(&replacement);
    noncanonical.extend_from_slice(&bytes[9 + old_width..]);
    assert!(
        decode_registered_proof_bounded(&noncanonical, REGISTERED_PROOF_STORAGE_LIMIT_BYTES)
            .is_err()
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        decode_registered_proof_bounded(&trailing, REGISTERED_PROOF_STORAGE_LIMIT_BYTES).is_err()
    );
    for removed in [1, 8, bytes.len() / 2] {
        assert!(decode_registered_proof_bounded(
            &bytes[..bytes.len() - removed],
            REGISTERED_PROOF_STORAGE_LIMIT_BYTES
        )
        .is_err());
    }
}

#[test]
fn registered_encoder_respects_caller_capacity_and_profile_cap() {
    let proof = template_node().proof;
    let expected = encoded(&proof);
    let mut exact = vec![0; expected.len()];
    assert_eq!(
        encode_registered_proof_into(&proof, &mut exact).unwrap(),
        expected
    );
    for len in [0, 7, expected.len() - 1] {
        assert!(encode_registered_proof_into(&proof, &mut vec![0; len]).is_err());
    }
    let mut large = vec![0xa5; profile::MAX_PROOF_BYTES + 16];
    assert_eq!(
        encode_registered_proof_into(&proof, &mut large).unwrap(),
        expected
    );
    assert_eq!(&large[profile::MAX_PROOF_BYTES..], &[0xa5; 16]);
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[test]
fn registered_round_trip_passes_real_cpu_verification_and_rejects_mutation() {
    use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir, ProgramBuilder};
    fn program() -> crate::block_v2::machine::Program {
        let mut b = ProgramBuilder::new(1).unwrap();
        let public = b.public(0).unwrap();
        let witness = b.input();
        b.assert_equal(public, witness);
        b.finish(Some(8)).unwrap()
    }
    let expected = [Val::from_u64(37)];
    let prover = RegisteredProgram::new(MachineAir::new(program())).unwrap();
    let proof = prover.prove(&expected, &expected).unwrap();
    let bytes = encoded(&proof);
    drop(proof);
    drop(prover);
    // Reconstruct and register the trusted public relation independently.
    let reconstructed = RegisteredProgram::new(MachineAir::new(program())).unwrap();
    let verifier = reconstructed.verifier();
    drop(reconstructed);
    let mut decoded =
        decode_registered_proof_bounded(&bytes, REGISTERED_PROOF_STORAGE_LIMIT_BYTES).unwrap();
    verifier.verify(&decoded, &expected).unwrap();
    assert!(verifier
        .verify(&decoded, &[expected[0] + Val::ONE])
        .is_err());
    decoded.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += profile::Challenge::ONE;
    assert!(verifier.verify(&decoded, &expected).is_err());
}
