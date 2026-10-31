//! Codec fixtures only: the zero-filled shape is never accepted as a proof.
use super::*;
use lattica_prover_p3::block_v2::machine::{programs, verifier::template};
use p3_field::PrimeCharacteristicRing;

fn expected() -> Header {
    Header {
        representation: CompilerRepresentation::FusedTernaryRangesV1,
        context: Context([0x37; 32]),
        public: [Val::ONE; 4],
        descriptor: ProofDescriptor {
            active_rows: 1,
            padded_rows: 64,
            wires: 16,
            witness_values: 1,
            canonical_manifest_digest: [0x38; 32],
            registered_program_id: [1, 2, 3, 4],
        },
    }
}

fn shape() -> BatchProof<profile::Config> {
    template::batch(&programs::shape(64).unwrap()).unwrap()
}

fn packet() -> Vec<u8> {
    encode_header_with(
        expected(),
        &shape(),
        WORKER_HOST_BYTES,
        Header::encode_outer,
    )
    .unwrap()
}

#[test]
fn child_and_outer_domains_cannot_cross_even_with_substituted_magic() {
    let expected = expected();
    let child = expected.encode(8).unwrap();
    let outer = expected.encode_outer(8).unwrap();
    assert_eq!(child.len(), HEADER_BYTES);
    assert_eq!(outer.len(), HEADER_BYTES);
    assert_ne!(&child[..40], &outer[..40]);
    assert!(matches!(Header::decode(&outer), Err(Error::Profile)));
    assert!(matches!(Header::decode_outer(&child), Err(Error::Profile)));
    let mut changed = outer;
    changed[..8].copy_from_slice(&child[..8]);
    assert!(matches!(Header::decode(&changed), Err(Error::Profile)));
    changed = child;
    changed[..8].copy_from_slice(&outer[..8]);
    assert!(matches!(
        Header::decode_outer(&changed),
        Err(Error::Profile)
    ));
    let (decoded, length) = Header::decode_outer(&outer).unwrap();
    assert_eq!(length, 8);
    assert_eq!(decoded.descriptor, expected.descriptor);
    assert_eq!(decoded.public, expected.public);
    assert_eq!(decoded.context, expected.context);
    assert_eq!(decoded.representation, expected.representation);
    assert_eq!(decoded.encode_outer(length).unwrap(), outer);
    assert!(matches!(
        Artifact::decode(packet(), WORKER_HOST_BYTES),
        Err(Error::Profile)
    ));
}

#[test]
fn expected_outer_claims_are_checked_before_invalid_payload_decode() {
    // Deliberately invalid payload. A different failure class demonstrates the
    // expected-context/profile gate runs before the proof decoder is reached.
    let header = expected();
    let mut bytes = Vec::from(header.encode_outer(8).unwrap());
    bytes.extend_from_slice(&[0; 8]);
    let mut other = header;
    other.context.0[0] ^= 1;
    assert!(matches!(
        decode_expected(bytes.clone(), other, WORKER_HOST_BYTES),
        Err(Error::Context)
    ));
    other = header;
    other.representation = CompilerRepresentation::FusedTernaryNttV1;
    assert!(matches!(
        decode_expected(bytes.clone(), other, WORKER_HOST_BYTES),
        Err(Error::Profile)
    ));
    other = header;
    other.public[0] += Val::ONE;
    assert!(matches!(
        decode_expected(bytes.clone(), other, WORKER_HOST_BYTES),
        Err(Error::ProofRejected)
    ));
    for lane in 0..6 {
        other = header;
        match lane {
            0 => other.descriptor.active_rows += 1,
            1 => other.descriptor.padded_rows *= 2,
            2 => other.descriptor.wires += 1,
            3 => other.descriptor.witness_values += 1,
            4 => other.descriptor.canonical_manifest_digest[0] ^= 1,
            5 => other.descriptor.registered_program_id[0] += 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            decode_expected(packet(), other, WORKER_HOST_BYTES),
            Err(Error::ProofRejected)
        ));
    }
    assert!(matches!(
        decode_expected(bytes, header, WORKER_HOST_BYTES),
        Err(Error::ProofRejected)
    ));
}

#[test]
fn outer_header_reuses_canonical_geometry_profile_and_length_guards() {
    let bytes = expected().encode_outer(8).unwrap();
    for offset in [0, 8, 40] {
        let mut changed = bytes;
        changed[offset] ^= 0x80;
        assert!(matches!(
            Header::decode_outer(&changed),
            Err(Error::Profile)
        ));
    }
    for offset in [76, 172] {
        let mut changed = bytes;
        changed[offset..offset + 8].copy_from_slice(&crate::GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(
            Header::decode_outer(&changed),
            Err(Error::NonCanonical)
        ));
    }
    for (offset, value) in [
        (108, 0u64),
        (116, 63),
        (124, 3),
        (132, 13),
        (204, 0),
        (204, u64::MAX),
    ] {
        let mut changed = bytes;
        changed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(
            Header::decode_outer(&changed),
            Err(Error::Geometry)
        ));
    }
    for length in [0, 7, HEADER_BYTES - 1] {
        assert!(Header::decode_outer(&bytes[..length]).is_err());
    }
}

#[test]
fn outer_transport_roundtrip_is_canonical_and_keeps_fixed_limits() {
    let header = expected();
    let original = packet();
    let required = required_host_bytes().unwrap();
    assert_eq!(
        required,
        MAX_RETAINED_PROOF_BYTES + MAX_ENCODED_BYTES + FIXED_CODEC_BYTES + TRANSPORT_FIXED_BYTES
    );
    assert_eq!(codec_allowance(required - 1), Err(Error::ResourceLimit));
    assert_eq!(
        codec_allowance(WORKER_HOST_BYTES + 1),
        Err(Error::ResourceLimit)
    );
    let (decoded, report) = roundtrip(
        shape(),
        header.context,
        header.representation,
        header.public,
        header.descriptor,
        required,
    )
    .unwrap();
    let encoded =
        encode_header_with(header, &decoded, WORKER_HOST_BYTES, Header::encode_outer).unwrap();
    assert_eq!(encoded, original);
    assert_eq!(report.encoded_bytes, original.len());
    assert_eq!(original.capacity(), MAX_ENCODED_BYTES);
    assert_eq!(
        report.decoded_proof_retained_bytes,
        proof_bytes(&decoded).unwrap()
    );
    assert!(report.decoded_proof_retained_bytes <= MAX_RETAINED_PROOF_BYTES);
    assert!(report.total_ns > 0);
    assert!(matches!(
        roundtrip(
            shape(),
            header.context,
            header.representation,
            header.public,
            header.descriptor,
            required - 1
        ),
        Err(Error::ResourceLimit)
    ));
    eprintln!("direct_ring_outer_transport_storage phase_bytes={required} fixed_additional_bytes={TRANSPORT_FIXED_BYTES} encoded_bytes={} proof_validity_tested=false", report.encoded_bytes);
}

#[test]
fn outer_packet_charges_capacity_and_refuses_trailing_truncated_or_wrong_payload() {
    let original = packet();
    let mut excessive = Vec::with_capacity(MAX_ENCODED_BYTES + 8192);
    excessive.extend_from_slice(&original);
    let exact = decoding_required_host_bytes(&excessive).unwrap();
    assert!(matches!(
        decode_expected(excessive, expected(), exact - 1),
        Err(Error::ResourceLimit)
    ));
    let mut changed = original.clone();
    changed.push(0);
    assert!(matches!(
        decode_expected(changed, expected(), WORKER_HOST_BYTES),
        Err(Error::Geometry)
    ));
    let mut changed = original.clone();
    changed.pop();
    assert!(matches!(
        decode_expected(changed, expected(), WORKER_HOST_BYTES),
        Err(Error::Geometry)
    ));
    let mut changed = original;
    changed[HEADER_BYTES + 7] ^= 0x80;
    assert!(matches!(
        decode_expected(changed, expected(), WORKER_HOST_BYTES),
        Err(Error::ProofRejected)
    ));
}
