use super::*;
use crate::ring;
use lattica_prover_p3::block_v2::machine::{programs, verifier::template};
use p3_field::PrimeCharacteristicRing;

const REPRESENTATION: CompilerRepresentation = CompilerRepresentation::FusedTernaryRangesV1;

fn descriptor() -> ProofDescriptor {
    ProofDescriptor {
        active_rows: 1,
        padded_rows: 64,
        wires: 16,
        witness_values: 1,
        canonical_manifest_digest: [17; 32],
        registered_program_id: [1, 2, 3, 4],
    }
}

// This zero-filled shape object exercises transport only. It is not a proof
// and no test treats successful parsing as cryptographic verification.
fn transport_shape() -> BatchProof<profile::Config> {
    template::batch(&programs::shape(64).unwrap()).unwrap()
}

#[test]
#[ignore = "serialized full-height wide codec feasibility; shape only, no proof or GPU dispatch"]
fn full_height_wide_transport_shape_fits_fixed_inner_codec_ceiling() {
    use lattica_prover_p3::block_v2::machine::{MachineAir, ProgramBuilder};
    assert_eq!(codec::REGISTERED_PROOF_MAGIC, b"LBV2RP02");
    let program = ProgramBuilder::new(4)
        .unwrap()
        .finish(Some(1 << 19))
        .unwrap();
    let shape = template::batch(&MachineAir::new(program)).unwrap();
    let opened = &shape.opened_values.instances[0];
    assert_eq!(shape.degree_bits, [20]);
    assert_eq!(opened.base_opened_values.trace_local.len(), 94);
    assert_eq!(
        opened
            .base_opened_values
            .preprocessed_local
            .as_ref()
            .unwrap()
            .len(),
        200
    );
    assert_eq!(opened.base_opened_values.quotient_chunks.len(), 16);
    assert_eq!(opened.permutation_local.len(), 51);
    assert_eq!(shape.opening_proof.1.commit_phase_commits.len(), 20);
    assert_eq!(shape.opening_proof.1.query_proofs.len(), 128);
    let mut output = vec![0; profile::MAX_PROOF_BYTES];
    let length = codec::encode_registered_proof_into(&shape, &mut output)
        .unwrap()
        .len();
    assert!(length <= profile::MAX_PROOF_BYTES);
    let decoded = codec::decode_registered_proof_bounded(
        &output[..length],
        codec::REGISTERED_PROOF_STORAGE_LIMIT_BYTES,
    )
    .unwrap();
    let mut round_trip = vec![0; length];
    assert_eq!(
        codec::encode_registered_proof_into(&decoded, &mut round_trip).unwrap(),
        &output[..length]
    );
    assert!(codec::encode_registered_proof_into(&shape, &mut output[..length - 1]).is_err());
    eprintln!(
        "direct_ring_full_height_codec rows={} inner_bytes={length} inner_limit={} packet_bytes={} inner_margin={} proof_validity_tested=false",
        1 << 19, profile::MAX_PROOF_BYTES, length + HEADER_BYTES, profile::MAX_PROOF_BYTES - length,
    );
}

fn statement() -> Statement {
    ring::fixture(Context([61; 32])).unwrap().0
}

fn packet() -> (Statement, Vec<u8>) {
    let statement = statement();
    let bytes = encode(
        &statement,
        statement.context,
        REPRESENTATION,
        descriptor(),
        &transport_shape(),
        WORKER_HOST_BYTES,
    )
    .unwrap();
    (statement, bytes)
}

#[test]
fn streamed_public_binding_matches_reference_and_every_public_owner() {
    let statement = statement();
    assert_eq!(header::public_binding(&statement), statement.binding());
    let binding = statement.binding();
    for which in 0..9 {
        let mut mutated = statement.clone();
        match which {
            0 => mutated.context.0[0] ^= 1,
            1 => mutated.setup_seed[0] ^= 1,
            2 => mutated.ring.swap(0, 1),
            3 => mutated.ring[0][0].public_key[0][0] ^= 1,
            4 => mutated.ring[0][0].coin[0][0] ^= 1,
            5 => mutated.recipients[0][0][0] ^= 1,
            6 => mutated.output_coins[0][0][0] ^= 1,
            7 => mutated.serials.swap(0, 1),
            8 => mutated.profile = crate::Profile::PrivateNoteDirectV1,
            _ => unreachable!(),
        }
        assert_eq!(header::public_binding(&mutated), mutated.binding());
        assert_ne!(header::public_binding(&mutated), binding);
    }
}

#[test]
fn fixed_header_round_trip_preserves_all_fields_and_representation_tags() {
    let statement = statement();
    for representation in [
        CompilerRepresentation::InlinePublicMontgomeryConstantsV2,
        CompilerRepresentation::FusedPublicLinearV1,
        CompilerRepresentation::FusedPublicNttV1,
        CompilerRepresentation::FusedTernaryNttV1,
        CompilerRepresentation::FusedTernaryRangesV1,
    ] {
        let header =
            Header::for_statement(&statement, statement.context, representation, descriptor())
                .unwrap();
        let bytes = header.encode(8).unwrap();
        assert_eq!(bytes.len(), 212);
        let (decoded, len) = Header::decode(&bytes).unwrap();
        assert_eq!(len, 8);
        assert_eq!(decoded.representation, representation);
        assert_eq!(decoded.context, statement.context);
        assert_eq!(decoded.public, statement.binding());
        assert_eq!(decoded.descriptor, descriptor());
        assert_eq!(decoded.encode(len).unwrap(), bytes);
    }
}

#[test]
fn header_refuses_wrong_profile_noncanonical_fields_and_impossible_geometry() {
    let statement = statement();
    let header =
        Header::for_statement(&statement, statement.context, REPRESENTATION, descriptor()).unwrap();
    let bytes = header.encode(8).unwrap();
    for length in [0, 7, 40, HEADER_BYTES - 1] {
        assert!(Header::decode(&bytes[..length]).is_err());
    }
    for offset in [0, 8, 40] {
        let mut mutated = bytes;
        mutated[offset] ^= 0x80;
        assert!(matches!(Header::decode(&mutated), Err(Error::Profile)));
    }
    for offset in [76, 172] {
        let mut mutated = bytes;
        mutated[offset..offset + 8].copy_from_slice(&crate::GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(Header::decode(&mutated), Err(Error::NonCanonical)));
    }
    for (offset, value) in [
        (108, 0u64),
        (108, 65),
        (116, 63),
        (116, MAX_PADDED_ROWS * 2),
        (124, 3),
        (132, 13),
        (204, 0),
        (204, (profile::MAX_PROOF_BYTES + 1) as u64),
        (204, u64::MAX),
    ] {
        let mut mutated = bytes;
        mutated[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(Header::decode(&mutated), Err(Error::Geometry)));
    }
}

#[test]
fn expected_profile_context_and_statement_are_independent_of_packet_claims() {
    let (statement, bytes) = packet();
    let artifact = Artifact::decode(bytes, WORKER_HOST_BYTES).unwrap();
    artifact
        .check_expected(&statement, statement.context, REPRESENTATION)
        .unwrap();
    assert!(matches!(
        artifact.check_expected(
            &statement,
            statement.context,
            CompilerRepresentation::FusedTernaryNttV1
        ),
        Err(Error::Profile)
    ));
    let mut other = statement.clone();
    other.context.0[0] ^= 1;
    assert!(matches!(
        artifact.check_expected(&other, other.context, REPRESENTATION),
        Err(Error::Context)
    ));
    other = statement.clone();
    other.setup_seed[0] ^= 1;
    assert!(matches!(
        artifact.check_expected(&other, other.context, REPRESENTATION),
        Err(Error::ProofRejected)
    ));
}

#[test]
fn packet_refuses_trailing_truncated_and_cross_layout_payloads() {
    let (_, bytes) = packet();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        Artifact::decode(trailing, WORKER_HOST_BYTES),
        Err(Error::Geometry)
    ));
    let mut truncated = bytes.clone();
    truncated.pop();
    assert!(matches!(
        Artifact::decode(truncated, WORKER_HOST_BYTES),
        Err(Error::Geometry)
    ));
    let mut wrong_layout = bytes;
    wrong_layout[HEADER_BYTES + 7] = if codec::REGISTERED_PROOF_MAGIC[7] == b'1' {
        b'2'
    } else {
        b'1'
    };
    assert!(matches!(
        Artifact::decode(wrong_layout, WORKER_HOST_BYTES),
        Err(Error::ProofRejected)
    ));
}

#[test]
fn decoder_charges_entire_input_capacity_before_allocating_proof() {
    let (_, bytes) = packet();
    let mut oversized_owner = Vec::with_capacity(bytes.len() + 8192);
    oversized_owner.extend_from_slice(&bytes);
    let exact = decoding_required_host_bytes(&oversized_owner).unwrap();
    assert_eq!(
        exact,
        oversized_owner.capacity() + DECODE_STORAGE_LIMIT_BYTES + FIXED_CODEC_BYTES
    );
    let mut accepted = Vec::with_capacity(oversized_owner.capacity());
    accepted.extend_from_slice(&bytes);
    assert_eq!(accepted.capacity(), oversized_owner.capacity());
    assert!(Artifact::decode(accepted, exact).is_ok());
    assert!(matches!(
        Artifact::decode(oversized_owner, exact - 1),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        Artifact::decode(bytes, WORKER_HOST_BYTES + 1),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn encoder_charges_existing_proof_and_full_output_capacity() {
    let statement = statement();
    let proof = transport_shape();
    let exact = encoding_required_host_bytes(&proof).unwrap();
    assert_eq!(
        exact,
        proof_bytes(&proof).unwrap() + MAX_ENCODED_BYTES + FIXED_CODEC_BYTES
    );
    assert!(encode(
        &statement,
        statement.context,
        REPRESENTATION,
        descriptor(),
        &proof,
        exact,
    )
    .is_ok());
    assert!(matches!(
        encode(
            &statement,
            statement.context,
            REPRESENTATION,
            descriptor(),
            &proof,
            exact - 1,
        ),
        Err(Error::ResourceLimit)
    ));
    let artifact = Artifact::from_proof(
        &statement,
        statement.context,
        REPRESENTATION,
        descriptor(),
        proof,
        WORKER_HOST_BYTES,
    )
    .unwrap();
    assert_eq!(artifact.encoding_required_host_bytes().unwrap(), exact);
    let bytes = artifact.encode(exact).unwrap();
    let decoded = Artifact::decode(bytes, WORKER_HOST_BYTES).unwrap();
    assert_eq!(decoded.descriptor(), descriptor());
    assert_eq!(decoded.public(), statement.binding());
    assert!(decoded.retained_host_bytes().unwrap() >= size_of::<Artifact>());
}

#[test]
fn transport_shape_checks_never_substitute_for_numerical_verification() {
    let mut proof = transport_shape();
    descriptor().admit_proof(&proof).unwrap();
    proof.degree_bits[0] += 1;
    assert_eq!(descriptor().admit_proof(&proof), Err(Error::Geometry));
    proof.degree_bits[0] -= 1;
    proof.opening_proof.1.query_proofs.pop();
    assert_eq!(descriptor().admit_proof(&proof), Err(Error::Geometry));
    let statement = statement();
    let mut header =
        Header::for_statement(&statement, statement.context, REPRESENTATION, descriptor()).unwrap();
    header.public[0] += Val::ONE;
    let artifact = Artifact {
        header,
        proof: transport_shape(),
    };
    assert_eq!(
        artifact.check_expected(&statement, statement.context, REPRESENTATION),
        Err(Error::ProofRejected)
    );
}
