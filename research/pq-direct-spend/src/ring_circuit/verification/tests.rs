use super::*;
use crate::ring;
use crate::ring_circuit::{CompilerMemoryProfile, CompilerWireProfile};
use sha3::{Digest, Sha3_256};

const REPRESENTATION: CompilerRepresentation = CompilerRepresentation::FusedTernaryRangesV1;

fn capacity(memory: CompilerMemoryProfile) -> CompilerCapacityProfile {
    CompilerCapacityProfile::new(memory, CompilerWireProfile::Research16M)
}

#[test]
fn synthetic_inputs_are_domain_valid_and_owner_bounds_include_spare_capacity() {
    let (mut statement, _) = ring::fixture(Context([83; 32])).unwrap();
    let witness = reconstruction::synthetic_witness(&statement).unwrap();
    ring::admit_witness(&witness).unwrap();
    // Exhaustive destructuring makes a Witness field addition require updating
    // this zero-initialization validity check alongside the constructor audit.
    let ring::Witness {
        selected_pair,
        spending,
        input_openings,
        output_openings,
        input_values,
        output_values,
    } = &*witness;
    assert_eq!(*selected_pair, 0);
    assert!(spending
        .iter()
        .flatten()
        .flatten()
        .chain(input_openings.iter().flatten().flatten())
        .chain(output_openings.iter().flatten().flatten())
        .all(|&value| value == 0));
    assert_eq!(*input_values, [0; crate::INPUTS]);
    assert_eq!(*output_values, [0; crate::OUTPUTS]);
    let bytes = reconstruction::caller_bytes(&statement).unwrap();
    assert!(bytes <= REGISTERED_GPU_CALLER_HOST_BYTES);
    eprintln!(
        "direct_ring_verifier_caller_bytes actual={} orchestration={} allowance={} remaining={}",
        bytes,
        CALLER_ORCHESTRATION_BYTES,
        REGISTERED_GPU_CALLER_HOST_BYTES,
        REGISTERED_GPU_CALLER_HOST_BYTES - bytes,
    );
    assert!(bytes >= statement.ring.capacity() * std::mem::size_of::<[ring::Account; 2]>());
    statement.ring.reserve_exact(64);
    assert_eq!(
        reconstruction::caller_bytes(&statement),
        Err(Error::ResourceLimit)
    );
    assert_eq!(
        reconstruction::synthetic_witness(&statement).err(),
        Some(Error::ResourceLimit)
    );
}

#[test]
fn synthetic_witness_allocation_failure_is_fallible_and_follows_admission() {
    let mut statement = ring::fixture(Context([83; 32])).unwrap().0;
    let attempts = std::cell::Cell::new(0);
    assert!(reconstruction::caller_bytes(&statement).is_ok());
    assert!(matches!(
        reconstruction::synthetic_witness_with_forced_null(&statement, &attempts),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(attempts.get(), 1);

    attempts.set(0);
    statement.ring.reserve_exact(64);
    assert_eq!(
        reconstruction::caller_bytes(&statement),
        Err(Error::ResourceLimit)
    );
    assert!(matches!(
        reconstruction::synthetic_witness_with_forced_null(&statement, &attempts),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(attempts.get(), 0);
}

#[test]
fn reconstruction_rejects_wrong_expected_context_before_compiler_allocation() {
    let statement = ring::fixture(Context([83; 32])).unwrap().0;
    let error = reconstruction::compile(
        &statement,
        Context([84; 32]),
        capacity(CompilerMemoryProfile::Program2GiB),
        REPRESENTATION,
    )
    .err()
    .unwrap();
    assert_eq!(error, Error::Context);
}

#[test]
fn reconstructed_geometry_and_manifest_reject_each_changed_transport_claim() {
    use lattica_prover_p3::block_v2::machine::ProgramBuilder;
    let mut builder = ProgramBuilder::new(4).unwrap();
    let witness = builder.input();
    let public = builder.public(0).unwrap();
    builder.assert_equal(witness, public);
    let program = builder.finish(Some(8)).unwrap();
    let limits = capacity(CompilerMemoryProfile::Program2GiB).limits();
    let summary = Summary {
        representation: REPRESENTATION.name(),
        limits,
        host_allowance_bytes: HOST_BYTES,
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        wires: program.wire_count(),
        witness_values: program.witness_values(),
        compiler_requested_bytes_peak: program.construction_host_bytes(),
        compiler_packed_admitted_bytes_peak: program.construction_host_bytes(),
        deferred_crypto_obligations: 0,
        cryptographic_proof_available: false,
    };
    let manifest = proving::canonical_manifest_digest(&program).unwrap();
    let valid = reconstruction::descriptor(&program, manifest, [0; 4]);
    let relation = CompiledRelation {
        program,
        witness: vec![Val::ZERO],
        public: [Val::ZERO; 4],
        summary,
    };
    reconstruction::check_claims(&relation, valid).unwrap();
    for field in 0..5 {
        let mut invalid = valid;
        match field {
            0 => invalid.active_rows += 1,
            1 => invalid.padded_rows *= 2,
            2 => invalid.wires += 1,
            3 => invalid.witness_values += 1,
            4 => invalid.canonical_manifest_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            reconstruction::check_claims(&relation, invalid),
            Err(Error::ProofRejected)
        );
    }
}

#[test]
#[ignore = "serialized full-program equality; compiles several complete relations, no proof or GPU dispatch"]
fn full_program_reconstruction_is_independent_of_private_hints_and_capacity() {
    let context = Context([83; 32]);
    let (mut statement, witness) = ring::fixture(context).unwrap();
    let small = capacity(CompilerMemoryProfile::Program2GiB);
    let reference = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        small,
        REPRESENTATION,
        HOST_BYTES as usize,
    )
    .unwrap();
    drop(witness);
    assert_eq!(reference.summary.deferred_crypto_obligations, 0);
    let manifest = proving::canonical_manifest_digest(&reference.program).unwrap();
    let synthetic = reconstruction::compile(&statement, context, small, REPRESENTATION).unwrap();
    assert!(
        synthetic.program == reference.program,
        "zero hints changed the full program"
    );
    assert_eq!(synthetic.public, reference.public);
    assert!(
        synthetic.witness != reference.witness,
        "synthetic hints unexpectedly match fixture hints"
    );
    assert_eq!(
        proving::canonical_manifest_digest(&synthetic.program).unwrap(),
        manifest
    );
    drop(synthetic);

    let mut patterned = reconstruction::synthetic_witness(&statement).unwrap();
    patterned.selected_pair = ring::RING_PAIRS - 1;
    for (i, coefficient) in patterned
        .spending
        .iter_mut()
        .flatten()
        .flatten()
        .enumerate()
    {
        *coefficient = if i % 2 == 0 { 1 } else { -1 };
    }
    for coefficient in patterned.input_openings.iter_mut().flatten().flatten() {
        *coefficient = -1;
    }
    for coefficient in patterned.output_openings.iter_mut().flatten().flatten() {
        *coefficient = 1;
    }
    patterned.input_values = [1, crate::VALUE_LIMIT - 1];
    patterned.output_values = [crate::VALUE_LIMIT - 1, 1];
    ring::admit_witness(&patterned).unwrap();
    let other = compile_with_representation_diagnostics(
        &statement,
        &patterned,
        context,
        small,
        REPRESENTATION,
        HOST_BYTES as usize,
    )
    .unwrap();
    drop(patterned);
    assert!(
        other.program == reference.program,
        "private selection or boundary hints changed the full program"
    );
    assert!(
        other.witness != reference.witness,
        "patterned hints unexpectedly match fixture hints"
    );
    assert_eq!(
        proving::canonical_manifest_digest(&other.program).unwrap(),
        manifest
    );
    drop(other);

    let larger = reconstruction::compile(
        &statement,
        context,
        capacity(CompilerMemoryProfile::Program8GiB),
        REPRESENTATION,
    )
    .unwrap();
    assert!(
        larger.program == reference.program,
        "compiler allowance changed the full program"
    );
    assert_eq!(
        proving::canonical_manifest_digest(&larger.program).unwrap(),
        manifest
    );
    drop(larger);

    // Public matrices and public bindings are re-derived, never read from the
    // proof. Changing the seed must change the complete finalized relation.
    statement.setup_seed[0] ^= 1;
    let changed = reconstruction::compile(&statement, context, small, REPRESENTATION).unwrap();
    assert!(changed.program != reference.program);
    assert_ne!(
        proving::canonical_manifest_digest(&changed.program).unwrap(),
        manifest
    );
    assert_ne!(changed.public, reference.public);
}

#[test]
#[ignore = "serialized full fresh GPU proof, artifact round trip, independent verification and forged-envelope cryptographic negatives"]
fn full_proof_rebuild_and_forged_envelopes_are_numerically_checked() {
    use super::super::proving::FreshGpuProofInput;
    let context = Context([87; 32]);
    let selected_capacity = capacity(CompilerMemoryProfile::Program2GiB);
    let (statement, witness) = ring::fixture(context).unwrap();
    let relation = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        selected_capacity,
        REPRESENTATION,
        HOST_BYTES as usize,
    )
    .unwrap();
    drop(witness);
    let proved = FreshGpuProofInput::new(statement, context, relation)
        .unwrap()
        .prove()
        .unwrap();
    let (mut statement, original_descriptor, proof, report) = proved.into_parts();
    assert!(report.terminal.context_closed);
    assert!(report.terminal.queue_drained);
    drop(report);
    let codec_allowance = HOST_BYTES as usize - REGISTERED_GPU_CALLER_HOST_BYTES;
    let original = Artifact::from_proof(
        &statement,
        context,
        REPRESENTATION,
        original_descriptor,
        proof,
        codec_allowance,
    )
    .unwrap();
    let packet = original.encode(codec_allowance).unwrap();
    let canonical_digest: [u8; 32] = Sha3_256::digest(&packet).into();
    drop(original);
    let mut artifact = Artifact::decode(packet, codec_allowance).unwrap();
    let report = verify(
        &mut artifact,
        &statement,
        context,
        selected_capacity,
        REPRESENTATION,
    )
    .unwrap();
    assert!(report.verified);
    assert!(!report.reused_prover_state);
    assert!(!report.synthetic_hints_evaluated);
    assert_eq!(report.mutation_checks, 2);
    assert_eq!(report.expected_context, context.0);
    assert_eq!(
        report.expected_public_binding,
        statement.binding().map(|value| value.as_canonical_u64())
    );
    assert_eq!(
        report.artifact_profile_digest,
        artifact::profile_digest(REPRESENTATION)
    );
    assert_eq!(report.descriptor, original_descriptor);
    assert!(report.terminal.context_closed);
    assert!(!report.terminal.completion_claimed);
    drop(report);

    // Preserve one authentic proof, but forge every public transport claim to
    // match each independently changed expected statement. Fresh preprocessing
    // creates the actual changed cap before the CPU verifier sees the proof.
    // These assertions cannot pass merely because a header or ID was rejected.
    let original_recipient = statement.recipients[0][0][0];
    for changed_context in [false, true] {
        if changed_context {
            statement.context.0[0] ^= 1;
        } else {
            statement.recipients[0][0][0] = (original_recipient + 1) % ring::Q;
        }
        let relation = reconstruction::compile(
            &statement,
            statement.context,
            selected_capacity,
            REPRESENTATION,
        )
        .unwrap();
        let rebuilt = register_independently(relation, &statement, None).unwrap();
        assert_ne!(
            rebuilt.descriptor.canonical_manifest_digest,
            original_descriptor.canonical_manifest_digest
        );
        assert_ne!(
            rebuilt.descriptor.registered_program_id,
            original_descriptor.registered_program_id
        );
        artifact
            .forge_header_for_test(&statement, REPRESENTATION, rebuilt.descriptor)
            .unwrap();
        artifact
            .check_expected(&statement, statement.context, REPRESENTATION)
            .unwrap();
        assert_eq!(artifact.descriptor(), rebuilt.descriptor);
        assert_eq!(artifact.public(), artifact::statement_binding(&statement));
        assert!(rebuilt
            .verifier
            .verify(artifact.proof(), &artifact.public())
            .is_err());
        assert!(rebuilt.terminal.context_closed);
        drop(rebuilt);
        statement.context = context;
        statement.recipients[0][0][0] = original_recipient;
    }
    artifact
        .forge_header_for_test(&statement, REPRESENTATION, original_descriptor)
        .unwrap();
    let restored = artifact.encode(codec_allowance).unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha3_256::digest(&restored)),
        canonical_digest
    );
}
