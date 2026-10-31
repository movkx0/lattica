use super::*;
use crate::ring;
use crate::ring_circuit::{
    compile_with_representation_diagnostics, proving::FreshGpuProofInput, CompilerMemoryProfile,
    CompilerWireProfile, Summary,
};

const REPRESENTATION: CompilerRepresentation = CompilerRepresentation::FusedTernaryRangesV1;
const CAPACITY: CompilerCapacityProfile = CompilerCapacityProfile::new(
    CompilerMemoryProfile::Program2GiB,
    CompilerWireProfile::Research16M,
);

fn tiny_relation(height: usize) -> CompiledRelation {
    let mut builder = ProgramBuilder::new(PUBLICS).unwrap();
    let input = builder.input();
    builder.assert_equal(input, builder.public(0).unwrap());
    let program = builder.finish(Some(height)).unwrap();
    let summary = Summary {
        representation: REPRESENTATION.name(),
        limits: CAPACITY.limits(),
        host_allowance_bytes: HOST_BYTES as u64,
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        wires: program.wire_count(),
        witness_values: program.witness_values(),
        compiler_requested_bytes_peak: program.construction_host_bytes(),
        compiler_packed_admitted_bytes_peak: program.construction_host_bytes(),
        deferred_crypto_obligations: 0,
        cryptographic_proof_available: false,
    };
    CompiledRelation {
        program,
        witness: vec![Val::ZERO],
        public: [Val::ZERO; PUBLICS],
        summary,
    }
}

#[test]
fn source_geometry_rejects_incomplete_or_changed_reconstruction_without_planning() {
    let mut relation = tiny_relation(8);
    assert_eq!(source_shape(&relation).unwrap().height, 8);
    relation.summary.deferred_crypto_obligations = 1;
    assert_eq!(source_shape(&relation), Err(Error::Geometry));
    relation.summary.deferred_crypto_obligations = 0;
    relation.summary.padded_rows = 16;
    assert_eq!(source_shape(&relation), Err(Error::Geometry));
    relation.summary.padded_rows = 8;
    relation.witness.clear();
    assert_eq!(source_shape(&relation), Err(Error::Geometry));
    assert_eq!(
        source_shape(&tiny_relation(MAX_ROWS * 2)),
        Err(Error::Geometry)
    );
}

// Metadata-only fixture: it cannot construct a trusted cap, verified child or
// expected source. The checked conversion is independent of planner allocation.
fn core_conversion_fixture() -> VerifierCoreBound {
    VerifierCoreBound {
        operations: OperationCounts {
            scalar: usize::MAX,
            cubic: usize::MAX - 1,
            poseidon: usize::MAX - 2,
        },
        wire_upper_bound: MAX_WIRES,
        input_values_upper_bound: MAX_INPUTS,
        selection_hint_words_upper_bound: usize::MAX,
        active_rows_upper_bound: MAX_ROWS - 1,
        padded_rows_upper_bound: MAX_ROWS,
        planner_requested_program_bytes_peak: usize::MAX,
        storage: PlanningStorage {
            symbolic_workspace_bytes: 1,
            symbolic_retained_bytes: 2,
            template_retained_bytes: 3,
            template_construction_bytes: 4,
            input_backing_bytes: 5,
            returned_wire_bytes: 6,
            helper_bytes: 7,
            auxiliary_peak_bytes: 8,
            total_requested_bytes: 9,
        },
    }
}

#[test]
fn retained_core_preserves_full_width_conformance_geometry() {
    let core = core_conversion_fixture();
    let retained = RetainedCoreBound::checked(&core, &core.storage).unwrap();
    assert_eq!(retained.operations, core.operations);
    assert_eq!(retained.wire_upper_bound, core.wire_upper_bound);
    assert_eq!(
        retained.input_values_upper_bound,
        core.input_values_upper_bound
    );
    assert_eq!(
        retained.active_rows_upper_bound,
        core.active_rows_upper_bound
    );
    assert_eq!(
        retained.padded_rows_upper_bound,
        core.padded_rows_upper_bound
    );
    assert_eq!(size_of::<RetainedCoreBound>(), 7 * size_of::<usize>());
    assert!(size_of::<RetainedCoreBound>() < size_of::<VerifierCoreBound>());
}

#[test]
fn retained_core_rejects_storage_identity_and_each_existing_ceiling() {
    let core = core_conversion_fixture();
    for field in 0..9 {
        let mut mismatched = core.storage;
        let value = match field {
            0 => &mut mismatched.symbolic_workspace_bytes,
            1 => &mut mismatched.symbolic_retained_bytes,
            2 => &mut mismatched.template_retained_bytes,
            3 => &mut mismatched.template_construction_bytes,
            4 => &mut mismatched.input_backing_bytes,
            5 => &mut mismatched.returned_wire_bytes,
            6 => &mut mismatched.helper_bytes,
            7 => &mut mismatched.auxiliary_peak_bytes,
            8 => &mut mismatched.total_requested_bytes,
            _ => unreachable!(),
        };
        *value += 1;
        assert!(matches!(
            RetainedCoreBound::checked(&core, &mismatched),
            Err(Error::ResourceLimit)
        ));
    }
    for field in 0..3 {
        let mut exceeded = core;
        match field {
            0 => exceeded.padded_rows_upper_bound += 1,
            1 => exceeded.wire_upper_bound += 1,
            2 => exceeded.input_values_upper_bound += 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            RetainedCoreBound::checked(&exceeded, &core.storage),
            Err(Error::ResourceLimit)
        ));
    }
}

#[test]
fn source_overlap_and_later_child_retention_share_the_original_worker_limit() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let shape = source_shape(&tiny_relation(8)).unwrap();
    let storage = PlanningStorage::for_children(PUBLICS, &[shape], construction()).unwrap();
    let base = memory_bounds(0, 0, storage).unwrap();
    assert_eq!(
        base.recursive_compilation_bytes,
        storage.total_requested_bytes + MAX_RETAINED_PROOF_BYTES + REGISTERED_GPU_CALLER_HOST_BYTES,
    );
    let remaining = HOST_BYTES - base.source_planning_bytes;
    assert_eq!(
        memory_bounds(remaining, 0, storage)
            .unwrap()
            .source_planning_bytes,
        HOST_BYTES
    );
    assert!(matches!(
        memory_bounds(remaining, 1, storage),
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        memory_bounds(usize::MAX, 1, storage),
        Err(Error::ResourceLimit)
    ));
    assert!(
        base.recursive_evaluation_bytes
            >= PROGRAM_BYTES
                + fields(MAX_WIRES).unwrap()
                + MAX_RETAINED_PROOF_BYTES
                + REGISTERED_GPU_CALLER_HOST_BYTES
    );
    assert!(base.recursive_evaluation_bytes <= HOST_BYTES);
}

#[test]
#[ignore = "fresh complete direct-ring proof plus independent verifier GPU setup and bounded recursive constraints; coordinator guard only"]
fn genuine_direct_ring_child_closes_recursive_constraints_and_rejects_public_mutations() {
    assert!(cfg!(all(
        not(debug_assertions),
        target_arch = "x86_64",
        target_os = "linux"
    )));
    assert_eq!(
        std::env::var("LATTICA_DIRECT_RING_RECURSIVE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    let context = Context([0x73; 32]);
    let (statement, witness) = ring::fixture(context).unwrap();
    let relation = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        CAPACITY,
        REPRESENTATION,
        HOST_BYTES - REGISTERED_GPU_CALLER_HOST_BYTES,
    )
    .unwrap();
    drop(witness);
    let generated = FreshGpuProofInput::new(statement, context, relation)
        .unwrap()
        .prove()
        .unwrap();
    let (statement, descriptor, proof, proving_report) = generated.into_parts();
    eprint!("direct_ring_recursive_child_proving_report ");
    serde_json::to_writer(std::io::stderr().lock(), &proving_report).unwrap();
    eprintln!();
    drop(proving_report);
    let artifact = Artifact::from_proof(
        &statement,
        context,
        REPRESENTATION,
        descriptor,
        proof,
        HOST_BYTES - REGISTERED_GPU_CALLER_HOST_BYTES,
    )
    .unwrap();
    let result = qualify_single_child(artifact, &statement, context, CAPACITY, REPRESENTATION);
    match result {
        Ok(report) => {
            assert!(report.child_verification.verified);
            assert!(report.child_verification.terminal.context_closed);
            assert!(report.child_verification.terminal.queue_drained);
            assert!(report.all_recursive_constraints_satisfied);
            assert_eq!(report.public_binding_mutation_rejections, 4);
            assert_eq!(report.recursive_proofs_generated, 0);
            assert!(!report.complete_transaction_aggregate);
            assert!(!report.final_aggregate);
            eprint!("direct_ring_recursive_constraint_report ");
            serde_json::to_writer(std::io::stderr().lock(), &report).unwrap();
            eprintln!();
        }
        Err(failure) => {
            eprint!("direct_ring_recursive_constraint_failure ");
            serde_json::to_writer(std::io::stderr().lock(), &failure).unwrap();
            eprintln!();
            panic!("direct-ring recursive constraint qualification failed: {failure}");
        }
    }
}
