use super::*;
use crate::ring;
use crate::ring_circuit::{
    compile_with_representation_diagnostics, proving::FreshGpuProofInput, CompilerMemoryProfile,
    CompilerWireProfile,
};
use std::{cell::RefCell, rc::Rc};

struct DropProbe(Rc<Cell<usize>>);
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn outer_refusal_footprint_slot_drops_only_initialized_values_once() {
    let uninitialized = FootprintAllocation {
        forced_null_attempts: None,
    }
    .slot::<DropProbe>()
    .unwrap();
    drop(uninitialized);
    let drops = Rc::new(Cell::new(0));
    let slot = FootprintAllocation {
        forced_null_attempts: None,
    }
    .slot::<DropProbe>()
    .unwrap();
    let initialized = initialize_footprint_slot(slot, DropProbe(drops.clone()));
    assert_eq!(drops.get(), 0);
    drop(initialized);
    assert_eq!(drops.get(), 1);
}

#[test]
fn outer_refusal_footprint_allocation_failure_is_terminal_before_dispatch() {
    let attempts = Cell::new(0);
    let result = footprint_slot(FootprintAllocation {
        forced_null_attempts: Some(&attempts),
    });
    let failure = match result {
        Ok(_) => panic!("forced null footprint allocation succeeded"),
        Err(failure) => failure,
    };
    assert_eq!(attempts.get(), 1);
    assert_eq!(failure.phase, "preflight");
    assert_eq!(failure.reason, "refusal footprint storage");
    assert!(!failure.outer_proof_started);
    assert!(failure.refusal_footprint.is_none());
    assert!(failure.outer_proving_terminal.is_none());
    assert!(failure.outer_verification_terminal.is_none());
}

#[test]
fn outer_fixed_type_census_diagnostic_grants_no_admission() {
    use lattica_prover_p3::proving::{ComponentObservation, Observation};
    let components = [
        ("footprint_storage", footprint_storage_bytes().unwrap()),
        ("typed_mutation", mutation::caller_bytes()),
        (
            "artifact_transport_report_4",
            4 * size_of::<ArtifactRoundtripReport>(),
        ),
        (
            "artifact_source_reference_4",
            4 * size_of::<&ExpectedRecursiveSource>(),
        ),
        (
            "artifact_unit_error_result_4",
            4 * size_of::<Result<(), Error>>(),
        ),
        ("outer_input_4", 4 * size_of::<OuterInput>()),
        ("expected_program_4", 4 * size_of::<ExpectedProgram>()),
        ("generated_4", 4 * size_of::<Generated>()),
        ("setup_4", 4 * size_of::<Setup>()),
        ("preflight_4", 4 * size_of::<Preflight>()),
        ("report_4", 4 * size_of::<Report>()),
        ("report_result_4", 4 * size_of::<Result<Report, Failure>>()),
        (
            "generated_result_4",
            4 * size_of::<Result<Generated, Failure>>(),
        ),
        ("setup_result_4", 4 * size_of::<Result<Setup, Failure>>()),
        (
            "program_result_4",
            4 * size_of::<Result<ExpectedProgram, Failure>>(),
        ),
        (
            "generated_catch_4",
            4 * size_of::<std::thread::Result<Result<Generated, Failure>>>(),
        ),
        (
            "setup_catch_4",
            4 * size_of::<std::thread::Result<Result<Setup, Failure>>>(),
        ),
        (
            "program_catch_4",
            4 * size_of::<std::thread::Result<Result<ExpectedProgram, Failure>>>(),
        ),
        ("proving_attempt_4", 4 * size_of::<ProvingAttempt>()),
        (
            "proving_result_4",
            4 * size_of::<Result<ProvingAttempt, Failure>>(),
        ),
        (
            "proving_catch_4",
            4 * size_of::<std::thread::Result<Result<ProvingAttempt, Failure>>>(),
        ),
        (
            "proving_finish_4",
            4 * size_of::<Result<(ProvingAttempt, TerminalReceipt), Failure>>(),
        ),
        (
            "setup_finish_4",
            4 * size_of::<Result<(Setup, TerminalReceipt), Failure>>(),
        ),
        ("failure_4", 4 * size_of::<Failure>()),
        (
            "gpu_plan_4",
            4 * size_of::<RegisteredGpuMemoryPlan<'static>>(),
        ),
        (
            "gpu_admission_4",
            4 * size_of::<RegisteredGpuAdmission<'static>>(),
        ),
        ("registered_verifier_4", 4 * size_of::<RegisteredVerifier>()),
        ("registered_program_4", 4 * size_of::<RegisteredProgram>()),
        ("gpu_limits_4", 4 * size_of::<RegisteredGpuLimits>()),
        ("storage_report_4", 4 * size_of::<StorageReport>()),
        ("native_report_4", 4 * size_of::<NativeReport>()),
        ("program_4", 4 * size_of::<Program>()),
        ("proof_inputs_4", 4 * size_of::<ProofInputs>()),
        ("builder_4", 4 * size_of::<ProgramBuilder>()),
        ("public_4", 4 * size_of::<[Val; PUBLICS]>()),
        (
            "report_backing",
            4 * (128 * size_of::<Observation>() + 16 * size_of::<ComponentObservation>()),
        ),
        ("other_frames", 8 << 10),
    ];
    let mut total = 0usize;
    for (component, bytes) in components {
        eprintln!("direct_ring_outer_fixed_component name={component} bytes={bytes}");
        total = total.checked_add(bytes).unwrap();
    }
    assert_eq!(total, inline_bytes().unwrap());
    eprintln!("direct_ring_outer_fixed_total bytes={total} admission=false");
}

#[test]
fn outer_source_retention_and_cpu_reservations_remain_inside_original_worker() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let child = RegisteredChildShape {
        public_values: 4,
        height: 8,
        preprocessing_cap_roots: CAP_ROOTS,
    };
    let storage = storage_for_shape(child, 8).unwrap();
    assert_eq!(
        storage.independent_registration_host_partition_bytes as usize
            + storage.retained_outer_proof_allowance_bytes,
        HOST_BYTES
    );
    assert!(
        storage.source_comparison_peak_bytes > storage.source_construction_bytes + PROGRAM_BYTES
    );
    assert!(
        storage.reconstruction_with_retained_outer_peak_bytes
            >= storage.source_construction_bytes
                + MAX_RETAINED_PROOF_BYTES
                + REGISTERED_GPU_CALLER_HOST_BYTES
    );
    assert!(storage.cpu_verifier_with_proof_reserved_bytes >= MAX_RETAINED_PROOF_BYTES);
    assert!(storage.cpu_phase_peak_bytes <= HOST_BYTES);
    assert_eq!(
        storage.artifact_roundtrip_peak_bytes,
        artifact_transport::required_host_bytes().unwrap() + REGISTERED_GPU_CALLER_HOST_BYTES
    );
    assert!(storage.artifact_roundtrip_peak_bytes <= HOST_BYTES);
    for height in [0, 7, 9, MAX_ROWS + 1, usize::MAX] {
        assert!(storage_for_shape(child, height).is_err());
    }
}

struct FakeSession {
    events: Rc<RefCell<Vec<&'static str>>>,
    fail: bool,
}
fn terminal() -> serde_json::Value {
    serde_json::json!({
        "host_allowance_bytes": HOST_BYTES, "device_allowance_bytes": DEVICE_BYTES,
        "gpu_context_allowance_bytes": CONTEXT_BYTES, "max_rows": MAX_ROWS,
        "commits": 1, "allocations": 1, "managed_peak_bytes": 1,
        "uploaded_bytes": 1, "downloaded_bytes": 1, "context_closed": true,
        "queue_drained": true, "completion_claimed": false, "stark_completion_claimed": false,
    })
}
impl RetiringSession for FakeSession {
    fn finish(self) -> Result<serde_json::Value, String> {
        self.events.borrow_mut().push("finish");
        if self.fail {
            Err("retirement failed".into())
        } else {
            Ok(terminal())
        }
    }
    fn close(self) -> Result<serde_json::Value, String> {
        self.events.borrow_mut().push("close");
        if self.fail {
            Err("retirement failed".into())
        } else {
            Ok(terminal())
        }
    }
}
struct Payload(Rc<RefCell<Vec<&'static str>>>);
impl Drop for Payload {
    fn drop(&mut self) {
        self.0.borrow_mut().push("payload dropped");
    }
}

#[test]
fn outer_panics_drop_payload_before_retirement_and_preserve_failure_receipt() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let attempted: Result<(), Failure> = attempt("outer_proving", || {
        let _payload = Payload(events.clone());
        panic!("private panic payload must never be reported");
    });
    let failure = finish(
        FakeSession {
            events: events.clone(),
            fail: false,
        },
        attempted,
        true,
    )
    .unwrap_err();
    assert_eq!(&*events.borrow(), &["payload dropped", "close"]);
    assert_eq!(failure.reason, "backend panicked");
    let receipt = failure.outer_proving_terminal.unwrap();
    assert!(receipt.context_closed && receipt.queue_drained && !receipt.completion_claimed);
    assert!(!failure.cleanup_failed);
}

#[test]
fn cleanup_failure_withholds_outer_success_and_keeps_original_failure() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let failure = finish(
        FakeSession {
            events: events.clone(),
            fail: true,
        },
        Ok(7),
        true,
    )
    .unwrap_err();
    assert!(failure.cleanup_failed);
    assert!(failure.outer_proving_terminal.is_none());
    assert_eq!(&*events.borrow(), &["finish"]);
    let failure = finish(
        FakeSession { events, fail: true },
        Err::<(), _>(Failure::new("source", "original refusal")),
        false,
    )
    .unwrap_err();
    assert_eq!(failure.reason, "original refusal");
    assert!(failure.cleanup_failed);
}

#[test]
#[ignore = "genuine direct-ring child and one fresh outer proof with independent source reconstruction/CPU verification; coordinator guard only"]
fn genuine_direct_ring_child_has_fresh_outer_proof_and_independent_cpu_verification() {
    assert!(cfg!(all(
        not(debug_assertions),
        target_arch = "x86_64",
        target_os = "linux"
    )));
    assert_eq!(
        std::env::var("LATTICA_DIRECT_RING_OUTER_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    let context = Context([0x74; 32]);
    let capacity = CompilerCapacityProfile::new(
        CompilerMemoryProfile::Program2GiB,
        CompilerWireProfile::Research16M,
    );
    let representation = CompilerRepresentation::FusedTernaryRangesV1;
    // Check all surviving driver state plus the new timing/output frames
    // before either the timer or the first fixture allocation is constructed.
    qualification_timing::caller_bytes().unwrap();
    let component_started = Instant::now();
    let (statement, witness) = ring::fixture(context).unwrap();
    let relation = compile_with_representation_diagnostics(
        &statement,
        &witness,
        context,
        capacity,
        representation,
        HOST_BYTES - REGISTERED_GPU_CALLER_HOST_BYTES,
    )
    .unwrap();
    drop(witness);
    let generated = FreshGpuProofInput::new(statement, context, relation)
        .unwrap()
        .prove()
        .unwrap();
    let (statement, descriptor, proof, child_proving) = generated.into_parts();
    eprint!("direct_ring_recursive_outer_child_proving_report ");
    serde_json::to_writer(std::io::stderr().lock(), &child_proving).unwrap();
    eprintln!();
    drop(child_proving);
    let artifact = Artifact::from_proof(
        &statement,
        context,
        representation,
        descriptor,
        proof,
        HOST_BYTES - REGISTERED_GPU_CALLER_HOST_BYTES,
    )
    .unwrap();
    match qualify_single_child_outer(artifact, &statement, context, capacity, representation) {
        Ok(report) => {
            assert_eq!(report.outer_recursive_proofs_generated, 1);
            assert_eq!(report.independently_verified_outer_proofs, 1);
            assert!(report.independent_verification.cpu_verified);
            assert!(report.independent_verification.source_manifest_matches);
            assert!(!report.independent_verification.synthetic_hints_evaluated);
            assert_eq!(
                report.independent_verification.public_mutation_rejections,
                4
            );
            assert_eq!(
                report.independent_verification.opening_mutation_rejections,
                1
            );
            assert!(
                report.proving.terminal.context_closed && report.proving.terminal.queue_drained
            );
            assert!(
                report.independent_verification.terminal.context_closed
                    && report.independent_verification.terminal.queue_drained
            );
            assert!(
                !report.complete_transaction_aggregate
                    && !report.final_aggregate
                    && report.artifact_roundtrip
            );
            assert!(
                report.artifact_transport.encoded_bytes
                    > crate::ring_circuit::artifact::HEADER_BYTES
            );
            assert!(
                report.artifact_transport.encoded_bytes
                    <= crate::ring_circuit::artifact::MAX_ENCODED_BYTES
            );
            assert!(
                report.artifact_transport.decoded_proof_retained_bytes <= MAX_RETAINED_PROOF_BYTES
            );
            assert!(report.artifact_transport.total_ns > 0);
            assert!(report.proving.total_ns >= report.artifact_transport.total_ns);
            eprint!("direct_ring_recursive_outer_report ");
            serde_json::to_writer(std::io::stderr().lock(), &report).unwrap();
            eprintln!();
        }
        Err(failure) => {
            eprint!("direct_ring_recursive_outer_failure ");
            serde_json::to_writer(std::io::stderr().lock(), &failure).unwrap();
            eprintln!();
            panic!("single-child recursive outer qualification failed: {failure}");
        }
    }
    // The successful match arm has destroyed the outer report. The child
    // report and all proof/program/source/session owners have already died.
    // Include the final expected statement destruction in this enclosing time.
    drop(statement);
    qualification_timing::emit(component_started.elapsed().as_nanos());
}
