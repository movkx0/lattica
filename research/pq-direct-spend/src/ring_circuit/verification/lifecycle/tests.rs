use super::*;
use std::{cell::RefCell, rc::Rc};

struct FakeSession {
    events: Rc<RefCell<Vec<&'static str>>>,
    fail: bool,
    commits: u64,
}
impl TerminalSession for FakeSession {
    fn close(self) -> Result<serde_json::Value, String> {
        self.events.borrow_mut().push("session_close");
        if self.fail {
            return Err("shutdown failed".into());
        }
        Ok(serde_json::json!({
            "host_allowance_bytes": HOST_BYTES,
            "device_allowance_bytes": DEVICE_BYTES,
            "gpu_context_allowance_bytes": CONTEXT_BYTES,
            "max_rows": MAX_ROWS,
            "commits": self.commits,
            "allocations": 1,
            "managed_peak_bytes": 1,
            "uploaded_bytes": 1,
            "downloaded_bytes": 1,
            "context_closed": true,
            "queue_drained": true,
            "completion_claimed": false,
            "stark_completion_claimed": false,
        }))
    }
}
struct Registration(Rc<RefCell<Vec<&'static str>>>);
impl Drop for Registration {
    fn drop(&mut self) {
        self.0.borrow_mut().push("registration_dropped");
    }
}

#[test]
fn verifier_unwinding_drops_registration_before_session_cleanup() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let attempted: Result<(), _> =
        attempt(&Cell::new("registration"), &Cell::new(true), false, || {
            let _owner = Registration(events.clone());
            panic!("private backend panic payload");
        });
    let failure = finish(
        FakeSession {
            events: events.clone(),
            fail: false,
            commits: 0,
        },
        attempted,
    )
    .unwrap_err();
    assert_eq!(
        &*events.borrow(),
        &["registration_dropped", "session_close"]
    );
    assert_eq!(failure.phase, "registration");
    assert!(failure.gpu_registration_started);
    assert!(!failure.cpu_verification_started);
    assert!(!failure.error.contains("private backend panic payload"));
    let terminal = failure.terminal.unwrap();
    assert!(terminal.context_closed);
    assert!(!terminal.completion_claimed);
}

#[test]
fn verification_preserves_failure_and_withholds_success_on_teardown_error() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let attempted: Result<(), _> = Err(VerificationFailure::new(
        "registration",
        true,
        false,
        &"setup failed",
    ));
    let failure = finish(
        FakeSession {
            events: events.clone(),
            fail: true,
            commits: 1,
        },
        attempted,
    )
    .unwrap_err();
    assert!(failure.error.contains("setup failed"));
    assert!(failure.cleanup_error.unwrap().contains("shutdown failed"));
    assert!(failure.terminal.is_none());
    let failure = finish(
        FakeSession {
            events: events.clone(),
            fail: true,
            commits: 1,
        },
        Ok(()),
    )
    .unwrap_err();
    assert_eq!(failure.phase, "session_close");
    let failure = finish(
        FakeSession {
            events,
            fail: false,
            commits: 0,
        },
        Ok(()),
    )
    .unwrap_err();
    assert_eq!(failure.phase, "preprocessing_terminal_receipt");
    assert!(failure.terminal.is_some());
}

fn shape_artifact() -> Artifact {
    use lattica_prover_p3::block_v2::machine::{programs, verifier::template};
    let statement = crate::ring::fixture(Context([37; 32])).unwrap().0;
    Artifact::from_proof(
        &statement,
        statement.context,
        CompilerRepresentation::FusedTernaryRangesV1,
        ProofDescriptor {
            active_rows: 1,
            padded_rows: 64,
            wires: 16,
            witness_values: 1,
            canonical_manifest_digest: [0; 32],
            registered_program_id: [0; 4],
        },
        template::batch(&programs::shape(64).unwrap()).unwrap(),
        HOST_BYTES as usize,
    )
    .unwrap()
}

#[test]
fn opening_probe_restores_proof_after_error_and_unwinding() {
    // Shape-only transport object: this test checks restoration and never
    // treats it as a valid cryptographic proof.
    let mut artifact = shape_artifact();
    let before = artifact.encode(HOST_BYTES as usize).unwrap();
    for panic in [false, true] {
        let result: Result<(), _> = restored_opening_probe(&mut artifact, |mutated| {
            assert_ne!(mutated.encode(HOST_BYTES as usize).unwrap(), before);
            if panic {
                panic!("private mutation payload");
            }
            Err(VerificationFailure::new(
                "injected",
                true,
                true,
                &"injected failure",
            ))
        });
        let error = result.unwrap_err();
        assert!(error.cpu_verification_started);
        assert!(!error.error.contains("private mutation payload"));
        assert_eq!(artifact.encode(HOST_BYTES as usize).unwrap(), before);
    }
}

#[test]
fn verifier_errors_have_bounded_utf8_capacity() {
    let error = bounded(&"π".repeat(2048));
    assert!(error.len() <= ERROR_BYTES);
    assert!(error.capacity() <= ERROR_BYTES);
    assert!(error.is_char_boundary(error.len()));
}

#[test]
fn typed_probe_infrastructure_failure_restores_opening_and_withholds_credit() {
    use lattica_prover_p3::block_v2::machine::backend::RegisteredVerificationFailure as Failure;
    let mut artifact = shape_artifact();
    let before = artifact.encode(HOST_BYTES as usize).unwrap();
    let mut mutation_credit = 0;
    for failure in [
        Failure::Admission("proof rejected".into()),
        Failure::Configuration("proof rejected".into()),
        Failure::Allocation("proof rejected".into()),
    ] {
        let result = restored_opening_probe(&mut artifact, |mutated| {
            assert_ne!(mutated.encode(HOST_BYTES as usize).unwrap(), before);
            mutation::require_rejection(Err(failure))
                .map_err(|reason| VerificationFailure::new("opening_probe", true, true, &reason))
        });
        if result.is_ok() {
            mutation_credit += 1;
        }
        let error = result.unwrap_err();
        assert_eq!(error.phase, "opening_probe");
        assert!(error.cpu_verification_started);
        assert_eq!(artifact.encode(HOST_BYTES as usize).unwrap(), before);
    }
    assert_eq!(mutation_credit, 0);
}
