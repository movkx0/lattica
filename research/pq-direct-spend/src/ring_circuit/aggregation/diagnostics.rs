//! Bounded admission evidence from the actual compiled program. These observed
//! counts describe this program only; they grant no source bound or admission.
use super::*;

const ERROR_BYTES: usize = 2048;

/// Fixed inline storage keeps backend errors inside the caller/Failure census.
/// Every ordinary planner error is retained verbatim. An oversized error is
/// explicitly marked incomplete rather than silently presented as exact.
pub struct CoreError {
    bytes: [u8; ERROR_BYTES],
    len: usize,
}
impl CoreError {
    fn capture(error: &str) -> Self {
        let mut len = error.len().min(ERROR_BYTES);
        while !error.is_char_boundary(len) { len -= 1; }
        let mut bytes = [0; ERROR_BYTES];
        bytes[..len].copy_from_slice(&error.as_bytes()[..len]);
        Self { bytes, len }
    }
    fn as_str(&self) -> &str {
        // capture copies only a complete UTF-8 prefix.
        std::str::from_utf8(&self.bytes[..self.len]).expect("captured UTF-8 planner error")
    }
}
impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.as_str()) }
}
impl std::fmt::Debug for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.as_str(), f)
    }
}
impl Serialize for CoreError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Serialize)]
pub struct AdmissionFailure {
    /// The zero registered_program_id means this is an unregistered descriptor.
    pub actual_program: artifact::ProofDescriptor,
    pub scalar_operations: usize,
    pub cubic_operations: usize,
    pub poseidon_operations: usize,
    pub core_error: CoreError,
    pub original_error_bytes: usize,
    pub original_error_complete: bool,
}

pub(super) fn failure(compiled: &Compiled, phase: &'static str, reason: &'static str,
    error: String) -> Failure {
    let counts = OperationCounts::from_program(&compiled.program);
    let core_error = CoreError::capture(&error);
    let original_error_complete = core_error.len == error.len();
    Failure { admission: Some(AdmissionFailure {
        actual_program: compiler::descriptor(&compiled.program, compiled.manifest, [0; 4]),
        scalar_operations: counts.scalar, cubic_operations: counts.cubic,
        poseidon_operations: counts.poseidon, core_error,
        original_error_bytes: error.len(), original_error_complete,
    }), ..Failure::new(phase, reason) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct PlanCase<'a> {
        schema: &'static str,
        program_kind: &'static str,
        actual_program: artifact::ProofDescriptor,
        source_upper_bound_claimed: bool,
        admitted: bool,
        footprint: Option<&'a RegisteredGpuFootprint>,
        error: Option<&'a AdmissionFailure>,
    }
    #[derive(Serialize)]
    struct PlanTerminal {
        schema: &'static str,
        cases: usize,
        admitted: usize,
        refused: usize,
        engine_report_absent_before: bool,
        engine_report_absent_after: bool,
        public_hash_absent_before: bool,
        public_hash_absent_after: bool,
        session_creation_attempts: usize,
        cryptographic_proof_started: bool,
    }
    fn emit(prefix: &str, value: &impl Serialize) {
        use std::io::Write;
        let mut output = std::io::stderr().lock();
        write!(output, "{prefix} ").unwrap();
        serde_json::to_writer(&mut output, value).unwrap();
        output.write_all(b"\n").unwrap();
    }

    #[test]
    fn core_error_preserves_the_exact_message_with_bounded_utf8_storage() {
        let message = "registered GPU complete phase bound unavailable; diagnostic floors cannot admit execution";
        assert_eq!(CoreError::capture(message).as_str(), message);
        let oversized = "\u{00e9}".repeat(ERROR_BYTES);
        let captured = CoreError::capture(&oversized);
        assert_eq!(captured.len, ERROR_BYTES);
        assert_eq!(captured.as_str(), &oversized[..ERROR_BYTES]);
    }

    /// No fixture, verifier compilation, registration, Session or proof. A
    /// padded shell uses the same qualified wide AIR dimensions. Success here
    /// establishes only that shell's admission, never admission of N3/N4.
    #[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "coordinator-only source geometry reproduction; captured qualified execution selection required"]
    fn flat_n4_padding_boundary_original_memory_plan_without_dispatch() {
        use lattica_prover_p3::block_v2::gpu_hash;
        let engine_report_absent_before = gpu_hash::report("direct ring source plan before").is_none();
        let public_hash_absent_before = gpu_hash::public_hash_execution().unwrap().is_none();
        assert!(engine_report_absent_before && public_hash_absent_before);
        runtime::request().unwrap();
        bounds::caller_census().unwrap();
        let limits = RegisteredGpuLimits::new(HOST_BYTES as u64, DEVICE_BYTES, CONTEXT_BYTES, MAX_ROWS).unwrap();
        for height in [1 << 19, 1 << 20] {
            let builder = ProgramBuilder::new_with_construction_limits(PUBLICS, ConstructionLimits {
                max_requested_program_bytes: 1 << 20, max_wires: 16, max_input_values: 0,
            }).unwrap();
            let program = Arc::new(builder.finish(Some(height)).unwrap());
            let compiled = Compiled { program, inputs: SecretInputs(Vec::new()),
                public: [Val::ZERO; PUBLICS], manifest: [0; 32] };
            let result = runtime::preflight_plan(&compiled, limits);
            match (&result, height) {
                (Ok(footprint), 524288) => {
                    assert_eq!(footprint.main_columns, 94);
                    assert_eq!(footprint.preprocessing_columns, 200);
                    emit("direct_ring_source_plan_case", &PlanCase {
                        schema: "direct-ring-source-plan-case-v1",
                        program_kind: "four_public_empty_padded_shell",
                        actual_program: compiler::descriptor(&compiled.program, compiled.manifest, [0; 4]),
                        source_upper_bound_claimed: false, admitted: true,
                        footprint: Some(footprint), error: None,
                    });
                }
                (Err(failure), 1048576) => {
                    let evidence = failure.admission.as_ref().expect("actual plan error retained");
                    assert_eq!(evidence.actual_program.padded_rows, height as u64);
                    assert!(evidence.original_error_complete);
                    emit("direct_ring_source_plan_case", &PlanCase {
                        schema: "direct-ring-source-plan-case-v1",
                        program_kind: "four_public_empty_padded_shell",
                        actual_program: evidence.actual_program,
                        source_upper_bound_claimed: false, admitted: false,
                        footprint: None, error: Some(evidence),
                    });
                }
                _ => panic!("unexpected source-only boundary result at {height}: {result:?}"),
            }
        }
        let engine_report_absent_after = gpu_hash::report("direct ring source plan after").is_none();
        let public_hash_absent_after = gpu_hash::public_hash_execution().unwrap().is_none();
        assert!(engine_report_absent_after && public_hash_absent_after);
        emit("direct_ring_source_plan_terminal", &PlanTerminal {
            schema: "direct-ring-source-plan-terminal-v1", cases: 2, admitted: 1, refused: 1,
            engine_report_absent_before, engine_report_absent_after,
            public_hash_absent_before, public_hash_absent_after,
            // This test's fixed call graph contains no Session creation or
            // proving call. The two observed engine reports independently
            // establish pristine engine state at the entry/exit boundaries.
            session_creation_attempts: 0, cryptographic_proof_started: false,
        });
    }
}
