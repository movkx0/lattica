//! Separately selected one-child recursive proof qualification. The only child
//! key source is the private expected-public reconstruction retained from the
//! independent verifier. No supplied cap, raw program, report or proof header
//! can enter the outer producer. This does not aggregate transactions.
use super::super::artifact::outer as artifact_transport;
pub use super::super::artifact::outer::Report as ArtifactRoundtripReport;
use super::super::verification::mutation;
use super::super::{artifact::ProofDescriptor, proving, verification::ExpectedRecursiveSource};
use super::*;
use lattica_pq_ringct_research::opencl::{Limits, Session};
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::{public_hash_execution, PublicHashExecution},
        machine::{
            backend::{retained_proof_capacity_bytes, RegisteredProgram, RegisteredVerifier},
            verifier::batch::source_program,
            RegisteredGpuAdmission, RegisteredGpuFootprint, RegisteredGpuLimits,
            RegisteredGpuMemoryPlan,
        },
    },
    proving::{Policy, Report as NativeReport, Request},
};
use p3_batch_stark::BatchProof;
use std::{cell::Cell, mem::MaybeUninit, sync::Arc};

const DEVICE_BYTES: u64 = 8 << 30;
const CONTEXT_BYTES: u64 = 4 << 30;

#[derive(Debug, Serialize)]
pub struct Failure {
    pub schema: &'static str,
    pub phase: &'static str,
    pub reason: &'static str,
    pub outer_proof_started: bool,
    pub child_failure: Option<VerificationFailure>,
    pub child_terminal: Option<TerminalReceipt>,
    pub outer_proving_terminal: Option<TerminalReceipt>,
    pub outer_verification_terminal: Option<TerminalReceipt>,
    pub cleanup_failed: bool,
    pub refusal_footprint: Option<Box<RegisteredGpuFootprint>>,
}
impl Failure {
    fn new(phase: &'static str, reason: &'static str) -> Self {
        Self {
            schema: "lattica-research-direct-ring-recursive-outer-failure-v1",
            phase,
            reason,
            outer_proof_started: false,
            child_failure: None,
            child_terminal: None,
            outer_proving_terminal: None,
            outer_verification_terminal: None,
            cleanup_failed: false,
            refusal_footprint: None,
        }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.phase, self.reason)
    }
}
impl std::error::Error for Failure {}

// Private, fallible allocation of diagnostic storage. A refusal remains a
// terminal refusal if its footprint cannot be stored; it never retries a plan.
struct FootprintAllocation<'a> {
    forced_null_attempts: Option<&'a Cell<usize>>,
}
impl FootprintAllocation<'_> {
    fn slot<T>(self) -> Result<Box<MaybeUninit<T>>, ()> {
        let layout = std::alloc::Layout::new::<MaybeUninit<T>>();
        // Only the exact footprint is used in production. Smaller private
        // probes test both initialized and uninitialized destruction paths.
        if layout.size() == 0
            || layout.size() > size_of::<RegisteredGpuFootprint>()
            || layout.align() > std::mem::align_of::<RegisteredGpuFootprint>()
        {
            return Err(());
        }
        let pointer = if let Some(attempts) = self.forced_null_attempts {
            attempts.set(attempts.get().saturating_add(1));
            std::ptr::null_mut()
        } else {
            // SAFETY: layout is the exact nonzero layout checked above.
            unsafe { std::alloc::alloc(layout) }.cast::<MaybeUninit<T>>()
        };
        if pointer.is_null() {
            return Err(());
        }
        // SAFETY: a unique aligned allocation of the exact layout backs this
        // slot. Uninitialized bytes are valid for MaybeUninit and are released
        // without invoking T's destructor if initialization never happens.
        Ok(unsafe { Box::from_raw(pointer) })
    }
}
fn initialize_footprint_slot<T>(mut slot: Box<MaybeUninit<T>>, value: T) -> Box<T> {
    slot.as_mut().write(value);
    // SAFETY: write just initialized all of T in its sole correctly typed slot.
    unsafe { slot.assume_init() }
}
fn footprint_slot(
    allocation: FootprintAllocation<'_>,
) -> Result<Box<MaybeUninit<RegisteredGpuFootprint>>, Failure> {
    allocation
        .slot::<RegisteredGpuFootprint>()
        .map_err(|()| Failure::new("preflight", "refusal footprint storage"))
}
fn phase_refusal(reason: &'static str, footprint: RegisteredGpuFootprint) -> Failure {
    // Only the already caller-admitted preflight constructs this diagnostic.
    // No GPU phase has started, and allocation failure remains terminal.
    let slot = match footprint_slot(FootprintAllocation {
        forced_null_attempts: None,
    }) {
        Ok(slot) => slot,
        Err(failure) => return failure,
    };
    let footprint = initialize_footprint_slot(slot, footprint);
    Failure {
        refusal_footprint: Some(footprint),
        ..Failure::new("preflight", reason)
    }
}

fn footprint_storage_bytes() -> Result<usize, Error> {
    sum(&[
        // At most one refusal is returned. Its sole backing and four explicit
        // by-value initialization/argument frames are additional to all old
        // plan, admission, failure and Result/catch/finish frame multiplicities.
        size_of::<RegisteredGpuFootprint>(),
        4 * size_of::<RegisteredGpuFootprint>(),
        8 * size_of::<Box<MaybeUninit<RegisteredGpuFootprint>>>(),
        8 * size_of::<Box<RegisteredGpuFootprint>>(),
        8 * size_of::<Result<Box<MaybeUninit<RegisteredGpuFootprint>>, Failure>>(),
        8 * size_of::<Result<Box<MaybeUninit<RegisteredGpuFootprint>>, ()>>(),
        8 * size_of::<std::alloc::Layout>(),
        8 * size_of::<*mut MaybeUninit<RegisteredGpuFootprint>>(),
        4 * size_of::<FootprintAllocation<'static>>(),
        4 * size_of::<Option<&Cell<usize>>>(),
        4 * size_of::<&Cell<usize>>(),
        4 * size_of::<Cell<usize>>(),
        8 * size_of::<usize>(),
    ])
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct StorageReport {
    pub caller_reserved_bytes: usize,
    pub source_construction_bytes: usize,
    pub source_comparison_peak_bytes: usize,
    pub reconstruction_with_retained_outer_peak_bytes: usize,
    pub retained_outer_proof_allowance_bytes: usize,
    pub cpu_verifier_with_proof_reserved_bytes: usize,
    pub cpu_phase_peak_bytes: usize,
    /// Full encoded owner, original-or-decoded proof, codec/transport scratch,
    /// and unchanged caller. Admitted before the first outer GPU dispatch.
    pub artifact_roundtrip_peak_bytes: usize,
    /// This smaller planner partition leaves the entire original outer proof
    /// inside the unchanged 32 GiB worker during independent registration.
    pub independent_registration_host_partition_bytes: u64,
}

#[derive(Serialize)]
pub struct ProvingReport {
    pub footprint: RegisteredGpuFootprint,
    pub registration: NativeReport,
    pub proving: NativeReport,
    pub public_hash: PublicHashExecution,
    pub terminal: TerminalReceipt,
    pub descriptor: ProofDescriptor,
    pub retained_proof_bytes: usize,
    pub setup_ns: u128,
    pub proving_ns: u128,
    pub teardown_ns: u128,
    pub total_ns: u128,
}

#[derive(Serialize)]
pub struct IndependentReport {
    pub footprint: RegisteredGpuFootprint,
    pub registration: NativeReport,
    pub public_hash: PublicHashExecution,
    pub terminal: TerminalReceipt,
    pub descriptor: ProofDescriptor,
    pub synthetic_hints_evaluated: bool,
    pub source_manifest_matches: bool,
    pub cpu_verified: bool,
    pub public_mutation_rejections: u32,
    pub opening_mutation_rejections: u32,
    pub reconstruction_ns: u128,
    pub setup_ns: u128,
    pub teardown_ns: u128,
    pub cpu_verification_ns: u128,
    pub mutation_checks_ns: u128,
    pub total_ns: u128,
}

#[derive(Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub scope: &'static str,
    pub proof_generation: &'static str,
    pub independently_verified_children: u32,
    pub outer_recursive_proofs_generated: u32,
    pub independently_verified_outer_proofs: u32,
    pub complete_transaction_aggregate: bool,
    pub final_aggregate: bool,
    pub artifact_roundtrip: bool,
    pub artifact_transport: ArtifactRoundtripReport,
    pub source_cap_provenance: &'static str,
    pub compiler: CompilerReport,
    pub storage: StorageReport,
    /// Also included in the independent child's verification lifecycle.
    pub source_preflight_ns: u128,
    pub recursive_compilation_ns: u128,
    pub recursive_constraint_evaluation_ns: u128,
    pub recursive_public_mutation_checks_ns: u128,
    pub source_comparison_ns: u128,
    pub total_qualification_ns: u128,
    pub child_verification: Box<VerificationReport>,
    pub proving: ProvingReport,
    pub independent_verification: IndependentReport,
}

struct OuterInput {
    program: Arc<Program>,
    inputs: SecretInputs,
    source: ExpectedRecursiveSource,
    child_report: Box<VerificationReport>,
    compiler: CompilerReport,
}
struct SecretInputs(Vec<Val>);
impl Drop for SecretInputs {
    fn drop(&mut self) {
        for value in &mut self.0 {
            // SAFETY: each initialized field is exclusively borrowed.
            unsafe { std::ptr::write_volatile(value, Val::ZERO) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
struct Generated {
    proof: BatchProof<profile::Config>,
    report: ProvingReport,
    artifact_transport: ArtifactRoundtripReport,
}
type ProvingAttempt = (
    BatchProof<profile::Config>,
    NativeReport,
    NativeReport,
    ProofDescriptor,
    PublicHashExecution,
    usize,
    u128,
    u128,
);
struct ExpectedProgram {
    program: Arc<Program>,
    // Domain-valid synthetic values for planner identity only. They are never
    // evaluated or sent to a proving method by this owner.
    synthetic: Vec<Val>,
    manifest: [u8; 32],
}
struct Preflight {
    source_manifest: [u8; 32],
    proof_limits: RegisteredGpuLimits,
    verification_limits: RegisteredGpuLimits,
    storage: StorageReport,
}
struct Setup {
    verifier: RegisteredVerifier,
    registration: NativeReport,
    descriptor: ProofDescriptor,
    public_hash: PublicHashExecution,
    setup_ns: u128,
}

/// Additive fixed frames and additional bounded native-report backing. The
/// existing recursive 192 KiB sub-ceiling and full 1 MiB caller census still
/// apply; refusal cannot be converted into a larger allowance.
pub(super) fn inline_bytes() -> Result<usize, Error> {
    use lattica_prover_p3::proving::{ComponentObservation, Observation};
    sum(&[
        footprint_storage_bytes()?,
        mutation::caller_bytes(),
        // Persistent transport observations and added source accessors. Codec
        // buffers, result/move/catch frames are separately phase-admitted.
        4 * size_of::<ArtifactRoundtripReport>(),
        4 * size_of::<&ExpectedRecursiveSource>(),
        4 * size_of::<Result<(), Error>>(),
        4 * size_of::<OuterInput>(),
        4 * size_of::<ExpectedProgram>(),
        4 * size_of::<Generated>(),
        4 * size_of::<Setup>(),
        4 * size_of::<Preflight>(),
        4 * size_of::<Report>(),
        4 * size_of::<Result<Report, Failure>>(),
        4 * size_of::<Result<Generated, Failure>>(),
        4 * size_of::<Result<Setup, Failure>>(),
        4 * size_of::<Result<ExpectedProgram, Failure>>(),
        4 * size_of::<std::thread::Result<Result<Generated, Failure>>>(),
        4 * size_of::<std::thread::Result<Result<Setup, Failure>>>(),
        4 * size_of::<std::thread::Result<Result<ExpectedProgram, Failure>>>(),
        4 * size_of::<ProvingAttempt>(),
        4 * size_of::<Result<ProvingAttempt, Failure>>(),
        4 * size_of::<std::thread::Result<Result<ProvingAttempt, Failure>>>(),
        4 * size_of::<Result<(ProvingAttempt, TerminalReceipt), Failure>>(),
        4 * size_of::<Result<(Setup, TerminalReceipt), Failure>>(),
        4 * size_of::<Failure>(),
        4 * size_of::<RegisteredGpuMemoryPlan<'static>>(),
        4 * size_of::<RegisteredGpuAdmission<'static>>(),
        4 * size_of::<RegisteredVerifier>(),
        4 * size_of::<RegisteredProgram>(),
        4 * size_of::<RegisteredGpuLimits>(),
        4 * size_of::<StorageReport>(),
        4 * size_of::<NativeReport>(),
        4 * size_of::<Program>(),
        4 * size_of::<ProofInputs>(),
        4 * size_of::<ProgramBuilder>(),
        4 * size_of::<[Val; PUBLICS]>(),
        // Four extra retained/transient reports beyond the original two-report
        // session allowance. Exact native entry validation caps their vectors.
        4 * (128 * size_of::<Observation>() + 16 * size_of::<ComponentObservation>()),
        // Arc allocation headers, scalar/iterator/catch/result/manifest frames.
        8 << 10,
    ])
}

fn attempt<T>(phase: &'static str, run: impl FnOnce() -> Result<T, Failure>) -> Result<T, Failure> {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(result) => result,
        Err(payload) => {
            drop(payload);
            Err(Failure::new(phase, "backend panicked"))
        }
    }
}
fn request() -> Result<Request, Failure> {
    if !cfg!(all(
        not(debug_assertions),
        target_arch = "x86_64",
        target_os = "linux"
    )) {
        return Err(Failure::new("environment", "unsupported profile"));
    }
    let request = Request::from_env().map_err(|_| Failure::new("environment", "request"))?;
    let context = match std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES") {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| Failure::new("environment", "context"))?,
        Err(std::env::VarError::NotPresent) => CONTEXT_BYTES,
        Err(_) => return Err(Failure::new("environment", "context")),
    };
    if request.policy != Policy::GpuRequired || !request.emit_report || context != CONTEXT_BYTES {
        return Err(Failure::new("environment", "strict GPU policy"));
    }
    Ok(request)
}
fn descriptor(program: &Program, manifest: [u8; 32], id: [u64; 4]) -> ProofDescriptor {
    ProofDescriptor {
        active_rows: program.active_rows() as u64,
        padded_rows: program.height() as u64,
        wires: program.wire_count() as u64,
        witness_values: program.witness_values() as u64,
        canonical_manifest_digest: manifest,
        registered_program_id: id,
    }
}
fn conform(program: &Program, source: &ExpectedRecursiveSource) -> Result<(), Failure> {
    let bound = &source.bound().core;
    let counts = OperationCounts::from_program(program);
    if program.public_values() != PUBLICS
        || program.height() > MAX_ROWS
        || program.witness_values() > MAX_INPUTS
        || program.wire_count() > MAX_WIRES
        || counts.scalar > bound.operations.scalar
        || counts.cubic > bound.operations.cubic
        || counts.poseidon > bound.operations.poseidon
        || program.wire_count() > bound.wire_upper_bound
        || program.witness_values() > bound.input_values_upper_bound
        || program.active_rows() > bound.active_rows_upper_bound
        || program.height() > bound.padded_rows_upper_bound
        || program
            .retained_host_bytes()
            .map_err(|_| Failure::new("source", "program storage"))?
            > PROGRAM_BYTES
    {
        return Err(Failure::new("source", "source conformance"));
    }
    Ok(())
}
fn source_storage(
    source: &ExpectedRecursiveSource,
    outer_height: usize,
) -> Result<StorageReport, Failure> {
    storage_for_shape(source.bound().child, outer_height)
}

fn storage_for_shape(
    child: RegisteredChildShape,
    outer_height: usize,
) -> Result<StorageReport, Failure> {
    if !(8..=MAX_ROWS).contains(&outer_height) || !outer_height.is_power_of_two() {
        return Err(Failure::new("source_admission", "outer height"));
    }
    let fail = |_| Failure::new("source_admission", "host storage");
    let source_bytes = source_program::Storage::new(child, construction())
        .map_err(|_| Failure::new("source_admission", "source storage"))?
        .required_bytes();
    // Both genuine program/inputs and the reconstructed program/synthetic
    // inputs coexist during pre-dispatch comparison. Each complete input
    // backing is included, without assuming shrink-to-fit or move elision.
    let comparison = sum(&[
        source_bytes,
        PROGRAM_BYTES,
        2 * fields(MAX_INPUTS).map_err(fail)?,
        REGISTERED_GPU_CALLER_HOST_BYTES,
    ])
    .map_err(fail)?;
    let reconstruction = sum(&[
        source_bytes,
        MAX_RETAINED_PROOF_BYTES,
        fields(MAX_INPUTS).map_err(fail)?,
        REGISTERED_GPU_CALLER_HOST_BYTES,
    ])
    .map_err(fail)?;
    let roots =
        1 << (outer_height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
    let cpu = RegisteredVerifier::host_reservation_bytes(PUBLICS, outer_height, roots, roots)
        .map_err(|_| Failure::new("source_admission", "CPU verifier source"))?;
    let cpu_peak = sum(&[cpu, REGISTERED_GPU_CALLER_HOST_BYTES]).map_err(fail)?;
    let artifact_roundtrip = sum(&[
        artifact_transport::required_host_bytes().map_err(fail)?,
        REGISTERED_GPU_CALLER_HOST_BYTES,
    ])
    .map_err(fail)?;
    for required in [comparison, reconstruction, cpu_peak, artifact_roundtrip] {
        admit(required).map_err(fail)?;
    }
    Ok(StorageReport {
        caller_reserved_bytes: REGISTERED_GPU_CALLER_HOST_BYTES,
        source_construction_bytes: source_bytes,
        source_comparison_peak_bytes: comparison,
        reconstruction_with_retained_outer_peak_bytes: reconstruction,
        retained_outer_proof_allowance_bytes: MAX_RETAINED_PROOF_BYTES,
        cpu_verifier_with_proof_reserved_bytes: cpu,
        cpu_phase_peak_bytes: cpu_peak,
        artifact_roundtrip_peak_bytes: artifact_roundtrip,
        independent_registration_host_partition_bytes: (HOST_BYTES - MAX_RETAINED_PROOF_BYTES)
            as u64,
    })
}
fn reconstruct(
    source: &ExpectedRecursiveSource,
    storage: StorageReport,
) -> Result<ExpectedProgram, Failure> {
    attempt("source_reconstruction", || {
        let program = source_program::reconstruct_single_child(
            source.bound().child,
            source.cap(),
            construction(),
            storage.source_construction_bytes,
        )
        .map_err(|_| Failure::new("source_reconstruction", "bounded reconstruction"))?;
        conform(&program, source)?;
        let manifest = proving::canonical_manifest_digest(&program)
            .map_err(|_| Failure::new("source_reconstruction", "manifest"))?;
        let mut synthetic = Vec::new();
        synthetic
            .try_reserve_exact(program.witness_values())
            .map_err(|_| Failure::new("source_reconstruction", "synthetic input allocation"))?;
        if synthetic.capacity() > MAX_INPUTS {
            return Err(Failure::new("source_reconstruction", "synthetic capacity"));
        }
        synthetic.resize(program.witness_values(), Val::ZERO);
        Ok(ExpectedProgram {
            program: Arc::new(program),
            synthetic,
            manifest,
        })
    })
}
fn preflight(input: &OuterInput) -> Result<Preflight, Failure> {
    let _ = request()?;
    let storage = source_storage(&input.source, input.program.height())?;
    let expected = reconstruct(&input.source, storage)?;
    let genuine_manifest = proving::canonical_manifest_digest(&input.program)
        .map_err(|_| Failure::new("preflight", "genuine manifest"))?;
    if expected.manifest != genuine_manifest
        || descriptor(&expected.program, expected.manifest, [0; 4])
            != descriptor(&input.program, genuine_manifest, [0; 4])
    {
        return Err(Failure::new("preflight", "independent source mismatch"));
    }
    let proof_limits =
        RegisteredGpuLimits::new(HOST_BYTES as u64, DEVICE_BYTES, CONTEXT_BYTES, MAX_ROWS)
            .map_err(|_| Failure::new("preflight", "prover limits"))?;
    let verification_limits = RegisteredGpuLimits::new(
        storage.independent_registration_host_partition_bytes,
        DEVICE_BYTES,
        CONTEXT_BYTES,
        MAX_ROWS,
    )
    .map_err(|_| Failure::new("preflight", "verifier limits"))?;
    let public = input.source.public();
    let proof_plan =
        RegisteredGpuMemoryPlan::new(&input.program, &public, &input.inputs.0, proof_limits)
            .map_err(|_| Failure::new("preflight", "prover plan"))?;
    let footprint = proof_plan.footprint();
    let proof = proof_plan
        .admit()
        .map_err(|_| phase_refusal("prover phase refused", footprint))?;
    let verify_plan = RegisteredGpuMemoryPlan::new(
        &expected.program,
        &public,
        &expected.synthetic,
        verification_limits,
    )
    .map_err(|_| Failure::new("preflight", "verifier plan"))?;
    let footprint = verify_plan.footprint();
    let verify = verify_plan
        .admit()
        .map_err(|_| phase_refusal("verifier phase refused", footprint))?;
    proof
        .check_execution_selection()
        .map_err(|_| Failure::new("preflight", "prover selection"))?;
    verify
        .check_execution_selection()
        .map_err(|_| Failure::new("preflight", "verifier selection"))?;
    if proof.footprint().physical_device_uuid != verify.footprint().physical_device_uuid {
        return Err(Failure::new("preflight", "physical device mismatch"));
    }
    drop(verify);
    drop(proof);
    let source_manifest = expected.manifest;
    drop(expected);
    Ok(Preflight {
        source_manifest,
        proof_limits,
        verification_limits,
        storage,
    })
}

trait RetiringSession {
    fn finish(self) -> Result<serde_json::Value, String>;
    fn close(self) -> Result<serde_json::Value, String>;
}
impl RetiringSession for Session {
    fn finish(self) -> Result<serde_json::Value, String> {
        Session::finish(self)
    }
    fn close(self) -> Result<serde_json::Value, String> {
        self.close_without_completion()
    }
}

fn finish<T>(
    session: impl RetiringSession,
    attempted: Result<T, Failure>,
    completed: bool,
) -> Result<(T, TerminalReceipt), Failure> {
    let terminal = attempt("session_retirement", || {
        let value = if completed && attempted.is_ok() {
            session.finish()
        } else {
            session.close()
        }
        .map_err(|_| Failure::new("session_retirement", "session cleanup"))?;
        proving::terminal_receipt(&value, completed && attempted.is_ok())
            .map_err(|_| Failure::new("session_retirement", "terminal receipt"))
    });
    match (attempted, terminal) {
        (Ok(value), Ok(terminal)) => Ok((value, terminal)),
        (Err(mut failure), Ok(terminal)) => {
            if completed {
                failure.outer_proving_terminal = Some(terminal);
            } else {
                failure.outer_verification_terminal = Some(terminal);
            }
            Err(failure)
        }
        (Ok(_), Err(mut failure)) | (Err(mut failure), Err(_)) => {
            failure.cleanup_failed = true;
            Err(failure)
        }
    }
}

fn prove(
    program: Arc<Program>,
    inputs: SecretInputs,
    source: &ExpectedRecursiveSource,
    preflight: &Preflight,
) -> Result<Generated, Failure> {
    let started = Instant::now();
    let public = source.public();
    let request = request()?;
    let plan = RegisteredGpuMemoryPlan::new(&program, &public, &inputs.0, preflight.proof_limits)
        .map_err(|_| Failure::new("outer_proving", "original plan"))?;
    let admitted = plan
        .admit()
        .map_err(|_| Failure::new("outer_proving", "original admission"))?;
    admitted
        .check_execution_selection()
        .map_err(|_| Failure::new("outer_proving", "execution selection"))?;
    let footprint = admitted.footprint();
    let session = attempt("outer_session_start", || {
        Session::start(Limits {
            host_bytes: HOST_BYTES as u64,
            device_bytes: DEVICE_BYTES,
            max_rows: MAX_ROWS,
        })
        .map_err(|_| Failure::new("outer_session_start", "session start"))
    })?;
    let proof_started = Cell::new(false);
    let attempted: Result<ProvingAttempt, Failure> = attempt("outer_proving", || {
        admitted
            .check_execution_selection()
            .map_err(|_| Failure::new("outer_proving", "execution selection"))?;
        let setup_started = Instant::now();
        let air = MachineAir::from_shared_program(Arc::clone(admitted.program()));
        let (registered, registration) =
            RegisteredProgram::new_with_request_and_identity_hint_and_report(
                air,
                admitted.host_budget_bytes(),
                request,
                None,
            )
            .map_err(|_| Failure::new("outer_registration", "registration"))?;
        proving::validate_registration_receipt(&registration)
            .map_err(|_| Failure::new("outer_registration", "native registration receipt"))?;
        let descriptor = descriptor(
            registered.air().program(),
            preflight.source_manifest,
            registered.id(),
        );
        let setup_ns = setup_started.elapsed().as_nanos();
        admitted
            .check_execution_selection()
            .map_err(|_| Failure::new("outer_proving", "execution selection"))?;
        proof_started.set(true);
        let proving_started = Instant::now();
        let (proof, proving) = registered
            .into_prove_with_request_and_report(&admitted, request)
            .map_err(|_| Failure::new("outer_proving", "fresh registered proof"))?;
        proving::validate_recursive_outer_proof_receipt(&proving)
            .map_err(|_| Failure::new("outer_proving", "native proof receipt"))?;
        let retained_proof_bytes = retained_proof_capacity_bytes(&proof, MAX_RETAINED_PROOF_BYTES)
            .map_err(|_| Failure::new("outer_proving", "proof storage"))?;
        let proving_ns = proving_started.elapsed().as_nanos();
        let public_hash = public_hash_execution()
            .map_err(|_| Failure::new("outer_proving", "public hash"))?
            .ok_or_else(|| Failure::new("outer_proving", "missing fresh public hash"))?;
        Ok((
            proof,
            registration,
            proving,
            descriptor,
            public_hash,
            retained_proof_bytes,
            setup_ns,
            proving_ns,
        ))
    });
    drop(admitted);
    drop(program);
    drop(inputs);
    let teardown_started = Instant::now();
    let (result, terminal) = finish(session, attempted, true).map_err(|mut failure| {
        failure.outer_proof_started = proof_started.get();
        failure
    })?;
    let teardown_ns = teardown_started.elapsed().as_nanos();
    let (
        proof,
        registration,
        proving,
        descriptor,
        public_hash,
        retained_proof_bytes,
        setup_ns,
        proving_ns,
    ) = result;
    // All original GPU/program/input owners have retired before serialization.
    // Original proof ownership moves into the transport helper and is destroyed
    // before bounded decoding. Only the decoded proof reaches CPU acceptance.
    let (proof, artifact_transport) = artifact_transport::roundtrip(
        proof,
        source.context(),
        source.representation(),
        public,
        descriptor,
        preflight.storage.artifact_roundtrip_peak_bytes - REGISTERED_GPU_CALLER_HOST_BYTES,
    )
    .map_err(|_| Failure {
        outer_proof_started: true,
        outer_proving_terminal: Some(terminal),
        ..Failure::new("outer_artifact_roundtrip", "bounded outer transport")
    })?;
    Ok(Generated {
        proof,
        artifact_transport,
        report: ProvingReport {
            footprint,
            registration,
            proving,
            descriptor,
            public_hash,
            terminal,
            retained_proof_bytes,
            setup_ns,
            proving_ns,
            teardown_ns,
            total_ns: started.elapsed().as_nanos(),
        },
    })
}

fn verify(
    source: &ExpectedRecursiveSource,
    generated: &mut Generated,
    preflight: &Preflight,
) -> Result<IndependentReport, Failure> {
    let started = Instant::now();
    admit(
        preflight
            .storage
            .reconstruction_with_retained_outer_peak_bytes,
    )
    .map_err(|_| Failure::new("outer_verification", "reconstruction admission"))?;
    let reconstruction_started = Instant::now();
    let expected = reconstruct(source, preflight.storage)?;
    if expected.manifest != preflight.source_manifest
        || descriptor(
            &expected.program,
            expected.manifest,
            generated.report.descriptor.registered_program_id,
        ) != generated.report.descriptor
    {
        return Err(Failure::new(
            "outer_verification",
            "independent source descriptor",
        ));
    }
    let reconstruction_ns = reconstruction_started.elapsed().as_nanos();
    let request = request()?;
    let public = source.public();
    let plan = RegisteredGpuMemoryPlan::new(
        &expected.program,
        &public,
        &expected.synthetic,
        preflight.verification_limits,
    )
    .map_err(|_| Failure::new("outer_verification", "memory plan"))?;
    let admitted = plan
        .admit()
        .map_err(|_| Failure::new("outer_verification", "memory admission"))?;
    admitted
        .check_execution_selection()
        .map_err(|_| Failure::new("outer_verification", "selection"))?;
    let footprint = admitted.footprint();
    let session = attempt("outer_verifier_session", || {
        Session::start(Limits {
            host_bytes: HOST_BYTES as u64,
            device_bytes: DEVICE_BYTES,
            max_rows: MAX_ROWS,
        })
        .map_err(|_| Failure::new("outer_verifier_session", "session start"))
    })?;
    let attempted = attempt("outer_verifier_registration", || {
        admitted
            .check_execution_selection()
            .map_err(|_| Failure::new("outer_verifier_registration", "selection"))?;
        let setup_started = Instant::now();
        let air = MachineAir::from_shared_program(Arc::clone(admitted.program()));
        let (registered, registration) =
            RegisteredProgram::new_with_request_and_identity_hint_and_report(
                air,
                admitted.host_budget_bytes(),
                request,
                None,
            )
            .map_err(|_| Failure::new("outer_verifier_registration", "registration"))?;
        proving::validate_registration_receipt(&registration)
            .map_err(|_| Failure::new("outer_verifier_registration", "native receipt"))?;
        let descriptor = descriptor(
            registered.air().program(),
            expected.manifest,
            registered.id(),
        );
        if descriptor != generated.report.descriptor {
            return Err(Failure::new(
                "outer_verifier_registration",
                "independent registered identity",
            ));
        }
        let cap = registered.preprocessing_cap();
        let roots = 1
            << (expected.program.height().ilog2() as usize + 1 + profile::LOG_BLOWUP)
                .min(profile::CAP_HEIGHT);
        if cap.roots().len() != roots || cap.root_capacity() != roots {
            return Err(Failure::new("outer_verifier_registration", "cap geometry"));
        }
        let verifier = registered.verifier();
        let public_hash = public_hash_execution()
            .map_err(|_| Failure::new("outer_verifier_registration", "public hash"))?
            .ok_or_else(|| {
                Failure::new("outer_verifier_registration", "missing fresh public hash")
            })?;
        let setup_ns = setup_started.elapsed().as_nanos();
        drop(registered);
        Ok(Setup {
            verifier,
            registration,
            descriptor,
            public_hash,
            setup_ns,
        })
    });
    drop(admitted);
    drop(expected);
    let teardown_started = Instant::now();
    let (setup, terminal) = finish(session, attempted, false)?;
    let teardown_ns = teardown_started.elapsed().as_nanos();
    if terminal.commits == 0 || terminal.allocations == 0 {
        return Err(Failure {
            outer_verification_terminal: Some(terminal),
            ..Failure::new("outer_verifier_retirement", "missing fresh setup execution")
        });
    }
    // No GPU owner, source program or synthetic witness remains during CPU
    // acceptance and the sequential, restored negative probes.
    let numerical = attempt("outer_cpu_verification", || {
        admit(preflight.storage.cpu_phase_peak_bytes)
            .map_err(|_| Failure::new("outer_cpu_verification", "CPU admission"))?;
        let cpu_started = Instant::now();
        setup
            .verifier
            .verify(&generated.proof, &public)
            .map_err(|_| Failure::new("outer_cpu_verification", "proof rejected"))?;
        let cpu_ns = cpu_started.elapsed().as_nanos();
        let mutation_started = Instant::now();
        for index in 0..PUBLICS {
            let mut changed = public;
            changed[index] += Val::ONE;
            // A panic never qualifies as a successful negative probe.
            attempt("outer_public_mutation", || {
                mutation::require_rejection(
                    setup.verifier.verify_classified(&generated.proof, &changed),
                )
                .map_err(|reason| Failure::new("outer_public_mutation", reason))
            })?;
        }
        let opening = generated
            .proof
            .opened_values
            .instances
            .first_mut()
            .and_then(|instance| instance.base_opened_values.trace_local.first_mut())
            .ok_or_else(|| Failure::new("outer_opening_mutation", "opening geometry"))?;
        let original = *opening;
        *opening += profile::Challenge::ONE;
        let rejected = attempt("outer_opening_mutation", || {
            mutation::require_rejection(setup.verifier.verify_classified(&generated.proof, &public))
                .map_err(|reason| Failure::new("outer_opening_mutation", reason))
        });
        generated.proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] = original;
        rejected?;
        Ok((cpu_ns, mutation_started.elapsed().as_nanos()))
    })
    .map_err(|mut failure| {
        failure.outer_verification_terminal = Some(terminal);
        failure
    })?;
    drop(setup.verifier);
    Ok(IndependentReport {
        footprint,
        registration: setup.registration,
        public_hash: setup.public_hash,
        terminal,
        descriptor: setup.descriptor,
        synthetic_hints_evaluated: false,
        source_manifest_matches: true,
        cpu_verified: true,
        public_mutation_rejections: PUBLICS as u32,
        opening_mutation_rejections: 1,
        reconstruction_ns,
        setup_ns: setup.setup_ns,
        teardown_ns,
        cpu_verification_ns: numerical.0,
        mutation_checks_ns: numerical.1,
        total_ns: started.elapsed().as_nanos(),
    })
}

/// Fresh outer proof of one independently verified full direct-ring child.
/// Independent reconstruction uses only the private expected-public cap/source
/// owner and the fixed proof layout. The original child is released before the
/// outer GPU session. No alternate profile, backend, retry or fallback exists.
pub fn qualify_single_child_outer(
    artifact: Artifact,
    expected_statement: &Statement,
    expected_context: Context,
    compiler_profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
) -> Result<Report, Failure> {
    let started = Instant::now();
    let child = verification::verify_for_recursion(
        artifact,
        expected_statement,
        expected_context,
        compiler_profile,
        representation,
    )
    .map_err(|failure| Failure {
        child_failure: Some(failure),
        ..Failure::new("independent_child", "child verification")
    })?;
    let child_terminal = child.terminal();
    qualify_verified(child, started).map_err(|mut failure| {
        failure.child_terminal = Some(child_terminal);
        failure
    })
}

fn qualify_verified(child: VerifiedRecursiveChild, started: Instant) -> Result<Report, Failure> {
    let compilation_started = Instant::now();
    let compiled =
        super::compile(child).map_err(|failure| Failure::new(failure.phase, failure.reason))?;
    let recursive_compilation_ns = compilation_started.elapsed().as_nanos();
    let evaluation_started = Instant::now();
    if !compiled
        .check(&compiled.public)
        .map_err(|f| Failure::new(f.phase, f.reason))?
    {
        return Err(Failure::new(
            "recursive_constraints",
            "valid constraints rejected",
        ));
    }
    let recursive_constraint_evaluation_ns = evaluation_started.elapsed().as_nanos();
    let mutations_started = Instant::now();
    for index in 0..PUBLICS {
        let mut changed = compiled.public;
        changed[index] += Val::ONE;
        if compiled
            .check(&changed)
            .map_err(|f| Failure::new(f.phase, f.reason))?
        {
            return Err(Failure::new(
                "recursive_constraints",
                "changed public accepted",
            ));
        }
    }
    let recursive_public_mutation_checks_ns = mutations_started.elapsed().as_nanos();
    let CompiledChild {
        program,
        inputs,
        child,
        report: compiler,
        ..
    } = compiled;
    let (source, child_report) = child.into_outer_source();
    let source_preflight_ns = source.bound().elapsed_ns;
    let input = OuterInput {
        program: Arc::new(program),
        inputs: SecretInputs(inputs.values),
        source,
        child_report,
        compiler,
    };
    let comparison_started = Instant::now();
    let preflight = preflight(&input)?;
    let source_comparison_ns = comparison_started.elapsed().as_nanos();
    let OuterInput {
        program,
        inputs,
        source,
        child_report,
        compiler,
    } = input;
    let mut generated = prove(program, inputs, &source, &preflight)?;
    let independent_verification =
        verify(&source, &mut generated, &preflight).map_err(|mut failure| {
            failure.outer_proof_started = true;
            failure.outer_proving_terminal = Some(generated.report.terminal);
            failure
        })?;
    let Generated {
        proof,
        report: proving,
        artifact_transport,
    } = generated;
    drop(proof);
    drop(source);
    Ok(Report {
        schema: "lattica-research-direct-ring-single-child-recursive-proof-v1",
        scope: "one-direct-ring-child-one-outer-proof",
        proof_generation: "fresh-only",
        independently_verified_children: 1,
        outer_recursive_proofs_generated: 1,
        independently_verified_outer_proofs: 1,
        complete_transaction_aggregate: false,
        final_aggregate: false,
        artifact_roundtrip: true,
        artifact_transport,
        source_cap_provenance: "private-expected-public-independent-child-reconstruction",
        compiler,
        storage: preflight.storage,
        source_preflight_ns,
        recursive_compilation_ns,
        recursive_constraint_evaluation_ns,
        recursive_public_mutation_checks_ns,
        source_comparison_ns,
        total_qualification_ns: started.elapsed().as_nanos(),
        child_verification: child_report,
        proving,
        independent_verification,
    })
}

#[cfg(test)]
pub(in crate::ring_circuit) mod qualification_timing;
#[cfg(test)]
mod tests;
