//! One fresh proof of the complete direct-ring relation. The caller hands over
//! both source owners; no artifact-supplied geometry or cached proof is used.
//! Core admission precedes GPU initialization. Independent verification is a
//! separate, fresh lifecycle and remains mandatory after this API returns.
use super::artifact::ProofDescriptor;
use super::{
    CompiledRelation, CompilerCapacityProfile, CompilerRepresentation, Context, Error, Program,
    Statement, Summary, Val,
};
use lattica_pq_ringct_research::opencl::{Limits, Session};
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::{public_hash_execution, PublicHashExecution},
        machine::{
            backend::{retained_proof_capacity_bytes, RegisteredProgram},
            MachineAir, RegisteredGpuFootprint, RegisteredGpuLimits, RegisteredGpuMemoryPlan,
            REGISTERED_GPU_CALLER_HOST_BYTES,
        },
        profile::Config,
    },
    proving::{Policy, Report, Request},
};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;
use std::{cell::Cell, fmt, sync::Arc, time::Instant};

mod lifecycle;
mod metadata;
mod receipts;
pub use receipts::{DeviceReceipt, TerminalReceipt};

// Shared with the independently rebuilt verifier, without exposing a way for
// external callers to mint a checked proof or dispatch token.
pub(super) fn validate_registration_receipt(report: &Report) -> Result<(), Error> {
    receipts::validate(report, receipts::NativeScope::Registration)
}
#[cfg(feature = "ring-recursive-outer-experiment")]
pub(super) fn validate_recursive_outer_proof_receipt(report: &Report) -> Result<(), Error> {
    receipts::validate(report, receipts::NativeScope::Proof)
}
pub(super) fn terminal_receipt(
    value: &serde_json::Value,
    completed: bool,
) -> Result<TerminalReceipt, Error> {
    TerminalReceipt::parse(value, completed)
}
pub(super) fn canonical_manifest_digest(program: &Program) -> Result<[u8; 32], Error> {
    metadata::manifest(program)
}

const HOST_BYTES: u64 = 32 << 30;
const DEVICE_BYTES: u64 = 8 << 30;
const CONTEXT_BYTES: u64 = 4 << 30;
const MAX_ROWS: usize = 1 << 20;
const PROOF_BYTES: usize = 64 << 20;

/// Only initialized witness elements are secret. No witness values, hints, or
/// private fixture data enter a report. The guard also runs on admission errors
/// and unwinding, before the session is explicitly drained and retired.
struct SecretValues(Vec<Val>);
impl Drop for SecretValues {
    fn drop(&mut self) {
        for value in &mut self.0 {
            // SAFETY: each value is live and exclusively borrowed.
            unsafe { std::ptr::write_volatile(value, Val::ZERO) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// A checked pairing of the expected public statement and the private compiler
/// owner. It cannot be cloned, re-padded, or filled with a caller-written plan.
/// Construction does not initialize a GPU or grant a dispatch token.
pub struct FreshGpuProofInput {
    statement: Statement,
    expected: Context,
    program: Arc<Program>,
    witness: SecretValues,
    public: [Val; 4],
    summary: Summary,
    caller_requested_bytes: usize,
}

impl FreshGpuProofInput {
    /// The original native Witness must be dropped by the caller after
    /// compilation. This owner retains only the compiler's necessary inputs.
    pub fn new(
        statement: Statement,
        expected: Context,
        relation: CompiledRelation,
    ) -> Result<Self, Error> {
        let CompiledRelation {
            program,
            witness,
            public,
            summary,
        } = relation;
        let witness = SecretValues(witness);
        let caller_requested_bytes = metadata::caller_bytes(&statement)?;
        metadata::validate_compilation(
            &program, &witness.0, &public, &summary, &statement, expected,
        )?;
        Ok(Self {
            statement,
            expected,
            program: Arc::new(program),
            witness,
            public,
            summary,
            caller_requested_bytes,
        })
    }

    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Registers once, proves once with fresh backend randomness, then retires
    /// every GPU/source owner before returning an unverified proof. A refusal
    /// or failure is terminal; there is no fallback, retry, or profile change.
    pub fn prove(self) -> Result<FreshGpuProof, ProofFailure> {
        self.prove_inner(None)
    }

    #[cfg(feature = "gpu-identity-reuse-experiment")]
    pub(crate) fn prove_capturing_identity(
        self,
        identity: &mut super::identity_reuse::Transfer,
    ) -> Result<FreshGpuProof, ProofFailure> {
        let result = self.prove_inner(Some(&mut *identity));
        if result.is_err() {
            identity.refuse();
        }
        result
    }

    fn prove_inner(
        self,
        mut identity: Option<&mut super::identity_reuse::Transfer>,
    ) -> Result<FreshGpuProof, ProofFailure> {
        let started = Instant::now();
        let Self {
            statement,
            expected,
            program,
            witness,
            public,
            mut summary,
            caller_requested_bytes,
        } = self;
        if let Some(identity) = identity.as_ref() {
            identity
                .check_prover_inputs(&statement, expected)
                .map_err(|error| ProofFailure::new("identity_receipt_inputs", false, &error))?;
        }
        let request =
            strict_request().map_err(|error| ProofFailure::new("environment", false, &error))?;
        let limits = RegisteredGpuLimits::new(HOST_BYTES, DEVICE_BYTES, CONTEXT_BYTES, MAX_ROWS)
            .map_err(|error| ProofFailure::new("memory_limits", false, &error))?;
        let plan = RegisteredGpuMemoryPlan::new(&program, &public, &witness.0, limits)
            .map_err(|error| ProofFailure::new("memory_plan", false, &error))?;
        let planned_footprint = plan.footprint();
        let admitted = plan.admit().map_err(|error| {
            let mut failure = ProofFailure::new("memory_admission", false, &error);
            failure.memory_footprint = Some(planned_footprint);
            failure
        })?;
        let footprint = admitted.footprint();
        admitted
            .check_execution_selection()
            .map_err(|error| ProofFailure::new("execution_selection", false, &error))?;
        let manifest = metadata::manifest(&program)
            .map_err(|error| ProofFailure::new("manifest", false, &error))?;
        let admission_ns = started.elapsed().as_nanos();
        let session_started = Instant::now();
        let session = lifecycle::attempt(&Cell::new("session_start"), &Cell::new(false), || {
            Session::start(Limits {
                host_bytes: HOST_BYTES,
                device_bytes: DEVICE_BYTES,
                max_rows: MAX_ROWS,
            })
            .map_err(|error| ProofFailure::new("session_start", false, &error))
        })?;
        let session_start_ns = session_started.elapsed().as_nanos();
        let phase = Cell::new("device_identity");
        let proof_started = Cell::new(false);
        let attempted = lifecycle::attempt(&phase, &proof_started, || {
            let device = DeviceReceipt::from_session(&session)
                .map_err(|error| ProofFailure::new(phase.get(), false, &error))?;
            phase.set("registration");
            admitted
                .check_execution_selection()
                .map_err(|error| ProofFailure::new(phase.get(), proof_started.get(), &error))?;
            let setup_started = Instant::now();
            let air = MachineAir::from_shared_program(Arc::clone(admitted.program()));
            let (registered, registration) =
                RegisteredProgram::new_with_request_and_identity_hint_and_report(
                    air,
                    admitted.host_budget_bytes(),
                    request,
                    None,
                )
                .map_err(|error| ProofFailure::new(phase.get(), proof_started.get(), &error))?;
            receipts::validate(&registration, receipts::NativeScope::Registration)
                .map_err(|error| ProofFailure::new("registration_receipt", false, &error))?;
            let setup_ns = setup_started.elapsed().as_nanos();
            // Geometry is re-read from the actual registered immutable owner.
            let descriptor = ProofDescriptor {
                active_rows: registered.air().program().active_rows() as u64,
                padded_rows: registered.air().program().height() as u64,
                wires: registered.air().program().wire_count() as u64,
                witness_values: registered.air().program().witness_values() as u64,
                canonical_manifest_digest: manifest,
                registered_program_id: registered.id(),
            };
            if let Some(identity) = identity.as_deref_mut() {
                identity
                    .capture(&registered, descriptor, &session)
                    .map_err(|error| {
                        ProofFailure::new("identity_receipt_capture", false, &error)
                    })?;
            }
            phase.set("proving");
            admitted
                .check_execution_selection()
                .map_err(|error| ProofFailure::new(phase.get(), false, &error))?;
            proof_started.set(true);
            let proving_started = Instant::now();
            let (proof, proving) = registered
                .into_prove_with_request_and_report(&admitted, request)
                .map_err(|error| ProofFailure::new(phase.get(), true, &error))?;
            receipts::validate(&proving, receipts::NativeScope::Proof)
                .map_err(|error| ProofFailure::new("proof_receipt", true, &error))?;
            let retained_proof_bytes = retained_proof_capacity_bytes(&proof, PROOF_BYTES)
                .map_err(|error| ProofFailure::new("proof_storage", true, &error))?;
            let proving_ns = proving_started.elapsed().as_nanos();
            let public_hash = public_hash_execution()
                .map_err(|error| ProofFailure::new("public_hash_execution", true, &error))?
                .ok_or_else(|| {
                    ProofFailure::new("public_hash_execution", true, &"no completed public hash")
                })?;
            // The consuming call has already retired cached preprocessing,
            // public metadata and native PCS owners before terminal cleanup.
            Ok(CompletedAttempt {
                public_hash,
                device,
                proof,
                descriptor,
                registration,
                proving,
                setup_ns,
                proving_ns,
                retained_proof_bytes,
            })
        });
        drop(admitted);
        drop(program);
        drop(witness);
        let teardown_started = Instant::now();
        let (completed, terminal) = lifecycle::finish(session, attempted)?;
        if let Some(identity) = identity {
            identity
                .retire_prover(terminal, completed.public_hash)
                .map_err(|error| {
                    let mut failure =
                        ProofFailure::new("identity_receipt_retirement", true, &error);
                    failure.terminal = Some(terminal);
                    failure
                })?;
        }
        let teardown_ns = teardown_started.elapsed().as_nanos();
        summary.cryptographic_proof_available = true;
        let report = ProofReport {
            public_hash: completed.public_hash,
            schema: "lattica-research-direct-ring-gpu-proof-v1",
            proof_generation: "fresh-only",
            registration_lifetime: "consumed-once",
            witness_instructions_retired_before_quotient: true,
            policy: Policy::GpuRequired,
            independent_verification_required: true,
            compiler: summary,
            footprint,
            device: completed.device,
            caller_requested_bytes,
            caller_reserved_bytes: REGISTERED_GPU_CALLER_HOST_BYTES,
            retained_proof_bytes: completed.retained_proof_bytes,
            admission_ns,
            session_start_ns,
            setup_ns: completed.setup_ns,
            proving_ns: completed.proving_ns,
            teardown_ns,
            total_proving_lifecycle_ns: started.elapsed().as_nanos(),
            registration: completed.registration,
            proving: completed.proving,
            terminal,
        };
        Ok(FreshGpuProof {
            statement,
            expected,
            descriptor: completed.descriptor,
            proof: completed.proof,
            report,
        })
    }
}

fn strict_request() -> Result<Request, Error> {
    if cfg!(debug_assertions) || !cfg!(target_arch = "x86_64") {
        return Err(Error::ResourceLimit);
    }
    let request = Request::from_env().map_err(|_| Error::IncompleteProofCoverage)?;
    if request.policy != Policy::GpuRequired || !request.emit_report {
        return Err(Error::IncompleteProofCoverage);
    }
    let context = match std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES") {
        Ok(value) => value.parse::<u64>().map_err(|_| Error::ResourceLimit)?,
        Err(std::env::VarError::NotPresent) => CONTEXT_BYTES,
        Err(_) => return Err(Error::ResourceLimit),
    };
    if context != CONTEXT_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(request)
}

struct CompletedAttempt {
    public_hash: PublicHashExecution,
    device: DeviceReceipt,
    proof: BatchProof<Config>,
    descriptor: ProofDescriptor,
    registration: Report,
    proving: Report,
    setup_ns: u128,
    proving_ns: u128,
    retained_proof_bytes: usize,
}

pub(super) fn admit_identity_caller(statement: &Statement) -> Result<(), Error> {
    metadata::caller_bytes(statement).map(|_| ())
}

/// Measured proving/setup/cleanup boundaries only. The complete workflow also
/// includes compilation, artifact round trips and independent CPU verification.
/// Public compilation is not represented as fresh GPU arithmetic in this report.
#[derive(Debug, Serialize)]
pub struct ProofReport {
    pub public_hash: PublicHashExecution,
    pub schema: &'static str,
    pub proof_generation: &'static str,
    /// Guaranteed by the consuming core API, after its observed trace fence.
    pub registration_lifetime: &'static str,
    pub witness_instructions_retired_before_quotient: bool,
    pub policy: Policy,
    pub independent_verification_required: bool,
    pub compiler: Summary,
    pub footprint: RegisteredGpuFootprint,
    pub device: DeviceReceipt,
    pub caller_requested_bytes: usize,
    pub caller_reserved_bytes: usize,
    pub retained_proof_bytes: usize,
    pub admission_ns: u128,
    pub session_start_ns: u128,
    pub setup_ns: u128,
    pub proving_ns: u128,
    pub teardown_ns: u128,
    pub total_proving_lifecycle_ns: u128,
    pub registration: Report,
    pub proving: Report,
    pub terminal: TerminalReceipt,
}

/// Generated, still unverified proof. No GPU or program owner survives here.
pub struct FreshGpuProof {
    statement: Statement,
    expected: Context,
    descriptor: ProofDescriptor,
    proof: BatchProof<Config>,
    report: ProofReport,
}

impl FreshGpuProof {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn context(&self) -> Context {
        self.expected
    }
    pub fn descriptor(&self) -> ProofDescriptor {
        self.descriptor
    }
    pub fn proof(&self) -> &BatchProof<Config> {
        &self.proof
    }
    pub fn report(&self) -> &ProofReport {
        &self.report
    }
    pub fn into_proof(self) -> BatchProof<Config> {
        self.proof
    }
    pub fn into_parts(self) -> (Statement, ProofDescriptor, BatchProof<Config>, ProofReport) {
        (self.statement, self.descriptor, self.proof, self.report)
    }
}

/// A failed phase never carries a proof or a success receipt. Any explicit
/// cleanup result is reported independently of the original failure.
#[derive(Debug, Serialize)]
pub struct ProofFailure {
    pub schema: &'static str,
    pub phase: &'static str,
    pub cryptographic_proof_started: bool,
    pub error: String,
    /// Planner diagnostics retained on pre-dispatch admission refusal. A floor
    /// in this field is never a successful reservation or execution receipt.
    pub memory_footprint: Option<RegisteredGpuFootprint>,
    pub terminal: Option<TerminalReceipt>,
    pub cleanup_error: Option<String>,
}

impl ProofFailure {
    fn new(phase: &'static str, started: bool, error: &impl fmt::Debug) -> Self {
        Self {
            schema: "lattica-research-direct-ring-gpu-failure-v1",
            phase,
            cryptographic_proof_started: started,
            error: lifecycle::bounded(error),
            memory_footprint: None,
            terminal: None,
            cleanup_error: None,
        }
    }
}
impl fmt::Display for ProofFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "direct-ring {} failed: {}", self.phase, self.error)?;
        if let Some(cleanup) = &self.cleanup_error {
            write!(f, "; cleanup failed: {cleanup}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ProofFailure {}

#[cfg(test)]
mod tests;
