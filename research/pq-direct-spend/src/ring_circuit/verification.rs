//! Independent verification of one complete direct-ring proof. The expected
//! public statement alone determines the reconstructed program and fresh
//! preprocessing cap. Synthetic compiler hints are never evaluated.
//!
//! Reconstruction registration uses a new GPU session after the prover has
//! retired its session. Numerical proof verification runs on the CPU only
//! after all GPU setup owners and the fresh session have been retired.
use super::{
    artifact::{self, Artifact, ProofDescriptor},
    compile_with_representation_diagnostics,
    proving::{self, TerminalReceipt},
    CompiledRelation, CompilerCapacityProfile, CompilerRepresentation, Context, Error, Program,
    Statement, Summary, Val,
};
use lattica_pq_ringct_research::opencl::{Limits, Session};
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::{public_hash_execution, PublicHashExecution},
        machine::{
            backend::{RegisteredProgram, RegisteredVerifier},
            MachineAir, RegisteredGpuFootprint, RegisteredGpuLimits, RegisteredGpuMemoryPlan,
            REGISTERED_GPU_CALLER_HOST_BYTES,
        },
        profile,
    },
    proving::{Policy, Report, Request},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use serde::Serialize;
use std::{cell::Cell, sync::Arc, time::Instant};

mod lifecycle;
pub(super) mod mutation;
pub(super) mod reconstruction;
#[cfg(feature = "ring-recursion-experiment")]
mod recursive_child;
#[cfg(feature = "ring-recursive-outer-experiment")]
pub(super) use recursive_child::ExpectedRecursiveSource;
#[cfg(feature = "ring-recursion-experiment")]
pub(super) use recursive_child::{verify_for_recursion, VerifiedRecursiveChild};
#[cfg(feature = "ring-recursion-experiment")]
use recursive_child::{RecursiveEvidence, TrustedCap};

const HOST_BYTES: u64 = 32 << 30;
const DEVICE_BYTES: u64 = 8 << 30;
const CONTEXT_BYTES: u64 = 4 << 30;
const MAX_ROWS: usize = 1 << 20;

/// Enclosing CLI arguments, path capacities and scalar/streaming report state.
/// Callers must bound those actual owners within this existing worker charge.
pub const CALLER_ORCHESTRATION_BYTES: usize = 32 << 10;

#[derive(Serialize)]
pub struct VerificationReport {
    /// None means the explicit reuse profile dispatched no fresh public hash.
    pub public_hash: Option<PublicHashExecution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) identity_reuse: Option<super::identity_reuse::ReuseReport>,
    pub schema: &'static str,
    pub verified: bool,
    pub public_reconstruction: &'static str,
    pub verifier_preprocessing_policy: Policy,
    pub proof_verification_backend: &'static str,
    pub reused_prover_state: bool,
    pub synthetic_hints_evaluated: bool,
    /// Independent expected inputs and local profile identity, never envelope
    /// claims copied from the artifact under verification.
    pub expected_context: [u8; 32],
    pub expected_public_binding: [u64; 4],
    pub artifact_profile_digest: [u8; 32],
    pub compiler: Summary,
    pub descriptor: ProofDescriptor,
    pub footprint: RegisteredGpuFootprint,
    pub caller_requested_bytes: usize,
    pub caller_reserved_bytes: usize,
    pub retained_artifact_bytes: usize,
    pub cpu_verifier_reserved_bytes: usize,
    pub reconstruction_ns: u128,
    pub admission_ns: u128,
    pub session_start_ns: u128,
    pub gpu_preprocessing_ns: u128,
    pub teardown_ns: u128,
    pub cpu_verification_ns: u128,
    pub mutation_checks_ns: u128,
    pub mutation_checks: u32,
    pub total_verification_lifecycle_ns: u128,
    pub registration: Report,
    pub terminal: TerminalReceipt,
}

#[derive(Debug, Serialize)]
pub struct VerificationFailure {
    pub schema: &'static str,
    pub phase: &'static str,
    pub gpu_registration_started: bool,
    pub cpu_verification_started: bool,
    pub error: String,
    pub cleanup_error: Option<String>,
    pub terminal: Option<TerminalReceipt>,
}

impl VerificationFailure {
    fn new(
        phase: &'static str,
        gpu_registration_started: bool,
        cpu_verification_started: bool,
        error: &impl std::fmt::Debug,
    ) -> Self {
        Self {
            schema: "lattica-research-direct-ring-verification-failure-v1",
            phase,
            gpu_registration_started,
            cpu_verification_started,
            error: lifecycle::bounded(error),
            cleanup_error: None,
            terminal: None,
        }
    }
}
impl std::fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.phase, self.error)
    }
}
impl std::error::Error for VerificationFailure {}

struct IndependentVerifier {
    public_hash: Option<PublicHashExecution>,
    identity_reuse: Option<super::identity_reuse::ReuseReport>,
    verifier: RegisteredVerifier,
    #[cfg(feature = "ring-recursion-experiment")]
    recursive_cap: TrustedCap,
    descriptor: ProofDescriptor,
    compiler: Summary,
    footprint: RegisteredGpuFootprint,
    caller_requested_bytes: usize,
    cpu_verifier_reserved_bytes: usize,
    admission_ns: u128,
    session_start_ns: u128,
    gpu_preprocessing_ns: u128,
    teardown_ns: u128,
    registration: Report,
    terminal: TerminalReceipt,
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

fn register_independently(
    relation: CompiledRelation,
    statement: &Statement,
    mut identity: Option<super::identity_reuse::Transfer>,
) -> Result<IndependentVerifier, VerificationFailure> {
    let started = Instant::now();
    let caller_requested_bytes = reconstruction::caller_bytes(statement)
        .map_err(|error| VerificationFailure::new("caller_storage", false, false, &error))?;
    let request = strict_request()
        .map_err(|error| VerificationFailure::new("environment", false, false, &error))?;
    let CompiledRelation {
        program,
        witness,
        public,
        summary,
    } = relation;
    let program = Arc::new(program);
    let limits = RegisteredGpuLimits::new(HOST_BYTES, DEVICE_BYTES, CONTEXT_BYTES, MAX_ROWS)
        .map_err(|error| VerificationFailure::new("memory_limits", false, false, &error))?;
    let plan = RegisteredGpuMemoryPlan::new(&program, &public, &witness, limits)
        .map_err(|error| VerificationFailure::new("memory_plan", false, false, &error))?;
    let admitted = plan
        .admit()
        .map_err(|error| VerificationFailure::new("memory_admission", false, false, &error))?;
    admitted
        .check_execution_selection()
        .map_err(|error| VerificationFailure::new("execution_selection", false, false, &error))?;
    let footprint = admitted.footprint();
    let manifest = proving::canonical_manifest_digest(&program)
        .map_err(|error| VerificationFailure::new("manifest", false, false, &error))?;
    if let Some(identity) = identity.as_ref() {
        identity
            .check_reconstructed(reconstruction::descriptor(&program, manifest, [0; 4]))
            .map_err(|error| {
                VerificationFailure::new("identity_receipt_program", false, false, &error)
            })?;
    }
    // The independently rebuilt verifier's cap has the pinned canonical root
    // count and capacity. Reserve its complete CPU lifecycle before GPU setup.
    let roots =
        1 << (program.height().ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
    let cpu_verifier_reserved_bytes =
        RegisteredVerifier::host_reservation_bytes(public.len(), program.height(), roots, roots)
            .map_err(|error| VerificationFailure::new("cpu_memory_plan", false, false, &error))?;
    if cpu_verifier_reserved_bytes
        .checked_add(REGISTERED_GPU_CALLER_HOST_BYTES)
        .is_none_or(|bytes| bytes > HOST_BYTES as usize)
    {
        return Err(VerificationFailure::new(
            "cpu_memory_admission",
            false,
            false,
            &Error::ResourceLimit,
        ));
    }
    let admission_ns = started.elapsed().as_nanos();
    let session_started = Instant::now();
    let session = lifecycle::attempt(
        &Cell::new("session_start"),
        &Cell::new(false),
        false,
        || {
            Session::start(Limits {
                host_bytes: HOST_BYTES,
                device_bytes: DEVICE_BYTES,
                max_rows: MAX_ROWS,
            })
            .map_err(|error| VerificationFailure::new("session_start", false, false, &error))
        },
    )?;
    let session_start_ns = session_started.elapsed().as_nanos();
    let phase = Cell::new("registration");
    let registration_started = Cell::new(false);
    let attempted = lifecycle::attempt(&phase, &registration_started, false, || {
        admitted.check_execution_selection().map_err(|error| {
            VerificationFailure::new("execution_selection", false, false, &error)
        })?;
        let setup_started = Instant::now();
        let air = MachineAir::from_shared_program(Arc::clone(admitted.program()));
        let hint = identity
            .as_mut()
            .map(|identity| identity.hint(&session))
            .transpose()
            .map_err(|error| {
                VerificationFailure::new("identity_receipt_device", false, false, &error)
            })?;
        registration_started.set(true);
        let (registered, registration) =
            RegisteredProgram::new_with_request_and_identity_hint_and_report(
                air,
                admitted.host_budget_bytes(),
                request,
                hint,
            )
            .map_err(|error| VerificationFailure::new("registration", true, false, &error))?;
        proving::validate_registration_receipt(&registration).map_err(|error| {
            VerificationFailure::new("registration_receipt", true, false, &error)
        })?;
        phase.set("independent_verifier_construction");
        if registered.preprocessing_cap().roots().len() != roots
            || registered.preprocessing_cap().root_capacity() != roots
        {
            return Err(VerificationFailure::new(
                phase.get(),
                true,
                false,
                &Error::Geometry,
            ));
        }
        let descriptor =
            reconstruction::descriptor(registered.air().program(), manifest, registered.id());
        let verifier = registered.verifier();
        // This value comes only from the newly registered, independently
        // reconstructed expected public program. Artifact claims never supply it.
        #[cfg(feature = "ring-recursion-experiment")]
        let recursive_cap = TrustedCap::capture(&registered)?;
        let public_hash = public_hash_execution().map_err(|error| {
            VerificationFailure::new("public_hash_execution", true, false, &error)
        })?;
        let identity_reuse = match identity.take() {
            Some(identity) => Some(identity.finish(&registered, public_hash).map_err(|error| {
                VerificationFailure::new("identity_receipt_match", true, false, &error)
            })?),
            None if public_hash.is_some() && !registered.identity_hint_hit() => None,
            None => {
                return Err(VerificationFailure::new(
                    "public_hash_execution",
                    true,
                    false,
                    &"no completed fresh public hash",
                ))
            }
        };
        let gpu_preprocessing_ns = setup_started.elapsed().as_nanos();
        drop(registered);
        Ok((
            verifier,
            #[cfg(feature = "ring-recursion-experiment")]
            recursive_cap,
            descriptor,
            registration,
            gpu_preprocessing_ns,
            public_hash,
            identity_reuse,
        ))
    });
    // No prepared state, source Arc or synthetic hint allocation survives into
    // independent CPU verification. A synthetic witness is never evaluated.
    drop(admitted);
    drop(program);
    drop(witness);
    let teardown_started = Instant::now();
    #[cfg(feature = "ring-recursion-experiment")]
    let (
        (
            verifier,
            recursive_cap,
            descriptor,
            registration,
            gpu_preprocessing_ns,
            public_hash,
            identity_reuse,
        ),
        terminal,
    ) = lifecycle::finish(session, attempted)?;
    #[cfg(not(feature = "ring-recursion-experiment"))]
    let (
        (verifier, descriptor, registration, gpu_preprocessing_ns, public_hash, identity_reuse),
        terminal,
    ) = lifecycle::finish(session, attempted)?;
    let teardown_ns = teardown_started.elapsed().as_nanos();
    Ok(IndependentVerifier {
        public_hash,
        identity_reuse,
        verifier,
        #[cfg(feature = "ring-recursion-experiment")]
        recursive_cap,
        descriptor,
        compiler: summary,
        footprint,
        caller_requested_bytes,
        cpu_verifier_reserved_bytes,
        admission_ns,
        session_start_ns,
        gpu_preprocessing_ns,
        teardown_ns,
        registration,
        terminal,
    })
}

/// Rebuild and verify using independently supplied public inputs. The artifact
/// is borrowed mutably only for a restored negative probe; successful return
/// preserves its canonical bytes. No prover-created verifier is accepted.
pub fn verify(
    artifact: &mut Artifact,
    expected_statement: &Statement,
    expected_context: Context,
    compiler_profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
) -> Result<VerificationReport, VerificationFailure> {
    verify_inner(
        artifact,
        expected_statement,
        expected_context,
        compiler_profile,
        representation,
        None,
        #[cfg(feature = "ring-recursion-experiment")]
        None,
    )
}

#[cfg(feature = "gpu-identity-reuse-experiment")]
pub(crate) fn verify_reusing_identity(
    artifact: &mut Artifact,
    expected_statement: &Statement,
    expected_context: Context,
    compiler_profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
    identity: super::identity_reuse::Transfer,
) -> Result<VerificationReport, VerificationFailure> {
    verify_inner(
        artifact,
        expected_statement,
        expected_context,
        compiler_profile,
        representation,
        Some(identity),
        #[cfg(feature = "ring-recursion-experiment")]
        None,
    )
}

fn verify_inner(
    artifact: &mut Artifact,
    expected_statement: &Statement,
    expected_context: Context,
    compiler_profile: CompilerCapacityProfile,
    representation: CompilerRepresentation,
    identity: Option<super::identity_reuse::Transfer>,
    #[cfg(feature = "ring-recursion-experiment")] recursive_evidence: Option<
        &mut Option<RecursiveEvidence>,
    >,
) -> Result<VerificationReport, VerificationFailure> {
    let started = Instant::now();
    if let Some(identity) = identity.as_ref() {
        identity
            .check_expected(expected_statement, expected_context, representation)
            .map_err(|error| {
                VerificationFailure::new("identity_receipt_expected_inputs", false, false, &error)
            })?;
    }
    artifact
        .check_expected(expected_statement, expected_context, representation)
        .map_err(|error| VerificationFailure::new("expected_inputs", false, false, &error))?;
    reconstruction::caller_bytes(expected_statement)
        .map_err(|error| VerificationFailure::new("caller_storage", false, false, &error))?;
    let retained_artifact_bytes = artifact
        .retained_host_bytes()
        .map_err(|error| VerificationFailure::new("artifact_storage", false, false, &error))?;
    let reconstruction_started = Instant::now();
    let relation = reconstruction::compile(
        expected_statement,
        expected_context,
        compiler_profile,
        representation,
    )
    .map_err(|error| VerificationFailure::new("public_reconstruction", false, false, &error))?;
    reconstruction::check_claims(&relation, artifact.descriptor())
        .map_err(|error| VerificationFailure::new("program_identity", false, false, &error))?;
    let reconstruction_ns = reconstruction_started.elapsed().as_nanos();
    // Recursive geometry comes from the complete expected-public reconstruction,
    // never the transport descriptor. Source planning and admission must finish
    // before the first verifier GPU registration. The plan grants no proving or
    // acceptance authority and is kept private until the child verifies below.
    #[cfg(feature = "ring-recursion-experiment")]
    let recursive_bound = if recursive_evidence.is_some() {
        Some(super::recursion::preflight(&relation).map_err(|error| {
            VerificationFailure::new("recursive_preflight", false, false, &error)
        })?)
    } else {
        None
    };
    let rebuilt = register_independently(relation, expected_statement, identity)?;
    if rebuilt.descriptor != artifact.descriptor() {
        let mut failure =
            VerificationFailure::new("registered_identity", true, false, &Error::ProofRejected);
        failure.terminal = Some(rebuilt.terminal);
        return Err(failure);
    }
    let cpu_started = Instant::now();
    let public = artifact::statement_binding(expected_statement);
    let result = lifecycle::cpu_attempt("cpu_verification", || {
        rebuilt
            .verifier
            .verify(artifact.proof(), &public)
            .map_err(|error| VerificationFailure::new("cpu_verification", true, true, &error))
    });
    let cpu_verification_ns = cpu_started.elapsed().as_nanos();
    if let Err(mut failure) = result {
        failure.terminal = Some(rebuilt.terminal);
        return Err(failure);
    }
    let mutation_started = Instant::now();
    if let Err(mut failure) = lifecycle::mutation_checks(&rebuilt.verifier, artifact, &public) {
        failure.terminal = Some(rebuilt.terminal);
        return Err(failure);
    }
    let mutation_checks_ns = mutation_started.elapsed().as_nanos();
    let IndependentVerifier {
        public_hash,
        identity_reuse,
        verifier,
        #[cfg(feature = "ring-recursion-experiment")]
        recursive_cap,
        descriptor,
        mut compiler,
        footprint,
        caller_requested_bytes,
        cpu_verifier_reserved_bytes,
        admission_ns,
        session_start_ns,
        gpu_preprocessing_ns,
        teardown_ns,
        registration,
        terminal,
    } = rebuilt;
    drop(verifier);
    #[cfg(feature = "ring-recursion-experiment")]
    if let Some(destination) = recursive_evidence {
        // Both options are selected by the same private entry condition. No
        // cap or geometry escapes on a failed CPU verification/mutation probe.
        let bound = recursive_bound.ok_or_else(|| {
            VerificationFailure::new("recursive_evidence", true, true, &Error::Geometry)
        })?;
        *destination = Some(RecursiveEvidence::new(recursive_cap, bound));
    }
    compiler.cryptographic_proof_available = true;
    Ok(VerificationReport {
        public_hash,
        identity_reuse,
        schema: if identity_reuse.is_some() {
            "lattica-research-direct-ring-identity-reuse-verification-v1"
        } else {
            "lattica-research-direct-ring-independent-verification-v1"
        },
        verified: true,
        public_reconstruction: "complete-program-and-fresh-preprocessing-cap",
        verifier_preprocessing_policy: Policy::GpuRequired,
        proof_verification_backend: "cpu",
        reused_prover_state: identity_reuse.is_some(),
        synthetic_hints_evaluated: false,
        expected_context: expected_context.0,
        expected_public_binding: public.map(|value| value.as_canonical_u64()),
        artifact_profile_digest: artifact::profile_digest(representation),
        compiler,
        descriptor,
        footprint,
        caller_requested_bytes,
        caller_reserved_bytes: REGISTERED_GPU_CALLER_HOST_BYTES,
        retained_artifact_bytes,
        cpu_verifier_reserved_bytes,
        reconstruction_ns,
        admission_ns,
        session_start_ns,
        gpu_preprocessing_ns,
        teardown_ns,
        cpu_verification_ns,
        mutation_checks_ns,
        mutation_checks: 2,
        total_verification_lifecycle_ns: started.elapsed().as_nanos(),
        registration,
        terminal,
    })
}

#[cfg(test)]
mod tests;
