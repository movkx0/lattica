//! Sequential GPU ownership. Every borrowed plan is admitted before Session;
//! every program/input/GPU owner is destroyed before explicit session retirement.
use super::*;
use lattica_pq_ringct_research::opencl::{Limits, Session};
use lattica_prover_p3::{block_v2::gpu_hash::{public_hash_execution, PublicHashExecution},
    proving::{Policy, Report as NativeReport, Request}};
use std::cell::Cell;

#[derive(Debug, Serialize)]
pub struct PhaseReport {
    pub kind: &'static str,
    pub child_index: Option<usize>,
    pub fresh_proof: bool,
    pub descriptor: artifact::ProofDescriptor,
    pub footprint: RegisteredGpuFootprint,
    pub registration: NativeReport,
    pub proving: Option<NativeReport>,
    pub public_hash: PublicHashExecution,
    pub terminal: proving::TerminalReceipt,
    pub setup_ns: u128,
    pub proving_ns: u128,
    pub teardown_ns: u128,
    pub total_ns: u128,
}

pub(super) fn request() -> Result<Request, Failure> {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64", target_os = "linux")) {
        return Err(Failure::new("environment", "unsupported research execution target"));
    }
    let request = Request::from_env().map_err(|_| Failure::new("environment", "proving request"))?;
    let context = match std::env::var("LATTICA_V2_GPU_CONTEXT_BYTES") {
        Ok(value) => value.parse::<u64>().map_err(|_| Failure::new("environment", "context reserve"))?,
        Err(std::env::VarError::NotPresent) => CONTEXT_BYTES,
        Err(_) => return Err(Failure::new("environment", "context reserve")),
    };
    if request.policy != Policy::GpuRequired || !request.emit_report || context != CONTEXT_BYTES {
        return Err(Failure::new("environment", "GpuRequired with complete native reports required"));
    }
    Ok(request)
}

pub(super) fn preflight(compiled: &Compiled, budget: &bounds::Budget) -> Result<RegisteredGpuFootprint, Failure> {
    request()?;
    let shape = compiler::shape(compiled)?;
    let cpu = RegisteredVerifier::host_reservation_bytes(PUBLICS, shape.height, ROOTS, ROOTS)
        .map_err(|_| Failure::new("preflight", "exact CPU lifecycle"))?;
    if cpu > budget.report.verifier_lifecycle_bytes_each {
        return Err(Failure::new("preflight", "CPU source envelope drift"));
    }
    preflight_plan(compiled, budget.limits)
}

pub(super) fn preflight_plan(compiled: &Compiled, limits: RegisteredGpuLimits)
    -> Result<RegisteredGpuFootprint, Failure> {
    let plan = RegisteredGpuMemoryPlan::new(&compiled.program, &compiled.public, &compiled.inputs.0, limits)
        .map_err(|error| diagnostics::failure(compiled, "preflight", "original GPU memory plan", error))?;
    let admitted = plan.admit().map_err(|error|
        diagnostics::failure(compiled, "preflight", "complete GPU phase admission", error))?;
    admitted.check_execution_selection().map_err(|error|
        diagnostics::failure(compiled, "preflight", "captured execution selection", error))?;
    Ok(admitted.footprint())
}

fn start() -> Result<Session, Failure> {
    attempt("session_start", || Session::start(Limits {
        host_bytes: HOST_BYTES as u64, device_bytes: DEVICE_BYTES, max_rows: MAX_ROWS,
    }).map_err(|_| Failure::new("session_start", "session creation")))
}
fn retire<T>(session: Session, result: Result<T, Failure>, proof_completed: bool)
    -> Result<(T, proving::TerminalReceipt), Failure> {
    let completed = proof_completed && result.is_ok();
    let terminal = attempt("session_retirement", || {
        let value = if completed { session.finish() } else { session.close_without_completion() }
            .map_err(|_| Failure::new("session_retirement", "session cleanup"))?;
        proving::terminal_receipt(&value, completed)
            .map_err(|_| Failure::new("session_retirement", "audited terminal receipt"))
    });
    match (result, terminal) {
        (Ok(value), Ok(terminal)) => Ok((value, terminal)),
        (Err(mut failure), Ok(terminal)) => { failure.terminal = Some(terminal); Err(failure) }
        (Ok(_), Err(mut failure)) | (Err(mut failure), Err(_)) => { failure.cleanup_failed = true; Err(failure) }
    }
}

pub(super) fn setup(compiled: Compiled, budget: &bounds::Budget,
    kind: &'static str, child_index: Option<usize>) -> Result<(PublicSource, PhaseReport), Failure> {
    let started = Instant::now();
    preflight(&compiled, budget)?;
    let shape = compiler::shape(&compiled)?;
    let request = request()?;
    let plan = RegisteredGpuMemoryPlan::new(&compiled.program, &compiled.public, &compiled.inputs.0, budget.limits)
        .map_err(|_| Failure::new("public_setup", "original plan"))?;
    let admitted = plan.admit().map_err(|_| Failure::new("public_setup", "original admission"))?;
    admitted.check_execution_selection().map_err(|_| Failure::new("public_setup", "execution selection"))?;
    let footprint = admitted.footprint();
    let session = start()?;
    let attempted = attempt("public_setup", || {
        admitted.check_execution_selection().map_err(|_| Failure::new("public_setup", "execution selection"))?;
        let setup_started = Instant::now();
        let air = MachineAir::from_shared_program(Arc::clone(admitted.program()));
        let (registered, registration) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
            air, admitted.host_budget_bytes(), request, None)
            .map_err(|_| Failure::new("public_setup", "fresh expected-public registration"))?;
        proving::validate_registration_receipt(&registration)
            .map_err(|_| Failure::new("public_setup", "native setup receipt"))?;
        let descriptor = compiler::descriptor(registered.air().program(), compiled.manifest, registered.id());
        let trusted = registered.preprocessing_cap();
        if trusted.roots().len() != ROOTS || trusted.root_capacity() != ROOTS {
            return Err(Failure::new("public_setup", "trusted cap capacity"));
        }
        let mut cap = [[Val::ZERO; 4]; ROOTS];
        cap.copy_from_slice(trusted.roots());
        let verifier = registered.verifier();
        let public_hash = public_hash_execution().map_err(|_| Failure::new("public_setup", "public hash report"))?
            .ok_or_else(|| Failure::new("public_setup", "missing fresh public hash"))?;
        let setup_ns = setup_started.elapsed().as_nanos();
        drop(registered);
        Ok((PublicSource { shape, cap, public: compiled.public, descriptor, verifier }, registration, public_hash, setup_ns))
    });
    drop(admitted);
    drop(compiled);
    let teardown_started = Instant::now();
    let ((source, registration, public_hash, setup_ns), terminal) = retire(session, attempted, false)?;
    let teardown_ns = teardown_started.elapsed().as_nanos();
    if terminal.commits == 0 || terminal.allocations == 0 {
        return Err(Failure { terminal: Some(terminal), ..Failure::new("public_setup", "no fresh setup execution") });
    }
    let descriptor = source.descriptor;
    Ok((source, PhaseReport { kind, child_index, fresh_proof: false, descriptor, footprint,
        registration, proving: None, public_hash, terminal, setup_ns, proving_ns: 0,
        teardown_ns, total_ns: started.elapsed().as_nanos() }))
}

pub(super) fn prove(compiled: Compiled, identity: compiler::Identity, expected_source: Option<&PublicSource>,
    budget: &bounds::Budget, kind: &'static str, child_index: Option<usize>)
    -> Result<(OwnedProof, PhaseReport), Failure> {
    let started = Instant::now();
    if compiler::Identity::from(&compiled)? != identity {
        return Err(Failure::new("proving", "pre-dispatch source identity drift"));
    }
    preflight(&compiled, budget)?;
    let request = request()?;
    let plan = RegisteredGpuMemoryPlan::new(&compiled.program, &compiled.public, &compiled.inputs.0, budget.limits)
        .map_err(|_| Failure::new("proving", "original plan"))?;
    let admitted = plan.admit().map_err(|_| Failure::new("proving", "original admission"))?;
    admitted.check_execution_selection().map_err(|_| Failure::new("proving", "execution selection"))?;
    let footprint = admitted.footprint();
    let session = start()?;
    let proof_started = Cell::new(false);
    let attempted = attempt("proving", || {
        admitted.check_execution_selection().map_err(|_| Failure::new("proving", "execution selection"))?;
        let setup_started = Instant::now();
        let air = MachineAir::from_shared_program(Arc::clone(admitted.program()));
        let (registered, registration) = RegisteredProgram::new_with_request_and_identity_hint_and_report(
            air, admitted.host_budget_bytes(), request, None)
            .map_err(|_| Failure::new("proving", "fresh registration"))?;
        proving::validate_registration_receipt(&registration)
            .map_err(|_| Failure::new("proving", "native registration receipt"))?;
        let descriptor = compiler::descriptor(registered.air().program(), compiled.manifest, registered.id());
        if let Some(source) = expected_source {
            if descriptor != source.descriptor || registered.preprocessing_cap().roots() != source.cap.as_slice() {
                return Err(Failure::new("proving", "independently registered child identity"));
            }
        }
        let setup_ns = setup_started.elapsed().as_nanos();
        admitted.check_execution_selection().map_err(|_| Failure::new("proving", "execution selection"))?;
        proof_started.set(true);
        let proving_started = Instant::now();
        let (proof, proving_report) = registered.into_prove_with_request_and_report(&admitted, request)
            .map_err(|_| Failure::new("proving", "fresh complete registered proof"))?;
        proving::validate_recursive_outer_proof_receipt(&proving_report)
            .map_err(|_| Failure::new("proving", "native complete proof receipt"))?;
        lattica_prover_p3::block_v2::machine::backend::retained_proof_capacity_bytes(
            &proof, artifact::MAX_RETAINED_PROOF_BYTES)
            .map_err(|_| Failure::new("proving", "retained proof capacity"))?;
        let proving_ns = proving_started.elapsed().as_nanos();
        let public_hash = public_hash_execution().map_err(|_| Failure::new("proving", "public hash report"))?
            .ok_or_else(|| Failure::new("proving", "missing fresh public hash"))?;
        Ok((OwnedProof { proof, descriptor }, registration, proving_report, public_hash, setup_ns, proving_ns))
    });
    drop(admitted);
    drop(compiled);
    let teardown_started = Instant::now();
    let ((proof, registration, proving, public_hash, setup_ns, proving_ns), terminal) =
        retire(session, attempted, true).map_err(|mut failure| { failure.proof_started = proof_started.get(); failure })?;
    let teardown_ns = teardown_started.elapsed().as_nanos();
    let descriptor = proof.descriptor;
    Ok((proof, PhaseReport { kind, child_index, fresh_proof: true, descriptor, footprint,
        registration, proving: Some(proving), public_hash, terminal, setup_ns, proving_ns,
        teardown_ns, total_ns: started.elapsed().as_nanos() }))
}

/// The CPU verifier is already source-authenticated and all GPU/source owners
/// have retired. Every negative is restored and only typed relation rejection
/// earns credit; allocation, configuration and admission failures are failures.
pub(super) fn verify_and_probe(verifier: &RegisteredVerifier, proof: &mut BatchProof<profile::Config>,
    public: [Val; PUBLICS], report: &mut Report) -> Result<(), Failure> {
    let started = Instant::now();
    attempt("cpu_verification", || verifier.verify(proof, &public)
        .map_err(|_| Failure::new("cpu_verification", "expected proof rejected")))?;
    report.cpu_verification_ns += started.elapsed().as_nanos();
    let mutations_started = Instant::now();
    for index in 0..PUBLICS {
        let mut changed = public;
        changed[index] += Val::ONE;
        attempt("public_mutation", || verification::mutation::require_rejection(verifier.verify_classified(proof, &changed))
            .map_err(|reason| Failure::new("public_mutation", reason)))?;
        report.public_mutation_rejections += 1;
    }
    let opening = proof.opened_values.instances.first_mut()
        .and_then(|instance| instance.base_opened_values.trace_local.first_mut())
        .ok_or_else(|| Failure::new("opening_mutation", "opening geometry"))?;
    let original = *opening;
    *opening += profile::Challenge::ONE;
    let rejection = attempt("opening_mutation", || verification::mutation::require_rejection(verifier.verify_classified(proof, &public))
        .map_err(|reason| Failure::new("opening_mutation", reason)));
    proof.opened_values.instances[0].base_opened_values.trace_local[0] = original;
    rejection?;
    report.opening_mutation_rejections += 1;
    attempt("restored_proof", || verifier.verify(proof, &public)
        .map_err(|_| Failure::new("restored_proof", "restored opening rejected")))?;
    report.restored_proof_acceptances += 1;
    report.mutation_checks_ns += mutations_started.elapsed().as_nanos();
    Ok(())
}
