//! Actual one-shot backend producer under the test-only ownership path.
//! Preclaims precede runtime startup; the same runtime token survives cleanup.
//! The result is a verified component output, not transaction acceptance.
use super::{output, source_token, OwnedCompiledShake, PlanningLease, MAX_ROWS};
use crate::{
    component_tree::{NodeKey, NodeProof, HEADER},
    execution::retained_resources::{Bytes, Category, Ledger, Reservation},
    graph_crypto::ReservedShakeRequest,
    opencl::{Limits, PendingRuntime},
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::machine::{
        backend::RegisteredProgram, MachineAir, OuterBackendAdmission, OuterBackendPlan,
        RegisteredGpuLimits,
    },
    proving::{
        proof_storage::outer_ocl::FixedOuterOclStorage, Backend, CoverageScope,
        FixedProofReportStorage, Observation, Policy, Profile, Report, Request, Stage,
        StageCapability,
    },
};
use std::sync::Arc;

#[cfg(feature = "owned-native-shake")]
mod preissued;

mod refusal;
use refusal::{AdmissionPhase, AdmissionRefusal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::component_tree::owned_shake) enum Error {
    Authority,
    Shape,
    Admission(AdmissionRefusal),
    Runtime,
    Setup,
    Proof,
    Report,
    Output(output::Error),
}

/// This type owns the pending runtime reservation before deriving remaining
/// backend allowance. It can execute its one exact compiled source once, with
/// no caller callback, proof/key, numeric memory allowance or policy argument.
pub(in crate::component_tree::owned_shake) struct PreparedOuter<'compiled, 'owner, 'request> {
    compiled: &'compiled OwnedCompiledShake<'request>,
    request: &'owner ReservedShakeRequest,
    output: output::OutputClaim<'compiled, 'owner, 'request>,
    backend: OuterBackendAdmission<'compiled>,
    // Drop unstarted runtime before releasing any enclosing phase tokens.
    runtime: PendingRuntime,
    ledger: Ledger,
    backend_token: Reservation,
    wrappers: Reservation,
    reports: Reservation,
    planning: PlanningLease,
}

/// Shared by both constructors: payload publication remains covered by the
/// fixed report bound, while every added forwarding/result and streaming
/// writer header is charged explicitly. No stack-slot elision or unused
/// planning/publication space is credited to these owners.
pub(in crate::component_tree::owned_shake) fn fixed_producer_report_host_bytes() -> Result<usize, Error> {
    let mut host = FixedProofReportStorage::fixed()
        .map_err(|_| Error::Report)?
        .required_host_bytes()
        .checked_mul(2)
        .ok_or(Error::Report)?;
    for (count, bytes) in [
        // Original, forwarding entry, inner producer and moved argument.
        (4, size_of::<PreparedOuter<'static, 'static, 'static>>()),
        (
            4,
            size_of::<Result<output::RetainedNodeOutput<'static>, Error>>(),
        ),
        (2, size_of::<ReportView<'static>>()),
        (2, size_of::<Request>()),
        (2, size_of::<&Report>()),
        // to_writer streams to the locked stderr directly; there is no
        // intermediate String/Value. Its concrete wrappers remain additive.
        (2, size_of::<std::io::Stderr>()),
        (2, size_of::<std::io::StderrLock<'static>>()),
        (
            2,
            size_of::<serde_json::Serializer<std::io::StderrLock<'static>>>(),
        ),
        (4, size_of::<Result<(), serde_json::Error>>()),
        (2, size_of::<std::io::Result<()>>()),
        (2, size_of::<Result<(), Error>>()),
        (4, size_of::<std::fmt::Arguments<'static>>()),
        (4, size_of::<bool>()),
    ] {
        host = bytes
            .checked_mul(count)
            .and_then(|bytes| host.checked_add(bytes))
            .ok_or_else(|| AdmissionRefusal::phase(AdmissionPhase::ReportSize))?;
    }
    Ok(host)
}

impl<'compiled, 'owner, 'request> PreparedOuter<'compiled, 'owner, 'request> {
    /// # Safety
    /// The serialized process guard must preserve the runtime environment
    /// from this preflight through produce (or destruction without dispatch).
    pub(in crate::component_tree::owned_shake) unsafe fn new(
        compiled: &'compiled OwnedCompiledShake<'request>,
        request: &'owner ReservedShakeRequest,
        ledger: &Ledger,
    ) -> Result<Self, Error> {
        if !request.belongs_to(ledger)
            || !compiled.is_for(request.request())
            || !compiled.report.belongs_to(ledger)
        {
            return Err(Error::Authority);
        }
        let planning = PlanningLease::reserve(ledger)
            .map_err(|_| AdmissionRefusal::phase(AdmissionPhase::Planning))?;
        let program_token = source_token(&compiled._program, Category::SymbolicCompiler, ledger)
            .map_err(|_| Error::Authority)?;
        let input_token = source_token(&compiled._inputs, Category::CompilerInputs, ledger)
            .map_err(|_| Error::Authority)?;
        let node = &compiled.compiled;
        let summary = compiled.summary;
        if HEADER + 8 != 46
            || node.program.public_values() != 46
            || node.public.len() != 46
            || node.witness.len() != node.program.witness_values()
            || summary.padded_rows != node.program.height()
            || summary.active_rows != node.program.active_rows()
            || summary.wires != node.program.wire_count()
            || summary.input_values != node.program.witness_values()
            || !(1..=2).contains(&summary.span.segment_count)
            || summary.independent_native_verifications != summary.span.segment_count
            || !(8..=MAX_ROWS).contains(&node.program.height())
            || !node.program.height().is_power_of_two()
        {
            return Err(Error::Shape);
        }
        let input_bytes = node
            .public
            .capacity()
            .checked_add(node.witness.capacity())
            .and_then(|count| count.checked_mul(size_of::<super::super::Val>()))
            .ok_or(Error::Shape)? as u64;
        if node
            .program
            .retained_host_bytes()
            .map_err(|_| Error::Shape)? as u64
            > program_token
            || input_bytes > input_token
        {
            return Err(Error::Shape);
        }
        let report_bytes = fixed_producer_report_host_bytes()?;
        let reports = ledger
            .reserve(
                Category::Report,
                Bytes {
                    host: report_bytes as u64,
                    device: 0,
                },
            )
            .map_err(|_| AdmissionRefusal::phase(AdmissionPhase::ReportReservation))?;
        let output =
            output::OutputClaim::reserve(compiled, request, ledger).map_err(Error::Output)?;
        // Startup's wrapper allowance covers raw kernels only. Claim every
        // additional outer wrapper and specialized Program/source before any
        // runtime, planner or backend can construct it. No overlap is credited.
        let wrappers = reserve_ocl_wrappers(ledger)?;
        let mut runtime = PendingRuntime::reserve_outer_host_v1(
            ledger,
            Limits {
                host_bytes: 32 << 30,
                device_bytes: 8 << 30,
                max_rows: MAX_ROWS,
            },
        )
        .map_err(|_| Error::Runtime)?;
        if !runtime.belongs_to(ledger) {
            return Err(Error::Authority);
        }
        let startup_device = runtime.reserved_bytes().device;
        let startup_tree_host = runtime.reserved_tree_host_bytes();
        // SAFETY: inherited from the caller; bounded capture and physical
        // selection precede every core planner that may inspect metadata.
        let preflight = unsafe { runtime.preflight() }.map_err(|_| Error::Runtime)?;
        let limits = RegisteredGpuLimits::new(32 << 30, 8 << 30, 4 << 30, MAX_ROWS)
            .map_err(|reason| AdmissionRefusal::reason(AdmissionPhase::Limits, &reason))?;
        let native = native_after_original_tree_claim(
            ledger.remaining().host,
            limits.retained_tree_host_bytes(),
            startup_tree_host,
        )?;
        let plan =
            OuterBackendPlan::new(&node.program, &node.public, &node.witness, limits, native)
                .map_err(|reason| AdmissionRefusal::reason(AdmissionPhase::BackendPlan, &reason))?;
        let footprint = plan.footprint();
        if !footprint.backend_phase_bounds_complete {
            return Err(AdmissionRefusal::phase(AdmissionPhase::IncompletePhaseBounds).into());
        }
        // The backend's inclusive device peak contains the same Engine
        // CONSTANT_BYTES + staging allocation in retained_query_base_bytes.
        // PendingRuntime already owns exactly that startup backing. Subtract
        // only this concrete overlap; its original token moves into Session
        // and remains live through the complete backend cleanup.
        let backend_device = footprint
            .device_phase_peak_bytes
            .checked_sub(startup_device)
            .ok_or_else(|| AdmissionRefusal::phase(AdmissionPhase::StartupOverlap))?;
        // The startup owner now retains exactly the full host-tree payload.
        // Its private profile getter, original ledger identity and captured
        // quota were checked before this plan. Remove that overlap once from
        // the inclusive backend scope; no runtime wrapper receives credit.
        let backend_host = footprint
            .backend_scope_host_bytes
            .checked_sub(startup_tree_host)
            .filter(|&bytes| bytes > 0)
            .ok_or_else(|| AdmissionRefusal::phase(AdmissionPhase::StartupOverlap))?;
        let backend_token = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: backend_host,
                    device: backend_device,
                },
            )
            .map_err(|_| AdmissionRefusal::phase(AdmissionPhase::BackendReservation))?;
        // This is before PendingRuntime::start; the idle-engine check cannot
        // be deferred until after registration or proof execution has started.
        let backend = plan.admit().map_err(|reason| {
            AdmissionRefusal::reason(AdmissionPhase::BackendAdmission, &reason)
        })?;
        drop(preflight);
        Ok(Self {
            compiled,
            request,
            output,
            backend,
            runtime,
            ledger: ledger.clone(),
            backend_token,
            wrappers,
            reports,
            planning,
        })
    }

    /// # Safety
    /// The process guard must keep the runtime environment immutable and
    /// serialize GPU work through startup, proving and shutdown. This is the
    /// same precondition as PendingRuntime::start, not an inferred capability.
    pub(in crate::component_tree::owned_shake) unsafe fn produce(
        self,
    ) -> Result<output::RetainedNodeOutput<'owner>, Error> {
        // SAFETY: inherited from this entry's documented process contract.
        unsafe { self.produce_inner(false) }
    }

    /// Same original closed producer, retaining real stage receipts in the
    /// coordinator's bounded log for the explicit continuation qualifier.
    /// # Safety
    /// The same immutable/exclusive process contract as produce is required.
    unsafe fn produce_reported(self) -> Result<output::RetainedNodeOutput<'owner>, Error> {
        // SAFETY: identical caller obligation, no policy or backend change.
        unsafe { self.produce_inner(true) }
    }

    unsafe fn produce_inner(
        self,
        emit_receipts: bool,
    ) -> Result<output::RetainedNodeOutput<'owner>, Error> {
        if !self.runtime.belongs_to(&self.ledger)
            || !self.backend_token.belongs_to(&self.ledger)
            || !self.wrappers.belongs_to(&self.ledger)
            || !self.reports.belongs_to(&self.ledger)
            || !self.planning.belongs_to(&self.ledger)
            || !self.request.belongs_to(&self.ledger)
            || !self.compiled.is_for(self.request.request())
        {
            return Err(Error::Authority);
        }
        // SAFETY: inherited explicitly from this fixed producer's caller.
        let session = unsafe { self.runtime.start() }.map_err(|_| Error::Runtime)?;
        let runtime_guard = session
            .check_reserved_runtime(&self.ledger)
            .map_err(|_| Error::Runtime)?;
        self.backend
            .check_execution_selection()
            .map_err(|_| Error::Runtime)?;
        let request = Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        };
        let node = &self.compiled.compiled;
        let (registered, report) =
            RegisteredProgram::new_with_cpu_identity_and_report(
                MachineAir::from_shared_program(Arc::clone(&node.program)),
                self.backend.host_budget_bytes(),
                request,
            )
            .map_err(|_| Error::Setup)?;
        validate_report(&report.preprocessing, CoverageScope::Preprocessing)?;
        validate_report(&report.identity, CoverageScope::Operation)?;
        if emit_receipts {
            emit_receipt(&report.preprocessing)?;
            emit_receipt(&report.identity)?;
        }
        let setup_elapsed_ns = report.preprocessing.elapsed_ns;
        drop(report);
        // Independent metadata and copied cap are constructed only after their
        // exact output/verification reservation, and before registration moves.
        let key = NodeKey {
            spec: node.spec.clone(),
            height: node.program.height(),
            cap: registered.preprocessing_cap().roots().to_vec(),
            verifier: Arc::new(registered.verifier()),
        };
        let (proof, report) = registered
            .into_prove_outer_with_request_and_report(&self.backend, request)
            .map_err(|_| Error::Proof)?;
        validate_report(&report, CoverageScope::RegisteredProof)?;
        if emit_receipts {
            emit_receipt(&report)?;
        }
        let proving_elapsed_ns = report.elapsed_ns;
        drop(report);
        let output = self
            .output
            .verify_and_retain(
                key,
                NodeProof {
                    public: node.public.clone(),
                    proof,
                },
                setup_elapsed_ns,
                proving_elapsed_ns,
            )
            .map_err(Error::Output)?;
        // Session's reserved exact-epoch shutdown runs while backend/report
        // tokens remain alive. Uncertain cleanup aborts the worker, never
        // releasing this output as a successful proof.
        drop(runtime_guard);
        drop(session);
        Ok(output)
    }
}

pub(in crate::component_tree::owned_shake) fn emit_receipt(report: &Report) -> Result<(), Error> {
    eprint!("proving_stage_report ");
    serde_json::to_writer(std::io::stderr().lock(), report).map_err(|_| Error::Report)?;
    eprintln!();
    Ok(())
}

fn native_after_original_tree_claim(
    remaining_host: u64,
    captured_tree_quota: u64,
    original_tree_claim: u64,
) -> Result<u64, Error> {
    if original_tree_claim != 8 << 30 || captured_tree_quota != original_tree_claim {
        return Err(AdmissionRefusal::phase(AdmissionPhase::TreeOwner).into());
    }
    // Restore only the exact original claim for this partition calculation;
    // the token remains live. Subtract the same full quota as the old schedule.
    // This is not a public constructor or caller-selected overlap allowance.
    remaining_host
        .checked_add(original_tree_claim)
        .and_then(|bytes| bytes.checked_sub(captured_tree_quota))
        .filter(|&bytes| bytes > 0)
        .map(|bytes| bytes.min(24 << 30))
        .ok_or_else(|| AdmissionRefusal::phase(AdmissionPhase::NativePartition).into())
}

fn reserve_ocl_wrappers(ledger: &Ledger) -> Result<Reservation, Error> {
    let census = FixedOuterOclStorage::fixed()
        .map_err(|_| AdmissionRefusal::phase(AdmissionPhase::WrapperCensus))?;
    ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: census.required_host_bytes() as u64,
                device: 0,
            },
        )
        .map_err(|_| AdmissionRefusal::phase(AdmissionPhase::WrapperReservation).into())
}

fn required(scope: CoverageScope, stage: Stage) -> bool {
    match scope {
        CoverageScope::Preprocessing => matches!(
            stage,
            Stage::Preprocessing | Stage::Randomness | Stage::Transform | Stage::Commitment
        ),
        CoverageScope::RegisteredProof => {
            Stage::ARITHMETIC.contains(&stage) && stage != Stage::PublicValues
        }
        _ => false,
    }
}

// A borrowed view of the real returned report. It cannot be converted into a
// Run, capability, proof or admission; keeping it private allows mutation tests
// without widening core Capabilities construction or its visibility.
struct ReportView<'a> {
    schema: &'a str,
    entry_point: &'a str,
    policy: Policy,
    profile: Profile,
    max_log_fri_arity: u8,
    scope: CoverageScope,
    stages: &'a [StageCapability],
    succeeded: bool,
    stage_coverage_complete: bool,
    completion_rejected: bool,
    observation_errors: u64,
    observations: &'a [Observation],
    component_count: usize,
}

pub(in crate::component_tree::owned_shake) fn validate_report(report: &Report, scope: CoverageScope) -> Result<(), Error> {
    validate_view(
        ReportView {
            schema: report.schema,
            entry_point: report.entry_point,
            policy: report.policy,
            profile: report.capabilities.profile(),
            max_log_fri_arity: report.capabilities.max_log_fri_arity(),
            scope: report.capabilities.scope(),
            stages: report.capabilities.stages(),
            succeeded: report.succeeded,
            stage_coverage_complete: report.stage_coverage_complete,
            completion_rejected: report.completion_rejected,
            observation_errors: report.observation_errors,
            observations: &report.observations,
            component_count: report.components.len(),
        },
        scope,
    )
}

fn validate_view(report: ReportView<'_>, scope: CoverageScope) -> Result<(), Error> {
    let entry = match scope {
        CoverageScope::Preprocessing => "block_v2_preprocessing",
        CoverageScope::RegisteredProof => "block_v2_registered_program",
        _ => return Err(Error::Report),
    };
    if report.schema != "lattica-proving-stages-v1"
        || report.entry_point != entry
        || report.policy != Policy::GpuRequired
        || report.profile != Profile::BlockV2Cubic
        || report.max_log_fri_arity != 1
        || report.scope != scope
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || report.component_count != 0
    {
        return Err(Error::Report);
    }
    let expected = Stage::ARITHMETIC
        .into_iter()
        .filter(|&stage| required(scope, stage));
    if report.stages.len() != expected.clone().count() {
        return Err(Error::Report);
    }
    for stage in expected {
        if report
            .stages
            .iter()
            .filter(|cap| cap.stage == stage && cap.backend == Backend::OpenCl)
            .count()
            != 1
            || report
                .observations
                .iter()
                .filter(|observed| observed.stage == stage)
                .count()
                != 1
            || !report.observations.iter().any(|observed| {
                observed.stage == stage
                    && observed.backend == Backend::OpenCl
                    && observed.calls == observed.completed_calls
                    && observed.completed_calls > 0
                    && observed.device_calls > 0
                    && observed.device_calls <= observed.completed_calls
            })
        {
            return Err(Error::Report);
        }
    }
    if report
        .observations
        .iter()
        .filter(|observed| observed.stage == Stage::Serialization)
        .count()
        > 1
        || report.observations.iter().any(|observed| {
            observed.calls == 0
                || observed.calls != observed.completed_calls
                || (observed.stage == Stage::Serialization
                    && (observed.backend != Backend::Cpu || observed.device_calls != 0))
                || (observed.stage != Stage::Serialization && !required(scope, observed.stage))
        })
    {
        return Err(Error::Report);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use preissued::{RetiredLeafAttempt, RetiredOuterOriginals};

#[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(in crate::component_tree::owned_shake) use preissued::{FutureHashxLeaf, PreissuedHashxLeaf, PreparedHashxLeaf, RetiredHashxLeafAttempt, RetiredHashxLeafOriginals};
