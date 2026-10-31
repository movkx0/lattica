//! Exact private component driver. Capacity is pure source/numeric projection;
//! preissue and proof modes require the coordinator's physical/runtime guard.
//! Neither this module nor its reports admit a full RingCT workflow.
use super::refusal::Probe;
use super::root_recheck::{PreissuedRootRecheck, RootRecheckPlanReport};
use super::*;
use crate::{
    component_tree::{
        owned_shake::{
            request_merge::{
                source::{ParentSourcePlan, VerifierHeightEnvelope},
                OpenRefusal, RefusedRequest, RequestClosurePlan, ReservedRequestClosure,
                SourceRefusal,
            },
            source_shape::{Error as SourceError, SourceShapePlan},
        },
        EndpointContext,
    },
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Admission, Policy as NativePolicy, ProjectedHashxQuota, ShakeRequestPlan},
};
use p3_field::PrimeCharacteristicRing;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

mod claims;
mod transport;
mod opening;
mod interior;
use claims::driver_requirement;

type DriverResult<T> = core::result::Result<T, &'static str>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Capacity,
    Preissue,
    Gpu,
    ReturnedRefusal(Probe),
    RootCapacity,
    RootPublic,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Capacity => "capacity",
            Self::Preissue => "preissue",
            Self::Gpu => "gpu",
            Self::ReturnedRefusal(probe) => probe.name(),
            Self::RootCapacity => "root-public-capacity",
            Self::RootPublic => "root-public",
        }
    }
}

fn guard(mode: Mode) -> DriverResult<()> {
    let key = match mode {
        Mode::Capacity | Mode::RootCapacity => "LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION",
        Mode::Preissue | Mode::Gpu | Mode::ReturnedRefusal(_) | Mode::RootPublic => {
            "LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION"
        }
    };
    if std::env::var(key).as_deref() != Ok("1") {
        return Err("exact combined component guard");
    }
    if !matches!(mode, Mode::Capacity | Mode::RootCapacity) {
        for (key, expected) in [
            ("LATTICA_PROVING_POLICY", "gpu-required"),
            ("LATTICA_V2_GPU_RETAINED_TREE_STORAGE", "host"),
            ("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES", "8589934592"),
        ] {
            if std::env::var(key).as_deref() != Ok(expected) {
                return Err("immutable combined component runtime guard");
            }
        }
    }
    if matches!(mode, Mode::ReturnedRefusal(_))
        && std::env::var("LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION").as_deref() != Ok("1")
    {
        return Err("exact combined returned-refusal guard");
    }
    match mode {
        Mode::RootCapacity
            if std::env::var("LATTICA_OWNED_HASHX_ROOT_PUBLIC_SOURCE_QUALIFICATION").as_deref()
                != Ok("1") =>
        {
            return Err("exact root-public source guard");
        }
        Mode::RootPublic
            if std::env::var("LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION").as_deref()
                != Ok("1") =>
        {
            return Err("exact root-public GPU guard");
        }
        _ => {}
    }
    Ok(())
}

fn request(input: &[u8], ledger: &Ledger) -> DriverResult<ReservedShakeRequest> {
    let plan = ShakeRequestPlan::new_active_opt_validate_v1(
        [98; 32],
        7,
        0,
        input,
        137,
        NativePolicy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .map_err(|_| "combined immutable request plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "combined request admission")?;
    plan.construct(original, ledger)
        .map_err(|_| "combined request construction")
}

fn group<'request>(
    owner: &'request ReservedShakeRequest,
    context: &EndpointContext,
    ordinal: usize,
) -> DriverResult<GroupCompilePlan<'request>> {
    GroupCompilePlan::new(
        owner.request(),
        ShakeWrapperLayout::PairedV1,
        ordinal,
        context.clone(),
    )
    .map_err(|_| "combined original leaf group plan")
}

fn project(
    attempt: &mut Attempt<'_, '_, '_, '_>,
    wrong: &ReservedShakeRequest,
) -> DriverResult<()> {
    let state = &mut attempt.state;
    let before = state.ledger.snapshot();
    let foreign = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let pending = state
        .pending_native
        .as_mut()
        .ok_or("combined pending originals")?;
    if pending.project_outer_quota(wrong, &state.ledger).is_ok()
        || pending.project_outer_quota(state.request, &foreign).is_ok()
        || state.ledger.snapshot() != before
        || foreign.snapshot().current != Bytes::ZERO
    {
        return Err("combined original projection refusal");
    }
    let started = std::time::Instant::now();
    let projected = pending
        .project_outer_quota(state.request, &state.ledger)
        .map_err(|_| "combined original quota projection")?;
    let projection_ns = started.elapsed().as_nanos();
    let after = state.ledger.snapshot();
    if after.current != before.current
        || after
            .categories
            .iter()
            .zip(&before.categories)
            .any(|(a, b)| a.current != b.current)
        || projected.retained_tree_host_bytes != 8 << 30
    {
        return Err("combined original projection restoration");
    }
    let host = [
        before.current.host,
        projected.startup.host,
        projected.phase_wrappers.host,
        projected.pcs.host,
    ]
    .into_iter()
    .try_fold(0u64, |a, b| a.checked_add(b))
    .ok_or("combined host projection overflow")?;
    let device = [
        before.current.device,
        projected.startup.device,
        projected.phase_wrappers.device,
        projected.pcs.device,
    ]
    .into_iter()
    .try_fold(0u64, |a, b| a.checked_add(b))
    .ok_or("combined device projection overflow")?;
    if host > 32 << 30 || device != 8 << 30 || after.peak.host < host || after.peak.device < device
    {
        return Err("combined simultaneous projected quota");
    }
    eprintln!("ringct_hashx_sequence_capacity_complete native_proofs=0 recursive_proofs=0 original_claims_host_bytes={} startup_host_bytes={} startup_device_bytes={} phase_wrappers_host_bytes={} phase_wrappers_device_bytes={} pcs_host_bytes={} pcs_device_bytes={} simultaneous_host_bytes={} simultaneous_device_bytes={} projection_ns={} wrong_request_and_ledger_refused=true original_claims_preserved=true physical_backend_fit=false native_dispatch_started=false complete_ringct_workflow=false",
        before.current.host, projected.startup.host, projected.startup.device,
        projected.phase_wrappers.host, projected.phase_wrappers.device, projected.pcs.host,
        projected.pcs.device, host, device, projection_ns);
    Ok(())
}

fn report(component: &Component<'_, '_, '_>) -> DriverResult<()> {
    let report = &component.report;
    let root = component.root.report();
    if report.native_proofs != NATIVE
        || report.leaf_proofs != LEAVES
        || report.parent_proofs != PARENTS
        || report.workflow_admitted
        || report.elapsed_ns == 0
        || root.parent != PARENTS - 1
        || !root.source_key_authenticated
        || root.transaction_context_authenticated
        || root.workflow_admitted
        || root.cpu_heights_admitted != 18
    {
        return Err("combined accepted report authority");
    }
    for ordinal in 0..LEAVES {
        let compiled =
            report.leaf_compilation[ordinal].ok_or("combined leaf compilation report")?;
        let accepted = report.leaf_acceptance[ordinal].ok_or("combined leaf acceptance report")?;
        if report.leaf_compiler_ns[ordinal] == 0
            || compiled.ordinal != ordinal
            || compiled.padded_rows != accepted.height
            || accepted.leaf != ordinal
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
        {
            return Err("combined leaf report coverage");
        }
        eprintln!("ringct_hashx_sequence_leaf ordinal={} first_segment={} segment_count={} first_unit={} units={} active_rows={} padded_rows={} wires={} input_values={} compiler_ns={} source_cpu_verification_ns={} source_key_authenticated=true transaction_context_authenticated=false provisional=true terminal_cleanup_complete=false complete_ringct_workflow=false",
            ordinal, compiled.span.first_segment, compiled.span.segment_count,
            compiled.span.first_unit, compiled.span.units, compiled.active_rows,
            compiled.padded_rows, compiled.wires, compiled.input_values,
            report.leaf_compiler_ns[ordinal], accepted.independent_verification_ns);
    }
    for ordinal in 0..PARENTS {
        let compiled =
            report.parent_compilation[ordinal].ok_or("combined parent compilation report")?;
        let accepted =
            report.parent_acceptance[ordinal].ok_or("combined parent acceptance report")?;
        if compiled.ordinal != ordinal
            || compiled.padded_rows != accepted.height
            || accepted.parent != ordinal
            || !accepted.source_key_authenticated
            || accepted.transaction_context_authenticated
            || accepted.workflow_admitted
        {
            return Err("combined parent report coverage");
        }
        eprintln!("ringct_hashx_sequence_parent ordinal={} first_unit={} units={} level={} active_rows={} padded_rows={} wires={} input_values={} compiler_ns={} source_cpu_verification_ns={} source_key_authenticated=true transaction_context_authenticated=false provisional=true terminal_cleanup_complete=false complete_ringct_workflow=false",
            ordinal, compiled.first, compiled.count, compiled.level, compiled.active_rows,
            compiled.padded_rows, compiled.wires, compiled.witness_values,
            compiled.compiler_elapsed_ns, accepted.independent_verification_ns);
    }
    eprintln!("ringct_hashx_sequence_acceptance_scope first_unit=0 units=122 level=3 preparation_through_acceptance_ns={} source_key_authenticated=true transaction_context_authenticated=false provisional=true terminal_cleanup_complete=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        report.elapsed_ns);
    Ok(())
}

fn returned_refusal(failure: Failure, probe: Probe, ledger: &Ledger) -> DriverResult<()> {
    let requirements = attempt_requirement().map_err(|_| "returned-refusal caller shape")?;
    if !matches!(&failure.cause, Cause::Injected(actual) if *actual == probe)
        || !failure.caller.belongs_to(ledger)
        || failure.caller.requirements() != requirements
    {
        // Earlier real compiler/proof/retirement errors, wrong seams and a
        // foreign/short caller original never earn refusal qualification.
        eprintln!("ringct_hashx_sequence_returned_refusal_unqualified requested_probe={} retry=false terminal_cleanup_complete=false complete_ringct_workflow=false", probe.name());
        return Err("combined exact returned refusal was not reached");
    }
    let before = ledger.snapshot();
    eprintln!("ringct_hashx_sequence_returned_refusal_reached probe={} expected_returned_refusal=true provisional=true terminal_cleanup_complete=false compiler_reclamation_complete=false ordinary_returned_refusal_only=true asynchronous_failure_checked=false unwind_checked=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false", probe.name());
    // The original caller remains held through the final failure diagnostic.
    // Its exact release is checked while the separately admitted driver caller
    // still backs every result/report/snapshot used by this helper.
    drop(failure);
    let after = ledger.snapshot();
    let total = requirements
        .total()
        .map_err(|_| "returned-refusal caller total")?;
    if before.current.host.checked_sub(after.current.host) != Some(total.host)
        || before.current.device.checked_sub(after.current.device) != Some(total.device)
        || after.peak != before.peak
    {
        return Err("returned-refusal caller total release");
    }
    for category in Category::ALL {
        let before = before.categories[category as usize];
        let after = after.categories[category as usize];
        let expected = requirements.get(category);
        if before.current.host.checked_sub(after.current.host) != Some(expected.host)
            || before.current.device.checked_sub(after.current.device) != Some(expected.device)
            || after.peak != before.peak
        {
            return Err("returned-refusal caller category release");
        }
    }
    Ok(())
}

fn root_public_report(report: RootPublicRecheckReport) -> DriverResult<()> {
    if report.cpu_heights != 18
        || report.positive_checks != 2
        || report.public_probes != 46
        || report.positive_verification_ns == 0
        || report.mutation_verification_ns == 0
        || report.elapsed_ns == 0
    {
        return Err("root-public actual report scope");
    }
    // The independent driver caller still backs this copied report after the
    // consumed Component/recheck ended. It does not survive exercise's caller.
    eprintln!("ringct_hashx_root_public_recheck_scope cpu_heights={} positive_checks={} public_probes={} positive_verification_ns={} mutation_verification_ns={} root_recheck_ns={} provisional=true terminal_cleanup_complete=false retained_output_immutable=true source_key_authenticated=true transaction_context_authenticated=false raw_proof_mutation_checks_complete=false interior_mutation_checks_complete=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        report.cpu_heights, report.positive_checks, report.public_probes,
        report.positive_verification_ns, report.mutation_verification_ns, report.elapsed_ns);
    Ok(())
}

/// # Safety
/// Preissue/Gpu preserve the exact coordinator source/binary/environment,
/// exclusive physical GPU and process/memory guard through final destruction.
unsafe fn exercise(mode: Mode, ledger: &Ledger) -> DriverResult<()> {
    let caller = ledger
        .admit_phase(driver_requirement()?)
        .map_err(|_| "combined driver admission")?;
    guard(mode)?;
    let input = [7u8; 16_416];
    let mut expected_output = [0u8; 137];
    let mut shake = Shake256::default();
    shake.update(&input);
    shake.finalize_xof().read(&mut expected_output);
    let context = EndpointContext {
        context: [99; 32],
        statement: [Val::from_u64(19); 4],
        input: crate::shake_air::commit_bytes(crate::shake_air::SHAKE_INPUT_DOMAIN, &input),
        output: crate::shake_air::commit_bytes(
            crate::shake_air::SHAKE_OUTPUT_DOMAIN,
            &expected_output,
        ),
    };
    let owner = request(&input, ledger)?;
    let wrong = request(&input, ledger)?;
    let groups: [GroupCompilePlan<'_>; LEAVES] = [
        group(&owner, &context, 0)?,
        group(&owner, &context, 1)?,
        group(&owner, &context, 2)?,
        group(&owner, &context, 3)?,
        group(&owner, &context, 4)?,
    ];
    let plan = RequestClosurePlan::new(&owner, context);
    let original = ledger
        .admit_phase(plan.requirements().map_err(|_| "combined closure source")?)
        .map_err(|_| "combined closure admission")?;
    let mut closure = plan
        .open(original, ledger)
        .map_err(|_| "combined closure construction")?;
    for group in &groups {
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, ledger)
            .map_err(|_| "combined leaf source plan")?;
        let original = ledger
            .admit_phase(plan.requirements())
            .map_err(|_| "combined leaf source admission")?;
        let source = plan
            .inspect(original, ledger)
            .map_err(|_| "combined leaf source inspection")?;
        closure = closure
            .retain_source(group, source, ledger)
            .map_err(|_| "combined original leaf retention")?;
    }
    let plan =
        ParentSourcePlan::new(&closure, ledger).map_err(|_| "combined parent source plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "combined parent source admission")?;
    let source = plan
        .inspect(original, ledger)
        .map_err(|_| "combined parent source inspection")?;
    // The additional verifier/caller/header/probe reservation exists before
    // Attempt can construct even its pending original native-capacity owner.
    let mut root_recheck = if matches!(mode, Mode::RootCapacity | Mode::RootPublic) {
        Some(
            PreissuedRootRecheck::reserve_before_native(&source, ledger)
                .map_err(|_| "root-public original preclaim")?,
        )
    } else {
        None
    };
    if let Some(recheck) = &root_recheck {
        let report = recheck
            .plan_report(ledger)
            .map_err(|_| "root-public claim report")?;
        eprintln!("ringct_hashx_root_public_recheck_claims cpu_heights={} verifier_host_bytes={} caller_host_bytes={} total_host_bytes={} planned_public_probes={} mode={} actual_root_public_probes=0 native_dispatch_started=false complete_ringct_workflow=false",
            report.cpu_heights, report.verifier_host_bytes, report.caller_host_bytes,
            report.total_host_bytes, report.planned_public_probes, mode.name());
    }
    let mut attempt = Some(
        Attempt::reserve_before_native(&source, groups.each_ref(), ledger)
            .map_err(|_| "combined all original preclaims")?,
    );
    let claimed = ledger.snapshot();
    eprintln!("ringct_hashx_sequence_source_claims native_outputs=10 native_attachments=10 retained_leaf_sources=5 retained_parent_sources=4 original_compiler_bank=1 leaf_output_claims=5 parent_output_claims=4 source_acceptance_claims=9 original_outer_sequence=true host_bytes={} device_bytes={} mode={} native_dispatch_started=false complete_ringct_workflow=false",
        claimed.current.host, claimed.current.device, mode.name());
    match mode {
        Mode::Capacity | Mode::RootCapacity => {
            project(attempt.as_mut().ok_or("combined original attempt")?, &wrong)?
        }
        Mode::Preissue => {
            let attempt = attempt.as_mut().ok_or("combined original attempt")?;
            unsafe { attempt.state.prepare() }.map_err(|_| "combined physical source preissue")?;
            let admitted = ledger.snapshot();
            if admitted.current.host > 32 << 30
                || admitted.current.device != 8 << 30
                || attempt.state.next != 0
                || attempt.state.first.is_none()
                || attempt.state.prepared_native.is_none()
                || attempt.state.pending_native.is_some()
                || attempt.state.ready_parents.iter().any(Option::is_none)
                || attempt.state.report.native_proofs != 0
                || attempt.state.report.leaf_proofs != 0
                || attempt.state.report.parent_proofs != 0
            {
                return Err("combined original preissue closure");
            }
            eprintln!("ringct_hashx_sequence_preissue_complete native_proofs=0 recursive_proofs=0 outer_source_backends=9 original_successor_backends=8 host_bytes={} device_bytes={} source_backend_preissue_complete=true actual_proving_fit=false native_dispatch_started=false complete_ringct_workflow=false",
                admitted.current.host, admitted.current.device);
        }
        Mode::Gpu | Mode::RootPublic => {
            let component = match unsafe {
                attempt.take().ok_or("combined original attempt")?.run()
            } {
                Ok(component) => component,
                Err(failure) => {
                    let reason = match &failure.cause {
                        Cause::Production(_) => "combined native/outer/source production",
                        Cause::Compiler(bank::Failure::Admission(_)) => {
                            "combined compiler bank admission"
                        }
                        Cause::Compiler(bank::Failure::Compilation { .. }) => {
                            "combined native verifier/compiler"
                        }
                        Cause::Injected(_) => "unexpected combined returned-refusal trip",
                    };
                    // Failure's bounded report/caller originals survive through
                    // this final classification, then die before terminal audit.
                    eprintln!("ringct_hashx_sequence_failure phase={reason:?} retry=false complete_ringct_workflow=false");
                    drop(failure);
                    return Err(reason);
                }
            };
            report(&component)?;
            if mode == Mode::RootPublic {
                // Only this consuming Component method pairs its own accepted
                // root with its own actual Parent3 originals. A separate root
                // or continuation is never accepted by the driver.
                let report = component
                    .recheck_root(
                        root_recheck.take().ok_or("root-public original owner")?,
                        ledger,
                    )
                    .map_err(|_| "root-public actual numerical recheck")?;
                root_public_report(report)?;
            } else {
                drop(component);
            }
        }
        Mode::ReturnedRefusal(probe) => {
            let selected = attempt
                .take()
                .ok_or("combined original refusal attempt")?
                .with_probe(probe)
                .map_err(|_| "combined initial-only refusal selection")?;
            match unsafe { selected.run() } {
                Err(failure) => returned_refusal(failure, probe, ledger)?,
                Ok(component) => {
                    // A missed seam cannot earn either component success or
                    // injected-refusal success. Destroy the whole component.
                    drop(component);
                    return Err("combined returned-refusal seam was missed");
                }
            }
        }
    }
    drop(attempt);
    drop(root_recheck);
    drop(source);
    let refused = match closure.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    if refused.report().retained_original_leaf_sources != LEAVES {
        return Err("combined request remains closed");
    }
    drop(refused);
    drop(groups);
    drop(wrong);
    drop(owner);
    drop(caller);
    Ok(())
}

/// # Safety
/// Same immutable/exclusive guard as exercise; the timer ends only after all
/// component/source/driver owners have actually been destroyed, on every path.
unsafe fn run(mode: Mode) -> DriverResult<()> {
    let started = std::time::Instant::now();
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let result = unsafe { exercise(mode, &ledger) };
    let terminal = ledger.snapshot();
    if terminal.current != Bytes::ZERO
        || terminal.categories.iter().any(|c| c.current != Bytes::ZERO)
    {
        return Err("combined terminal original quota");
    }
    let elapsed = started.elapsed().as_nanos();
    if result.is_ok() && mode == Mode::RootPublic {
        eprintln!("ringct_hashx_root_public_recheck_complete native_proofs=10 recursive_proofs=9 compiler_reclamations=9 first_unit=0 units=122 level=3 cpu_heights=18 positive_checks=2 public_probes=46 component_through_destruction_ns={} root_public_recheck_complete=true retained_output_immutable=true source_key_authenticated=true transaction_context_authenticated=false original_quota_released=true owner_quota_cleanup_complete=true process_engine_device_audit_complete=false raw_proof_mutation_checks_complete=false interior_mutation_checks_complete=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false", elapsed);
    }
    // Aggregate success exists only after the entire component/source/caller
    // scope returned successfully and all original categories are zero. A
    // destructor abort or returned cleanup failure can never print this line.
    if result.is_ok() && mode == Mode::Gpu {
        eprintln!("ringct_hashx_sequence_complete native_proofs=10 recursive_proofs=9 recursive_leaf_proofs=5 recursive_parent_proofs=4 compiler_reclamations=9 first_unit=0 units=122 level=3 component_through_destruction_ns={} original_quota_released=true source_key_authenticated=true transaction_context_authenticated=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
            elapsed);
    }
    if let Mode::ReturnedRefusal(probe) = mode {
        if result.is_ok() {
            let (native, recursive, installed) = probe.receipt_counts();
            eprintln!("ringct_hashx_sequence_returned_refusal_complete probe={} native_proofs_before_refusal={} recursive_proofs_before_refusal={} installed_leaf_outputs_before_refusal={} compiler_reclamations=0 component_through_destruction_ns={} expected_returned_refusal=true original_quota_released=true owner_quota_cleanup_complete=true process_engine_device_audit_complete=false component_success=false ordinary_returned_refusal_only=true asynchronous_failure_checked=false unwind_checked=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
                probe.name(), native, recursive, installed, elapsed);
        }
    }
    let component_success =
        result.is_ok() && !matches!(mode, Mode::ReturnedRefusal(_) | Mode::RootCapacity);
    eprintln!("ringct_hashx_sequence_terminal original_quota_released=true current_host_bytes={} current_device_bytes={} peak_host_bytes={} peak_device_bytes={} component_through_destruction_ns={} component_success={} mode={} mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        terminal.current.host, terminal.current.device, terminal.peak.host, terminal.peak.device,
        elapsed, component_success, mode.name());
    result
}

#[test]
#[ignore = "exact combined HashX source/quota projection guard; no backend, device or proofs"]
fn cpu_original_hashx_sequence_capacity() {
    unsafe { run(Mode::Capacity) }.unwrap();
}

#[test]
#[ignore = "exact coordinator combined HashX physical-source guard; preissue only, zero proofs"]
fn gpu_original_hashx_sequence_preissue() {
    unsafe { run(Mode::Preissue) }.unwrap();
}

#[test]
#[ignore = "exact coordinator combined HashX source/binary/environment/device guard; component only"]
fn gpu_original_hashx_sequence_source_authenticated() {
    unsafe { run(Mode::Gpu) }.unwrap();
}

#[test]
#[ignore = "exact coordinator combined HashX/refusal guard; ordinary returned error, zero proofs"]
fn gpu_original_hashx_sequence_refusal_after_preissue() {
    unsafe { run(Mode::ReturnedRefusal(Probe::AfterPreissue)) }.unwrap();
}

#[test]
#[ignore = "exact coordinator combined HashX/refusal guard; 10 native proofs before returned error"]
fn gpu_original_hashx_sequence_refusal_before_first_start() {
    unsafe { run(Mode::ReturnedRefusal(Probe::BeforeFirstStart)) }.unwrap();
}

#[test]
#[ignore = "exact coordinator combined HashX/refusal guard; real first producer retires before error"]
fn gpu_original_hashx_sequence_refusal_after_first_producer() {
    unsafe { run(Mode::ReturnedRefusal(Probe::AfterFirstProducer)) }.unwrap();
}

#[test]
#[ignore = "exact coordinator combined HashX/refusal guard; real first accepted output retained before error"]
fn gpu_original_hashx_sequence_refusal_after_first_acceptance() {
    unsafe { run(Mode::ReturnedRefusal(Probe::AfterFirstAcceptance)) }.unwrap();
}

#[test]
#[ignore = "exact root-public source/quota guard; no backend, device, proof or mutation execution"]
fn cpu_original_hashx_sequence_root_public_capacity() {
    unsafe { run(Mode::RootCapacity) }.unwrap();
}

#[test]
#[ignore = "exact coordinator root-public source/binary/environment/device guard; actual private root only"]
fn gpu_original_hashx_sequence_root_public_recheck() {
    unsafe { run(Mode::RootPublic) }.unwrap();
}

#[test]
fn combined_driver_caller_claim_is_exact_and_releases() {
    let requirements = driver_requirement().unwrap();
    let bytes = requirements.total().unwrap();
    assert_eq!(bytes.device, 0);
    for (host, fits) in [(bytes.host, true), (bytes.host - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let original = ledger.admit_phase(requirements);
        assert_eq!(original.is_ok(), fits);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
