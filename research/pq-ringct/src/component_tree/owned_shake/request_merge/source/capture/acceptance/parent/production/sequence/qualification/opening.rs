//! Inactive exact opt-in driver for one actual original-root opening probe.
//! Existing same-Attempt source/project/report helpers and B066's closed action
//! are reused. No ancestor, wrapper or production acceptance is changed here.
//! The final fixed observer remains separately process-audited harness scope.
use super::*;
use super::super::root_recheck::{
    PreissuedRootOpening, RetainedRootOpeningReport, RootOpeningMeasurements,
};

mod claims;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpeningMode {
    Capacity,
    Gpu,
}

impl OpeningMode {
    fn name(self) -> &'static str {
        match self {
            Self::Capacity => "root-opening-capacity",
            Self::Gpu => "root-opening",
        }
    }
}

// These fixed terminal fields do not contain a workload owner, measurement
// report, packet, proof, key, runtime continuation or dynamic error string.
// Their post-workload storage is not backed by any released worker claim.
struct TerminalObservation {
    result: DriverResult<()>,
    terminal: Snapshot,
    elapsed_ns: u128,
    mode: OpeningMode,
    observer_fixed_host_bytes: u64,
}

fn opening_guard(mode: OpeningMode) -> DriverResult<()> {
    let (base, key) = match mode {
        OpeningMode::Capacity => (
            super::Mode::Capacity,
            "LATTICA_OWNED_HASHX_ROOT_OPENING_SOURCE_QUALIFICATION",
        ),
        OpeningMode::Gpu => (
            super::Mode::Gpu,
            "LATTICA_OWNED_HASHX_ROOT_OPENING_QUALIFICATION",
        ),
    };
    // Preserve the existing immutable sequence, GpuRequired and host-retained
    // tree guards. This separate opt-in never upgrades another selected mode.
    super::guard(base)?;
    if std::env::var(key).as_deref() != Ok("1") {
        return Err("exact root-opening qualification guard");
    }
    Ok(())
}

fn opening_report(
    owner: &RetainedRootOpeningReport<'_, '_, '_>,
    ledger: &Ledger,
) -> DriverResult<()> {
    // Borrow under both complete B066 originals and this driver's original
    // caller. No detached report, proof/key borrow or mutable callback escapes.
    let measured = owner
        .report(ledger)
        .map_err(|_| "root-opening retained measurement authority")?;
    let subintervals = measured.positive_verification_ns
        .checked_add(measured.mutation_verification_ns)
        .ok_or("root-opening subinterval overflow")?;
    if measured.cpu_heights != 18
        || measured.positive_checks != 2
        || measured.opening_probes != 1
        || !measured.retained_output_restored
        || measured.positive_verification_ns == 0
        || measured.mutation_verification_ns == 0
        || measured.elapsed_ns == 0
        || subintervals > measured.elapsed_ns
    {
        return Err("root-opening actual report scope");
    }
    // B066 restores the changed word before classifying the negative result;
    // only RelationRejected earns credit, followed by a second positive check.
    // This is one opening probe, not complete raw/interior mutation coverage.
    eprintln!("ringct_hashx_root_opening_scope cpu_heights={} numerical_positive_checks={} typed_opening_relation_rejections={} positive_verification_ns={} mutation_verification_ns={} opening_action_ns={} provisional=true terminal_cleanup_complete=false opening_scope=single-root-first-local-permutation-opening retained_output_restored=true source_key_authenticated=true transaction_context_authenticated=false raw_proof_mutation_checks_complete=false interior_mutation_checks_complete=false mutation_checks_complete=false disk_artifact_roundtrip_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        measured.cpu_heights, measured.positive_checks, measured.opening_probes,
        measured.positive_verification_ns, measured.mutation_verification_ns,
        measured.elapsed_ns);
    Ok(())
}

/// # Safety
/// The exact coordinator source/binary/environment/device and exclusive
/// process/memory guard must remain valid through final workload destruction.
unsafe fn exercise(mode: OpeningMode, ledger: &Ledger) -> DriverResult<()> {
    let caller = ledger
        .admit_phase(claims::driver_requirement()?)
        .map_err(|_| "root-opening complete driver admission")?;
    opening_guard(mode)?;
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
        .admit_phase(plan.requirements().map_err(|_| "root-opening closure source")?)
        .map_err(|_| "root-opening closure admission")?;
    let mut closure = plan
        .open(original, ledger)
        .map_err(|_| "root-opening closure construction")?;
    for group in &groups {
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, ledger)
            .map_err(|_| "root-opening leaf source plan")?;
        let original = ledger
            .admit_phase(plan.requirements())
            .map_err(|_| "root-opening leaf source admission")?;
        let source = plan
            .inspect(original, ledger)
            .map_err(|_| "root-opening leaf source inspection")?;
        closure = closure
            .retain_source(group, source, ledger)
            .map_err(|_| "root-opening original leaf retention")?;
    }
    let plan = ParentSourcePlan::new(&closure, ledger)
        .map_err(|_| "root-opening parent source plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "root-opening parent source admission")?;
    let source = plan
        .inspect(original, ledger)
        .map_err(|_| "root-opening parent source inspection")?;

    // The complete B066 opening owner is admitted before Attempt can create
    // PendingNative. Its source/request/ledger are this very Attempt's originals.
    let mut opening = Some(
        PreissuedRootOpening::reserve_before_native(&source, ledger)
            .map_err(|_| "root-opening original all-height preclaim")?,
    );
    let planned = opening
        .as_ref()
        .ok_or("root-opening original owner")?
        .plan_report(ledger)
        .map_err(|_| "root-opening original plan report")?;
    let probe_sum = planned.caller_host_bytes
        .checked_add(planned.verifier_host_bytes)
        .ok_or("root-opening probe claim sum overflow")?;
    if planned.cpu_heights != 18
        || planned.planned_opening_probes != 1
        || planned.total_host_bytes != probe_sum
    {
        return Err("root-opening original plan scope");
    }
    let driver_host_bytes = caller.requirements().total()
        .map_err(|_| "root-opening driver claim total")?.host;
    let total_host_bytes = driver_host_bytes.checked_add(planned.total_host_bytes)
        .ok_or("root-opening combined driver and probe claim overflow")?;
    // These are only the probe-plus-driver claims. The following source
    // snapshot additionally includes the whole original Attempt and its sources.
    eprintln!("ringct_hashx_root_opening_claims cpu_heights={} probe_verifier_host_bytes={} probe_caller_host_bytes={} probe_host_bytes={} driver_host_bytes={} total_host_bytes={} planned_opening_probes={} mode={} actual_opening_probes=0 native_dispatch_started=false complete_ringct_workflow=false",
        planned.cpu_heights, planned.verifier_host_bytes, planned.caller_host_bytes,
        planned.total_host_bytes, driver_host_bytes, total_host_bytes,
        planned.planned_opening_probes, mode.name());
    let mut attempt = Some(
        Attempt::reserve_before_native(&source, groups.each_ref(), ledger)
            .map_err(|_| "root-opening all original attempt preclaims")?,
    );
    let claimed = ledger.snapshot();
    eprintln!("ringct_hashx_sequence_source_claims native_outputs=10 native_attachments=10 retained_leaf_sources=5 retained_parent_sources=4 original_compiler_bank=1 leaf_output_claims=5 parent_output_claims=4 source_acceptance_claims=9 original_outer_sequence=true host_bytes={} device_bytes={} mode={} native_dispatch_started=false complete_ringct_workflow=false",
        claimed.current.host, claimed.current.device, mode.name());
    match mode {
        OpeningMode::Capacity => {
            project(attempt.as_mut().ok_or("root-opening original attempt")?, &wrong)?;
        }
        OpeningMode::Gpu => {
            let component = match unsafe {
                attempt.take().ok_or("root-opening original attempt")?.run()
            } {
                Ok(component) => component,
                Err(failure) => {
                    let reason = match &failure.cause {
                        Cause::Production(_) => "root-opening native/outer/source production",
                        Cause::Compiler(bank::Failure::Admission(_)) => {
                            "root-opening compiler bank admission"
                        }
                        Cause::Compiler(bank::Failure::Compilation { .. }) => {
                            "root-opening native verifier/compiler"
                        }
                        Cause::Injected(_) => "unexpected root-opening returned-refusal trip",
                    };
                    eprintln!("ringct_hashx_sequence_failure phase={reason:?} retry=false complete_ringct_workflow=false");
                    drop(failure);
                    return Err(reason);
                }
            };
            // The same successful Attempt emits the unchanged actual graph
            // summaries before its own Component is consumed by the closed opening probe.
            report(&component)?;
            let retained = component
                .recheck_root_opening(
                    opening.take().ok_or("root-opening original preissued owner")?,
                    ledger,
                )
                .map_err(|_| "root-opening actual original probe")?;
            opening_report(&retained, ledger)?;
            drop(retained);
        }
    }
    drop(attempt);
    drop(opening);
    drop(source);
    let refused = match closure.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    if refused.report().retained_original_leaf_sources != LEAVES {
        return Err("root-opening complete transaction remains closed");
    }
    drop(refused);
    drop(groups);
    drop(wrong);
    drop(owner);
    // Every workload/error/plan/opening report has finished its last use.
    // This original does not back the separately identified terminal observer.
    drop(caller);
    Ok(())
}

/// # Safety
/// Same exclusive physical/process guard as exercise. Ledger bootstrap and this
/// fixed terminal observer are explicit harness scope, not source-storage or
/// released-reservation credit. The external process audit covers their memory.
unsafe fn run(mode: OpeningMode) -> DriverResult<()> {
    let observer_fixed_host_bytes = claims::terminal_observer_bytes()?;
    let started = std::time::Instant::now();
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let result = unsafe { exercise(mode, &ledger) };
    let terminal = ledger.snapshot();
    if terminal.current != Bytes::ZERO
        || terminal.categories.iter().any(|category| category.current != Bytes::ZERO)
    {
        return Err("root-opening terminal original quota");
    }
    let observed = TerminalObservation {
        result,
        terminal,
        elapsed_ns: started.elapsed().as_nanos(),
        mode,
        observer_fixed_host_bytes,
    };
    if observed.result.is_ok() && observed.mode == OpeningMode::Gpu {
        eprintln!("ringct_hashx_root_opening_complete native_proofs=10 recursive_proofs=9 recursive_leaf_proofs=5 recursive_parent_proofs=4 compiler_reclamations=9 first_unit=0 units=122 level=3 cpu_heights=18 numerical_positive_checks=2 typed_opening_relation_rejections=1 component_through_destruction_ns={} root_opening_probe_complete=true opening_scope=single-root-first-local-permutation-opening retained_output_restored=true source_key_authenticated=true transaction_context_authenticated=false original_quota_released=true owner_quota_cleanup_complete=true terminal_observer_scope=process-audit-only terminal_observer_fixed_host_bytes={} released_claims_cover_terminal_observer=false process_engine_device_audit_complete=false raw_proof_mutation_checks_complete=false interior_mutation_checks_complete=false mutation_checks_complete=false disk_artifact_roundtrip_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
            observed.elapsed_ns, observed.observer_fixed_host_bytes);
    }
    let component_success = observed.result.is_ok() && observed.mode == OpeningMode::Gpu;
    eprintln!("ringct_hashx_sequence_terminal original_quota_released=true current_host_bytes={} current_device_bytes={} peak_host_bytes={} peak_device_bytes={} component_through_destruction_ns={} component_success={} mode={} terminal_observer_scope=process-audit-only terminal_observer_fixed_host_bytes={} released_claims_cover_terminal_observer=false process_engine_device_audit_complete=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        observed.terminal.current.host, observed.terminal.current.device,
        observed.terminal.peak.host, observed.terminal.peak.device,
        observed.elapsed_ns, component_success, observed.mode.name(),
        observed.observer_fixed_host_bytes);
    observed.result
}

#[test]
#[ignore = "exact root-opening source/quota guard; no backend, device, proof or numerical probe execution"]
fn cpu_original_hashx_sequence_root_opening_capacity() {
    unsafe { run(OpeningMode::Capacity) }.unwrap();
}

#[test]
#[ignore = "exact coordinator root-opening source/binary/environment/device guard; single original private root opening probe only"]
fn gpu_original_hashx_sequence_root_opening_recheck() {
    unsafe { run(OpeningMode::Gpu) }.unwrap();
}
