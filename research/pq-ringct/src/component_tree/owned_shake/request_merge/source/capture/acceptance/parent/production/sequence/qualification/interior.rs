//! Exact opt-in driver for one actual Leaf0 opening probe inside Parent0.
//! The closed Attempt constructor preissues both complete originals before
//! PendingNative. The restored selected child continues through the same graph.
//! The final fixed observer remains separately process-audited harness scope.
use super::*;
use super::super::interior_opening::{
    InteriorOpeningMeasurements, InteriorOpeningPlanReport,
};

mod claims;

#[derive(Clone, Copy, PartialEq, Eq)]
enum InteriorMode {
    Capacity,
    Gpu,
}

impl InteriorMode {
    fn name(self) -> &'static str {
        match self {
            Self::Capacity => "interior-opening-capacity",
            Self::Gpu => "interior-opening",
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
    mode: InteriorMode,
    observer_fixed_host_bytes: u64,
}

fn interior_guard(mode: InteriorMode) -> DriverResult<()> {
    let (base, key) = match mode {
        InteriorMode::Capacity => (
            super::Mode::Capacity,
            "LATTICA_OWNED_HASHX_INTERIOR_OPENING_SOURCE_QUALIFICATION",
        ),
        InteriorMode::Gpu => (
            super::Mode::Gpu,
            "LATTICA_OWNED_HASHX_INTERIOR_OPENING_QUALIFICATION",
        ),
    };
    // Preserve the existing immutable sequence, GpuRequired and host-retained
    // tree guards. This separate opt-in never upgrades another selected mode.
    super::guard(base)?;
    if std::env::var(key).as_deref() != Ok("1") {
        return Err("exact interior-opening qualification guard");
    }
    Ok(())
}

fn interior_report(component: &Component<'_, '_, '_>, ledger: &Ledger) -> DriverResult<()> {
    // This borrow cannot outlive Component's retained complete probe original.
    // Scope was emitted inside Parent0 preparation, before consuming the child.
    let measured = component.interior_report(ledger)
        .map_err(|_| "interior-opening retained measurement authority")?;
    let subintervals = measured.positive_verification_ns
        .checked_add(measured.mutation_verification_ns)
        .ok_or("interior-opening subinterval overflow")?;
    if measured.cpu_heights != 18
        || measured.positive_checks != 2
        || measured.opening_probes != 1
        || !measured.retained_output_restored
        || !measured.parent0_child_consumed
        || measured.positive_verification_ns == 0
        || measured.mutation_verification_ns == 0
        || measured.elapsed_ns == 0
        || subintervals > measured.elapsed_ns
        || measured.elapsed_ns > component.report.elapsed_ns
    {
        return Err("interior-opening actual report scope");
    }
    // The strict external guard additionally sums all serialized receipt,
    // compiler and source-verifier times plus this action within preparation.
    Ok(())
}

/// # Safety
/// The exact coordinator source/binary/environment/device and exclusive
/// process/memory guard must remain valid through final workload destruction.
unsafe fn exercise(mode: InteriorMode, ledger: &Ledger) -> DriverResult<()> {
    let caller = ledger
        .admit_phase(claims::driver_requirement()?)
        .map_err(|_| "interior-opening complete driver admission")?;
    interior_guard(mode)?;
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
        .admit_phase(plan.requirements().map_err(|_| "interior-opening closure source")?)
        .map_err(|_| "interior-opening closure admission")?;
    let mut closure = plan
        .open(original, ledger)
        .map_err(|_| "interior-opening closure construction")?;
    for group in &groups {
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, ledger)
            .map_err(|_| "interior-opening leaf source plan")?;
        let original = ledger
            .admit_phase(plan.requirements())
            .map_err(|_| "interior-opening leaf source admission")?;
        let source = plan
            .inspect(original, ledger)
            .map_err(|_| "interior-opening leaf source inspection")?;
        closure = closure
            .retain_source(group, source, ledger)
            .map_err(|_| "interior-opening original leaf retention")?;
    }
    let plan = ParentSourcePlan::new(&closure, ledger)
        .map_err(|_| "interior-opening parent source plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "interior-opening parent source admission")?;
    let source = plan
        .inspect(original, ledger)
        .map_err(|_| "interior-opening parent source inspection")?;

    // The closed constructor admits the complete new caller and all-height
    // direct-verifier claim before the existing Attempt/PendingNative path.
    let mut attempt = Some(
        Attempt::reserve_interior_before_native(&source, groups.each_ref(), ledger)
            .map_err(|_| "interior-opening all original attempt preclaims")?,
    );
    let planned = attempt.as_ref().ok_or("interior-opening original attempt")?
        .interior_plan(ledger)
        .map_err(|_| "interior-opening original plan report")?;
    let probe_sum = planned.caller_host_bytes
        .checked_add(planned.verifier_host_bytes)
        .ok_or("interior-opening probe claim sum overflow")?;
    if planned.cpu_heights != 18
        || planned.planned_opening_probes != 1
        || planned.total_host_bytes != probe_sum
    {
        return Err("interior-opening original plan scope");
    }
    let driver_host_bytes = caller.requirements().total()
        .map_err(|_| "interior-opening driver claim total")?.host;
    let total_host_bytes = driver_host_bytes.checked_add(planned.total_host_bytes)
        .ok_or("interior-opening combined driver and probe claim overflow")?;
    // These are only the probe-plus-driver claims. The following source
    // snapshot additionally includes the whole original Attempt and its sources.
    eprintln!("ringct_hashx_interior_opening_claims cpu_heights={} probe_verifier_host_bytes={} probe_caller_host_bytes={} probe_host_bytes={} driver_host_bytes={} total_host_bytes={} planned_opening_probes={} mode={} actual_opening_probes=0 native_dispatch_started=false complete_ringct_workflow=false",
        planned.cpu_heights, planned.verifier_host_bytes, planned.caller_host_bytes,
        planned.total_host_bytes, driver_host_bytes, total_host_bytes,
        planned.planned_opening_probes, mode.name());
    let claimed = ledger.snapshot();
    eprintln!("ringct_hashx_sequence_source_claims native_outputs=10 native_attachments=10 retained_leaf_sources=5 retained_parent_sources=4 original_compiler_bank=1 leaf_output_claims=5 parent_output_claims=4 source_acceptance_claims=9 original_outer_sequence=true host_bytes={} device_bytes={} mode={} native_dispatch_started=false complete_ringct_workflow=false",
        claimed.current.host, claimed.current.device, mode.name());
    match mode {
        InteriorMode::Capacity => {
            project(attempt.as_mut().ok_or("interior-opening original attempt")?, &wrong)?;
        }
        InteriorMode::Gpu => {
            let component = match unsafe {
                attempt.take().ok_or("interior-opening original attempt")?.run()
            } {
                Ok(component) => component,
                Err(failure) => {
                    let reason = match &failure.cause {
                        Cause::Production(_) => "interior-opening native/outer/source production",
                        Cause::Compiler(bank::Failure::Admission(_)) => {
                            "interior-opening compiler bank admission"
                        }
                        Cause::Compiler(bank::Failure::Compilation { .. }) => {
                            "interior-opening native verifier/compiler"
                        }
                        Cause::Injected(_) => "unexpected interior-opening returned-refusal trip",
                    };
                    eprintln!("ringct_hashx_sequence_failure phase={reason:?} retry=false complete_ringct_workflow=false");
                    drop(failure);
                    return Err(reason);
                }
            };
            // No second action or detached report: scope already occurred
            // inside the same component preparation, between stage receipts.
            interior_report(&component, ledger)?;
            report(&component)?;
            drop(component);
        }
    }
    drop(attempt);
    drop(source);
    let refused = match closure.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    if refused.report().retained_original_leaf_sources != LEAVES {
        return Err("interior-opening complete transaction remains closed");
    }
    drop(refused);
    drop(groups);
    drop(wrong);
    drop(owner);
    // Every workload/error/plan/interior report has finished its last use.
    // This original does not back the separately identified terminal observer.
    drop(caller);
    Ok(())
}

/// # Safety
/// Same exclusive physical/process guard as exercise. Ledger bootstrap and this
/// fixed terminal observer are explicit harness scope, not source-storage or
/// released-reservation credit. The external process audit covers their memory.
unsafe fn run(mode: InteriorMode) -> DriverResult<()> {
    let observer_fixed_host_bytes = claims::terminal_observer_bytes()?;
    let started = std::time::Instant::now();
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let result = unsafe { exercise(mode, &ledger) };
    let terminal = ledger.snapshot();
    if terminal.current != Bytes::ZERO
        || terminal.categories.iter().any(|category| category.current != Bytes::ZERO)
    {
        return Err("interior-opening terminal original quota");
    }
    let observed = TerminalObservation {
        result,
        terminal,
        elapsed_ns: started.elapsed().as_nanos(),
        mode,
        observer_fixed_host_bytes,
    };
    if observed.result.is_ok() && observed.mode == InteriorMode::Gpu {
        eprintln!("ringct_hashx_interior_opening_complete artifact_roundtrip_complete=false child_first_unit=0 child_kind=leaf child_level=0 child_ordinal=0 child_side=left child_units=32 compiler_reclamations=9 complete_ringct_workflow=false cpu_heights=18 disk_artifact_roundtrip_complete=false first_unit=0 interior_mutation_checks_complete=false interior_opening_probe_complete=true level=3 mutation_checks_complete=false native_proofs=10 numerical_positive_checks=2 opening_scope=single-interior-parent0-left-leaf0-first-local-permutation-opening original_quota_released=true owner_quota_cleanup_complete=true parent0_child_consumed=true parent_boundary_mutation_checks_complete=false parent_first_unit=0 parent_level=1 parent_ordinal=0 parent_units=64 process_engine_device_audit_complete=false raw_proof_mutation_checks_complete=false recursive_leaf_proofs=5 recursive_parent_proofs=4 recursive_proofs=9 released_claims_cover_terminal_observer=false retained_output_restored=true sibling_first_unit=32 sibling_level=0 sibling_ordinal=1 sibling_units=32 source_key_authenticated=true terminal_observer_scope=process-audit-only timing_scope=within-component-preparation transaction_context_authenticated=false typed_opening_relation_rejections=1 units=122 whole_graph_mutation_checks_complete=false component_through_destruction_ns={} terminal_observer_fixed_host_bytes={}",
            observed.elapsed_ns, observed.observer_fixed_host_bytes);
    }
    let component_success = observed.result.is_ok() && observed.mode == InteriorMode::Gpu;
    eprintln!("ringct_hashx_sequence_terminal original_quota_released=true current_host_bytes={} current_device_bytes={} peak_host_bytes={} peak_device_bytes={} component_through_destruction_ns={} component_success={} mode={} terminal_observer_scope=process-audit-only terminal_observer_fixed_host_bytes={} released_claims_cover_terminal_observer=false process_engine_device_audit_complete=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        observed.terminal.current.host, observed.terminal.current.device,
        observed.terminal.peak.host, observed.terminal.peak.device,
        observed.elapsed_ns, component_success, observed.mode.name(),
        observed.observer_fixed_host_bytes);
    observed.result
}

#[test]
#[ignore = "exact interior-opening source/quota guard; no backend, device, proof or numerical probe execution"]
fn cpu_original_hashx_sequence_leaf0_opening_capacity() {
    unsafe { run(InteriorMode::Capacity) }.unwrap();
}

#[test]
#[ignore = "exact coordinator interior-opening source/binary/environment/device guard; single original private Leaf0 opening probe only"]
fn gpu_original_hashx_sequence_leaf0_opening_recheck() {
    unsafe { run(InteriorMode::Gpu) }.unwrap();
}
