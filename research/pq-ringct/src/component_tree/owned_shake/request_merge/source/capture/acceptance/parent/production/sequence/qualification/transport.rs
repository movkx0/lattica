//! Inactive exact opt-in driver for one actual original-root in-memory transport.
//! No ancestor module, wrapper or selector allowlist is changed by this file.
//! Workload reports retain their original caller; the final fixed observer is
//! separately identified harness scope under the coordinator's process guard.
use super::*;
use super::super::root_transport::{
    PreissuedRootTransport, RetainedRootTransportReport, RootTransportMeasurements,
};

mod claims;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    Capacity,
    Gpu,
}

impl TransportMode {
    fn name(self) -> &'static str {
        match self {
            Self::Capacity => "root-transport-capacity",
            Self::Gpu => "root-transport",
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
    mode: TransportMode,
    observer_fixed_host_bytes: u64,
}

fn transport_guard(mode: TransportMode) -> DriverResult<()> {
    let (base, key) = match mode {
        TransportMode::Capacity => (
            super::Mode::Capacity,
            "LATTICA_OWNED_HASHX_ROOT_TRANSPORT_SOURCE_QUALIFICATION",
        ),
        TransportMode::Gpu => (
            super::Mode::Gpu,
            "LATTICA_OWNED_HASHX_ROOT_TRANSPORT_QUALIFICATION",
        ),
    };
    // Preserve the existing immutable sequence, GpuRequired and host-retained
    // tree guards. This separate opt-in never upgrades another selected mode.
    super::guard(base)?;
    if std::env::var(key).as_deref() != Ok("1") {
        return Err("exact root-transport qualification guard");
    }
    Ok(())
}

fn transport_report(
    owner: &RetainedRootTransportReport<'_, '_, '_>,
    ledger: &Ledger,
) -> DriverResult<()> {
    // The entire report and both transport originals stay held during checking
    // and formatting. No detached measurement value is copied out of owner.
    let report = owner
        .measurements(ledger)
        .map_err(|_| "root-transport retained measurement authority")?;
    let header = &report.header_probes;
    let typed_header_total = [
        header.syntax_rejections,
        header.public_rejections,
        header.cap_rejections,
        header.height_rejections,
        header.canonical_rejections,
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or("root-transport header observation count overflow")?;
    let measured_subintervals = [
        report.original_verification_ns,
        report.encoding_ns,
        report.header_checks_ns,
        report.decoding_ns,
        report.decoded_verification_ns,
        report.reencoding_ns,
    ]
    .into_iter()
    .try_fold(0u128, u128::checked_add)
    .ok_or("root-transport subinterval overflow")?;
    if report.cpu_heights != 18
        || report.codec_heights != 18
        || report.positive_checks != 2
        || report.inner_bytes < 8
        || report.packet_bytes != report.inner_bytes.checked_add(2480)
            .ok_or("root-transport packet length overflow")?
        || report.packet_bytes >= 2 << 20
        || header.positive_checks != 2
        || header.syntax_rejections != 24
        || header.public_rejections != 46
        || header.cap_rejections != 256
        || header.height_rejections != 1
        || header.canonical_rejections != 302
        || typed_header_total != 629
        || report.original_verification_ns == 0
        || report.encoding_ns == 0
        || report.header_checks_ns == 0
        || report.decoding_ns == 0
        || report.decoded_verification_ns == 0
        || report.reencoding_ns == 0
        || report.elapsed_ns == 0
        || measured_subintervals > report.elapsed_ns
    {
        return Err("root-transport actual report scope");
    }
    // One successful decode is established by B067's closed actual action and
    // independently matched to the core codec's single storage diagnostic.
    // Header refusals are equality/syntax observations, never proof negatives.
    eprintln!("ringct_hashx_root_transport_scope cpu_heights={} codec_heights={} numerical_positive_checks={} bounded_decode_successes=1 packet_bytes={} inner_bytes={} header_positive_checks={} header_syntax_rejections={} header_public_rejections={} header_cap_rejections={} header_height_rejections={} header_canonical_rejections={} typed_header_refusals={} original_verification_ns={} encoding_ns={} header_checks_ns={} decoding_ns={} decoded_verification_ns={} reencoding_ns={} transport_action_ns={} provisional=true terminal_cleanup_complete=false transport_scope=single-root-in-memory retained_output_immutable=true source_key_authenticated=true transaction_context_authenticated=false decoder_failures_classified=false raw_proof_mutation_checks_complete=false interior_mutation_checks_complete=false mutation_checks_complete=false disk_artifact_roundtrip_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        report.cpu_heights, report.codec_heights, report.positive_checks,
        report.packet_bytes, report.inner_bytes, header.positive_checks,
        header.syntax_rejections, header.public_rejections, header.cap_rejections,
        header.height_rejections, header.canonical_rejections, typed_header_total,
        report.original_verification_ns, report.encoding_ns, report.header_checks_ns,
        report.decoding_ns, report.decoded_verification_ns, report.reencoding_ns,
        report.elapsed_ns);
    Ok(())
}

/// # Safety
/// The exact coordinator source/binary/environment/device and exclusive
/// process/memory guard must remain valid through final workload destruction.
unsafe fn exercise(mode: TransportMode, ledger: &Ledger) -> DriverResult<()> {
    let caller = ledger
        .admit_phase(claims::driver_requirement()?)
        .map_err(|_| "root-transport complete driver admission")?;
    transport_guard(mode)?;
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
        .admit_phase(plan.requirements().map_err(|_| "root-transport closure source")?)
        .map_err(|_| "root-transport closure admission")?;
    let mut closure = plan
        .open(original, ledger)
        .map_err(|_| "root-transport closure construction")?;
    for group in &groups {
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, ledger)
            .map_err(|_| "root-transport leaf source plan")?;
        let original = ledger
            .admit_phase(plan.requirements())
            .map_err(|_| "root-transport leaf source admission")?;
        let source = plan
            .inspect(original, ledger)
            .map_err(|_| "root-transport leaf source inspection")?;
        closure = closure
            .retain_source(group, source, ledger)
            .map_err(|_| "root-transport original leaf retention")?;
    }
    let plan = ParentSourcePlan::new(&closure, ledger)
        .map_err(|_| "root-transport parent source plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "root-transport parent source admission")?;
    let source = plan
        .inspect(original, ledger)
        .map_err(|_| "root-transport parent source inspection")?;

    // This actual callsite, rather than the constructor's name or Source+Ledger,
    // establishes transport admission before Attempt can create PendingNative.
    let mut transport = Some(
        PreissuedRootTransport::reserve_before_native(&source, ledger)
            .map_err(|_| "root-transport original all-height preclaim")?,
    );
    let planned = transport
        .as_ref()
        .ok_or("root-transport original owner")?
        .plan_report(ledger)
        .map_err(|_| "root-transport original plan report")?;
    let caller_host_bytes = caller.requirements().total()
        .map_err(|_| "root-transport driver claim total")?.host;
    let total_host_bytes = caller_host_bytes.checked_add(planned.additional_host_bytes)
        .ok_or("root-transport combined driver and transport claim overflow")?;
    // This is the transport-plus-driver subset. The following original source
    // snapshot additionally includes the complete same-Attempt workload claims.
    eprintln!("ringct_hashx_root_transport_claims cpu_heights={} codec_heights={} fixed_host_bytes={} packet_and_decoder_host_bytes={} verifier_host_bytes={} additional_host_bytes={} packet_limit_bytes={} decoder_limit_bytes={} max_inner_bytes={} max_packet_bytes={} max_packet_and_probe_bytes={} max_decoder_cumulative_bytes={} caller_host_bytes={} total_host_bytes={} mode={} actual_root_transports=0 native_dispatch_started=false complete_ringct_workflow=false",
        planned.cpu_heights, planned.codec_heights, planned.fixed_host_bytes,
        planned.packet_and_decoder_host_bytes, planned.verifier_host_bytes,
        planned.additional_host_bytes, planned.packet_limit_bytes,
        planned.decoder_limit_bytes, planned.max_inner_bytes,
        planned.max_packet_bytes, planned.max_packet_and_probe_bytes,
        planned.max_decoder_cumulative_bytes, caller_host_bytes, total_host_bytes,
        mode.name());
    let mut attempt = Some(
        Attempt::reserve_before_native(&source, groups.each_ref(), ledger)
            .map_err(|_| "root-transport all original attempt preclaims")?,
    );
    let claimed = ledger.snapshot();
    eprintln!("ringct_hashx_sequence_source_claims native_outputs=10 native_attachments=10 retained_leaf_sources=5 retained_parent_sources=4 original_compiler_bank=1 leaf_output_claims=5 parent_output_claims=4 source_acceptance_claims=9 original_outer_sequence=true host_bytes={} device_bytes={} mode={} native_dispatch_started=false complete_ringct_workflow=false",
        claimed.current.host, claimed.current.device, mode.name());
    match mode {
        TransportMode::Capacity => {
            project(attempt.as_mut().ok_or("root-transport original attempt")?, &wrong)?;
        }
        TransportMode::Gpu => {
            let component = match unsafe {
                attempt.take().ok_or("root-transport original attempt")?.run()
            } {
                Ok(component) => component,
                Err(failure) => {
                    let reason = match &failure.cause {
                        Cause::Production(_) => "root-transport native/outer/source production",
                        Cause::Compiler(bank::Failure::Admission(_)) => {
                            "root-transport compiler bank admission"
                        }
                        Cause::Compiler(bank::Failure::Compilation { .. }) => {
                            "root-transport native verifier/compiler"
                        }
                        Cause::Injected(_) => "unexpected root-transport returned-refusal trip",
                    };
                    eprintln!("ringct_hashx_sequence_failure phase={reason:?} retry=false complete_ringct_workflow=false");
                    drop(failure);
                    return Err(reason);
                }
            };
            // The same successful Attempt emits the unchanged actual graph
            // summaries before its own Component is consumed by transport.
            report(&component)?;
            let retained = component
                .roundtrip_root(
                    transport.take().ok_or("root-transport original preissued owner")?,
                    ledger,
                )
                .map_err(|_| "root-transport actual original roundtrip")?;
            transport_report(&retained, ledger)?;
            drop(retained);
        }
    }
    drop(attempt);
    drop(transport);
    drop(source);
    let refused = match closure.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    if refused.report().retained_original_leaf_sources != LEAVES {
        return Err("root-transport complete transaction remains closed");
    }
    drop(refused);
    drop(groups);
    drop(wrong);
    drop(owner);
    // Every workload/error/plan/transport report has finished its last use.
    // This original does not back the separately identified terminal observer.
    drop(caller);
    Ok(())
}

/// # Safety
/// Same exclusive physical/process guard as exercise. Ledger bootstrap and this
/// fixed terminal observer are explicit harness scope, not source-storage or
/// released-reservation credit. The external process audit covers their memory.
unsafe fn run(mode: TransportMode) -> DriverResult<()> {
    let observer_fixed_host_bytes = claims::terminal_observer_bytes()?;
    let started = std::time::Instant::now();
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let result = unsafe { exercise(mode, &ledger) };
    let terminal = ledger.snapshot();
    if terminal.current != Bytes::ZERO
        || terminal.categories.iter().any(|category| category.current != Bytes::ZERO)
    {
        return Err("root-transport terminal original quota");
    }
    let observed = TerminalObservation {
        result,
        terminal,
        elapsed_ns: started.elapsed().as_nanos(),
        mode,
        observer_fixed_host_bytes,
    };
    if observed.result.is_ok() && observed.mode == TransportMode::Gpu {
        eprintln!("ringct_hashx_root_transport_complete native_proofs=10 recursive_proofs=9 recursive_leaf_proofs=5 recursive_parent_proofs=4 compiler_reclamations=9 first_unit=0 units=122 level=3 cpu_heights=18 codec_heights=18 numerical_positive_checks=2 bounded_decode_successes=1 header_positive_checks=2 header_syntax_rejections=24 header_public_rejections=46 header_cap_rejections=256 header_height_rejections=1 header_canonical_rejections=302 typed_header_refusals=629 component_through_destruction_ns={} root_transport_roundtrip_complete=true transport_scope=single-root-in-memory retained_output_immutable=true source_key_authenticated=true transaction_context_authenticated=false original_quota_released=true owner_quota_cleanup_complete=true terminal_observer_scope=process-audit-only terminal_observer_fixed_host_bytes={} released_claims_cover_terminal_observer=false process_engine_device_audit_complete=false decoder_failures_classified=false raw_proof_mutation_checks_complete=false interior_mutation_checks_complete=false mutation_checks_complete=false disk_artifact_roundtrip_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
            observed.elapsed_ns, observed.observer_fixed_host_bytes);
    }
    let component_success = observed.result.is_ok() && observed.mode == TransportMode::Gpu;
    eprintln!("ringct_hashx_sequence_terminal original_quota_released=true current_host_bytes={} current_device_bytes={} peak_host_bytes={} peak_device_bytes={} component_through_destruction_ns={} component_success={} mode={} terminal_observer_scope=process-audit-only terminal_observer_fixed_host_bytes={} released_claims_cover_terminal_observer=false process_engine_device_audit_complete=false mutation_checks_complete=false artifact_roundtrip_complete=false complete_ringct_workflow=false",
        observed.terminal.current.host, observed.terminal.current.device,
        observed.terminal.peak.host, observed.terminal.peak.device,
        observed.elapsed_ns, component_success, observed.mode.name(),
        observed.observer_fixed_host_bytes);
    observed.result
}

#[test]
#[ignore = "exact root-transport source/quota guard; no backend, device, proof or decoder execution"]
fn cpu_original_hashx_sequence_root_transport_capacity() {
    unsafe { run(TransportMode::Capacity) }.unwrap();
}

#[test]
#[ignore = "exact coordinator root-transport source/binary/environment/device guard; actual private root only"]
fn gpu_original_hashx_sequence_root_transport_roundtrip() {
    unsafe { run(TransportMode::Gpu) }.unwrap();
}
