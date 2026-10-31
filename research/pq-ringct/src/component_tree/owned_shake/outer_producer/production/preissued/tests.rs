use super::*;
use crate::{
    component_tree::{EndpointContext, Val},
    execution::retained_resources::{Snapshot, WorkerAllowance},
    graph_crypto::{
        Policy as ProofPolicy, PreparedNativeSingleton, PreparedNativeSingletonAttachment,
        ShakeRequestPlan, ShakeWrapperLayout,
    },
};
use p3_field::PrimeCharacteristicRing;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

#[test]
fn future_outer_fixed_claims_require_the_existing_worker_envelope() {
    let metadata = metadata_requirement().unwrap();
    assert_eq!(metadata.get(Category::PhaseScratch).device, 0);
    assert!(metadata.get(Category::PhaseScratch).host < 1 << 20);
    assert!(report_requirement().unwrap().get(Category::Report).host > 0);
}

#[test]
#[ignore = "exact coordinator serialized native-to-outer host qualifier only"]
fn gpu_native_to_outer_singleton_uses_original_preclaims() {
    for (name, value) in [
        ("LATTICA_OWNED_SHAKE_OUTER_CONTINUATION_QUALIFICATION", "1"),
        ("LATTICA_PROVING_POLICY", "gpu-required"),
        ("LATTICA_V2_GPU_RETAINED_TREE_STORAGE", "host"),
        ("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES", "8589934592"),
    ] {
        assert_eq!(std::env::var(name).as_deref(), Ok(value));
    }
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let fixture = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: (16 * size_of::<Snapshot>()
                    + 12 * size_of::<Requirements>()
                    + 12 * size_of::<Reservation>()
                    + 8 * size_of::<std::time::Instant>()
                    + 4 * size_of::<crate::component_tree::owned_shake::Summary>()
                    + 4 * size_of::<EndpointContext>()
                    + 2 * size_of::<Shake256>()
                    + 2 * size_of::<Shake256Reader>()
                    + 4 * size_of::<[u8; 1]>()
                    + (2 * 4 * 8 + 22) * size_of::<Val>()
                    + size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>()
                    + 4 * size_of::<[Val; 8]>()) as u64,
                device: 0,
            },
        )
        .unwrap();
    let started = std::time::Instant::now();
    let input = [7u8];
    let mut expected_output = [0u8];
    let mut xof = Shake256::default();
    xof.update(&input);
    xof.finalize_xof().read(&mut expected_output);
    let endpoints = EndpointContext {
        // Context and statement are explicit component-test placeholders.
        // Only the request's public byte endpoints are independently derived.
        context: [97; 32],
        statement: [Val::from_u64(19); 4],
        input: crate::shake_air::commit_bytes(crate::shake_air::SHAKE_INPUT_DOMAIN, &input),
        output: crate::shake_air::commit_bytes(
            crate::shake_air::SHAKE_OUTPUT_DOMAIN,
            &expected_output,
        ),
    };
    let request = ShakeRequestPlan::new([96; 32], 7, 0, &input, 1, ProofPolicy::default()).unwrap();
    let request_claim = ledger.admit_phase(request.requirements()).unwrap();
    let owner = request.construct(request_claim, &ledger).unwrap();
    let group = GroupCompilePlan::new(owner.request(), ShakeWrapperLayout::Singleton, 0, endpoints)
        .unwrap();
    let source_plan = group.source_shape_plan(&owner, &ledger).unwrap();
    let source_claim = ledger.admit_phase(source_plan.requirements()).unwrap();
    let source = source_plan.inspect(source_claim, &ledger).unwrap();
    let compiler = ledger.admit_phase(group.requirements()).unwrap();
    let attachment =
        PreparedNativeSingletonAttachment::reserve_before_native(&owner, 0, &ledger).unwrap();
    let future = FutureOuter::reserve_before_native(&source, &group, &owner, &ledger).unwrap();
    let recheck =
        output::OutputRecheck::reserve_before_native(&source, &group, &owner, &ledger).unwrap();
    // SAFETY: exact recorded coordinator guard holds the immutable profile
    // through native and restored outer runtime retirement, with zero swap.
    let native = unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &ledger) }.unwrap();
    let capacity = native.outer_continuation_capacity().unwrap();
    let ready = future
        .complete_before_native(
            capacity.startup,
            capacity.pcs,
            capacity.retained_tree_host_bytes,
        )
        .unwrap();
    let admitted = ledger.snapshot();
    assert_eq!(admitted.current.device, 8 << 30);
    eprintln!("ringct_native_to_outer_preissued source_bounds_complete=true original_phase_owners_live=true native_dispatch_started=false host_bytes={} device_bytes={}", admitted.current.host, admitted.current.device);
    // SAFETY: same original process guard, no retries/fallback.
    let produced = unsafe { native.produce_retaining_originals() }.unwrap();
    let (verified, originals) = produced.into_parts();
    eprint!("proving_stage_report ");
    serde_json::to_writer(std::io::stderr().lock(), verified.report()).unwrap();
    eprintln!();
    let before_attachment = ledger.snapshot();
    let child = attachment.attach(verified, &ledger).unwrap();
    assert_eq!(ledger.snapshot(), before_attachment);
    let compile_started = std::time::Instant::now();
    let compiled = group
        .compile_cpu_reference([Some(child), None], compiler, &ledger)
        .unwrap();
    let compile_ns = compile_started.elapsed().as_nanos();
    source.check_compiled(&compiled, &ledger).unwrap();
    let summary = compiled.summary();
    let before_bind = ledger.snapshot();
    // SAFETY: exact original native runtime is retired and the same guard holds.
    let continuation = unsafe { ready.finish_native(&compiled, originals) }.unwrap();
    assert_eq!(ledger.snapshot(), before_bind);
    // SAFETY: restored runtime uses the same original startup and PCS claims.
    let mut output = unsafe { continuation.produce() }.unwrap();
    assert!(output.belongs_to(&ledger));
    assert!(output.report().independent_verification_complete);
    recheck.verify_mutations(&mut output, &ledger).unwrap();
    let report = output.report();
    eprintln!("ringct_native_to_outer_singleton native_proofs=1 recursive_proofs=1 fresh_gpu_required=true compiler_backend=cpu public_endpoint_preprocessing=cpu source_preclaims_before_native=true original_runtime_pcs_reused=true attachment_and_bind_ledger_unchanged=true independent_cpu_verified=true mutation_rejections=2 active_rows={} padded_rows={} compiler_ns={} setup_ns={} proving_ns={} cpu_verification_ns={} component_including_mutations_ns={} complete_ringct_workflow=false",
        summary.active_rows, summary.padded_rows, compile_ns,
        report.setup_elapsed_ns.unwrap(), report.proving_elapsed_ns.unwrap(),
        report.cpu_verification_elapsed_ns.unwrap(), started.elapsed().as_nanos());
    drop(output);
    drop(compiled);
    drop(source);
    drop(owner);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!("ringct_native_to_outer_terminal original_quota_released=true complete_ringct_workflow=false");
}
