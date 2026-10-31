use super::*;
use crate::{
    component_tree::{EndpointContext, Val},
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{
        Policy as ProofPolicy, PreparedNativeSingleton, PreparedNativeSingletonAttachment,
        ShakeRequestPlan, ShakeWrapperLayout, ShakeWrapperSpan,
    },
};
use p3_field::PrimeCharacteristicRing;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

fn summary(ordinal: usize, first: usize, count: usize) -> Summary {
    Summary {
        layout: ShakeWrapperLayout::PairedV1,
        ordinal,
        span: ShakeWrapperSpan {
            first_segment: first,
            segment_count: count,
            first_unit: first,
            units: count,
        },
        active_rows: 8,
        padded_rows: 8,
        wires: 1,
        input_values: 1,
        independent_native_verifications: count,
    }
}

#[test]
fn exact_pair_then_tail_sequence_rejects_reordering_gaps_and_overflow() {
    let pair = summary(0, 0, 2);
    let tail = summary(1, 2, 1);
    assert!(consecutive(pair, tail));
    assert!(!consecutive(tail, pair));
    let mut bad = tail;
    bad.layout = ShakeWrapperLayout::Singleton;
    assert!(!consecutive(pair, bad));
    bad = tail;
    bad.ordinal = 2;
    assert!(!consecutive(pair, bad));
    bad = tail;
    bad.span.first_segment = 1;
    assert!(!consecutive(pair, bad));
    bad = tail;
    bad.span.first_unit = 3;
    assert!(!consecutive(pair, bad));
    let mut bad_prior = pair;
    bad_prior.ordinal = usize::MAX;
    assert!(!consecutive(bad_prior, tail));
    bad_prior = pair;
    bad_prior.span.first_unit = usize::MAX;
    assert!(!consecutive(bad_prior, tail));
    bad_prior = pair;
    bad_prior.span.first_segment = usize::MAX;
    assert!(!consecutive(bad_prior, tail));
}

#[test]
fn support_release_matches_actual_original_drops_without_changing_peaks() {
    let ledger = Ledger::new(WorkerAllowance {
        host: 4096,
        device: 4096,
    });
    let retained = ledger
        .reserve(
            Category::RecursiveProof,
            Bytes {
                host: 600,
                device: 0,
            },
        )
        .unwrap();
    let pcs = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: 700,
                device: 900,
            },
        )
        .unwrap();
    let old_wrappers = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: 80,
                device: 0,
            },
        )
        .unwrap();
    let old_report = ledger
        .reserve(
            Category::Report,
            Bytes {
                host: 120,
                device: 0,
            },
        )
        .unwrap();
    let old_metadata = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: 160,
                device: 0,
            },
        )
        .unwrap();
    let next_support = ledger
        .reserve(
            Category::Report,
            Bytes {
                host: 120,
                device: 0,
            },
        )
        .unwrap();
    let before = ledger.snapshot();
    let mut release = old_wrappers.requirements();
    include(&mut release, old_report.requirements()).unwrap();
    include(&mut release, old_metadata.requirements()).unwrap();
    let expected = after_release(before, release).unwrap();
    let wrong_category = Requirements::single(Category::NativeProof, Bytes { host: 1, device: 0 });
    assert!(after_release(before, wrong_category).is_err());
    let excessive_device = Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: 0,
            device: 901,
        },
    );
    assert!(after_release(before, excessive_device).is_err());
    drop(old_wrappers);
    drop(old_report);
    drop(old_metadata);
    assert_eq!(ledger.snapshot(), expected);
    assert_eq!(ledger.snapshot().peak, before.peak);
    drop(next_support);
    drop(retained);
    drop(pcs);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
#[ignore = "exact coordinator serialized genuine outer-retirement restore-only qualifier"]
fn gpu_outer_retirement_restores_original_startup_without_dispatch() {
    for (name, value) in [
        ("LATTICA_OWNED_SHAKE_OUTER_RETIREMENT_QUALIFICATION", "1"),
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
    eprintln!("ringct_outer_retirement_preissued source_bounds_complete=true original_phase_owners_live=true native_dispatch_started=false restored_outer_dispatched=false host_bytes={} device_bytes={}", admitted.current.host, admitted.current.device);
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
    let continued = unsafe { continuation.produce_retaining_outer_originals() }.unwrap();
    let (mut output, originals) = continued.into_parts();
    assert!(retired(originals.runtime.receipt()));
    assert!(originals.runtime.belongs_to(&ledger));
    assert_eq!(
        originals.runtime.startup_requirements(),
        Requirements::single(Category::PhaseScratch, capacity.startup)
    );
    let before_restore = ledger.snapshot();
    let RetiredOuterOriginals {
        runtime,
        request: _,
        completed: _,
        ledger: prior_ledger,
        backend: original_pcs,
        wrappers: outer_wrappers,
        reports: outer_reports,
        planning: outer_planning,
        native_wrappers,
        metadata,
    } = originals;
    // No new planning, source claims, second group, GPU dispatch or preflight.
    // This consumes the actual first outer's sealed retirement and restores
    // only its original pending startup owner under the same process guard.
    let restored = PendingRuntime::restore_retired_outer_host_v1(
        runtime,
        &ledger,
        Limits {
            host_bytes: 32 << 30,
            device_bytes: 8 << 30,
            max_rows: MAX_ROWS,
        },
    )
    .map_err(|(error, _owner)| error)
    .unwrap();
    assert!(restored.belongs_to(&ledger));
    assert_eq!(restored.reserved_bytes(), capacity.startup);
    assert_eq!(restored.reserved_tree_host_bytes(), 8 << 30);
    assert!(original_pcs.belongs_to(&ledger));
    assert_eq!(
        original_pcs.requirements(),
        Requirements::single(Category::PhaseScratch, capacity.pcs)
    );
    assert_eq!(ledger.snapshot(), before_restore);
    eprintln!("ringct_outer_retirement_restored sealed_actual_outer_retirement=true original_startup_restored=true original_pcs_unchanged=true complete_ledger_snapshot_unchanged=true restored_outer_dispatched=false");
    assert!(output.belongs_to(&ledger));
    assert!(output.report().independent_verification_complete);
    recheck.verify_mutations(&mut output, &ledger).unwrap();
    let report = output.report();
    eprintln!("ringct_outer_retirement_singleton native_proofs=1 recursive_proofs=1 fresh_gpu_required=true compiler_backend=cpu public_endpoint_preprocessing=cpu source_preclaims_before_native=true original_runtime_pcs_reused=true attachment_and_bind_ledger_unchanged=true original_outer_startup_restored=true restored_outer_dispatched=false independent_cpu_verified=true mutation_rejections=2 active_rows={} padded_rows={} compiler_ns={} setup_ns={} proving_ns={} cpu_verification_ns={} component_including_mutations_ns={} complete_ringct_workflow=false",
        summary.active_rows, summary.padded_rows, compile_ns,
        report.setup_elapsed_ns.unwrap(), report.proving_elapsed_ns.unwrap(),
        report.cpu_verification_elapsed_ns.unwrap(), started.elapsed().as_nanos());
    drop(restored);
    drop(original_pcs);
    drop(outer_wrappers);
    drop(outer_reports);
    drop(outer_planning);
    drop(prior_ledger);
    drop(native_wrappers);
    drop(metadata);
    drop(output);
    drop(compiled);
    drop(source);
    drop(owner);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!("ringct_outer_retirement_terminal original_quota_released=true restored_outer_dispatched=false complete_ringct_workflow=false");
}
