//! Source-only phase screen for the unchanged active HashX native partition.
//! This test never creates a Runtime, records an AIR, or constructs a proof.
use super::*;
use crate::block_v2::gpu_hash::device::ringct_runtime::Footprint as StartupFootprint;
use crate::block_v2::native_gpu::{
    shake_output::PendingShakeOutput, shake_preparation::ShakePreparationGeometry,
};
use crate::ringct_research_quota::Snapshot;

const INPUT_BYTES: usize = 16_416;
const OUTPUT_BYTES: usize = 137;
const SEGMENTS: usize = 10;
const PERMUTATIONS: [usize; SEGMENTS] = [16, 16, 16, 16, 16, 16, 16, 8, 1, 1];

fn source(index: usize) -> ShakePreparationPlan {
    let first_permutation = PERMUTATIONS[..index].iter().sum();
    let permutations = PERMUTATIONS[index];
    let spec = ShakeTraceSpec {
        input_len: INPUT_BYTES,
        output_len: OUTPUT_BYTES,
        first_permutation,
        permutations,
    };
    if permutations == 1 {
        ShakePreparationPlan::singleton(spec)
    } else {
        ShakePreparationPlan::batch(spec)
    }
    .expect("unchanged active HashX source geometry")
}

fn preparation_claim(source: ShakePreparationPlan) -> Requirements {
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source
        .host()
        .required_host_bytes()
        .checked_sub(symbolic)
        .and_then(|n| {
            n.checked_add(crate::block_v2::native_gpu::shake_recording::additional_host_bytes())
        })
        .unwrap();
    let mut result = Requirements::single(
        Category::SymbolicCompiler,
        Bytes {
            host: symbolic as u64,
            device: 0,
        },
    );
    result
        .add(
            Category::PhaseScratch,
            Bytes {
                host: other as u64,
                device: 0,
            },
        )
        .unwrap();
    result
}

fn fixture_host_bytes() -> usize {
    // Full owning arrays, results, return/forwarding slots and diagnostics are
    // charged before the source catalogue, captured selection or PCS planner.
    // Fixed source/planner error strings and selected environment values have
    // a separately counted 16 KiB ceiling under the exact env-clear guard.
    let mut bytes = 4usize.checked_mul(4096).unwrap();
    for item in [
        4 * size_of::<[Option<PendingShakeOutput>; SEGMENTS]>(),
        4 * size_of::<[ShakePreparationPlan; SEGMENTS]>(),
        4 * size_of::<[Option<NativeShakePcsFootprint>; SEGMENTS]>(),
        8 * size_of::<ShakePreparationPlan>(),
        8 * size_of::<ShakePreparationGeometry>(),
        8 * size_of::<ShakeTraceSpec>(),
        8 * size_of::<ShakeOutputPlan>(),
        8 * size_of::<PendingShakeOutput>(),
        8 * size_of::<
            core::result::Result<ShakeOutputPlan, crate::block_v2::native_gpu::shake_output::Error>,
        >(),
        8 * size_of::<
            core::result::Result<
                PendingShakeOutput,
                crate::block_v2::native_gpu::shake_output::Error,
            >,
        >(),
        8 * size_of::<
            core::result::Result<
                ShakePreparationPlan,
                crate::block_v2::native_gpu::shake_preparation::Error,
            >,
        >(),
        8 * size_of::<NativeShakePcsPlan>(),
        8 * size_of::<NativeShakePcsFootprint>(),
        8 * size_of::<core::result::Result<NativeShakePcsPlan, String>>(),
        8 * size_of::<RegisteredGpuLimits>(),
        8 * size_of::<core::result::Result<RegisteredGpuLimits, String>>(),
        8 * size_of::<StartupPlan>(),
        8 * size_of::<StartupFootprint>(),
        16 * size_of::<Ledger>(),
        16 * size_of::<Reservation>(),
        16 * size_of::<Requirements>(),
        16 * size_of::<Bytes>(),
        16 * size_of::<Snapshot>(),
        8 * size_of::<core::result::Result<Reservation, crate::ringct_research_quota::Error>>(),
        8 * size_of::<core::result::Result<Requirements, crate::ringct_research_quota::Error>>(),
        8 * size_of::<core::result::Result<Bytes, crate::ringct_research_quota::Error>>(),
        8 * size_of::<String>(),
        8 * size_of::<std::env::VarError>(),
        8 * size_of::<std::fmt::Arguments<'static>>(),
        256 * size_of::<usize>(),
    ] {
        bytes = bytes.checked_add(item).unwrap();
    }
    bytes
}

#[test]
#[ignore = "source-only active HashX phase preflight; exact immutable env-clear serialized RTX 5080 guard"]
fn active_hashx_native_shapes_have_bounded_source_preflight() {
    let ledger = ledger();
    let fixture = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: fixture_host_bytes() as u64,
                device: 0,
            },
        )
        .unwrap();
    for (name, expected) in [
        ("LATTICA_OWNED_NATIVE_SHAKE_SHAPE_PREFLIGHT", "1"),
        ("LATTICA_PROVING_POLICY", "gpu-required"),
        ("LATTICA_V2_GPU_RETAINED_TREE_STORAGE", "host"),
        ("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES", "8589934592"),
        ("LATTICA_V2_HOST_OUTPUT_BYTES", "25769803776"),
    ] {
        assert_eq!(std::env::var(name).as_deref(), Ok(expected));
    }

    let sources: [ShakePreparationPlan; SEGMENTS] = core::array::from_fn(source);
    let preparation_requirements = preparation_claim(sources[0]);
    for (index, planned) in sources.iter().enumerate() {
        let geometry = planned.geometry();
        assert_eq!(geometry.input_len(), INPUT_BYTES);
        assert_eq!(geometry.output_len(), OUTPUT_BYTES);
        assert_eq!(geometry.permutations(), PERMUTATIONS[index]);
        assert_eq!(
            geometry.first_permutation(),
            PERMUTATIONS[..index].iter().sum::<usize>()
        );
        assert_eq!(geometry.rows(), 4096 * PERMUTATIONS[index]);
        assert_eq!(
            geometry.width(),
            if PERMUTATIONS[index] == 1 { 517 } else { 518 }
        );
        // This is an eligibility check for a future workspace, not permission
        // to move one token between phases after native proving has started.
        assert_eq!(preparation_claim(*planned), preparation_requirements);
    }
    assert_eq!(sources[7].geometry().first_permutation(), 112);
    assert_eq!(sources[8].geometry().first_permutation(), 120);
    assert_eq!(sources[9].geometry().first_permutation(), 121);
    assert_eq!(PERMUTATIONS.iter().sum::<usize>(), 122);

    let preparation = ledger.admit_phase(preparation_requirements).unwrap();
    let mut outputs: [Option<PendingShakeOutput>; SEGMENTS] = core::array::from_fn(|_| None);
    for (slot, &planned) in outputs.iter_mut().zip(&sources) {
        let output = ShakeOutputPlan::new(planned).unwrap();
        let proof = ledger.admit_phase(output.proof_requirement()).unwrap();
        let report = ledger.admit_phase(output.report_requirement()).unwrap();
        *slot = Some(output.claim(proof, report, &ledger).unwrap());
    }
    let verifier = ledger
        .reserve(
            Category::IndependentVerifier,
            Bytes {
                host: VERIFIER_HOST,
                device: 0,
            },
        )
        .unwrap();
    let startup_plan = StartupPlan::outer_host_v1().unwrap();
    let startup_footprint = startup_plan.footprint();
    assert_eq!(startup_footprint.retained_tree_host_bytes, 8 << 30);
    assert_eq!(
        startup_footprint.driver_context_reserve,
        CONTEXT_DEVICE as usize
    );
    let startup = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: startup_footprint.requested_host_bytes as u64,
                device: startup_footprint.managed_device_bytes as u64,
            },
        )
        .unwrap();
    let wrappers = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: TreeProfile::OuterHostV1.phase_wrapper_host_bytes().unwrap() as u64,
                device: 0,
            },
        )
        .unwrap();
    let operation_host = operation_host_budget(&ledger).unwrap();
    let pcs = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: operation_host as u64,
                device: MANAGED_DEVICE
                    .checked_sub(startup_footprint.managed_device_bytes as u64)
                    .unwrap(),
            },
        )
        .unwrap();
    let admitted = ledger.snapshot();
    assert!(admitted.current.host <= WORKER_HOST);
    assert_eq!(admitted.current.device, MANAGED_DEVICE);
    assert_eq!(
        operation_host as u64,
        pcs.requirements().get(Category::PhaseScratch).host
    );

    // Capture the physical selector exactly once while all source/claim
    // owners exist. This enumerates devices but creates no context or queue.
    let limits = RegisteredGpuLimits::new(WORKER_HOST, MANAGED_DEVICE, CONTEXT_DEVICE, MAX_ROWS)
        .expect("captured physical selection under exact source-preflight guard");
    eprintln!("active_hashx_source_preflight schema=1 scope=source_phase_only native_count=10 paired_group_count=5 input_bytes={INPUT_BYTES} output_bytes={OUTPUT_BYTES} operation_host_bytes={operation_host} worker_host_bytes={WORKER_HOST} managed_device_bytes={MANAGED_DEVICE} context_device_bytes={CONTEXT_DEVICE} native_host_ceiling_bytes={NATIVE_HOST} max_rows={MAX_ROWS} cryptographic_proof_started=false");
    eprintln!("active_hashx_source_preflight_limits {limits:?}");
    eprintln!("active_hashx_source_preflight_startup {startup_footprint:?}");
    eprintln!("active_hashx_source_preflight_preparation {preparation_requirements:?}");
    eprintln!("active_hashx_source_preflight_admitted {admitted:?}");

    let mut footprints: [Option<NativeShakePcsFootprint>; SEGMENTS] = [None; SEGMENTS];
    let mut refused = 0usize;
    for (index, planned) in sources.iter().enumerate() {
        let geometry = planned.geometry();
        // Every exact plan is constructed before any possible proof. All ten
        // output/report claims and the original common scratch remain live.
        let result =
            NativeShakePcsPlan::new(geometry.rows(), geometry.width(), operation_host, limits);
        match result {
            Ok(plan) => {
                let footprint = plan.footprint();
                TreeProfile::OuterHostV1.check_plan(footprint).unwrap();
                assert!(footprint.maintained_device_plan_complete);
                assert!(!footprint.complete_native_dispatch_admission);
                assert_eq!(footprint.operation_host_budget_bytes, operation_host);
                assert_eq!(
                    footprint.managed_phase_ceiling_bytes,
                    MANAGED_DEVICE as usize
                );
                assert_eq!(
                    footprint.fresh_runtime_baseline_bytes,
                    startup_footprint.managed_device_bytes
                );
                assert!(footprint.required_pcs_host_bytes <= operation_host);
                assert!(footprint.maintained_phase_peak_bytes <= MANAGED_DEVICE as usize);
                footprints[index] = Some(footprint);
                eprintln!("active_hashx_source_preflight_shape index={index} first_permutation={} permutations={} admitted=true footprint={footprint:?}", geometry.first_permutation(), geometry.permutations());
                drop(plan);
            }
            Err(error) => {
                refused += 1;
                assert!(
                    error.len() <= 4096,
                    "source planner diagnostic exceeds counted bound"
                );
                eprintln!("active_hashx_source_preflight_shape index={index} first_permutation={} permutations={} rows={} width={} admitted=false refusal={error}", geometry.first_permutation(), geometry.permutations(), geometry.rows(), geometry.width());
                drop(error);
            }
        }
        assert_eq!(ledger.snapshot(), admitted);
    }
    // These source plans never become executable owners. No claimed scratch
    // is recycled, no runtime is fabricated, and no failure is retried.
    drop(footprints);
    drop(pcs);
    drop(wrappers);
    drop(startup);
    drop(verifier);
    drop(outputs);
    drop(preparation);
    drop(fixture);
    let terminal = ledger.snapshot();
    assert_eq!(terminal.current, Bytes::ZERO);
    assert!(terminal
        .categories
        .iter()
        .all(|category| category.current == Bytes::ZERO));
    eprintln!("active_hashx_source_preflight_terminal screened=10 admitted={} refused={refused} phase_feasibility={} complete_request_admission=false cryptographic_proof_started=false terminal={terminal:?}", SEGMENTS - refused, refused == 0);
    // Refusal is valid screen evidence. The coordinator must read the explicit
    // phase_feasibility flag; a successful test exit alone does not mean fit.
}
