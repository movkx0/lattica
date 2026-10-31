//! Exact test-only post-configuration refusal through real continuation owners.
//! No alternate AIR or failure callback is exposed by the production producer.
use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Policy, ShakeRequestPlan},
    opencl::RuntimeError,
};
use lattica_prover_p3::block_v2::{
    gpu_hash::device::ringct_runtime::RetiredRuntime,
    native_gpu::{
        owned_shake::Error as NativeError,
        shake_recording::{PreparedShake, ShakeRecorder},
    },
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;

struct DegreeEight;
impl BaseAir<Val> for DegreeEight {
    fn width(&self) -> usize {
        517
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        42
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for DegreeEight {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let value: AB::Expr = main.current_slice()[0].into();
        // The actual normalized degree is eight. Unchanged native metadata
        // permits seven and must refuse after the real config/session exists.
        builder.assert_zero(value.square().square().square());
    }
}

fn record_refusal<'claim>(
    preparation: &'claim mut PendingNativePreparation<'_>,
    ledger: &'claim Ledger,
) -> PreparedShake<'claim> {
    let census = preparation.census();
    assert_eq!(census.geometry().width(), 517);
    assert_eq!(census.geometry().periodic_columns(), 42);
    assert_eq!(census.geometry().permutations(), 1);
    let mut recorder = ShakeRecorder::begin(census, &mut preparation.reservation, ledger).unwrap();
    DegreeEight.eval(recorder.builder_mut());
    for index in 0..42 {
        recorder.periodic_column_mut(index).unwrap();
    }
    recorder.finish().unwrap()
}

fn without_released(mut before: Snapshot, released: Requirements) -> Snapshot {
    let total = released.total().unwrap();
    before.current.host = before.current.host.checked_sub(total.host).unwrap();
    before.current.device = before.current.device.checked_sub(total.device).unwrap();
    for category in Category::ALL {
        let bytes = released.get(category);
        let current = &mut before.categories[category as usize].current;
        current.host = current.host.checked_sub(bytes.host).unwrap();
        current.device = current.device.checked_sub(bytes.device).unwrap();
    }
    before
}

#[test]
#[ignore = "exact immutable host continuation rejection guard; dedicated serialized RTX 5080 worker only"]
fn gpu_owned_host_continuation_normalization_rejection_retires_originals() {
    for (name, value) in [
        (
            "LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_REJECTION_QUALIFICATION",
            "1",
        ),
        ("LATTICA_PROVING_POLICY", "gpu-required"),
        ("LATTICA_V2_GPU_RETAINED_TREE_STORAGE", "host"),
        ("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES", "8589934592"),
    ] {
        assert_eq!(std::env::var(name).as_deref(), Ok(value));
    }
    let ledger = Ledger::new(WorkerAllowance {
        host: HOST_BYTES,
        device: DEVICE_BYTES,
    });
    // All extra fixture records/moves precede request/source/recorder/runtime
    // construction. Recorder/config allocations retain the original complete
    // source partitions from the genuine singleton preparation constructor.
    let fixture = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: (16 * size_of::<Snapshot>()
                    + 14 * size_of::<Requirements>()
                    + 16 * size_of::<Reservation>()
                    + 4 * size_of::<RetiredNativeReservations>()
                    + 4 * size_of::<std::result::Result<OwnedShakeProof, NativeError>>()
                    + 4 * size_of::<crate::opencl::Session>()
                    + 4 * size_of::<PendingNativePreparation<'static>>()
                    + 4 * size_of::<PreparedShake<'static>>()
                    + 4 * size_of::<ShakeRecorder<'static>>()
                    + 4 * size_of::<ShakeOutputPlan>()
                    + 4 * size_of::<RetiredRuntime>()
                    + 4 * size_of::<PendingRuntime>()
                    + 4 * size_of::<
                        std::result::Result<PendingRuntime, (RuntimeError, RetiredRuntime)>,
                    >()
                    + 2 * size_of::<Limits>()
                    + 4 * size_of::<std::fmt::Arguments<'static>>()
                    + 2 * size_of::<OuterContinuationCapacity>()
                    + 2 * size_of::<Ledger>()
                    + 2 * size_of::<DegreeEight>()
                    + 2 * size_of::<[u8; 1]>()) as u64,
                device: 0,
            },
        )
        .unwrap();
    let input = [1u8];
    let plan = ShakeRequestPlan::new([95; 32], 8, 0, &input, 1, Policy::default()).unwrap();
    let request = ledger.admit_phase(plan.requirements()).unwrap();
    let owner = plan.construct(request, &ledger).unwrap();
    // SAFETY: exact guard retains the immutable host profile and exclusive
    // physical device through actual runtime retirement and every owner drop.
    let prepared =
        unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &ledger) }.unwrap();
    let capacity = prepared.outer_continuation_capacity().unwrap();
    let output_plan = ShakeOutputPlan::new(prepared.preparation.census()).unwrap();
    let mut output_claims = output_plan.proof_requirement();
    include(&mut output_claims, output_plan.report_requirement()).unwrap();
    let PreparedNativeSingleton {
        owner: _,
        index: _,
        mut phase,
        mut preparation,
        runtime,
        verifier,
        verification,
        ledger: phase_ledger,
        bookkeeping,
    } = prepared;
    let admitted = ledger.snapshot();
    assert_eq!(admitted.current.device, DEVICE_BYTES);
    // Session is declared after all backing owners, so unexpected unwinding
    // still destroys its actual runtime before any original claim can drop.
    let session = unsafe { runtime.start() }.unwrap();
    let attempted = {
        let checked = session.check_reserved_runtime(&ledger).unwrap();
        let runtime = checked.borrow_core().unwrap();
        let recording = record_refusal(&mut preparation, &ledger);
        // SAFETY: the test alone substitutes the fixed, bounded degree-eight
        // recording under the actual original singleton source owners. It must
        // be rejected; no callback or alternate AIR enters a production API.
        unsafe {
            phase.produce(
                recording,
                &input,
                runtime.runtime(),
                runtime.reservation(),
                &verification,
            )
        }
    };
    // Never retry or admit again after the attempt. Retire the actual private
    // Session pair before checking any success/refusal assertions.
    let retired = session.finish_reserved_with_owner(&ledger).unwrap();
    let retirement = retired.receipt();
    assert_eq!(ledger.snapshot(), admitted);
    assert!(retirement_is_complete(retirement));
    assert!(retirement.managed_peak_bytes as u64 <= DEVICE_BYTES);
    assert!(phase.attempted());
    assert!(matches!(&attempted, Err(NativeError::Normalization)));
    drop(attempted);
    // The native phase's private Weak still identifies this exact retired
    // runtime. A032's outer-only bridge must preserve the complete seal and
    // refuse; a later native extraction is not a proof retry or readmission.
    assert!(retired.belongs_to(&ledger));
    let startup = retired.startup_requirements();
    assert_eq!(
        startup,
        Requirements::single(Category::PhaseScratch, capacity.startup)
    );
    let before_outer_refusal = ledger.snapshot();
    let retired = match PendingRuntime::restore_retired_outer_host_v1(
        retired,
        &ledger,
        Limits {
            host_bytes: HOST_BYTES,
            device_bytes: DEVICE_BYTES,
            max_rows: MAX_ROWS,
        },
    ) {
        Err((RuntimeError::Lifecycle, retired)) => retired,
        Err((_, retired)) => {
            drop(retired);
            panic!("outer-only bridge refused before its native-binding check");
        }
        Ok(pending) => {
            drop(pending);
            panic!("outer-only bridge accepted a surviving native phase binding");
        }
    };
    assert_eq!(ledger.snapshot(), before_outer_refusal);
    assert_eq!(retired.startup_requirements(), startup);
    assert!(retired.belongs_to(&ledger));
    assert_eq!(retired.receipt(), retirement);
    let originals = match phase.into_retired_reservations(retired, &ledger) {
        Ok(originals) => originals,
        Err((_, phase, retired)) => {
            drop(phase);
            drop(retired);
            panic!("actual post-bind refusal did not preserve retired originals");
        }
    };
    assert!(originals.belongs_to(&ledger));
    assert_eq!(originals.retirement(), retirement);
    assert_eq!(
        originals.startup_requirements(),
        Requirements::single(Category::PhaseScratch, capacity.startup)
    );
    // Failed production leaves an untouched pending proof/report slot. Exact
    // extraction destroys that slot, so only its two claims leave current
    // accounting; every category and aggregate historical peak is unchanged.
    assert_eq!(ledger.snapshot(), without_released(admitted, output_claims));
    assert_eq!(ledger.snapshot().current.device, DEVICE_BYTES);
    eprintln!(
        "ringct_owned_native_continuation_rejection failure_stage=normalization actual_configuration_completed=true private_trace_started=false proof_produced=false retry_attempted=false readmission_after_attempt=false original_retirement_snapshot_unchanged=true outer_only_restore_refused=true native_binding_retained=true outer_refusal_snapshot_unchanged=true extraction_delta_only_pending_proof_report=true peaks_unchanged=true managed_live_bytes=0 host_tree_live_bytes=0 lease_released=true retained_managed_claim_bytes={} managed_peak_bytes={} high_level_producer_qualified=false async_failure_qualified=false complete_ringct_workflow=false",
        ledger.snapshot().current.device,
        retirement.managed_peak_bytes,
    );
    drop(verifier);
    drop(preparation);
    drop(verification);
    drop(bookkeeping);
    drop(phase_ledger);
    drop(originals);
    drop(owner);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!(
        "ringct_owned_native_continuation_rejection_terminal original_quota_released=true actual_runtime_retired=true proof_produced=false complete_ringct_workflow=false"
    );
}
