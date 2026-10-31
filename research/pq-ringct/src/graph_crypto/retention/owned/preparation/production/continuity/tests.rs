use super::*;
use crate::{
    execution::retained_resources::{Snapshot, WorkerAllowance},
    graph_crypto::{Policy, ShakeRequestPlan},
};
use p3_field::PrimeCharacteristicRing;

#[test]
#[ignore = "exact immutable host continuation selector/guard; dedicated RTX 5080 serialized worker only"]
fn gpu_owned_host_continuations_preserve_originals_verify_mutations_and_retire() {
    for (name, value) in [
        ("LATTICA_OWNED_NATIVE_SHAKE_CONTINUATION_QUALIFICATION", "1"),
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
    let fixture = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: (12 * size_of::<Snapshot>()
                    + 8 * size_of::<Requirements>()
                    + 10 * size_of::<Reservation>()
                    + 2 * size_of::<RetiredNativeReservations>()
                    + 2 * size_of::<PendingRuntime>()
                    + 2 * size_of::<std::time::Instant>()
                    + 2 * size_of::<Option<[Val; PUBLIC_VALUES]>>()
                    + 2 * size_of::<[u8; 1]>()) as u64,
                device: 0,
            },
        )
        .unwrap();
    let baseline = ledger.snapshot().current;
    let mut previous = None;
    for byte in [1, 2] {
        let input = [byte];
        let plan = ShakeRequestPlan::new([94; 32], 7, 0, &input, 1, Policy::default()).unwrap();
        let request = ledger.admit_phase(plan.requirements()).unwrap();
        let owner = plan.construct(request, &ledger).unwrap();
        let started = std::time::Instant::now();
        let adapter =
            PreparedNativeSingletonAttachment::reserve_before_native(&owner, 0, &ledger).unwrap();
        let mutation_verifier = ledger
            .admit_phase(VerificationPlan::component_requirement())
            .unwrap();
        let child_verifier = ledger
            .admit_phase(VerificationPlan::component_requirement())
            .unwrap();
        // SAFETY: exact dedicated guard holds the complete immutable profile
        // through original runtime retirement and every retained claim drop.
        let prepared =
            unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &ledger) }.unwrap();
        let before_capacity = ledger.snapshot();
        let capacity = prepared.outer_continuation_capacity().unwrap();
        assert_eq!(ledger.snapshot(), before_capacity);
        assert_eq!(capacity.startup, prepared.runtime.reserved_bytes());
        assert_eq!(capacity.retained_tree_host_bytes, 8 << 30);
        assert_eq!(capacity.startup.device + capacity.pcs.device, DEVICE_BYTES);
        let startup_requirement = Requirements::single(Category::PhaseScratch, capacity.startup);
        // SAFETY: same original process/device exclusivity contract.
        let continued = unsafe { prepared.produce_retaining_originals() }.unwrap();
        let before_move = ledger.snapshot();
        let (produced, originals) = continued.into_parts();
        assert_eq!(ledger.snapshot(), before_move);
        assert!(produced.is_for(&owner, 0, &ledger));
        assert!(originals.belongs_to(&ledger));
        assert!(retirement_is_complete(originals.retirement()));
        // Real runtime storage is gone; the original managed claim is retained
        // for the next preplanned phase. It must not appear as fresh GPU work.
        assert_eq!(ledger.snapshot().current.device, DEVICE_BYTES);
        if let Some(previous) = previous {
            assert_ne!(previous, produced.artifact().public_values);
        }
        previous = Some(produced.artifact().public_values);
        eprint!("proving_stage_report ");
        serde_json::to_writer(std::io::stderr().lock(), produced.report()).unwrap();
        eprintln!();
        let air = &owner.request().shake_partition().unwrap().segments()[0];
        let mut changed = Vec::new();
        changed.try_reserve_exact(PUBLIC_VALUES).unwrap();
        assert_eq!(changed.capacity(), PUBLIC_VALUES);
        changed.extend_from_slice(&produced.artifact().public_values);
        changed[0] += Val::ONE;
        let rejection = VerificationPlan::new(air)
            .unwrap()
            .admit_pre_reserved(
                air,
                &produced.artifact().proof,
                &changed,
                produced.output.proof_reservation(),
                mutation_verifier,
                &ledger,
            )
            .unwrap()
            .verify();
        assert!(matches!(
            &rejection,
            Err(VerificationFailure::InvalidProof(_))
        ));
        drop(rejection);
        drop(changed);
        let before_attachment = ledger.snapshot();
        let child = adapter.attach(produced, &ledger).unwrap();
        assert_eq!(ledger.snapshot(), before_attachment);
        child.verify_pre_reserved(child_verifier, &ledger).unwrap();
        let before_transfer = ledger.snapshot();
        assert_eq!(originals.startup_requirements(), startup_requirement);
        let (restored, wrappers, pcs) = match PendingRuntime::restore_outer_host_v1(
            originals,
            &ledger,
            Limits {
                host_bytes: HOST_BYTES,
                device_bytes: DEVICE_BYTES,
                max_rows: MAX_ROWS,
            },
        ) {
            Ok(restored) => restored,
            Err(_) => panic!("retired original host startup was not preserved"),
        };
        assert_eq!(ledger.snapshot(), before_transfer);
        assert_eq!(restored.reserved_bytes(), capacity.startup);
        assert_eq!(
            pcs.requirements(),
            Requirements::single(Category::PhaseScratch, capacity.pcs)
        );
        let wrapper_requirement = wrappers.requirements();
        let mut phase = wrappers.reunite(pcs).unwrap();
        assert_eq!(ledger.snapshot(), before_transfer);
        let wrappers = phase.split(wrapper_requirement).unwrap();
        assert_eq!(ledger.snapshot(), before_transfer);
        let phase = phase.reunite(wrappers).unwrap();
        assert_eq!(ledger.snapshot(), before_transfer);
        assert!(restored.belongs_to(&ledger));
        assert_eq!(restored.reserved_tree_host_bytes(), 8 << 30);
        eprintln!(
            "ringct_owned_native_continuation_case input_byte={byte} fresh_gpu_required=true independent_cpu_verified=true mutation_rejected=true child_cpu_verified=true exact_originals_retained=true transfer_ledger_unchanged=true declared_original_capacity_matched=true source_runtime_restored=true restored_runtime_dispatched=false managed_live_bytes=0 host_tree_live_bytes=0 lease_released=true retained_managed_claim_bytes={} component_including_mutation_attachment_transfer_ns={} complete_ringct_workflow=false",
            ledger.snapshot().current.device,
            started.elapsed().as_nanos()
        );
        drop(restored);
        drop(phase);
        drop(child);
        drop(owner);
        assert_eq!(ledger.snapshot().current, baseline);
    }
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!(
        "ringct_owned_native_continuation_terminal original_quota_released=true complete_ringct_workflow=false"
    );
}
