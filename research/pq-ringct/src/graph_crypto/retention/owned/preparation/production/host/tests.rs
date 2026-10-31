use super::super::{
    Bytes, Category, PUBLIC_VALUES, PreparedNativeSingletonAttachment, Requirements,
    Reservation, Val, VerificationFailure, VerificationPlan, VerificationReceipt,
    retirement_is_complete, size_of,
};
use super::*;
use crate::{
    execution::retained_resources::{Snapshot, WorkerAllowance},
    graph_crypto::{Policy, ShakeRequestPlan},
};
use lattica_prover_p3::block_v2::gpu_hash::device::ringct_runtime::StartupPlan;
use p3_field::PrimeCharacteristicRing;

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host,
        device: DEVICE_BYTES,
    })
}

fn limits() -> Limits {
    Limits {
        host_bytes: HOST_BYTES,
        device_bytes: DEVICE_BYTES,
        max_rows: MAX_ROWS,
    }
}

fn owned(ledger: &Ledger, byte: u8) -> ReservedShakeRequest {
    let input = [byte];
    let plan = ShakeRequestPlan::new([92; 32], 5, 0, &input, 1, Policy::default()).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(token, ledger).unwrap()
}

#[test]
fn original_host_startup_is_additive_and_reduces_native_pcs_room() {
    let ledger = ledger(HOST_BYTES);
    let owner = owned(&ledger, 1);
    let source = SourcePlan::new(&owner, 0).unwrap();
    let original = ledger.admit_phase(source.requirements).unwrap();
    let claimed = source.claim_for(&owner, 0, original, &ledger).unwrap();
    let source_baseline = ledger.snapshot().current;
    let device = PendingRuntime::reserve(&ledger, limits()).unwrap();
    let device_bytes = device.reserved_bytes();
    assert_eq!(device.reserved_tree_host_bytes(), 0);
    drop(device);
    assert_eq!(ledger.snapshot().current, source_baseline);

    let host = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    let host_bytes = host.reserved_bytes();
    let footprint = StartupPlan::outer_host_v1().unwrap().footprint();
    assert!(host.belongs_to(&ledger));
    assert_eq!(host.reserved_tree_host_bytes(), HOST_TREE_BYTES);
    assert!(footprint.retained_tree_quota_wrapper_bytes > 0);
    assert_eq!(
        host_bytes.host - device_bytes.host,
        HOST_TREE_BYTES + footprint.retained_tree_quota_wrapper_bytes as u64
    );
    assert_eq!(host_bytes.device, device_bytes.device);
    assert_eq!(
        ledger.snapshot().current.host,
        source_baseline.host + host_bytes.host
    );
    assert_eq!(
        ledger.remaining().host,
        HOST_BYTES - source_baseline.host - host_bytes.host
    );
    assert!(ledger.remaining().host < 24 << 30);
    assert_eq!(
        ledger.remaining().device,
        DEVICE_BYTES - source_baseline.device - host_bytes.device
    );
    drop(host);
    assert_eq!(ledger.snapshot().current, source_baseline);
    drop(claimed);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn host_startup_one_byte_short_refuses_before_preflight_and_releases_source() {
    let generous = ledger(HOST_BYTES);
    let owner = owned(&generous, 2);
    let request_bytes = generous.snapshot().current.host;
    let source_bytes = SourcePlan::new(&owner, 0)
        .unwrap()
        .requirements
        .total()
        .unwrap()
        .host;
    let runtime = PendingRuntime::reserve_outer_host_v1(&generous, limits()).unwrap();
    let runtime_bytes = runtime.reserved_bytes().host;
    drop(runtime);
    drop(owner);
    assert_eq!(generous.snapshot().current, Bytes::ZERO);

    let short = ledger(request_bytes + source_bytes + runtime_bytes - 1);
    let owner = owned(&short, 2);
    let before = short.snapshot();
    // SAFETY: the exact source census leaves the original host startup one
    // byte short, so reserve fails before environment/device preflight.
    let result = unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &short) };
    assert!(matches!(&result, Err(Error::Runtime)));
    drop(result);
    let after = short.snapshot();
    assert_eq!(after.current, before.current);
    assert_eq!(after.allowance, before.allowance);
    // Source admission succeeded before runtime admission refused. Releasing
    // the original source owner restores current usage, not its peak history.
    let source = SourcePlan::new(&owner, 0).unwrap().requirements;
    for category in Category::ALL {
        let actual = after.categories[category as usize];
        let previous = before.categories[category as usize];
        let admitted = source.get(category);
        assert_eq!(actual.current, previous.current);
        assert_eq!(
            actual.peak.host,
            previous
                .peak
                .host
                .max(previous.current.host + admitted.host)
        );
        assert_eq!(
            actual.peak.device,
            previous
                .peak
                .device
                .max(previous.current.device + admitted.device)
        );
    }
    assert_eq!(
        after.peak.host,
        before.peak.host.max(before.current.host + source_bytes)
    );
    assert_eq!(after.peak.device, before.peak.device);
    drop(owner);
    assert_eq!(short.snapshot().current, Bytes::ZERO);
}

#[test]
fn host_component_rejects_foreign_ledger_and_source_index_before_preflight() {
    let ledger = ledger(HOST_BYTES);
    let unrelated = self::ledger(HOST_BYTES);
    let owner = owned(&ledger, 3);
    let before = ledger.snapshot();
    // SAFETY: original-ledger rejection is the first source-only check.
    assert!(matches!(
        unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &unrelated) },
        Err(Error::Authority)
    ));
    // SAFETY: the invalid source index is rejected before runtime admission.
    assert!(matches!(
        unsafe {
            PreparedNativeSingleton::new_outer_host_v1(
                &owner,
                owner.request().segments().len(),
                &ledger,
            )
        },
        Err(Error::Source)
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn retained_future_phase_claims_reduce_room_before_original_host_startup() {
    let ledger = ledger(HOST_BYTES);
    let owner = owned(&ledger, 4);
    let source = SourcePlan::new(&owner, 0).unwrap();
    let original = ledger.admit_phase(source.requirements).unwrap();
    let claimed = source.claim_for(&owner, 0, original, &ledger).unwrap();
    // This sentinel checks composition in the original ledger; it is not a
    // native-to-outer planner or authority for the future recursive workload.
    let retained = ledger
        .reserve(
            Category::RecursiveProof,
            Bytes {
                host: 64 << 20,
                device: 0,
            },
        )
        .unwrap();
    let before = ledger.remaining();
    let runtime = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    assert_eq!(
        ledger.remaining().host,
        before.host - runtime.reserved_bytes().host
    );
    assert_eq!(
        ledger.remaining().device,
        before.device - runtime.reserved_bytes().device
    );
    assert!(retained.belongs_to(&ledger));
    drop(runtime);
    assert_eq!(ledger.remaining(), before);
    drop(retained);
    drop(claimed);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
#[ignore = "dedicated immutable outer_host_v1 RTX 5080 worker; exact coordinator selector/process guard only"]
fn gpu_owned_host_singletons_prove_fresh_verify_mutation_and_retire_original_owners() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_NATIVE_SHAKE_HOST_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    assert_eq!(
        std::env::var("LATTICA_V2_GPU_RETAINED_TREE_STORAGE").as_deref(),
        Ok("host")
    );
    assert_eq!(
        std::env::var("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES").as_deref(),
        Ok("8589934592")
    );
    struct FixtureState {
        previous_public: Option<[Val; PUBLIC_VALUES]>,
    }
    let ledger = ledger(HOST_BYTES);
    let fixture_token = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: (2 * size_of::<FixtureState>()
                    + size_of::<[u8; 1]>()
                    + size_of::<std::time::Instant>()
                    + 8 * size_of::<Snapshot>()
                    + 4 * size_of::<Reservation>()
                    + 4 * size_of::<Requirements>()
                    + 2 * size_of::<VerificationReceipt>()) as u64,
                device: 0,
            },
        )
        .unwrap();
    let mut fixture = FixtureState {
        previous_public: None,
    };
    let fixture_baseline = ledger.snapshot().current;
    for byte in [1, 2] {
        let owner = owned(&ledger, byte);
        let component_started = std::time::Instant::now();
        // Original adapter/key and both additional verifier owners precede
        // native preparation, so the native PCS sees their retained charges.
        let attachment =
            PreparedNativeSingletonAttachment::reserve_before_native(&owner, 0, &ledger)
                .unwrap();
        let mutation_verifier = ledger
            .admit_phase(VerificationPlan::component_requirement())
            .unwrap();
        let child_verifier = ledger
            .admit_phase(VerificationPlan::component_requirement())
            .unwrap();
        // SAFETY: the exact ignored-test coordinator guard holds the complete
        // immutable host profile and excludes unrelated work through cleanup.
        let prepared =
            unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &ledger) }.unwrap();
        // SAFETY: the same exact process contract remains in force.
        let produced = unsafe { prepared.produce() }.unwrap();
        assert!(produced.is_for(&owner, 0, &ledger));
        assert!(retirement_is_complete(produced.retirement()));
        assert!((1..=DEVICE_BYTES as usize).contains(&produced.retirement().managed_peak_bytes));
        assert!(produced.verification().proof_backing_bytes > 0);
        assert_eq!(ledger.snapshot().current.device, 0);
        {
            let report = serde_json::to_string(produced.report()).unwrap();
            eprintln!("proving_stage_report {report}");
        }
        if let Some(previous) = fixture.previous_public {
            assert_ne!(previous, produced.artifact().public_values);
        }
        fixture.previous_public = Some(produced.artifact().public_values);
        let air = &owner.request().shake_partition().unwrap().segments()[0];
        let verifier = VerificationPlan::new(air).unwrap();
        let mut changed = Vec::new();
        changed.try_reserve_exact(PUBLIC_VALUES).unwrap();
        assert_eq!(changed.capacity(), PUBLIC_VALUES);
        changed.extend_from_slice(&produced.artifact().public_values);
        changed[0] += Val::ONE;
        let rejection = verifier
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
        eprintln!(
            "ringct_owned_native_host_singleton_case input_byte={byte} tree_profile=outer_host_v1 fresh_gpu_required=true independent_cpu_verified=true mutation_rejected=true managed_live_bytes=0 host_tree_live_bytes=0 lease_released=true managed_peak_bytes={} component_including_mutation_ns={} native_report_ns={} complete_ringct_workflow=false",
            produced.retirement().managed_peak_bytes,
            component_started.elapsed().as_nanos(),
            produced.report().elapsed_ns
        );
        // Moving the intact original owner into the compiler child creates
        // no admission, release, proof/report copy or replacement authority.
        let before_attachment = ledger.snapshot();
        let child = attachment.attach(produced, &ledger).unwrap();
        assert_eq!(ledger.snapshot(), before_attachment);
        assert!(child.is_for(owner.request(), 0, &ledger));
        assert_eq!(
            Some(child.shake_artifact().public_values),
            fixture.previous_public
        );
        let receipt = child.verify_pre_reserved(child_verifier, &ledger).unwrap();
        assert!(receipt.proof_backing_bytes > 0);
        eprintln!(
            "ringct_owned_native_host_child_case input_byte={byte} tree_profile=outer_host_v1 preissued_adapter=true attachment_ledger_unchanged=true final_child_cpu_verified=true component_including_mutation_attachment_reverify_ns={} complete_ringct_workflow=false",
            component_started.elapsed().as_nanos()
        );
        drop(child);
        drop(owner);
        assert_eq!(ledger.snapshot().current, fixture_baseline);
    }
    drop(fixture);
    drop(fixture_token);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!(
        "ringct_owned_native_host_singleton_terminal tree_profile=outer_host_v1 original_quota_released=true complete_ringct_workflow=false"
    );
}
