use super::*;
use crate::{
    execution::retained_resources::{Snapshot, WorkerAllowance},
    graph_crypto::{Policy, ShakeRequestPlan},
};
use p3_field::PrimeCharacteristicRing;

fn ledger(host: u64, device: u64) -> Ledger {
    Ledger::new(WorkerAllowance { host, device })
}

fn owned(ledger: &Ledger, input: &[u8], output_len: usize) -> ReservedShakeRequest {
    let plan = ShakeRequestPlan::new([91; 32], 4, 0, input, output_len, Policy::default()).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(token, ledger).unwrap()
}

#[test]
fn source_selection_rejects_batches_and_bad_indices_without_environment_or_runtime() {
    let ledger = ledger(HOST_BYTES, DEVICE_BYTES);
    let owner = owned(&ledger, &[3; 8 * 136 + 7], 10 * 136 + 1);
    let before = ledger.snapshot();
    let mut singles = 0;
    let mut batches = 0;
    for (index, air) in owner
        .request()
        .shake_partition()
        .unwrap()
        .segments()
        .iter()
        .enumerate()
    {
        match air {
            ShakeSegmentAir::Single(_) => {
                let source = SourcePlan::new(&owner, index).unwrap();
                assert!(source.is_for(&owner, index));
                assert_eq!(source.preparation.census().geometry().permutations(), 1);
                assert_eq!(source.requirements.total().unwrap().device, 0);
                singles += 1;
            }
            ShakeSegmentAir::Batch(_) => {
                assert!(matches!(SourcePlan::new(&owner, index), Err(Error::Source)));
                batches += 1;
            }
        }
    }
    assert!(singles > 0 && batches > 0);
    assert!(matches!(
        SourcePlan::new(&owner, owner.request().segments().len()),
        Err(Error::Source)
    ));
    assert_eq!(ledger.snapshot(), before);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn original_complete_source_claim_is_split_once_and_retired_with_empty_owners() {
    let ledger = ledger(HOST_BYTES, DEVICE_BYTES);
    let owner = owned(&ledger, &[7], 1);
    let baseline = ledger.snapshot().current;
    let source = SourcePlan::new(&owner, 0).unwrap();
    let expected = source.requirements;
    let exact = ledger.admit_phase(expected).unwrap();
    let claimed = source.claim_for(&owner, 0, exact, &ledger).unwrap();
    assert!(claimed.preparation.is_for(&owner, 0, &ledger));
    assert!(claimed.verification.belongs_to(&ledger));
    assert_eq!(
        claimed.verification.requirements(),
        VerificationPlan::component_requirement()
    );
    assert_eq!(
        claimed.bookkeeping.requirements(),
        bookkeeping_requirement().unwrap()
    );
    assert_eq!(
        ledger.snapshot().current.host,
        baseline.host + expected.total().unwrap().host
    );
    assert_eq!(ledger.snapshot().current.device, baseline.device);
    let moved = Some(claimed);
    drop(moved);
    assert_eq!(ledger.snapshot().current, baseline);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn equal_request_foreign_ledger_mixed_category_and_wrong_device_ceiling_are_refused() {
    let ledger = ledger(HOST_BYTES, DEVICE_BYTES);
    let unrelated = self::ledger(HOST_BYTES, DEVICE_BYTES);
    let first = owned(&ledger, &[1], 1);
    let equal = owned(&ledger, &[1], 1);
    let baseline = ledger.snapshot().current;
    let source = SourcePlan::new(&first, 0).unwrap();
    let token = ledger.admit_phase(source.requirements).unwrap();
    assert!(matches!(
        source.claim_for(&equal, 0, token, &ledger),
        Err(Error::Authority)
    ));
    let source = SourcePlan::new(&first, 0).unwrap();
    let token = unrelated.admit_phase(source.requirements).unwrap();
    assert!(matches!(
        source.claim_for(&first, 0, token, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
    let source = SourcePlan::new(&first, 0).unwrap();
    let token = ledger
        .reserve(Category::PhaseScratch, source.requirements.total().unwrap())
        .unwrap();
    assert!(matches!(
        source.claim_for(&first, 0, token, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot().current, baseline);
    for device in [0, DEVICE_BYTES - 1] {
        let wrong = self::ledger(HOST_BYTES, device);
        let owner = owned(&wrong, &[1], 1);
        let source = SourcePlan::new(&owner, 0).unwrap();
        let token = wrong.admit_phase(source.requirements).unwrap();
        assert!(matches!(
            source.claim_for(&owner, 0, token, &wrong),
            Err(Error::Authority)
        ));
        drop(owner);
        assert_eq!(wrong.snapshot().current, Bytes::ZERO);
    }
    // An oversized worker is already rejected by the original request owner,
    // so no such owner can reach the later producer claim boundary.
    let oversized = self::ledger(HOST_BYTES, DEVICE_BYTES + 1);
    let request = ShakeRequestPlan::new([91; 32], 4, 0, &[1], 1, Policy::default()).unwrap();
    let token = oversized.admit_phase(request.requirements()).unwrap();
    assert!(matches!(
        request.construct(token, &oversized),
        Err(crate::graph_crypto::request_owner::Error::WrongReservation)
    ));
    assert_eq!(oversized.snapshot().current, Bytes::ZERO);
    drop(first);
    drop(equal);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn one_byte_short_source_admission_preserves_request_and_all_category_counters() {
    let generous = ledger(HOST_BYTES, DEVICE_BYTES);
    let owner = owned(&generous, &[2], 1);
    let original = generous.snapshot().current.host;
    let required = SourcePlan::new(&owner, 0)
        .unwrap()
        .requirements
        .total()
        .unwrap()
        .host;
    drop(owner);
    let short = ledger(original + required - 1, DEVICE_BYTES);
    let owner = owned(&short, &[2], 1);
    let source = SourcePlan::new(&owner, 0).unwrap();
    let before = short.snapshot();
    assert!(short.admit_phase(source.requirements).is_err());
    assert_eq!(short.snapshot(), before);
    drop(source);
    drop(owner);
    assert_eq!(short.snapshot().current, Bytes::ZERO);
}

#[test]
fn retirement_requires_zero_managed_and_tree_storage_and_original_lease_release() {
    let good = Retirement {
        managed_live_bytes: 0,
        managed_peak_bytes: 64 << 20,
        host_tree_live_bytes: 0,
        lease_released: true,
    };
    assert!(retirement_is_complete(good));
    for bad in [
        Retirement {
            managed_live_bytes: 1,
            ..good
        },
        Retirement {
            host_tree_live_bytes: 1,
            ..good
        },
        Retirement {
            lease_released: false,
            ..good
        },
    ] {
        assert!(!retirement_is_complete(bad));
    }
}

#[test]
#[ignore = "dedicated immutable env-clear RTX 5080 worker; exact coordinator selector/process guard only"]
fn gpu_owned_singletons_prove_fresh_verify_mutation_and_retire_original_owners() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("gpu-required")
    );
    struct FixtureState {
        previous_public: Option<[Val; PUBLIC_VALUES]>,
    }
    let ledger = ledger(HOST_BYTES, DEVICE_BYTES);
    let fixture_token = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: (2 * size_of::<FixtureState>()
                    + size_of::<[u8; 1]>()
                    + size_of::<std::time::Instant>()
                    + 6 * size_of::<Snapshot>()) as u64,
                device: 0,
            },
        )
        .unwrap();
    let mut fixture = FixtureState {
        previous_public: None,
    };
    let fixture_baseline = ledger.snapshot().current;
    for byte in [1u8, 2] {
        let owner = owned(&ledger, &[byte], 1);
        let component_started = std::time::Instant::now();
        // SAFETY: coordinator's exact isolated ignored-test worker fixes the
        // environment and serializes all GPU work through terminal retirement.
        let prepared = unsafe { PreparedNativeSingleton::new(&owner, 0, &ledger) }.unwrap();
        // SAFETY: same external process contract remains valid without changes.
        let produced = unsafe { prepared.produce() }.unwrap();
        assert!(produced.is_for(&owner, 0, &ledger));
        assert_eq!(produced.index(), 0);
        assert!(retirement_is_complete(produced.retirement()));
        assert!((1..=DEVICE_BYTES as usize).contains(&produced.retirement().managed_peak_bytes));
        assert!(produced.verification().proof_backing_bytes > 0);
        assert_eq!(ledger.snapshot().current.device, 0);
        // Serialize the actual native report while its original Report owner
        // remains live. B037's fixed report census includes this temporary.
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
        let token = ledger
            .admit_phase(VerificationPlan::component_requirement())
            .unwrap();
        // Original bookkeeping owns this one public Vec; no proof copy or raw
        // token attachment is made for the mutation check.
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
                token,
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
        eprintln!("ringct_owned_native_singleton_case input_byte={byte} fresh_gpu_required=true independent_cpu_verified=true mutation_rejected=true managed_live_bytes=0 host_tree_live_bytes=0 lease_released=true managed_peak_bytes={} component_including_mutation_ns={} native_report_ns={} complete_ringct_workflow=false", produced.retirement().managed_peak_bytes, component_started.elapsed().as_nanos(), produced.report().elapsed_ns);
        let before_attachment = ledger.snapshot();
        let child = produced.into_reserved_child(&ledger).unwrap();
        assert!(child.is_for(owner.request(), 0, &ledger));
        for category in [Category::NativeProof, Category::Report] {
            assert_eq!(
                ledger.snapshot().categories[category as usize],
                before_attachment.categories[category as usize],
            );
        }
        assert_eq!(child.shake_artifact().public_values, fixture.previous_public.unwrap());
        let verifier = ledger.admit_phase(VerificationPlan::component_requirement()).unwrap();
        assert!(child.verify_pre_reserved(verifier, &ledger).unwrap().proof_backing_bytes > 0);
        eprintln!("ringct_owned_native_graph_child intact_original_output=true no_duplicate_proof_claim=true independent_reverified=true complete_ringct_workflow=false");
        drop(child);
        drop(owner);
        assert_eq!(ledger.snapshot().current, fixture_baseline);
    }
    drop(fixture);
    drop(fixture_token);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!("ringct_owned_native_singleton_terminal original_quota_released=true complete_ringct_workflow=false");
}
