use super::super::Val;
use super::*;
use crate::block_v2::machine::verifier::template;
use crate::spill_alloc::allocation_requests::measure;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::MerkleCap;

fn cap(height: usize, capacity: usize) -> p3_batch_stark::Commitment<Config> {
    let roots = 1 << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
    let mut values = Vec::with_capacity(capacity.max(roots));
    values.resize(roots, [Val::ZERO; 4]);
    MerkleCap::new(values)
}

#[test]
fn public_reservation_precedes_cap_allocation_and_rejects_overflow() {
    for height in [8usize, 64, 1 << 24] {
        let roots = 1 << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
        let (reservation, requests) = measure(|| RegisteredVerifier::host_reservation_bytes(46, height, roots, roots));
        assert_eq!(requests.calls, 0);
        let reservation = reservation.unwrap();
        assert!(reservation <= LIMIT_BYTES);
        assert_eq!(reservation, Plan::new(46, height, &cap(height, roots), Limits::default()).unwrap().peak_bytes);
        for (publics, height, count, capacity) in [
            (65, height, roots, roots), (46, 0, roots, roots),
            (46, height, 0, roots), (46, height, roots, roots - 1),
            (46, height, roots, usize::MAX),
        ] {
            let (reservation, requests) = measure(|| RegisteredVerifier::host_reservation_bytes(publics, height, count, capacity));
            assert!(reservation.is_err());
            assert_eq!(requests.calls, 0);
            assert_eq!(requests.bytes, 0);
        }
    }
}

#[test]
fn trusted_geometry_has_constant_shape_storage_and_separate_construction_and_call_phases() {
    let mut maximum = 0;
    for publics in [0, 1, 23, 32, 33, 64] {
        let mut last = None;
        for height in [8, 64, 1 << 19, 1 << 24] {
            let cap = cap(height, 64);
            let (plan, allocation) =
                measure(|| Plan::new(publics, height, &cap, Limits::default()));
            assert_eq!(allocation.calls, 0);
            let plan = plan.unwrap();
            assert_eq!(plan.graph_workspace_bytes, 192 << 20);
            assert!(plan.construction_peak_bytes > plan.verification_peak_bytes);
            assert_eq!(plan.peak_bytes, plan.construction_peak_bytes);
            assert!(plan.metadata_retained_bytes > 64 << 20);
            assert!(plan.peak_bytes < LIMIT_BYTES);
            if let Some(last) = last {
                assert_eq!(plan, last);
            }
            last = Some(plan);
            maximum = maximum.max(plan.peak_bytes);
            let verifier = RegisteredVerifier::from_trusted_cap(publics, height, cap).unwrap();
            assert_eq!(verifier.storage_plan(), plan);
            verifier.admit_storage(plan.peak_bytes).unwrap();
            assert!(verifier.admit_storage(plan.peak_bytes - 1).is_err());
        }
    }
    eprintln!("native_verifier_lifetimes_templates cases=24 max_peak_bytes={maximum} limit_bytes={LIMIT_BYTES} planning_allocation_free=true wide={}", cfg!(feature = "block-v2-wide-lanes"));
}

#[test]
fn cap_spare_capacity_is_admitted_before_shape_and_metadata_allocation() {
    let roots = CAP_LIMIT_BYTES / size_of::<[Val; 4]>();
    let input = cap(64, roots);
    let plan = Plan::new(64, 64, &input, Limits::default()).unwrap();
    assert_eq!(plan.cap_bytes, CAP_LIMIT_BYTES);
    RegisteredVerifier::from_trusted_cap(64, 64, input).unwrap();
    let oversized = cap(64, roots + 1);
    let (result, observed) = measure(|| RegisteredVerifier::from_trusted_cap(64, 64, oversized));
    assert!(matches!(result, Err(ExecutionError::TooLarge)));
    assert_eq!(observed.calls, 0);
    for (publics, height) in [(65, 64), (1, 0), (1, 7), (1, 65), (1, 1 << 25)] {
        let cap = cap(64, 64);
        let (result, observed) =
            measure(|| RegisteredVerifier::from_trusted_cap(publics, height, cap));
        assert!(result.is_err());
        assert_eq!(observed.calls, 0);
    }
    eprintln!("native_verifier_lifetimes_caps exact_boundary=true oversized_rejected_before_allocation=true invalid_geometry=true");
}

#[test]
fn deserialized_trusted_caps_fail_before_shape_or_metadata_allocation() {
    for roots in [0, 3] {
        let wire = postcard::to_allocvec(&(vec![[Val::ZERO; 4]; roots], ())).unwrap();
        let cap: p3_batch_stark::Commitment<Config> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(cap.roots().len(), roots);
        let (result, requests) = measure(|| RegisteredVerifier::from_trusted_cap(1, 64, cap));
        assert!(matches!(result, Err(ExecutionError::InvalidHeight)));
        assert!(!requests.overflow);
        assert_eq!(requests.calls, 0);
        assert_eq!(requests.bytes, 0);
    }
    eprintln!("registered_cap_trusted cases=2 allocations=0");
}

#[test]
fn metadata_limits_drive_both_simultaneous_phases_and_reject_invalid_allowances() {
    let cap = cap(64, 64);
    let limits = Limits {
        recording: 13,
        normalization: 17,
        packing: 97,
        retained: 31,
    };
    let plan = Plan::new(33, 64, &cap, limits).unwrap();
    assert_eq!(plan.graph_workspace_bytes, 114);
    assert!(plan.verification_peak_bytes > plan.construction_peak_bytes);
    assert_eq!(plan.peak_bytes, plan.verification_peak_bytes);
    assert!(Plan::new(
        33,
        64,
        &cap,
        Limits {
            retained: (64 << 20) + 1,
            ..limits
        }
    )
    .is_err());
    assert!(add(usize::MAX, 1).is_err());
    assert!(bytes::<Row>(usize::MAX).is_err());
}

#[test]
fn proof_capacity_preflight_does_not_allocate_or_replace_shape_verification() {
    let verifier = RegisteredVerifier::from_trusted_cap(1, 64, cap(64, 64)).unwrap();
    let mut proof = template::batch(&verifier.air).unwrap();
    let (accepted, requests) = measure(|| RegisteredVerifier::admit_proof_storage(&proof));
    assert!(accepted.unwrap() > 0);
    assert_eq!(requests.calls, 0);
    // The capacity walker does not index using proof-supplied geometry. It is
    // safe to call before metadata exists even for an invalid proof shape.
    proof.opening_proof.1.query_proofs.clear();
    let (accepted, requests) = measure(|| RegisteredVerifier::admit_proof_storage(&proof));
    assert!(accepted.is_ok());
    assert_eq!(requests.calls, 0);
    assert!(verifier.verify(&proof, &[Val::ZERO]).is_err());
}

#[test]
fn constructed_metadata_requests_fit_the_source_phase_bound() {
    for publics in [0, 33, 64] {
        let cap = cap(64, 64);
        let plan = Plan::new(publics, 64, &cap, Limits::default()).unwrap();
        let (verifier, observed) =
            measure(|| RegisteredVerifier::from_trusted_cap(publics, 64, cap));
        let verifier = verifier.unwrap();
        assert_eq!(verifier.storage_plan(), plan);
        assert!(!observed.overflow && observed.bytes > 0);
        // Cumulative requests overestimate the observed live payload here;
        // they check conformance but do not define the simultaneous formula.
        assert!(
            observed.bytes + plan.cap_bytes
                <= plan.construction_peak_bytes - verification_call::PROOF_LIMIT_BYTES
        );
        eprintln!("native_verifier_lifetimes_constructed publics={publics} requested_bytes={} calls={} source_construction_peak={} wide={}", observed.bytes, observed.calls, plan.construction_peak_bytes, cfg!(feature = "block-v2-wide-lanes"));
    }
}
