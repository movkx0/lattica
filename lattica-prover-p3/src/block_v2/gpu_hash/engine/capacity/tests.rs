use super::super::reserve;
use super::*;
use std::sync::Barrier;

fn accounting() -> Arc<Mutex<Accounting>> {
    Arc::new(Mutex::new(Accounting::default()))
}

fn observed(a: &Arc<Mutex<Accounting>>) -> (usize, usize, u64) {
    let a = a.lock().unwrap();
    (a.live, a.peak, a.allocations)
}

#[test]
fn request_plan_refusal_preserves_counters_and_reservation_generation() {
    let a = accounting();
    let baseline = reserve(&a, 20, 100).unwrap();
    let before = observed(&a);
    assert!(Lease::new_checked(a.clone(), 100, 100, |live| {
        assert_eq!(live, 20);
        Err("request phase does not fit".into())
    }).is_err());
    assert_eq!(observed(&a), before);
    assert_eq!(a.lock().unwrap().capacity_generation, 0);
    assert!(a.lock().unwrap().proof_capacity.is_none());
    drop(baseline);
}

#[test]
fn request_plan_and_capacity_grant_share_one_locked_snapshot() {
    let a = accounting();
    let baseline = reserve(&a, 20, 100).unwrap();
    let capacity = Lease::new_checked(a.clone(), 100, 100, |live| {
        assert_eq!(live, 20);
        assert!(matches!(a.try_lock(), Err(std::sync::TryLockError::WouldBlock)));
        Ok(())
    }).unwrap();
    assert_eq!(a.lock().unwrap().capacity_generation, 1);
    thread::scope(|scope| {
        scope.spawn(|| assert!(reserve(&a, 1, 100).is_err())).join().unwrap();
    });
    drop(capacity);
    drop(baseline);
}

#[test]
fn full_capacity_includes_baseline_once_and_keeps_future_bytes_from_competitors() {
    let a = accounting();
    let baseline = reserve(&a, 20, 100).unwrap();
    let capacity = Lease::new(a.clone(), 100, 100).unwrap();
    assert_eq!(observed(&a), (20, 20, 1));
    assert!(Lease::new(a.clone(), 100, 100).is_err());
    thread::scope(|scope| {
        scope
            .spawn(|| assert!(reserve(&a, 1, 100).is_err()))
            .join()
            .unwrap();
    });
    let work = reserve(&a, 80, 100).unwrap();
    assert!(reserve(&a, 1, 100).is_err());
    assert_eq!(observed(&a), (100, 100, 2));
    drop(work);
    drop(capacity);
    drop(baseline);
    assert_eq!(observed(&a), (0, 100, 2));
}

#[test]
fn smaller_envelope_partitions_foreign_allocations_without_lending_reserved_bytes() {
    let a = accounting();
    let baseline = reserve(&a, 20, 100).unwrap();
    let capacity = Lease::new(a.clone(), 60, 100).unwrap();
    let outside = thread::scope(|scope| {
        scope
            .spawn(|| {
                let outside = reserve(&a, 40, 100).unwrap();
                assert!(reserve(&a, 1, 100).is_err());
                outside
            })
            .join()
            .unwrap()
    });
    let inside = reserve(&a, 40, 100).unwrap();
    assert_eq!(observed(&a), (100, 100, 3));
    drop(outside);
    // Free capacity outside the envelope does not enlarge the owner's bound.
    assert!(reserve(&a, 1, 100).is_err());
    assert_eq!(a.lock().unwrap().proof_capacity.unwrap().outside_live, 0);
    let replacement = thread::scope(|scope| {
        scope
            .spawn(|| reserve(&a, 40, 100).unwrap())
            .join()
            .unwrap()
    });
    drop(inside);
    drop(replacement);
    drop(capacity);
    drop(baseline);
    assert_eq!(observed(&a), (0, 100, 4));
}

#[test]
fn retired_baseline_capacity_can_be_reused_by_the_same_proof() {
    let a = accounting();
    let old_workspace = reserve(&a, 60, 100).unwrap();
    let capacity = Lease::new(a.clone(), 100, 100).unwrap();
    drop(old_workspace);
    let replacement = reserve(&a, 100, 100).unwrap();
    assert_eq!(observed(&a), (100, 100, 2));
    drop(replacement);
    drop(capacity);
    assert_eq!(observed(&a).0, 0);
}

#[test]
fn ending_capacity_does_not_release_retained_allocations() {
    let a = accounting();
    let capacity = Lease::new(a.clone(), 100, 100).unwrap();
    let mut output = reserve(&a, 70, 100).unwrap();
    output.mark_retained().unwrap();
    drop(capacity);
    assert!(a.lock().unwrap().proof_capacity.is_none());
    assert_eq!(observed(&a), (70, 70, 1));
    let other = thread::scope(|scope| {
        scope
            .spawn(|| {
                assert!(reserve(&a, 31, 100).is_err());
                reserve(&a, 30, 100).unwrap()
            })
            .join()
            .unwrap()
    });
    drop(output);
    assert_eq!(a.lock().unwrap().retained_live, 0);
    assert_eq!(observed(&a).0, 30);
    drop(other);
    assert_eq!(observed(&a).0, 0);
}

#[test]
fn old_foreign_allocation_drop_does_not_change_a_new_reservations_partition() {
    let a = accounting();
    let first = Lease::new(a.clone(), 60, 100).unwrap();
    let old_outside = thread::scope(|scope| {
        scope
            .spawn(|| reserve(&a, 40, 100).unwrap())
            .join()
            .unwrap()
    });
    drop(first);
    let second = Lease::new(a.clone(), 70, 100).unwrap();
    let new_outside = thread::scope(|scope| {
        scope
            .spawn(|| reserve(&a, 30, 100).unwrap())
            .join()
            .unwrap()
    });
    drop(old_outside);
    assert_eq!(a.lock().unwrap().proof_capacity.unwrap().outside_live, 30);
    let inside = reserve(&a, 70, 100).unwrap();
    assert_eq!(observed(&a).0, 100);
    drop(new_outside);
    assert_eq!(a.lock().unwrap().proof_capacity.unwrap().outside_live, 0);
    assert!(reserve(&a, 1, 100).is_err());
    drop(inside);
    drop(second);
}

#[test]
fn unwinding_releases_unused_capacity_but_preserves_preexisting_storage() {
    let a = accounting();
    let baseline = reserve(&a, 20, 100).unwrap();
    let result = std::panic::catch_unwind(|| {
        let _capacity = Lease::new(a.clone(), 100, 100).unwrap();
        let _work = reserve(&a, 80, 100).unwrap();
        panic!("injected proof failure");
    });
    assert!(result.is_err());
    assert!(a.lock().unwrap().proof_capacity.is_none());
    assert_eq!(observed(&a), (20, 100, 2));
    drop(Lease::new(a.clone(), 100, 100).unwrap());
    drop(baseline);
}

#[test]
fn invalid_capacity_and_exhausted_generations_are_transactional() {
    let a = accounting();
    let baseline = reserve(&a, 20, 100).unwrap();
    for ceiling in [0, 19, 101, usize::MAX] {
        assert!(Lease::new(a.clone(), ceiling, 100).is_err());
        assert!(a.lock().unwrap().proof_capacity.is_none());
        assert_eq!(a.lock().unwrap().capacity_generation, 0);
        assert_eq!(observed(&a), (20, 20, 1));
    }
    a.lock().unwrap().capacity_generation = u64::MAX;
    assert!(Lease::new(a.clone(), 100, 100).is_err());
    assert!(a.lock().unwrap().proof_capacity.is_none());
    assert_eq!(observed(&a), (20, 20, 1));
    drop(baseline);
}

#[test]
fn rejected_allocations_do_not_consume_capacity_or_change_measurements() {
    let a = accounting();
    let capacity = Lease::new(a.clone(), 100, 100).unwrap();
    assert!(reserve(&a, usize::MAX, 100).is_err());
    a.lock().unwrap().allocations = u64::MAX;
    assert!(reserve(&a, 1, 100).is_err());
    assert_eq!(observed(&a), (0, 0, u64::MAX));
    assert_eq!(a.lock().unwrap().proof_capacity.unwrap().outside_live, 0);
    drop(capacity);
}

#[test]
fn racing_proofs_have_one_capacity_owner() {
    let a = accounting();
    let before = Barrier::new(2);
    let admitted = Barrier::new(2);
    let winners = thread::scope(|scope| {
        let attempt = || {
            before.wait();
            let capacity = Lease::new(a.clone(), 100, 100);
            let won = capacity.is_ok();
            admitted.wait();
            drop(capacity);
            usize::from(won)
        };
        let left = scope.spawn(attempt);
        let right = scope.spawn(attempt);
        left.join().unwrap() + right.join().unwrap()
    });
    assert_eq!(winners, 1);
    assert!(a.lock().unwrap().proof_capacity.is_none());
    assert_eq!(observed(&a), (0, 0, 0));
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires complete owned OpenCL path and a bounded zero-swap GPU service"]
fn gpu_wallet_capacity_rejects_competition_before_work_and_releases_after_proofs() {
    use crate::block_v2::{commitment::Context, gpu_hash, leaf, profile, quotient_pcs};
    use crate::joinsplit_air as js;
    use crate::proving::{Policy, Request};
    use gpu_hash::device::{DeviceSession, Extension, MatrixSpec, RowOrder};

    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    gpu_hash::initialize_from_env().unwrap();
    assert!(gpu_hash::initialize_resident_from_env().unwrap());
    let request = Request {
        policy: Policy::GpuRequired,
        emit_report: true,
    };
    let witness = js::demo_witness();
    // Explicit CPU fixture/oracle preparation is outside the proving requests.
    let public = js::public_values(&witness);
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [47; 32],
    };
    let snapshot = || {
        let engine = super::super::ENGINE.get().unwrap().lock().unwrap();
        let a = *engine.as_ref().unwrap().accounting.lock().unwrap();
        (
            a.allocations,
            a.capacity_generation,
            a.proof_capacity.is_some(),
        )
    };
    let session = DeviceSession::new().unwrap();
    let capacity = session.reserve_proof_capacity().unwrap();
    let before = snapshot();
    assert!(before.2);
    assert!(session.reserve_proof_capacity().is_err());
    assert!(matches!(
        js::prove_to_bytes_with_request(&witness, request),
        Err(crate::proving::Error::ComponentRejected)
    ));
    assert_eq!(
        leaf::prove_joinsplit_with_request(&witness, &context, request),
        Err(leaf::LeafError::GpuFailure)
    );
    thread::scope(|scope| {
        scope
            .spawn(|| {
                let competitor = DeviceSession::new().unwrap();
                assert!(competitor.reserve_proof_capacity().is_err());
                let spec = MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1).unwrap();
                assert!(competitor.upload(spec, &[1]).is_err());
            })
            .join()
            .unwrap();
    });
    assert!(gpu_hash::shutdown().is_err());
    assert_eq!(
        snapshot(),
        before,
        "rejection must precede GPU allocation/arithmetic"
    );
    drop(capacity);
    assert!(!snapshot().2);
    let generation = snapshot().1;
    let (legacy, report) = js::prove_to_bytes_with_request(&witness, request).unwrap();
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(snapshot().1, generation + 1);
    assert!(!snapshot().2);
    let cubic = leaf::prove_joinsplit_with_request(&witness, &context, request).unwrap();
    assert_eq!(snapshot().1, generation + 2);
    assert!(!snapshot().2);
    drop(session);
    gpu_hash::shutdown().unwrap();
    assert!(js::verify_bytes(&legacy, &public));
    leaf::verify_joinsplit_research(&cubic, &context, &public).unwrap();
    let mut wrong = public.clone();
    use p3_field::PrimeCharacteristicRing;
    wrong[0] += crate::config::Val::ONE;
    assert!(!js::verify_bytes(&legacy, &wrong));
    assert!(leaf::verify_joinsplit_research(&cubic, &context, &wrong).is_err());
    eprintln!(
        "gpu_wallet_capacity_regression fresh_proofs=2 cpu_verified=2 altered_publics_rejected=2"
    );
}
