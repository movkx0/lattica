use super::*;

#[test]
fn aggregate_reservations_reject_exhaustion_and_overflow_without_changing_live_bytes() {
    let owner = Arc::new(HostQuota::new(32));
    assert!(owner.reserve(0).is_err());
    let first = owner.reserve(13).unwrap();
    let second = owner.reserve(19).unwrap();
    assert_eq!(owner.live(), 32);
    assert!(owner.reserve(1).is_err());
    assert!(owner.reserve(usize::MAX).is_err());
    assert_eq!(owner.live(), 32);
    drop(first);
    let replacement = owner.reserve(13).unwrap();
    drop((second, replacement));
    assert_eq!(owner.live(), 0);
}

#[test]
fn nested_checks_require_the_original_owner_and_do_not_reserve_again() {
    let owner = Arc::new(HostQuota::new(32));
    let other = Arc::new(HostQuota::new(32));
    let scope = owner.reserve(24).unwrap();
    for bytes in [1, 7, 24] {
        scope.check(&owner, bytes).unwrap();
    }
    assert!(scope.check(&owner, 0).is_err());
    assert!(scope.check(&owner, 25).is_err());
    assert!(scope.check(&other, 24).is_err());
    assert_eq!(owner.live(), 24);
    assert_eq!(other.live(), 0);
}

#[test]
fn ownership_survives_the_original_handle_and_releases_on_error_and_unwind() {
    let owner = Arc::new(HostQuota::new(32));
    let failure = (|| -> Result<(), &'static str> {
        let _scope = owner.reserve(32).unwrap();
        Err("operation failed")
    })();
    assert!(failure.is_err());
    assert_eq!(owner.live(), 0);
    assert!(std::panic::catch_unwind(|| {
        let _scope = owner.reserve(32).unwrap();
        panic!("operation unwound");
    })
    .is_err());
    assert_eq!(owner.live(), 0);
    let scope = owner.reserve(32).unwrap();
    let weak = Arc::downgrade(&owner);
    drop(owner);
    assert_eq!(weak.upgrade().unwrap().live(), 32);
    drop(scope);
    assert!(weak.upgrade().is_none());
}

#[test]
fn simultaneous_callers_cannot_each_spend_the_same_allowance() {
    let owner = Arc::new(HostQuota::new(32));
    let barrier = std::sync::Barrier::new(4);
    std::thread::scope(|threads| {
        let handles = (0..4)
            .map(|_| {
                threads.spawn(|| {
                    let scope = owner.reserve(16);
                    barrier.wait();
                    let observed = owner.live();
                    let admitted = scope.is_ok();
                    barrier.wait();
                    drop(scope);
                    assert_eq!(observed, 32);
                    admitted
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            handles
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|&admitted| admitted)
                .count(),
            2
        );
    });
    assert_eq!(owner.live(), 0);
}

#[cfg(feature = "stream")]
#[test]
fn successful_reservation_and_nested_checks_do_not_allocate() {
    use crate::spill_alloc::allocation_requests::measure;
    let owner = Arc::new(HostQuota::new(32));
    let ((first, second), allocations) = measure(|| {
        let first = owner.reserve(7).unwrap();
        let second = owner.reserve(25).unwrap();
        first.check(&owner, 7).unwrap();
        second.check(&owner, 25).unwrap();
        (first, second)
    });
    assert_eq!(allocations.calls, 0);
    assert!(!allocations.overflow);
    drop((first, second));
    assert_eq!(owner.live(), 0);
}
