use super::*;

fn bytes(host: u64, device: u64) -> Bytes {
    Bytes { host, device }
}

fn ledger(host: u64, device: u64) -> Ledger {
    Ledger::new(WorkerAllowance { host, device })
}

#[test]
fn host_and_device_boundaries_refuse_atomically() {
    let ledger = ledger(100, 50);
    let retained = ledger
        .reserve(Category::NativeProof, bytes(30, 10))
        .unwrap();
    for request in [bytes(71, 0), bytes(0, 41), bytes(71, 41)] {
        let before = ledger.snapshot();
        assert_eq!(
            ledger.reserve(Category::PhaseScratch, request).unwrap_err(),
            Error::ExceedsWorkerAllowance {
                requested: request,
                remaining: bytes(70, 40),
            }
        );
        assert_eq!(ledger.snapshot(), before);
    }
    let boundary = ledger
        .reserve(Category::PhaseScratch, bytes(70, 40))
        .unwrap();
    assert_eq!(ledger.remaining(), Bytes::ZERO);
    drop(boundary);
    drop(retained);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, bytes(100, 50));
}

#[test]
fn later_category_refusal_never_partially_charges_a_phase() {
    let ledger = ledger(100, 20);
    let mut request = Requirements::single(Category::CompilerInputs, bytes(80, 0));
    request.add(Category::PhaseScratch, bytes(10, 21)).unwrap();
    let before = ledger.snapshot();
    assert!(matches!(
        ledger.admit_phase(request),
        Err(Error::ExceedsWorkerAllowance { .. })
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(ledger.remaining(), bytes(100, 20));
}

#[test]
fn arithmetic_overflow_preserves_requests_and_live_reservations() {
    for (maximum, increment) in [
        (bytes(u64::MAX, 0), bytes(1, 0)),
        (bytes(0, u64::MAX), bytes(0, 1)),
    ] {
        let mut request = Requirements::single(Category::NativeProof, maximum);
        let original = request;
        assert_eq!(
            request.add(Category::NativeProof, increment),
            Err(Error::Overflow)
        );
        assert_eq!(request, original);
        assert_eq!(
            request.add(Category::Report, increment),
            Err(Error::Overflow)
        );
        assert_eq!(request, original);
        let ledger = ledger(u64::MAX, u64::MAX);
        let held = ledger.admit_phase(request).unwrap();
        let before = ledger.snapshot();
        assert_eq!(
            ledger.reserve(Category::Report, increment).unwrap_err(),
            Error::Overflow
        );
        assert_eq!(ledger.snapshot(), before);
        drop(held);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn tokens_follow_moves_and_splits_without_releasing_ownership() {
    struct Owner {
        charge: Reservation,
    }
    fn move_owner(owner: Owner) -> Owner {
        owner
    }
    let ledger = ledger(100, 100);
    let other = Ledger::new(WorkerAllowance {
        host: 100,
        device: 100,
    });
    let token = ledger
        .reserve(Category::NativeProof, bytes(80, 60))
        .unwrap();
    let mut owner = move_owner(Owner { charge: token });
    assert!(owner.charge.belongs_to(&ledger));
    assert!(!owner.charge.belongs_to(&other));
    let before = ledger.snapshot();
    let first = owner
        .charge
        .split(Requirements::single(Category::NativeProof, bytes(20, 40)))
        .unwrap();
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(owner.charge.requirements().total().unwrap(), bytes(60, 20));
    let second = owner
        .charge
        .split(Requirements::single(Category::NativeProof, bytes(60, 20)))
        .unwrap();
    assert_eq!(owner.charge.requirements().total().unwrap(), Bytes::ZERO);
    drop(owner);
    assert_eq!(ledger.snapshot(), before);
    drop(first);
    assert_eq!(ledger.snapshot().current, bytes(60, 20));
    drop(second);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, bytes(80, 60));
}

#[test]
fn invalid_split_preserves_token_including_earlier_categories() {
    let ledger = ledger(100, 100);
    let mut request = Requirements::single(Category::NativeProof, bytes(30, 20));
    request.add(Category::Report, bytes(10, 0)).unwrap();
    let mut token = ledger.admit_phase(request).unwrap();
    let mut invalid = Requirements::single(Category::NativeProof, bytes(10, 10));
    invalid.add(Category::Report, bytes(11, 0)).unwrap();
    let before = ledger.snapshot();
    assert!(matches!(
        token.split(invalid),
        Err(Error::SplitExceedsReservation {
            category: Category::Report,
            ..
        })
    ));
    assert_eq!(token.requirements(), request);
    assert_eq!(ledger.snapshot(), before);
    assert!(token
        .split(Requirements::single(Category::NativeProof, bytes(0, 21)))
        .is_err());
    assert_eq!(token.requirements(), request);
}

#[test]
fn nested_phase_retains_outputs_and_releases_only_temporary_owners() {
    let ledger = ledger(100, 60);
    let native = ledger
        .reserve(Category::NativeProof, bytes(20, 10))
        .unwrap();
    let mut request = Requirements::single(Category::RecursiveProof, bytes(10, 5));
    request.add(Category::CompilerInputs, bytes(10, 0)).unwrap();
    request
        .add(Category::SymbolicCompiler, bytes(30, 0))
        .unwrap();
    request.add(Category::PhaseScratch, bytes(15, 35)).unwrap();
    let mut phase = ledger.admit_phase(request).unwrap();
    assert_eq!(ledger.snapshot().current, bytes(85, 50));
    let alias = ledger.clone();
    assert!(alias
        .reserve(Category::IndependentVerifier, bytes(16, 0))
        .is_err());
    let nested = alias
        .reserve(Category::IndependentVerifier, bytes(5, 1))
        .unwrap();
    assert_eq!(ledger.snapshot().current, bytes(90, 51));
    let result = phase
        .split(Requirements::single(Category::RecursiveProof, bytes(10, 5)))
        .unwrap();
    drop(nested);
    drop(phase);
    assert_eq!(ledger.snapshot().current, bytes(30, 15));
    assert_eq!(
        ledger.snapshot().categories[Category::RecursiveProof as usize].current,
        bytes(10, 5)
    );
    assert_eq!(
        ledger.snapshot().categories[Category::PhaseScratch as usize].current,
        Bytes::ZERO
    );
    drop(native);
    assert_eq!(ledger.snapshot().current, bytes(10, 5));
    drop(result);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, bytes(90, 51));
}

#[test]
fn failure_cleanup_releases_reservations_but_preserves_preexisting_owners() {
    let ledger = ledger(100, 100);
    let prior = ledger
        .reserve(Category::RegisteredMetadata, bytes(10, 5))
        .unwrap();
    let fail = || -> Result<(), Error> {
        let _phase = ledger.reserve(Category::PhaseScratch, bytes(50, 40))?;
        let _report = ledger.reserve(Category::Report, bytes(50, 0))?;
        Ok(())
    };
    assert!(fail().is_err());
    assert_eq!(ledger.snapshot().current, bytes(10, 5));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _phase = ledger
            .reserve(Category::PhaseScratch, bytes(50, 40))
            .unwrap();
        panic!("simulated failure after reservation");
    }));
    assert!(panic.is_err());
    assert_eq!(ledger.snapshot().current, bytes(10, 5));
    drop(prior);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, bytes(60, 45));
}

#[test]
fn last_token_keeps_ledger_alive_and_independent_peaks_are_explicit() {
    let ledger = ledger(100, 100);
    let host = ledger
        .reserve(Category::CompilerInputs, bytes(90, 0))
        .unwrap();
    drop(host);
    let device = ledger
        .reserve(Category::PhaseScratch, bytes(0, 80))
        .unwrap();
    assert_eq!(ledger.snapshot().current, bytes(0, 80));
    assert_eq!(ledger.snapshot().peak, bytes(90, 80));
    let weak = Rc::downgrade(&ledger.0);
    drop(ledger);
    assert!(weak.upgrade().is_some());
    drop(device);
    assert!(weak.upgrade().is_none());
}
