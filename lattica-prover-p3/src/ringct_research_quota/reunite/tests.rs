use super::*;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 4096,
        device: 4096,
    })
}

#[test]
fn reunite_preserves_each_category_all_counters_and_original_ledger() {
    let ledger = ledger();
    let mut first = Requirements::default();
    let mut second = Requirements::default();
    for (index, category) in Category::ALL.into_iter().enumerate() {
        first
            .add(
                category,
                Bytes {
                    host: index as u64 + 1,
                    device: 2 * index as u64 + 1,
                },
            )
            .unwrap();
        second
            .add(
                category,
                Bytes {
                    host: 3 * index as u64 + 1,
                    device: 4 * index as u64 + 1,
                },
            )
            .unwrap();
    }
    let left = ledger.admit_phase(first).unwrap();
    let right = ledger.admit_phase(second).unwrap();
    let before = ledger.snapshot();
    let mut together = left.reunite(right).unwrap();
    assert!(together.belongs_to(&ledger));
    assert_eq!(together.requirements(), combined(first, second).unwrap());
    assert_eq!(ledger.snapshot(), before);
    // Reunification does not turn one category into another. Splitting moves
    // exactly the original subset back out without a new admission.
    let original_second = together.split(second).unwrap();
    assert_eq!(together.requirements(), first);
    assert_eq!(original_second.requirements(), second);
    assert_eq!(ledger.snapshot(), before);
    let moved = Some(together.reunite(original_second).unwrap());
    assert_eq!(ledger.snapshot(), before);
    drop(moved);
    let after = ledger.snapshot();
    assert_eq!(after.current, Bytes::ZERO);
    assert_eq!(after.peak, before.peak);
    for category in Category::ALL {
        assert_eq!(after.categories[category as usize].current, Bytes::ZERO);
        assert_eq!(
            after.categories[category as usize].peak,
            before.categories[category as usize].peak
        );
    }
}

#[test]
fn different_ledgers_refuse_and_return_both_original_claims_intact() {
    let first = ledger();
    let second = ledger();
    let requirements = Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: 99,
            device: 101,
        },
    );
    let left = first.admit_phase(requirements).unwrap();
    let right = second.admit_phase(requirements).unwrap();
    let before_first = first.snapshot();
    let before_second = second.snapshot();
    let (error, left, right) = left.reunite(right).unwrap_err();
    assert_eq!(error, Error::DifferentLedger);
    assert!(left.belongs_to(&first));
    assert!(!left.belongs_to(&second));
    assert!(right.belongs_to(&second));
    assert_eq!(left.requirements(), requirements);
    assert_eq!(right.requirements(), requirements);
    assert_eq!(first.snapshot(), before_first);
    assert_eq!(second.snapshot(), before_second);
    drop(left);
    assert_eq!(first.snapshot().current, Bytes::ZERO);
    assert_eq!(second.snapshot(), before_second);
    drop(right);
    assert_eq!(second.snapshot().current, Bytes::ZERO);
}

#[test]
fn zero_claims_and_shared_ledger_handles_do_not_admit_or_release_bytes() {
    let ledger = ledger();
    let shared = ledger.clone();
    let occupied = ledger
        .reserve(
            Category::Report,
            Bytes {
                host: 4096,
                device: 4096,
            },
        )
        .unwrap();
    let empty = shared.admit_phase(Requirements::default()).unwrap();
    let before = ledger.snapshot();
    let combined = empty.reunite(occupied).unwrap();
    assert_eq!(ledger.snapshot(), before);
    assert!(combined.belongs_to(&ledger));
    assert!(combined.belongs_to(&shared));
    assert_eq!(ledger.remaining(), Bytes::ZERO);
    drop(combined);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn pure_sum_checks_category_and_total_overflow_without_constructing_invalid_tokens() {
    // Live same-ledger claims already satisfy the enclosing u64 allowance.
    // Exercise defensive arithmetic without fabricating impossible ownership.
    for (left, right) in [
        (
            Requirements::single(
                Category::PhaseScratch,
                Bytes {
                    host: u64::MAX,
                    device: 0,
                },
            ),
            Requirements::single(Category::PhaseScratch, Bytes { host: 1, device: 0 }),
        ),
        (
            Requirements::single(
                Category::PhaseScratch,
                Bytes {
                    host: 0,
                    device: u64::MAX,
                },
            ),
            Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: 1 }),
        ),
        (
            Requirements::single(
                Category::NativeProof,
                Bytes {
                    host: u64::MAX,
                    device: 0,
                },
            ),
            Requirements::single(Category::RecursiveProof, Bytes { host: 1, device: 0 }),
        ),
        (
            Requirements::single(
                Category::NativeProof,
                Bytes {
                    host: 0,
                    device: u64::MAX,
                },
            ),
            Requirements::single(Category::RecursiveProof, Bytes { host: 0, device: 1 }),
        ),
    ] {
        let before = (left, right);
        assert_eq!(combined(left, right), Err(Error::Overflow));
        assert_eq!((left, right), before);
    }
}
