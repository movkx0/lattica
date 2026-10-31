use super::*;

#[test]
fn interior_opening_caller_preserves_every_baseline_category() {
    let baseline = super::super::super::claims::driver_requirement().unwrap();
    let complete = driver_requirement().unwrap();
    let added = added_driver_host_bytes().unwrap();
    assert!(added > 0);
    for category in Category::ALL {
        let before = baseline.get(category);
        let after = complete.get(category);
        assert_eq!(after.device, before.device);
        assert_eq!(after.host, before.host.checked_add(
            if category == Category::PhaseScratch { added } else { 0 },
        ).unwrap());
    }
    assert_eq!(complete.total().unwrap().device, 0);
}

#[test]
fn interior_opening_caller_exact_and_one_short_use_original_ledger() {
    let required = driver_requirement().unwrap();
    let total = required.total().unwrap();
    assert!(total.host > 0);
    let exact = Ledger::new(WorkerAllowance { host: total.host, device: 0 });
    let foreign = Ledger::new(WorkerAllowance { host: total.host, device: 0 });
    let original = exact.admit_phase(required).unwrap();
    assert!(original.belongs_to(&exact));
    assert!(!original.belongs_to(&foreign));
    assert_eq!(original.requirements(), required);
    assert_eq!(exact.snapshot().current, total);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let before_extra = exact.snapshot();
    assert!(exact.admit_phase(Requirements::single(
        Category::PhaseScratch, Bytes { host: 1, device: 0 },
    )).is_err());
    assert_eq!(exact.snapshot(), before_extra);
    drop(original);
    let released = exact.snapshot();
    assert_eq!(released.current, Bytes::ZERO);
    assert!(released.categories.iter().all(|category| category.current == Bytes::ZERO));
    assert_eq!(released.peak, total);

    let short = Ledger::new(WorkerAllowance { host: total.host - 1, device: 0 });
    let before_short = short.snapshot();
    assert!(short.admit_phase(required).is_err());
    assert_eq!(short.snapshot(), before_short);
}

#[test]
fn interior_opening_caller_census_refuses_arithmetic_overflow() {
    assert!(repeated_layout(&[usize::MAX]).is_err());
    assert!(repeated_layout(&[usize::MAX / FRAME_COPIES + 1]).is_err());
    assert!(repeated_layout(&[usize::MAX / 2, usize::MAX / 2]).is_err());
}

#[test]
fn interior_opening_terminal_census_is_bounded_and_non_admitting() {
    let unrelated = Ledger::new(WorkerAllowance { host: 0, device: 0 });
    let before = unrelated.snapshot();
    let bytes = terminal_observer_bytes().unwrap();
    assert!(bytes > 0 && bytes <= OBSERVER_FIXED_HOST_LIMIT);
    assert_eq!(unrelated.snapshot(), before);
    assert_eq!(OBSERVER_OUTPUT_BYTES, 4096);
}
