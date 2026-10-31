use super::*;

#[test]
fn exact_boundary_moves_and_session_retirement_preserve_ownership() {
    assert!(Quota::new(LEDGER_BYTES - 1).is_err());
    let quota = Quota::new(LEDGER_BYTES + 19).unwrap();
    let owner = quota.reserve(19).unwrap();
    let retained = owner.reserve_related(0).unwrap();
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES + 19);
    assert!(quota.reserve(1).is_err());
    drop(quota);
    let moved = owner;
    assert!(retained.reserve_related(1).is_err());
    drop(moved);
    let reused = retained.reserve_related(19).unwrap();
    assert!(reused.same_ledger(&retained));
    assert_eq!(reused.reserved_bytes(), 19);
}

#[test]
fn split_transfers_charge_without_lending_live_payload_twice() {
    let quota = Quota::new(LEDGER_BYTES + 23).unwrap();
    let mut producer = quota.reserve(23).unwrap();
    let before = quota.snapshot();
    let output = producer.split_off(17).unwrap();
    assert_eq!(producer.reserved_bytes(), 6);
    assert_eq!(output.reserved_bytes(), 17);
    assert!(producer.same_ledger(&output));
    assert_eq!(quota.snapshot(), before);
    assert!(producer.split_off(7).is_err());
    assert_eq!(producer.reserved_bytes(), 6);
    drop(producer);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES + 17);
    assert!(quota.reserve(7).is_err());
    let available = quota.reserve(6).unwrap();
    drop(output);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES + 6);
    drop(available);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn unrelated_ledgers_and_counter_overflows_fail_closed() {
    let first = Quota::new(LEDGER_BYTES + 10).unwrap();
    let second = Quota::new(LEDGER_BYTES + 10).unwrap();
    assert!(!first
        .reserve(0)
        .unwrap()
        .same_ledger(&second.reserve(0).unwrap()));
    first.total.set(usize::MAX);
    let before = first.snapshot();
    assert!(first.reserve(1).is_err());
    let after = first.snapshot();
    assert_eq!(after.live_reserved_bytes, before.live_reserved_bytes);
    assert_eq!(
        after.cumulative_reserved_bytes,
        before.cumulative_reserved_bytes
    );
    assert_eq!(after.admitted_attempts, before.admitted_attempts);
    assert_eq!(after.rejected_attempts, before.rejected_attempts + 1);
    first.total.set(LEDGER_BYTES);
    first.admitted.set(usize::MAX);
    assert!(first.reserve(0).is_err());
    assert_eq!(first.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[cfg(feature = "stream")]
#[test]
fn ledger_census_and_token_operations_match_allocation_requests() {
    use crate::spill_alloc::allocation_requests::measure;
    let (quota, allocated) = measure(|| Quota::new(LEDGER_BYTES + 100).unwrap());
    assert_eq!(allocated.bytes, LEDGER_BYTES);
    assert_eq!(allocated.calls, 1);
    assert!(!allocated.overflow);
    let ((), operations) = measure(|| {
        let mut owner = quota.reserve(100).unwrap();
        let split = owner.split_off(30).unwrap();
        assert!(owner.same_ledger(&split));
        assert!(owner.reserve_related(1).is_err());
        assert!(owner.split_off(71).is_err());
        drop(owner);
        drop(split);
    });
    assert_eq!(operations.calls, 0);
    assert!(!operations.overflow);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
}
