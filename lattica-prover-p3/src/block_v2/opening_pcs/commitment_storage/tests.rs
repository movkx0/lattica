use super::*;
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn commitment_partition_counts_repeated_owners_without_deduplication_allocation() {
    let (plan, requests) = measure(|| {
        Partition::from_backings([Ok(Some(137)), Ok(Some(137)), Ok(Some(61))], 1024)
            .unwrap()
            .unwrap()
    });
    assert_eq!(plan.retained_bytes, 335);
    assert_eq!(plan.opening_allowance, 689);
    assert_eq!(
        plan.opening_allowance + plan.retained_bytes,
        plan.operation_allowance
    );
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
}

#[test]
fn commitment_partition_preserves_explicit_hybrid_path_and_rejects_insufficient_budget() {
    assert!(Partition::from_backings([Ok(Some(100)), Ok(None)], 1024)
        .unwrap()
        .is_none());
    assert_eq!(
        Partition::from_backings([Ok(Some(100))], 101)
            .unwrap()
            .unwrap()
            .opening_allowance,
        1
    );
    for allowance in [0, 99, 100] {
        assert!(Partition::from_backings([Ok(Some(100))], allowance).is_err());
    }
    assert!(Partition::from_backings([Ok(Some(usize::MAX)), Ok(Some(1))], usize::MAX).is_err());
    assert!(Partition::from_backings([Err("invalid commitment owner".into())], 1024).is_err());
}
