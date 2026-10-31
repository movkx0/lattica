use super::*;
use crate::execution::retained_resources::WorkerAllowance;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: WORKER_HOST,
        device: MANAGED_DEVICE,
    })
}

fn limits() -> Limits {
    Limits {
        host_bytes: WORKER_HOST,
        device_bytes: MANAGED_DEVICE,
        max_rows: MAX_ROWS,
    }
}

// CPU tests exercise only the pure source validation with real unstarted
// owners. No Runtime, selected device, binding, or sealed retirement owner is
// fabricated. Actual typed restoration requires the separate GPU qualifier.
#[test]
fn original_host_source_plan_preserves_all_counters_and_ownership() {
    let ledger = ledger();
    let pending = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    let original = pending.reservation.requirements();
    let before = ledger.snapshot();
    let plan = restoration_plan(original, pending.belongs_to(&ledger), &ledger, limits())
        .expect("exact original source plan refused");
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(pending.reservation.requirements(), original);
    assert!(pending.belongs_to(&ledger));
    assert!(pending.selection.is_none());
    assert_eq!(plan.footprint().retained_tree_host_bytes, 8 << 30);
    drop(plan);
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn source_plan_refuses_foreign_ledger_and_wrong_profile_without_changes() {
    let ledger = ledger();
    let foreign = self::ledger();
    let pending = PendingRuntime::reserve_outer_host_v1(&ledger, limits()).unwrap();
    let original = pending.reservation.requirements();
    let before = ledger.snapshot();
    let error = match restoration_plan(original, pending.belongs_to(&foreign), &foreign, limits()) {
        Err(error) => error,
        Ok(_) => panic!("foreign source plan accepted"),
    };
    assert_eq!(error, RuntimeError::WrongLedger);
    assert!(pending.belongs_to(&ledger));
    assert_eq!(pending.reservation.requirements(), original);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);

    let pending = PendingRuntime::reserve(&ledger, limits()).unwrap();
    let original = pending.reservation.requirements();
    let before = ledger.snapshot();
    let error = match restoration_plan(original, pending.belongs_to(&ledger), &ledger, limits()) {
        Err(error) => error,
        Ok(_) => panic!("device source plan retargeted to host"),
    };
    assert_eq!(error, RuntimeError::Admission);
    assert!(pending.belongs_to(&ledger));
    assert_eq!(pending.reservation.requirements(), original);
    assert_eq!(ledger.snapshot(), before);
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
