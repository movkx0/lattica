use super::*;
use crate::execution::retained_resources::WorkerAllowance;

fn limits() -> Limits {
    Limits {
        host_bytes: WORKER_HOST,
        device_bytes: MANAGED_DEVICE,
        max_rows: MAX_ROWS,
    }
}

fn ledger(host: u64, device: u64) -> Ledger {
    Ledger::new(WorkerAllowance { host, device })
}

#[test]
fn pending_startup_has_original_ledger_identity_across_moves() {
    let first = ledger(WORKER_HOST, MANAGED_DEVICE);
    let alias = first.clone();
    let unrelated = ledger(WORKER_HOST, MANAGED_DEVICE);
    let pending = PendingRuntime::reserve(&first, limits()).unwrap();
    assert_eq!(pending.reserved_tree_host_bytes(), 0);
    let reserved = first.snapshot().current;
    assert!(reserved.host >= 64 << 20);
    assert!(reserved.device > 64 << 20);
    assert!(pending.selection.is_none());
    assert!(pending.belongs_to(&first));
    assert!(pending.belongs_to(&alias));
    assert!(!pending.belongs_to(&unrelated));
    let moved = Some(pending);
    assert_eq!(first.snapshot().current, reserved);
    let moved = moved.unwrap();
    assert!(moved.belongs_to(&first));
    assert_eq!(first.snapshot().current, reserved);
    drop(moved);
    assert_eq!(first.snapshot().current, Bytes::ZERO);
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
}

#[test]
fn outer_tree_payload_is_admitted_atomically_in_the_original_worker_ledger() {
    let host_plan = core::StartupPlan::outer_host_v1().unwrap();
    let exact = requested(&host_plan).unwrap();
    assert!(exact.host > 8 << 30 && exact.host < WORKER_HOST);
    let short = ledger(exact.host - 1, exact.device);
    assert!(matches!(
        PendingRuntime::reserve_outer_host_v1(&short, limits()),
        Err(RuntimeError::Admission)
    ));
    assert_eq!(short.snapshot().current, Bytes::ZERO);
    let short_device = ledger(exact.host, exact.device - 1);
    assert!(matches!(
        PendingRuntime::reserve_outer_host_v1(&short_device, limits()),
        Err(RuntimeError::Admission)
    ));
    assert_eq!(short_device.snapshot().current, Bytes::ZERO);
    let original = ledger(exact.host, exact.device);
    let marker = original.clone();
    let unrelated = ledger(exact.host, exact.device);
    let pending = PendingRuntime::reserve_outer_host_v1(&original, limits()).unwrap();
    assert_eq!(original.remaining(), Bytes::ZERO);
    assert_eq!(pending.reserved_tree_host_bytes(), 8 << 30);
    assert!(pending.belongs_to(&marker));
    assert!(!pending.belongs_to(&unrelated));
    assert!(pending.selection.is_none());
    assert_eq!(pending.reserved_bytes(), exact);
    drop(original);
    let moved = Some(pending);
    assert_eq!(marker.snapshot().current, exact);
    assert_eq!(moved.as_ref().unwrap().reserved_tree_host_bytes(), 8 << 30);
    drop(moved);
    assert_eq!(marker.snapshot().current, Bytes::ZERO);
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
}

#[test]
fn startup_refuses_each_short_budget_without_environment_or_driver_access() {
    let plan = core::StartupPlan::new().unwrap();
    let exact = requested(&plan).unwrap();
    for (host, device) in [
        (exact.host - 1, exact.device),
        (exact.host, exact.device - 1),
    ] {
        let short = ledger(host, device);
        assert!(matches!(
            PendingRuntime::reserve(&short, limits()),
            Err(RuntimeError::Admission)
        ));
        assert_eq!(short.snapshot().current, Bytes::ZERO);
    }
    let exact_ledger = ledger(exact.host, exact.device);
    let pending = PendingRuntime::reserve(&exact_ledger, limits()).unwrap();
    assert_eq!(exact_ledger.remaining(), Bytes::ZERO);
    assert!(pending.selection.is_none());
    drop(pending);
    assert_eq!(exact_ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn runtime_startup_rejects_profile_or_worker_allowance_expansion() {
    let original = ledger(WORKER_HOST, MANAGED_DEVICE);
    for wrong in [
        Limits {
            host_bytes: WORKER_HOST + 1,
            ..limits()
        },
        Limits {
            host_bytes: WORKER_HOST - 1,
            ..limits()
        },
        Limits {
            device_bytes: MANAGED_DEVICE + 1,
            ..limits()
        },
        Limits {
            max_rows: MAX_ROWS * 2,
            ..limits()
        },
        Limits {
            max_rows: 3,
            ..limits()
        },
    ] {
        assert!(matches!(
            PendingRuntime::reserve(&original, wrong),
            Err(RuntimeError::Configuration)
        ));
        assert_eq!(original.snapshot().current, Bytes::ZERO);
    }
    for expanded in [
        ledger(WORKER_HOST + 1, MANAGED_DEVICE),
        ledger(WORKER_HOST, MANAGED_DEVICE + 1),
    ] {
        assert!(matches!(
            PendingRuntime::reserve(&expanded, limits()),
            Err(RuntimeError::Configuration)
        ));
        assert_eq!(expanded.snapshot().current, Bytes::ZERO);
    }
}

#[test]
#[ignore = "dedicated immutable env-clear RTX 5080 worker; fixed process/VRAM guard; coordinator only"]
fn gpu_reserved_runtime_rechecks_original_ledger_and_retires_startup() {
    let original = ledger(WORKER_HOST, MANAGED_DEVICE);
    let unrelated = ledger(WORKER_HOST, MANAGED_DEVICE);
    for _ in 0..2 {
        let mut pending = PendingRuntime::reserve(&original, limits()).unwrap();
        let reserved = pending.reserved_bytes();
        {
            // SAFETY: the coordinator launches this sole ignored test in the
            // dedicated immutable-env process; no test/environment mutation.
            let preflight = unsafe { pending.preflight().unwrap() };
            assert!(preflight.reservation().belongs_to(&original));
            assert!(!preflight.reservation().belongs_to(&unrelated));
            assert_eq!(
                preflight
                    .reservation()
                    .requirements()
                    .get(Category::PhaseScratch),
                reserved
            );
            assert_eq!(original.snapshot().current, reserved);
        }
        // SAFETY: same worker contract remains live through terminal cleanup.
        let session = unsafe { pending.start().unwrap() };
        assert!(matches!(
            session.check_reserved_runtime(&unrelated),
            Err(RuntimeError::WrongLedger)
        ));
        {
            let runtime = session.check_reserved_runtime(&original).unwrap();
            let borrowed = runtime.borrow_core().unwrap();
            assert!(borrowed.reservation().belongs_to(&original));
            assert!(!borrowed.reservation().belongs_to(&unrelated));
            assert_eq!(borrowed.runtime().footprint().retained_tree_host_bytes, 0);
            assert!(matches!(
                runtime.borrow_core(),
                Err(RuntimeError::Lifecycle)
            ));
            assert_eq!(original.snapshot().current, reserved);
        }
        let retirement = session.finish_reserved().unwrap();
        assert_eq!(retirement.managed_live_bytes, 0);
        assert_eq!(retirement.host_tree_live_bytes, 0);
        assert!(retirement.lease_released);
        assert_eq!(original.snapshot().current, Bytes::ZERO);
    }
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
}
