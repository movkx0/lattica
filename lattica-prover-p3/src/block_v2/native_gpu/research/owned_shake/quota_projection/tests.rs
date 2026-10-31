use super::*;
use crate::ringct_research_quota::WorkerAllowance;

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host,
        device: MANAGED_DEVICE,
    })
}

fn startup(ledger: &Ledger) -> Reservation {
    let source = StartupPlan::outer_host_v1().unwrap().footprint();
    ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: source.requested_host_bytes as u64,
                device: source.managed_device_bytes as u64,
            },
        )
        .unwrap()
}

#[test]
fn original_startup_is_borrowed_and_all_projection_claims_are_released() {
    let ledger = ledger(WORKER_HOST);
    let startup = startup(&ledger);
    let before = ledger.snapshot().current;
    let projection = NativeShakeQuotaProjection::reserve_outer_host_v1(&startup, &ledger).unwrap();
    assert_eq!(ledger.snapshot().current.device, MANAGED_DEVICE);
    assert_eq!(projection.wrapper_bytes().device, 0);
    assert!(projection.wrapper_bytes().host > 0);
    assert!(projection.pcs_bytes().host > 0);
    assert!(projection.pcs_bytes().host <= NATIVE_HOST as u64);
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + projection.wrapper_bytes().host + projection.pcs_bytes().host
    );
    drop(projection);
    assert_eq!(ledger.snapshot().current, before);
    drop(startup);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn foreign_startup_and_one_byte_short_device_refuse_without_leaked_claims() {
    let ledger = ledger(WORKER_HOST);
    let foreign = self::ledger(WORKER_HOST);
    let startup = startup(&ledger);
    assert!(matches!(
        NativeShakeQuotaProjection::reserve_outer_host_v1(&startup, &foreign),
        Err(Error::Authority)
    ));
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let blocker = ledger
        .reserve(Category::PhaseScratch, Bytes { host: 0, device: 1 })
        .unwrap();
    let before = ledger.snapshot().current;
    assert!(matches!(
        NativeShakeQuotaProjection::reserve_outer_host_v1(&startup, &ledger),
        Err(Error::Admission)
    ));
    assert_eq!(ledger.snapshot().current, before);
    drop((blocker, startup));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn one_byte_short_wrapper_budget_releases_every_partial_claim() {
    let ledger = ledger(WORKER_HOST);
    let startup = startup(&ledger);
    let wrappers = TreeProfile::OuterHostV1.phase_wrapper_host_bytes().unwrap() as u64;
    let blocker = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: ledger.remaining().host - (wrappers - 1),
                device: 0,
            },
        )
        .unwrap();
    let before = ledger.snapshot().current;
    assert!(matches!(
        NativeShakeQuotaProjection::reserve_outer_host_v1(&startup, &ledger),
        Err(Error::Admission)
    ));
    assert_eq!(ledger.snapshot().current, before);
    drop((blocker, startup));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
