use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use crate::graph_crypto::{Admission, Policy, ShakeRequestPlan};

fn original_request(ledger: &Ledger) -> ReservedShakeRequest {
    let input = [43; 16_416];
    let plan = ShakeRequestPlan::new_active_opt_validate_v1(
        [41; 32],
        9,
        0,
        &input,
        137,
        Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

#[test]
fn independent_sequence_claim_refuses_missing_short_foreign_and_releases() {
    let requirement = sequence_requirement().unwrap();
    let bytes = requirement.total().unwrap();
    assert_eq!(bytes.device, 0);
    assert_eq!(requirement.get(Category::PhaseScratch), bytes);
    let ledger = Ledger::new(WorkerAllowance {
        host: bytes.host,
        device: 0,
    });
    check_pending(false, None, &ledger).unwrap();
    assert_eq!(check_pending(true, None, &ledger), Err(Error::Authority));
    let original = ledger.admit_phase(requirement).unwrap();
    check_pending(true, Some(&original), &ledger).unwrap();
    assert_eq!(
        check_pending(false, Some(&original), &ledger),
        Err(Error::Authority)
    );
    let foreign = Ledger::new(WorkerAllowance {
        host: bytes.host,
        device: 0,
    });
    assert_eq!(
        check_pending(true, Some(&original), &foreign),
        Err(Error::Authority)
    );
    assert!(ledger
        .reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 })
        .is_err());
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    let short = Ledger::new(WorkerAllowance {
        host: bytes.host - 1,
        device: 0,
    });
    assert!(short.admit_phase(requirement).is_err());
    assert_eq!(short.snapshot().current, Bytes::ZERO);
    // Claims and source ordinals only: no fake backend, runtime, proof or
    // successful sequence is constructed by these focused checks.
}

#[test]
fn source_sequence_preclaims_bridge_and_queue_before_runtime_and_releases() {
    let ledger = Ledger::new(WorkerAllowance {
        host: HOST_BYTES,
        device: DEVICE_BYTES,
    });
    let request = original_request(&ledger);
    let pending = PendingNativeHashx::reserve_before_native(&request, &ledger).unwrap();
    assert!(pending.outer_bridge.is_none());
    assert!(pending.outer_sequence.is_none());
    let before = ledger.snapshot();
    let pending = pending.with_outer_sequence().unwrap();
    check_bridge(pending.outer_bridge.as_ref().unwrap(), &ledger).unwrap();
    check_pending(true, pending.outer_sequence.as_ref(), &ledger).unwrap();
    assert_eq!(
        ledger.snapshot().current.host - before.current.host,
        bridge_requirement().unwrap().total().unwrap().host
            + sequence_requirement().unwrap().total().unwrap().host
    );
    assert_eq!(ledger.snapshot().current.device, before.current.device);
    assert!(pending.with_outer_sequence().is_err());
    drop(request);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn short_sequence_admission_consumes_and_cleans_the_entire_pending_owner() {
    let ledger = Ledger::new(WorkerAllowance {
        host: HOST_BYTES,
        device: DEVICE_BYTES,
    });
    let request = original_request(&ledger);
    let only_request = ledger.snapshot().current;
    let pending = PendingNativeHashx::reserve_before_native(&request, &ledger).unwrap();
    let needed = bridge_requirement().unwrap().total().unwrap().host
        + sequence_requirement().unwrap().total().unwrap().host;
    let blocker = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: ledger.remaining().host - (needed - 1),
                device: 0,
            },
        )
        .unwrap();
    assert!(matches!(
        pending.with_outer_sequence(),
        Err(Error::Admission)
    ));
    drop(blocker);
    assert_eq!(ledger.snapshot().current, only_request);
    drop(request);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
