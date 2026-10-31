use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Policy, ShakeRequestPlan},
};

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: HOST_BYTES,
        device: DEVICE_BYTES,
    })
}

fn request(ledger: &Ledger, input: &[u8], output: usize) -> ReservedShakeRequest {
    let plan = ShakeRequestPlan::new([96; 32], 9, 0, input, output, Policy::default()).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(token, ledger).unwrap()
}

#[test]
fn all_future_native_claims_precede_runtime_and_drop_to_the_original_request() {
    let ledger = ledger();
    let owner = request(&ledger, &[7; 137], 137);
    assert_eq!(owner.request().segments().len(), 3);
    let before = ledger.snapshot().current;
    let one = FutureNativeSingleton::reserve_before_native(&owner, 1, &ledger).unwrap();
    let two = FutureNativeSingleton::reserve_before_native(&owner, 2, &ledger).unwrap();
    assert!(one.source.preparation.is_for(&owner, 1, &ledger));
    assert!(two.source.preparation.is_for(&owner, 2, &ledger));
    assert_eq!(ledger.snapshot().current.device, before.device);
    assert!(ledger.snapshot().current.host > before.host);
    drop((one, two));
    assert_eq!(ledger.snapshot().current, before);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn unsupported_counts_indices_and_foreign_ledgers_refuse_without_claiming() {
    let ledger = ledger();
    let other = self::ledger();
    let singleton = request(&ledger, &[1], 1);
    let pair = request(&ledger, &[1], 137);
    let batched = request(&ledger, &[3; 8 * 136 + 7], 10 * 136 + 1);
    assert_eq!(pair.request().segments().len(), 2);
    let before = ledger.snapshot();
    for (owner, index) in [(&singleton, 1), (&pair, 0), (&pair, 2), (&batched, 1)] {
        assert!(matches!(
            FutureNativeSingleton::reserve_before_native(owner, index, &ledger),
            Err(Error::Source)
        ));
        assert_eq!(ledger.snapshot(), before);
    }
    assert!(matches!(
        FutureNativeSingleton::reserve_before_native(&pair, 1, &other),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(other.snapshot().current, Bytes::ZERO);
}

#[test]
fn sequence_caller_census_refuses_unbounded_shapes_and_counts_full_return_owners() {
    assert!(matches!(
        FutureNativeSingleton::additional_sequence_caller_host_bytes(0),
        Err(Error::Source)
    ));
    assert!(matches!(
        FutureNativeSingleton::additional_sequence_caller_host_bytes(3),
        Err(Error::Source)
    ));
    let one = FutureNativeSingleton::additional_sequence_caller_host_bytes(1).unwrap();
    let two = FutureNativeSingleton::additional_sequence_caller_host_bytes(2).unwrap();
    assert_eq!(two, 2 * one);
    assert!(one > 4 * size_of::<NativeSuccessorError<'static>>());
}
