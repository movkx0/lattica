use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Policy, ShakeRequestPlan},
};

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance {
        host,
        device: DEVICE_BYTES,
    })
}

fn owner(ledger: &Ledger, input: &[u8], output_len: usize) -> ReservedShakeRequest {
    let plan = ShakeRequestPlan::new([93; 32], 6, 0, input, output_len, Policy::default()).unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

#[test]
fn original_preissued_metadata_owns_exact_source_charge_before_any_native_owner() {
    let ledger = ledger(HOST_BYTES);
    let owner = owner(&ledger, &[1], 1);
    let before = ledger.snapshot();
    let expected = MetadataOwner::source_requirement(&owner, 0).unwrap();
    assert_eq!(ledger.snapshot(), before);
    let prepared = MetadataOwner::reserve_before_native(&owner, 0, &ledger).unwrap();
    assert!(prepared.is_for(&owner, 0, &ledger));
    assert_eq!(prepared.original.requirements(), expected);
    assert_eq!(prepared.key, owner.request().cache_key(0).unwrap());
    assert!(prepared.shape.retained_bytes() <= 64 << 20);
    assert_eq!(
        ledger.snapshot().current.host,
        before.current.host + expected.total().unwrap().host
    );
    assert_eq!(ledger.snapshot().current.device, before.current.device);
    for category in Category::ALL {
        let actual = ledger.snapshot().categories[category as usize];
        let previous = before.categories[category as usize];
        let additional = expected.get(category);
        assert_eq!(actual.current.host, previous.current.host + additional.host);
        assert_eq!(
            actual.current.device,
            previous.current.device + additional.device
        );
    }
    let moved = Some(prepared);
    drop(moved);
    assert_eq!(ledger.snapshot().current, before.current);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn preissued_metadata_rejects_foreign_ledger_and_cannot_be_retargeted() {
    let ledger = ledger(HOST_BYTES);
    let foreign = self::ledger(HOST_BYTES);
    let first = owner(&ledger, &[2], 1);
    let equal = owner(&ledger, &[2], 1);
    let before = ledger.snapshot();
    assert!(matches!(
        MetadataOwner::reserve_before_native(&first, 0, &foreign),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let prepared = MetadataOwner::reserve_before_native(&first, 0, &ledger).unwrap();
    assert!(!prepared.is_for(&equal, 0, &ledger));
    assert!(!prepared.is_for(&first, 1, &ledger));
    assert!(!prepared.is_for(&first, 0, &foreign));
    assert!(prepared.is_for(&first, 0, &ledger));
    drop(prepared);
    assert_eq!(ledger.snapshot().current, before.current);
    drop(first);
    drop(equal);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn preissued_metadata_refuses_short_budget_and_unsupported_source_without_leaks() {
    let generous = ledger(HOST_BYTES);
    let original = owner(&generous, &[3], 1);
    let request_bytes = generous.snapshot().current.host;
    let adapter_bytes = MetadataOwner::source_requirement(&original, 0)
        .unwrap()
        .total()
        .unwrap()
        .host;
    drop(original);
    let short = ledger(request_bytes + adapter_bytes - 1);
    let original = owner(&short, &[3], 1);
    let before = short.snapshot();
    assert!(matches!(
        MetadataOwner::reserve_before_native(&original, 0, &short),
        Err(Error::Admission)
    ));
    assert_eq!(short.snapshot(), before);
    drop(original);
    assert_eq!(short.snapshot().current, Bytes::ZERO);

    let original = owner(&generous, &[5; 8 * 136 + 7], 10 * 136 + 1);
    let before = generous.snapshot();
    let batch = original
        .request()
        .shake_partition()
        .unwrap()
        .segments()
        .iter()
        .position(|air| matches!(air, ShakeSegmentAir::Batch(_)))
        .unwrap();
    for index in [batch, original.request().segments().len()] {
        assert!(matches!(
            MetadataOwner::source_requirement(&original, index),
            Err(Error::Source)
        ));
        assert!(matches!(
            MetadataOwner::reserve_before_native(&original, index, &generous),
            Err(Error::Source)
        ));
    }
    assert_eq!(generous.snapshot(), before);
    drop(original);
    assert_eq!(generous.snapshot().current, Bytes::ZERO);
}
