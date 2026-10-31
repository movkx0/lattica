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
    let plan = ShakeRequestPlan::new([31; 32], 2, 0, input, output_len, Policy::default()).unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

#[test]
fn adapter_has_only_additive_host_metadata_without_another_proof_claim() {
    let requirement = requirements().unwrap();
    let bytes = requirement.total().unwrap();
    assert!(bytes.host > size_of::<VerifiedNativeSingleton>() as u64);
    assert!(bytes.host < 1 << 20);
    assert_eq!(bytes.device, 0);
    for category in Category::ALL {
        assert_eq!(
            requirement.get(category),
            if category == Category::PhaseScratch {
                bytes
            } else {
                Bytes::ZERO
            }
        );
    }
}

#[test]
fn metadata_key_is_constructed_under_the_original_adapter_claim_and_moves_with_it() {
    let ledger = ledger(HOST_BYTES);
    let owner = owner(&ledger, &[3], 1);
    let before = ledger.snapshot().current;
    let plan = AttachmentPlan::new(&owner, 0).unwrap();
    let expected = plan.requirements;
    let original = ledger.admit_phase(expected).unwrap();
    let pending = plan.claim_for(&owner, 0, original, &ledger).unwrap();
    let metadata = pending.prepare_metadata().unwrap();
    assert!(core::ptr::eq(metadata.owner, &owner));
    assert_eq!(metadata.index, 0);
    assert_eq!(metadata.key, owner.request().cache_key(0).unwrap());
    assert_eq!(metadata.original.requirements(), expected);
    assert!(metadata.shape.retained_bytes() <= 64 << 20);
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + expected.total().unwrap().host
    );
    let moved = Some(metadata);
    drop(moved);
    assert_eq!(ledger.snapshot().current, before);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn adapter_rejects_equal_requests_wrong_index_ledger_and_category_before_key_construction() {
    let ledger = ledger(HOST_BYTES);
    let unrelated = self::ledger(HOST_BYTES);
    let first = owner(&ledger, &[5], 1);
    let equal = owner(&ledger, &[5], 1);
    let before = ledger.snapshot().current;
    for wrong_index in [0, 1] {
        let plan = AttachmentPlan::new(&first, 0).unwrap();
        let original = ledger.admit_phase(plan.requirements).unwrap();
        let candidate = if wrong_index == 0 { &equal } else { &first };
        assert!(matches!(
            plan.claim_for(candidate, wrong_index, original, &ledger),
            Err(Error::Authority)
        ));
    }
    let plan = AttachmentPlan::new(&first, 0).unwrap();
    let original = unrelated.admit_phase(plan.requirements).unwrap();
    assert!(matches!(
        plan.claim_for(&first, 0, original, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
    let plan = AttachmentPlan::new(&first, 0).unwrap();
    let original = ledger
        .reserve(Category::NativeProof, plan.requirements.total().unwrap())
        .unwrap();
    assert!(matches!(
        plan.claim_for(&first, 0, original, &ledger),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot().current, before);
    drop(first);
    drop(equal);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn one_byte_short_adapter_admission_preserves_all_original_request_counters() {
    let generous = ledger(HOST_BYTES);
    let original = owner(&generous, &[7], 1);
    let request_bytes = generous.snapshot().current.host;
    let adapter_bytes = AttachmentPlan::new(&original, 0)
        .unwrap()
        .requirements
        .total()
        .unwrap()
        .host;
    drop(original);
    let short = ledger(request_bytes + adapter_bytes - 1);
    let original = owner(&short, &[7], 1);
    let before = short.snapshot();
    let plan = AttachmentPlan::new(&original, 0).unwrap();
    assert!(short.admit_phase(plan.requirements).is_err());
    assert_eq!(short.snapshot(), before);
    drop(plan);
    drop(original);
    assert_eq!(short.snapshot().current, Bytes::ZERO);
}

#[test]
fn source_plan_refuses_batches_and_missing_segments_without_metadata_or_runtime() {
    let ledger = ledger(HOST_BYTES);
    let owner = owner(&ledger, &[11; 8 * 136 + 7], 10 * 136 + 1);
    let before = ledger.snapshot();
    let mut batches = 0;
    for (index, air) in owner
        .request()
        .shake_partition()
        .unwrap()
        .segments()
        .iter()
        .enumerate()
    {
        match air {
            ShakeSegmentAir::Single(_) => {
                assert!(AttachmentPlan::new(&owner, index).is_ok());
            }
            ShakeSegmentAir::Batch(_) => {
                assert!(matches!(
                    AttachmentPlan::new(&owner, index),
                    Err(Error::Source)
                ));
                batches += 1;
            }
        }
    }
    assert!(batches > 0);
    assert!(matches!(
        AttachmentPlan::new(&owner, owner.request().segments().len()),
        Err(Error::Source)
    ));
    assert_eq!(ledger.snapshot(), before);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
