use super::*;
use crate::{
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Policy, ShakeRequestPlan},
};

fn ledger(host: u64) -> Ledger {
    Ledger::new(WorkerAllowance { host, device: 0 })
}

fn owned(ledger: &Ledger, input: &[u8], output_len: usize) -> ReservedShakeRequest {
    let plan = ShakeRequestPlan::new([37; 32], 4, 0, input, output_len, Policy::default()).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(token, ledger).unwrap()
}

#[test]
fn actual_request_source_selects_singletons_batches_and_transition_tails() {
    for (input_len, output_len) in [(0, 0), (0, 137), (135, 272), (8 * 136 + 7, 10 * 136 + 1)] {
        let input = vec![29; input_len];
        let ledger = ledger(32 << 30);
        let owner = owned(&ledger, &input, output_len);
        let before = ledger.snapshot();
        let Payload::Shake(owned_input) = &owner.request().payload else {
            unreachable!()
        };
        for index in 0..owner.request().segments().len() {
            let plan = NativePreparationPlan::new(&owner, index).unwrap();
            let census = plan.census();
            let info = owner.request().segments()[index];
            assert_eq!(census.geometry().first_permutation(), info.first_unit);
            assert_eq!(census.geometry().permutations(), info.units);
            assert_eq!(census.geometry().rows(), info.height);
            assert_eq!(census.geometry().width(), info.width);
            assert_eq!(
                census.trace_device().trace_bytes() as u64,
                info.raw_trace_bytes
            );
            assert_eq!(plan.input.as_ptr(), owned_input.as_ptr());
            assert_eq!(plan.input.len(), input_len);
            assert_eq!(plan.requirements().total().unwrap().device, 0);
            assert_eq!(
                plan.requirements().get(Category::SymbolicCompiler).host,
                census.host().prepared_partition_bytes().unwrap() as u64
            );
            assert_eq!(
                plan.requirements().total().unwrap().host as usize,
                census.host().required_host_bytes()
                    + size_of::<NativePreparationPlan<'_>>()
                    + size_of::<PendingNativePreparation<'_>>()
                    + shake_recording::additional_host_bytes()
            );
        }
        assert_eq!(ledger.snapshot(), before);
        assert!(matches!(
            NativePreparationPlan::new(&owner, owner.request().segments().len()),
            Err(Error::Request)
        ));
        drop(owner);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn original_request_and_token_identity_cannot_be_substituted() {
    let ledger = ledger(32 << 30);
    let unrelated = self::ledger(32 << 30);
    let first = owned(&ledger, &[1, 2, 3], 137);
    let equal = owned(&ledger, &[1, 2, 3], 137);
    let baseline = ledger.snapshot().current;
    let plan = NativePreparationPlan::new(&first, 0).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    assert!(matches!(
        plan.claim_for(&equal, 0, token, &ledger),
        Err(Error::Request)
    ));
    assert_eq!(ledger.snapshot().current, baseline);
    let plan = NativePreparationPlan::new(&first, 0).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    assert!(matches!(
        plan.claim_for(&first, 1, token, &ledger),
        Err(Error::Request)
    ));
    assert_eq!(ledger.snapshot().current, baseline);
    let plan = NativePreparationPlan::new(&first, 0).unwrap();
    let token = unrelated.admit_phase(plan.requirements()).unwrap();
    assert!(matches!(
        plan.claim_for(&first, 0, token, &ledger),
        Err(Error::WrongLedger)
    ));
    assert_eq!(unrelated.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().current, baseline);
}

#[test]
fn exact_category_claim_is_required_and_moves_keep_original_storage_live() {
    let ledger = ledger(32 << 30);
    let marker = ledger.clone();
    let owner = owned(&ledger, &[6; 137], 272);
    let baseline = ledger.snapshot().current;
    let plan = NativePreparationPlan::new(&owner, 0).unwrap();
    let total = plan.requirements().total().unwrap();
    let token = ledger.reserve(Category::PhaseScratch, total).unwrap();
    assert!(matches!(
        plan.claim_for(&owner, 0, token, &ledger),
        Err(Error::WrongReservation)
    ));
    assert_eq!(ledger.snapshot().current, baseline);
    let plan = NativePreparationPlan::new(&owner, 0).unwrap();
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let pending = plan.claim_for(&owner, 0, token, &ledger).unwrap();
    assert!(pending.is_for(&owner, 0, &marker));
    assert!(core::ptr::eq(pending.request(), owner.request()));
    assert_eq!(pending.index(), 0);
    assert_eq!(pending.input(), &[6; 137]);
    assert_eq!(pending.air().height(), pending.census().geometry().rows());
    assert!(pending.reservation().belongs_to(&marker));
    drop(ledger);
    let moved = Some(pending);
    assert_eq!(marker.snapshot().current.host, baseline.host + total.host);
    drop(moved);
    assert_eq!(marker.snapshot().current, baseline);
    drop(owner);
    assert_eq!(marker.snapshot().current, Bytes::ZERO);
}

#[test]
fn one_byte_short_preparation_admission_preserves_original_request() {
    let generous = ledger(32 << 30);
    let owner = owned(&generous, &[4; 136], 137);
    let source = generous.snapshot().current;
    let preparation = NativePreparationPlan::new(&owner, 0)
        .unwrap()
        .requirements()
        .total()
        .unwrap();
    drop(owner);
    let short = ledger(source.host + preparation.host - 1);
    let owner = owned(&short, &[4; 136], 137);
    let plan = NativePreparationPlan::new(&owner, 0).unwrap();
    let before = short.snapshot();
    assert!(short.admit_phase(plan.requirements()).is_err());
    assert_eq!(short.snapshot(), before);
    drop(plan);
    drop(owner);
    assert_eq!(short.snapshot().current, Bytes::ZERO);
}
