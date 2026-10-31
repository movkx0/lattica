use super::*;
use crate::execution::{
    retained_resources::{Bytes, Category, Ledger, Requirements},
    ProvingContext,
};
use std::{cell::Cell, rc::Rc};

fn bytes(host: u64) -> Bytes {
    Bytes { host, device: 0 }
}

fn specs() -> [SlotSpec; 2] {
    [
        SlotSpec { requirements: Requirements::single(Category::NativeProof, bytes(64)) },
        SlotSpec { requirements: Requirements::single(Category::Report, bytes(32)) },
    ]
}

fn requirements() -> Requirements {
    let mut request = Requirements::single(Category::PhaseScratch, bytes(128));
    request.add(Category::NativeProof, bytes(64)).unwrap();
    request.add(Category::Report, bytes(32)).unwrap();
    request.add(Category::RegisteredMetadata, bytes(owners::SlotPool::bookkeeping_bytes(2).unwrap())).unwrap();
    request
}

struct PayloadProbe {
    ledger: Ledger,
    observed: Rc<Cell<bool>>,
}

struct SplitPayloadProbe {
    payload: PayloadProbe,
    proof: crate::execution::retained_resources::Reservation,
    report: crate::execution::retained_resources::Reservation,
}
impl owners::OriginalOutput for SplitPayloadProbe {
    fn destroy_into_originals(self) -> [Option<crate::execution::retained_resources::Reservation>; 4] {
        let Self { payload, proof, report } = self;
        drop(payload);
        [Some(proof), Some(report), None, None]
    }
}

#[test]
fn split_output_claims_follow_payload_moves_and_rejoin_after_payload_death() {
    let context = ProvingContext::cpu(8192).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(requirements()).unwrap();
    let mut output = Requirements::single(Category::NativeProof, bytes(64));
    output.add(Category::Report, bytes(32)).unwrap();
    let pool = owners::SlotPool::new(&mut phase, &[SlotSpec { requirements: output }]).unwrap();
    pool.begin().unwrap();
    let mut claim = pool.claim(SlotId::new(0)).unwrap();
    let proof = claim.split(Requirements::single(Category::NativeProof, bytes(64))).unwrap();
    let report = claim.split(Requirements::single(Category::Report, bytes(32))).unwrap();
    let observed = Rc::new(Cell::new(false));
    let retained = owners::RetainedOriginal::produced(SplitPayloadProbe {
        payload: PayloadProbe { ledger: ledger.clone(), observed: Rc::clone(&observed) },
        proof,
        report,
    }, claim, PhaseBinding::fixture(PhaseKind::Native));
    let moved = retained;
    assert_eq!(ledger.snapshot().current, bytes(224 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    drop(moved);
    assert!(observed.get());
    assert_eq!(ledger.snapshot().current, bytes(224 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    assert!(!pool.is_available(SlotId::new(0)));
    phase.cleanup_between_operations().unwrap();
    pool.after_cleanup().unwrap();
    assert!(pool.is_available(SlotId::new(0)));
    phase.complete_after_cleanup().unwrap();
    pool.retire().unwrap();
    drop(pool);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

impl Drop for PayloadProbe {
    fn drop(&mut self) {
        // The complete original pool and scratch are still charged while the
        // payload destructor executes, including on a moved/error path.
        assert_eq!(self.ledger.snapshot().current, bytes(224 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
        self.observed.set(true);
    }
}

#[test]
fn original_slot_survives_move_and_payload_drop_until_actual_cleanup() {
    let context = ProvingContext::cpu(8192).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(requirements()).unwrap();
    let pool = owners::SlotPool::new(&mut phase, &specs()).unwrap();
    pool.begin().unwrap();
    let claim = pool.claim(SlotId::new(0)).unwrap();
    let observed = Rc::new(Cell::new(false));
    let value = Retained::produced(
        PayloadProbe { ledger: ledger.clone(), observed: Rc::clone(&observed) },
        claim,
        PhaseBinding::fixture(PhaseKind::Native),
    );
    assert_eq!(value.slot_id(), SlotId::new(0));
    let moved = value;
    drop(moved);
    assert!(observed.get());
    assert!(!pool.is_available(SlotId::new(0)));
    assert_eq!(ledger.snapshot().current, bytes(224 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    phase.cleanup_between_operations().unwrap();
    pool.after_cleanup().unwrap();
    assert!(pool.is_available(SlotId::new(0)));
    // Reuse moves the SAME reservation: no fresh ledger admission or decrease
    // in the whole preissued pool occurs across successive output lifetimes.
    pool.begin().unwrap();
    let original_again = pool.claim(SlotId::new(0)).unwrap();
    assert_eq!(ledger.snapshot().current, bytes(224 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    drop(original_again);
    phase.cleanup_between_operations().unwrap();
    pool.after_cleanup().unwrap();
    phase.complete_after_cleanup().unwrap();
    pool.retire().unwrap();
    assert_eq!(ledger.snapshot().current, bytes(96 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    drop(pool);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn failed_phase_never_reopens_slots_and_terminal_cleanup_does_not_resume() {
    let context = ProvingContext::cpu(8192).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(requirements()).unwrap();
    let pool = owners::SlotPool::new(&mut phase, &specs()).unwrap();
    pool.begin().unwrap();
    let original = pool.claim(SlotId::new(0)).unwrap();
    drop(original);
    pool.poison();
    assert!(pool.begin().is_err());
    assert!(pool.after_cleanup().is_err());
    assert!(!pool.is_available(SlotId::new(0)));
    assert_eq!(ledger.snapshot().current, bytes(224 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    phase.retire_after_failure().unwrap();
    pool.retire_after_cleanup();
    assert!(pool.begin().is_err());
    drop(pool);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn retained_failure_outlives_context_cleanup_with_its_original_claim() {
    let context = ProvingContext::cpu(8192).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(requirements()).unwrap();
    let pool = owners::SlotPool::new(&mut phase, &specs()).unwrap();
    pool.begin().unwrap();
    let failure = RetainedFailure::produced(
        Some(7u8),
        Some(WorkflowError::Sequence),
        pool.claim(SlotId::new(1)).unwrap(),
    );
    phase.cleanup_between_operations().unwrap();
    pool.after_cleanup().unwrap();
    phase.retire_after_failure().unwrap();
    pool.retire_after_cleanup();
    drop(pool);
    drop(context);
    assert_eq!(failure.get(), Some(&7));
    assert_eq!(failure.status(), Some(&WorkflowError::Sequence));
    assert_eq!(ledger.snapshot().current, bytes(96 + owners::SlotPool::bookkeeping_bytes(2).unwrap()));
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn owned_phase_scratch_cannot_be_split_or_rebound_after_completion() {
    let context = ProvingContext::cpu(8192).unwrap();
    let capability = context.phase_capability(bytes(128)).unwrap();
    let mut phase = capability.admit_owned(requirements()).unwrap();
    assert!(phase
        .split(Requirements::single(Category::PhaseScratch, bytes(1)))
        .is_err());
    phase.complete_after_cleanup().unwrap();
    assert!(context.phase_capability(Bytes::ZERO).is_err());
}
