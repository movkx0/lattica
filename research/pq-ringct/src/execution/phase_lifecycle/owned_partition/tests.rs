use super::*;

fn scratch(host: u64) -> Requirements {
    Requirements::single(Category::PhaseScratch, Bytes { host, device: 0 })
}

#[test]
fn exact_originals_move_without_new_credit_and_restore_the_same_phase() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(scratch(512)).unwrap();
    let before = ledger.snapshot();
    let mut partition = phase.partition_originals(scratch(384)).unwrap();
    let startup = partition.split(scratch(128)).unwrap();
    let pcs = partition.split(scratch(256)).unwrap();
    assert_eq!(ledger.snapshot(), before);
    partition.reunite(startup).unwrap();
    partition.reunite(pcs).unwrap();
    assert!(partition.restore().is_ok());
    assert_eq!(ledger.snapshot(), before);
    phase.complete_after_cleanup().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn missing_piece_prevents_restoration_without_consuming_any_owner() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(scratch(512)).unwrap();
    let before = ledger.snapshot();
    let mut partition = phase.partition_originals(scratch(384)).unwrap();
    let pcs = partition.split(scratch(256)).unwrap();
    let mut partition = match partition.restore() {
        Err(partition) => partition,
        Ok(()) => panic!("incomplete originals were restored"),
    };
    assert_eq!(ledger.snapshot(), before);
    partition.reunite(pcs).unwrap();
    assert!(partition.restore().is_ok());
    phase.complete_after_cleanup().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn foreign_and_excess_claims_are_returned_intact() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(scratch(512)).unwrap();
    let foreign = Ledger::new(WorkerAllowance { host: 128, device: 0 });
    let mut partition = phase.partition_originals(scratch(384)).unwrap();
    let wrong = foreign.admit_phase(scratch(64)).unwrap();
    let (error, wrong) = partition.reunite(wrong).unwrap_err();
    assert_eq!(error, Error::Reservation(ReservationError::DifferentLedger));
    assert!(wrong.belongs_to(&foreign));
    drop(wrong);
    let extra = ledger.admit_phase(scratch(1)).unwrap();
    let (error, extra) = partition.reunite(extra).unwrap_err();
    assert_eq!(error, Error::IncompleteOwnedPartition);
    assert_eq!(extra.requirements(), scratch(1));
    drop(extra);
    assert!(partition.restore().is_ok());
    phase.complete_after_cleanup().unwrap();
}

#[test]
fn forgotten_partition_cannot_open_a_cleanup_or_dispatch_gap() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(scratch(512)).unwrap();
    let partition = phase.partition_originals(scratch(384)).unwrap();
    core::mem::forget(partition);
    assert_eq!(phase.cleanup_between_operations(), Err(Error::OutstandingOwnedPartition));
    assert!(matches!(phase.split(scratch(0)), Err(Error::OutstandingOwnedPartition)));
    assert!(matches!(phase.original_for_preissue(), Err(Error::OutstandingOwnedPartition)));
    assert_eq!(phase.retire_after_failure(), Err(Error::OutstandingOwnedPartition));
    assert_eq!(ledger.snapshot().current, Bytes { host: 512, device: 0 });
}

#[test]
fn preissue_borrows_the_same_original_without_releasing_credit() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let phase = capability.admit_owned(scratch(512)).unwrap();
    let before = ledger.snapshot();
    let original = phase.original_for_preissue().unwrap();
    assert!(original.belongs_to(&ledger));
    assert_eq!(original.requirements(), scratch(512));
    assert_eq!(ledger.snapshot(), before);
    assert!(context.phases.state.try_borrow_mut().is_err());
    drop(original);
    phase.complete_after_cleanup().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn abandoned_partition_permanently_poisons_the_accounting_scope() {
    let context = ProvingContext::cpu(1024).unwrap();
    let capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability.admit_owned(scratch(512)).unwrap();
    drop(phase.partition_originals(scratch(384)).unwrap());
    assert_eq!(context.phases.state.borrow().status, Status::Poisoned);
    assert!(phase.cleanup_between_operations().is_err());
    assert_eq!(phase.retire_after_failure(), Err(Error::OutstandingOwnedPartition));
    assert_eq!(ledger.snapshot().current, Bytes { host: 512, device: 0 });
}
