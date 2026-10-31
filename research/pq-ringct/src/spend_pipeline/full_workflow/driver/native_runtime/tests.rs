use super::*;
use crate::execution::retained_resources::{Ledger, WorkerAllowance};

#[test]
fn retained_failure_survives_inspection_and_refused_extraction() {
    let ledger = Ledger::new(WorkerAllowance { host: 4096, device: 0 });
    let original = ledger.admit_phase(Requirements::single(Category::Report,
        Bytes { host: 512, device: 0 })).unwrap();
    let mut value: Option<Outcome<(), _>> = Some(Err(original));
    assert!(matches!(ready(&value), Err(WorkflowError::Poisoned)));
    assert!(matches!(take_ready(&mut value), Err(WorkflowError::Poisoned)));
    assert!(value.as_ref().unwrap().as_ref().unwrap_err().belongs_to(&ledger));
    assert_eq!(ledger.snapshot().current, Bytes { host: 512, device: 0 });
    drop(value);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn occupied_or_borrowed_cell_keeps_original_owner() {
    let ledger = Ledger::new(WorkerAllowance { host: 4096, device: 0 });
    let original = ledger.admit_phase(Requirements::single(Category::Report,
        Bytes { host: 512, device: 0 })).unwrap();
    let cell = RefCell::new(Some(Ok::<_, WorkflowError>(original)));
    let borrowed = read(&cell).unwrap();
    assert!(matches!(empty(&borrowed), Err(WorkflowError::SlotBusy)));
    assert!(matches!(write(&cell), Err(WorkflowError::SlotBusy)));
    assert_eq!(ledger.snapshot().current, Bytes { host: 512, device: 0 });
    drop(borrowed);
    let owner = take_ready(&mut write(&cell).unwrap()).unwrap();
    assert!(owner.belongs_to(&ledger));
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn route_ordinals_reject_missing_reordered_and_overflow_without_advancing() {
    let mut count = 0usize;
    assert!(matches!(next_count(&mut count, 1), Err(WorkflowError::Sequence)));
    assert_eq!(count, 0);
    next_count(&mut count, 0).unwrap();
    assert!(matches!(next_count(&mut count, 0), Err(WorkflowError::Sequence)));
    assert_eq!(count, 1);
    let mut full = usize::MAX;
    assert!(matches!(next_count(&mut full, usize::MAX), Err(WorkflowError::Overflow)));
    assert_eq!(full, usize::MAX);
}
