use super::*;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn fresh_planning_startup_has_no_idle_tree_payload_or_second_worker_allowance() {
    if cfg!(debug_assertions) { return; }
    let plan = PlanningStartupPlan::new().unwrap();
    let permanent = plan.permanent_requirements();
    let startup = plan.startup_requirements();
    let together = plan.requirements().unwrap();
    assert_eq!(startup.total().unwrap().host, 0);
    assert!(startup.total().unwrap().device > 0);
    assert!(startup.total().unwrap().device < 8 << 30);
    assert_eq!(permanent.total().unwrap().device, 0);
    assert_eq!(permanent.get(Category::RegisteredMetadata).host, 64 << 20);
    assert!(permanent.total().unwrap().host < 1 << 30);
    assert_eq!(together, super::super::memory::combine(permanent, startup).unwrap());
}

#[test]
fn uncertain_planning_startup_does_not_release_its_original() {
    let ledger = Ledger::new(WorkerAllowance { host: 1024, device: 1024 });
    let requirements = Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: 512 });
    let original = ledger.admit_phase(requirements).unwrap();
    let owner = OriginalPlanningStartup { ledger: ledger.clone(),
        original: RefCell::new(Some(original)), requirements, session_id: Cell::new(None),
        closed_requirements: Cell::new(None), capability_issued: Cell::new(false), armed: Cell::new(true) };
    assert_eq!(owner.current_requirements().unwrap(), requirements);
    drop(owner);
    // No actual runtime/retirement is fabricated by this bookkeeping test.
    // The reservation is intentionally kept, so later admissions cannot reuse
    // the uncertain epoch's allowance just because its Rust wrapper dropped.
    assert_eq!(ledger.snapshot().current.device, 512);
    assert!(ledger.admit_phase(Requirements::single(Category::PhaseScratch,
        Bytes { host: 0, device: 513 })).is_err());
}

#[test]
fn unstarted_planning_storage_can_drop_without_fabricating_retirement() {
    let ledger = Ledger::new(WorkerAllowance { host: 1024, device: 1024 });
    let requirements = Requirements::single(Category::PhaseScratch, Bytes { host: 0, device: 512 });
    let owner = OriginalPlanningStartup { ledger: ledger.clone(),
        original: RefCell::new(Some(ledger.admit_phase(requirements).unwrap())),
        requirements, session_id: Cell::new(None), closed_requirements: Cell::new(None), capability_issued: Cell::new(false),
        armed: Cell::new(false) };
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
