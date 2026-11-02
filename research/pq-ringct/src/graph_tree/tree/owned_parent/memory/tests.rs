use super::*;
use crate::execution::retained_resources::{Bytes, WorkerAllowance};

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 })
}

#[test]
fn parent_retained_plan_keeps_outer_metadata_and_each_temporary_scope_covers_callers() {
    let retained = GraphParentPlan::planning_requirements().unwrap();
    let prefix = retained_planning_frames().unwrap();
    let outer = PreissuedGraphParentOuter::metadata_host_bytes().unwrap();
    assert_eq!(retained.get(Category::RegisteredMetadata).host, (prefix + outer) as u64);
    assert_eq!(retained.total().unwrap().host, (prefix + outer) as u64);
    assert_eq!(retained.total().unwrap().device, 0);
    assert!(prefix >= size_of::<GraphParentPlan<'static, 'static>>());

    let callers = caller_frames().unwrap() as u64;
    let construction = GraphParentPlan::planning_scratch_requirements().unwrap();
    let (_, compiler) = compiler_requirements(source::MAX_ROWS, source::MAX_ROWS).unwrap();
    let outer = super::super::outer::caller_requirements().unwrap();
    assert!(construction.get(Category::PhaseScratch).host >= planning_frames().unwrap() as u64);
    assert!(compiler.get(Category::PhaseScratch).host >= callers);
    assert!(outer.get(Category::PhaseScratch).host >= callers);

    let ledger = ledger();
    let original = ledger.admit_phase(retained).unwrap();
    let scratch = ledger.admit_phase(construction).unwrap();
    GraphParentPlan::check_planning_claims(&original, &scratch, &ledger).unwrap();
    let original = Some(original).unwrap();
    drop(scratch);
    // Retiring temporary construction storage never releases the plan or its
    // complete outer-preissue metadata. No graph, case, or proof is fabricated.
    assert_eq!(ledger.snapshot().current, retained.total().unwrap());
    assert_eq!(original.requirements(), retained);
    assert!(original.belongs_to(&ledger));
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn parent_planning_claim_refusal_preserves_originals_and_ledger_counters() {
    let ledger = ledger();
    let foreign = self::ledger();
    let required = GraphParentPlan::planning_requirements().unwrap();
    let construction = GraphParentPlan::planning_scratch_requirements().unwrap();
    let original = ledger.admit_phase(required).unwrap();
    let scratch = ledger.admit_phase(construction).unwrap();
    let other_original = foreign.admit_phase(required).unwrap();
    let other_scratch = foreign.admit_phase(construction).unwrap();
    let before = ledger.snapshot();
    let foreign_before = foreign.snapshot();
    assert_eq!(GraphParentPlan::check_planning_claims(&other_original, &scratch, &ledger),
        Err(GraphParentFailure::Authority));
    assert_eq!(GraphParentPlan::check_planning_claims(&original, &other_scratch, &ledger),
        Err(GraphParentFailure::Authority));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot(), foreign_before);
    assert_eq!(original.requirements(), required);
    assert_eq!(scratch.requirements(), construction);

    drop(other_scratch);
    drop(other_original);
    drop(scratch);
    assert_eq!(ledger.snapshot().current, required.total().unwrap());
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn parent_claim_requires_exact_retained_original_and_full_construction_scratch() {
    let ledger = ledger();
    let required = GraphParentPlan::planning_requirements().unwrap();
    let construction = GraphParentPlan::planning_scratch_requirements().unwrap();
    let host = required.get(Category::RegisteredMetadata).host;
    let scratch_host = construction.get(Category::PhaseScratch).host;
    for retained_host in [host - 1, host + caller_frames().unwrap() as u64] {
        let altered = Requirements::single(Category::RegisteredMetadata,
            Bytes { host: retained_host, device: 0 });
        let original = ledger.admit_phase(altered).unwrap();
        let scratch = ledger.admit_phase(construction).unwrap();
        let before = ledger.snapshot();
        assert_eq!(GraphParentPlan::check_planning_claims(&original, &scratch, &ledger),
            Err(GraphParentFailure::Authority));
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(original.requirements(), altered);
    }
    let original = ledger.admit_phase(required).unwrap();
    let short = Requirements::single(Category::PhaseScratch,
        Bytes { host: scratch_host - 1, device: 0 });
    let scratch = ledger.admit_phase(short).unwrap();
    let before = ledger.snapshot();
    assert_eq!(GraphParentPlan::check_planning_claims(&original, &scratch, &ledger),
        Err(GraphParentFailure::Authority));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(original.requirements(), required);
    assert_eq!(scratch.requirements(), short);
}
