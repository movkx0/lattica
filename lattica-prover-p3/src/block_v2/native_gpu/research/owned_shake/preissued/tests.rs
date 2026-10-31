use super::*;
use crate::block_v2::native_gpu::{ShakeTraceSpec, shake_output::ShakeOutputPlan};
use crate::ringct_research_quota::WorkerAllowance;

fn source() -> ShakePreparationPlan {
    ShakePreparationPlan::singleton(ShakeTraceSpec {
        input_len: 137, output_len: 17, first_permutation: 0, permutations: 1,
    }).unwrap()
}

#[test]
fn preissued_inventory_is_pure_and_charges_the_complete_device_capacity_once() {
    for host_trees in [false, true] {
        let preparation = source();
        let (plan, allocations) = crate::spill_alloc::allocation_requests::measure(|| {
            if host_trees {
                NativeShakeReservationPlan::outer_host_v1(preparation, 1 << 30)
            } else {
                NativeShakeReservationPlan::device(preparation, 1 << 30)
            }.unwrap()
        });
        assert_eq!((allocations.calls, allocations.bytes, allocations.overflow), (0, 0, false));
        assert_eq!(plan.preparation(), preparation);
        let start = plan.startup_requirement().get(Category::PhaseScratch);
        let pcs = plan.pcs_requirement().get(Category::PhaseScratch);
        let wrapper = plan.wrapper_requirement().get(Category::PhaseScratch);
        assert_eq!(start.device + pcs.device + wrapper.device, MANAGED_DEVICE);
        assert_eq!(pcs.host, 1 << 30);
        assert!(wrapper.host > 0);
        assert_eq!(plan.verifier_requirement(), Requirements::single(
            Category::IndependentVerifier, Bytes { host: VERIFIER_HOST, device: 0 }));
        if host_trees { assert!(start.host > 8 << 30); }
    }
    assert!(NativeShakeReservationPlan::device(source(), 0).is_err());
    assert!(NativeShakeReservationPlan::device(source(), NATIVE_HOST + 1).is_err());
}

#[test]
fn wrong_preissued_wrapper_returns_all_originals_without_runtime_or_fresh_credit() {
    let ledger = Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE });
    let source = source();
    let plan = NativeShakeReservationPlan::device(source, 1 << 30).unwrap();
    let preparation = ledger.admit_phase(plan.preparation_requirement().unwrap()).unwrap();
    let startup = ledger.admit_phase(plan.startup_requirement()).unwrap();
    let verifier = ledger.admit_phase(plan.verifier_requirement()).unwrap();
    let mut wrapper = plan.wrapper_requirement().get(Category::PhaseScratch);
    wrapper.host -= 1;
    let wrapper = ledger.reserve(Category::PhaseScratch, wrapper).unwrap();
    let pcs = ledger.admit_phase(plan.pcs_requirement()).unwrap();
    let output_plan = ShakeOutputPlan::new(source).unwrap();
    let output = output_plan.claim(
        ledger.admit_phase(output_plan.proof_requirement()).unwrap(),
        ledger.admit_phase(output_plan.report_requirement()).unwrap(),
        &ledger,
    ).unwrap();
    let before = ledger.snapshot().current;
    // The deliberately wrong original wrapper is rejected before physical
    // selection or any GPU runtime constructor is reachable.
    let refused = unsafe { NativeShakePhase::from_originals(
        plan, &preparation, &startup, output, &verifier, wrapper, pcs, &ledger,
    ) };
    let Err((error, output, wrapper, pcs)) = refused else {
        panic!("wrong original wrapper was accepted");
    };
    assert_eq!(error, Error::Authority);
    assert_eq!(ledger.snapshot().current, before);
    let (proof, report) = output.into_originals();
    assert_eq!(proof.requirements(), output_plan.proof_requirement());
    assert_eq!(report.requirements(), output_plan.report_requirement());
    assert_eq!(pcs.requirements(), plan.pcs_requirement());
    drop((preparation, startup, verifier, wrapper, pcs, proof, report));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn wrong_ledger_output_claim_returns_the_exact_originals_without_credit_release() {
    let ledger = Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE });
    let foreign = Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE });
    let plan = ShakeOutputPlan::new(source()).unwrap();
    let proof = ledger.admit_phase(plan.proof_requirement()).unwrap();
    let report = foreign.admit_phase(plan.report_requirement()).unwrap();
    let own_before = ledger.snapshot().current;
    let other_before = foreign.snapshot().current;
    let Err((_error, proof, report)) = plan.claim_preserving(proof, report, &ledger) else {
        panic!("foreign report original was accepted");
    };
    assert!(proof.belongs_to(&ledger));
    assert!(report.belongs_to(&foreign));
    assert_eq!(ledger.snapshot().current, own_before);
    assert_eq!(foreign.snapshot().current, other_before);
    drop((proof, report));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
}
