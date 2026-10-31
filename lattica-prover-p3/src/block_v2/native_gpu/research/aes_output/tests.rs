use super::*;
use crate::block_v2::native_gpu::AesTraceSpec;
use crate::ringct_research_quota::WorkerAllowance;

fn source(blocks: usize, first_block: usize) -> AesPreparationPlan {
    AesPreparationPlan::new(AesTraceSpec {
        domain: 17,
        start_counter: u32::MAX,
        output_len: (blocks + first_block) * 16 - 1,
        first_block,
        blocks,
    })
    .unwrap()
}

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 })
}

#[test]
fn every_native_aes_shape_has_a_pure_retained_output_bound() {
    let mut previous = 0;
    for blocks in 1..=64 {
        let source = source(blocks, 0);
        let (plan, allocations) = crate::spill_alloc::allocation_requests::measure(|| {
            AesOutputPlan::new(source).unwrap()
        });
        assert_eq!((allocations.calls, allocations.bytes, allocations.overflow), (0, 0, false));
        assert!(plan.source_proof_host_bytes() >= previous);
        assert!(plan.source_proof_host_bytes() <= PROOF_BACKING_CEILING);
        previous = plan.source_proof_host_bytes();
    }
}

#[test]
fn original_aes_claims_move_and_release_without_reserving_twice() {
    let ledger = ledger();
    let source = source(5, 64);
    let plan = AesOutputPlan::new(source).unwrap();
    let proof = ledger.admit_phase(plan.proof_requirement()).unwrap();
    let report = ledger.admit_phase(plan.report_requirement()).unwrap();
    let before = ledger.snapshot().current;
    let pending = plan.claim(proof, report, &ledger).unwrap();
    pending.check(source, &ledger).unwrap();
    let moved = Some(pending);
    assert_eq!(ledger.snapshot().current, before);
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn equal_size_foreign_aes_claims_and_changed_segment_identity_are_refused() {
    let ledger = ledger();
    let foreign = self::ledger();
    let source = source(4, 0);
    let plan = AesOutputPlan::new(source).unwrap();
    for foreign_proof in [false, true] {
        let proof = if foreign_proof { &foreign } else { &ledger }
            .admit_phase(plan.proof_requirement()).unwrap();
        let report = if foreign_proof { &ledger } else { &foreign }
            .admit_phase(plan.report_requirement()).unwrap();
        assert!(matches!(plan.claim(proof, report, &ledger), Err(Error::Authority)));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
    let pending = plan.claim(
        ledger.admit_phase(plan.proof_requirement()).unwrap(),
        ledger.admit_phase(plan.report_requirement()).unwrap(),
        &ledger,
    ).unwrap();
    let shifted = self::source(4, 4);
    assert_eq!(source.geometry().rows(), shifted.geometry().rows());
    assert_eq!(pending.check(shifted, &ledger), Err(Error::Authority));
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn aes_output_claim_rejects_a_wrong_category_or_byte_boundary() {
    let ledger = ledger();
    let plan = AesOutputPlan::new(source(1, 0)).unwrap();
    for (category, host, device) in [
        (Category::NativeProof, PROOF_BACKING_CEILING as u64 - 1, 0),
        (Category::NativeProof, PROOF_BACKING_CEILING as u64 + 1, 0),
        (Category::NativeProof, PROOF_BACKING_CEILING as u64, 1),
        (Category::Report, PROOF_BACKING_CEILING as u64, 0),
    ] {
        let proof = ledger.reserve(category, Bytes { host, device }).unwrap();
        let report = ledger.admit_phase(plan.report_requirement()).unwrap();
        assert!(matches!(plan.claim(proof, report, &ledger), Err(Error::Authority)));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
