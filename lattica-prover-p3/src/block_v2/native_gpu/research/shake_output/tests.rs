use super::*;
use crate::block_v2::native_gpu::ShakeTraceSpec;
use crate::ringct_research_quota::WorkerAllowance;

fn census() -> ShakePreparationPlan {
    ShakePreparationPlan::singleton(ShakeTraceSpec {
        input_len: 1,
        output_len: 1,
        first_permutation: 0,
        permutations: 1,
    })
    .unwrap()
}

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    })
}

#[test]
fn fixed_output_census_is_allocation_free_and_fits_all_native_heights() {
    let single = census();
    let (plan, requests) =
        crate::spill_alloc::allocation_requests::measure(|| ShakeOutputPlan::new(single).unwrap());
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
    assert!(plan.source_proof_host_bytes() < PROOF_BACKING_CEILING);
    let mut previous = plan.source_proof_host_bytes();
    for log in 1..=8 {
        let permutations = 1 << log;
        let batch = ShakePreparationPlan::batch(ShakeTraceSpec {
            input_len: permutations * 136,
            output_len: 137,
            first_permutation: 0,
            permutations,
        })
        .unwrap();
        let next = ShakeOutputPlan::new(batch).unwrap();
        assert!(next.source_proof_host_bytes() >= previous);
        assert!(next.source_proof_host_bytes() < PROOF_BACKING_CEILING);
        previous = next.source_proof_host_bytes();
    }
}

#[test]
fn output_claim_moves_original_tokens_without_reserving_again() {
    let ledger = ledger();
    let plan = ShakeOutputPlan::new(census()).unwrap();
    let proof = ledger.admit_phase(plan.proof_requirement()).unwrap();
    let report = ledger.admit_phase(plan.report_requirement()).unwrap();
    let before = ledger.snapshot().current;
    let pending = plan.claim(proof, report, &ledger).unwrap();
    pending.check(census(), &ledger).unwrap();
    let moved = Some(pending);
    assert_eq!(ledger.snapshot().current, before);
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn equal_sized_foreign_claims_are_refused_and_both_ledgers_clean_up() {
    let ledger = ledger();
    let foreign = self::ledger();
    let plan = ShakeOutputPlan::new(census()).unwrap();
    for proof_is_foreign in [false, true] {
        let proof = if proof_is_foreign { &foreign } else { &ledger }
            .admit_phase(plan.proof_requirement())
            .unwrap();
        let report = if proof_is_foreign { &ledger } else { &foreign }
            .admit_phase(plan.report_requirement())
            .unwrap();
        assert!(matches!(
            plan.claim(proof, report, &ledger),
            Err(Error::Authority)
        ));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn output_claim_requires_exact_categories_and_cannot_retarget_geometry() {
    let ledger = ledger();
    let plan = ShakeOutputPlan::new(census()).unwrap();
    for (category, host, device) in [
        (Category::NativeProof, PROOF_BACKING_CEILING as u64 - 1, 0),
        (Category::NativeProof, PROOF_BACKING_CEILING as u64 + 1, 0),
        (Category::PhaseScratch, PROOF_BACKING_CEILING as u64, 0),
        (Category::NativeProof, PROOF_BACKING_CEILING as u64, 1),
    ] {
        let proof = ledger.reserve(category, Bytes { host, device }).unwrap();
        let report = ledger.admit_phase(plan.report_requirement()).unwrap();
        assert!(matches!(
            plan.claim(proof, report, &ledger),
            Err(Error::Authority)
        ));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let proof = ledger.admit_phase(plan.proof_requirement()).unwrap();
    let report = ledger.admit_phase(plan.report_requirement()).unwrap();
    let pending = plan.claim(proof, report, &ledger).unwrap();
    let other = ShakePreparationPlan::singleton(ShakeTraceSpec {
        input_len: 2,
        ..census().geometry().trace_spec()
    })
    .unwrap();
    assert_eq!(pending.check(other, &ledger), Err(Error::Authority));
    pending.check(census(), &ledger).unwrap();
    drop(pending);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

fn body<'a>(source: &'a str, signature: &str) -> &'a str {
    let tail = source.split_once(signature).unwrap().1;
    let start = tail.find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in tail.as_bytes()[start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[start..=start + offset];
                }
            }
            _ => {}
        }
    }
    panic!("fixed source function body missing");
}

#[test]
fn fixed_output_inventory_matches_the_existing_retention_source() {
    let original =
        include_str!("../../../../../../research/pq-ringct/src/graph_crypto/retention.rs");
    let fixed = include_str!("storage.rs");
    let original = body(original, "fn heap_bound(self)");
    let fixed = body(fixed, "fn heap_bound(self)");
    assert_eq!(
        original.split_whitespace().collect::<String>(),
        fixed.split_whitespace().collect::<String>(),
    );
}
