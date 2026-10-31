use super::*;
use crate::block_v2::native_gpu::AesTraceSpec;
use crate::ringct_research_quota::WorkerAllowance;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance { host: WORKER_HOST, device: MANAGED_DEVICE })
}

fn source() -> AesPreparationPlan {
    AesPreparationPlan::new(AesTraceSpec {
        domain: 11,
        start_counter: u32::MAX,
        output_len: 2047,
        first_block: 64,
        blocks: 64,
    }).unwrap()
}

fn preparation_requirements(source: AesPreparationPlan) -> Requirements {
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic
        + super::super::aes_recording::additional_host_bytes();
    let mut requirements = Requirements::single(Category::SymbolicCompiler,
        Bytes { host: symbolic as u64, device: 0 });
    requirements.add(Category::PhaseScratch,
        Bytes { host: other as u64, device: 0 }).unwrap();
    requirements
}

#[test]
fn aes_attempt_is_consumed_even_if_later_source_or_runtime_checks_fail() {
    let mut attempted = false;
    begin_attempt(&mut attempted).unwrap();
    assert!(attempted);
    for _ in 0..3 {
        assert_eq!(begin_attempt(&mut attempted), Err(Error::AlreadyAttempted));
    }
}

#[test]
fn aes_preparation_and_verifier_require_the_same_original_ledger() {
    let ledger = ledger();
    let foreign = self::ledger();
    let source = source();
    let preparation = ledger.admit_phase(preparation_requirements(source)).unwrap();
    let verifier = ledger.reserve(Category::IndependentVerifier,
        Bytes { host: VERIFIER_HOST, device: 0 }).unwrap();
    let (_, allocations) = crate::spill_alloc::allocation_requests::measure(|| {
        check_ledger(&ledger).unwrap();
        check_preparation(source, &preparation, &ledger).unwrap();
        check_verifier(&verifier, &ledger).unwrap();
        assert_eq!(check_preparation(source, &preparation, &foreign), Err(Error::Authority));
        assert_eq!(check_verifier(&verifier, &foreign), Err(Error::Authority));
    });
    assert_eq!((allocations.calls, allocations.bytes, allocations.overflow), (0, 0, false));
    drop((preparation, verifier));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn aes_source_preparation_minimum_and_verifier_exact_bytes_are_checked() {
    let ledger = ledger();
    let source = source();
    let original = preparation_requirements(source);
    for delta in [-1i64, 1] {
        let mut changed = Requirements::single(Category::SymbolicCompiler,
            original.get(Category::SymbolicCompiler));
        let bytes = original.get(Category::PhaseScratch);
        changed.add(Category::PhaseScratch,
            Bytes { host: (bytes.host as i64 + delta) as u64, device: 0 }).unwrap();
        let preparation = ledger.admit_phase(changed).unwrap();
        if delta < 0 {
            assert_eq!(check_preparation(source, &preparation, &ledger), Err(Error::Authority));
        } else {
            // The enclosing source caller may add its own preparation headers.
            check_preparation(source, &preparation, &ledger).unwrap();
        }
        drop(preparation);
        let verifier = ledger.reserve(Category::IndependentVerifier,
            Bytes { host: (VERIFIER_HOST as i64 + delta) as u64, device: 0 }).unwrap();
        assert_eq!(check_verifier(&verifier, &ledger), Err(Error::Authority));
        drop(verifier);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
