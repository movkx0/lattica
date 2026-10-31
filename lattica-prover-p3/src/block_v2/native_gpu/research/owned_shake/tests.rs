use super::*;
use crate::block_v2::native_gpu::{shake_output::ShakeOutputPlan, ShakeTraceSpec};
use crate::ringct_research_quota::WorkerAllowance;

mod runtime;

mod active_hashx_preflight;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: WORKER_HOST,
        device: MANAGED_DEVICE,
    })
}
fn census() -> ShakePreparationPlan {
    ShakePreparationPlan::singleton(ShakeTraceSpec {
        input_len: 1,
        output_len: 1,
        first_permutation: 0,
        permutations: 1,
    })
    .unwrap()
}
fn preparation_requirements() -> Requirements {
    let source = census();
    let symbolic = source.host().prepared_partition_bytes().unwrap();
    let other = source.host().required_host_bytes() - symbolic
        + super::super::shake_recording::additional_host_bytes();
    let mut requirements = Requirements::single(
        Category::SymbolicCompiler,
        Bytes {
            host: symbolic as u64,
            device: 0,
        },
    );
    requirements
        .add(
            Category::PhaseScratch,
            Bytes {
                host: other as u64,
                device: 0,
            },
        )
        .unwrap();
    requirements
}

#[test]
fn phase_attempt_refuses_retry_after_any_first_attempt() {
    let mut attempted = false;
    begin_attempt(&mut attempted).unwrap();
    assert!(attempted);
    // The flag changes before any source/runtime/configuration check, so even
    // pre-trace failures leave this owner permanently consumed.
    for _ in 0..3 {
        assert_eq!(begin_attempt(&mut attempted), Err(Error::AlreadyAttempted));
    }
}

#[test]
fn original_preparation_runtime_and_verifier_checks_are_allocation_free() {
    let ledger = ledger();
    let unrelated = self::ledger();
    let preparation = ledger.admit_phase(preparation_requirements()).unwrap();
    let startup = StartupPlan::new().unwrap().footprint();
    let runtime = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: startup.requested_host_bytes as u64,
                device: startup.managed_device_bytes as u64,
            },
        )
        .unwrap();
    let verifier = ledger
        .reserve(
            Category::IndependentVerifier,
            Bytes {
                host: VERIFIER_HOST,
                device: 0,
            },
        )
        .unwrap();
    let (_, allocations) = crate::spill_alloc::allocation_requests::measure(|| {
        check_ledger(&ledger).unwrap();
        check_preparation(census(), &preparation, &ledger).unwrap();
        assert_eq!(
            check_startup(&runtime, &ledger).unwrap(),
            startup.managed_device_bytes
        );
        check_verifier(&verifier, &ledger).unwrap();
        assert_eq!(
            check_preparation(census(), &preparation, &unrelated),
            Err(Error::Authority)
        );
        assert_eq!(check_startup(&runtime, &unrelated), Err(Error::Authority));
        assert_eq!(check_verifier(&verifier, &unrelated), Err(Error::Authority));
        assert!(wrapper_host_bytes().unwrap() >= 2 * size_of::<NativeShakePhase>());
    });
    assert_eq!(
        (allocations.calls, allocations.bytes, allocations.overflow),
        (0, 0, false)
    );
    drop(verifier);
    drop(runtime);
    drop(preparation);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn missing_original_verifier_is_refused_before_selection_or_runtime_work() {
    let ledger = ledger();
    let preparation = ledger.admit_phase(preparation_requirements()).unwrap();
    let startup = StartupPlan::new().unwrap().footprint();
    let runtime = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: startup.requested_host_bytes as u64,
                device: startup.managed_device_bytes as u64,
            },
        )
        .unwrap();
    let verifier = ledger
        .reserve(
            Category::IndependentVerifier,
            Bytes {
                host: VERIFIER_HOST - 1,
                device: 0,
            },
        )
        .unwrap();
    let retained = ledger.snapshot().current;
    let plan = ShakeOutputPlan::new(census()).unwrap();
    let proof = ledger.admit_phase(plan.proof_requirement()).unwrap();
    let report = ledger.admit_phase(plan.report_requirement()).unwrap();
    let output = plan.claim(proof, report, &ledger).unwrap();
    let (result, allocations) = crate::spill_alloc::allocation_requests::measure(|| {
        // SAFETY: the wrong verifier is rejected before preflight-dependent
        // selection inspection, context creation or any dispatch is reachable.
        unsafe {
            NativeShakePhase::new(census(), &preparation, &runtime, output, &verifier, &ledger)
        }
    });
    assert!(matches!(result, Err(Error::Authority)));
    assert_eq!(
        (allocations.calls, allocations.bytes, allocations.overflow),
        (0, 0, false)
    );
    assert_eq!(ledger.snapshot().current, retained);
    drop(verifier);
    drop(runtime);
    drop(preparation);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn native_ledger_and_exact_verifier_limits_cannot_grow_or_borrow_categories() {
    for (host, device) in [
        (0, MANAGED_DEVICE),
        (WORKER_HOST + 1, MANAGED_DEVICE),
        (WORKER_HOST, MANAGED_DEVICE - 1),
        (WORKER_HOST, MANAGED_DEVICE + 1),
    ] {
        let ledger = Ledger::new(WorkerAllowance { host, device });
        assert_eq!(check_ledger(&ledger), Err(Error::Authority));
    }
    let ledger = ledger();
    for (category, host, device) in [
        (Category::IndependentVerifier, VERIFIER_HOST - 1, 0),
        (Category::IndependentVerifier, VERIFIER_HOST + 1, 0),
        (Category::IndependentVerifier, VERIFIER_HOST, 1),
        (Category::PhaseScratch, VERIFIER_HOST, 0),
    ] {
        let token = ledger.reserve(category, Bytes { host, device }).unwrap();
        assert_eq!(check_verifier(&token, &ledger), Err(Error::Authority));
        drop(token);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
