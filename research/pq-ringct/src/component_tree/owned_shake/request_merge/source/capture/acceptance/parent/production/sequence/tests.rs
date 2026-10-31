use super::*;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn attempt_caller_is_additive_exact_and_terminal_failure_retains_original() {
    let requirements = attempt_requirement().unwrap();
    let total = requirements.total().unwrap();
    assert_eq!(total.device, 0);
    assert_eq!(requirements.get(Category::PhaseScratch), total);
    assert!(total.host > 64 << 10);
    let ledger = Ledger::new(WorkerAllowance {
        host: total.host,
        device: 0,
    });
    let caller = ledger.admit_phase(requirements).unwrap();
    let before = ledger.snapshot();
    assert!(ledger
        .reserve(Category::PhaseScratch, Bytes { host: 1, device: 0 })
        .is_err());
    let failure = Failure {
        cause: Cause::Production(Error::Authority),
        #[cfg(all(test, feature = "owned-native-shake", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
        interior: None,
        caller,
    };
    assert_eq!(ledger.snapshot(), before);
    assert!(matches!(
        &failure.cause,
        Cause::Production(Error::Authority)
    ));
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, before.peak);
    let short = Ledger::new(WorkerAllowance {
        host: total.host - 1,
        device: 0,
    });
    assert!(short.admit_phase(requirements).is_err());
    assert_eq!(short.snapshot().current, Bytes::ZERO);
}

// No fake Program, child, accepted owner, retirement, registered verifier or
// caller-selected A state is constructed here. Genuine compiler-bank cycles,
// all source-envelopes, first-leaf equivalence, returned failure retirement,
// mutation checks and actual GPU feasibility require separate guarded tests.
