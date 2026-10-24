use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn bytes(host: u64, device: u64) -> Bytes {
    Bytes { host, device }
}

fn request(parts: &[(Category, u64, u64)]) -> Requirements {
    let mut result = Requirements::default();
    for &(category, host, device) in parts {
        result.add(category, bytes(host, device)).unwrap();
    }
    result
}

fn bound(host: u64, device: u64) -> ContextPhases {
    let phases = ContextPhases::new();
    phases
        .bind(WorkerAllowance { host, device }, Bytes::ZERO)
        .unwrap();
    phases
}

#[test]
fn baseline_is_inert_and_binding_subtracts_enclosing_storage_once() {
    let phases = ContextPhases::new();
    assert!(phases.ledger.get().is_none());
    assert_eq!(phases.state.borrow().status, Status::Unbound);
    for enclosing in [bytes(101, 0), bytes(0, 201)] {
        assert_eq!(
            phases.bind(
                WorkerAllowance {
                    host: 100,
                    device: 200
                },
                enclosing
            ),
            Err(Error::EnclosingAllowance)
        );
        assert!(phases.ledger.get().is_none());
        assert_eq!(phases.state.borrow().status, Status::Unbound);
    }
    phases
        .bind(
            WorkerAllowance {
                host: 100,
                device: 200,
            },
            bytes(10, 20),
        )
        .unwrap();
    assert_eq!(phases.ledger().remaining(), bytes(90, 180));
    assert_eq!(
        phases.bind(
            WorkerAllowance {
                host: 1000,
                device: 2000
            },
            Bytes::ZERO
        ),
        Err(Error::AlreadyBound)
    );
    assert_eq!(phases.ledger().remaining(), bytes(90, 180));
}

#[test]
fn capability_and_output_tokens_are_bound_to_one_actual_context() {
    let first = ProvingContext::cpu(1024).unwrap();
    let second = ProvingContext::cpu(1024).unwrap();
    let mut first_capability = first.phase_capability(bytes(128, 0)).unwrap();
    let mut second_capability = second.phase_capability(Bytes::ZERO).unwrap();
    assert!(first_capability.belongs_to(&first));
    assert!(!first_capability.belongs_to(&second));
    assert!(matches!(
        first.phase_capability(Bytes::ZERO),
        Err(Error::AlreadyBound)
    ));
    assert_eq!(first_capability.ledger().remaining(), bytes(896, 0));
    let mut phase = first_capability
        .admit(request(&[
            (Category::PhaseScratch, 100, 0),
            (Category::NativeProof, 20, 0),
        ]))
        .unwrap();
    assert!(phase.belongs_to(&first));
    assert!(!phase.belongs_to(&second));
    let retained = phase
        .split(Requirements::single(Category::NativeProof, bytes(20, 0)))
        .unwrap();
    assert!(retained.belongs_to(phase.ledger()));
    assert!(!retained.belongs_to(second_capability.ledger()));
    phase.complete_after_cleanup().unwrap();
    assert_eq!(first_capability.ledger().snapshot().current, bytes(20, 0));
    first_capability.retire().unwrap();
    second_capability.retire().unwrap();
    drop(retained);
    assert_eq!(first_capability.ledger().snapshot().current, Bytes::ZERO);
}

#[test]
fn whole_backend_envelope_and_all_outputs_are_one_atomic_request() {
    let phases = bound(100, 200);
    let existing = phases
        .ledger()
        .reserve(Category::NativeProof, bytes(10, 20))
        .unwrap();
    let before = phases.ledger().snapshot();
    for rejected in [
        request(&[(Category::PhaseScratch, 60, 100), (Category::Report, 31, 0)]),
        request(&[(Category::PhaseScratch, 60, 181), (Category::Report, 1, 0)]),
    ] {
        assert!(matches!(phases.admit(rejected), Err(Error::Reservation(_))));
        assert_eq!(phases.ledger().snapshot(), before);
        assert_eq!(phases.state.borrow().status, Status::Ready);
        assert_eq!(phases.state.borrow().generation, 0);
    }
    // The complete backend envelope is charged once, not again as imagined
    // internal compiler/PCS categories. Existing and new owners total100/200.
    let generation = phases
        .admit(request(&[
            (Category::PhaseScratch, 60, 180),
            (Category::Report, 30, 0),
        ]))
        .unwrap();
    assert_eq!(phases.ledger().snapshot().current, bytes(100, 200));
    phases.complete_with_cleanup(generation, || Ok(())).unwrap();
    assert_eq!(phases.ledger().snapshot().current, bytes(10, 20));
    drop(existing);
}

#[test]
fn outputs_and_pre_reserved_verifier_move_without_recharging_backend() {
    let context = ProvingContext::cpu(512).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut phase = capability
        .admit(request(&[
            (Category::PhaseScratch, 100, 0),
            (Category::NativeProof, 40, 0),
            (Category::IndependentVerifier, 64, 0),
            (Category::Report, 10, 0),
        ]))
        .unwrap();
    assert_eq!(phase.backend_allowance().unwrap(), bytes(100, 0));
    let native = phase
        .split(Requirements::single(Category::NativeProof, bytes(40, 0)))
        .unwrap();
    let verifier = phase
        .split(Requirements::single(
            Category::IndependentVerifier,
            bytes(64, 0),
        ))
        .unwrap();
    assert!(native.belongs_to(&ledger) && verifier.belongs_to(&ledger));
    assert_eq!(ledger.snapshot().current, bytes(214, 0));
    assert!(matches!(
        phase.split(Requirements::single(Category::PhaseScratch, bytes(1, 0))),
        Err(Error::BackendReservationCannotEscape)
    ));
    assert!(matches!(
        phase.split(Requirements::single(Category::Report, bytes(11, 0))),
        Err(Error::Reservation(_))
    ));
    assert_eq!(ledger.snapshot().current, bytes(214, 0));
    // The real verifier owner would keep this token through config teardown.
    drop(verifier);
    assert_eq!(ledger.snapshot().current, bytes(150, 0));
    phase.complete_after_cleanup().unwrap();
    assert_eq!(ledger.snapshot().current, bytes(40, 0));
    capability.retire().unwrap();
    drop(native);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn cleanup_observes_full_charge_and_retained_outputs_survive_phase_end() {
    let phases = bound(200, 300);
    let generation = phases
        .admit(request(&[
            (Category::PhaseScratch, 100, 200),
            (Category::RecursiveProof, 40, 0),
        ]))
        .unwrap();
    let output = phases
        .split(
            generation,
            Requirements::single(Category::RecursiveProof, bytes(40, 0)),
        )
        .unwrap();
    phases
        .complete_with_cleanup(generation, || {
            assert_eq!(phases.ledger().snapshot().current, bytes(140, 200));
            assert_eq!(phases.state.borrow().status, Status::Active);
            Ok(())
        })
        .unwrap();
    assert_eq!(phases.ledger().snapshot().current, bytes(40, 0));
    assert_eq!(phases.state.borrow().status, Status::Ready);
    let next = phases
        .admit(Requirements::single(
            Category::PhaseScratch,
            bytes(160, 300),
        ))
        .unwrap();
    phases.complete_with_cleanup(next, || Ok(())).unwrap();
    drop(output);
}

#[test]
fn failed_cleanup_holds_reservation_and_recovery_only_retires() {
    let phases = bound(200, 300);
    let generation = phases
        .admit(Requirements::single(
            Category::PhaseScratch,
            bytes(100, 200),
        ))
        .unwrap();
    let before = phases.ledger().snapshot();
    assert_eq!(
        phases.complete_with_cleanup(generation, || Err(CleanupFailure::QueueDrain)),
        Err(Error::Cleanup(CleanupFailure::QueueDrain))
    );
    assert_eq!(phases.state.borrow().status, Status::Poisoned);
    assert_eq!(phases.ledger().snapshot(), before);
    assert_eq!(
        phases.admit(Requirements::single(Category::PhaseScratch, bytes(1, 1))),
        Err(Error::NotReady(Status::Poisoned))
    );
    assert!(phases
        .retire_with_cleanup(|| Err(CleanupFailure::QueueDrain))
        .is_err());
    assert_eq!(phases.ledger().snapshot(), before);
    phases
        .retire_with_cleanup(|| {
            assert_eq!(phases.ledger().snapshot(), before);
            Ok(())
        })
        .unwrap();
    assert_eq!(phases.ledger().snapshot().current, Bytes::ZERO);
    assert_eq!(phases.state.borrow().status, Status::Retired);
    assert_eq!(
        phases.admit(Requirements::single(Category::PhaseScratch, bytes(1, 1))),
        Err(Error::NotReady(Status::Retired))
    );
}

#[test]
fn abandoned_or_unwound_lease_poison_without_releasing() {
    for unwind in [false, true] {
        let context = ProvingContext::cpu(200).unwrap();
        let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
        let ledger = capability.ledger().clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let phase = capability
                .admit(Requirements::single(Category::PhaseScratch, bytes(100, 0)))
                .unwrap();
            if unwind {
                context
                    .phases
                    .complete_with_cleanup(phase.generation, || panic!("injected cleanup panic"))
                    .unwrap();
            }
            drop(phase);
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(capability.status(), Status::Poisoned);
        assert_eq!(ledger.snapshot().current, bytes(100, 0));
        assert!(matches!(
            capability.admit(Requirements::single(Category::PhaseScratch, bytes(1, 0))),
            Err(Error::NotReady(Status::Poisoned))
        ));
        capability.retire().unwrap();
        assert_eq!(capability.status(), Status::Retired);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn unverified_context_destruction_cannot_reopen_surviving_ledger_capacity() {
    let phases = bound(200, 300);
    let ledger = phases.ledger().clone();
    phases
        .admit(Requirements::single(
            Category::PhaseScratch,
            bytes(100, 200),
        ))
        .unwrap();
    drop(phases);
    // Intentionally strands only one accounting token. No GPU work or payload
    // exists in this test; a real unclean worker must terminate.
    assert_eq!(ledger.snapshot().current, bytes(100, 200));
    assert_eq!(ledger.remaining(), bytes(100, 100));
}

#[test]
fn empty_overflow_and_stale_phase_requests_leave_accounting_unchanged() {
    let phases = bound(200, 300);
    assert_eq!(
        phases.admit(Requirements::default()),
        Err(Error::EmptyPhase)
    );
    phases.state.borrow_mut().generation = u64::MAX;
    assert_eq!(
        phases.admit(Requirements::single(Category::PhaseScratch, bytes(1, 1))),
        Err(Error::GenerationExhausted)
    );
    assert_eq!(phases.ledger().snapshot().current, Bytes::ZERO);
    phases.state.borrow_mut().generation = 0;
    let generation = phases
        .admit(Requirements::single(Category::PhaseScratch, bytes(1, 1)))
        .unwrap();
    let before = phases.ledger().snapshot();
    assert!(matches!(
        phases.split(generation + 1, Requirements::default()),
        Err(Error::StalePhase)
    ));
    assert_eq!(
        phases.complete_with_cleanup(generation + 1, || panic!("stale callback")),
        Err(Error::StalePhase)
    );
    assert_eq!(phases.ledger().snapshot(), before);
    phases.complete_with_cleanup(generation, || Ok(())).unwrap();
}

#[test]
fn actual_cpu_adapter_releases_registered_prepared_state_before_phase_charge() {
    use lattica_prover_p3::block_v2::machine::ProgramBuilder;
    let context = ProvingContext::cpu(2 << 30).unwrap();
    let mut capability = context.phase_capability(bytes(64 << 20, 0)).unwrap();
    let phase = capability
        .admit(Requirements::single(
            Category::PhaseScratch,
            bytes(1 << 30, 0),
        ))
        .unwrap();
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    builder.assert_equal(public, input);
    // Registration only: this fixture tests the real release adapter, not a
    // complete compiler/prover footprint or a GPU allocation/retirement claim.
    context
        .with_registered(builder.finish(Some(8)).unwrap(), |_| Ok(()))
        .unwrap();
    assert_eq!(context.report()["prepared_entries"], 1);
    phase.complete_after_cleanup().unwrap();
    assert_eq!(context.report()["prepared_entries"], 0);
    assert_eq!(capability.ledger().snapshot().current, Bytes::ZERO);
    capability.retire().unwrap();
    drop(capability);
    assert_eq!(context.finish().unwrap()["session_closed"], true);
}

#[test]
fn binding_after_baseline_work_is_refused_without_creating_ledger() {
    let context = ProvingContext::cpu(1024).unwrap();
    context.with_native_cpu(|| Ok(())).unwrap();
    assert!(matches!(
        context.phase_capability(Bytes::ZERO),
        Err(Error::WorkAlreadyStarted)
    ));
    assert!(context.phases.ledger.get().is_none());
}

#[test]
fn actual_cleanup_failure_returns_only_static_stage_after_retirement() {
    let context = ProvingContext::cpu(1024).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let phase = capability
        .admit(Requirements::single(Category::PhaseScratch, bytes(100, 0)))
        .unwrap();
    // Exercise the real checked context cleanup adapter, without GPU work or
    // an arbitrary caller-supplied cleanup receipt. The backend creates its
    // existing reentrancy error; the adapter drops it while the charge is held.
    let busy_registry = context.registry.borrow_mut();
    let error = phase.complete_after_cleanup().unwrap_err();
    assert_eq!(error, Error::Cleanup(CleanupFailure::PreparedRelease));
    assert_eq!(capability.status(), Status::Poisoned);
    assert_eq!(ledger.snapshot().current, bytes(100, 0));
    drop(busy_registry);
    capability.retire().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(capability.status(), Status::Retired);
    // The escaped diagnostic owns only a fixed enum, not a String/Vec whose
    // allocation could survive release of the phase reservation.
    assert_eq!(error, Error::Cleanup(CleanupFailure::PreparedRelease));
}
