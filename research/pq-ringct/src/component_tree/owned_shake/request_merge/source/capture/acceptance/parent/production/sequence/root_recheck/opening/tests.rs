//! Fixed fixtures only; never actual root, proof or GPU qualification.
use super::*;
use crate::execution::retained_resources::WorkerAllowance;

struct FixedOpening {
    word: Option<Challenge>,
}
impl mutation::OpeningOwner for FixedOpening {
    fn opening_mut(&mut self) -> Option<&mut Challenge> {
        self.word.as_mut()
    }
}

#[test]
fn opening_guard_refuses_absent_slot_without_mutation() {
    let mut fixture = FixedOpening { word: None };
    assert!(OpeningMutation::new(&mut fixture).is_err());
    assert!(fixture.word.is_none());
}

#[test]
fn opening_guard_restores_before_each_typed_outcome_is_classified() {
    use RegisteredVerificationFailure as Failure;
    for outcome in [
        Ok(()),
        Err(Failure::RelationRejected("synthetic only".into())),
        Err(Failure::Admission("synthetic only".into())),
        Err(Failure::Configuration("synthetic only".into())),
        Err(Failure::Allocation("synthetic only".into())),
    ] {
        let expects_rejection = matches!(&outcome, Err(Failure::RelationRejected(_)));
        let original = Challenge::from_u64(31);
        let mut fixture = FixedOpening { word: Some(original) };
        let guard = OpeningMutation::new(&mut fixture).unwrap();
        assert_eq!(guard.original(), original);
        assert_eq!(guard.proof().word, Some(original + Challenge::ONE));
        drop(guard);
        assert_eq!(fixture.word, Some(original));
        assert_eq!(require_relation_rejection(outcome).is_ok(), expects_rejection);
    }
}

#[test]
fn opening_guard_restores_on_synthetic_unwind_without_gpu_cleanup_credit() {
    let original = Challenge::from_u64(37);
    let mut fixture = FixedOpening { word: Some(original) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = OpeningMutation::new(&mut fixture).unwrap();
        assert_eq!(guard.proof().word, Some(original + Challenge::ONE));
        panic!("synthetic verifier unwind, no GPU/runtime owner");
    }));
    assert!(result.is_err());
    assert_eq!(fixture.word, Some(original));
}

#[test]
fn opening_additional_claim_is_exact_and_never_replaces_root_cpu_claim() {
    let extra = additional_requirement().unwrap();
    let cpu = CpuEnvelope::source().unwrap();
    let base = requirements(cpu).unwrap();
    let base_bytes = base.total().unwrap();
    let extra_bytes = extra.total().unwrap();
    assert_eq!(extra_bytes.device, 0);
    assert_eq!(extra.get(Category::IndependentVerifier), Bytes::ZERO);
    assert_eq!(extra.get(Category::PhaseScratch).host, extra_bytes.host);
    assert!(extra_bytes.host > 64 << 10);
    let total = base_bytes.host.checked_add(extra_bytes.host).unwrap();
    for (host, fits) in [(total, true), (total - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let extra_owner = ledger.admit_phase(extra).unwrap();
        let base_owner = ledger.admit_phase(base);
        assert_eq!(base_owner.is_ok(), fits);
        drop(base_owner);
        assert_eq!(ledger.snapshot().current.host, extra_bytes.host);
        drop(extra_owner);
        let terminal = ledger.snapshot();
        assert_eq!(terminal.current, Bytes::ZERO);
        assert!(terminal.categories.iter().all(|c| c.current == Bytes::ZERO));
    }
}
