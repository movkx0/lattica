use super::*;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn complete_parent_compiler_claim_refuses_any_extra_category_byte_and_releases() {
    let storage = Storage::source().unwrap();
    let total = storage.complete.total().unwrap();
    assert_eq!(total.device, 0);
    assert!(total.host > crate::component_tree::owned_shake::PROGRAM_BYTES as u64);
    let ledger = Ledger::new(WorkerAllowance {
        host: total.host,
        device: 0,
    });
    let original = ledger.admit_phase(storage.complete).unwrap();
    assert_eq!(ledger.snapshot().current.host, total.host);
    assert!(ledger
        .admit_phase(Requirements::single(
            Category::RegisteredMetadata,
            Bytes { host: 1, device: 0 }
        ))
        .is_err());
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    for category in [
        Category::SymbolicCompiler,
        Category::CompilerInputs,
        Category::PhaseScratch,
        Category::RegisteredMetadata,
    ] {
        assert!(storage.complete.get(category).host > 0);
        let mut too_large = storage.complete;
        too_large
            .add(category, Bytes { host: 1, device: 0 })
            .unwrap();
        assert!(ledger.admit_phase(too_large).is_err());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn parent_acceptance_original_claim_is_exact_and_releases() {
    let cpu = CpuEnvelope::source().unwrap();
    assert_eq!(cpu.heights, 18);
    let requirement = children::acceptance_requirement(cpu).unwrap();
    let total = requirement.total().unwrap();
    let ledger = Ledger::new(WorkerAllowance {
        host: total.host,
        device: total.device,
    });
    let original = ledger.admit_phase(requirement).unwrap();
    assert_eq!(ledger.snapshot().current, total);
    assert!(ledger
        .reserve(Category::RegisteredMetadata, Bytes { host: 1, device: 0 })
        .is_err());
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    let mut short = requirement;
    short
        .add(Category::IndependentVerifier, Bytes { host: 1, device: 0 })
        .unwrap();
    assert!(ledger.admit_phase(short).is_err());
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
