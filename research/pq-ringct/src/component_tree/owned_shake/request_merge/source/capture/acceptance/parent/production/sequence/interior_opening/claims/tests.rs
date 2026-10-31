use super::*;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn interior_verifier_keeps_complete_source_envelope_and_classified_increment() {
    let cpu = CpuEnvelope::source().unwrap();
    assert_eq!(cpu.heights, 18);
    assert!(cpu.bytes > 0);
    let required = verifier_requirement(cpu).unwrap();
    let expected = u64::try_from(cpu.bytes.checked_add(
        RegisteredVerifier::classified_call_extra_bytes(),
    ).unwrap()).unwrap();
    assert!(expected > u64::try_from(cpu.bytes).unwrap());
    for category in Category::ALL {
        assert_eq!(required.get(category), Bytes {
            host: if category == Category::IndependentVerifier { expected } else { 0 },
            device: 0,
        });
    }
}

#[test]
fn interior_verifier_refuses_missing_height_coverage_and_overflow() {
    let source = CpuEnvelope::source().unwrap();
    for heights in [0, 17, 19] {
        assert!(verifier_requirement(CpuEnvelope {
            bytes: source.bytes, heights,
        }).is_err());
    }
    assert!(verifier_requirement(CpuEnvelope { bytes: 0, heights: 18 }).is_err());
    assert!(verifier_requirement(CpuEnvelope {
        bytes: usize::MAX, heights: 18,
    }).is_err());
}

#[test]
fn interior_caller_independently_covers_common_forwarding_without_device_credit() {
    let forwarding = common_forwarding_host_bytes().unwrap();
    let caller = caller_requirement().unwrap();
    let host = caller.get(Category::PhaseScratch).host;
    assert!(forwarding > 0);
    assert!(host > 64 << 10);
    assert!(host >= u64::try_from(forwarding).unwrap());
    for category in Category::ALL {
        assert_eq!(caller.get(category), Bytes {
            host: if category == Category::PhaseScratch { host } else { 0 },
            device: 0,
        });
    }
}

#[test]
fn interior_complete_probe_claims_exact_and_one_short_are_atomic() {
    let mut combined = caller_requirement().unwrap();
    let verifier = verifier_requirement(CpuEnvelope::source().unwrap()).unwrap();
    for category in Category::ALL {
        combined.add(category, verifier.get(category)).unwrap();
    }
    let bytes = combined.total().unwrap();
    let exact = Ledger::new(WorkerAllowance { host: bytes.host, device: 0 });
    let foreign = Ledger::new(WorkerAllowance { host: bytes.host, device: 0 });
    let original = exact.admit_phase(combined).unwrap();
    assert!(original.belongs_to(&exact));
    assert!(!original.belongs_to(&foreign));
    assert_eq!(original.requirements(), combined);
    assert_eq!(exact.snapshot().current, bytes);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let before_extra = exact.snapshot();
    assert!(exact.admit_phase(Requirements::single(
        Category::PhaseScratch, Bytes { host: 1, device: 0 },
    )).is_err());
    assert_eq!(exact.snapshot(), before_extra);
    drop(original);
    let released = exact.snapshot();
    assert_eq!(released.current, Bytes::ZERO);
    assert!(released.categories.iter().all(|category| category.current == Bytes::ZERO));
    assert_eq!(released.peak, bytes);

    let short = Ledger::new(WorkerAllowance { host: bytes.host - 1, device: 0 });
    let before_short = short.snapshot();
    assert!(short.admit_phase(combined).is_err());
    assert_eq!(short.snapshot(), before_short);
}

#[test]
fn interior_caller_census_refuses_checked_arithmetic_overflow() {
    assert!(repeated_layout(&[usize::MAX]).is_err());
    assert!(repeated_layout(&[usize::MAX / FRAME_COPIES + 1]).is_err());
    assert!(repeated_layout(&[usize::MAX / 2, usize::MAX / 2]).is_err());
}
