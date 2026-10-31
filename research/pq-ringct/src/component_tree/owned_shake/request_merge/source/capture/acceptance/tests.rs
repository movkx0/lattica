use super::*;
use crate::{
    component_tree::{Contract, COUNT, FIRST, LEVEL},
    execution::retained_resources::WorkerAllowance,
};

#[test]
fn independent_cpu_source_exhaustively_covers_every_admitted_height() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let envelope = CpuEnvelope::source().unwrap();
    assert_eq!(envelope.heights, 18);
    assert!(envelope.bytes > 64 << 20);
    for log in 3..=20 {
        assert!(
            RegisteredVerifier::host_reservation_bytes(HEADER + 8, 1 << log, ROOTS, ROOTS).unwrap()
                <= envelope.bytes
        );
    }
    let metadata = metadata_requirement().unwrap();
    let whole = whole_requirement(envelope).unwrap();
    assert_eq!(
        whole.get(Category::RegisteredMetadata),
        metadata.get(Category::RegisteredMetadata)
    );
    assert_eq!(
        whole.get(Category::IndependentVerifier).host,
        envelope.bytes as u64
    );
    assert_eq!(whole.total().unwrap().device, 0);
    assert!(
        metadata.total().unwrap().host > size_of::<AcceptedLeafCompletion<'_, '_, '_>>() as u64
    );
    // Pure admission/cleanup only: these tokens cannot construct a source cap,
    // RetiredLeafAttempt, registration, proof or accepted child.
    let bytes = whole.total().unwrap().host;
    for (host, accepted) in [(bytes, true), (bytes - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let result = ledger.admit_phase(whole);
        assert_eq!(result.is_ok(), accepted);
        drop(result);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn exact_source_binding_rejects_any_cap_public_span_level_or_height_change() {
    let contract = Contract::shake(
        [7; 32],
        9,
        crate::shake_air::Descriptor {
            input_len: 16_416,
            output_len: 137,
        },
    )
    .unwrap();
    let spec = contract.span(0, 32).unwrap();
    let public = [Val::from_u64(17); HEADER + 8];
    let cap = [[Val::from_u64(19); 4]; ROOTS];
    let matches =
        |actual_spec: &Spec, height, actual_public: &[Val], actual_cap: &[[Val; 4]], capacity| {
            exact_binding(
                &spec,
                8,
                &public,
                &cap,
                actual_spec,
                height,
                actual_public,
                actual_cap,
                capacity,
            )
        };
    assert!(matches(&spec, 8, &public, &cap, ROOTS));
    for height in [0, 7, 16, usize::MAX] {
        assert!(!matches(&spec, height, &public, &cap, ROOTS));
    }
    for capacity in [ROOTS - 1, ROOTS + 1, usize::MAX] {
        assert!(!matches(&spec, 8, &public, &cap, capacity));
    }
    assert!(!matches(&spec, 8, &public[..HEADER + 7], &cap, ROOTS));
    assert!(!matches(&spec, 8, &public, &cap[..ROOTS - 1], ROOTS));
    for field in 0..HEADER + 8 {
        let mut changed = public;
        changed[field] += Val::ONE;
        assert!(!matches(&spec, 8, &changed, &cap, ROOTS), "public {field}");
    }
    for root in 0..ROOTS {
        for word in 0..4 {
            let mut changed = cap;
            changed[root][word] += Val::ONE;
            assert!(!matches(&spec, 8, &public, &changed, ROOTS));
        }
    }
    for field in [FIRST, COUNT, LEVEL] {
        let mut changed = spec.clone();
        match field {
            FIRST => changed.first += 1,
            COUNT => changed.count += 1,
            LEVEL => changed.level += 1,
            _ => unreachable!(),
        }
        assert!(!matches(&changed, 8, &public, &cap, ROOTS));
    }
    // Helper data cannot mint the private, producer-issued acceptance input.
}
