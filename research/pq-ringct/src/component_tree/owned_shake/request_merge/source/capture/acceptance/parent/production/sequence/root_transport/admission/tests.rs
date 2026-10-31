//! Source geometry and original-ledger arithmetic only; no actual root exists.
use super::*;
use crate::component_tree::RegisteredVerifier;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn full_outer_packet_and_trailing_probe_fit_all_eighteen_heights() {
    let envelope = TransportEnvelope::for_root().unwrap();
    check_envelope(&envelope).unwrap();
    assert_eq!(envelope.cases.len(), HEIGHTS);
    for case in envelope.cases {
        assert!(packet_with_probe(case.encoded_inner_bytes).unwrap() <= PACKET_LIMIT);
        assert!(case.decoded_cumulative_bytes <= DECODE_LIMIT);
    }
}

#[test]
fn packet_plus_probe_ceiling_is_exact_and_overflow_refuses() {
    let exact = PACKET_LIMIT - HEADER_BYTES - TRAILING_PROBE_BYTES;
    assert_eq!(packet_with_probe(exact).unwrap(), PACKET_LIMIT);
    assert!(packet_with_probe(exact + 1).is_err());
    assert!(packet_with_probe(usize::MAX).is_err());
    assert!(packet_with_probe(0).is_err());
}

#[test]
fn changed_height_or_aggregate_geometry_refuses_without_payloads() {
    let source = TransportEnvelope::for_root().unwrap();
    let mut changed = source;
    changed.cases[0].rows = 16;
    assert!(check_envelope(&changed).is_err());
    let mut changed = source;
    changed.encoded_inner_bytes += 1;
    assert!(check_envelope(&changed).is_err());
    let mut changed = source;
    changed.cases[0].decoded_cumulative_bytes += 1;
    assert!(check_envelope(&changed).is_err());
}

#[test]
fn fixed_decoder_packets_and_cpu_claims_are_additive_at_exact_budget() {
    let fixed = claims::fixed().unwrap();
    let cpu = CpuEnvelope::source().unwrap();
    let payload = claims::payload(cpu).unwrap();
    assert_eq!(fixed.get(Category::IndependentVerifier), Bytes::ZERO);
    assert_eq!(payload.get(Category::PhaseScratch).host, (DECODE_LIMIT + 2 * PACKET_LIMIT) as u64);
    assert_eq!(payload.get(Category::IndependentVerifier).host,
        (cpu.bytes + RegisteredVerifier::classified_call_extra_bytes()) as u64);
    let fixed_bytes = fixed.total().unwrap();
    let payload_bytes = payload.total().unwrap();
    assert_eq!(fixed_bytes.device, 0);
    assert_eq!(payload_bytes.device, 0);
    let total = fixed_bytes.host.checked_add(payload_bytes.host).unwrap();
    assert!(total <= 32 << 30); // Incremental claims, not combined-worker fit.
    for (host, fits) in [(total, true), (total - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let first = ledger.admit_phase(fixed).unwrap();
        let second = ledger.admit_phase(payload);
        assert_eq!(second.is_ok(), fits);
        drop(second);
        assert_eq!(ledger.snapshot().current, fixed_bytes);
        drop(first);
        let final_state = ledger.snapshot();
        assert_eq!(final_state.current, Bytes::ZERO);
        assert!(final_state.categories.iter().all(|entry| entry.current == Bytes::ZERO));
    }
    assert!(claims::payload(CpuEnvelope { bytes: cpu.bytes, heights: 17 }).is_err());
    assert!(claims::payload(CpuEnvelope { bytes: 0, heights: HEIGHTS }).is_err());
}
