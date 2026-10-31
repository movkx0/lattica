use super::*;
use crate::execution::retained_resources::WorkerAllowance;

fn claims() -> (Ledger, Reservation, Requirements, Requirements) {
    let ledger = Ledger::new(WorkerAllowance { host: 4096, device: 4096 });
    let left = Requirements::single(Category::PhaseScratch, Bytes { host: 97, device: 13 });
    let right = Requirements::single(Category::SymbolicCompiler, Bytes { host: 211, device: 7 });
    let all = sum(left, right).unwrap();
    let original = ledger.admit_phase(all).unwrap();
    (ledger, original, all, right)
}

#[test]
fn verifier_recording_reunites_exact_categories_without_admission() {
    let (ledger, mut original, expected, recording) = claims();
    let before = ledger.snapshot();
    let exact = original.split(recording).unwrap();
    {
        let mut guard = RecordingOriginal { remainder: &mut original, recording: Some(exact) };
        assert_eq!(guard.recording.as_ref().unwrap().requirements(), recording);
        assert_eq!(ledger.snapshot(), before);
        guard.restore().unwrap();
        assert!(guard.recording.is_none());
    }
    assert_eq!(original.requirements(), expected);
    assert_eq!(ledger.snapshot(), before);
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn verifier_recording_unwind_restores_the_original_scratch() {
    let (ledger, mut original, expected, recording) = claims();
    let before = ledger.snapshot();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let exact = original.split(recording).unwrap();
        let _guard = RecordingOriginal { remainder: &mut original, recording: Some(exact) };
        panic!("simulated source verifier recording refusal");
    }));
    assert!(failure.is_err());
    assert_eq!(original.requirements(), expected);
    assert_eq!(ledger.snapshot(), before);
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn crypto_constructor_success_is_not_endpoint_completion() {
    // Counter mechanics only: no metadata identity, case slot, original or
    // successful production endpoint capability is manufactured by this test.
    for family in [ProducerFamily::Shake, ProducerFamily::Aes] {
        let mut counts = [0usize; 48];
        let index = (family as usize) * 3;
        assert!(crypto_endpoints_complete(&counts));
        assert!(pending_crypto_endpoint(&counts, family, 0).is_err());
        counts[index] = 1; // The raw constructor succeeded; preparation did not.
        assert!(!crypto_endpoints_complete(&counts));
        assert_eq!(pending_crypto_endpoint(&counts, family, 0).unwrap(), index + 1);
        assert!(pending_crypto_endpoint(&counts, family, 1).is_err());
        counts[index + 1] = 1;
        assert!(crypto_endpoints_complete(&counts));
        // A completed source cannot be prepared again or advance the next one.
        assert!(pending_crypto_endpoint(&counts, family, 0).is_err());
        assert!(pending_crypto_endpoint(&counts, family, 1).is_err());
    }
}

#[test]
fn endpoint_gate_refuses_skipped_or_simultaneously_pending_sources() {
    let shake = (ProducerFamily::Shake as usize) * 3;
    let aes = (ProducerFamily::Aes as usize) * 3;
    let mut counts = [0usize; 48];
    counts[shake] = 2;
    // Neither source position can explain two constructors with no completion.
    assert!(pending_crypto_endpoint(&counts, ProducerFamily::Shake, 0).is_err());
    assert!(pending_crypto_endpoint(&counts, ProducerFamily::Shake, 1).is_err());
    counts[shake] = 1;
    counts[aes] = 1;
    assert!(!crypto_endpoints_complete(&counts));
    assert!(pending_crypto_endpoint(&counts, ProducerFamily::Shake, 0).is_err());
    assert!(pending_crypto_endpoint(&counts, ProducerFamily::Aes, 0).is_err());
    assert!(pending_crypto_endpoint(&counts, ProducerFamily::Source, 0).is_err());
    assert!(pending_crypto_endpoint(&counts, ProducerFamily::Shake, usize::MAX).is_err());
}
