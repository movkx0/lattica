use super::*;
use crate::{note, Profile};
use sha3::{Digest, Sha3_256};
use std::time::Instant;

#[test]
fn complete_continuation_reserves_original_ledger_before_driver_or_entropy() {
    let context = Context([96; 32]);
    let (expected, witness) = note::fixture(context).unwrap();
    let session = DecodeSession::new(WORKER_HOST_BYTES).unwrap();
    let prepared = session.prepare_note(&witness, &expected, context).unwrap();
    let preparation_bytes = prepared.receipt().aggregate_reserved_bytes;
    let preceding = session.snapshot();
    let admission = Admission::reserve(&prepared).unwrap();
    let continuation_bytes =
        admission.runtime.reserved_bytes() + admission.handoff.reserved_bytes();
    assert!(admission.runtime.same_ledger(&prepared._reservation));
    assert!(admission.handoff.same_ledger(&prepared._reservation));
    assert_eq!(
        admission.plan.total_bytes,
        admission.handoff.reserved_bytes()
    );
    let admitted = session.snapshot();
    let moved = Some(admission);
    assert_eq!(session.snapshot(), admitted);
    drop(moved);
    assert_eq!(
        session.snapshot().live_reserved_bytes,
        preceding.live_reserved_bytes
    );
    drop(prepared);
    assert_eq!(session.snapshot().live_reserved_bytes, quota::LEDGER_BYTES);
    for missing in [0, 1] {
        let limit = quota::LEDGER_BYTES + preparation_bytes + continuation_bytes - missing;
        let session = DecodeSession::new(limit).unwrap();
        let prepared = session.prepare_note(&witness, &expected, context).unwrap();
        let before = session.snapshot().live_reserved_bytes;
        let admitted = Admission::reserve(&prepared);
        if missing == 0 {
            let admitted = admitted.unwrap();
            assert_eq!(session.snapshot().live_reserved_bytes, limit);
            drop(admitted);
        } else {
            assert!(matches!(admitted, Err(PreparationError::ResourceLimit)));
        }
        assert_eq!(session.snapshot().live_reserved_bytes, before);
        drop(prepared);
        assert_eq!(session.snapshot().live_reserved_bytes, quota::LEDGER_BYTES);
    }
}

#[test]
fn handoff_plan_covers_maximum_encoding_and_rejects_invalid_geometry_inputs() {
    let plan = HandoffPlan::new(26).unwrap();
    assert!(plan.decoder_bytes > 2 * MAX_PROOF_BYTES);
    assert!(plan.verifier_bytes > 0 && plan.verifier_bytes <= 64 << 20);
    assert_eq!(
        plan.total_bytes,
        plan.decoder_bytes + plan.verifier_bytes + plan.inline_bytes
    );
    assert!(plan.total_bytes < NATIVE_HOST_BYTES);
    assert!(HandoffPlan::new(25).is_err());
    assert!(HandoffPlan::new(usize::MAX).is_err());
}

// Copies only after this ignored test's explicit harness claim; ordinary
// decoder and verifier calls additionally reserve their complete phase before
// allocation/numerical work. No helper is an alternative native producer.
fn copy_packet(bytes: &[u8], extra: usize) -> Vec<u8> {
    let length = bytes.len().checked_add(extra).unwrap();
    assert!(length <= ARTIFACT_HEADER_BYTES + MAX_PROOF_BYTES + 1);
    let mut copy = Vec::new();
    copy.try_reserve_exact(length).unwrap();
    assert_eq!(copy.capacity(), length);
    copy.extend_from_slice(bytes);
    copy
}

fn mutation_checks(
    session: &DecodeSession,
    plan: &VerificationPlan,
    artifact: &mut DecodedArtifact,
    expected: &note::Statement,
    context: Context,
) {
    let before = session.snapshot().live_reserved_bytes;
    for offset in [0, 8, 40, ARTIFACT_HEADER_BYTES - 8] {
        let mut packet = copy_packet(artifact.canonical_packet(), 0);
        packet[offset] ^= 1;
        assert!(session.decode(packet, expected, context).is_err());
        assert_eq!(session.snapshot().live_reserved_bytes, before);
    }
    let mut trailing = copy_packet(artifact.canonical_packet(), 1);
    trailing.push(0);
    let length = trailing.len() - ARTIFACT_HEADER_BYTES;
    trailing[ARTIFACT_HEADER_BYTES - 8..ARTIFACT_HEADER_BYTES]
        .copy_from_slice(&(length as u64).to_le_bytes());
    assert!(session.decode(trailing, expected, context).is_err());
    let mut wrong = expected.clone();
    wrong.profile = Profile::RingDirectV1;
    assert!(session
        .decode(copy_packet(artifact.canonical_packet(), 0), &wrong, context)
        .is_err());
    assert!(session
        .decode(
            copy_packet(artifact.canonical_packet(), 0),
            expected,
            Context([97; 32])
        )
        .is_err());
    let mut noncanonical = copy_packet(artifact.canonical_packet(), 0);
    noncanonical[40..48].copy_from_slice(&crate::GOLDILOCKS_MODULUS.to_le_bytes());
    assert!(session.decode(noncanonical, expected, context).is_err());
    use lattica_prover_p3::joinsplit_air as js;
    for index in [js::PI_ANCHOR, js::PI_NF, js::PI_OUTCM] {
        let mut changed = expected.clone();
        changed.public[index] ^= 1;
        let mut packet = copy_packet(artifact.canonical_packet(), 0);
        packet[40 + index * 8..48 + index * 8]
            .copy_from_slice(&changed.public[index].to_le_bytes());
        let changed = session.decode(packet, &changed, context).unwrap();
        assert!(matches!(
            plan.verify(&changed),
            Err(VerificationError::ProofRejected)
        ));
        drop(changed);
        assert_eq!(session.snapshot().live_reserved_bytes, before);
    }
    artifact.mutate_opening_for_test();
    let before_attempts = session.snapshot().admitted_attempts;
    assert!(matches!(
        plan.verify(artifact),
        Err(VerificationError::ProofRejected)
    ));
    // Even a failed verification borrows the pre-dispatch original token; it
    // neither admits replacement bytes nor leaks its single-flight guard.
    assert_eq!(session.snapshot().admitted_attempts, before_attempts);
    assert_eq!(session.snapshot().live_reserved_bytes, before);
}

#[test]
#[ignore = "exact dedicated immutable env-clear RTX 5080 worker, coordinator process/VRAM guard only"]
fn gpu_owned_note_handoff_verifies_fresh_proofs_and_rejects_mutations() {
    let context = Context([96; 32]);
    let (expected, witness) = note::fixture(context).unwrap();
    let session = DecodeSession::new(WORKER_HOST_BYTES).unwrap();
    let anchor = session.reserve_for_producer(0).unwrap();
    let plan = VerificationPlan::new().unwrap();
    let handoff = HandoffPlan::new(expected.public.capacity()).unwrap();
    // Fixed harness copies and statement clones are additional to native,
    // packet/decoder and verifier claims. Fixture/reference construction and
    // runtime/allocator/thread internals remain the external test guard's
    // obligations, outside the measured producer/decoder/verifier interval.
    let harness_bytes = 2 * (MAX_PROOF_BYTES + ARTIFACT_HEADER_BYTES + 1)
        + 2 * expected.public.capacity() * size_of::<u64>()
        + size_of::<note::Witness>()
        + size_of::<note::Statement>();
    let harness = session.reserve_for_producer(harness_bytes).unwrap();
    let baseline = session.snapshot().live_reserved_bytes;
    let mut hashes = [[0u8; 32]; 2];
    let mut retained = None;
    for ordinal in 0..2 {
        let workflow = Instant::now();
        let prepared = session.prepare_note(&witness, &expected, context).unwrap();
        let setup_ns = workflow.elapsed().as_nanos();
        assert!(prepared.require_dispatch().is_err());
        let native_started = Instant::now();
        // SAFETY: the coordinator's exact ignored-test guard clears the
        // environment, applies the fixed profile, and serializes all GPU work
        // through the full call. This test never mutates the environment.
        let produced = unsafe { prepared.prove_owned_for_qualification() }.unwrap();
        let native_and_retirement_ns = native_started.elapsed().as_nanos();
        assert!(produced.runtime_retired());
        let native_bytes = produced.native_proof_bytes();
        let retained_operation = produced.retained_operation_bytes();
        let mut artifact = produced.into_decoded().unwrap();
        hashes[ordinal] = Sha3_256::digest(artifact.canonical_packet()).into();
        assert_eq!(artifact.context(), context);
        assert_eq!(
            artifact.public(),
            &codec::expected_public(&expected, context).unwrap()
        );
        assert!(
            session.snapshot().live_reserved_bytes
                >= baseline + retained_operation + handoff.decoder_bytes
        );
        let before_verify = session.snapshot();
        let verified = plan.verify(&artifact).unwrap();
        let cpu_ns = verified.receipt().cpu_verification_ns;
        assert!(verified.receipt().independent_cpu_verification);
        assert!(
            !verified.receipt().gpu_work_performed && !verified.receipt().production_acceptance
        );
        drop(verified);
        assert_eq!(session.snapshot(), before_verify);
        let roundtrip_started = Instant::now();
        let packet = copy_packet(artifact.canonical_packet(), 0);
        let restored = session.decode(packet, &expected, context).unwrap();
        assert_eq!(restored.canonical_packet(), artifact.canonical_packet());
        let verified = plan.verify(&restored).unwrap();
        assert!(verified.receipt().independent_cpu_verification);
        drop(verified);
        drop(restored);
        let roundtrip_ns = roundtrip_started.elapsed().as_nanos();
        let qualification_ns = workflow.elapsed().as_nanos();
        eprintln!("private_note_owned_gpu_handoff ordinal={ordinal} native_proofs=1 recursive_proofs=0 fresh_public_preparation=true setup_ns={setup_ns} native_and_retirement_ns={native_and_retirement_ns} independent_cpu_verification_ns={cpu_ns} roundtrip_ns={roundtrip_ns} qualification_interval_ns={qualification_ns} proof_bytes={native_bytes} retained_operation_bytes={retained_operation} original_quota_peak={} independent_verification=true runtime_retired=true matched_ringct_workflow=false production_acceptance=false", session.snapshot().peak_reserved_bytes);
        if ordinal == 0 {
            mutation_checks(&session, &plan, &mut artifact, &expected, context);
            drop(artifact);
            assert_eq!(session.snapshot().live_reserved_bytes, baseline);
        } else {
            retained = Some(artifact);
        }
    }
    assert_ne!(hashes[0], hashes[1]);
    drop(session);
    let before = anchor.snapshot();
    let verified = plan.verify(retained.as_ref().unwrap()).unwrap();
    assert!(verified.receipt().independent_cpu_verification);
    drop(verified);
    assert_eq!(anchor.snapshot(), before);
    drop(retained);
    drop(harness);
    assert_eq!(anchor.snapshot().live_reserved_bytes, quota::LEDGER_BYTES);
    eprintln!("private_note_owned_gpu_handoff_terminal fresh_proofs=2 mutation_cases=12 original_quota_released=true independent_cpu_verification=true complete_ringct_workflow=false");
}
