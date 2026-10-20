use super::*;
use crate::spill_alloc::allocation_requests::measure;
use p3_commit::BatchOpening;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments, OpenedValues};

type Cap = MerkleCap<Val, [Val; 4]>;
type Quadratic = crate::config::Challenge;
type Cubic = crate::block_v2::profile::Challenge;
const LIMIT: usize = 1 << 20;

#[cfg(all(feature = "gpu-cuda", feature = "block-v2-host"))]
#[test]
fn native_cuda_export_matches_existing_wire_and_charges_all_retained_capacity() {
    use p3_field::PrimeField64;
    let wallet = super::super::recursive::WalletProof {
        chain: [0x6d; 32], public: vec![Val::ONE; 26], proof: fixture::<Cubic>(),
    };
    let mut encoded_wallet = b"LBV2TW01".to_vec();
    encoded_wallet.extend(postcard::to_allocvec(&wallet).unwrap());
    let mut expected = b"LBV2WP01".to_vec();
    expected.extend((encoded_wallet.len() as u32).to_le_bytes());
    expected.extend((wallet.public.len() as u32).to_le_bytes());
    expected.extend(encoded_wallet);
    for value in &wallet.public { expected.extend(value.as_canonical_u64().to_le_bytes()); }
    let mut backing = storage::Backing::new(LIMIT);
    backing.proof(&wallet.proof).unwrap();
    backing.vector(&wallet.public).unwrap();
    let exact = backing.bytes() + expected.len();
    let (result, requests) = measure(|| serialize_export(&wallet, exact));
    assert_eq!(result.unwrap(), expected);
    assert_eq!(requests.calls, 1);
    assert_eq!(requests.bytes, expected.len());
    let (rejected, requests) = measure(|| serialize_export(&wallet, exact - 1));
    assert!(rejected.is_err());
    assert_eq!(requests.calls, 0);
}

fn cap() -> Cap {
    MerkleCap::new(vec![[Val::NEG_ONE; 4]])
}

// Every allocation survives in the result: no clones or temporary heap data.
// The independent allocator observer can therefore census the entire backing.
fn fixture<E: PcsField>() -> Proof<ProvingConfig<E>> {
    let extension = E::from_basis_coefficients_fn(|i| Val::from_u64(257 + i as u64));
    Proof {
        commitments: Commitments {
            trace: cap(),
            quotient_chunks: cap(),
            random: Some(cap()),
        },
        opened_values: OpenedValues {
            trace_local: vec![extension, E::ONE],
            trace_next: Some(Vec::with_capacity(3)),
            preprocessed_local: Some(vec![extension]),
            preprocessed_next: Some(Vec::with_capacity(5)),
            quotient_chunks: vec![vec![extension], vec![E::ONE, E::ZERO]],
            random: Some(vec![extension]),
        },
        opening_proof: (
            vec![vec![vec![vec![extension, E::ONE]], vec![vec![E::ZERO]]]],
            FriProof {
                commit_phase_commits: vec![cap(), cap()],
                commit_pow_witnesses: vec![Val::ONE, Val::NEG_ONE],
                query_proofs: vec![QueryProof {
                    input_proof: vec![BatchOpening::new(
                        vec![vec![Val::NEG_ONE, Val::ZERO], vec![Val::ONE]],
                        (vec![vec![Val::NEG_ONE; 4]], vec![[Val::ONE; 4]]),
                    )],
                    commit_phase_openings: vec![CommitPhaseProofStep {
                        log_arity: 1,
                        sibling_values: vec![extension],
                        opening_proof: (vec![vec![Val::NEG_ONE; 4]], vec![[Val::ONE; 4]]),
                    }],
                }],
                final_poly: vec![extension],
                query_pow_witness: Val::NEG_ONE,
            },
        ),
        degree_bits: 14,
    }
}

fn proof_bytes<E: PcsField>(proof: &Proof<ProvingConfig<E>>) -> usize {
    let mut backing = storage::Backing::new(LIMIT);
    let (result, requests) = measure(|| backing.proof(proof));
    result.unwrap();
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
    backing.bytes()
}

fn census<E: PcsField>() {
    let (proof, requests) = measure(fixture::<E>);
    let counted = proof_bytes(&proof);
    assert!(!requests.overflow && requests.calls > 0);
    assert_eq!(counted, requests.bytes);
    let (publics, public_requests) = measure(|| [vec![Val::ONE; 23], Vec::with_capacity(71)]);
    let (plan, observed) =
        measure(|| Plan::new(&proof, &[&publics[0], &publics[1]], &[], LIMIT, LIMIT));
    let plan = plan.unwrap();
    assert_eq!(observed.calls, 0);
    assert_eq!(plan.proof_backing_bytes, counted);
    assert_eq!(plan.public_backing_bytes, public_requests.bytes);
    assert!(!public_requests.overflow && !observed.overflow);
    eprintln!("wallet_serialization_census extension={} proof_backing_bytes={counted} independent_allocation_bytes={} public_backing_bytes={} allocation_free=true", E::DIMENSION, requests.bytes, public_requests.bytes);
}

#[test]
fn retained_backing_matches_independent_allocation_requests_in_both_fields() {
    census::<Quadratic>();
    census::<Cubic>();
}

fn grow<T>(vector: &mut Vec<T>) -> usize {
    let before = vector.capacity();
    vector.reserve_exact(before + 7 - vector.len());
    (vector.capacity() - before) * core::mem::size_of::<T>()
}

fn grow_cap(value: &mut Cap) -> usize {
    let before = value.root_capacity();
    let mut roots = Vec::with_capacity(before + 7);
    roots.extend_from_slice(value.roots());
    *value = MerkleCap::new(roots);
    (value.root_capacity() - before) * core::mem::size_of::<[Val; 4]>()
}

fn spare_capacity<E: PcsField>() {
    let mut proof = fixture::<E>();
    let mut previous = proof_bytes(&proof);
    let mut mutations = 0;
    macro_rules! check {
        ($change:expr) => {{
            let added = $change;
            assert!(added > 0);
            let current = proof_bytes(&proof);
            assert_eq!(current - previous, added);
            previous = current;
            mutations += 1;
        }};
    }
    check!(grow_cap(&mut proof.commitments.trace));
    check!(grow_cap(&mut proof.commitments.quotient_chunks));
    check!(grow_cap(proof.commitments.random.as_mut().unwrap()));
    check!(grow(&mut proof.opened_values.trace_local));
    check!(grow(proof.opened_values.trace_next.as_mut().unwrap()));
    check!(grow(
        proof.opened_values.preprocessed_local.as_mut().unwrap()
    ));
    check!(grow(
        proof.opened_values.preprocessed_next.as_mut().unwrap()
    ));
    check!(grow(proof.opened_values.random.as_mut().unwrap()));
    check!(grow(&mut proof.opened_values.quotient_chunks));
    check!(grow(&mut proof.opened_values.quotient_chunks[0]));
    check!(grow(&mut proof.opening_proof.0));
    check!(grow(&mut proof.opening_proof.0[0]));
    check!(grow(&mut proof.opening_proof.0[0][0]));
    check!(grow(&mut proof.opening_proof.0[0][0][0]));
    check!(grow(&mut proof.opening_proof.1.commit_phase_commits));
    check!(grow_cap(&mut proof.opening_proof.1.commit_phase_commits[0]));
    check!(grow(&mut proof.opening_proof.1.commit_pow_witnesses));
    check!(grow(&mut proof.opening_proof.1.final_poly));
    check!(grow(&mut proof.opening_proof.1.query_proofs));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0]
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .0
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .0[0]
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .1
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .0
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .0[0]
    ));
    check!(grow(
        &mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .1
    ));
    assert_eq!(mutations, 30);
    assert_eq!(proof_bytes(&proof), previous);
    eprintln!("wallet_serialization_capacity extension={} mutations={mutations} optional_empty_buffers=2 allocation_free=true", E::DIMENSION);
}

#[test]
fn quadratic_spare_capacity_at_every_owned_level_is_counted_once() {
    spare_capacity::<Quadratic>();
}

#[test]
fn cubic_spare_capacity_at_every_owned_level_is_counted_once() {
    spare_capacity::<Cubic>();
}

fn boundaries<E: PcsField>() {
    let proof = fixture::<E>();
    let publics = [vec![Val::ONE; 23], Vec::with_capacity(71)];
    let publics = [&publics[0], &publics[1]];
    for prefix in [&[][..], &[&b"LBV2JS01"[..], &[5; 32][..], &[9; 32][..]][..]] {
        let plan = Plan::new(&proof, &publics, prefix, LIMIT, LIMIT).unwrap();
        let (exact, requests) = measure(|| {
            encode(
                &proof,
                &publics,
                prefix,
                plan.encoded_bytes,
                plan.aggregate_bytes,
            )
        });
        let (bytes, exact) = exact.unwrap();
        assert_eq!(exact, plan);
        assert_eq!(bytes.len(), plan.encoded_bytes);
        assert_eq!(requests.calls, 1);
        assert_eq!(requests.bytes, plan.encoded_bytes);
        for (encoded_limit, allowance, expected) in [
            (
                plan.encoded_bytes,
                plan.aggregate_bytes - 1,
                Error::HostLimit,
            ),
            (
                plan.encoded_bytes - 1,
                plan.aggregate_bytes,
                Error::SizeLimit,
            ),
            (
                LIMIT,
                plan.proof_backing_bytes + plan.public_backing_bytes - 1,
                Error::HostLimit,
            ),
            (LIMIT, plan.public_backing_bytes - 1, Error::HostLimit),
            (LIMIT, 0, Error::HostLimit),
            (0, LIMIT, Error::SizeLimit),
        ] {
            let (result, requests) =
                measure(|| encode(&proof, &publics, prefix, encoded_limit, allowance));
            assert_eq!(result.unwrap_err(), expected);
            assert_eq!(requests.calls, 0);
            assert!(!requests.overflow);
        }
    }
}

#[test]
fn exact_limits_pass_and_short_limits_reject_without_allocating_in_both_fields() {
    boundaries::<Quadratic>();
    boundaries::<Cubic>();
}

fn parity<E: PcsField>() {
    let proof = fixture::<E>();
    let payload = postcard::to_allocvec(&proof).unwrap();
    let (bytes, plan) = encode(&proof, &[], &[], LIMIT, LIMIT).unwrap();
    assert_eq!(bytes, payload);
    assert_eq!(plan.prefix_bytes, 0);
    for magic in [b"LBV2JS01", b"LBV2HT01", b"LBV2CB01"] {
        let context = crate::block_v2::commitment::Context {
            profile_id: crate::block_v2::profile::CANDIDATE_PROFILE_ID,
            chain_id: [0x5a; 32],
        };
        // Original CPU encoder's independent payload-then-envelope construction.
        let mut expected = Vec::with_capacity(72 + payload.len());
        expected.extend_from_slice(magic);
        expected.extend_from_slice(&context.profile_id);
        expected.extend_from_slice(&context.chain_id);
        expected.extend_from_slice(&payload);
        let (bytes, plan) = encode(
            &proof,
            &[],
            &[magic, &context.profile_id, &context.chain_id],
            LIMIT,
            LIMIT,
        )
        .unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(plan.prefix_bytes, 72);
        let decoded: Proof<ProvingConfig<E>> = postcard::from_bytes(&bytes[72..]).unwrap();
        assert_eq!(postcard::to_allocvec(&decoded).unwrap(), payload);
    }
}

#[test]
fn output_preserves_postcard_and_all_three_envelopes_in_both_fields() {
    parity::<Quadratic>();
    parity::<Cubic>();
}

#[test]
fn optional_absence_and_empty_owned_storage_preserve_admission() {
    let mut proof = fixture::<Cubic>();
    proof.commitments.random = None;
    proof.opened_values.trace_next = None;
    proof.opened_values.preprocessed_local = None;
    proof.opened_values.preprocessed_next = None;
    proof.opened_values.random = None;
    let before = proof_bytes(&proof);
    proof.opened_values.trace_next = Some(Vec::with_capacity(17));
    assert_eq!(
        proof_bytes(&proof) - before,
        17 * core::mem::size_of::<Cubic>()
    );
    let public = Vec::with_capacity(37);
    let plan = Plan::new(&proof, &[&public], &[], LIMIT, LIMIT).unwrap();
    assert_eq!(plan.public_backing_bytes, 37 * core::mem::size_of::<Val>());
    let ((bytes, _), requests) = {
        let (result, requests) =
            measure(|| encode(&proof, &[&public], &[], LIMIT, plan.aggregate_bytes));
        (result.unwrap(), requests)
    };
    assert_eq!(requests.calls, 1);
    assert_eq!(requests.bytes, bytes.capacity());
    assert_eq!(bytes, postcard::to_allocvec(&proof).unwrap());
}

#[test]
fn checked_storage_and_size_counters_reject_overflow() {
    storage::Backing::overflow_checks();
    let mut size = BoundedSize { bytes: 0, limit: 3 };
    size.try_extend(&[0; 2]).unwrap();
    size.try_push(0).unwrap();
    assert_eq!(size.try_push(0), Err(postcard::Error::SerializeBufferFull));
    assert_eq!(size.finalize().unwrap(), 3);
    let mut size = BoundedSize {
        bytes: 0,
        limit: usize::MAX,
    };
    size.add(usize::MAX).unwrap();
    assert_eq!(size.add(1), Err(postcard::Error::SerializeBufferFull));
    assert_eq!(size.finalize().unwrap(), usize::MAX);
}
