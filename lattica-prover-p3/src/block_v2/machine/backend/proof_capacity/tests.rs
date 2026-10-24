//! Small invalid-shaped fixtures only. No proof generation or verification.
//! Authored during the freeze; none of these tests has been executed.
use super::*;
use crate::block_v2::profile::Challenge;
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, OpenedValues};
use p3_commit::BatchOpening;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_lookup::LookupTerminal;
use p3_symmetric::MerkleCap;

fn cap() -> p3_batch_stark::Commitment<Config> {
    MerkleCap::new(vec![[Val::ZERO; 4]])
}

fn minimal_shape() -> BatchProof<Config> {
    BatchProof {
        commitments: BatchCommitments {
            main: cap(),
            permutation: None,
            quotient_chunks: cap(),
            random: None,
        },
        opened_values: BatchOpenedValues { instances: Vec::new() },
        opening_proof: (
            Vec::new(),
            FriProof {
                commit_phase_commits: Vec::new(),
                commit_pow_witnesses: Vec::new(),
                query_proofs: Vec::new(),
                final_poly: Vec::new(),
                query_pow_witness: Val::ZERO,
            },
        ),
        lookup_terminals: Vec::new(),
        degree_bits: Vec::new(),
    }
}

fn nested_shape() -> BatchProof<Config> {
    let mut proof = minimal_shape();
    proof.commitments.permutation = Some(cap());
    proof.commitments.random = Some(cap());
    proof.degree_bits.push(3);
    proof.lookup_terminals.push(Some(LookupTerminal(Challenge::ZERO)));
    proof.opened_values.instances.push(OpenedValuesWithLookups {
        base_opened_values: OpenedValues {
            trace_local: vec![Challenge::ZERO],
            trace_next: Some(vec![Challenge::ZERO]),
            preprocessed_local: Some(vec![Challenge::ZERO]),
            preprocessed_next: Some(vec![Challenge::ZERO]),
            quotient_chunks: vec![vec![Challenge::ZERO]],
            random: Some(vec![Challenge::ZERO]),
        },
        permutation_local: vec![Challenge::ZERO],
        permutation_next: vec![Challenge::ZERO],
    });
    proof.opening_proof.0.push(vec![vec![vec![Challenge::ZERO]]]);
    let fri = &mut proof.opening_proof.1;
    fri.commit_phase_commits.push(cap());
    fri.commit_pow_witnesses.push(Val::ZERO);
    fri.final_poly.push(Challenge::ZERO);
    fri.query_proofs.push(QueryProof {
        input_proof: vec![BatchOpening::new(
            vec![vec![Val::ZERO]],
            (vec![vec![Val::ZERO]], vec![[Val::ZERO; 4]]),
        )],
        commit_phase_openings: vec![CommitPhaseProofStep {
            log_arity: 1,
            sibling_values: vec![Challenge::ZERO],
            opening_proof: (vec![vec![Val::ZERO]], vec![[Val::ZERO; 4]]),
        }],
    });
    proof
}

#[test]
fn checked_capacity_arithmetic_refuses_overflow_and_accepts_exact_limits() {
    let mut heap = Backing::new(0);
    heap.capacity::<u8>(0).unwrap();
    assert!(matches!(heap.capacity::<u8>(1), Err(ExecutionError::TooLarge)));
    let mut heap = Backing::new(usize::MAX);
    assert!(matches!(heap.capacity::<Val>(usize::MAX), Err(ExecutionError::TooLarge)));
    let mut heap = Backing::new(usize::MAX);
    heap.capacity::<u8>(usize::MAX).unwrap();
    assert!(matches!(heap.capacity::<u8>(1), Err(ExecutionError::TooLarge)));
    // Preserve the original verifier's exact 64 MiB arithmetic boundary
    // without allocating any such buffer.
    let mut heap = Backing::new(64 << 20);
    heap.capacity::<u8>(64 << 20).unwrap();
    assert!(matches!(heap.capacity::<u8>(1), Err(ExecutionError::TooLarge)));
}

#[test]
fn resource_measurement_counts_even_invalid_shapes_without_inline_headers() {
    let proof = minimal_shape();
    let expected = (proof.commitments.main.root_capacity()
        + proof.commitments.quotient_chunks.root_capacity())
        * core::mem::size_of::<[Val; 4]>();
    assert_eq!(retained_proof_capacity_bytes(&proof, expected).unwrap(), expected);
    assert!(matches!(
        retained_proof_capacity_bytes(&proof, expected - 1),
        Err(ExecutionError::TooLarge)
    ));
    assert!(matches!(
        retained_proof_capacity_bytes(&proof, 0),
        Err(ExecutionError::TooLarge)
    ));
}

fn grow<T>(vector: &mut Vec<T>) -> usize {
    let before = vector.capacity();
    vector.reserve_exact(before + 3 - vector.len());
    (vector.capacity() - before) * core::mem::size_of::<T>()
}

fn grow_cap(value: &mut p3_batch_stark::Commitment<Config>) -> usize {
    let before = value.root_capacity();
    // Every cap in these deliberately invalid fixtures contains only zeros.
    // The old field elements are never inspected or cloned.
    let mut roots = Vec::with_capacity(before + 3);
    roots.resize(value.num_roots(), [Val::ZERO; 4]);
    *value = MerkleCap::new(roots);
    (value.root_capacity() - before) * core::mem::size_of::<[Val; 4]>()
}

#[test]
fn spare_capacity_at_every_nested_owner_is_counted_once() {
    let mut proof = nested_shape();
    let mut previous = retained_proof_capacity_bytes(&proof, usize::MAX).unwrap();
    let mut mutations = 0;
    macro_rules! check {
        ($change:expr) => {{
            let added = $change;
            assert!(added > 0);
            let current = retained_proof_capacity_bytes(&proof, usize::MAX).unwrap();
            assert_eq!(current - previous, added);
            assert_eq!(retained_proof_capacity_bytes(&proof, current).unwrap(), current);
            assert!(matches!(
                retained_proof_capacity_bytes(&proof, current - 1),
                Err(ExecutionError::TooLarge)
            ));
            previous = current;
            mutations += 1;
        }};
    }
    check!(grow_cap(&mut proof.commitments.main));
    check!(grow_cap(&mut proof.commitments.quotient_chunks));
    check!(grow_cap(proof.commitments.permutation.as_mut().unwrap()));
    check!(grow_cap(proof.commitments.random.as_mut().unwrap()));
    check!(grow(&mut proof.degree_bits));
    check!(grow(&mut proof.lookup_terminals));
    check!(grow(&mut proof.opened_values.instances));
    check!(grow(&mut proof.opened_values.instances[0].base_opened_values.trace_local));
    check!(grow(proof.opened_values.instances[0].base_opened_values.trace_next.as_mut().unwrap()));
    check!(grow(proof.opened_values.instances[0].base_opened_values.preprocessed_local.as_mut().unwrap()));
    check!(grow(proof.opened_values.instances[0].base_opened_values.preprocessed_next.as_mut().unwrap()));
    check!(grow(proof.opened_values.instances[0].base_opened_values.random.as_mut().unwrap()));
    check!(grow(&mut proof.opened_values.instances[0].base_opened_values.quotient_chunks));
    check!(grow(&mut proof.opened_values.instances[0].base_opened_values.quotient_chunks[0]));
    check!(grow(&mut proof.opened_values.instances[0].permutation_local));
    check!(grow(&mut proof.opened_values.instances[0].permutation_next));
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
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0]));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof[0].opening_proof.0));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof[0].opening_proof.0[0]));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].input_proof[0].opening_proof.1));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].commit_phase_openings));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].opening_proof.0));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].opening_proof.0[0]));
    check!(grow(&mut proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].opening_proof.1));
    assert_eq!(mutations, 36);
    assert!(previous > 0);
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
#[test]
fn legacy_admission_and_portable_observation_agree_on_retained_capacity() {
    let proof = nested_shape();
    let observed = retained_proof_capacity_bytes(&proof, 64 << 20).unwrap();
    let legacy = super::super::verification_call::proof_bytes(&proof).unwrap();
    assert_eq!(observed, legacy);
}
