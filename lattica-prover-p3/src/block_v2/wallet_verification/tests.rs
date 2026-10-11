use super::*;
use crate::block_v2::{
    commitment::Context,
    typed_recursive::{self, Policy},
};
use crate::spill_alloc::allocation_requests::measure;
use p3_commit::BatchOpening;
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments, OpenedValues, Proof};
use profile::Challenge as Ext;

fn cap(log: usize) -> MerkleCap<Val, [Val; 4]> {
    MerkleCap::new(vec![[Val::ZERO; 4]; 1 << log.min(profile::CAP_HEIGHT)])
}

fn decoded_cap(roots: usize) -> MerkleCap<Val, [Val; 4]> {
    // Match the derived struct wire format without invoking the constructor,
    // just as a caller deserializing an untrusted wallet proof can do.
    let wire = postcard::to_allocvec(&(vec![[Val::ZERO; 4]; roots], ())).unwrap();
    let cap: MerkleCap<Val, [Val; 4]> = postcard::from_bytes(&wire).unwrap();
    assert_eq!(cap.roots().len(), roots);
    cap
}

// Shape-only, deliberately invalid proofs exercise admission without proving.
pub(super) fn template(degree: usize, htlc: bool) -> WalletProof {
    let shape = Envelope::new(degree, htlc).unwrap();
    let hiding = (0..ROUNDS)
        .map(|round| {
            (0..shape.matrices[round])
                .map(|_| {
                    vec![
                        vec![Ext::ZERO; profile::NUM_RANDOM_CODEWORDS];
                        if round == 1 { 2 } else { 1 }
                    ]
                })
                .collect()
        })
        .collect();
    let queries = (0..profile::NUM_QUERIES)
        .map(|_| QueryProof {
            input_proof: (0..ROUNDS)
                .map(|round| {
                    BatchOpening::new(
                        vec![
                            vec![Val::ZERO; shape.widths[round] + profile::NUM_RANDOM_CODEWORDS];
                            shape.matrices[round]
                        ],
                        (
                            vec![vec![Val::ZERO; 4]; shape.matrices[round]],
                            vec![[Val::ZERO; 4]; shape.log_lde.saturating_sub(profile::CAP_HEIGHT)],
                        ),
                    )
                })
                .collect(),
            commit_phase_openings: (0..degree)
                .map(|layer| CommitPhaseProofStep {
                    log_arity: 1,
                    sibling_values: vec![Ext::ZERO],
                    opening_proof: (
                        vec![vec![Val::ZERO; 4]],
                        vec![
                            [Val::ZERO; 4];
                            (shape.log_lde - layer - 1).saturating_sub(profile::CAP_HEIGHT)
                        ],
                    ),
                })
                .collect(),
        })
        .collect();
    WalletProof {
        chain: [7; 32],
        public: vec![
            Val::ZERO;
            if htlc {
                crate::htlc_air::N_PUBLIC
            } else {
                crate::joinsplit_air::N_PUBLIC
            }
        ],
        proof: Proof {
            commitments: Commitments {
                trace: cap(shape.log_lde),
                quotient_chunks: cap(shape.log_lde),
                random: Some(cap(shape.log_lde)),
            },
            opened_values: OpenedValues {
                trace_local: vec![Ext::ZERO; shape.widths[1]],
                trace_next: Some(vec![Ext::ZERO; shape.widths[1]]),
                preprocessed_local: None,
                preprocessed_next: None,
                quotient_chunks: vec![vec![Ext::ZERO; 3]; shape.matrices[2]],
                random: Some(vec![Ext::ZERO; 3]),
            },
            opening_proof: (
                hiding,
                FriProof {
                    commit_phase_commits: (0..degree)
                        .map(|layer| cap(shape.log_lde - layer - 1))
                        .collect(),
                    commit_pow_witnesses: vec![Val::ZERO; degree],
                    query_proofs: queries,
                    final_poly: vec![Ext::ZERO],
                    query_pow_witness: Val::ZERO,
                },
            ),
            degree_bits: degree,
        },
    }
}

#[test]
fn every_admitted_degree_and_wallet_geometry_has_allocation_free_input_admission() {
    let mut maximum = 0;
    for htlc in [false, true] {
        for degree in 1..=MAX_DEGREE_BITS {
            let wallet = template(degree, htlc);
            let mut expected = wallet.public.clone();
            expected.extend(
                Context {
                    profile_id: profile::CANDIDATE_PROFILE_ID,
                    chain_id: wallet.chain,
                }
                .to_fields()
                .map(Val::from_u64),
            );
            let (admitted, requests) = measure(|| inputs(&wallet, htlc));
            assert_eq!(requests.calls, 0);
            let admitted = admitted.unwrap();
            assert_eq!(admitted.public(), expected);
            maximum = maximum.max(admitted.proof_backing_bytes);
        }
    }
    println!("wallet_verification_input_shapes cases=56 maximum_backing_bytes={maximum} backing_limit_bytes={PROOF_BACKING_LIMIT} public_stack_bytes={} allocations=0",
        core::mem::size_of::<[Val; MAX_PUBLIC + 16]>());
}

fn grow<T>(values: &mut Vec<T>) -> usize {
    let old = values.capacity();
    values.reserve_exact(old + 7 - values.len());
    (values.capacity() - old) * core::mem::size_of::<T>()
}
fn grow_cap(value: &mut MerkleCap<Val, [Val; 4]>) -> usize {
    let old = value.root_capacity();
    let mut roots = Vec::with_capacity(old + 7);
    roots.extend_from_slice(value.roots());
    *value = MerkleCap::new(roots);
    (value.root_capacity() - old) * core::mem::size_of::<[Val; 4]>()
}

#[test]
fn every_owned_proof_level_charges_spare_capacity_once() {
    let mut wallet = template(12, false);
    let mut previous = inputs(&wallet, false).unwrap().proof_backing_bytes;
    let mut cases = 0;
    macro_rules! check {
        ($change:expr) => {{
            let added = $change;
            let (admitted, requests) = measure(|| inputs(&wallet, false));
            assert_eq!(requests.calls, 0);
            let current = admitted.unwrap().proof_backing_bytes;
            assert_eq!(current, previous + added);
            previous = current;
            cases += 1;
        }};
    }
    check!(grow(&mut wallet.public));
    check!(grow_cap(&mut wallet.proof.commitments.trace));
    check!(grow_cap(&mut wallet.proof.commitments.quotient_chunks));
    check!(grow_cap(wallet.proof.commitments.random.as_mut().unwrap()));
    check!(grow(&mut wallet.proof.opened_values.trace_local));
    check!(grow(
        wallet.proof.opened_values.trace_next.as_mut().unwrap()
    ));
    wallet.proof.opened_values.preprocessed_local = Some(Vec::new());
    check!(grow(
        wallet
            .proof
            .opened_values
            .preprocessed_local
            .as_mut()
            .unwrap()
    ));
    wallet.proof.opened_values.preprocessed_next = Some(Vec::new());
    check!(grow(
        wallet
            .proof
            .opened_values
            .preprocessed_next
            .as_mut()
            .unwrap()
    ));
    check!(grow(wallet.proof.opened_values.random.as_mut().unwrap()));
    check!(grow(&mut wallet.proof.opened_values.quotient_chunks));
    check!(grow(&mut wallet.proof.opened_values.quotient_chunks[0]));
    check!(grow(&mut wallet.proof.opening_proof.0));
    check!(grow(&mut wallet.proof.opening_proof.0[0]));
    check!(grow(&mut wallet.proof.opening_proof.0[0][0]));
    check!(grow(&mut wallet.proof.opening_proof.0[0][0][0]));
    check!(grow(&mut wallet.proof.opening_proof.1.commit_phase_commits));
    check!(grow_cap(
        &mut wallet.proof.opening_proof.1.commit_phase_commits[0]
    ));
    check!(grow(&mut wallet.proof.opening_proof.1.commit_pow_witnesses));
    check!(grow(&mut wallet.proof.opening_proof.1.final_poly));
    check!(grow(&mut wallet.proof.opening_proof.1.query_proofs));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].input_proof
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0]
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .0
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .0[0]
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].input_proof[0]
            .opening_proof
            .1
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].commit_phase_openings
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].sibling_values
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .0
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .0[0]
    ));
    check!(grow(
        &mut wallet.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
            .opening_proof
            .1
    ));
    println!("wallet_verification_input_capacity cases={cases} final_backing_bytes={previous} allocations=0");
}

#[test]
fn malformed_shapes_and_large_spare_buffers_fail_without_allocation() {
    let changes: &[fn(&mut WalletProof)] = &[
        |w| w.public.push(Val::ZERO),
        |w| w.proof.degree_bits = 0,
        |w| w.proof.degree_bits = MAX_DEGREE_BITS + 1,
        |w| w.proof.degree_bits = usize::MAX,
        |w| w.proof.commitments.trace = MerkleCap::new(vec![[Val::ZERO; 4]; 128]),
        |w| w.proof.commitments.quotient_chunks = MerkleCap::new(vec![[Val::ZERO; 4]; 128]),
        |w| w.proof.commitments.random = Some(MerkleCap::new(vec![[Val::ZERO; 4]; 128])),
        |w| w.proof.commitments.trace = decoded_cap(0),
        |w| w.proof.commitments.trace = decoded_cap(3),
        |w| w.proof.commitments.quotient_chunks = decoded_cap(0),
        |w| w.proof.commitments.quotient_chunks = decoded_cap(3),
        |w| w.proof.commitments.random = Some(decoded_cap(0)),
        |w| w.proof.commitments.random = Some(decoded_cap(3)),
        |w| w.proof.opening_proof.1.commit_phase_commits[0] = decoded_cap(0),
        |w| w.proof.opening_proof.1.commit_phase_commits[0] = decoded_cap(3),
        |w| w.proof.opened_values.trace_local.push(Ext::ZERO),
        |w| {
            w.proof
                .opened_values
                .trace_next
                .as_mut()
                .unwrap()
                .push(Ext::ZERO)
        },
        |w| w.proof.opened_values.preprocessed_local = Some(vec![Ext::ZERO]),
        |w| w.proof.opened_values.preprocessed_next = Some(vec![Ext::ZERO]),
        |w| {
            w.proof
                .opened_values
                .random
                .as_mut()
                .unwrap()
                .push(Ext::ZERO)
        },
        |w| w.proof.opened_values.quotient_chunks.push(vec![]),
        |w| w.proof.opened_values.quotient_chunks[0].push(Ext::ZERO),
        |w| w.proof.opening_proof.0.push(vec![]),
        |w| w.proof.opening_proof.0[0].push(vec![]),
        |w| w.proof.opening_proof.0[0][0].push(vec![]),
        |w| w.proof.opening_proof.0[1][0].push(vec![]),
        |w| w.proof.opening_proof.0[2].push(vec![]),
        |w| w.proof.opening_proof.0[0][0][0].push(Ext::ZERO),
        |w| w.proof.opening_proof.1.commit_phase_commits.push(cap(16)),
        |w| {
            w.proof.opening_proof.1.commit_phase_commits[0] =
                MerkleCap::new(vec![[Val::ZERO; 4]; 128])
        },
        |w| w.proof.opening_proof.1.commit_pow_witnesses.push(Val::ZERO),
        |w| w.proof.opening_proof.1.final_poly.push(Ext::ZERO),
        |w| {
            let q = w.proof.opening_proof.1.query_proofs[0].clone();
            w.proof.opening_proof.1.query_proofs.push(q);
        },
        |w| {
            let p = w.proof.opening_proof.1.query_proofs[0].input_proof[0].clone();
            w.proof.opening_proof.1.query_proofs[0].input_proof.push(p);
        },
        |w| {
            w.proof.opening_proof.1.query_proofs[0].input_proof[0]
                .opened_values
                .push(vec![])
        },
        |w| w.proof.opening_proof.1.query_proofs[0].input_proof[0].opened_values[0].push(Val::ZERO),
        |w| {
            w.proof.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .0
                .push(vec![])
        },
        |w| {
            w.proof.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .0[0]
                .push(Val::ZERO)
        },
        |w| {
            w.proof.opening_proof.1.query_proofs[0].input_proof[0]
                .opening_proof
                .1
                .push([Val::ZERO; 4])
        },
        |w| {
            let p = w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].clone();
            w.proof.opening_proof.1.query_proofs[0]
                .commit_phase_openings
                .push(p);
        },
        |w| w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].log_arity = 0,
        |w| w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0].log_arity = 2,
        |w| {
            w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .sibling_values
                .push(Ext::ZERO)
        },
        |w| {
            w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .opening_proof
                .0
                .push(vec![])
        },
        |w| {
            w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .opening_proof
                .0[0]
                .push(Val::ZERO)
        },
        |w| {
            w.proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                .opening_proof
                .1
                .push([Val::ZERO; 4])
        },
    ];
    for change in changes {
        let mut wallet = template(12, false);
        change(&mut wallet);
        let (result, requests) = measure(|| inputs(&wallet, false));
        assert!(result.is_err());
        assert_eq!(requests.calls, 0);
    }
    let mut wallet = template(12, false);
    wallet
        .public
        .reserve_exact(PROOF_BACKING_LIMIT / core::mem::size_of::<Val>() + 1);
    let (result, requests) = measure(|| inputs(&wallet, false));
    assert!(result.is_err());
    assert_eq!(requests.calls, 0);
    let mut backing = storage::Backing::default();
    backing.capacity::<u8>(PROOF_BACKING_LIMIT).unwrap();
    assert!(backing.capacity::<u8>(1).is_err());
    assert!(storage::Backing::default()
        .capacity::<Val>(usize::MAX)
        .is_err());
    println!("wallet_verification_input_rejections shapes={} oversized_spare=true overflow=true allocations=0", changes.len());
}

#[test]
fn bounded_diagnostics_preserve_labels_and_limit_owned_error_storage() {
    for text in ["small".to_owned(), "é".repeat(600), "x".repeat(8192)] {
        let (error, requests) = measure(|| error("wallet verification", &text));
        assert!(requests.bytes <= 1024 + core::mem::size_of::<String>());
        assert!(requests.calls <= 2);
        let message = error.to_string();
        assert!(
            message.starts_with("wallet verification:")
                || message.contains("diagnostic exceeds limit")
        );
        assert!(message.len() <= 1024);
    }
    println!("wallet_verification_input_diagnostics heap_limit_bytes=1048 output_limit_bytes=1024");
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh(index: usize) {
    use crate::block_v2::{leaf::ContextJoinSplitAir, typed_fixture, typed_leaf::ContextAir};
    let (mut wallet, policy) = typed_fixture::wallet(index).unwrap();
    crate::block_v2::execution::job::typed_registry_fresh_check(&wallet, policy);
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    super::scratch::tests::fresh_check(&mut wallet, policy);
    let htlc = matches!(policy, Policy::Htlc { .. });
    let admitted = inputs(&wallet, htlc).unwrap();
    // Independent unchanged upstream numerical verifier, using the original AIR.
    let config = profile::make_config();
    match policy {
        Policy::JoinSplit => p3_uni_stark::verify(
            &config,
            &ContextJoinSplitAir,
            &wallet.proof,
            admitted.public(),
        )
        .unwrap(),
        Policy::Htlc { .. } => p3_uni_stark::verify(
            &config,
            &ContextAir(crate::htlc_air::HtlcAir),
            &wallet.proof,
            admitted.public(),
        )
        .unwrap(),
        Policy::Issuance { .. } => p3_uni_stark::verify(
            &config,
            &ContextAir(crate::joinsplit_air::JoinSplitAir),
            &wallet.proof,
            admitted.public(),
        )
        .unwrap(),
    }
    typed_recursive::verify_wallet(&wallet, policy).unwrap();
    wallet.chain[0] ^= 1;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
    wallet.chain[0] ^= 1;
    wallet.public[0] += Val::ONE;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
    wallet.public[0] -= Val::ONE;
    wallet.proof.opened_values.trace_local[0] += Ext::ONE;
    assert!(typed_recursive::verify_wallet(&wallet, policy).is_err());
    println!("wallet_verification_input_fresh index={index} proof_backing_bytes={} cpu_proofs=1 upstream_verified=true altered_chain_rejected=true altered_public_rejected=true altered_opening_rejected=true", admitted.proof_backing_bytes);
}

#[test]
#[ignore = "bounded fresh CPU proof qualification"]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh_join_split() {
    fresh(0);
}
#[test]
#[ignore = "bounded fresh CPU proof qualification"]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh_htlc_redeem() {
    fresh(1);
}
#[test]
#[ignore = "bounded fresh CPU proof qualification"]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh_htlc_refund() {
    fresh(2);
}
#[test]
#[ignore = "bounded fresh CPU proof qualification"]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh_issuance() {
    fresh(3);
}
