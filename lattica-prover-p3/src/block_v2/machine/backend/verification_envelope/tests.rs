use super::super::{RegisteredVerifier, Val};
use super::*;
use crate::block_v2::machine::verifier::template;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::MerkleCap;

type Proof = BatchProof<Config>;

fn copy<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
    postcard::from_bytes(&postcard::to_allocvec(value).unwrap()).unwrap()
}

fn cap(log_height: usize) -> p3_batch_stark::Commitment<Config> {
    MerkleCap::new(vec![
        [Val::ZERO; 4];
        1 << log_height.min(profile::CAP_HEIGHT)
    ])
}

fn fixture(publics: usize, height: usize) -> (RegisteredVerifier, Envelope, Proof) {
    let log_lde = height.ilog2() as usize + 1 + profile::LOG_BLOWUP;
    let verifier = RegisteredVerifier::from_trusted_cap(publics, height, cap(log_lde)).unwrap();
    let envelope =
        Envelope::new(&verifier.air, &verifier.common, verifier.quotient_chunks).unwrap();
    let proof = template::batch(&verifier.air).unwrap();
    (verifier, envelope, proof)
}

fn rejected(envelope: Envelope, proof: &Proof, change: impl FnOnce(&mut Proof)) {
    let mut changed = copy(proof);
    change(&mut changed);
    assert_eq!(
        envelope.check(&changed),
        Err("native verifier proof exceeds registered envelope")
    );
}

#[test]
fn registered_templates_fit_at_public_height_and_cap_boundaries() {
    for publics in [0, 1, 23, 32, 33, 64] {
        for height in [8, 64, 1 << 19, 1 << 24] {
            let (_, envelope, proof) = fixture(publics, height);
            envelope.check(&proof).unwrap();
            assert_eq!(
                envelope.matrices[2],
                proof.opened_values.instances[0]
                    .base_opened_values
                    .quotient_chunks
                    .len()
            );
            assert_eq!(
                envelope.degree,
                proof.opening_proof.1.commit_phase_commits.len()
            );
            assert_eq!(
                envelope.widths[4],
                proof.opened_values.instances[0].permutation_local.len()
            );
        }
    }
    eprintln!(
        "native_verifier_envelope templates=24 max_height=16777216 wide={}",
        cfg!(feature = "block-v2-wide-lanes")
    );
}

#[test]
fn opened_value_and_commitment_lengths_are_admitted_before_native_verification() {
    let (verifier, e, p) = fixture(1, 64);
    let zero = profile::Challenge::ZERO;
    for which in 0..4 {
        rejected(e, &p, |p| {
            let oversized = MerkleCap::new(vec![[Val::ZERO; 4]; 1 << (profile::CAP_HEIGHT + 1)]);
            match which {
                0 => p.commitments.main = oversized,
                1 => p.commitments.quotient_chunks = oversized,
                2 => p.commitments.random = Some(oversized),
                _ => p.commitments.permutation = Some(oversized),
            }
        });
    }
    rejected(e, &p, |p| {
        p.opened_values
            .instances
            .push(copy(&p.opened_values.instances[0]))
    });
    rejected(e, &p, |p| p.opened_values.instances.clear());
    for trace in [false, true] {
        for empty in [false, true] {
            rejected(e, &p, |p| {
                let v = &mut p.opened_values.instances[0].base_opened_values;
                let width = if trace { e.widths[1] } else { e.widths[3] };
                let row = Some(vec![zero; if empty { 0 } else { width }]);
                if trace {
                    v.trace_next = row;
                } else {
                    v.preprocessed_next = row;
                }
            });
        }
    }
    for which in 0..9 {
        rejected(e, &p, |p| {
            let i = &mut p.opened_values.instances[0];
            let v = &mut i.base_opened_values;
            match which {
                0 => v.trace_local.push(zero),
                1 => v.trace_next = Some(vec![zero; e.widths[1] + 1]),
                2 => v.preprocessed_local.as_mut().unwrap().push(zero),
                3 => v.preprocessed_next = Some(vec![zero; e.widths[3] + 1]),
                4 => v.random.as_mut().unwrap().push(zero),
                5 => v.quotient_chunks.push(vec![]),
                6 => v.quotient_chunks[0].push(zero),
                7 => i.permutation_local.push(zero),
                _ => i.permutation_next.push(zero),
            }
            assert_eq!(
                verifier.verify(p, &[Val::ZERO]).unwrap_err(),
                "native verifier proof exceeds registered envelope"
            );
        });
    }
}

#[cfg(feature = "stream")]
#[test]
fn deserialized_cap_invariants_are_rejected_before_native_verification() {
    use crate::spill_alloc::allocation_requests::measure;
    let (verifier, envelope, proof) = fixture(1, 64);
    let mut cases = 0;
    for roots in [0, 3] {
        for which in 0..5 {
            let wire = postcard::to_allocvec(&(vec![[Val::ZERO; 4]; roots], ())).unwrap();
            let cap: p3_batch_stark::Commitment<Config> = postcard::from_bytes(&wire).unwrap();
            assert_eq!(cap.roots().len(), roots);
            let mut changed = copy(&proof);
            match which {
                0 => changed.commitments.main = cap,
                1 => changed.commitments.quotient_chunks = cap,
                2 => changed.commitments.random = Some(cap),
                3 => changed.commitments.permutation = Some(cap),
                _ => changed.opening_proof.1.commit_phase_commits[0] = cap,
            }
            let (result, requests) = measure(|| envelope.check(&changed));
            assert_eq!(
                result,
                Err("native verifier proof exceeds registered envelope")
            );
            assert!(!requests.overflow);
            assert_eq!(requests.calls, 0);
            assert_eq!(requests.bytes, 0);
            assert_eq!(
                verifier.verify(&changed, &[Val::ZERO]).unwrap_err(),
                "native verifier proof exceeds registered envelope"
            );
            cases += 1;
        }
    }
    eprintln!("registered_cap_invariants proof_cases={cases} allocations=0");
}

#[test]
fn every_hiding_round_matrix_point_and_width_is_bounded() {
    let (_, e, p) = fixture(0, 8);
    rejected(e, &p, |p| p.opening_proof.0.push(vec![]));
    for round in 0..ROUNDS {
        rejected(e, &p, |p| p.opening_proof.0[round].push(vec![]));
        rejected(e, &p, |p| p.opening_proof.0[round][0].push(vec![]));
        rejected(e, &p, |p| {
            p.opening_proof.0[round][0][0].push(profile::Challenge::ZERO)
        });
    }
    assert_eq!(hiding_width(3), 0);
}

#[test]
fn fri_layers_caps_pow_final_polynomial_and_query_count_are_bounded() {
    let (_, e, p) = fixture(0, 64);
    rejected(e, &p, |p| {
        p.opening_proof.1.commit_phase_commits.push(cap(0))
    });
    rejected(e, &p, |p| {
        p.opening_proof.1.commit_pow_witnesses.push(Val::ZERO)
    });
    rejected(e, &p, |p| {
        p.opening_proof.1.final_poly.push(profile::Challenge::ZERO)
    });
    rejected(e, &p, |p| {
        p.opening_proof
            .1
            .query_proofs
            .push(p.opening_proof.1.query_proofs[0].clone())
    });
    for layer in 0..e.degree {
        rejected(e, &p, |p| {
            let log_cap = (e.log_lde - layer - 1).min(profile::CAP_HEIGHT);
            p.opening_proof.1.commit_phase_commits[layer] =
                MerkleCap::new(vec![[Val::ZERO; 4]; 1 << (log_cap + 1)]);
        });
    }
}

#[test]
fn query_rows_salts_paths_and_fold_steps_are_bounded() {
    let (_, e, p) = fixture(0, 64);
    rejected(e, &p, |p| {
        let q = &mut p.opening_proof.1.query_proofs[0];
        q.input_proof.push(q.input_proof[0].clone());
    });
    rejected(e, &p, |p| {
        let q = &mut p.opening_proof.1.query_proofs[0];
        q.commit_phase_openings
            .push(q.commit_phase_openings[0].clone());
    });
    for query in [0, profile::NUM_QUERIES - 1] {
        for round in 0..ROUNDS {
            for which in 0..5 {
                rejected(e, &p, |p| {
                    let o = &mut p.opening_proof.1.query_proofs[query].input_proof[round];
                    match which {
                        0 => o.opened_values.push(vec![]),
                        1 => o.opened_values[0].push(Val::ZERO),
                        2 => o.opening_proof.0.push(vec![]),
                        3 => o.opening_proof.0[0].push(Val::ZERO),
                        _ => o.opening_proof.1.push([Val::ZERO; 4]),
                    }
                });
            }
        }
        for layer in 0..e.degree {
            for which in 0..5 {
                rejected(e, &p, |p| {
                    let o = &mut p.opening_proof.1.query_proofs[query].commit_phase_openings[layer];
                    match which {
                        0 => o.log_arity = 2,
                        1 => o.sibling_values.push(profile::Challenge::ZERO),
                        2 => o.opening_proof.0.push(vec![]),
                        3 => o.opening_proof.0[0].push(Val::ZERO),
                        _ => o.opening_proof.1.push([Val::ZERO; 4]),
                    }
                });
            }
        }
    }
}

#[test]
fn envelope_does_not_replace_verification_or_admit_caller_capacity() {
    let (verifier, e, mut p) = fixture(1, 8);
    p.opened_values.instances[0]
        .base_opened_values
        .trace_local
        .reserve(1024);
    let capacity = p.opened_values.instances[0]
        .base_opened_values
        .trace_local
        .capacity();
    p.opening_proof.1.query_proofs.pop();
    e.check(&p).unwrap();
    let error = verifier.verify(&p, &[Val::ZERO]).unwrap_err();
    assert_ne!(error, "native verifier proof exceeds registered envelope");
    assert_eq!(
        p.opened_values.instances[0]
            .base_opened_values
            .trace_local
            .capacity(),
        capacity
    );
    for chunks in [0, profile::MAX_QUOTIENT_CHUNKS + 1, usize::MAX] {
        assert!(Envelope::new(&verifier.air, &verifier.common, chunks).is_err());
    }
    p.degree_bits = vec![usize::MAX];
    assert_eq!(
        verifier.verify(&p, &[Val::ZERO]),
        Err("unregistered degree".into())
    );
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn native_proofs_and_tampering_match_the_unmodified_verifier() {
    use super::super::RegisteredProgram;
    use crate::block_v2::machine::ProgramBuilder;
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    builder.assert_equal(public, input);
    let registered =
        RegisteredProgram::new(MachineAir::new(builder.finish(Some(8)).unwrap())).unwrap();
    let public = [Val::from_u64(17)];
    let proof = registered.prove(&public, &public).unwrap();
    let verifier = registered.verifier();
    let original = |proof: &Proof, public: &[Val]| {
        p3_batch_stark::verify_batch(
            &profile::make_config(),
            core::slice::from_ref(&verifier.air),
            proof,
            &[public.to_vec()],
            &verifier.common,
        )
        .is_ok()
    };
    let encoded = postcard::to_allocvec(&proof).unwrap();
    assert!(original(&proof, &public));
    verifier.verify(&proof, &public).unwrap();
    registered.verify(&proof, &public).unwrap();
    assert_eq!(postcard::to_allocvec(&proof).unwrap(), encoded);
    let changed = [public[0] + Val::ONE];
    assert!(!original(&proof, &changed));
    assert!(verifier.verify(&proof, &changed).is_err());
    let mut unused_next = copy(&proof);
    unused_next.opened_values.instances[0]
        .base_opened_values
        .preprocessed_next = Some(vec![
        profile::Challenge::ZERO;
        verifier.air.preprocessed_width()
    ]);
    assert!(!original(&unused_next, &public));
    assert!(verifier.verify(&unused_next, &public).is_err());
    unused_next.opened_values.instances[0]
        .base_opened_values
        .preprocessed_next = Some(vec![]);
    // Frozen upstream regression: lengths alone accept the empty optional row,
    // PCS verification succeeds, then VerticalPair's width assertion panics.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        original(&unused_next, &public)
    }))
    .is_err());
    assert_eq!(
        verifier.verify(&unused_next, &public).unwrap_err(),
        "native verifier proof exceeds registered envelope"
    );
    assert!(registered.verify(&unused_next, &public).is_err());
    let mut altered = proof;
    altered.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += profile::Challenge::ONE;
    assert!(!original(&altered, &public));
    assert!(verifier.verify(&altered, &public).is_err());
    eprintln!("native_verifier_envelope proof_bytes={} tamper_parity=true unexpected_next_rejected=true upstream_empty_next_panics=true wide={}", encoded.len(), cfg!(feature = "block-v2-wide-lanes"));
}
