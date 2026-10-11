use super::super::test_support::ReplayPow;
use super::*;
use crate::block_v2::{
    gpu_hash::{self, device::MatrixSpec},
    pcs_field::PcsField,
    quotient_pcs::CandidatePcs,
};
use crate::config::{MyCompress, MyHash, ValMmcs};
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage};
use p3_challenger::CanObserve;
use p3_field::PrimeField64;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Serialize};

type CpuMmcs<E> = p3_commit::ExtensionMmcs<Val, E, ValMmcs>;
type CpuPcs<E> = p3_fri::HidingFriPcs<Val, crate::config::Dft, ValMmcs, CpuMmcs<E>, ChaCha20Rng>;
type CpuProof<E> = <CpuPcs<E> as Pcs<E, Challenger>>::Proof;

fn params<E: PcsField, M>(mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: crate::config::LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: E::MAX_LOG_ARITY,
        num_queries: E::NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: crate::config::QUERY_POW_BITS,
        mmcs,
    }
}

#[test]
#[ignore = "requires owned OpenCL PCS flags and bounded native service"]
fn quadratic_resident_hiding_pcs_matches_upstream_and_verifies_after_shutdown() {
    conformance::<crate::config::Challenge>();
}

#[test]
#[ignore = "requires owned OpenCL PCS flags and bounded native service"]
fn cubic_resident_hiding_pcs_matches_upstream_and_verifies_after_shutdown() {
    conformance::<Challenge>();
}

#[test]
#[ignore = "requires explicit host-opening research flags and bounded OpenCL service"]
fn quadratic_host_hiding_preserves_streams_and_rejects_compact_inputs() {
    type E = crate::config::Challenge;
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = crate::block_v2::quotient_pcs::initialize_research_from_env().unwrap();
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(!crate::block_v2::quotient_pcs::gpu_opening_eval_enabled());
    gpu_hash::initialize_from_env().unwrap();
    crate::block_v2::resident_pcs::initialize_research_from_env().unwrap();
    let perm = default_goldilocks_poseidon2_8();
    let cpu_mmcs = |seed| {
        ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            crate::config::CAP_HEIGHT,
            ChaCha20Rng::from_seed([seed; 32]),
        )
    };
    let gpu_mmcs = |seed| {
        CandidateMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            crate::config::CAP_HEIGHT,
            ChaCha20Rng::from_seed([seed; 32]),
        )
    };
    let cpu = CpuPcs::<E>::new(
        Default::default(),
        cpu_mmcs(37),
        params::<E, _>(CpuMmcs::new(cpu_mmcs(71))),
        4,
        ChaCha20Rng::from_seed([43; 32]),
    );
    let pcs = CandidatePcs::<E>::new_resident(
        Default::default(),
        gpu_mmcs(37),
        params::<E, _>(FriExtensionMmcs::new(gpu_mmcs(71))),
        4,
        ChaCha20Rng::from_seed([43; 32]),
        64 << 20,
    )
    .unwrap()
    .with_gpu_openings()
    .unwrap();
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, 4).unwrap();
    let input = RowMajorMatrix::new((0..24).map(Val::from_u64).collect(), 3);
    let expected = <CpuPcs<E> as Pcs<E, Challenger>>::commit(&cpu, vec![(domain, input.clone())]);
    let actual = pcs.commit([(domain, input)]);
    assert_eq!(expected.0, actual.0);
    let point = E::from_u64(3);
    let mut proofs = Vec::new();
    for _ in 0..2 {
        let mut verifier = Challenger::new(perm.clone());
        verifier.observe(actual.0.clone());
        let mut challenger = verifier.clone();
        let rounds = vec![(&actual.1, vec![vec![point]])];
        if crate::block_v2::resident_pcs::compact_prover_data() {
            let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pcs.open(rounds, &mut challenger)
            }))
            .err()
            .expect("upstream host opening must not consume compact prefixes");
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap();
            assert!(message.contains("quadratic compact PCS requires owned GPU openings"));
            break;
        }
        let (values, proof) = pcs.open(rounds, &mut challenger);
        let mut reference = ReplayPow {
            inner: verifier.clone(),
            witnesses: proof
                .1
                .commit_pow_witnesses
                .iter()
                .copied()
                .map(|w| (0, w))
                .chain([(crate::config::QUERY_POW_BITS, proof.1.query_pow_witness)])
                .collect(),
        };
        let expected_proof = <CpuPcs<E> as Pcs<E, ReplayPow>>::open(
            &cpu,
            vec![(&expected.1, vec![vec![point]])],
            &mut reference,
        );
        assert!(reference.witnesses.is_empty());
        assert_eq!(values, expected_proof.0);
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected_proof.1).unwrap()
        );
        assert_eq!(
            challenger.sample_algebra_element::<E>(),
            reference.sample_algebra_element::<E>()
        );
        let proof: CpuProof<E> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        proofs.push((
            proof,
            verifier,
            vec![(
                actual.0.clone(),
                vec![(domain, vec![(point, values[0][0][0].clone())])],
            )],
        ));
    }
    drop(actual);
    drop(pcs);
    gpu_hash::shutdown().unwrap();
    for (proof, mut verifier, rounds) in proofs {
        <CpuPcs<E> as Pcs<E, Challenger>>::verify(&cpu, rounds, &proof, &mut verifier).unwrap();
    }
}

fn conformance<E: PcsField + Serialize + DeserializeOwned>() {
    use device::{DomainSpec, Extension, RowOrder};
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = crate::block_v2::quotient_pcs::initialize_research_from_env().unwrap();
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled());
    assert!(crate::block_v2::quotient_pcs::gpu_fri_resident_enabled());
    gpu_hash::initialize_from_env().unwrap();
    crate::block_v2::resident_pcs::initialize_research_from_env().unwrap();
    let mut artifacts = Vec::new();
    for (case, shapes) in [vec![(3, 3)], vec![(5, 1), (5, 5)], vec![(9, 3), (9, 7)]]
        .into_iter()
        .enumerate()
    {
        let perm = default_goldilocks_poseidon2_8();
        let cpu_mmcs = |seed| {
            ValMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm.clone()),
                crate::config::CAP_HEIGHT,
                ChaCha20Rng::from_seed([seed; 32]),
            )
        };
        let gpu_mmcs = |seed| {
            CandidateMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm.clone()),
                crate::config::CAP_HEIGHT,
                ChaCha20Rng::from_seed([seed; 32]),
            )
        };
        let cpu = CpuPcs::<E>::new(
            Default::default(),
            cpu_mmcs(37),
            params::<E, _>(CpuMmcs::new(cpu_mmcs(71))),
            crate::config::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([43; 32]),
        );
        let pcs = CandidatePcs::<E>::new_resident(
            Default::default(),
            gpu_mmcs(37),
            params::<E, _>(FriExtensionMmcs::new(gpu_mmcs(71))),
            crate::config::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([43; 32]),
            64 << 20,
        )
        .unwrap()
        .with_fused_quotients(ChaCha20Rng::from_seed([47; 32]))
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .unwrap();
        let session = pcs.quotient_session().unwrap();
        let cloned = pcs.clone();
        let mut cpu_data = Vec::new();
        let mut gpu_data = Vec::new();
        let mut commitments = Vec::new();
        let mut domains = Vec::new();
        // Public inputs are uploaded before the opening operation. All masks,
        // salts, LDEs, opening reductions, FRI layers and queries stay on GPU.
        let random_domain = TwoAdicMultiplicativeCoset::new(Val::ONE, shapes[0].0 + 1).unwrap();
        let expected = <CpuPcs<E> as Pcs<E, Challenger>>::get_opt_randomization_poly_commitment(
            &cpu,
            [random_domain],
        )
        .unwrap();
        let actual = pcs
            .randomization_device([DomainSpec::new(1, shapes[0].0 + 1).unwrap()])
            .unwrap();
        assert_eq!(expected.0, actual.0);
        commitments.push(expected.0);
        cpu_data.push(expected.1);
        gpu_data.push(actual.1);
        domains.push(vec![random_domain]);
        // Two successive trace rounds exercise shared streams across active
        // PCS clones; the second must not reuse masks or commitment salts.
        for round in 0..2 {
            let mut host = Vec::new();
            let mut device = Vec::new();
            let mut round_domains = Vec::new();
            for &(log_rows, columns) in &shapes {
                let log_rows = log_rows - round;
                let extension = if round == 0 {
                    Extension::Base
                } else {
                    E::DEVICE_EXTENSION
                };
                let width = columns * extension.degree();
                let matrix = RowMajorMatrix::new(
                    (0..((1 << log_rows) * width))
                        .map(|i| Val::from_u64((i * 7 + round * 23 + 11) as u64))
                        .collect(),
                    width,
                );
                let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, log_rows + 1).unwrap();
                let owned = session
                    .upload(
                        MatrixSpec::new(log_rows as u32, columns, extension, RowOrder::Natural, 1)
                            .unwrap(),
                        &matrix
                            .values
                            .iter()
                            .map(|x| x.as_canonical_u64())
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                host.push((domain, matrix));
                device.push((domain, owned));
                round_domains.push(domain);
            }
            let expected = <CpuPcs<E> as Pcs<E, Challenger>>::commit(&cpu, host);
            let actual = if round == 0 {
                pcs.commit_main_device(device)
            } else {
                cloned.commit_lookup_device(device)
            }
            .unwrap();
            assert_eq!(expected.0, actual.0);
            commitments.push(expected.0);
            cpu_data.push(expected.1);
            gpu_data.push(actual.1);
            domains.push(round_domains);
        }
        let stages = [
            Stage::Randomness,
            Stage::Transform,
            Stage::Commitment,
            Stage::Opening,
            Stage::FriFold,
            Stage::FriQuery,
            Stage::FinalPolynomial,
            Stage::Transcript,
            Stage::Grinding,
        ];
        let profile = if E::DEVICE_EXTENSION == Extension::Quadratic {
            Profile::LegacyQuadratic
        } else {
            Profile::BlockV2Cubic
        };
        let mut caps =
            Capabilities::cpu(profile, false, false).scoped(CoverageScope::Operation, &stages);
        for stage in stages {
            caps.set(stage, Backend::OpenCl);
        }
        let operation = Run::new(
            "resident_hiding_pcs",
            Request {
                policy: Policy::GpuRequired,
                emit_report: true,
            },
            caps,
        )
        .unwrap();
        let mut challenger = pcs.gpu_challenger().unwrap();
        let attempt = pcs.begin_randomness_attempt().unwrap().unwrap();
        let transcript_attempt = challenger.begin_attempt().unwrap().unwrap();
        let opening = session.observe_opening(&operation).unwrap();
        let fri = session.observe_fri(&operation, false).unwrap();
        let randomness =
            crate::block_v2::randomness::RandomnessObservation::new(&operation, session.clone())
                .unwrap();
        let transcript = challenger.observe_fri(&operation).unwrap().unwrap();
        let mut verifier = Challenger::new(perm);
        for commitment in &commitments {
            challenger.observe(commitment.clone());
            verifier.observe(commitment.clone());
        }
        let point: E = challenger.sample_algebra_element();
        assert_eq!(point, verifier.sample_algebra_element::<E>());
        let points: Vec<Vec<Vec<E>>> = domains
            .iter()
            .map(|round| round.iter().map(|_| vec![point, point + E::ONE]).collect())
            .collect();
        let rounds = gpu_data
            .iter()
            .zip(&points)
            .map(|(data, p)| (data, p.clone()))
            .collect();
        let (opened, proof) = pcs.open(rounds, &mut challenger);
        transcript_attempt.complete();
        attempt.complete();
        drop(transcript);
        drop(randomness);
        drop(fri);
        drop(opening);
        assert!(operation.finish(true).unwrap().stage_coverage_complete);
        let mut reference = ReplayPow {
            inner: verifier.clone(),
            witnesses: proof
                .1
                .commit_pow_witnesses
                .iter()
                .copied()
                .map(|w| (0, w))
                .chain([(crate::config::QUERY_POW_BITS, proof.1.query_pow_witness)])
                .collect(),
        };
        let rounds = cpu_data
            .iter()
            .zip(&points)
            .map(|(data, p)| (data, p.clone()))
            .collect();
        let (expected_values, expected) =
            <CpuPcs<E> as Pcs<E, ReplayPow>>::open(&cpu, rounds, &mut reference);
        assert!(reference.witnesses.is_empty());
        assert_eq!(opened, expected_values);
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
        assert_eq!(
            challenger.sample_algebra_element::<E>(),
            reference.sample_algebra_element::<E>()
        );
        let proof: CpuProof<E> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        let rounds = commitments
            .into_iter()
            .zip(domains.into_iter().zip(points.into_iter().zip(opened)))
            .map(|(commitment, (domains, (points, values)))| {
                (
                    commitment,
                    domains
                        .into_iter()
                        .zip(points.into_iter().zip(values))
                        .map(|(domain, (p, v))| (domain, p.into_iter().zip(v).collect()))
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        artifacts.push((cpu, proof, verifier, rounds, case));
    }
    gpu_hash::shutdown().unwrap();
    for (cpu, proof, verifier, rounds, case) in artifacts {
        <CpuPcs<E> as Pcs<E, Challenger>>::verify(
            &cpu,
            rounds.clone(),
            &proof,
            &mut verifier.clone(),
        )
        .unwrap();
        let mut changed = rounds.clone();
        changed[1].1[0].1[0].1[0] += E::ONE;
        assert!(<CpuPcs<E> as Pcs<E, Challenger>>::verify(
            &cpu,
            changed,
            &proof,
            &mut verifier.clone()
        )
        .is_err());
        let mut bad: CpuProof<E> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        bad.1.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
        assert!(<CpuPcs<E> as Pcs<E, Challenger>>::verify(
            &cpu,
            rounds,
            &bad,
            &mut verifier.clone()
        )
        .is_err());
        eprintln!(
            "resident_hiding_pcs field={:?} case={case} verified_after_shutdown=true",
            E::DEVICE_EXTENSION
        );
    }
}
