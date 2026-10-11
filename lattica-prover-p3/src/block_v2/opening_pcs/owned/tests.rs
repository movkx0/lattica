use super::*;
use crate::block_v2::gpu_hash::{self, device::MatrixSpec, FriExtensionMmcs};
use crate::block_v2::opening_pcs::test_support::ReplayPow;
use crate::block_v2::profile;
use crate::config::{Dft, MyCompress, MyHash, ValMmcs};
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::ExtensionMmcs;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Serialize};

type CpuFriMmcs<F> = ExtensionMmcs<Val, F, ValMmcs>;
type CpuPcs<F> = p3_fri::TwoAdicFriPcs<Val, Dft, ValMmcs, CpuFriMmcs<F>>;
type CpuProof<F> = <CpuPcs<F> as Pcs<F, Challenger>>::Proof;

fn params<F: FriExtension, M>(mmcs: M) -> FriParameters<M> {
    let quadratic = F::DEVICE_EXTENSION == Extension::Quadratic;
    FriParameters {
        log_blowup: crate::config::LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: if quadratic { 4 } else { 1 },
        num_queries: if quadratic {
            crate::config::NUM_QUERIES
        } else {
            profile::NUM_QUERIES
        },
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: crate::config::QUERY_POW_BITS,
        mmcs,
    }
}

fn run<F: FriExtension + Serialize + DeserializeOwned>() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    let fusion = crate::block_v2::quotient_pcs::initialize_research_from_env().unwrap();
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled());
    assert!(crate::block_v2::quotient_pcs::gpu_fri_resident_enabled());
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    let mut artifacts = Vec::new();
    for (case, shape) in [
        vec![vec![(5, 3)]],
        vec![vec![(6, 1), (6, 5)], vec![(4, 3)], vec![(5, 2)]],
        vec![vec![(9, 3)], vec![(7, 7)], vec![(6, 2)]],
    ]
    .into_iter()
    .enumerate()
    {
        let perm = default_goldilocks_poseidon2_8();
        let cpu_mmcs = |seed| {
            ValMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm.clone()),
                profile::CAP_HEIGHT,
                ChaCha20Rng::from_seed([seed; 32]),
            )
        };
        let cpu = CpuPcs::<F>::new(
            Dft::default(),
            cpu_mmcs(37),
            params::<F, _>(CpuFriMmcs::new(cpu_mmcs(71))),
        );
        let gpu_mmcs = |seed| {
            CandidateMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm.clone()),
                profile::CAP_HEIGHT,
                ChaCha20Rng::from_seed([seed; 32]),
            )
        };
        let mmcs = gpu_mmcs(37).share_for_resident().unwrap();
        let fri_mmcs = gpu_mmcs(71);
        let failure = crate::block_v2::randomness::Failure::default();
        mmcs.activate_private_randomness(&session, &failure)
            .unwrap();
        fri_mmcs
            .activate_private_randomness(&session, &failure)
            .unwrap();
        let fri = params::<F, _>(FriExtensionMmcs::<F>::new(fri_mmcs));

        // Public input fixtures are uploaded before the scoped operation. Every
        // commitment, retained prefix, opening, reduction and query below is
        // produced by the GPU path; no CPU input proof is attached afterward.
        let mut inputs = Vec::new();
        let mut cpu_data = Vec::new();
        let mut commitments = Vec::new();
        let mut domains = Vec::new();
        let mut points = Vec::new();
        let mut verifier = Challenger::new(perm.clone());
        for (round, matrices) in shape.iter().enumerate() {
            let mut host = Vec::new();
            let mut device = Vec::new();
            let mut round_domains = Vec::new();
            let mut round_points = Vec::new();
            for (matrix, &(log, width)) in matrices.iter().enumerate() {
                let rows = 1usize << log;
                let values: Vec<_> = (0..rows * width)
                    .map(|i| {
                        Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xfedc_ba98_7654_3210)
                                .wrapping_add((case * 113 + round * 19 + matrix * 7) as u64),
                        )
                    })
                    .collect();
                let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, log).unwrap();
                device.push(
                    session
                        .upload(
                            MatrixSpec::new(
                                log as u32,
                                width,
                                Extension::Base,
                                RowOrder::Natural,
                                1,
                            )
                            .unwrap(),
                            &values
                                .iter()
                                .map(PrimeField64::as_canonical_u64)
                                .collect::<Vec<_>>(),
                        )
                        .unwrap(),
                );
                host.push((domain, RowMajorMatrix::new(values, width)));
                round_domains.push(domain);
                round_points.push(
                    (0..if case == 0 { 1 } else { 3 })
                        .map(|point| {
                            let point = if point == 2 { 0 } else { point };
                            F::from_basis_coefficients_fn(|coefficient| {
                                Val::from_u64((11 + point * 37 + coefficient * 13) as u64)
                            })
                        })
                        .collect::<Vec<_>>(),
                );
            }
            let (commitment, data) = <CpuPcs<F> as Pcs<F, Challenger>>::commit(&cpu, host);
            verifier.observe(commitment.clone());
            commitments.push(commitment);
            cpu_data.push(data);
            inputs.push(device);
            domains.push(round_domains);
            points.push(round_points);
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
        let profile = if F::DEVICE_EXTENSION == Extension::Quadratic {
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
            "gpu_owned_extension_pcs",
            Request {
                policy: Policy::GpuRequired,
                emit_report: true,
            },
            caps,
        )
        .unwrap();
        let mut actual = Challenger::new_gpu(&session).unwrap();
        let randomness_attempt = failure.begin().unwrap();
        let transcript_attempt = actual.begin_attempt().unwrap().unwrap();
        let opening_observation = session.observe_opening(&operation).unwrap();
        let fri_observation = session.observe_fri(&operation, false).unwrap();
        let randomness_observation =
            crate::block_v2::randomness::RandomnessObservation::new(&operation, session.clone())
                .unwrap();
        let transcript_observation = actual.observe_fri(&operation).unwrap().unwrap();
        let mut data = Vec::new();
        for (round, matrices) in inputs.iter().enumerate() {
            let prepared = matrices
                .iter()
                .map(|m| session.prepare_evaluations(m).unwrap())
                .collect::<Vec<_>>();
            let shapes = prepared
                .iter()
                .map(|m| m.shape(fri.log_blowup).unwrap())
                .collect::<Vec<_>>();
            mmcs.preflight_private_salts(&shapes, 64 << 20, 0, &[])
                .unwrap();
            let salts = mmcs
                .private_device_salts(matrices[0].spec().rows() << fri.log_blowup, matrices.len())
                .unwrap();
            let (commitment, retained) = mmcs
                .commit_evaluations_with_device_salts(
                    &prepared,
                    fri.log_blowup,
                    salts,
                    &session,
                    64 << 20,
                )
                .unwrap();
            assert_eq!(commitment, commitments[round]);
            actual.observe(commitment);
            data.push(retained);
        }
        let rounds = data
            .iter()
            .zip(&points)
            .map(|(d, p)| (d, p.clone()))
            .collect::<Vec<_>>();
        let (opened, reduced, height) =
            evaluate_and_reduce::<F>(&session, &mmcs, fri.log_blowup, &rounds, &mut actual)
                .unwrap();
        let FriInputs::Device(reduced) = reduced else {
            panic!("owned PCS must not return host FRI inputs");
        };
        let retained = data.iter().collect::<Vec<_>>();
        let proof = super::super::owned_fri::general::prove(
            &session,
            &mmcs,
            &fri,
            reduced,
            &mut actual,
            height,
            &retained,
        )
        .unwrap();
        transcript_attempt.complete();
        randomness_attempt.complete();
        drop(transcript_observation);
        drop(randomness_observation);
        drop(fri_observation);
        drop(opening_observation);
        assert!(operation.finish(true).unwrap().stage_coverage_complete);

        let mut reference = ReplayPow {
            inner: verifier.clone(),
            witnesses: proof
                .commit_pow_witnesses
                .iter()
                .copied()
                .map(|w| (fri.commit_proof_of_work_bits, w))
                .chain([(fri.query_proof_of_work_bits, proof.query_pow_witness)])
                .collect(),
        };
        let reference_rounds = cpu_data
            .iter()
            .zip(&points)
            .map(|(d, p)| (d, p.clone()))
            .collect();
        let (expected_values, expected) =
            <CpuPcs<F> as Pcs<F, ReplayPow>>::open(&cpu, reference_rounds, &mut reference);
        assert!(reference.witnesses.is_empty());
        assert_eq!(opened, expected_values);
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
        let next_actual: F = actual.sample_algebra_element();
        let next_expected: F = reference.sample_algebra_element();
        assert_eq!(next_actual, next_expected);
        let proof: CpuProof<F> =
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
                        .map(|(domain, (points, values))| {
                            (domain, points.into_iter().zip(values).collect())
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        artifacts.push((cpu, proof, verifier, rounds, case));
    }
    drop(session);
    gpu_hash::shutdown().unwrap();
    for (pcs, proof, verifier, rounds, case) in artifacts {
        <CpuPcs<F> as Pcs<F, Challenger>>::verify(
            &pcs,
            rounds.clone(),
            &proof,
            &mut verifier.clone(),
        )
        .unwrap();
        let mut bad_rounds = rounds.clone();
        bad_rounds[0].1[0].1[0].1[0] += F::ONE;
        assert!(<CpuPcs<F> as Pcs<F, Challenger>>::verify(
            &pcs,
            bad_rounds,
            &proof,
            &mut verifier.clone()
        )
        .is_err());
        let mut bad: CpuProof<F> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        bad.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
        assert!(<CpuPcs<F> as Pcs<F, Challenger>>::verify(
            &pcs,
            rounds.clone(),
            &bad,
            &mut verifier.clone()
        )
        .is_err());
        eprintln!("owned_extension_pcs_cpu_verified degree={} case={case} initial_openings=gpu prefix_upload_bytes=0 prefix_readback_bytes=0 fri_vector_readback_bytes=0", F::DIMENSION);
    }
    assert!(gpu_hash::report("owned_extension_pcs_after_cpu_verification").is_none());
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
fn gpu_quadratic_owned_pcs_matches_upstream_and_cpu_verifies_after_shutdown() {
    run::<crate::config::Challenge>();
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
fn gpu_cubic_owned_pcs_matches_upstream_and_cpu_verifies_after_shutdown() {
    run::<crate::block_v2::profile::Challenge>();
}
