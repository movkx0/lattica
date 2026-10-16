use super::*;
use crate::block_v2::gpu_hash::{
    self,
    device::{Extension, MatrixSpec, RowOrder},
};
use crate::block_v2::opening_pcs::test_support::ReplayPow;
use crate::config::{MyCompress, MyHash, ValMmcs};
use crate::proving::{Backend, Capabilities, CoverageScope, Policy, Profile, Request, Run, Stage};
use p3_challenger::FieldChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{
    batch_multiplicative_inverse, coset::TwoAdicMultiplicativeCoset, Field, TwoAdicField,
};
use p3_fri::{TwoAdicFriFolding, TwoAdicFriFoldingForMmcs};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Serialize};

type CpuMmcs<F> = ExtensionMmcs<Val, F, ValMmcs>;
type CpuProof<F> = FriProof<F, CpuMmcs<F>, Val, Vec<BatchOpening<Val, ValMmcs>>>;

fn params<M>(mmcs: M, queries: usize, arity: usize, final_len: usize) -> FriParameters<M> {
    FriParameters {
        log_blowup: crate::config::LOG_BLOWUP,
        log_final_poly_len: final_len,
        max_log_arity: arity,
        num_queries: queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: crate::config::QUERY_POW_BITS,
        mmcs,
    }
}

fn run<F: FriExtension + Serialize + DeserializeOwned>() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    let queries = if F::DEVICE_EXTENSION == Extension::Quadratic {
        crate::config::NUM_QUERIES
    } else {
        profile::NUM_QUERIES
    };
    let mut artifacts = Vec::new();
    for (log_height, max_arity, final_len) in [
        (10, 1, 0),
        (10, 2, 0),
        (10, 3, 0),
        (10, 4, 0),
        (12, 4, 3),
        (16, 4, 8),
    ] {
        let perm = default_goldilocks_poseidon2_8();
        let input_mmcs = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([37; 32]),
        );
        let base = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([71; 32]),
        );
        let cpu = params(CpuMmcs::<F>::new(base), queries, max_arity, final_len);
        let mmcs = CandidateMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([71; 32]),
        );
        let failure = crate::block_v2::randomness::Failure::default();
        mmcs.activate_private_randomness(&session, &failure)
            .unwrap();
        let gpu = params(
            FriExtensionMmcs::<F>::new(mmcs.clone()),
            queries,
            max_arity,
            final_len,
        );

        // Public CPU fixture setup and input openings are outside the GPU FRI
        // operation. This does not stand in for a legacy STARK/PCS adapter.
        let coefficient_count = 1 << (log_height - cpu.log_blowup);
        let coefficients: Vec<_> = (0..coefficient_count)
            .map(|i| Val::from_u64((i * 19 + 7) as u64))
            .collect();
        let zeta = F::from_basis_coefficients_fn(|i| Val::from_u64((i + 11) as u64));
        let claimed = coefficients
            .iter()
            .rev()
            .fold(F::ZERO, |a, c| a * zeta + F::from(*c));
        let mut padded = coefficients.clone();
        padded.resize(1 << log_height, Val::ZERO);
        let mut scale = Val::ONE;
        for v in &mut padded {
            *v *= scale;
            scale *= Val::GENERATOR;
        }
        let mut values = Radix2DFTSmallBatch::<Val>::default().dft(padded);
        let generator = Val::two_adic_generator(log_height);
        let mut x = Val::GENERATOR;
        let denominators: Vec<_> = (0..values.len())
            .map(|_| {
                let d = F::from(x) - zeta;
                x *= generator;
                d
            })
            .collect();
        let inverses = batch_multiplicative_inverse(&denominators);
        let mut reduced: Vec<F> = values
            .iter()
            .zip(inverses)
            .map(|(v, inv)| (F::from(*v) - claimed) * inv)
            .collect();
        reverse_slice_index_bits(&mut values);
        reverse_slice_index_bits(&mut reduced);
        let (commitment, data) = input_mmcs.commit_matrix(RowMajorMatrix::new(values, 1));
        let mut reference = Challenger::new(perm);
        reference.observe(commitment.clone());
        let verifier = reference.clone();
        let alpha: F = reference.sample_algebra_element();
        let mut actual = Challenger::new_gpu(&session).unwrap();
        actual.observe(commitment.clone());
        assert_eq!(alpha, actual.sample_algebra_element::<F>());
        let folding: TwoAdicFriFoldingForMmcs<Val, ValMmcs> =
            TwoAdicFriFolding(core::marker::PhantomData);
        let input = session
            .upload(
                MatrixSpec::new(
                    log_height as u32,
                    1,
                    F::DEVICE_EXTENSION,
                    RowOrder::BitReversed,
                    1,
                )
                .unwrap(),
                &reduced.iter().copied().flat_map(words).collect::<Vec<_>>(),
            )
            .unwrap();
        let before = session.stats();
        let mut invalid = gpu.clone();
        invalid.max_log_arity = 0;
        assert!(prove(
            &session,
            &mmcs,
            &invalid,
            vec![session.alias_private(&input).unwrap()],
            &mut actual,
            log_height,
            &[],
            64 << 20,
        )
        .is_err());
        let foreign = DeviceSession::new().unwrap();
        // Insufficient combined storage rejects before folds, randomness or
        // transcript work. The subsequent byte-for-byte oracle also checks
        // that rejection did not consume either stream.
        assert!(prove(
            &session,
            &mmcs,
            &gpu,
            vec![session.alias_private(&input).unwrap()],
            &mut actual,
            log_height,
            &[],
            0,
        )
        .is_err());
        assert!(prove(
            &foreign,
            &mmcs,
            &gpu,
            vec![session.alias_private(&input).unwrap()],
            &mut actual,
            log_height,
            &[],
            64 << 20,
        )
        .is_err());
        assert_eq!(before, session.stats());

        let mut stages = vec![
            Stage::Randomness,
            Stage::Commitment,
            Stage::FriFold,
            Stage::FriQuery,
            Stage::FinalPolynomial,
            Stage::Transcript,
            Stage::Grinding,
        ];
        if final_len > 0 {
            stages.push(Stage::Transform);
        }
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
            "gpu_general_fri_core",
            Request {
                policy: Policy::GpuRequired,
                emit_report: true,
            },
            caps,
        )
        .unwrap();
        let guard = failure.begin().unwrap();
        let transcript = actual.begin_attempt().unwrap().unwrap();
        let execution = session.observe_fri(&operation, final_len > 0).unwrap();
        let randomness =
            crate::block_v2::randomness::RandomnessObservation::new(&operation, session.clone())
                .unwrap();
        let transcript_execution = actual.observe_fri(&operation).unwrap().unwrap();
        let proof = prove(
            &session,
            &mmcs,
            &gpu,
            vec![input],
            &mut actual,
            log_height,
            &[],
            64 << 20,
        )
        .unwrap();
        transcript.complete();
        assert_eq!(proof.query_proofs.capacity(), gpu.num_queries);
        assert_eq!(
            proof.commit_phase_commits.capacity(),
            proof.commit_phase_commits.len()
        );
        assert_eq!(
            proof.commit_pow_witnesses.capacity(),
            proof.commit_pow_witnesses.len()
        );
        assert_eq!(proof.final_poly.capacity(), 1 << final_len);
        for query in &proof.query_proofs {
            assert_eq!(
                query.commit_phase_openings.capacity(),
                proof.commit_phase_commits.len()
            );
            for step in &query.commit_phase_openings {
                assert_eq!(step.sibling_values.capacity(), 1 << step.log_arity);
                assert_eq!(
                    step.sibling_values.len() + 1,
                    step.sibling_values.capacity()
                );
            }
        }
        guard.complete();
        drop(transcript_execution);
        drop(randomness);
        drop(execution);
        assert!(operation.finish(true).unwrap().stage_coverage_complete);
        let mut reference = ReplayPow {
            inner: reference,
            witnesses: proof
                .commit_pow_witnesses
                .iter()
                .copied()
                .map(|w| (cpu.commit_proof_of_work_bits, w))
                .chain([(cpu.query_proof_of_work_bits, proof.query_pow_witness)])
                .collect(),
        };
        let expected = p3_fri::prover::prove_fri(
            &folding,
            &cpu,
            vec![reduced],
            &mut reference,
            log_height,
            &[(&data, vec![vec![zeta]])],
            &input_mmcs,
        );
        assert!(reference.witnesses.is_empty());
        let commit_matches: Vec<_> = proof
            .commit_phase_commits
            .iter()
            .zip(&expected.commit_phase_commits)
            .map(|(actual, expected)| actual == expected)
            .collect();
        eprintln!(
            "general_fri_reference degree={} max_log_arity={} log_final_len={} commits={:?} final_poly={} query_pow={}",
            F::DIMENSION,
            max_arity,
            final_len,
            commit_matches,
            proof.final_poly == expected.final_poly,
            proof.query_pow_witness == expected.query_pow_witness,
        );
        let a: F = actual.sample_algebra_element();
        let b: F = reference.sample_algebra_element();
        assert_eq!(a, b);

        let mut proof: CpuProof<F> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        // The GPU component supplies all FRI layers and their queries. Input
        // matrix openings are supplied by this independent CPU fixture.
        for (actual, expected) in proof.query_proofs.iter_mut().zip(&expected.query_proofs) {
            actual.input_proof = expected.input_proof.clone();
        }
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
        let domain =
            TwoAdicMultiplicativeCoset::new(Val::GENERATOR, log_height - cpu.log_blowup).unwrap();
        artifacts.push((
            proof, cpu, verifier, input_mmcs, commitment, domain, zeta, claimed, max_arity,
            final_len,
        ));
    }
    drop(session);
    gpu_hash::shutdown().unwrap();
    for (proof, params, verifier, mmcs, commitment, domain, zeta, claimed, arity, final_len) in
        artifacts
    {
        let folding: TwoAdicFriFoldingForMmcs<Val, ValMmcs> =
            TwoAdicFriFolding(core::marker::PhantomData);
        let rounds = [(commitment, vec![(domain, vec![(zeta, vec![claimed])])])];
        p3_fri::verifier::verify_fri(
            &folding,
            &params,
            &proof,
            &mut verifier.clone(),
            &rounds,
            &mmcs,
        )
        .unwrap();
        let mut bad_rounds = rounds.clone();
        bad_rounds[0].1[0].1[0].1[0] += F::ONE;
        assert!(p3_fri::verifier::verify_fri(
            &folding,
            &params,
            &proof,
            &mut verifier.clone(),
            &bad_rounds,
            &mmcs
        )
        .is_err());
        let mut bad: CpuProof<F> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        bad.final_poly[0] += F::ONE;
        assert!(p3_fri::verifier::verify_fri(
            &folding,
            &params,
            &bad,
            &mut verifier.clone(),
            &rounds,
            &mmcs
        )
        .is_err());
        let mut bad: CpuProof<F> =
            postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
        bad.query_proofs[0].commit_phase_openings[0].sibling_values[0] += F::ONE;
        assert!(p3_fri::verifier::verify_fri(
            &folding,
            &params,
            &bad,
            &mut verifier.clone(),
            &rounds,
            &mmcs
        )
        .is_err());
        eprintln!("general_fri_cpu_verified degree={} max_log_arity={arity} log_final_len={final_len} input_openings=cpu_fixture", F::DIMENSION);
    }
    assert!(gpu_hash::report("general_fri_after_cpu_verification").is_none());
}

#[test]
#[ignore = "requires OpenCL GPU in a <=3 GiB zero-swap service"]
fn gpu_quadratic_fri_matches_upstream_bytes_and_cpu_verifies_after_shutdown() {
    run::<crate::config::Challenge>();
}

#[test]
#[ignore = "requires OpenCL GPU in a <=3 GiB zero-swap service"]
fn gpu_cubic_fri_matches_upstream_bytes_and_cpu_verifies_after_shutdown() {
    run::<crate::block_v2::profile::Challenge>();
}
