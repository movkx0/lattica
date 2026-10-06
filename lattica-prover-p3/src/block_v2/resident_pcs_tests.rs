//! Exact CPU-oracle checks for the research hiding-PCS integration. All seeds
//! below are deterministic test fixtures, never production proving interfaces.
use super::{CandidateMmcs, Limits, ProverData, engine};
use crate::block_v2::{profile, quotient_pcs::CandidatePcs};
use crate::config::{Challenger, MyCompress, MyHash, Val, ValMmcs};
use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs, Pcs, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::HidingFriPcs;
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

type Domain = TwoAdicMultiplicativeCoset<Val>;
type Challenge = profile::Challenge;
type CpuExtensionMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type CpuPcs = HidingFriPcs<Val, crate::config::Dft, ValMmcs, CpuExtensionMmcs, ChaCha20Rng>;
type CpuData = <ValMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
type Commitment = <ValMmcs as Mmcs<Val>>::Commitment;

fn mmcs(gpu: bool) -> CandidateMmcs {
    let perm = default_goldilocks_poseidon2_8();
    let mut mmcs = CandidateMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm),
        profile::CAP_HEIGHT,
        ChaCha20Rng::from_seed([41; 32]),
    );
    // Explicit test selection, independent of process-global library defaults.
    mmcs.gpu = gpu;
    mmcs
}

fn reference() -> (CpuPcs, ValMmcs) {
    let mmcs = (*mmcs(false).cpu).clone();
    let pcs = CpuPcs::new(
        crate::config::Dft::default(),
        mmcs.clone(),
        profile::fri(CpuExtensionMmcs::new(mmcs.clone())),
        profile::NUM_RANDOM_CODEWORDS,
        ChaCha20Rng::from_seed([43; 32]),
    );
    (pcs, mmcs)
}

fn candidate(fusion: bool) -> (CandidatePcs, CandidateMmcs) {
    let mmcs = mmcs(true);
    let pcs = CandidatePcs::new_resident(
        Default::default(),
        mmcs.clone(),
        profile::fri(profile::ChallengeMmcs::new(mmcs.clone())),
        profile::NUM_RANDOM_CODEWORDS,
        ChaCha20Rng::from_seed([43; 32]),
        64 << 20,
    )
    .unwrap();
    let pcs = if fusion {
        pcs.with_fused_quotients(ChaCha20Rng::from_seed([47; 32]))
    } else {
        pcs
    };
    (pcs, mmcs)
}

fn initialize() {
    assert_eq!(
        std::env::var("LATTICA_V2_GPU_RETAIN_TREES").as_deref(),
        Ok("1")
    );
    engine::initialize_mode(
        Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 1 << 20,
            staging_bytes: 64 << 10,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
}

fn matrix(height: usize, width: usize, offset: usize) -> RowMajorMatrix<Val> {
    RowMajorMatrix::new(
        (0..height * width)
            .map(|i| Val::from_usize(i + offset))
            .collect(),
        width,
    )
}

#[path = "quotient_pipeline_tests.rs"]
mod quotient_pipeline_tests;

fn compare(
    cpu: &ValMmcs,
    gpu: &CandidateMmcs,
    expected: (Commitment, CpuData),
    actual: (Commitment, ProverData<RowMajorMatrix<Val>>),
) {
    assert_eq!(expected.0, actual.0);
    assert!(matches!(actual.1, ProverData::GpuRetained { .. }));
    let a = cpu.get_matrices(&expected.1);
    let b = gpu.get_matrices(&actual.1);
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(&b) {
        assert_eq!(a.dimensions(), b.dimensions());
        assert_eq!(a.values, b.values);
    }
    let dims: Vec<_> = a.iter().map(|m| m.dimensions()).collect();
    for index in [0, a[0].height() / 2, a[0].height() - 1] {
        let a = cpu.open_batch(index, &expected.1);
        let b = gpu.open_batch(index, &actual.1);
        assert_eq!(a.opened_values, b.opened_values);
        assert_eq!(a.opening_proof, b.opening_proof);
        cpu.verify_batch(
            &actual.0,
            &dims,
            index,
            BatchOpeningRef::new(&b.opened_values, &b.opening_proof),
        )
        .unwrap();
    }
}

#[test]
fn resident_constructor_rejects_unavailable_backend_and_changed_parameters() {
    let cpu_mmcs = mmcs(false);
    assert!(
        CandidatePcs::new_resident(
            Default::default(),
            cpu_mmcs.clone(),
            profile::fri(profile::ChallengeMmcs::new(cpu_mmcs.clone())),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([43; 32]),
            64 << 20,
        )
        .is_err()
    );
    for which in 0..9 {
        let mut fri = profile::fri(profile::ChallengeMmcs::new(cpu_mmcs.clone()));
        let mut columns = profile::NUM_RANDOM_CODEWORDS;
        let mut budget = 64 << 20;
        match which {
            0 => fri.log_blowup -= 1,
            1 => fri.log_final_poly_len = 1,
            2 => fri.max_log_arity = 2,
            3 => fri.num_queries -= 1,
            4 => fri.commit_proof_of_work_bits = 1,
            5 => fri.query_proof_of_work_bits -= 1,
            6 => columns -= 1,
            7 => budget = 0,
            _ => budget = (32 << 30) + 1,
        }
        let error = CandidatePcs::new_resident(
            Default::default(),
            cpu_mmcs.clone(),
            fri,
            columns,
            ChaCha20Rng::from_seed([43; 32]),
            budget,
        )
        .err()
        .expect("unsupported parameters must fail before GPU access");
        assert!(error.contains("unchanged candidate parameters"), "{error}");
    }
}

#[test]
#[ignore = "requires an OpenCL GPU, retained trees, and a serial <=3 GiB service"]
fn gpu_resident_matches_all_cpu_commitment_streams_across_active_clones() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let (cpu, cpu_mmcs) = reference();
    let (gpu, gpu_mmcs) = candidate(false);
    // Clone BEFORE any draws. A deep clone would incorrectly replay the first
    // hiding/salt draws when the interleaved operations below use this handle.
    let clone = gpu.clone();
    for round in 0..2 {
        let height: usize = 8 << round;
        let domain = Domain::new(Val::from_u64(7), (height * 2).ilog2() as usize).unwrap();
        let inputs = vec![
            (domain, matrix(height, 3, 5)),
            (domain, matrix(height, 11, 17)),
        ];
        let expected =
            <CpuPcs as Pcs<Challenge, Challenger>>::commit_preprocessing(&cpu, inputs.clone());
        let actual = clone.commit_preprocessing(inputs.clone());
        for idx in 0..2 {
            let a = <CpuPcs as Pcs<Challenge, Challenger>>::get_evaluations_on_domain_no_random(
                &cpu,
                &expected.1,
                idx,
                domain,
            );
            let b = gpu.get_evaluations_on_domain_no_random(&actual.1, idx, domain);
            assert_eq!(a.to_row_major_matrix(), b.to_row_major_matrix());
        }
        compare(&cpu_mmcs, &gpu_mmcs, expected, actual);

        let expected = <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, inputs.clone());
        let actual = gpu.commit(inputs);
        for idx in 0..2 {
            let a = <CpuPcs as Pcs<Challenge, Challenger>>::get_evaluations_on_domain(
                &cpu,
                &expected.1,
                idx,
                domain,
            );
            let b = clone.get_evaluations_on_domain(&actual.1, idx, domain);
            assert_eq!(a.to_row_major_matrix(), b.to_row_major_matrix());
        }
        compare(&cpu_mmcs, &gpu_mmcs, expected, actual);

        let quotient_domain = Domain::new(Val::GENERATOR, (height * 4).ilog2() as usize).unwrap();
        let quotient_inputs: Vec<_> = quotient_domain
            .split_domains(4)
            .into_iter()
            .zip(quotient_domain.split_evals(4, matrix(height * 4, 3, 19)))
            .collect();
        let expected = <CpuPcs as Pcs<Challenge, Challenger>>::get_quotient_ldes(
            &cpu,
            quotient_inputs.clone(),
            4,
        );
        let actual = clone.get_quotient_ldes(quotient_inputs, 4);
        assert_eq!(
            expected, actual,
            "upstream masks must follow resident hiding draws"
        );
        compare(
            &cpu_mmcs,
            &gpu_mmcs,
            <CpuPcs as Pcs<Challenge, Challenger>>::commit_ldes(&cpu, expected),
            gpu.commit_ldes(actual),
        );

        compare(
            &cpu_mmcs,
            &gpu_mmcs,
            <CpuPcs as Pcs<Challenge, Challenger>>::get_opt_randomization_poly_commitment(
                &cpu,
                [domain, domain],
            )
            .unwrap(),
            clone
                .get_opt_randomization_poly_commitment([domain, domain])
                .unwrap(),
        );
    }
    let stats = super::report("resident PCS commitment equivalence").unwrap();
    assert_eq!(stats.upload_device_ns > 0, engine::test_device_transfers());
    assert_eq!(
        stats.download_device_ns > 0,
        engine::test_device_transfers()
    );
    assert!(stats.upload_wall_ns > 0 && stats.download_wall_ns > 0);
}

#[test]
#[ignore = "requires an OpenCL GPU, retained trees, and a serial <=3 GiB service"]
fn gpu_resident_admission_errors_do_not_consume_masks_or_salts() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let (cpu, cpu_mmcs) = reference();
    let mmcs = mmcs(true);
    let state = crate::block_v2::resident_pcs::ResidentState::new(
        Default::default(),
        mmcs.clone(),
        profile::fri(profile::ChallengeMmcs::new(mmcs.clone())),
        profile::NUM_RANDOM_CODEWORDS,
        ChaCha20Rng::from_seed([43; 32]),
        64 << 20,
    )
    .unwrap();
    let domain = Domain::new(Val::ONE, 4).unwrap();
    let taller = Domain::new(Val::ONE, 5).unwrap();
    assert!(state.commit([], false).is_err());
    assert!(state.commit([(domain, matrix(4, 3, 2))], false).is_err());
    let mut malformed = matrix(8, 3, 2);
    malformed.width = 0;
    assert!(state.commit([(domain, malformed)], false).is_err());
    // These shapes individually match the hiding convention but cannot share
    // the equal-output-height GPU MMCS. Admission must precede all RNG draws.
    assert!(
        state
            .commit(
                [(domain, matrix(8, 3, 2)), (taller, matrix(16, 3, 2)),],
                false
            )
            .is_err()
    );
    assert!(state.randomization([domain, taller]).is_err());
    let input = [(domain, matrix(8, 3, 2))];
    compare(
        &cpu_mmcs,
        &mmcs,
        <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, input.clone()),
        state.commit(input, false).unwrap(),
    );
}

#[test]
#[ignore = "requires an OpenCL GPU and an isolated child in a serial <=3 GiB service"]
fn gpu_resident_research_switch_only_selects_explicit_proving_configs() {
    use p3_uni_stark::StarkGenericConfig;
    const CHILD: &str = "LATTICA_TEST_RESIDENT_SELECTION_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        // Global one-shot selection and environment mutation belong in a fresh
        // process, never in the same process as other hardware tests.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact",
                "block_v2::gpu_hash::resident_pcs_tests::gpu_resident_research_switch_only_selects_explicit_proving_configs",
                "--test-threads=1", "--nocapture"])
            .env(CHILD, "1").env("LATTICA_V2_GPU_HASH", "1")
            .env("LATTICA_V2_GPU_PIPELINE", "0")
            .env("LATTICA_V2_GPU_RESIDENT_LDE", "1")
            .env("LATTICA_V2_GPU_RETAIN_TREES", "0")
            .status().unwrap();
        assert!(status.success());
        return;
    }
    let _shutdown = engine::TestShutdownGuard;
    assert!(
        !profile::make_proving_config()
            .pcs()
            .uses_resident_commitments(),
        "an environment variable alone must not select the backend"
    );
    assert!(
        super::initialize_resident_from_env().is_err(),
        "GPU hashing is not initialized"
    );
    super::initialize_from_env().unwrap();
    assert!(
        super::initialize_resident_from_env().is_err(),
        "retained trees are required"
    );
    super::shutdown().unwrap();
    std::env::set_var("LATTICA_V2_GPU_RETAIN_TREES", "1");
    super::initialize_from_env().unwrap();
    assert!(super::initialize_resident_from_env().unwrap());
    assert!(super::initialize_resident_from_env().unwrap());
    assert!(
        profile::make_proving_config()
            .pcs()
            .uses_resident_commitments()
    );
    assert!(
        profile::preprocessing_config()
            .pcs()
            .uses_resident_commitments()
    );
    assert!(
        !profile::make_config().pcs().uses_resident_commitments(),
        "wallet/default/verification configuration must not select resident commitments"
    );
    std::env::set_var("LATTICA_V2_GPU_RESIDENT_LDE", "true");
    assert!(super::initialize_resident_from_env().is_err());
    std::env::set_var("LATTICA_V2_GPU_RESIDENT_LDE", "0");
    assert!(
        super::initialize_resident_from_env().is_err(),
        "mode is immutable once selected"
    );
}

struct RecurrenceAir;
impl p3_air::BaseAir<Val> for RecurrenceAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
}
impl<AB: p3_air::AirBuilder<F = Val>> p3_air::Air<AB> for RecurrenceAir {
    fn eval(&self, builder: &mut AB) {
        use p3_air::{AirBuilder, WindowAccess};
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values();
        let (first, second, last) = (public[0], public[1], public[2]);
        builder.when_first_row().assert_eq(local[0], first);
        builder.when_first_row().assert_eq(local[1], second);
        builder.when_transition().assert_eq(next[0], local[1]);
        builder
            .when_transition()
            .assert_eq(next[1], local[0] + local[1]);
        builder.when_last_row().assert_eq(local[0], last);
    }
}

#[test]
#[ignore = "requires an OpenCL GPU, retained trees, and a serial <=3 GiB service"]
fn gpu_resident_full_strength_cubic_proofs_replay_through_original_cpu_pcs() {
    full_strength_cubic_proofs(false);
}

#[test]
#[ignore = "requires an OpenCL GPU, retained trees, and a serial <=3 GiB service"]
fn gpu_openings_full_strength_cubic_proofs_replay_through_original_cpu_pcs() {
    full_strength_cubic_proofs(true);
}

#[test]
#[ignore = "requires an OpenCL GPU, retained trees, and a serial <=3 GiB service"]
fn gpu_openings_match_reference_transcript_and_preprocessing() {
    opening_transcript_equivalence(false);
}
fn opening_transcript_equivalence(compact: bool) {
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::BasedVectorSpace;
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let (used, _) = candidate(false);
    used.natural_domain_for_degree(128);
    assert!(
        used.with_gpu_openings().is_err(),
        "mode must be selected before use"
    );
    let (shared, _) = candidate(false);
    let live_clone = shared.clone();
    assert!(
        shared.with_gpu_openings().is_err(),
        "mode must be selected before sharing"
    );
    drop(live_clone);
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(|| {
            for preprocessing in [false, true] {
                let (reference, _) = candidate(false);
                let (accelerated, _) = candidate(false);
                let accelerated = accelerated.with_gpu_openings().unwrap();
                let domains = [
                    reference.natural_domain_for_degree(256),
                    reference.natural_domain_for_degree(128),
                ];
                let a = matrix(128, 5, 19);
                let b = matrix(64, 7, 29);
                let commit_first = |pcs: &CandidatePcs| {
                    if preprocessing {
                        pcs.commit_preprocessing([(domains[0], a.clone())])
                    } else {
                        pcs.commit([(domains[0], a.clone())])
                    }
                };
                let (ra_cap, ra) = commit_first(&reference);
                let (ga_cap, ga) = commit_first(&accelerated);
                let (rb_cap, rb) = reference.commit([(domains[1], b.clone())]);
                let (gb_cap, gb) = accelerated.commit([(domains[1], b.clone())]);
                assert_eq!(ra_cap, ga_cap);
                assert_eq!(rb_cap, gb_cap);
                let ga = if compact {
                    compact_test_data(ga, 1)
                } else {
                    ga
                };
                let gb = if compact {
                    compact_test_data(gb, profile::LOG_BLOWUP)
                } else {
                    gb
                };
                let mut rc = Challenger::new(default_goldilocks_poseidon2_8());
                let mut gc = Challenger::new(default_goldilocks_poseidon2_8());
                for challenger in [&mut rc, &mut gc] {
                    challenger.observe(ra_cap.clone());
                    challenger.observe(rb_cap.clone());
                }
                let point = Challenge::from_basis_coefficients_slice(&[
                    Val::from_u64(7),
                    Val::from_u64(11),
                    Val::from_u64(13),
                ])
                .unwrap();
                let points = vec![point, point + Val::ONE];
                let expected = reference.open_with_preprocessing(
                    vec![(&ra, vec![points.clone()]), (&rb, vec![vec![point]])],
                    &mut rc,
                    preprocessing,
                );
                let actual = accelerated.open_with_preprocessing(
                    vec![(&ga, vec![points.clone()]), (&gb, vec![vec![point]])],
                    &mut gc,
                    preprocessing,
                );
                assert_eq!(actual.0, expected.0);
                assert_eq!(
                    postcard::to_allocvec(&actual.1).unwrap(),
                    postcard::to_allocvec(&expected.1).unwrap()
                );
                let next_reference: Challenge = rc.sample_algebra_element();
                let next_accelerated: Challenge = gc.sample_algebra_element();
                assert_eq!(next_reference, next_accelerated);
            }
        });
    let stats = super::report("GPU opening exact transcript").unwrap();
    assert_eq!(stats.opening_calls, 2);
}

fn full_strength_cubic_proofs(gpu_openings: bool) {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    type CpuConfig = p3_uni_stark::StarkConfig<CpuPcs, Challenge, Challenger>;
    let (cpu, _) = reference();
    let cpu = CpuConfig::new(cpu, Challenger::new(default_goldilocks_poseidon2_8()));
    let (mut a, mut b) = (Val::from_u64(3), Val::from_u64(5));
    let mut values = Vec::with_capacity(256);
    for _ in 0..128 {
        values.extend([a, b]);
        (a, b) = (b, a + b);
    }
    let public = [values[0], values[1], values[values.len() - 2]];
    let trace = RowMajorMatrix::new(values, 2);
    for fusion in [false, true] {
        let (pcs, _) = candidate(fusion);
        let pcs = if gpu_openings {
            pcs.with_gpu_openings().unwrap()
        } else {
            pcs
        };
        let original = profile::Config::new(
            pcs.clone(),
            Challenger::new(default_goldilocks_poseidon2_8()),
        );
        let cloned = profile::Config::new(pcs, Challenger::new(default_goldilocks_poseidon2_8()));
        let mut commitments = Vec::new();
        for config in [&original, &cloned] {
            let proof = p3_uni_stark::prove(config, &RecurrenceAir, trace.clone(), &public);
            commitments.push(postcard::to_allocvec(&proof.commitments).unwrap());
            let bytes = postcard::to_allocvec(&proof).unwrap();
            let decoded: p3_uni_stark::Proof<CpuConfig> = postcard::from_bytes(&bytes).unwrap();
            p3_uni_stark::verify(&cpu, &RecurrenceAir, &decoded, &public).unwrap();
            let mut wrong = public;
            wrong[2] += Val::ONE;
            assert!(p3_uni_stark::verify(&cpu, &RecurrenceAir, &decoded, &wrong).is_err());
        }
        assert_ne!(
            commitments[0], commitments[1],
            "cloned attempt must not replay randomness"
        );
    }
    super::report("resident PCS full-strength cubic proofs").unwrap();
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded service"]
fn gpu_compact_prefix_readback_reconstructs_original_rows_salts_and_paths() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    for (height, width) in [(2usize, 1usize), (32, 7), (256, 35), (4096, 257)] {
        for bits in [1, profile::LOG_BLOWUP] {
            let full = mmcs(true);
            let compact = mmcs(true);
            let domain = Domain::new(Val::from_u64(7), height.ilog2() as usize).unwrap();
            let input = matrix(height, width, 19);
            let (a, ad) = full
                .commit_resident_retained(
                    vec![(domain, input.clone())],
                    profile::LOG_BLOWUP,
                    1 << 30,
                    None,
                    0,
                )
                .unwrap();
            let (b, bd) = compact
                .commit_resident_retained(
                    vec![(domain, input)],
                    profile::LOG_BLOWUP,
                    1 << 30,
                    None,
                    bits,
                )
                .unwrap();
            assert_eq!(a, b);
            assert_eq!(
                compact.get_matrix_heights(&bd),
                full.get_matrix_heights(&ad)
            );
            let logical = height << profile::LOG_BLOWUP;
            assert_eq!(compact.prefix_matrices(&bd)[0].0.height(), logical >> bits);
            let indices = [0, logical - 1, logical / 3, logical / 2, logical / 3];
            let before = engine::report("compact query oracle before").unwrap();
            compact.prepare_queries(&bd, &indices).unwrap();
            let after = engine::report("compact query oracle after").unwrap();
            let tiles = after.query_reconstruction_tiles - before.query_reconstruction_tiles;
            let readbacks = after.query_readbacks - before.query_readbacks;
            assert!(tiles > 0);
            if std::env::var("LATTICA_V2_GPU_QUERY_GATHER").as_deref() == Ok("1") {
                assert_eq!(readbacks, tiles, "one download per reconstructed tile");
            } else {
                assert!(
                    readbacks > tiles,
                    "control downloads query rows individually"
                );
            }
            for index in indices {
                let x = full.open_batch(index, &ad);
                let y = compact.open_batch(index, &bd);
                assert_eq!(x.opened_values, y.opened_values);
                assert_eq!(x.opening_proof, y.opening_proof);
            }
        }
    }
}

fn compact_test_data(
    data: ProverData<RowMajorMatrix<Val>>,
    bits: usize,
) -> ProverData<RowMajorMatrix<Val>> {
    let ProverData::GpuRetained {
        mut matrices,
        salts,
        tree,
    } = data
    else {
        panic!("retained test data")
    };
    let height = matrices[0].height();
    for matrix in &mut matrices {
        matrix.values.truncate((height >> bits) * matrix.width);
        matrix.values.shrink_to_fit();
    }
    ProverData::Compact(super::compact_data::CompactData::new(
        matrices, height, salts, tree,
    ))
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded service"]
fn gpu_compact_prover_data_preserves_fixed_seed_proof_bytes_and_challenger() {
    opening_transcript_equivalence(true);
}
