use super::*;
use crate::block_v2::{gpu_quotient_prover, machine, quotient_pcs};
use p3_air::BaseAir;
use p3_batch_stark::{prove_batch, verify_batch, ProverData as BatchData, StarkInstance};
use p3_field::PrimeField64;
use p3_uni_stark::StarkGenericConfig;

#[path = "multi_air_pipeline_tests.rs"]
mod multi_air;

const COMPILER_HOST_BUDGET: usize = (64 << 20)
    + crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES as usize
    + crate::block_v2::machine::symbolic::HOST_BYTES as usize
    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES as usize
    + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES as usize;

fn cpu_config() -> profile::Config {
    let base = mmcs(false);
    profile::Config::new(
        CandidatePcs::new(
            Default::default(),
            base.clone(),
            profile::fri(profile::ChallengeMmcs::new(base)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([43; 32]),
        )
        .with_fused_quotients(ChaCha20Rng::from_seed([47; 32])),
        Challenger::new(default_goldilocks_poseidon2_8()),
    )
}

fn all_operations() -> machine::MachineAir {
    let mut b = machine::ProgramBuilder::new(33).unwrap();
    let x = b.input();
    let square = b.mul(x, x);
    let public = b.public(0).unwrap();
    b.assert_equal(square, public);
    let one = b.constant(Val::ONE);
    let zero = b.constant(Val::ZERO);
    let inverse = b.inverse(x);
    let identity = b.mul(x, inverse);
    b.assert_equal(identity, one);
    let high = b.bit_hint(inverse, 63);
    let low = b.bit_hint(x, 0);
    b.assert_bool(high);
    b.assert_bool(low);
    let selected = b.select(low, square, inverse);
    let hinted = b.select_hint(vec![x, selected, square, inverse], &[low, high]);
    let sum = b.add(hinted, selected);
    let product = b.cubic_mul([x, one, zero], [sum, zero, one]);
    let inverse = b.cubic_inverse(product);
    let identity = b.cubic_mul(product, inverse);
    b.assert_equal(identity[0], one);
    b.assert_equal(identity[1], zero);
    b.assert_equal(identity[2], zero);
    let hash = b.poseidon([x, sum, one, zero, selected, hinted, square, public]);
    let hash = b.poseidon(hash);
    let _ = b.add(hash[0], public);
    machine::MachineAir::new(b.finish(None).unwrap())
}

#[test]
#[ignore = "requires OpenCL GPU, owned lookup/opening/FRI and <=3 GiB zero-swap service"]
fn device_witness_key_and_all_opcode_proofs_reuse_public_state_across_fresh_sessions() {
    device_witness_public_state_proofs(false, false, false);
}

fn public_setup(gpu: bool) -> profile::Config {
    let perm = default_goldilocks_poseidon2_8();
    let mut mmcs = CandidateMmcs::new_public_preprocessing(
        MyHash::new(perm.clone()),
        MyCompress::new(perm.clone()),
        profile::CAP_HEIGHT,
    );
    mmcs.gpu = gpu;
    let fri = profile::fri(profile::ChallengeMmcs::new(mmcs.clone()));
    let pcs = if gpu {
        CandidatePcs::new_resident(
            Default::default(),
            mmcs,
            fri,
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([0; 32]),
            64 << 20,
        )
        .unwrap()
        .with_gpu_openings()
        .unwrap()
        .with_gpu_preprocessing_salts()
        .unwrap()
    } else {
        CandidatePcs::new(
            Default::default(),
            mmcs,
            fri,
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([0; 32]),
        )
    };
    profile::Config::new(pcs, Challenger::new(perm))
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_public_salts_preserve_keys_and_complete_proofs_across_fresh_sessions() {
    device_witness_public_state_proofs(true, false, false);
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_public_salt_selection_and_admission_preserve_reference_draws() {
    use crate::block_v2::gpu_hash::device::{
        DeviceSession, Extension, MatrixSpec, RowOrder, TraceCommitShape,
    };
    use machine::gpu_program::WitnessProgram;
    quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let make = |public| {
        let perm = default_goldilocks_poseidon2_8();
        let mut mmcs = if public {
            CandidateMmcs::new_public_preprocessing(
                MyHash::new(perm.clone()),
                MyCompress::new(perm),
                profile::CAP_HEIGHT,
            )
        } else {
            CandidateMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm),
                profile::CAP_HEIGHT,
                ChaCha20Rng::from_seed([0; 32]),
            )
        };
        mmcs.gpu = true;
        CandidatePcs::new_resident(
            Default::default(),
            mmcs.clone(),
            profile::fri(profile::ChallengeMmcs::new(mmcs)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([0; 32]),
            64 << 20,
        )
        .unwrap()
        .with_gpu_openings()
        .unwrap()
    };
    let before = engine::report("public salt selection rejection before").unwrap();
    assert!(make(false).with_gpu_preprocessing_salts().is_err());
    let original = make(true);
    assert!(original.clone().with_gpu_preprocessing_salts().is_err());
    drop(original);
    let started = make(true);
    assert!(started.commit_preprocessing_device(vec![]).is_err());
    assert!(started.with_gpu_preprocessing_salts().is_err());
    let after = engine::report("public salt selection rejection after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);

    let gpu = make(true).with_gpu_preprocessing_salts().unwrap();
    let session = gpu.quotient_session().unwrap();
    let air = all_operations();
    let witness = session
        .prepare_witness(std::sync::Arc::new(
            WitnessProgram::compile(air.program(), 64 << 20).unwrap(),
        ))
        .unwrap();
    let height = air.program().height();
    let domain = Domain::new(Val::ONE, height.ilog2() as usize + 1).unwrap();
    let before = session.stats();
    assert!(gpu
        .commit_main_device(Vec::<(crate::block_v2::gpu_hash::device::DomainSpec, _)>::new())
        .is_err());
    assert!(gpu.commit_preprocessing_device(vec![]).is_err());
    let trace = witness.preprocessing_trace(&session).unwrap();
    let before_domain = session.stats();
    assert!(gpu
        .commit_preprocessing_device(vec![(
            Domain::new(Val::from_u64(7), domain.log_size())
                .unwrap()
                .into(),
            trace
        )])
        .is_err());
    assert_eq!(session.stats().random_calls, before.random_calls);
    assert_eq!(session.stats().random_fields, before.random_fields);
    assert_eq!(session.stats().uploaded_bytes, before_domain.uploaded_bytes);
    let mut gpu_mmcs = mmcs(true);
    gpu_mmcs.device_only = true;
    let excessive = TraceCommitShape::preprocessing(
        MatrixSpec::new(20, 64, Extension::Base, RowOrder::Natural, 1).unwrap(),
    )
    .unwrap();
    let stats = engine::report("public salt memory rejection before").unwrap();
    assert!(gpu_mmcs
        .preflight_public_preprocessing_salts(&[excessive], 64 << 20)
        .is_err());
    assert_eq!(
        engine::report("public salt memory rejection after")
            .unwrap()
            .allocations,
        stats.allocations
    );

    let cpu = public_setup(false);
    let shared = gpu.clone();
    let mut caps = Vec::new();
    for pcs in [&gpu, &shared] {
        let trace = witness.preprocessing_trace(&session).unwrap();
        let (cap, data) = pcs
            .commit_preprocessing_device(vec![(domain.into(), trace)])
            .unwrap();
        let expected = BatchData::from_airs_and_degrees(
            &cpu,
            core::slice::from_ref(&air),
            &[domain.log_size()],
        );
        assert_eq!(
            cap,
            expected.common.preprocessed.as_ref().unwrap().commitment
        );
        assert!(matches!(
            data,
            ProverData::DeviceOnly {
                salts: super::super::SaltStore::PublicDevice(_),
                ..
            }
        ));
        let fresh = DeviceSession::new().unwrap();
        let indices = [0, (domain.size() << profile::LOG_BLOWUP) - 1, 3, 3];
        let queries = gpu_mmcs
            .open_owned_queries(&fresh, &data, &indices, 64 << 20)
            .unwrap();
        let cpu_data = expected
            .prover_only
            .preprocessed_prover_data
            .as_ref()
            .unwrap();
        for (&index, query) in indices.iter().zip(queries) {
            assert_eq!(
                postcard::to_allocvec(&mmcs(false).open_batch(index, cpu_data)).unwrap(),
                postcard::to_allocvec(&query).unwrap()
            );
        }
        caps.push(cap);
    }
    assert_ne!(
        caps[0], caps[1],
        "active PCS clones must advance public salt draws"
    );
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_randomness_complete_proofs_match_cpu_and_reuse_public_salts() {
    device_witness_public_state_proofs(true, true, false);
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_transcript_complete_proofs_match_cpu_and_reuse_public_salts() {
    device_witness_public_state_proofs(true, true, true);
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_randomness_aborted_proof_retires_active_clones_after_main_draws() {
    aborted_private_proof(false);
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_transcript_aborted_proof_retires_transcript_and_randomness_clones() {
    aborted_private_proof(true);
}

#[test]
#[ignore = "requires OpenCL GPU, device-only PCS and a <=3 GiB zero-swap service"]
fn gpu_transcript_selection_rejects_foreign_sessions_before_private_draws() {
    quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let air = all_operations();
    let setup = public_setup(true);
    let setup_run = crate::proving::Run::new(
        "gpu_witness_test_setup",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let prepared =
        machine::gpu_backend::prepare(&air, &setup, COMPILER_HOST_BUDGET, &setup_run).unwrap();
    setup_run.finish(true).unwrap();
    assert!(setup.pcs().gpu_challenger().is_err());
    assert!(cpu_config().pcs().gpu_challenger().is_err());
    let plain = candidate(true).0.with_gpu_openings().unwrap();
    let plain_session = plain.quotient_session().unwrap();
    let before = plain_session.stats();
    assert!(plain.gpu_challenger().is_err());
    assert_eq!(plain_session.stats(), before);
    drop((plain_session, plain, setup));

    let source = candidate(true)
        .0
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .unwrap();
    let challenger = source.gpu_challenger().unwrap();
    let retired = challenger.clone();
    let source_session = source.quotient_session().unwrap();
    let pcs = candidate(true)
        .0
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .unwrap();
    let session = pcs.quotient_session().unwrap();
    let config = profile::Config::new(pcs, challenger);
    let mut public_words: Vec<_> = (0..33).map(|i| 3 + i).collect();
    public_words[0] = 9;
    let public: Vec<_> = public_words.iter().copied().map(Val::from_u64).collect();
    let trace = prepared
        .witness
        .trace(&session, &public_words, &[3], 64 << 20)
        .unwrap();
    let before = session.stats();
    let source_before = source_session.stats();
    let run = crate::proving::Run::new(
        "foreign_gpu_transcript_test",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gpu_quotient_prover::prove_batch(
            &config,
            vec![gpu_quotient_prover::ProvingInstance::from_device(
                &air, trace, &public,
            )],
            &prepared.data,
            CandidateMmcs::release_quotient_prefix,
            |_, _| panic!("no host quotient callback"),
            &run,
        )
    }))
    .err()
    .expect("foreign transcript must fail before private draws");
    run.finish(false).unwrap();
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("session mismatch"), "{message}");
    assert_eq!(session.stats().random_calls, before.random_calls);
    assert_eq!(session.stats().random_fields, before.random_fields);
    assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(session.stats().downloaded_bytes, before.downloaded_bytes);
    assert_eq!(
        source_session.stats().transcript_observations,
        source_before.transcript_observations
    );
    assert_eq!(
        source_session.stats().transcript_samples,
        source_before.transcript_samples
    );
    assert!(config.pcs().begin_randomness_attempt().is_err());
    assert!(retired.begin_attempt().is_err());

    // A failed initial transcript snapshot must retire the fresh random group
    // even though the prover has not obtained its transcript guard yet.
    let pcs = candidate(true)
        .0
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .unwrap();
    let session = pcs.quotient_session().unwrap();
    let challenger = pcs.gpu_challenger().unwrap();
    drop(challenger.begin_attempt().unwrap().unwrap());
    let config = profile::Config::new(pcs, challenger);
    let trace = prepared
        .witness
        .trace(&session, &public_words, &[3], 64 << 20)
        .unwrap();
    let before = session.stats();
    let run = crate::proving::Run::new(
        "retired_gpu_transcript_test",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gpu_quotient_prover::prove_batch(
            &config,
            vec![gpu_quotient_prover::ProvingInstance::from_device(
                &air, trace, &public,
            )],
            &prepared.data,
            CandidateMmcs::release_quotient_prefix,
            |_, _| panic!("no host quotient callback"),
            &run,
        )
    }))
    .err()
    .expect("retired transcript must fail before private draws");
    run.finish(false).unwrap();
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("GPU transcript failed"), "{message}");
    assert_eq!(session.stats(), before);
    assert!(config.pcs().begin_randomness_attempt().is_err());
}

fn aborted_private_proof(gpu_transcript: bool) {
    quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let air = all_operations();
    let setup = public_setup(true);
    let setup_run = crate::proving::Run::new(
        "gpu_witness_test_setup",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let mut prepared =
        machine::gpu_backend::prepare(&air, &setup, COMPILER_HOST_BUDGET, &setup_run).unwrap();
    setup_run.finish(true).unwrap();
    drop(setup);
    // Keep valid public metadata, but remove its backing prover data. Lookup
    // execution will reject this only after the main commitment has drawn its
    // hiding samples and salts, outside that commitment's completed guard.
    drop(
        prepared
            .data
            .prover_only
            .preprocessed_prover_data
            .take()
            .unwrap(),
    );
    let pcs = candidate(true)
        .0
        .with_gpu_openings()
        .unwrap()
        .with_gpu_randomness()
        .unwrap();
    let challenger = if gpu_transcript {
        pcs.gpu_challenger().unwrap()
    } else {
        Challenger::new(default_goldilocks_poseidon2_8())
    };
    let transcript_clone = challenger.clone();
    let config = profile::Config::new(pcs, challenger);
    let shared = config.pcs().clone();
    let session = config.pcs().quotient_session().unwrap();
    let mut public_words: Vec<u64> = (0..33).map(|i| 3 + i).collect();
    public_words[0] = 9;
    let public: Vec<_> = public_words.iter().copied().map(Val::from_u64).collect();
    let trace = prepared
        .witness
        .trace(&session, &public_words, &[3], 64 << 20)
        .unwrap();
    let retry = session.alias_private(&trace).unwrap();
    let domain = Domain::new(Val::ONE, air.program().height().ilog2() as usize + 1).unwrap();
    let before = session.stats();
    let run = crate::proving::Run::new(
        "device_randomness_aborted_proof_test",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pool.install(|| {
            gpu_quotient_prover::prove_batch(
                &config,
                vec![gpu_quotient_prover::ProvingInstance::from_device(
                    &air, trace, &public,
                )],
                &prepared.data,
                CandidateMmcs::release_quotient_prefix,
                |_, _| panic!("device quotient must not enter the host callback"),
                &run,
            )
        })
    }));
    let report = run.finish(false).unwrap();
    let observed = report
        .observations
        .iter()
        .find(|o| o.stage == crate::proving::Stage::Randomness)
        .unwrap();
    assert_eq!(observed.backend, crate::proving::Backend::OpenCl);
    assert_eq!(observed.calls, 2);
    assert_eq!(observed.completed_calls, 2);
    assert!(observed.device_ns > 0);
    assert_eq!(observed.inclusive_ns, 0);
    let error = aborted
        .err()
        .expect("missing preprocessing must abort proof");
    let message = error
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| error.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("");
    assert!(message.contains("preprocessing data"), "{message}");
    let after = session.stats();
    assert!(after.random_calls > before.random_calls);
    assert!(after.random_fields > before.random_fields);
    for pcs in [config.pcs(), &shared] {
        assert!(pcs.begin_randomness_attempt().is_err());
        let error = pcs
            .commit_main_device(vec![(domain, session.alias_private(&retry).unwrap())])
            .err()
            .expect("aborted proof must retire all active clones");
        assert!(error.contains("attempt has failed"), "{error}");
    }
    assert_eq!(session.stats().random_calls, after.random_calls);
    assert_eq!(session.stats().random_fields, after.random_fields);
    if gpu_transcript {
        assert!(after.transcript_observations > before.transcript_observations);
        assert!(after.transcript_samples > before.transcript_samples);
        assert!(transcript_clone.begin_attempt().is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            config.initialise_challenger();
        }))
        .is_err());
        assert_eq!(session.stats(), after);
    }
}

fn device_witness_public_state_proofs(
    public_salts: bool,
    gpu_randomness: bool,
    gpu_transcript: bool,
) {
    quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(quotient_pcs::gpu_fri_resident_enabled());
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let air = all_operations();
    let degree = air.program().height().ilog2() as usize + 1;
    let reference_setup = if public_salts {
        public_setup(false)
    } else {
        cpu_config()
    };
    let reference_data =
        BatchData::from_airs_and_degrees(&reference_setup, core::slice::from_ref(&air), &[degree]);
    let setup = if public_salts {
        public_setup(true)
    } else {
        profile::Config::new(
            candidate(false).0,
            Challenger::new(default_goldilocks_poseidon2_8()),
        )
    };
    let setup_run = crate::proving::Run::new(
        "gpu_witness_test_setup",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let prepared =
        machine::gpu_backend::prepare(&air, &setup, COMPILER_HOST_BUDGET, &setup_run).unwrap();
    setup_run.finish(true).unwrap();
    if public_salts {
        assert!(matches!(
            prepared
                .data
                .prover_only
                .preprocessed_prover_data
                .as_ref()
                .unwrap(),
            ProverData::DeviceOnly {
                salts: super::super::SaltStore::PublicDevice(_),
                ..
            }
        ));
    }
    assert_eq!(
        reference_data
            .common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment,
        prepared
            .data
            .common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment,
    );
    let expected_meta = reference_data.common.preprocessed.as_ref().unwrap();
    let actual_meta = prepared.data.common.preprocessed.as_ref().unwrap();
    assert_eq!(
        expected_meta.matrix_to_instance,
        actual_meta.matrix_to_instance
    );
    assert_eq!(
        expected_meta.instances[0].as_ref().unwrap().width,
        air.preprocessed_width()
    );
    assert_eq!(
        actual_meta.instances[0].as_ref().unwrap().degree_bits,
        degree
    );
    assert_eq!(
        format!("{:?}", reference_data.common.lookups),
        format!("{:?}", prepared.data.common.lookups)
    );
    drop(setup);
    let baseline = engine::report("device witness public baseline").unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut proofs = Vec::new();
    for x in [3u64, 5, 17] {
        let mut public_words: Vec<_> = (0..33).map(|i| x + i).collect();
        public_words[0] = x * x;
        let public: Vec<_> = public_words.iter().copied().map(Val::from_u64).collect();
        let trace = air.trace(&public, &[Val::from_u64(x)]).unwrap();
        let reference = pool.install(|| {
            prove_batch(
                &cpu_config(),
                &[StarkInstance {
                    air: &air,
                    trace: &trace,
                    public_values: public.clone(),
                }],
                &reference_data,
            )
        });
        // This host trace exists only for the independent CPU oracle.
        drop(trace);
        let pcs = candidate(true).0.with_gpu_openings().unwrap();
        let pcs = if gpu_randomness {
            pcs.with_gpu_randomness().unwrap()
        } else {
            pcs
        };
        let challenger = if gpu_transcript {
            pcs.gpu_challenger().unwrap()
        } else {
            Challenger::new(default_goldilocks_poseidon2_8())
        };
        let config = profile::Config::new(pcs, challenger);
        let session = config.pcs().quotient_session().unwrap();
        let before = session.stats();
        if gpu_randomness {
            assert_eq!(before.random_streams, 4);
        }
        let trace = prepared
            .witness
            .trace(&session, &public_words, &[x], 64 << 20)
            .unwrap();
        assert_eq!(
            session.stats().uploaded_bytes - before.uploaded_bytes,
            34 * 8
        );
        assert_eq!(
            session.stats().downloaded_bytes - before.downloaded_bytes,
            8
        );
        let run = crate::proving::Run::new(
            "device_witness_pipeline_test",
            crate::proving::Request::compatible(),
            profile::proving_capabilities(true),
        )
        .unwrap();
        let actual = pool.install(|| {
            gpu_quotient_prover::prove_batch(
                &config,
                vec![gpu_quotient_prover::ProvingInstance::from_device(
                    &air, trace, &public,
                )],
                &prepared.data,
                CandidateMmcs::release_quotient_prefix,
                |_, _| panic!("device quotient must not enter the host callback"),
                &run,
            )
        });
        run.finish(true).unwrap();
        if gpu_randomness {
            let stats = session.stats();
            assert_eq!(stats.random_streams, 4);
            assert!(stats.random_calls > 4);
            assert!(stats.random_fields > 0);
        }
        let stats = session.stats();
        if gpu_transcript {
            assert_eq!(stats.transcript_creations, 1);
            assert_eq!(stats.transcript_snapshots, 1);
            assert!(stats.transcript_observations > 0);
            assert!(stats.transcript_samples > 0);
            assert!(stats.transcript_device_ns > 0);
            assert_eq!(stats.grinding_calls, 1);
            assert!(stats.grinding_device_ns > 0);
            assert!(stats.scalar_lookup_prefixes > 0);
            assert_eq!(stats.scalar_next_points, 1);
            assert_eq!(stats.scalar_disjoint_domains, 1);
            assert!(stats.scalar_cosets > 0);
            assert!(stats.scalar_device_ns > 0);
            eprintln!("gpu_transcript_complete_proof stats={stats:?}");
        } else {
            assert_eq!(stats.transcript_creations, 0);
            assert_eq!(stats.transcript_observations, 0);
            assert_eq!(stats.transcript_samples, 0);
            assert_eq!(stats.grinding_calls, 0);
        }
        assert_eq!(
            postcard::to_allocvec(&reference).unwrap(),
            postcard::to_allocvec(&actual).unwrap()
        );
        assert_eq!(session.stats().witness_programs, 0);
        assert_eq!(session.stats().witness_evaluations, 1);
        drop((session, config));
        let after = engine::report("device witness proof released").unwrap();
        assert_eq!(
            after.device_matrix_live_bytes,
            baseline.device_matrix_live_bytes
        );
        assert_eq!(after.device_matrices, baseline.device_matrices);
        if quotient_pcs::gpu_pcs_device_only_enabled() {
            assert_eq!(after.lde_host_output_bytes, baseline.lde_host_output_bytes);
            assert_eq!(
                after.lde_host_reordered_bytes,
                baseline.lde_host_reordered_bytes
            );
        }
        proofs.push((postcard::to_allocvec(&actual).unwrap(), public));
    }
    drop(prepared);
    engine::shutdown().unwrap();
    let upstream = p3_uni_stark::StarkConfig::<CpuPcs, Challenge, crate::config::Challenger>::new(
        if public_salts {
            let perm = default_goldilocks_poseidon2_8();
            let mmcs = ValMmcs::new(
                MyHash::new(perm.clone()),
                MyCompress::new(perm),
                profile::CAP_HEIGHT,
                ChaCha20Rng::from_seed([0; 32]),
            );
            CpuPcs::new(
                Default::default(),
                mmcs.clone(),
                profile::fri(CpuExtensionMmcs::new(mmcs)),
                profile::NUM_RANDOM_CODEWORDS,
                ChaCha20Rng::from_seed([0; 32]),
            )
        } else {
            reference().0
        },
        crate::config::Challenger::new(default_goldilocks_poseidon2_8()),
    );
    let data = BatchData::from_airs_and_degrees(&upstream, core::slice::from_ref(&air), &[degree]);
    for (bytes, public) in proofs {
        let proof = postcard::from_bytes(&bytes).unwrap();
        verify_batch(
            &upstream,
            core::slice::from_ref(&air),
            &proof,
            &[public.clone()],
            &data.common,
        )
        .unwrap();
        let mut wrong = public;
        wrong[32] += Val::ONE;
        assert!(verify_batch(
            &upstream,
            core::slice::from_ref(&air),
            &proof,
            &[wrong],
            &data.common
        )
        .is_err());
    }
}

#[test]
#[ignore = "requires OpenCL GPU, owned resident PCS and <=3 GiB zero-swap service"]
fn device_preprocessing_admission_preserves_salts_hiding_streams_and_public_ownership() {
    use crate::block_v2::gpu_hash::device::DeviceSession;
    use machine::gpu_program::WitnessProgram;
    quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let air = all_operations();
    let height = air.program().height();
    let domain = Domain::new(Val::ONE, height.ilog2() as usize + 1).unwrap();
    let (cpu, cpu_mmcs) = reference();
    let (gpu, gpu_mmcs) = candidate(false);
    let session = gpu.quotient_session().unwrap();
    let prepared = session
        .prepare_witness(std::sync::Arc::new(
            WitnessProgram::compile(air.program(), 64 << 20).unwrap(),
        ))
        .unwrap();
    let foreign = DeviceSession::new().unwrap();
    let wrong_session = prepared.preprocessing_trace(&foreign).unwrap();
    let wrong_domain = prepared.preprocessing_trace(&session).unwrap();
    let before = session.stats();
    assert!(gpu
        .commit_preprocessing_device(vec![(domain.into(), wrong_session)])
        .is_err());
    assert!(gpu
        .commit_preprocessing_device(vec![(
            Domain::new(Val::from_u64(7), domain.log_size())
                .unwrap()
                .into(),
            wrong_domain
        )])
        .is_err());
    assert!(gpu.commit_preprocessing_device(vec![]).is_err());
    assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(session.stats().downloaded_bytes, before.downloaded_bytes);
    let input = prepared.preprocessing_trace(&session).unwrap();
    let expected = <CpuPcs as Pcs<Challenge, Challenger>>::commit_preprocessing(
        &cpu,
        [(domain, air.preprocessed_trace().unwrap())],
    );
    let actual = gpu
        .commit_preprocessing_device(vec![(domain.into(), input)])
        .unwrap();
    let prefix = actual.1.owned_matrix(&foreign, 0).unwrap();
    assert_eq!(prefix.spec().columns(), air.preprocessed_width());
    drop(prefix);
    compare(&cpu_mmcs, &gpu_mmcs, expected, actual);
    // Deterministic preprocessing consumes salts but no hiding samples.
    // The next private commitment matches both independent CPU streams.
    let trace = matrix(height, 7, 23);
    let expected = <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, [(domain, trace.clone())]);
    let words: Vec<_> = trace.values.iter().map(|v| v.as_canonical_u64()).collect();
    let input = session
        .upload(
            crate::block_v2::gpu_hash::device::MatrixSpec::new(
                height.ilog2(),
                7,
                crate::block_v2::gpu_hash::device::Extension::Base,
                crate::block_v2::gpu_hash::device::RowOrder::Natural,
                1,
            )
            .unwrap(),
            &words,
        )
        .unwrap();
    let actual = gpu.commit_main_device(vec![(domain, input)]).unwrap();
    assert!(actual.1.owned_matrix(&foreign, 0).is_err());
    compare(&cpu_mmcs, &gpu_mmcs, expected, actual);
}
