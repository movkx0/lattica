//! Complete owned-input batch proofs, with an independent seeded CPU oracle.
use super::*;

#[test]
#[ignore = "requires bounded OpenCL device-only lookup/opening/FRI runner"]
fn gpu_owned_multi_air_proofs_match_cpu_with_distinct_programs_and_reordering() {
    owned_multi_air(false);
}

#[test]
#[ignore = "requires bounded OpenCL device-only randomness/transcript runner"]
fn gpu_owned_multi_air_randomness_and_transcript_match_cpu() {
    owned_multi_air(true);
}

fn owned_multi_air(gpu_randomness: bool) {
    let fusion = quotient_pcs::initialize_research_from_env().unwrap();
    quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    crate::block_v2::gpu_hash::initialize_from_env().unwrap();
    assert!(crate::block_v2::gpu_hash::initialize_resident_from_env().unwrap());
    assert!(quotient_pcs::gpu_fri_resident_enabled());
    let _shutdown = engine::TestShutdownGuard;
    assert_eq!(
        std::env::var("LATTICA_V2_GPU_MANAGED_BYTES").as_deref(),
        Ok("1073741824")
    );
    let unpadded: Vec<_> = [1, 16, 32]
        .into_iter()
        .map(|rounds| {
            let mut builder = machine::ProgramBuilder::new(33).unwrap();
            let x = builder.input();
            let square = builder.mul(x, x);
            let public = builder.public(0).unwrap();
            builder.assert_equal(square, public);
            let mut state = [x; 8];
            for _ in 0..rounds {
                state = builder.poseidon(state);
            }
            machine::MachineAir::new(builder.finish(None).unwrap())
        })
        .collect();
    let height = unpadded.iter().map(|a| a.program().height()).max().unwrap();
    assert!(unpadded.iter().any(|a| a.program().height() != height));
    let airs: Vec<_> = unpadded
        .iter()
        .map(|a| machine::MachineAir::new(a.program().clone().pad_to(height).unwrap()))
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut proofs = Vec::new();
    for order in [[0usize, 1, 2], [2usize, 0, 1]] {
        let ordered: Vec<_> = order.iter().map(|&i| airs[i].clone()).collect();
        let degrees: Vec<_> = ordered
            .iter()
            .map(|air| air.program().height().ilog2() as usize + 1)
            .collect();
        let reference_setup = public_setup(false);
        let reference_data = BatchData::from_airs_and_degrees(&reference_setup, &ordered, &degrees);
        let setup = public_setup(true);
        let air_refs: Vec<_> = ordered.iter().collect();
        let run = crate::proving::Run::new(
            "gpu_multi_air_setup",
            if gpu_randomness {
                crate::proving::Request {
                    policy: crate::proving::Policy::GpuRequired,
                    emit_report: true,
                }
            } else {
                crate::proving::Request::compatible()
            },
            profile::preprocessing_capabilities(),
        )
        .unwrap();
        let session = setup.pcs().quotient_session().unwrap();
        let before = session.stats();
        assert!(machine::gpu_backend::prepare_batch(
            &unpadded.iter().collect::<Vec<_>>(),
            &setup,
            usize::MAX,
            &run,
        )
        .err()
        .unwrap()
        .contains("equal padded AIR heights"));
        assert!(machine::gpu_backend::prepare_batch(&[], &setup, usize::MAX, &run).is_err());
        assert!(machine::gpu_backend::prepare_batch(&air_refs, &setup, 1, &run).is_err());
        assert_eq!(before.uploaded_bytes, session.stats().uploaded_bytes);
        assert_eq!(before.downloaded_bytes, session.stats().downloaded_bytes);
        let randomness_observation = setup.pcs().observe_randomness(&run).unwrap();
        let prepared = machine::gpu_backend::prepare_batch(
            &air_refs,
            &setup,
            ordered.len() * COMPILER_HOST_BUDGET,
            &run,
        )
        .unwrap();
        drop(randomness_observation);
        run.finish(true).unwrap();
        let expected = reference_data.common.preprocessed.as_ref().unwrap();
        let actual = prepared.data.common.preprocessed.as_ref().unwrap();
        assert_eq!(expected.commitment, actual.commitment);
        assert_eq!(actual.matrix_to_instance, vec![0, 1, 2]);
        assert_eq!(expected.matrix_to_instance, actual.matrix_to_instance);
        for (i, meta) in actual.instances.iter().enumerate() {
            let meta = meta.as_ref().unwrap();
            assert_eq!(meta.matrix_index, i);
            assert_eq!(meta.width, ordered[i].preprocessed_width());
            assert_eq!(meta.degree_bits, degrees[i]);
        }
        assert_eq!(
            format!("{:?}", reference_data.common.lookups),
            format!("{:?}", prepared.data.common.lookups)
        );
        drop((session, setup));
        let baseline = engine::report("multi AIR preprocessing retained").unwrap();
        for offset in [3u64, 11] {
            let xs: Vec<_> = order.iter().map(|&i| offset + i as u64).collect();
            let public_words: Vec<Vec<_>> = xs
                .iter()
                .map(|&x| {
                    let mut p: Vec<_> = (0..33).map(|i| x + i).collect();
                    p[0] = x * x;
                    p
                })
                .collect();
            let public: Vec<Vec<_>> = public_words
                .iter()
                .map(|p| p.iter().map(|&v| Val::from_u64(v)).collect())
                .collect();
            let traces: Vec<_> = ordered
                .iter()
                .zip(&public)
                .zip(&xs)
                .map(|((air, p), &x)| air.trace(p, &[Val::from_u64(x)]).unwrap())
                .collect();
            let reference = pool.install(|| {
                prove_batch(
                    &cpu_config(),
                    &ordered
                        .iter()
                        .zip(&traces)
                        .zip(&public)
                        .map(|((air, trace), p)| StarkInstance {
                            air,
                            trace,
                            public_values: p.clone(),
                        })
                        .collect::<Vec<_>>(),
                    &reference_data,
                )
            });
            // Host matrices belong exclusively to the CPU oracle.
            drop(traces);
            let pcs = candidate(true).0.with_gpu_openings().unwrap();
            let pcs = if gpu_randomness {
                pcs.with_gpu_randomness().unwrap()
            } else {
                pcs
            };
            let challenger = if gpu_randomness {
                pcs.gpu_challenger().unwrap()
            } else {
                Challenger::new(default_goldilocks_poseidon2_8())
            };
            let config = profile::Config::new(pcs, challenger);
            let session = config.pcs().quotient_session().unwrap();
            let run = crate::proving::Run::new(
                "gpu_owned_multi_air_test",
                if gpu_randomness {
                    crate::proving::Request {
                        policy: crate::proving::Policy::GpuRequired,
                        emit_report: true,
                    }
                } else {
                    crate::proving::Request::compatible()
                },
                profile::registered_proof_capabilities(),
            )
            .unwrap();
            let witness_observation = session.observe_witness(&run).unwrap();
            let before = session.stats();
            let inputs = ordered
                .iter()
                .zip(&prepared.witnesses)
                .zip(&public_words)
                .zip(&public)
                .zip(&xs)
                .map(|((((air, witness), words), p), &x)| {
                    let trace = witness.trace(&session, words, &[x], 64 << 20).unwrap();
                    gpu_quotient_prover::ProvingInstance::from_device(air, trace, p)
                })
                .collect();
            assert_eq!(
                session.stats().uploaded_bytes - before.uploaded_bytes,
                3 * 34 * 8
            );
            assert_eq!(
                session.stats().downloaded_bytes - before.downloaded_bytes,
                3 * 8
            );
            drop(witness_observation);
            let proof = pool.install(|| {
                gpu_quotient_prover::prove_batch(
                    &config,
                    inputs,
                    &prepared.data,
                    CandidateMmcs::release_quotient_prefix,
                    |_, _| panic!("owned batch quotient must not enter the host callback"),
                    &run,
                )
            });
            run.finish(true).unwrap();
            let stats = session.stats();
            assert_eq!(stats.witness_evaluations, 3);
            if gpu_randomness {
                assert_eq!(stats.random_streams, 4);
                assert!(stats.random_calls > 4);
                assert_eq!(stats.transcript_creations, 1);
                assert_eq!(stats.transcript_snapshots, 1);
                assert!(stats.scalar_lookup_prefixes > 0);
                assert_eq!(stats.grinding_calls, 1);
            }
            let bytes = postcard::to_allocvec(&proof).unwrap();
            assert_eq!(postcard::to_allocvec(&reference).unwrap(), bytes);
            eprintln!("gpu_owned_multi_air_complete airs=3 order={order:?} rows={degrees:?} gpu_randomness={gpu_randomness} bytes={} stats={stats:?}", bytes.len());
            drop((session, config));
            let after = engine::report("multi AIR proof released").unwrap();
            assert_eq!(
                after.device_matrix_live_bytes,
                baseline.device_matrix_live_bytes
            );
            assert_eq!(after.device_matrices, baseline.device_matrices);
            assert_eq!(after.lde_host_output_bytes, baseline.lde_host_output_bytes);
            assert_eq!(
                after.lde_host_reordered_bytes,
                baseline.lde_host_reordered_bytes
            );
            proofs.push((order, bytes, public));
        }
        drop(prepared);
    }
    engine::shutdown().unwrap();
    for (order, bytes, public) in proofs {
        let perm = default_goldilocks_poseidon2_8();
        let mmcs = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([0; 32]),
        );
        let upstream =
            p3_uni_stark::StarkConfig::<CpuPcs, Challenge, crate::config::Challenger>::new(
                CpuPcs::new(
                    Default::default(),
                    mmcs.clone(),
                    profile::fri(CpuExtensionMmcs::new(mmcs)),
                    profile::NUM_RANDOM_CODEWORDS,
                    ChaCha20Rng::from_seed([0; 32]),
                ),
                crate::config::Challenger::new(perm),
            );
        let ordered: Vec<_> = order.iter().map(|&i| airs[i].clone()).collect();
        let degrees: Vec<_> = ordered
            .iter()
            .map(|air| air.program().height().ilog2() as usize + 1)
            .collect();
        let data = BatchData::from_airs_and_degrees(&upstream, &ordered, &degrees);
        let proof = postcard::from_bytes(&bytes).unwrap();
        verify_batch(&upstream, &ordered, &proof, &public, &data.common).unwrap();
        let mut wrong = public.clone();
        wrong[1][32] += Val::ONE;
        assert!(verify_batch(&upstream, &ordered, &proof, &wrong, &data.common).is_err());
        let mut reordered = public.clone();
        reordered.swap(0, 1);
        assert!(verify_batch(&upstream, &ordered, &proof, &reordered, &data.common).is_err());
    }
}
