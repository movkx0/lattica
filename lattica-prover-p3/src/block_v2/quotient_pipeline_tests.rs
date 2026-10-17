use super::*;

const COMPILER_HOST_BUDGET: usize = (64 << 20)
    + crate::block_v2::machine::symbolic::LOOKUP_RETAINED_HOST_BYTES as usize
    + crate::block_v2::machine::symbolic::HOST_BYTES as usize
    + crate::block_v2::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES as usize
    + crate::block_v2::gpu_hash::ENGINE_RETAINED_HOST_BYTES as usize;

#[test]
#[ignore = "requires OpenCL GPU, GPU_PCS_DEVICE_ONLY=1 and a <=3 GiB zero-swap service"]
fn gpu_device_only_pcs_preserves_full_proof_bytes_without_lde_readback() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled());
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_PCS_DEVICE_ONLY=1 and a <=3 GiB zero-swap service"]
fn gpu_device_only_pcs_preserves_compact_selection_proof_bytes_without_lde_readback() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled());
    quotient_proof_equivalence(true);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_FRI_RESIDENT=1 and a <=3 GiB zero-swap service"]
fn gpu_resident_fri_preserves_full_proof_bytes_and_cpu_verify() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_fri_resident_enabled());
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_FRI_RESIDENT=1 and a <=3 GiB zero-swap service"]
fn gpu_resident_fri_preserves_compact_proof_bytes_and_cpu_verify() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_fri_resident_enabled());
    quotient_proof_equivalence(true);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_OPENING_EVAL=1 and a <=3 GiB zero-swap service"]
fn gpu_owned_openings_preserve_full_proof_bytes_and_cpu_verify() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_opening_eval_enabled());
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_OPENING_EVAL=1 and a <=3 GiB zero-swap service"]
fn gpu_owned_openings_preserve_compact_proof_bytes_and_cpu_verify() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_opening_eval_enabled());
    quotient_proof_equivalence(true);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_LOOKUP=1 and a <=3 GiB zero-swap service"]
fn gpu_lookup_pipeline_preserves_full_proof_bytes_and_cpu_verifies() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_lookup_enabled());
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_LOOKUP=1 and a <=3 GiB zero-swap service"]
fn gpu_lookup_pipeline_preserves_compact_proof_bytes() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_lookup_enabled());
    quotient_proof_equivalence(true);
}

#[test]
#[ignore = "requires OpenCL GPU, owned resident PCS and a <=3 GiB zero-swap service"]
fn gpu_lookup_commit_and_original_trace_recovery_match_reference_and_preserve_rng() {
    device_trace_commit_equivalence(crate::block_v2::gpu_hash::device::Extension::Cubic);
}

#[test]
#[ignore = "requires OpenCL GPU, owned resident PCS and a <=3 GiB zero-swap service"]
fn gpu_main_commit_and_original_trace_recovery_match_reference_and_preserve_rng() {
    device_trace_commit_equivalence(crate::block_v2::gpu_hash::device::Extension::Base);
}

fn device_trace_commit_equivalence(extension: crate::block_v2::gpu_hash::device::Extension) {
    use crate::block_v2::gpu_hash::device::{DeviceSession, Extension, MatrixSpec, RowOrder};
    use p3_field::PrimeField64;
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let cases = if extension == Extension::Cubic {
        [
            (1, vec![3]),
            (8, vec![3, 9]),
            (256, vec![6, 15]),
            (8192, vec![3]),
        ]
    } else {
        [
            (1, vec![1]),
            (8, vec![1, 7, 33]),
            (256, vec![2, 65]),
            (8192, vec![5]),
        ]
    };
    for (height, widths) in cases {
        let height: usize = height;
        let domain = Domain::new(Val::ONE, (height * 2).ilog2() as usize).unwrap();
        let (cpu, cpu_mmcs) = reference();
        let (gpu, gpu_mmcs) = candidate(false);
        let session = gpu.quotient_session().unwrap();
        let commit = |inputs| {
            if extension == Extension::Cubic {
                gpu.commit_lookup_device(inputs)
            } else {
                gpu.commit_main_device(inputs)
            }
        };
        let inputs: Vec<_> = widths
            .iter()
            .enumerate()
            .map(|(i, width)| (domain, matrix(height, *width, 5 + i * 13)))
            .collect();
        // The public deterministic prefix also recovers original subgroup rows.
        let preprocessing = gpu.commit_preprocessing(inputs.clone());
        for (i, (_, original)) in inputs.iter().enumerate() {
            let before = session.stats().downloaded_bytes;
            let recovered = gpu
                .lookup_original_trace(&preprocessing.1, i, height.ilog2(), original.width)
                .unwrap();
            assert_eq!(session.stats().downloaded_bytes, before);
            assert_eq!(
                session.read(&recovered, recovered.spec().bytes()).unwrap(),
                original
                    .values
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>()
            );
        }
        let expected_pre =
            <CpuPcs as Pcs<Challenge, Challenger>>::commit_preprocessing(&cpu, inputs.clone());
        compare(&cpu_mmcs, &gpu_mmcs, expected_pre, preprocessing);
        for round in 0..2 {
            let mut device_inputs = Vec::new();
            for (domain, trace) in &inputs {
                let spec = MatrixSpec::new(
                    height.ilog2(),
                    trace.width / extension.degree(),
                    extension,
                    RowOrder::Natural,
                    1,
                )
                .unwrap();
                let words: Vec<_> = trace.values.iter().map(|v| v.as_canonical_u64()).collect();
                let owned = session.upload(spec, &words).unwrap();
                if round == 0 && device_inputs.is_empty() {
                    let foreign = DeviceSession::new().unwrap().upload(spec, &words).unwrap();
                    assert!(commit(vec![(*domain, foreign)]).is_err());
                    assert!(commit(vec![(
                        Domain::new(Val::from_u64(7), (height * 2).ilog2() as usize).unwrap(),
                        session.alias_private(&owned).unwrap()
                    )])
                    .is_err());
                    assert!(commit(vec![(
                        *domain,
                        session
                            .lde(&owned, height.ilog2(), 1, RowOrder::BitReversed)
                            .unwrap()
                    )])
                    .is_err());
                    // A base trace cannot enter the cubic lookup interface,
                    // nor can a cubic trace enter the main interface.
                    let wrong = if extension == Extension::Cubic {
                        gpu.commit_main_device(vec![(
                            *domain,
                            session.alias_private(&owned).unwrap(),
                        )])
                    } else {
                        gpu.commit_lookup_device(vec![(
                            *domain,
                            session.alias_private(&owned).unwrap(),
                        )])
                    };
                    assert!(wrong.is_err());
                }
                device_inputs.push((*domain, owned));
            }
            assert!(commit(vec![]).is_err());
            let expected = <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, inputs.clone());
            let actual = commit(device_inputs).unwrap();
            for (i, (_, original)) in inputs.iter().enumerate() {
                let before = session.stats().downloaded_bytes;
                let recovered = gpu
                    .lookup_original_trace(&actual.1, i, height.ilog2(), original.width)
                    .unwrap();
                assert_eq!(session.stats().downloaded_bytes, before);
                assert_eq!(
                    session.read(&recovered, recovered.spec().bytes()).unwrap(),
                    original
                        .values
                        .iter()
                        .map(|v| v.as_canonical_u64())
                        .collect::<Vec<_>>()
                );
                assert!(gpu
                    .lookup_original_trace(&actual.1, i, height.ilog2() + 1, original.width)
                    .is_err());
            }
            compare(&cpu_mmcs, &gpu_mmcs, expected, actual);
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU, owned quotient flags, <=3 GiB cgroup and zero swap"]
fn gpu_owned_quotient_commit_matches_reference_and_rejections_preserve_rng() {
    owned_quotient_commit_conformance::<Challenge>();
}

#[test]
#[ignore = "requires bounded OpenCL device-only quotient runner"]
fn gpu_owned_quotient_batches_preserve_cpu_order_and_rejection_randomness() {
    use crate::block_v2::gpu_hash::device::{DeviceSession, Extension, MatrixSpec, RowOrder};
    use p3_field::PrimeField64;
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        Limits {
            managed_bytes: 1 << 30,
            tile_bytes: 32 << 20,
            staging_bytes: 8 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    for gpu_randomness in [false, true] {
        let (gpu, gpu_mmcs) = candidate(true);
        let gpu = gpu.with_gpu_openings().unwrap();
        let gpu = if gpu_randomness {
            gpu.with_gpu_randomness().unwrap()
        } else {
            gpu
        };
        let session = gpu.quotient_session().unwrap();
        let cpu_mmcs = (*mmcs(false).cpu).clone();
        let reference = CpuPcs::new(
            Default::default(),
            cpu_mmcs.clone(),
            profile::fri(CpuExtensionMmcs::new(cpu_mmcs.clone())),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([47; 32]),
        );
        let mut owned = Vec::new();
        let mut domains = Vec::new();
        let mut expected = Vec::new();
        let chunks = [2usize, 16, 32];
        for (i, &count) in chunks.iter().enumerate() {
            let shift = [7, 11, 13][i];
            let log_rows = (8 * count).ilog2();
            let domain = Domain::new(Val::from_u64(shift), log_rows as usize).unwrap();
            let values = matrix(8 * count, 3, 19 + i);
            let spec =
                MatrixSpec::new(log_rows, 1, Extension::Cubic, RowOrder::Natural, shift).unwrap();
            owned.push(
                session
                    .upload(
                        spec,
                        &values
                            .values
                            .iter()
                            .map(|v| v.as_canonical_u64())
                            .collect::<Vec<_>>(),
                    )
                    .unwrap(),
            );
            domains.push(
                crate::block_v2::gpu_hash::device::DomainSpec::new(shift, log_rows as usize)
                    .unwrap(),
            );
            expected.extend(<CpuPcs as Pcs<Challenge, Challenger>>::get_quotient_ldes(
                &reference,
                domain
                    .split_domains(count)
                    .into_iter()
                    .zip(domain.split_evals(count, values)),
                count,
            ));
        }
        let before = session.stats();
        assert!(gpu.commit_quotients_device(vec![]).is_err());
        assert!(gpu
            .commit_quotients_device(vec![(domains[2], &owned[2], 32); 9])
            .is_err());
        // Different chunk heights and a foreign session must fail before any draw.
        assert!(gpu
            .commit_quotients_device(vec![
                (domains[0], &owned[0], 4),
                (domains[1], &owned[1], 16)
            ])
            .is_err());
        let foreign_session = DeviceSession::new().unwrap();
        let spec = owned[2].spec();
        let foreign = foreign_session
            .upload(spec, &vec![1; spec.bytes() / 8])
            .unwrap();
        assert!(gpu
            .commit_quotients_device(vec![(domains[0], &owned[0], 2), (domains[2], &foreign, 32)])
            .is_err());
        assert_eq!(session.stats().random_calls, before.random_calls);
        let actual = gpu
            .commit_quotients_device((0..3).map(|i| (domains[i], &owned[i], chunks[i])).collect())
            .unwrap();
        assert_eq!(expected.len(), 50);
        for (i, lde) in expected.iter().enumerate() {
            let captured = actual.1.owned_matrix(&session, i).unwrap();
            assert_eq!(captured.spec().rows(), 16);
            assert_eq!(
                session.read(&captured, captured.spec().bytes()).unwrap(),
                lde.values[..16 * 7]
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>()
            );
        }
        super::device_pcs_tests::compare_device(
            &cpu_mmcs,
            &gpu_mmcs,
            &session,
            cpu_mmcs.commit(expected),
            actual,
        );
        eprintln!(
            "gpu_owned_quotient_batch_cpu_matched airs=3 chunks=50 gpu_randomness={gpu_randomness}"
        );
    }
}

#[test]
#[ignore = "requires OpenCL GPU, owned quotient flags, <=3 GiB cgroup and zero swap"]
fn gpu_quadratic_owned_quotient_commit_matches_reference_and_rejections_preserve_rng() {
    owned_quotient_commit_conformance::<crate::config::Challenge>();
}

fn owned_quotient_commit_conformance<E: crate::block_v2::pcs_field::PcsField>() {
    let extension = E::DEVICE_EXTENSION;
    use crate::block_v2::gpu_hash::device::{DeviceSession, MatrixSpec, RowOrder};
    use p3_field::PrimeField64;
    let fusion = crate::block_v2::quotient_pcs::initialize_research_from_env().unwrap();
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, fusion).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_quotient_resident_enabled());
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 8 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    let cases = [
        (8usize, 2usize, 7u64),
        (32, 4, 11),
        (64, 16, 7),
        (64, 32, 11),
        (8192, 2, 11),
    ];
    for (height, chunks, shift) in cases {
        let log_rows = (height * chunks).ilog2();
        let domain = Domain::new(Val::from_u64(shift), log_rows as usize).unwrap();
        let values = matrix(height * chunks, extension.degree(), 19);
        let domains = domain.split_domains(chunks);
        let matrices = domain.split_evals(chunks, values.clone());
        // The oracle is the upstream CPU PCS with the same independent test
        // quotient stream, never the resident device-only adapter.
        let cpu_mmcs = (*mmcs(false).cpu).clone();
        let reference = CpuPcs::new(
            crate::config::Dft::default(),
            cpu_mmcs.clone(),
            profile::fri(CpuExtensionMmcs::new(cpu_mmcs.clone())),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([47; 32]),
        );
        let (gpu, gpu_mmcs) = candidate_field::<E>(true);
        let gpu = gpu
            .with_gpu_openings()
            .unwrap()
            .with_gpu_randomness()
            .unwrap();
        let session = gpu.quotient_session().unwrap();
        let spec = MatrixSpec::new(log_rows, 1, extension, RowOrder::Natural, shift).unwrap();
        let words: Vec<_> = values.values.iter().map(|v| v.as_canonical_u64()).collect();
        let owned = session.upload(spec, &words).unwrap();
        let other = if extension == crate::block_v2::gpu_hash::device::Extension::Quadratic {
            crate::block_v2::gpu_hash::device::Extension::Cubic
        } else {
            crate::block_v2::gpu_hash::device::Extension::Quadratic
        };
        let wrong_spec = MatrixSpec::new(log_rows, 1, other, RowOrder::Natural, shift).unwrap();
        let wrong = session
            .upload(wrong_spec, &vec![1; wrong_spec.bytes() / 8])
            .unwrap();
        assert!(gpu.commit_quotient_device(domain, &wrong, chunks).is_err());
        let foreign = DeviceSession::new().unwrap().upload(spec, &words).unwrap();
        assert!(gpu
            .commit_quotient_device(domain, &foreign, chunks)
            .is_err());
        assert!(gpu
            .commit_quotient_device(
                Domain::new(
                    Val::from_u64(if shift == 7 { 11 } else { 7 }),
                    log_rows as usize
                )
                .unwrap(),
                &owned,
                chunks
            )
            .is_err());
        for invalid in [0, 1, 3, 64] {
            assert!(gpu.commit_quotient_device(domain, &owned, invalid).is_err());
        }
        let ldes = <CpuPcs as Pcs<Challenge, Challenger>>::get_quotient_ldes(
            &reference,
            domains.into_iter().zip(matrices),
            chunks,
        );
        let actual = gpu.commit_quotient_device(domain, &owned, chunks).unwrap();
        if crate::block_v2::quotient_pcs::gpu_opening_eval_enabled() {
            for (index, lde) in ldes.iter().enumerate() {
                let captured = actual.1.owned_matrix(&session, index).unwrap();
                assert_eq!(captured.spec().rows(), height * 2);
                assert_eq!(captured.spec().columns(), extension.degree() + 4);
                assert_eq!(
                    session.read(&captured, captured.spec().bytes()).unwrap(),
                    lde.values[..height * 2 * (extension.degree() + 4)]
                        .iter()
                        .map(|v| v.as_canonical_u64())
                        .collect::<Vec<_>>()
                );
                assert!(actual
                    .1
                    .owned_matrix(&DeviceSession::new().unwrap(), index)
                    .is_err());
            }
        }
        super::device_pcs_tests::compare_device(
            &cpu_mmcs,
            &gpu_mmcs,
            &session,
            cpu_mmcs.commit(ldes),
            actual,
        );
    }
    assert_eq!(
        engine::report("owned quotient commitments")
            .unwrap()
            .quotient_lde_commits,
        cases.len() as u64
    );
    eprintln!(
        "extension_quotient_commit_cpu_matched degree={} cases={}",
        extension.degree(),
        cases.len()
    );
}

#[test]
#[ignore = "requires OpenCL GPU, retained trees, <=3 GiB cgroup and zero swap"]
fn gpu_quotient_pipeline_matches_cpu_matrices_caps_and_openings() {
    let _shutdown = engine::TestShutdownGuard;
    assert_eq!(
        std::env::var("LATTICA_V2_GPU_RETAIN_TREES").as_deref(),
        Ok("1")
    );
    // Large staging exercises the actual parallel decode branch when requested,
    // while the 8192-row input also crosses the multi-kernel NTT boundary.
    engine::initialize_mode(
        Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 8 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    for (height, chunks, width) in [
        (8usize, 2usize, 3usize),
        (32, 4, 1),
        (64, 16, 3),
        (8192, 2, 3),
    ] {
        let domain = Domain::new(Val::from_u64(7), (height * chunks).ilog2() as usize).unwrap();
        let domains = domain.split_domains(chunks);
        let matrices = domain.split_evals(chunks, matrix(height * chunks, width, 19));
        let (reference, _) = candidate(true);
        let (gpu, gpu_mmcs) = candidate(true);
        // All rejected admissions precede hiding and salt draws. The exact
        // comparison below also checks that rejection did not advance RNGs.
        assert!(gpu.commit_quotient_evaluations(vec![]).is_err());
        assert!(gpu
            .commit_quotient_evaluations(vec![(domains.clone(), vec![])])
            .is_err());
        assert!(gpu
            .commit_quotient_evaluations(vec![
                (domains.clone(), matrices.clone()),
                (domains.clone(), matrices.clone()),
            ])
            .is_err());
        let mut overlap = domains.clone();
        overlap[1] = overlap[0];
        assert!(gpu
            .commit_quotient_evaluations(vec![(overlap, matrices.clone())])
            .is_err());
        let cpu_mmcs = (*mmcs(false).cpu).clone();
        let ldes =
            reference.get_quotient_ldes(domains.iter().copied().zip(matrices.clone()), chunks);
        compare(
            &cpu_mmcs,
            &gpu_mmcs,
            cpu_mmcs.commit(ldes),
            gpu.commit_quotient_evaluations(vec![(domains, matrices)])
                .unwrap(),
        );
    }
    let stats = engine::report("GPU quotient differential").unwrap();
    assert_eq!(stats.quotient_lde_commits, 4);
    if std::env::var("LATTICA_V2_GPU_PARALLEL_READBACK").as_deref() == Ok("1") {
        assert!(stats.lde_parallel_decode_bytes > 0);
        assert!(stats.lde_parallel_decode_chunks > 0);
    }
}

#[test]
#[ignore = "requires OpenCL GPU, retained trees, <=3 GiB cgroup and zero swap"]
fn gpu_quotient_pipeline_proof_matches_upstream_and_cpu_verifies() {
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, retained trees, GPU_QUOTIENT_EVAL=1, <=3 GiB cgroup zero swap"]
fn gpu_evaluated_quotient_preserves_full_proof_bytes_and_cpu_verifies() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_quotient_eval_enabled());
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_QUOTIENT_RESIDENT=1 and <=3 GiB zero-swap service"]
fn gpu_owned_quotient_inputs_preserve_full_proof_bytes_and_cpu_verifies() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_quotient_resident_enabled());
    quotient_proof_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU, GPU_QUOTIENT_RESIDENT=1 and <=3 GiB zero-swap service"]
fn gpu_owned_quotient_inputs_preserve_compact_proof_bytes() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_quotient_resident_enabled());
    quotient_proof_equivalence(true);
}
#[test]
#[ignore = "requires OpenCL GPU, retained trees, <=3 GiB cgroup and zero swap"]
fn gpu_compact_quotient_pipeline_preserves_full_proof_bytes() {
    quotient_proof_equivalence(true);
}
#[test]
#[ignore = "requires OpenCL GPU, owned lookup/opening/FRI and <=3 GiB zero-swap service"]
fn gpu_witness_main_handoff_preserves_full_proof_bytes_and_cpu_verifies() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    quotient_proof_equivalence_with_device_main(false, true);
}

#[test]
#[ignore = "requires OpenCL GPU, owned lookup/opening/FRI and <=3 GiB zero-swap service"]
fn gpu_witness_main_handoff_preserves_compact_proof_bytes_and_cpu_verifies() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    quotient_proof_equivalence_with_device_main(true, true);
}

fn quotient_proof_equivalence(compact: bool) {
    quotient_proof_equivalence_with_device_main(compact, false);
}

fn quotient_proof_equivalence_with_device_main(compact: bool, device_main: bool) {
    quotient_proof_equivalence_count(compact, device_main, 1);
}

#[test]
#[ignore = "requires OpenCL GPU, host-input quotient evaluation and <=3 GiB zero-swap service"]
fn gpu_symbolic_multi_air_preserves_full_proof_bytes_and_cpu_verifies() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    assert!(crate::block_v2::quotient_pcs::gpu_quotient_eval_enabled());
    assert!(!crate::block_v2::quotient_pcs::gpu_quotient_resident_enabled());
    quotient_proof_equivalence_count(false, false, 2);
}

fn quotient_proof_equivalence_count(compact: bool, device_main: bool, count: usize) {
    assert!(count > 0 && (!device_main || count == 1));
    use crate::block_v2::machine::{MachineAir, ProgramBuilder};
    use p3_batch_stark::{prove_batch, verify_batch, ProverData as BatchData, StarkInstance};
    use p3_uni_stark::StarkGenericConfig;
    let owned_openings = crate::block_v2::quotient_pcs::gpu_opening_eval_enabled();
    if compact {
        assert_eq!(
            std::env::var("LATTICA_V2_GPU_OPENING_COMPACT").as_deref(),
            Ok("1"),
            "compact prover data requires the compact opening reduction test mode"
        );
    }
    let _shutdown = engine::TestShutdownGuard;
    if crate::block_v2::quotient_pcs::gpu_quotient_eval_enabled() {
        engine::initialize_mode(
            Limits {
                managed_bytes: 256 << 20,
                tile_bytes: 16 << 20,
                staging_bytes: 64 << 10,
            },
            engine::TransferMode::Serial,
        )
        .unwrap();
    } else {
        initialize();
    }
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    let square = builder.mul(input, input);
    builder.assert_equal(square, public);
    let air = MachineAir::new(builder.finish(Some(64)).unwrap());
    let public = vec![Val::from_u64(9)];
    let trace = air.trace(&public, &[Val::from_u64(3)]).unwrap();
    let data = BatchData::from_airs_and_degrees(
        &profile::preprocessing_config(),
        &vec![air.clone(); count],
        &vec![7; count],
    );
    // The owned route deliberately refuses CPU-only preprocessing. Build the
    // same deterministic key on GPU and compare its cap before using it.
    let mut prepared_witness = None;
    let owned_data = if crate::block_v2::quotient_pcs::gpu_quotient_resident_enabled() {
        let perm = default_goldilocks_poseidon2_8();
        let mut pre_mmcs = CandidateMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([0; 32]),
        );
        pre_mmcs.gpu = true;
        let pre_pcs = CandidatePcs::new_resident(
            Default::default(),
            pre_mmcs.clone(),
            profile::fri(profile::ChallengeMmcs::new(pre_mmcs)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([0; 32]),
            64 << 20,
        )
        .unwrap();
        let pre_config = profile::Config::new(pre_pcs, Challenger::new(perm));
        let owned = if device_main {
            let setup_run = crate::proving::Run::new(
                "gpu_quotient_test_setup",
                crate::proving::Request::compatible(),
                profile::proving_capabilities(true),
            )
            .unwrap();
            let prepared = crate::block_v2::machine::gpu_backend::prepare(
                &air,
                &pre_config,
                COMPILER_HOST_BUDGET,
                &setup_run,
            )
            .unwrap();
            setup_run.finish(true).unwrap();
            prepared_witness = Some(prepared.witness);
            prepared.data
        } else {
            BatchData::from_airs_and_degrees(
                &pre_config,
                &vec![air.clone(); count],
                &vec![7; count],
            )
        };
        assert_eq!(
            owned.common.preprocessed.as_ref().unwrap().commitment,
            data.common.preprocessed.as_ref().unwrap().commitment
        );
        assert_eq!(
            format!("{:?}", owned.common.lookups),
            format!("{:?}", data.common.lookups)
        );
        Some(owned)
    } else {
        None
    };
    let instances: Vec<_> = (0..count)
        .map(|_| StarkInstance {
            air: &air,
            trace: &trace,
            public_values: public.clone(),
        })
        .collect();
    let config = |gpu_openings| {
        profile::Config::new(
            if gpu_openings {
                candidate(true).0.with_gpu_openings().unwrap()
            } else if crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled() {
                // An independent CPU reference must not inherit device-only
                // storage from global research selection. Keep all seeds and
                // the separate quotient-fusion stream identical.
                let mmcs = mmcs(false);
                CandidatePcs::new(
                    Default::default(),
                    mmcs.clone(),
                    profile::fri(profile::ChallengeMmcs::new(mmcs)),
                    profile::NUM_RANDOM_CODEWORDS,
                    ChaCha20Rng::from_seed([43; 32]),
                )
                .with_fused_quotients(ChaCha20Rng::from_seed([47; 32]))
            } else {
                candidate(true).0
            },
            Challenger::new(default_goldilocks_poseidon2_8()),
        )
    };
    // One PoW search thread makes upstream's first valid nonce deterministic.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let run = crate::proving::Run::new(
        "quotient_pipeline_test",
        crate::proving::Request::compatible(),
        profile::proving_capabilities(true),
    )
    .unwrap();
    let (reference, actual) = pool.install(|| {
        // The reference always uses the upstream CPU opening arithmetic, even
        // when owned opening mode is selected for the experimental prover.
        let reference = prove_batch(&config(false), &instances, &data);
        if compact {
            crate::block_v2::resident_pcs::enable_compact_for_test();
        }
        let config = config(compact || owned_openings);
        let session = owned_openings.then(|| config.pcs().quotient_session().unwrap());
        let live = engine::report("before owned opening proof").unwrap();
        let actual_instances = if device_main {
            let session = session
                .as_ref()
                .expect("device main requires owned opening test mode");
            let prepared = prepared_witness.as_ref().expect("device witness program");
            let before = session.stats();
            let device_trace = prepared.trace(session, &[9], &[3], 64 << 20).unwrap();
            let after = session.stats();
            assert_eq!(after.uploaded_bytes - before.uploaded_bytes, 16);
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
            vec![
                crate::block_v2::gpu_quotient_prover::ProvingInstance::from_device(
                    &air,
                    device_trace,
                    &public,
                ),
            ]
        } else {
            instances
                .iter()
                .map(crate::block_v2::gpu_quotient_prover::ProvingInstance::from_host)
                .collect()
        };
        let actual = crate::block_v2::gpu_quotient_prover::prove_batch(
            &config,
            actual_instances,
            owned_data.as_ref().unwrap_or(&data),
            |data| {
                CandidateMmcs::release_quotient_prefix(data);
                if crate::block_v2::quotient_pcs::gpu_fri_resident_enabled() {
                    // After quotient evaluation neither owned openings nor
                    // queries may depend on the legacy main/permutation LDEs.
                    match data {
                        ProverData::GpuRetained { matrices, .. } => matrices.clear(),
                        ProverData::Compact(d) => d.prefixes.clear(),
                        ProverData::DeviceOnly { .. } => {
                            assert!(crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled());
                        }
                        _ => panic!("resident FRI requires owned GPU PCS data"),
                    }
                }
            },
            |pcs, groups| {
                if count == 1 {
                    pcs.commit_quotient_evaluations(groups).unwrap()
                } else {
                    // The host-input experimental evaluator supports batches;
                    // this host-input callback retains its single-AIR commitment adapter.
                    // Use the upstream batch commitment adapter for this check.
                    use p3_commit::Pcs;
                    let ldes = groups
                        .into_iter()
                        .flat_map(|(domains, matrices)| {
                            let chunks = domains.len();
                            pcs.get_quotient_ldes(domains.into_iter().zip(matrices), chunks)
                        })
                        .collect();
                    pcs.commit_ldes(ldes)
                }
            },
            &run,
        );
        if let Some(session) = session {
            let stats = session.stats();
            assert_eq!(stats.witness_evaluations, u64::from(device_main));
            assert!(stats.opening_evaluations > 0);
            assert_eq!(stats.opening_evaluations, stats.opening_reductions);
            assert!(stats.opening_value_bytes > 0);
            if crate::block_v2::quotient_pcs::gpu_fri_resident_enabled() {
                assert!(stats.cubic_folds > 0);
                assert_eq!(stats.query_reconstructions, stats.opening_evaluations);
                assert!(stats.query_reconstruction_tiles >= stats.query_reconstructions);
                assert!(stats.query_value_bytes > 0);
                assert_eq!(stats.commitments, stats.cubic_folds);
                assert_eq!(
                    stats.gathered_value_bytes,
                    24 + stats.cubic_folds * profile::NUM_QUERIES as u64 * 80
                );
            }
            let after = engine::report("after owned opening proof").unwrap();
            if crate::block_v2::quotient_pcs::gpu_pcs_device_only_enabled() {
                assert!(after.lde_device_only_commits > live.lde_device_only_commits);
                assert_eq!(
                    after.lde_commits - live.lde_commits,
                    after.lde_device_only_commits - live.lde_device_only_commits
                );
                assert_eq!(after.lde_host_output_bytes, live.lde_host_output_bytes);
                assert_eq!(
                    after.lde_host_reordered_bytes,
                    live.lde_host_reordered_bytes
                );
            }
            assert_eq!(
                after.device_matrix_live_bytes,
                live.device_matrix_live_bytes
            );
            assert_eq!(after.device_matrices, live.device_matrices);
        }
        (reference, actual)
    });
    run.finish(true).unwrap();
    assert_eq!(
        postcard::to_allocvec(&reference).unwrap(),
        postcard::to_allocvec(&actual).unwrap()
    );
    // Decode and verify with the pinned upstream cubic PCS/extension adapter,
    // not merely with the local adapter that produced the proof.
    if crate::block_v2::quotient_pcs::gpu_fri_resident_enabled() {
        let perm = default_goldilocks_poseidon2_8();
        let base = ValMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([0; 32]),
        );
        let pcs = CpuPcs::new(
            Default::default(),
            base.clone(),
            profile::fri(CpuExtensionMmcs::new(base)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([0; 32]),
        );
        let upstream = p3_uni_stark::StarkConfig::<CpuPcs, Challenge, Challenger>::new(
            pcs,
            Challenger::new(perm),
        );
        let key =
            BatchData::from_airs_and_degrees(&upstream, &vec![air.clone(); count], &vec![7; count]);
        let decoded: p3_batch_stark::BatchProof<_> =
            postcard::from_bytes(&postcard::to_allocvec(&actual).unwrap()).unwrap();
        verify_batch(
            &upstream,
            &vec![air.clone(); count],
            &decoded,
            &vec![public.clone(); count],
            &key.common,
        )
        .unwrap();
    }
    verify_batch(
        &profile::make_config(),
        &vec![air.clone(); count],
        &actual,
        &vec![public; count],
        &data.common,
    )
    .unwrap();
    assert!(verify_batch(
        &profile::make_config(),
        &vec![air; count],
        &actual,
        &vec![vec![Val::from_u64(10)]; count],
        &data.common
    )
    .is_err());
}

#[cfg(feature = "gpu-metal")]
#[test]
#[ignore = "Apple GPU memory coordination; isolated process"]
fn gpu_apple_shared_preprocessing_preserves_proofs_and_private_randomness() {
    use crate::block_v2::machine::{MachineAir, ProgramBuilder, backend::RegisteredProgram};
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public_wire = builder.public(0).unwrap();
    let input = builder.input();
    let square = builder.mul(input, input);
    builder.assert_equal(square, public_wire);
    let air = MachineAir::new(builder.finish(Some(64)).unwrap());
    let reference = RegisteredProgram::new(air.clone()).unwrap();
    let verifier = reference.verifier();
    let cap = reference.preprocessing_cap().clone();
    drop(reference);
    let dir = std::env::temp_dir().join(format!("lattica-apple-memory-proof-{}", std::process::id()));
    crate::block_v2::worker_memory::private_directory(&dir).unwrap();
    for (name, value) in [
        ("LATTICA_V2_GPU_HASH", "1"), ("LATTICA_V2_GPU_MANAGED_BYTES", "268435456"),
        ("LATTICA_V2_GPU_RESIDENT_LDE", "1"), ("LATTICA_V2_GPU_OPENINGS", "1"),
        ("LATTICA_V2_GPU_QUOTIENT_LDE", "1"), ("LATTICA_V2_GPU_COMPACT_PROVER_DATA", "1"),
        ("LATTICA_V2_GPU_OPENING_COMPACT", "1"), ("LATTICA_V2_GPU_DIRECT_READBACK", "1"),
        ("LATTICA_APPLE_MEMORY_RECLAIM", "1"), ("LATTICA_APPLE_PHASE_SLOTS", "2"),
        ("LATTICA_APPLE_LDE_SCRATCH_BYTES", "2097152"),
        ("LATTICA_APPLE_QUERY_SCRATCH_BYTES", "65536"), ("LATTICA_APPLE_LATE_PHASE_SLOTS", "1"),
        ("LATTICA_APPLE_COMPACT_SALTS", "1"), ("LATTICA_APPLE_QUERY_PHASE_SLOTS", "1"),
    ] { std::env::set_var(name, value); }
    std::env::set_var("LATTICA_APPLE_SHARED_PREPROCESSING_DIR", dir.join("shared"));
    std::env::set_var("LATTICA_APPLE_PHASE_DIR", dir.join("phases"));
    crate::block_v2::gpu_hash::initialize_from_env().unwrap();
    crate::block_v2::resident_pcs::initialize_research_from_env().unwrap();
    let _shutdown = engine::TestShutdownGuard;
    let first = RegisteredProgram::new(air.clone()).unwrap();
    let second = RegisteredProgram::new(air).unwrap();
    assert_eq!(first.preprocessing_cap(), &cap);
    assert_eq!(second.preprocessing_cap(), &cap);
    let public = [Val::from_u64(9)];
    let witness = [Val::from_u64(3)];
    let a = first.prove(&public, &witness).unwrap();
    let b = second.prove(&public, &witness).unwrap();
    verifier.verify(&a, &public).unwrap();
    verifier.verify(&b, &public).unwrap();
    assert!(verifier.verify(&b, &[Val::from_u64(10)]).is_err());
    assert_ne!(postcard::to_allocvec(&a.commitments).unwrap(), postcard::to_allocvec(&b.commitments).unwrap(),
        "independent witness proofs must use fresh private randomness");
    assert_eq!(std::fs::read_dir(dir.join("shared")).unwrap().filter(|p| p.as_ref().unwrap().path().extension().is_some_and(|x| x == "prefix")).count(), 1);
    drop((first, second));
    std::fs::remove_dir_all(dir).unwrap();
}
