use super::*;
use crate::block_v2::machine::{
    programs::{self, RegistryPrefix},
    typed_finalizer, typed_pairs, typed_programs,
    verifier::{template, CompileError},
};
use crate::proving::Policy;
use p3_field::PrimeCharacteristicRing;

fn caps<const N: usize>() -> programs::Caps<N> {
    core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
}

// Shape-only objects for rejection tests and unused registration slots. These
// are never submitted to a proof verifier or represented as valid wallet proofs.
fn unused_wallet() -> recursive::WalletProof {
    let batch = template::batch(&programs::shape(16).unwrap()).unwrap();
    recursive::WalletProof {
        chain: [0; 32],
        public: vec![Val::ZERO; crate::joinsplit_air::N_PUBLIC],
        proof: p3_uni_stark::Proof {
            commitments: p3_uni_stark::Commitments {
                trace: batch.commitments.main,
                quotient_chunks: batch.commitments.quotient_chunks,
                random: batch.commitments.random,
            },
            opened_values: p3_uni_stark::OpenedValues {
                trace_local: vec![],
                trace_next: None,
                preprocessed_local: None,
                preprocessed_next: None,
                quotient_chunks: vec![],
                random: None,
            },
            opening_proof: batch.opening_proof,
            degree_bits: 0,
        },
    }
}

fn matches_reference<const N: usize>(request: Request, backend: Backend) {
    let caps = caps::<N>();
    for height in [64, 2048, 4096] {
        let (result, report) = compile_reported(request, height, N, |prefix| {
            let compiled = programs::empty_with_registry(height, &caps, Some(prefix))?;
            let reference = programs::empty(height, &caps)?;
            assert_eq!(compiled.program, reference.program);
            assert_eq!(compiled.witness, reference.witness);
            let context = Context {
                profile_id: programs::profile_id(height, &caps)?,
                chain_id: [0x21; 32],
            };
            let public =
                programs::statement(commitment::empty_subtree(context, 5)?, programs::EMPTY);
            compiled
                .program
                .evaluate(&public, &compiled.witness)
                .map_err(|error| format!("{error:?}"))?;
            Ok(())
        })
        .unwrap();
        result.unwrap();
        assert!(report.succeeded && report.stage_coverage_complete);
        assert_eq!(report.entry_point, "block_v2_registry_compilation");
        assert_eq!(report.observations.len(), 1);
        let o = &report.observations[0];
        assert_eq!(o.stage, Stage::Preprocessing);
        assert_eq!(o.backend, backend);
        assert_eq!(o.completed_calls, o.calls);
        assert!(o.calls > 0);
        if backend == Backend::Cpu {
            assert_eq!(o.device_ns, 0);
        } else {
            assert!(o.device_ns > 0);
            assert_eq!(o.inclusive_ns, 0);
        }
    }
}

#[test]
fn cpu_registry_prefix_preserves_exact_program_witness_and_profile_binding() {
    let request = Request {
        policy: Policy::CpuRequired,
        emit_report: false,
    };
    matches_reference::<3>(request, Backend::Cpu);
    matches_reference::<5>(request, Backend::Cpu);
    matches_reference::<6>(request, Backend::Cpu);
    matches_reference::<12>(request, Backend::Cpu);
}

#[cfg(feature = "gpu-cuda")]
#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_registry_compilation_preserves_programs_and_request_component_boundaries() {
    use crate::{
        cuda_compute::{Limits, PublicArithmetic, Runtime},
        proving::{Capabilities, CoverageScope, Profile},
    };
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits::default(),
    )
    .unwrap();
    let context = PublicArithmetic::new(&runtime, 1 << 16).unwrap();
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    for stage in Stage::ARITHMETIC {
        capabilities.set(stage, Backend::Cuda);
    }
    let request = Run::request(
        "cuda_public_request",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
        &[
            ("statement", CoverageScope::Statement),
            ("registry", CoverageScope::RegistryCompilation),
            ("statement_check", CoverageScope::Statement),
            ("preprocessing", CoverageScope::Preprocessing),
            ("proof", CoverageScope::RegisteredProof),
        ],
    )
    .unwrap();
    let caps = caps::<12>();
    let height = 2048;
    let reference = programs::empty(height, &caps).unwrap();
    let node = commitment::empty_subtree(
        Context {
            profile_id: programs::profile_id(height, &caps).unwrap(),
            chain_id: [0x21; 32],
        },
        5,
    )
    .unwrap();
    assert_eq!(
        derive_cuda_in(&context, &request, "statement", |derive| derive
            .empty(node.context, node.level))
        .unwrap(),
        node
    );
    let (compiled, report) = compile_cuda_in_reported(&context, &request, height, 12, |prefix| {
        wrong_prefix_rejects(prefix, height * 2);
        Ok(programs::empty_with_registry(height, &caps, Some(prefix))?)
    })
    .unwrap();
    assert_eq!(compiled.program, reference.program);
    assert_eq!(compiled.witness, reference.witness);
    let public = programs::statement(node, programs::EMPTY);
    compiled
        .program
        .evaluate(&public, &compiled.witness)
        .unwrap();
    assert_eq!(
        derive_cuda_in(&context, &request, "statement_check", |derive| derive
            .summary(&public, 12))
        .unwrap(),
        node
    );
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].backend, Backend::Cuda);
    assert_eq!(report.observations[0].stage, Stage::Preprocessing);
    // Public work cannot satisfy the missing private proof/setup components.
    assert!(request.finish(true).is_err());
}

#[cfg(feature = "gpu-cuda")]
#[test]
#[ignore = "opt-in public component benchmark; requires CUDA/NVRTC"]
fn cuda_public_component_benchmark() {
    use crate::cuda_compute::{Limits, PublicArithmetic, Runtime};
    use std::time::Instant;
    assert_eq!(
        std::env::var("LATTICA_CUDA_PUBLIC_BENCHMARK").as_deref(),
        Ok("1")
    );
    let start = Instant::now();
    let runtime = Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits::default(),
    )
    .unwrap();
    let context = PublicArithmetic::new(&runtime, 1 << 16).unwrap();
    let preparation_seconds = start.elapsed().as_secs_f64();
    let caps = caps::<12>();
    let height = 2048;
    let expected_program = programs::empty(height, &caps).unwrap();
    let node = commitment::empty_subtree(
        Context {
            profile_id: programs::profile_id(height, &caps).unwrap(),
            chain_id: [0x21; 32],
        },
        5,
    )
    .unwrap();
    let public = programs::statement(node, programs::EMPTY);
    for case in ["statement", "registry_compilation"] {
        for iteration in 0..4 {
            let stage = if case == "statement" {
                Stage::PublicValues
            } else {
                Stage::Preprocessing
            };
            let run = Run::new(
                "cuda_public_component_benchmark",
                Request {
                    policy: Policy::GpuRequired,
                    emit_report: false,
                },
                PublicArithmetic::capabilities(stage).unwrap(),
            )
            .unwrap();
            let before = runtime.snapshot();
            let start = Instant::now();
            let (output, report) = operate_cuda_in(&context, run, stage, |hash| {
                if case == "statement" {
                    let derived = hash.empty(node.context, node.level)?;
                    let decoded = hash.summary(&public, 12)?;
                    Ok((Some((derived, decoded)), None))
                } else {
                    let prefix = RegistryPrefix::with_backend(
                        height,
                        12,
                        &mut |d, f| hash.hash(d, f),
                        hash.compiler_constants(),
                    )?;
                    Ok((
                        None,
                        Some(programs::empty_with_registry(height, &caps, Some(&prefix))?),
                    ))
                }
            })
            .unwrap();
            let seconds = start.elapsed().as_secs_f64();
            let after = runtime.snapshot();
            // Unchanged CPU reference checks are outside the measured region.
            if let Some((derived, decoded)) = output.0 {
                assert_eq!(derived, node);
                assert_eq!(decoded, node);
            }
            if let Some(compiled) = output.1 {
                assert_eq!(compiled.program, expected_program.program);
                assert_eq!(compiled.witness, expected_program.witness);
                compiled
                    .program
                    .evaluate(&public, &compiled.witness)
                    .unwrap();
            }
            assert_eq!(after.live_bytes, before.live_bytes);
            println!(
                "cuda_public_component_benchmark {}",
                serde_json::json!({
                    "case":case, "warmup":iteration==0, "iteration":iteration, "seconds":seconds,
                    "preparation_seconds":preparation_seconds, "cpu_reference_checked":true,
                    "completed_commands":after.completed_commands-before.completed_commands,
                    "uploaded_bytes":after.uploaded_bytes-before.uploaded_bytes,
                    "downloaded_bytes":after.downloaded_bytes-before.downloaded_bytes,
                    "peak_managed_bytes":after.peak_bytes, "report":report,
                })
            );
        }
    }
}

fn wrong_prefix_rejects(prefix: &RegistryPrefix, height: usize) {
    let wallet = unused_wallet();
    let batch = template::batch(&programs::shape(height).unwrap()).unwrap();
    let public = [Val::ZERO; PUBLIC_VALUES];
    let check = |result: Result<programs::Compiled, CompileError>| {
        assert!(matches!(
            result,
            Err(CompileError::Shape("registry prefix height/key count"))
        ));
    };
    check(programs::wrapper_with_registry(
        height,
        &caps::<3>(),
        &wallet.public,
        &wallet.proof,
        Some(prefix),
    ));
    check(programs::wrapper_pair_with_registry(
        height,
        &caps(),
        [&wallet.public; 2],
        [&wallet.proof; 2],
        Some(prefix),
    ));
    check(programs::empty_with_registry(
        height,
        &caps::<3>(),
        Some(prefix),
    ));
    check(programs::merge_with_registry(
        height,
        &caps::<3>(),
        [&public; 2],
        [&batch; 2],
        Some(prefix),
    ));
    for n in [5, 6] {
        for mode in [
            programs::WRAPPER,
            typed_programs::HTLC,
            typed_programs::ISSUANCE,
        ] {
            let values = vec![
                Val::ZERO;
                if mode == typed_programs::HTLC {
                    crate::htlc_air::N_PUBLIC
                } else {
                    crate::joinsplit_air::N_PUBLIC
                }
            ];
            if n == 5 {
                check(typed_programs::wrapper_with_registry(
                    height,
                    &caps::<5>(),
                    mode,
                    &values,
                    &wallet.proof,
                    Some(prefix),
                ));
            } else {
                check(typed_programs::wrapper_with_registry(
                    height,
                    &caps::<6>(),
                    mode,
                    &values,
                    &wallet.proof,
                    Some(prefix),
                ));
            }
        }
    }
    check(typed_finalizer::compile_with_registry(
        height,
        &caps(),
        &public,
        &batch,
        Some(prefix),
    ));
    for mode in 1..=12 {
        if typed_pairs::leaf_modes(mode).is_ok() {
            check(typed_pairs::wrapper_pair_with_registry(
                height,
                &caps(),
                mode,
                [&wallet.public; 2],
                [&wallet.proof; 2],
                Some(prefix),
            ));
        }
    }
    check(typed_pairs::finalize_with_registry(
        height,
        &caps(),
        &public,
        &batch,
        Some(prefix),
    ));
    for mode in [
        programs::WRAPPER,
        programs::EMPTY,
        programs::MERGE,
        typed_finalizer::FINALIZE,
    ] {
        check(typed_finalizer::compile_registration_with_registry(
            height,
            mode,
            Some(&wallet),
            Some(prefix),
        ));
    }
    for mode in [
        typed_pairs::mode_for([programs::WRAPPER; 2]).unwrap(),
        programs::EMPTY,
        programs::MERGE,
        typed_pairs::FINALIZE,
    ] {
        check(typed_pairs::compile_registration_with_registry(
            height,
            mode,
            Some([&wallet; 2]),
            Some(prefix),
        ));
    }
}

#[test]
fn every_compiler_rejects_mismatched_prefix_and_hash_errors_propagate() {
    let prefix = RegistryPrefix::with_hash(2048, 3, &mut |d, f| -> Result<Digest, Error> {
        Ok(commitment::hash_fields(d, f)?)
    })
    .unwrap();
    wrong_prefix_rejects(&prefix, 4096);
    // A same-height prefix cannot cross registry kinds either.
    assert!(matches!(
        programs::empty_with_registry(2048, &caps::<5>(), Some(&prefix)),
        Err(CompileError::Shape("registry prefix height/key count"))
    ));
    assert!(
        RegistryPrefix::with_hash(2048, 4, &mut |_, _| -> Result<Digest, Error> {
            panic!("bad key count must reject before hash")
        })
        .is_err()
    );
    let result = RegistryPrefix::with_hash(2048, 3, &mut |_, _| -> Result<Digest, Error> {
        Err("injected registry backend failure".into())
    });
    assert_eq!(
        result.err().unwrap().to_string(),
        "injected registry backend failure"
    );
}

#[test]
fn strict_gpu_compilation_rejects_before_metadata_or_hash_work() {
    assert!(compile_reported(
        Request {
            policy: Policy::GpuRequired,
            emit_report: false
        },
        usize::MAX,
        3,
        |_| -> Result<(), Error> { panic!("must reject before compiler") }
    )
    .is_err());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_registry_compilation_matches_cpu_programs_and_retains_failure_reports() {
    use crate::block_v2::gpu_hash;
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let request = Request::compatible();
    matches_reference::<3>(request, Backend::OpenCl);
    matches_reference::<5>(request, Backend::OpenCl);
    matches_reference::<6>(request, Backend::OpenCl);
    matches_reference::<12>(request, Backend::OpenCl);
    let (result, report) = compile_reported(request, 2048, 3, |prefix| -> Result<(), Error> {
        wrong_prefix_rejects(prefix, 4096);
        Err("injected post-hash compilation failure".into())
    })
    .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "injected post-hash compilation failure"
    );
    assert!(!report.succeeded && !report.stage_coverage_complete);
    assert!(report.observations[0].completed_calls > 0 && report.observations[0].device_ns > 0);
    let keys = caps::<3>();
    let expected = programs::empty(2048, &keys).unwrap();
    let (result, report) = compile_reported(
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        2048,
        3,
        |prefix| Ok(programs::empty_with_registry(2048, &keys, Some(prefix))?),
    )
    .unwrap();
    let actual = result.unwrap();
    assert_eq!(actual.program, expected.program);
    assert_eq!(actual.witness, expected.witness);
    assert!(report.succeeded && report.stage_coverage_complete);
    assert_eq!(
        report.capabilities.scope(),
        crate::proving::CoverageScope::RegistryCompilation
    );
    let baseline = gpu_hash::report("registry before admission").unwrap();
    for policy in [Policy::CpuRequired] {
        assert!(compile_reported(
            Request {
                policy,
                emit_report: false
            },
            2048,
            3,
            |_| -> Result<(), Error> { panic!("admission must precede hashing") }
        )
        .is_err());
    }
    let after = gpu_hash::report("registry after admission").unwrap();
    assert_eq!(baseline.allocations, after.allocations);
    assert_eq!(baseline.uploaded_bytes, after.uploaded_bytes);
    matches_reference::<3>(request, Backend::OpenCl);
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires selected GPU witness backend and <=3 GiB zero-swap service"]
fn gpu_registration_entrypoints_preserve_cpu_compiler_caps() {
    use crate::block_v2::machine::{backend::RegisteredProgram, MachineAir};
    use crate::block_v2::{gpu_hash, typed_recursive};
    let _shutdown = gpu_hash::TestShutdownGuard;
    super::tests::initialize();
    let height = 2048;
    let wallet = unused_wallet();
    fn reference<const N: usize>(height: usize) -> Vec<[Val; 4]> {
        let compiled = programs::empty(height, &caps::<N>()).unwrap();
        RegisteredProgram::new_with_memory_budget(
            MachineAir::new(compiled.program.pad_to(height).unwrap()),
            1 << 30,
        )
        .unwrap()
        .preprocessing_cap()
        .roots()
        .to_vec()
    }
    assert_eq!(
        recursive::register(height, programs::EMPTY, None).unwrap(),
        reference::<3>(height)
    );
    assert_eq!(
        recursive::WrapperConstruction::GroupedPair
            .register(height, programs::EMPTY, None)
            .unwrap(),
        reference::<3>(height)
    );
    assert_eq!(
        typed_recursive::register(height, programs::EMPTY, None, 1 << 30).unwrap(),
        reference::<5>(height)
    );
    assert_eq!(
        typed_recursive::register_finalized(height, programs::EMPTY, None, 1 << 30).unwrap(),
        reference::<6>(height)
    );
    assert_eq!(
        typed_recursive::register_paired(height, programs::EMPTY, [&wallet; 3], 1 << 30).unwrap(),
        reference::<12>(height)
    );
}
