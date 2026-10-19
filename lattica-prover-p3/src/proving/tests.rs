use super::*;

fn request(policy: Policy) -> Request {
    Request {
        policy,
        emit_report: false,
    }
}

#[test]
fn policy_parser_is_explicit_and_gpu_feature_does_not_admit_cpu_proving() {
    assert_eq!(Policy::parse(None), Ok(Policy::Compatible));
    assert_eq!(Policy::parse(Some("gpu-required")), Ok(Policy::GpuRequired));
    for bad in ["gpu", "", "1", "GPU", "gpu-required "] {
        assert_eq!(Policy::parse(Some(bad)), Err(Error::InvalidPolicy));
    }
    for profile in [Profile::LegacyQuadratic, Profile::BlockV2Cubic] {
        let capabilities = Capabilities::cpu(profile, true, true);
        assert!(capabilities.admit(Policy::CpuRequired).is_ok());
        assert!(matches!(
            capabilities.admit(Policy::GpuRequired),
            Err(Error::Unsupported { .. })
        ));
    }
}

#[test]
fn wallet_entry_points_reject_before_invalid_trace_or_batch_inputs_are_used() {
    // These invalid witnesses/batches would panic or do work if admission were late.
    let mut js = crate::joinsplit_air::demo_witness();
    js.fee = u64::MAX;
    let mut htlc = crate::htlc_air::demo_witness();
    htlc.fee = u64::MAX;
    let required = request(Policy::GpuRequired);
    assert!(matches!(
        crate::joinsplit_air::prove_to_bytes_with_request(&js, required),
        Err(Error::Unsupported { .. })
    ));
    assert!(matches!(
        crate::htlc_air::prove_to_bytes_with_request(&htlc, required),
        Err(Error::Unsupported { .. })
    ));
    assert!(matches!(
        crate::batch_joinsplit_air::prove_batch_to_bytes_with_request(&[], required),
        Err(Error::Unsupported { .. })
    ));
    assert!(matches!(
        crate::batch_htlc_air::prove_batch_to_bytes_with_request(&[], required),
        Err(Error::Unsupported { .. })
    ));
}

#[test]
fn environment_policy_also_guards_standalone_cpu_proving_helpers() {
    const CHILD: &str = "LATTICA_TEST_PROVING_POLICY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut js = crate::joinsplit_air::demo_witness();
        js.fee = u64::MAX;
        let mut htlc = crate::htlc_air::demo_witness();
        htlc.fee = u64::MAX;
        assert!(crate::joinsplit_air::prove_verify(&js).is_err());
        assert!(crate::joinsplit_air::prove_verify_with(&js, &[]).is_err());
        assert!(crate::joinsplit_air::prove_real_verify_with(&js, &[]).is_err());
        assert!(crate::htlc_air::prove_verify(&htlc).is_err());
        assert!(crate::htlc_air::prove_verify_with(&htlc, &[]).is_err());
        assert!(crate::htlc_air::prove_real_verify_with(&htlc, &[]).is_err());
        return;
    }
    // Isolate process-global environment from concurrently running tests.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "proving::tests::environment_policy_also_guards_standalone_cpu_proving_helpers",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("LATTICA_PROVING_POLICY", "gpu-required")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_advertised_gpu_path_cannot_execute_a_cpu_or_opaque_fallback() {
    // A synthetic capability set exercises runtime enforcement, not GPU correctness.
    let mut capabilities = legacy_cpu();
    for entry in &mut capabilities.stages {
        entry.backend = Backend::OpenCl;
    }
    let run = Run::new("test", request(Policy::GpuRequired), capabilities).unwrap();
    for (stage, backend) in [
        (Stage::Quotient, Backend::Cpu),
        (Stage::FriFold, Backend::Mixed),
        (Stage::UpstreamProver, Backend::OpenCl),
        (Stage::ConstraintAudit, Backend::Cpu),
    ] {
        assert!(matches!(
            run.measure(stage, backend, || panic!("must not execute fallback")),
            Err(Error::StageRejected { .. })
        ));
    }
    assert!(run
        .measure(Stage::Serialization, Backend::Cpu, || ())
        .is_ok());
    assert!(!run.finish(false).unwrap().stage_coverage_complete);
}

#[test]
fn reports_do_not_infer_coverage_from_an_opaque_upstream_timer() {
    let run = Run::new("test", Request::compatible(), legacy_cpu()).unwrap();
    run.measure(Stage::UpstreamProver, Backend::Cpu, || 17)
        .unwrap();
    let report = run.finish(true).unwrap();
    assert!(report.succeeded);
    assert!(!report.stage_coverage_complete);
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].completed_calls, 1);
}

#[test]
fn observations_are_bounded_and_shared_with_parallel_work() {
    let run = Run::new("test", Request::compatible(), legacy_cpu()).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let run = &run;
            scope.spawn(move || {
                for _ in 0..100 {
                    run.measure(Stage::Quotient, Backend::Cpu, || 1).unwrap();
                }
            });
        }
    });
    let report = run.finish(true).unwrap();
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].calls, 800);
    assert_eq!(report.observations[0].completed_calls, 800);
}

#[test]
fn unwind_marks_the_stage_incomplete_without_poisoning_the_ledger() {
    let run = Run::new("test", Request::compatible(), legacy_cpu()).unwrap();
    let result = std::panic::catch_unwind(|| {
        run.measure(Stage::WitnessTrace, Backend::Cpu, || {
            panic!("invalid witness")
        })
        .unwrap();
    });
    assert!(result.is_err());
    let report = run.finish(false).unwrap();
    assert!(!report.stage_coverage_complete);
    assert_eq!(report.observations[0].calls, 1);
    assert_eq!(report.observations[0].completed_calls, 0);
}

#[cfg(feature = "block-v2")]
#[test]
fn cubic_wallet_requests_reject_before_context_or_witness_arithmetic() {
    use crate::block_v2::{commitment::Context, leaf, typed_leaf};
    let context = Context {
        profile_id: [0; 32],
        chain_id: [0; 32],
    };
    let js = crate::joinsplit_air::demo_witness();
    let htlc = crate::htlc_air::demo_witness();
    let required = request(Policy::GpuRequired);
    assert_eq!(
        leaf::prove_joinsplit_with_request(&js, &context, required),
        Err(leaf::LeafError::ProvingPolicy)
    );
    assert_eq!(
        typed_leaf::prove_htlc_with_request(&htlc, &context, required),
        Err(typed_leaf::Error::Leaf(leaf::LeafError::ProvingPolicy))
    );
    assert_eq!(
        typed_leaf::prove_issuance_with_request(&js, &context, 0, required),
        Err(typed_leaf::Error::Leaf(leaf::LeafError::ProvingPolicy))
    );
}

#[cfg(feature = "block-v2")]
#[test]
fn registered_program_checks_policy_before_preprocessing_or_trace() {
    use crate::block_v2::machine::{
        analysis::AdmissionError, backend::RegisteredProgram, ExecutionError, MachineAir,
        ProgramBuilder,
    };
    let mut builder = ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    builder.assert_equal(input, builder.public(0).unwrap());
    let air = MachineAir::new(builder.finish(Some(8)).unwrap());
    let required = request(Policy::GpuRequired);
    assert!(matches!(
        RegisteredProgram::new_with_request(air.clone(), 0, required),
        Err(AdmissionError::ProvingPolicy(_))
    ));
    let registered =
        RegisteredProgram::new_with_request(air, 1 << 30, Request::compatible()).unwrap();
    assert!(matches!(
        registered.prove_with_request(&[], &[], required),
        Err(ExecutionError::ProvingPolicy)
    ));
}

#[test]
#[ignore = "real production-strength CPU proof"]
fn observed_wallet_proof_still_verifies_with_the_unchanged_verifier() {
    let witness = crate::joinsplit_air::demo_witness();
    let (bytes, report) =
        crate::joinsplit_air::prove_to_bytes_with_request(&witness, request(Policy::CpuRequired))
            .unwrap();
    assert!(crate::joinsplit_air::verify_bytes(
        &bytes,
        &crate::joinsplit_air::public_values(&witness)
    ));
    assert!(report.succeeded);
    assert!(!report.stage_coverage_complete);
    assert_eq!(
        report
            .observations
            .iter()
            .map(|o| o.stage)
            .collect::<Vec<_>>(),
        [
            Stage::PublicValues,
            Stage::WitnessTrace,
            Stage::UpstreamProver,
            Stage::Serialization
        ]
    );
}

#[test]
fn gpu_wall_envelopes_alone_never_complete_stage_coverage() {
    let mut capabilities = legacy_cpu();
    for entry in &mut capabilities.stages {
        entry.backend = Backend::OpenCl;
    }
    let stages: Vec<_> = capabilities.stages.iter().map(|s| s.stage).collect();
    let run = Run::new(
        "synthetic_envelopes",
        request(Policy::GpuRequired),
        capabilities,
    )
    .unwrap();
    for stage in stages {
        run.measure(stage, Backend::OpenCl, || ()).unwrap();
    }
    let Error::IncompleteCoverage {
        missing,
        unaccounted,
        observation_errors,
        ..
    } = run.finish(true).unwrap_err()
    else {
        panic!("wall-only inventory must fail strict completion");
    };
    assert_eq!(missing.len(), legacy_cpu().stages.len());
    assert!(unaccounted.is_empty());
    assert_eq!(observation_errors, 0);
}

#[test]
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn lost_device_observations_prevent_a_coverage_claim() {
    for lose_observation in [false, true] {
        // Synthetic receipts test ledger semantics, not GPU execution.
        let mut capabilities = legacy_cpu();
        for entry in &mut capabilities.stages {
            entry.backend = Backend::OpenCl;
        }
        let stages: Vec<_> = capabilities.stages.iter().map(|s| s.stage).collect();
        let run = Run::new(
            "synthetic_receipts",
            request(Policy::GpuRequired),
            capabilities,
        )
        .unwrap();
        for stage in stages {
            run.observe_device(stage, Backend::OpenCl, 1, 100).unwrap();
        }
        if lose_observation {
            run.observation_failed();
        }
        let result = run.finish(true);
        if lose_observation {
            assert!(matches!(
                result,
                Err(Error::IncompleteCoverage {
                    observation_errors: 1,
                    ..
                })
            ));
        } else {
            let report = result.unwrap();
            assert!(
                report.succeeded && report.stage_coverage_complete && !report.completion_rejected
            );
            assert_eq!(report.observation_errors, 0);
        }
    }
}

#[test]
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn device_observation_overflow_keeps_prior_receipts_and_invalidates_coverage() {
    for (calls, ns) in [(u64::MAX, 1), (1, u128::MAX)] {
        let run = Run::new("counter_overflow", Request::compatible(), legacy_cpu()).unwrap();
        run.observe_device(Stage::Transform, Backend::OpenCl, 1, 100)
            .unwrap();
        assert!(matches!(
            run.observe_device(Stage::Transform, Backend::OpenCl, calls, ns),
            Err(Error::ObservationOverflow)
        ));
        let report = run.finish(true).unwrap();
        assert_eq!(report.observation_errors, 1);
        assert!(!report.stage_coverage_complete);
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].device_calls, 1);
        assert_eq!(report.observations[0].device_ns, 100);
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn transform_inventory() -> Capabilities {
    let mut capabilities = legacy_cpu();
    capabilities
        .stages
        .retain(|entry| entry.stage == Stage::Transform);
    capabilities.set(Stage::Transform, Backend::OpenCl);
    capabilities
}

#[test]
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn strict_completion_rejects_partial_unlisted_and_interrupted_work() {
    for fault in ["missing", "unlisted", "interrupted"] {
        let run = Run::new(
            "completion_fault",
            request(Policy::GpuRequired),
            transform_inventory(),
        )
        .unwrap();
        run.observe_device(
            Stage::Transform,
            Backend::OpenCl,
            u64::from(fault != "missing"),
            100,
        )
        .unwrap();
        if fault == "unlisted" {
            run.observe_device(Stage::FriFold, Backend::OpenCl, 1, 100)
                .unwrap();
        }
        if fault == "interrupted" {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run.measure(Stage::Transform, Backend::OpenCl, || {
                    panic!("incomplete operation")
                })
                .unwrap();
            }))
            .is_err());
        }
        let Error::IncompleteCoverage {
            missing,
            unaccounted,
            observation_errors,
            missing_components: _,
        } = run.finish(true).unwrap_err()
        else {
            panic!("{fault} must prevent strict completion");
        };
        assert_eq!(missing.len(), usize::from(fault == "missing"));
        assert_eq!(unaccounted.len(), usize::from(fault != "missing"));
        assert_eq!(observation_errors, 0);
    }
}

#[test]
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn compatible_completion_reports_unlisted_cpu_work_without_rejecting_output() {
    let run = Run::new(
        "compatible_fault",
        Request::compatible(),
        transform_inventory(),
    )
    .unwrap();
    run.observe_device(Stage::Transform, Backend::OpenCl, 1, 100)
        .unwrap();
    run.measure(Stage::Transform, Backend::Cpu, || ()).unwrap();
    let report = run.finish(true).unwrap();
    assert!(report.succeeded && !report.stage_coverage_complete && !report.completion_rejected);
    assert_eq!(report.observations.len(), 2);
}

#[test]
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn strict_completion_allows_host_serialization_and_preserves_failed_outcomes() {
    let run = Run::new(
        "host_serialization",
        request(Policy::GpuRequired),
        transform_inventory(),
    )
    .unwrap();
    run.observe_device(Stage::Transform, Backend::OpenCl, 1, 100)
        .unwrap();
    let encoded = run
        .measure(Stage::Serialization, Backend::Cpu, || vec![1, 2, 3])
        .unwrap();
    let report = run.finish(true).unwrap();
    assert_eq!(encoded, [1, 2, 3]);
    assert!(report.succeeded && report.stage_coverage_complete && !report.completion_rejected);
    let run = Run::new(
        "prior_failure",
        request(Policy::GpuRequired),
        transform_inventory(),
    )
    .unwrap();
    let report = run.finish(false).unwrap();
    assert!(!report.succeeded && !report.stage_coverage_complete && !report.completion_rejected);
}

#[test]
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
fn complete_component_receipts_do_not_complete_a_whole_request() {
    let mut capabilities = legacy_cpu();
    for stage in &mut capabilities.stages {
        stage.backend = Backend::OpenCl;
    }
    let component = capabilities
        .clone()
        .scoped(CoverageScope::Statement, &[Stage::PublicValues]);
    let run = Run::new("scoped_statement", request(Policy::GpuRequired), component).unwrap();
    run.observe_device(Stage::PublicValues, Backend::OpenCl, 1, 100)
        .unwrap();
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(report.capabilities.scope(), CoverageScope::Statement);
    let run = Run::new("whole_request", request(Policy::GpuRequired), capabilities).unwrap();
    run.observe_device(Stage::PublicValues, Backend::OpenCl, 1, 100)
        .unwrap();
    assert!(matches!(
        run.finish(true),
        Err(Error::IncompleteCoverage { .. })
    ));
}

#[test]
#[cfg(all(feature = "gpu", feature = "block-v2"))]
#[ignore = "requires bounded OpenCL GPU; <=3 GiB zero-swap service"]
fn strict_native_completion_withholds_outputs_without_receipts_and_releases_buffers() {
    use crate::block_v2::gpu_hash::{
        self,
        device::{DeviceSession, Extension, MatrixSpec, RowOrder},
    };
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_quotient_test_engine(gpu_hash::Limits {
        managed_bytes: 256 << 20,
        tile_bytes: 16 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let session = DeviceSession::new().unwrap();
    let spec = MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::BitReversed, 1).unwrap();
    let input = session.upload(spec, &vec![0; spec.words()]).unwrap();
    let live = gpu_hash::report("strict completion input")
        .unwrap()
        .managed_live_bytes;
    for (omit_receipts, lose_observation) in [(true, false), (false, true), (false, false)] {
        // Only this real FRI operation is admitted; this does not qualify a full prover.
        let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
        capabilities
            .stages
            .retain(|entry| entry.stage == Stage::FriFold);
        capabilities.set(Stage::FriFold, Backend::OpenCl);
        let capabilities = capabilities.scoped(CoverageScope::Operation, &[Stage::FriFold]);
        let run = Run::new(
            "native_completion",
            Request {
                policy: Policy::GpuRequired,
                emit_report: true,
            },
            capabilities,
        )
        .unwrap();
        let output = (|| -> Result<_, Error> {
            let folded = {
                let _observation =
                    (!omit_receipts).then(|| session.observe_execution(&run).unwrap());
                session.fold_cubic(&input, [7, 0, 0]).unwrap()
            };
            if lose_observation {
                run.observation_failed();
            }
            let report = run.finish(true)?;
            Ok((folded, report))
        })();
        if omit_receipts || lose_observation {
            let Err(Error::IncompleteCoverage {
                missing,
                unaccounted,
                observation_errors,
                missing_components: _,
            }) = output
            else {
                panic!("native output must be withheld");
            };
            assert_eq!(missing.len(), usize::from(omit_receipts));
            assert!(unaccounted.is_empty());
            assert_eq!(observation_errors, u64::from(lose_observation));
        } else {
            let (folded, report) = output.unwrap();
            assert!(
                report.succeeded && report.stage_coverage_complete && !report.completion_rejected
            );
            assert_eq!(report.observations[0].device_calls, 1);
            assert!(report.observations[0].device_ns > 0);
            drop(folded);
        }
        assert_eq!(
            gpu_hash::report("strict completion released")
                .unwrap()
                .managed_live_bytes,
            live
        );
    }
    drop((input, session));
    gpu_hash::shutdown().unwrap();
}
mod entrypoints;

#[test]
fn cuda_wall_envelopes_do_not_establish_device_coverage() {
    let mut capabilities = legacy_cpu().scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::Cuda);
    let run = Run::new("cuda_envelope", request(Policy::GpuRequired), capabilities).unwrap();
    run.measure(Stage::WitnessTrace, Backend::Cuda, || ())
        .unwrap();
    assert!(matches!(
        run.finish(true),
        Err(Error::IncompleteCoverage { .. })
    ));
}

#[test]
#[cfg(feature = "gpu-cuda")]
fn cuda_receipts_obey_policy_and_scoped_inventory() {
    // Synthetic observations exercise enforcement only, not GPU correctness.
    let mut capabilities = legacy_cpu().scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::Cuda);
    assert!(Run::new(
        "cuda_cpu_required",
        request(Policy::CpuRequired),
        capabilities.clone()
    )
    .is_err());
    let run = Run::new("cuda_receipts", request(Policy::GpuRequired), capabilities).unwrap();
    assert!(run
        .check_device_stage(Stage::WitnessTrace, Backend::Cpu)
        .is_err());
    run.observe_device(Stage::WitnessTrace, Backend::Cuda, 2, 200)
        .unwrap();
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete);
    assert_eq!(report.observations[0].device_calls, 2);
    assert_eq!(report.observations[0].device_ns, 200);
}
