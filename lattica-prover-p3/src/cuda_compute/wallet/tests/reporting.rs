use super::*;

fn request() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_wallet_requests_have_complete_receipts_and_pass_unchanged_cpu_verification() {
    let runtime = open_runtime(limits());
    let prover = WalletProver::new(&runtime).unwrap();
    let joinsplit = prover.prepare_joinsplit(256 << 20).unwrap();
    let htlc = prover.prepare_htlc(256 << 20).unwrap();
    macro_rules! verify {
        ($prepared:expr, $witness:expr, $air:expr, $statement:path) => {{
            let witness = $witness;
            let before = runtime.snapshot();
            let result = $prepared.prove(&witness, request(), 64 << 20).unwrap();
            let after = runtime.snapshot();
            let report = &result.report;
            assert!(report.succeeded && report.stage_coverage_complete);
            assert_eq!(report.capabilities.scope(), CoverageScope::ProofRequest);
            assert_eq!(report.capabilities.stages().len(), 14);
            assert_eq!(report.observations.len(), 14);
            assert_eq!(report.observation_errors, 0);
            for o in &report.observations {
                assert_eq!(o.backend, Backend::Cuda);
                assert_eq!(o.calls, o.completed_calls);
                assert_eq!(o.calls, o.device_calls);
                assert!(o.calls > 0);
                assert_eq!(o.inclusive_ns, 0);
            }
            assert_eq!(
                report
                    .observations
                    .iter()
                    .map(|o| o.device_calls)
                    .sum::<u64>(),
                after.completed_commands - before.completed_commands
            );
            assert_eq!(
                report
                    .observations
                    .iter()
                    .map(|o| o.device_ns)
                    .sum::<u128>(),
                after.device_ns - before.device_ns
            );
            assert_eq!(
                report
                    .observations
                    .iter()
                    .find(|o| o.stage == Stage::WitnessTrace)
                    .unwrap()
                    .calls,
                2
            );
            assert_eq!(
                report
                    .observations
                    .iter()
                    .find(|o| o.stage == Stage::PublicValues)
                    .unwrap()
                    .calls,
                1
            );
            assert_eq!(result.public_values, $statement(&witness));
            p3_uni_stark::verify(
                &crate::config::make_config(),
                &$air,
                &result.proof,
                &result.public_values,
            )
            .unwrap();
            let mut altered = result.public_values.clone();
            altered[0] += Val::ONE;
            assert!(p3_uni_stark::verify(
                &crate::config::make_config(),
                &$air,
                &result.proof,
                &altered
            )
            .is_err());
            let mut altered_proof = result.proof;
            altered_proof.opened_values.quotient_chunks[0][0] += Challenge::ONE;
            assert!(p3_uni_stark::verify(
                &crate::config::make_config(),
                &$air,
                &altered_proof,
                &result.public_values
            )
            .is_err());
            assert_eq!(runtime.snapshot(), after);
            assert_eq!(after.live_bytes, before.live_bytes);
            assert_eq!(after.allocations, before.allocations);
            assert_eq!(after.pending_commands, 0);
        }};
    }
    verify!(
        joinsplit,
        super::joinsplit(1),
        js::JoinSplitAir,
        js::public_values
    );
    verify!(htlc, super::htlc(1), htlc::HtlcAir, htlc::public_values);
    verify!(htlc, super::htlc(2), htlc::HtlcAir, htlc::public_values);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_wallet_request_failures_publish_no_proof_and_retries_use_fresh_randomness() {
    let runtime = open_runtime(limits());
    let prover = WalletProver::new(&runtime).unwrap();
    let prepared = prover.prepare_joinsplit(256 << 20).unwrap();
    let witness = joinsplit(1);
    let before = runtime.snapshot();
    assert!(prepared
        .prove(
            &witness,
            Request {
                policy: Policy::CpuRequired,
                emit_report: false
            },
            64 << 20
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(prepared.prove(&witness, request(), 1).is_err());
    assert_eq!(runtime.snapshot(), before);
    // The trace/public kernels complete before the STARK host allowance fails.
    assert!(prepared.prove(&witness, request(), 64 << 10).is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    let first = prepared.prove(&witness, request(), 64 << 20).unwrap();
    let second = prepared.prove(&witness, request(), 64 << 20).unwrap();
    for result in [&first, &second] {
        assert!(result.report.stage_coverage_complete);
        p3_uni_stark::verify(
            &crate::config::make_config(),
            &js::JoinSplitAir,
            &result.proof,
            &result.public_values,
        )
        .unwrap();
    }
    assert_ne!(
        postcard::to_allocvec(&first.proof).unwrap(),
        postcard::to_allocvec(&second.proof).unwrap()
    );
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_wallet_manual_reporter_rejects_the_wrong_run_without_duplicate_receipts() {
    let runtime = open_runtime(limits());
    let wallets = Wallets::new(&runtime).unwrap();
    let owner = run();
    let wrong = run();
    runtime
        .reported(&owner, || {
            let before = runtime.snapshot();
            assert!(wallets.joinsplit(&joinsplit(1), 1 << 20, &wrong).is_err());
            assert_eq!(runtime.snapshot(), before);
            wallets.joinsplit(&joinsplit(1), 1 << 20, &owner)
        })
        .unwrap();
    finish(owner);
    assert!(wrong.finish(true).is_err());
}
