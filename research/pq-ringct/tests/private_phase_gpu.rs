#![cfg(feature = "native-spend-oracle")]
//! Explicit post-freeze qualification, not a benchmark or completion receipt.
use lattica_pq_ringct_research::{
    execution::ProvingContext,
    native::{
        self,
        private_spend_fixture::{generate_spend_fixture, oracle as reference, NativeSpendFixture},
        FixtureAmounts,
    },
    opencl::Limits,
};
use lattica_prover_p3::{
    block_v2::native_gpu::private_spend::{phase_oracle, SpendLimits},
    proving::{Backend, CoverageScope, Policy, Profile, Request, Stage},
};
use std::sync::atomic::{compiler_fence, Ordering};

const CONTEXT: [u8; 32] = [0x4d; 32];
const SETUP_SEED: [u8; 32] = [0xa3; 32];
const HOST_BYTES: usize = 24 << 30;
struct Key([u8; 32]);
impl Drop for Key {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
fn request() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    }
}
fn admitted() -> Result<(), &'static str> {
    if std::env::var("LATTICA_NATIVE_SPEND_QUALIFICATION").as_deref() != Ok("1") {
        return Err("explicit post-freeze phase qualification admission is missing");
    }
    if !native::available() {
        return Err("native phase reference CPU ISA prerequisites are missing");
    }
    Ok(())
}
fn fixture(index: u64, amounts: FixtureAmounts) -> Result<NativeSpendFixture, &'static str> {
    generate_spend_fixture(CONTEXT, Some(SETUP_SEED), index, amounts)
        .map_err(|_| "phase fixture input generation failed")
}
fn ordinary() -> Result<NativeSpendFixture, &'static str> {
    fixture(
        4,
        FixtureAmounts {
            input: [29, 31],
            output: [23, 37],
        },
    )
}
fn with_context(work: impl FnOnce() -> Result<(), &'static str>) -> Result<(), &'static str> {
    admitted()?;
    let context = ProvingContext::opencl(Limits {
        host_bytes: 32 << 30,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    })
    .map_err(|_| "phase diagnostic context admission failed")?;
    let result = work();
    let cleanup = context
        .close_without_completion()
        .map_err(|_| "phase diagnostic context cleanup failed")?;
    if cleanup["completion_claimed"] != false
        || cleanup["session_closed"] != true
        || cleanup["session_cleanup"]["completion_claimed"] != false
        || cleanup["session_cleanup"]["completion_scope"] != "cleanup_only"
        || cleanup["session_cleanup"]["stark_completion_claimed"] != false
        || cleanup["session_cleanup"]["validated_native_spend_reports"].as_u64() != Some(0)
        || cleanup["session_cleanup"]["queue_drained"] != true
        || cleanup["session_cleanup"]["context_closed"] != true
    {
        return Err("phase diagnostic teardown incorrectly claimed proving completion");
    }
    for field in [
        "native_cpu_calls",
        "native_gpu_calls",
        "prove_calls",
        "native_spend_calls",
        "native_spend_succeeded",
        "native_spend_complete_reports",
    ] {
        if cleanup["operations"][field].as_u64() != Some(0) {
            return Err("phase diagnostic was counted as a native spend or STARK proof");
        }
    }
    result
}

fn phase_parity() -> Result<(), &'static str> {
    with_context(|| {
        let edge = (1u64 << 52) - 1;
        let cases = [
            (
                0,
                FixtureAmounts {
                    input: [0, 0],
                    output: [0, 0],
                },
            ),
            (
                4,
                FixtureAmounts {
                    input: [29, 31],
                    output: [23, 37],
                },
            ),
            (
                9,
                FixtureAmounts {
                    input: [edge, 1],
                    output: [edge - 1, 2],
                },
            ),
        ];
        for (case, (index, amounts)) in cases.into_iter().enumerate() {
            let key = Key([0x31 + case as u8; 32]);
            let input = fixture(index, amounts)?;
            let cpu = reference::spend(&input, &key.0, 1024)
                .map_err(|_| "native phase reference spend failed")?;
            let input = input
                .into_gpu_request()
                .map_err(|_| "phase witness conversion failed")?;
            let (gpu, records, report, evidence) =
                phase_oracle::spend(input, SpendLimits::bounded(HOST_BYTES), request(), key.0)
                    .map_err(|_| "GPU phase diagnostic spend failed")?;
            if gpu.statement != cpu.statement
                || gpu.proof != cpu.proof
                || !cpu.output_keys_equal(gpu.output_keys.polynomials())
            {
                return Err("phase capture changed deterministic native spend outputs");
            }
            // Compare every actual checkpoint, including rejected attempts.
            // No assertion renders a private digest, value, index or counter.
            if records.records().len() != cpu.phases().len()
                || records
                    .records()
                    .iter()
                    .zip(cpu.phases())
                    .any(|(gpu, cpu)| {
                        gpu.phase != cpu.phase
                            || gpu.component != cpu.component
                            || gpu.bytes != cpu.bytes
                            || gpu.digest != cpu.digest
                            || gpu.private_blocks != cpu.private_blocks
                    })
            {
                return Err("GPU private phase checkpoints differ from the native reference");
            }
            for phase in [30, 35, 40, 50, 60, 70, 80] {
                if !records.records().iter().any(|record| record.phase == phase) {
                    return Err("accepted phase diagnostic lacks a required checkpoint group");
                }
            }
            // One accepted attempt executes31 physical production dispatches:
            // 26 logical steps plus three extra EARLY and two extra LATE jobs.
            // Seven capture events and two explicit trace wipes make40 total.
            if report.entry_point != phase_oracle::ENTRY_POINT
                || report.entry_point == "native_matrict_spend"
                || report.policy != Policy::GpuRequired
                || !report.succeeded
                || !report.stage_coverage_complete
                || report.completion_rejected
                || report.observation_errors != 0
                || !report.components.is_empty()
                || report.capabilities.profile() != Profile::MatrictN10
                || report.capabilities.scope() != CoverageScope::Operation
                || report.observations.len() != 1
                || report.observations.iter().any(|o| {
                    o.stage != Stage::WitnessTrace
                        || o.backend != Backend::OpenCl
                        || o.calls < 40
                        || o.calls != o.completed_calls
                        || o.device_calls != o.completed_calls
                })
                || evidence.prelude_steps != 0x3f
                || evidence.accepted_attempt_steps != 0x03ff_ffc0
            {
                return Err("phase diagnostic lacks isolated strict GPU execution evidence");
            }
            if !native::verify(&CONTEXT, &gpu.statement, &gpu.proof)
                .map_err(|_| "phase diagnostic public verifier failed")?
            {
                return Err("phase diagnostic output failed independent native verification");
            }
        }
        // These finite witnesses do not claim all rejection branches execute.
        Ok(())
    })
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_phase_digests_and_private_rng_cursors_match_c() {
    if let Err(message) = phase_parity() {
        panic!("{message}");
    }
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_phase_limits_refuse_truncation_and_failures_cleanup() {
    let result = (|| -> Result<(), &'static str> {
        admitted()?;
        let key = Key([0x63; 32]);
        for attempts in [0, phase_oracle::MAX_ATTEMPTS + 1] {
            let input = ordinary()?
                .into_gpu_request()
                .map_err(|_| "phase refusal input failed")?;
            let mut limits = SpendLimits::bounded(HOST_BYTES);
            limits.max_attempts = attempts;
            match phase_oracle::spend(input, limits, request(), key.0) {
                Err(message) if message == "phase diagnostic attempts must be in 1..=8192" => {}
                _ => return Err("phase diagnostic accepted an out-of-bound record capacity"),
            }
        }
        for policy in [Policy::CpuRequired, Policy::Compatible] {
            let input = ordinary()?
                .into_gpu_request()
                .map_err(|_| "phase refusal input failed")?;
            match phase_oracle::spend(
                input,
                SpendLimits::bounded(HOST_BYTES),
                Request {
                    policy,
                    emit_report: false,
                },
                key.0,
            ) {
                Err(message)
                    if message == "phase diagnostic requires explicit GPU-required policy" => {}
                _ => return Err("phase diagnostic accepted a non-GPU policy"),
            }
        }
        for kind in 0..3 {
            with_context(|| {
                let input = ordinary()?
                    .into_gpu_request()
                    .map_err(|_| "phase failure input failed")?;
                let mut limits = SpendLimits::bounded(HOST_BYTES);
                if kind == 0 {
                    // Fits ordinary spend transfer staging, but not the two
                    // full-capacity phase record buffers admitted on host.
                    limits.host_bytes = 4 << 20;
                    limits.max_attempts = phase_oracle::MAX_ATTEMPTS;
                } else if kind == 1 {
                    limits.random_call_limit = 1;
                } else {
                    limits.proposal_limit = 1;
                }
                let result = phase_oracle::spend(input, limits, request(), key.0);
                match result {
                    Err(message)
                        if kind == 0
                            && message
                                == "native spend transfer staging exceeds host admission" =>
                    {
                        Ok(())
                    }
                    Err(message)
                        if kind != 0
                            && message
                                .starts_with("native spend device reported fatal status bits ") =>
                    {
                        Ok(())
                    }
                    _ => Err("phase staging or device exhaustion failed to refuse cleanly"),
                }
            })?;
        }
        Ok(())
    })();
    if let Err(message) = result {
        panic!("{message}");
    }
}
