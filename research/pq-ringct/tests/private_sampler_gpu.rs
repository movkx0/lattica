#![cfg(feature = "native-spend-oracle")]
//! Serialized, explicitly admitted qualification. No performance baseline.
//! Sampler probes are diagnostics and never establish full-spend completion.

use lattica_pq_ringct_research::{
    execution::ProvingContext,
    native::{self, private_spend_fixture::oracle as reference},
    opencl::Limits,
};
use lattica_prover_p3::{
    block_v2::native_gpu::private_spend::oracle::{self, SamplerLimits},
    proving::{Backend, CoverageScope, Policy, Profile, Request, Stage},
};
use std::sync::atomic::{compiler_fence, Ordering};

const HOST_BYTES: usize = 1 << 20;
struct Key([u8; 32]);
impl Drop for Key {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

fn admitted() -> Result<(), &'static str> {
    if std::env::var("LATTICA_NATIVE_SPEND_QUALIFICATION").as_deref() != Ok("1") {
        return Err("explicit post-freeze sampler qualification admission is missing");
    }
    if !native::available() {
        return Err("sampler reference CPU ISA prerequisites are missing");
    }
    Ok(())
}

fn request() -> Request {
    Request {
        policy: Policy::GpuRequired,
        emit_report: false,
    }
}

fn with_admitted_context(
    work: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    admitted()?;
    let context = ProvingContext::opencl(Limits {
        host_bytes: 32 << 30,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    })
    .map_err(|_| "sampler OpenCL context admission failed")?;
    let result = work();
    // Always explicitly close, including failed parity or exhausted samplers.
    // The worker has no native-spend/STARK completion receipt for these calls.
    let cleanup = context
        .close_without_completion()
        .map_err(|_| "sampler diagnostic context cleanup failed")?;
    if cleanup["completion_claimed"] != false
        || cleanup["session_cleanup"]["completion_claimed"] != false
        || cleanup["session_cleanup"]["completion_scope"] != "cleanup_only"
        || cleanup["session_cleanup"]["stark_completion_claimed"] != false
        || cleanup["session_cleanup"]["validated_native_spend_reports"].as_u64() != Some(0)
        || cleanup["session_cleanup"]["queue_drained"] != true
        || cleanup["session_cleanup"]["context_closed"] != true
        || cleanup["session_closed"] != true
    {
        return Err("sampler diagnostic teardown incorrectly claimed proving completion");
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
            return Err("sampler diagnostic was counted as native spend or STARK proving");
        }
    }
    result
}

fn sampler_diagnostic_error(message: String) -> &'static str {
    // Expose only fixed host diagnostic categories, never arbitrary backend
    // messages or private status words, RNG cursors, keys or coefficients.
    const PUBLIC_ERRORS: &[&str] = &[
        "sampler diagnostic device status failed: reserved words",
        "sampler diagnostic device status failed: phase mismatch",
        "sampler diagnostic device status failed: unexpected outcome",
        "sampler diagnostic device status failed: invalid input",
        "sampler diagnostic device status failed: counter exhausted",
        "sampler diagnostic device status failed: budget or uniform exhaustion",
        "sampler diagnostic device status failed: numerical contract",
        "sampler diagnostic device status failed: unrecognized fatal code",
        "sampler diagnostic RNG state failed",
        "sampler diagnostic scrub verification failed",
    ];
    PUBLIC_ERRORS
        .iter()
        .copied()
        .find(|&known| known == message.as_str())
        .unwrap_or("GPU sampler diagnostic failed outside status/RNG/scrub gates")
}

fn compare(key: &Key, profile: u32, one_rows: u32) -> Result<(), &'static str> {
    let cpu = reference::samples(&key.0, profile, one_rows)
        .map_err(|_| "native sampler reference failed")?;
    let (gpu, report, evidence) = oracle::samples(
        key.0,
        profile,
        one_rows,
        SamplerLimits::bounded(HOST_BYTES),
        request(),
    )
    .map_err(sampler_diagnostic_error)?;
    // Boolean comparisons never render private coefficients, seeds or cursors.
    if gpu.words() != cpu.words()
        || gpu.private_blocks() != cpu.private_blocks()
        || gpu.private_calls() != cpu.private_calls()
    {
        return Err("GPU sampler or private RNG consumption differs from C reference");
    }
    let rows = match profile {
        0 => 9,
        1 | 4 => 11,
        2 => 10,
        3 => 8,
        5 => one_rows as usize,
        _ => return Err("test supplied unsupported sampler profile"),
    };
    if gpu.words().len() != rows * 256
        || (profile == 5
            && (gpu
                .words()
                .iter()
                .any(|&word| ![0, 1, u64::MAX].contains(&word))
                || gpu.private_proposals() != 0))
        || (profile < 5 && (gpu.private_proposals() == 0 || gpu.private_proposals() % 8 != 0))
    {
        return Err("sampler output shape or proposal accounting is invalid");
    }
    if report.entry_point != oracle::ENTRY_POINT
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
        || report.observations.iter().any(|observation| {
            observation.stage != Stage::WitnessTrace
                || observation.backend != Backend::OpenCl
                || observation.calls != 6
                || observation.completed_calls != 6
                || observation.device_calls != 6
        })
        || evidence.profile != profile
        || evidence.rows != rows
        || !evidence.scrub_verified
        || evidence.managed_bytes != (32 + rows * 256 + 36 + 8) * 8
        || evidence.kernel_source_sha256.len() != 64
    {
        return Err("sampler diagnostic lacks exact isolated GPU operation evidence");
    }
    Ok(())
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_sampler_profiles_and_all_sample_one_rows_match_c() {
    let result = with_admitted_context(|| {
        // All five Gaussian profiles and every legal sample_1 row count.
        // Fixed seeds exercise repeatability; they do not cover all branches.
        for seed in [0x00, 0x5a, 0xff] {
            let key = Key([seed; 32]);
            for profile in 0..5 {
                compare(&key, profile, 0)?;
            }
            for rows in 1..=11 {
                compare(&key, 5, rows)?;
            }
        }
        Ok(())
    });
    if let Err(message) = result {
        panic!("{message}");
    }
}

#[test]
#[ignore = "requires explicit post-freeze qualification admission"]
fn gpu_sampler_host_bounds_and_cpu_policy_are_refused() {
    let result = (|| -> Result<(), &'static str> {
        admitted()?;
        let key = Key([0x42; 32]);
        for (profile, rows) in [
            (5, 0),
            (5, 12),
            (5, u32::MAX),
            (6, 0),
            (u32::MAX, 0),
            (0, 1),
        ] {
            match oracle::samples(
                key.0,
                profile,
                rows,
                SamplerLimits::bounded(HOST_BYTES),
                request(),
            ) {
                Err(message) if message == "sampler diagnostic profile or row count is invalid" => {
                }
                _ => return Err("invalid sampler shape was not rejected before device dispatch"),
            }
        }
        for kind in 0..4 {
            let mut limits = SamplerLimits::bounded(HOST_BYTES);
            match kind {
                0 => limits.host_bytes = 1,
                1 => limits.random_call_limit = 0,
                2 => limits.proposal_limit = 0,
                _ => limits.random_call_limit = (1 << 32) + 1,
            }
            match oracle::samples(key.0, 0, 0, limits, request()) {
                Err(message)
                    if message
                        == "sampler diagnostic resource limits are outside the bounded profile" => {
                }
                _ => return Err("invalid sampler budget was not rejected before device dispatch"),
            }
        }
        for policy in [Policy::CpuRequired, Policy::Compatible] {
            match oracle::samples(
                key.0,
                0,
                0,
                SamplerLimits::bounded(HOST_BYTES),
                Request {
                    policy,
                    emit_report: false,
                },
            ) {
                Err(message)
                    if message == "sampler diagnostic requires explicit GPU-required policy" => {}
                _ => return Err("non-GPU policy was accepted by private sampler diagnostics"),
            }
        }
        Ok(())
    })();
    if let Err(message) = result {
        panic!("{message}");
    }
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_sampler_exhaustion_scrubs_and_allows_fresh_retry() {
    let result = with_admitted_context(|| {
        let key = Key([0xc3; 32]);
        for kind in 0..2 {
            let mut limits = SamplerLimits::bounded(HOST_BYTES);
            if kind == 0 {
                limits.random_call_limit = 1;
            } else {
                limits.proposal_limit = 1;
            }
            match oracle::samples(key.0, 0, 0, limits, request()) {
                Err(message)
                    if message == "sampler diagnostic device status failed: budget or uniform exhaustion" => {}
                _ => return Err("exhausted sampler did not fail at the budget-exhausted device status gate"),
            }
            // Same admitted context, fresh owned key/state: exact C parity
            // after exhaustion proves no poisoned private state is reused.
            compare(&key, 0, 0)?;
        }
        Ok(())
    });
    if let Err(message) = result {
        panic!("{message}");
    }
}
