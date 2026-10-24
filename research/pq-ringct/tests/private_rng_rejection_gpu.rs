#![cfg(feature = "native-spend-oracle")]
//! Serialized post-freeze correctness probes; no performance baseline.
use lattica_pq_ringct_research::{
    execution::ProvingContext,
    native::{self, private_rng_rejection_oracle as reference},
    opencl::Limits,
};
use lattica_prover_p3::{
    block_v2::native_gpu::private_spend::rng_rejection_oracle::{self as oracle, ProbeLimits},
    proving::{Backend, CoverageScope, Policy, Profile, Report, Request, Stage},
};
use std::sync::atomic::{compiler_fence, Ordering};

const HOST_BYTES: usize = 8 << 20;
struct Key([u8; 32]);
impl Drop for Key {
    fn drop(&mut self) {
        for byte in &mut self.0 { unsafe { std::ptr::write_volatile(byte, 0) }; }
        compiler_fence(Ordering::SeqCst);
    }
}
struct Words(Vec<u64>);
impl Drop for Words {
    fn drop(&mut self) {
        for word in &mut self.0 { unsafe { std::ptr::write_volatile(word, 0) }; }
        compiler_fence(Ordering::SeqCst);
    }
}
fn admitted() -> Result<(), &'static str> {
    if std::env::var("LATTICA_NATIVE_SPEND_QUALIFICATION").as_deref() != Ok("1") {
        return Err("explicit post-freeze RNG/rejection qualification admission is missing");
    }
    if !native::available() { return Err("native reference CPU ISA prerequisites are missing"); }
    Ok(())
}
fn request() -> Request { Request { policy: Policy::GpuRequired, emit_report: false } }
fn limits() -> ProbeLimits { ProbeLimits::bounded(HOST_BYTES) }
fn with_admitted_context(work: impl FnOnce() -> Result<(), &'static str>) -> Result<(), &'static str> {
    admitted()?;
    let context = ProvingContext::opencl(Limits {
        host_bytes: 32 << 30, device_bytes: 8 << 30, max_rows: 1 << 20,
    }).map_err(|_| "RNG/rejection OpenCL context admission failed")?;
    let result = work();
    let cleanup = context.close_without_completion()
        .map_err(|_| "RNG/rejection diagnostic context cleanup failed")?;
    if cleanup["completion_claimed"] != false
        || cleanup["session_cleanup"]["completion_claimed"] != false
        || cleanup["session_cleanup"]["completion_scope"] != "cleanup_only"
        || cleanup["session_cleanup"]["stark_completion_claimed"] != false
        || cleanup["session_cleanup"]["validated_native_spend_reports"].as_u64() != Some(0)
        || cleanup["session_cleanup"]["queue_drained"] != true
        || cleanup["session_cleanup"]["context_closed"] != true
        || cleanup["session_closed"] != true
    { return Err("RNG/rejection teardown incorrectly claimed proving completion"); }
    for field in ["native_cpu_calls", "native_gpu_calls", "prove_calls", "native_spend_calls",
        "native_spend_succeeded", "native_spend_complete_reports"] {
        if cleanup["operations"][field].as_u64() != Some(0) {
            return Err("RNG/rejection probe was counted as spend or STARK proving");
        }
    }
    result
}
fn evidence(
    report: &Report, evidence: &oracle::ProbeEvidence, entry: &str, managed_bytes: usize,
) -> Result<(), &'static str> {
    if report.entry_point != entry || report.entry_point == "native_matrict_spend"
        || report.policy != Policy::GpuRequired || !report.succeeded
        || !report.stage_coverage_complete || report.completion_rejected
        || report.observation_errors != 0 || !report.components.is_empty()
        || report.capabilities.profile() != Profile::MatrictN10
        || report.capabilities.scope() != CoverageScope::Operation
        || report.observations.len() != 1
        || report.observations.iter().any(|o| {
            o.stage != Stage::WitnessTrace || o.backend != Backend::OpenCl
                || o.calls != 8 || o.completed_calls != 8 || o.device_calls != 8
        })
        || !evidence.scrub_verified || evidence.managed_bytes != managed_bytes
        || evidence.kernel_source_sha256.len() != 64 || evidence.diagnostic_source_sha256.len() != 64
    { return Err("RNG/rejection diagnostic lacks isolated GPU operation evidence"); }
    Ok(())
}
fn rng_managed(lengths: &[u32]) -> usize {
    let total = lengths.iter().map(|&v| v as usize).sum::<usize>();
    (32 + total.div_ceil(8).max(1) + 36 + 8 + 3 * lengths.len()) * 8
}
fn compare_rng(key: &Key, lengths: &[u32]) -> Result<(), &'static str> {
    let cpu = reference::rng_calls(&key.0, lengths).map_err(|_| "native RNG reference failed")?;
    let (gpu, report, metadata) = oracle::rng_calls(key.0, lengths, limits(), request())
        .map_err(|_| "GPU RNG probe failed")?;
    // Compare booleans only; never format private bytes, seeds or counters.
    if gpu.bytes() != cpu.bytes() || gpu.progress() != cpu.progress() {
        return Err("GPU RNG bytes or per-call counters differ from native reference");
    }
    evidence(&report, &metadata, oracle::RNG_ENTRY_POINT, rng_managed(lengths))
}
fn compare_rejection(
    key: &Key, kind: u32, words: &Words, expected_rejected: Option<bool>, calls: u64,
) -> Result<(), &'static str> {
    let cpu = reference::rejection(&key.0, kind, &words.0)
        .map_err(|_| "native rejection reference failed")?;
    let (gpu, report, metadata) = oracle::rejection(key.0, kind, &words.0, limits(), request())
        .map_err(|_| "GPU rejection probe failed")?;
    if gpu.rejected() != cpu.rejected() || gpu.private_blocks() != cpu.private_blocks()
        || gpu.private_calls() != cpu.private_calls() || gpu.private_calls() != calls
        || gpu.private_blocks() != calls
        || expected_rejected.is_some_and(|expected| gpu.rejected() != expected)
    { return Err("GPU rejection decision or RNG consumption differs from reference contract"); }
    evidence(&report, &metadata, oracle::REJECTION_ENTRY_POINT, (32 + words.0.len() + 36 + 8 + 10 + 1) * 8)
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_rng_call_boundaries_and_zero_lengths_match_c() {
    let result = with_admitted_context(|| {
        for seed in [0x00, 0x5a, 0xff] {
            let key = Key([seed; 32]);
            for lengths in [
                &[0][..], &[0, 0, 0], &[1, 15], &[16], &[9, 9],
                &[0, 1, 2, 15, 16, 17, 31, 32, 33, 9, 4095, 4096, 0],
            ] { compare_rng(&key, lengths)?; }
        }
        let key = Key([0xa3; 32]);
        compare_rng(&key, &[0; oracle::MAX_RNG_CALLS])?;
        // Exact maximum total, call count and private scratch cap together.
        compare_rng(&key, &[oracle::MAX_RNG_CALL_BYTES; oracle::MAX_RNG_CALLS])?;
        Ok(())
    });
    if let Err(message) = result { panic!("{message}"); }
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_all_rejection_forms_match_decisions_and_rng_consumption() {
    let result = with_admitted_context(|| {
        for seed in [0x00, 0x5a, 0xff] {
            let key = Key([seed; 32]);
            for (kind, count, c_row) in [
                (0, oracle::REJECTION_F_WORDS, 11),
                (1, oracle::REJECTION_Z_WORDS, 8),
                (2, oracle::REJECTION_OP_WORDS, 59),
            ] {
                let mut words = Words(vec![0; count]);
                compare_rejection(&key, kind, &words, None, 1)?;
                words.0[c_row * 256] = 1;
                compare_rejection(&key, kind, &words, None, 1)?;
                words.0[c_row * 256] = 0;
                // Guaranteed norm rejection still consumes exactly one
                // 9-byte Bernoulli request, on either signed norm boundary.
                for z in [1i64 << 40, -(1i64 << 40)] {
                    words.0[0] = z as u64;
                    compare_rejection(&key, kind, &words, Some(true), 1)?;
                }
            }
            // Every operand family in OP's dot product, including both
            // z_out halves, must take its negative-dot zero-RNG early exit.
            for (z_row, c_row) in [(0, 59), (9, 68), (18, 77), (29, 88), (40, 99), (49, 108)] {
                let mut words = Words(vec![0; oracle::REJECTION_OP_WORDS]);
                words.0[z_row * 256] = u64::MAX;
                words.0[c_row * 256] = 1;
                compare_rejection(&key, 2, &words, Some(true), 0)?;
            }
        }
        Ok(())
    });
    if let Err(message) = result { panic!("{message}"); }
}

#[test]
#[ignore = "requires explicit post-freeze qualification admission"]
fn rng_rejection_host_admission_and_cpu_fallback_are_refused() {
    let result = (|| -> Result<(), &'static str> {
        admitted()?;
        let key = Key([0x31; 32]);
        for lengths in [&[][..], &[0; 257], &[4097], &[u32::MAX]] {
            match oracle::rng_calls(key.0, lengths, limits(), request()) {
                Err(message) if message == "RNG probe call shape is outside the bounded profile" => {},
                _ => return Err("invalid RNG call shape was not refused before device work"),
            }
        }
        match oracle::rng_calls_from_counter(key.0, &[0], oracle::COUNTER_END + 1, limits(), request()) {
            Err(message) if message == "RNG probe call shape is outside the bounded profile" => {},
            _ => return Err("invalid initial RNG counter was not refused before device work"),
        }
        for case in 0..3 {
            let mut bounded = limits();
            match case { 0 => bounded.host_bytes = 1, 1 => bounded.random_call_limit = 0,
                _ => bounded.random_call_limit = oracle::COUNTER_END + 1 }
            match oracle::rng_calls(key.0, &[1], bounded, request()) {
                Err(message) if message == "RNG/rejection probe resource limits are outside the bounded profile" => {},
                _ => return Err("invalid RNG/rejection resource bound was not refused"),
            }
        }
        for (kind, length) in [(0, 0), (1, oracle::REJECTION_F_WORDS), (2, 118), (3, 0), (u32::MAX, 0)] {
            let words = Words(vec![0; length]);
            match oracle::rejection(key.0, kind, &words.0, limits(), request()) {
                Err(message) if message == "rejection probe input shape is invalid" => {},
                _ => return Err("invalid rejection shape was not refused before device work"),
            }
        }
        let words = Words(vec![0; oracle::REJECTION_F_WORDS]);
        for policy in [Policy::CpuRequired, Policy::Compatible] {
            let request = || Request { policy, emit_report: false };
            match oracle::rng_calls(key.0, &[0], limits(), request()) {
                Err(message) if message == "RNG/rejection probe requires explicit GPU-required policy" => {},
                _ => return Err("RNG diagnostic accepted CPU fallback"),
            }
            match oracle::rejection(key.0, 0, &words.0, limits(), request()) {
                Err(message) if message == "RNG/rejection probe requires explicit GPU-required policy" => {},
                _ => return Err("rejection diagnostic accepted CPU fallback"),
            }
        }
        Ok(())
    })();
    if let Err(message) = result { panic!("{message}"); }
}

#[test]
#[ignore = "requires serialized post-freeze admission and qualified FP64 OpenCL device"]
fn gpu_rng_exhaustion_scrubs_and_allows_fresh_retry() {
    let result = with_admitted_context(|| {
        let key = Key([0x87; 32]);
        for lengths in [&[0, 0][..], &[1, 1], &[16, 17]] {
            let mut bounded = limits(); bounded.random_call_limit = 1;
            match oracle::rng_calls(key.0, lengths, bounded, request()) {
                Err(message) if message == "RNG/rejection probe call budget exhausted" => {},
                _ => return Err("RNG call exhaustion returned success or a different failure"),
            }
            compare_rng(&key, &[0, 1, 15, 16, 17, 0])?;
        }
        // Terminal counter qualification is device-contract testing, not C
        // byte parity: the bounded native adapter cannot reach this position.
        for (start, lengths) in [
            (oracle::COUNTER_END, &[0, 0][..]),
            (oracle::COUNTER_END - 1, &[16, 0][..]),
        ] {
            let (output, report, metadata) = oracle::rng_calls_from_counter(
                key.0, lengths, start, limits(), request(),
            ).map_err(|_| "legal terminal-counter request failed")?;
            if output.progress() != [oracle::COUNTER_END, 1, oracle::COUNTER_END, 2]
                || output.bytes().len() != lengths.iter().sum::<u32>() as usize
            { return Err("terminal-counter zero-length semantics are invalid"); }
            evidence(&report, &metadata, oracle::RNG_ENTRY_POINT, rng_managed(lengths))?;
        }
        for (start, lengths) in [
            (oracle::COUNTER_END, &[1][..]),
            (oracle::COUNTER_END - 1, &[17][..]),
            (oracle::COUNTER_END - 1, &[16, 1][..]),
        ] {
            match oracle::rng_calls_from_counter(key.0, lengths, start, limits(), request()) {
                Err(message) if message == "RNG/rejection probe counter exhausted" => {},
                _ => return Err("RNG counter exhaustion returned success or a different failure"),
            }
            compare_rng(&key, &[0, 1, 15, 16, 17, 0])?;
        }
        Ok(())
    });
    if let Err(message) = result { panic!("{message}"); }
}
