// Explicit compact-profile GPU grouped-eight research worker.
// Preparation, checkpoint checks, pruning and audits use CPU tools.
mod grouped_common;

use grouped_common::{Command, Error, PinnedAction};
use lattica_prover_p3::{
    block_v2::{codec, gpu_hash, perf::Profiler, profile, quotient_pcs},
    spill_alloc,
};
use std::{fs, path::Path, time::Instant};

const GIB: u64 = 1 << 30;

fn parse_backend(hash: &str, retained: &str, overlap: &str, resident: &str) -> Result<bool, Error> {
    if hash != "1" || retained != "1" || overlap != "0" {
        return Err(
            "GPU grouped worker requires explicit GPU_HASH=1, GPU_RETAIN_TREES=1, GPU_PIPELINE=0"
                .into(),
        );
    }
    match resident {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("GPU grouped worker requires explicit LATTICA_V2_GPU_RESIDENT_LDE=0 or 1".into()),
    }
}

fn parse_gpu_command(args: &[String]) -> Result<Command, Error> {
    let command = grouped_common::parse_command(args)?;
    if !command.is_gpu_work() {
        return Err("GPU grouped worker supports register/wrap-pair/wrap-all/merge/merge-all only; use CPU tools for preparation, checks, pruning and audits".into());
    }
    Ok(command)
}

fn parse_openings(value: &str, resident: bool) -> Result<bool, Error> {
    match value {
        "0" => Ok(false),
        "1" if resident => Ok(true),
        "1" => Err("GPU openings require the resident grouped backend".into()),
        _ => Err("GPU grouped worker requires explicit LATTICA_V2_GPU_OPENINGS=0 or 1".into()),
    }
}

// Unset keeps historical controller invocations on the original path. Invalid
// or non-Unicode values must not silently turn an experiment off.
fn optional_policy_env(name: &str) -> Result<String, Error> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok("0".to_owned()),
        Err(error) => Err(error.into()),
    }
}

fn parse_parallel_readback(value: &str, resident: bool) -> Result<bool, Error> {
    match value {
        "0" => Ok(false),
        "1" if resident => Ok(true),
        _ => Err("GPU parallel readback requires 0 or 1 and the resident backend".into()),
    }
}

fn parse_opening_policy(
    compact: &str,
    pinned: &str,
    resident: bool,
    openings: bool,
) -> Result<bool, Error> {
    if pinned != "0" {
        return Err("GPU grouped qualification requires GPU_OPENING_PINNED=0".into());
    }
    match compact {
        "0" => Ok(false),
        "1" if resident && openings => Ok(true),
        "1" => Err("compact openings require resident LDEs and GPU openings".into()),
        _ => Err("GPU grouped worker requires GPU_OPENING_COMPACT=0 or 1".into()),
    }
}

fn validate_opening_work(
    stats: &gpu_hash::Snapshot,
    expected: u64,
    compact: bool,
) -> Result<(), Error> {
    if stats.opening_calls != expected {
        return Err("GPU opening work count differs from selected command/backend".into());
    }
    if stats.opening_pinned_uploaded_bytes != 0 || stats.opening_pinned_upload_chunks != 0 {
        return Err("unexpected pinned opening uploads in grouped qualification".into());
    }
    let compact_calls = if compact { expected } else { 0 };
    if stats.opening_compact_calls != compact_calls {
        return Err("compact opening work count differs from selected command/backend".into());
    }
    let work = [
        u128::from(stats.opening_compact_saved_input_bytes),
        stats.opening_compact_compress_ns,
        stats.opening_compact_ntt_ns,
    ];
    if compact_calls > 0 {
        if work.contains(&0) {
            return Err("compact opening compression/extension work is absent".into());
        }
    } else if work.iter().any(|value| *value != 0) {
        return Err("unexpected compact opening work".into());
    }
    Ok(())
}

fn expected_opening_calls(command: &Command) -> u64 {
    match command {
        Command::Pinned {
            action: PinnedAction::WrapAll,
            ..
        } => 4,
        Command::Pinned {
            action: PinnedAction::MergeAll,
            ..
        } => 3,
        Command::Pinned {
            action: PinnedAction::WrapPair(_) | PinnedAction::Merge { .. },
            ..
        } => 1,
        _ => 0,
    }
}

fn validate_worker_limits(
    unit: &str,
    expected_unit: &str,
    slice: &str,
    memory: &str,
    swap: &str,
    slice_memory: &str,
    slice_swap: &str,
) -> Result<(), Error> {
    if !unit.starts_with("lattica-v2-gpu-grouped-")
        || !unit.ends_with(".service")
        || !unit
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        || unit != expected_unit
        || slice != "lattica-v2-grouped.slice"
    {
        return Err("GPU grouped worker requires its named accounting-bound service in the grouped resource slice".into());
    }
    let memory: u64 = memory.parse()?;
    let slice_memory: u64 = slice_memory.parse()?;
    if memory == 0
        || memory > 44 * GIB
        || swap != "0"
        || slice_memory != 48 * GIB
        || slice_swap != "0"
    {
        return Err(
            "GPU grouped worker requires MemoryMax<=44G and zero swap under the 48G/no-swap slice"
                .into(),
        );
    }
    Ok(())
}

#[cfg(feature = "gpu")]
fn require_worker_limits() -> Result<(), Error> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let groups: Vec<_> = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect();
    if groups.len() != 1 {
        return Err("GPU grouped worker requires cgroup v2".into());
    }
    let group = Path::new("/sys/fs/cgroup").join(groups[0].trim_start_matches('/'));
    let parent = group.parent().ok_or("missing worker resource slice")?;
    let text = |path| fs::read_to_string(path).map(|s| s.trim().to_owned());
    validate_worker_limits(
        group
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid worker unit")?,
        &std::env::var("LATTICA_V2_ACCOUNTING_UNIT")?,
        parent
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid resource slice")?,
        &text(group.join("memory.max"))?,
        &text(group.join("memory.swap.max"))?,
        &text(parent.join("memory.max"))?,
        &text(parent.join("memory.swap.max"))?,
    )
}

#[cfg(feature = "gpu-metal")]
struct MetalWatchdog {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "gpu-metal")]
fn process_memory() -> Result<(u64, u64), Error> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    // proc_pid_rusage writes the selected fixed-layout version into this buffer.
    let result = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            usage.as_mut_ptr().cast(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let usage = unsafe { usage.assume_init() };
    Ok((usage.ri_resident_size, usage.ri_phys_footprint))
}

#[cfg(feature = "gpu-metal")]
fn require_worker_limits() -> Result<MetalWatchdog, Error> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    fn limit(name: &str, default: u64, maximum: u64) -> Result<u64, Error> {
        let value = match std::env::var(name) {
            Ok(value) => value.parse()?,
            Err(std::env::VarError::NotPresent) => default,
            Err(error) => return Err(error.into()),
        };
        if value == 0 || value > maximum {
            return Err(format!("invalid {name}: must be 1..={maximum}").into());
        }
        Ok(value)
    }
    let rss_limit = limit("LATTICA_V2_METAL_RSS_LIMIT_BYTES", 44 * GIB, 44 * GIB)?;
    let timeout = limit("LATTICA_V2_METAL_TIMEOUT_SECONDS", 7200, 7200)?;
    let scratch: u64 = std::env::var("LATTICA_SPILL_MAX_BYTES")?.parse()?;
    if scratch == 0
        || scratch > 34 * GIB
        || std::env::var("LATTICA_SPILL_BACKING").as_deref() != Ok("memory")
    {
        return Err(
            "Metal worker requires memory scratch with explicit 0 < SPILL_MAX_BYTES <= 34 GiB"
                .into(),
        );
    }
    let (rss, footprint) = process_memory()?;
    if rss > rss_limit {
        return Err("Metal worker already exceeds its RSS limit".into());
    }
    println!("metal_worker_limits rss_limit_bytes={rss_limit} scratch_limit_bytes={scratch} timeout_seconds={timeout} sample_ms=500 enforcement=watchdog swap_enforcement=false initial_rss_bytes={rss} initial_footprint_bytes={footprint}");
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let thread = std::thread::Builder::new().name("metal-memory-watchdog".into()).spawn(move || {
        let started = Instant::now();
        let (mut peak_rss, mut peak_footprint) = (rss, footprint);
        loop {
            match process_memory() {
                Ok((rss, footprint)) => {
                    peak_rss = peak_rss.max(rss); peak_footprint = peak_footprint.max(footprint);
                    if rss > rss_limit || started.elapsed().as_secs() >= timeout {
                        eprintln!("FAILED: Metal watchdog limit exceeded rss_bytes={rss} footprint_bytes={footprint} elapsed_seconds={}", started.elapsed().as_secs());
                        std::process::exit(124);
                    }
                }
                Err(error) => { eprintln!("FAILED: Metal watchdog sampling: {error}"); std::process::exit(70); }
            }
            if signal.load(Ordering::Acquire) { break; }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        println!("metal_worker_memory peak_rss_bytes={peak_rss} peak_footprint_bytes={peak_footprint} sample_ms=500 gpu_bytes_overlap_process_memory=true");
    })?;
    Ok(MetalWatchdog {
        stop,
        thread: Some(thread),
    })
}

#[cfg(feature = "gpu-metal")]
impl Drop for MetalWatchdog {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct GpuGuard(bool);
impl GpuGuard {
    fn finish(&mut self) -> Result<(), Error> {
        gpu_hash::shutdown()?;
        self.0 = false;
        Ok(())
    }
}
impl Drop for GpuGuard {
    fn drop(&mut self) {
        if self.0 {
            if let Err(error) = gpu_hash::shutdown() {
                eprintln!("FAILED: GPU grouped teardown: {error}");
                std::process::abort();
            }
        }
    }
}

fn run(args: &[String]) -> Result<(), Error> {
    let started = Instant::now();
    let command = parse_gpu_command(args)?;
    let resident = parse_backend(
        &std::env::var("LATTICA_V2_GPU_HASH")?,
        &std::env::var("LATTICA_V2_GPU_RETAIN_TREES")?,
        &std::env::var("LATTICA_V2_GPU_PIPELINE")?,
        &std::env::var("LATTICA_V2_GPU_RESIDENT_LDE")?,
    )?;
    let openings = parse_openings(&std::env::var("LATTICA_V2_GPU_OPENINGS")?, resident)?;
    let parallel_readback = parse_parallel_readback(
        &optional_policy_env("LATTICA_V2_GPU_PARALLEL_READBACK")?,
        resident,
    )?;
    let compact = parse_opening_policy(
        &optional_policy_env("LATTICA_V2_GPU_OPENING_COMPACT")?,
        &optional_policy_env("LATTICA_V2_GPU_OPENING_PINNED")?,
        resident,
        openings,
    )?;
    let expected_openings = if openings {
        expected_opening_calls(&command)
    } else {
        0
    };
    let _limits = require_worker_limits()?;
    let fusion = quotient_pcs::initialize_research_from_env()?;
    let gpu_quotient = quotient_pcs::initialize_gpu_quotient_from_env(resident, fusion)?;
    let expected_quotients = if gpu_quotient {
        expected_opening_calls(&command)
    } else {
        0
    };
    println!("gpu_quotient_research enabled={gpu_quotient} production_ready=false");
    println!("quotient_fusion_research enabled={fusion} production_ready=false");
    println!("gpu_readback_research parallel={parallel_readback} production_ready=false");
    println!("machine_layout_research name=wide23 revision=3 scalar_lanes=23 cubic_lanes=7 main_width=94 public_bank_width=32 separate_registry_required=true production_ready=false");
    println!(
        "node_codec_research revision={} magic={} profile_bound=true production_ready=false",
        profile::NODE_CODEC_REVISION,
        std::str::from_utf8(codec::NODE_MAGIC)?
    );
    let _spill = spill_alloc::SpillScope::arm();
    let profiler = Profiler::from_env()?;
    gpu_hash::initialize_from_env()?;
    let mut guard = GpuGuard(true);
    if gpu_hash::initialize_resident_from_env()? != resident {
        return Err("GPU grouped resident selection mismatch".into());
    }
    println!("gpu_grouped_research resident_lde={resident} gpu_openings={openings} retained_trees=true transfer_overlap=false cpu_only=false production_ready=false");
    println!("gpu_grouped_opening_policy compact={compact} pinned=false cpu_only=false production_ready=false");
    let result = grouped_common::run(command, profiler.as_ref(), false);
    if let Some(profiler) = &profiler {
        profiler.report("GPU grouped process remainder");
    }
    let stats = gpu_hash::report("GPU grouped process remainder").ok_or("GPU telemetry missing")?;
    guard.finish()?;
    result?;
    if stats.quotient_lde_commits != expected_quotients {
        return Err("GPU quotient work differs from requested policy".into());
    }
    if parallel_readback != (stats.lde_parallel_decode_bytes > 0)
        || parallel_readback != (stats.lde_parallel_decode_chunks > 0)
    {
        return Err("GPU readback work differs from requested policy".into());
    }
    validate_opening_work(&stats, expected_openings, compact)?;
    if stats.commits == 0
        || (resident && stats.lde_commits == 0)
        || (!resident && stats.lde_commits != 0)
    {
        return Err("GPU grouped operation did not execute the selected backend; no fallback or resumed timing".into());
    }
    println!("grouped_stage_elapsed_ms={} spill_peak_bytes={} cpu_only=false resident_lde={resident} gpu_openings={openings} production_ready=false",
        started.elapsed().as_millis(), spill_alloc::spill_peak_bytes());
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_readback_policy_requires_explicit_resident_selection() {
        assert!(!parse_parallel_readback("0", false).unwrap());
        assert!(!parse_parallel_readback("0", true).unwrap());
        assert!(parse_parallel_readback("1", true).unwrap());
        assert!(parse_parallel_readback("1", false).is_err());
        for value in ["", "true", "01", " 1", "2"] {
            assert!(parse_parallel_readback(value, true).is_err());
        }
    }

    #[test]
    fn compact_policy_is_explicit_compatible_and_never_pinned() {
        for resident in [false, true] {
            for openings in [false, true] {
                assert!(!parse_opening_policy("0", "0", resident, openings).unwrap());
                assert_eq!(
                    parse_opening_policy("1", "0", resident, openings).is_ok(),
                    resident && openings
                );
            }
        }
        for value in ["", "true", "01", " 1", "2"] {
            assert!(parse_opening_policy(value, "0", true, true).is_err());
        }
        for value in ["", "true", "00", " 0", "1", "2"] {
            assert!(parse_opening_policy("1", value, true, true).is_err());
        }
    }

    #[test]
    fn opening_policy_requires_actual_complete_work_and_zero_pinned_uploads() {
        for expected in [0, 1, 3, 4] {
            for compact in [false, true] {
                let active = compact && expected > 0;
                let stats = gpu_hash::Snapshot {
                    opening_calls: expected,
                    opening_compact_calls: if compact { expected } else { 0 },
                    opening_compact_saved_input_bytes: if active { 128 } else { 0 },
                    opening_compact_compress_ns: if active { 20 } else { 0 },
                    opening_compact_ntt_ns: if active { 30 } else { 0 },
                    ..Default::default()
                };
                validate_opening_work(&stats, expected, compact).unwrap();
                for field in 0..7 {
                    let mut bad = stats;
                    match field {
                        0 => bad.opening_calls += 1,
                        1 => bad.opening_compact_calls += 1,
                        2 => bad.opening_compact_saved_input_bytes = if active { 0 } else { 1 },
                        3 => bad.opening_compact_compress_ns = if active { 0 } else { 1 },
                        4 => bad.opening_compact_ntt_ns = if active { 0 } else { 1 },
                        5 => bad.opening_pinned_uploaded_bytes = 1,
                        _ => bad.opening_pinned_upload_chunks = 1,
                    }
                    assert!(validate_opening_work(&bad, expected, compact).is_err());
                }
            }
        }
    }

    #[test]
    fn opening_selection_is_explicit_and_resident_only() {
        assert!(!parse_openings("0", false).unwrap());
        assert!(!parse_openings("0", true).unwrap());
        assert!(parse_openings("1", true).unwrap());
        assert!(parse_openings("1", false).is_err());
        for value in ["", "true", "01", " 1", "2"] {
            assert!(parse_openings(value, true).is_err());
        }
    }

    #[test]
    fn opening_count_is_bound_to_the_exact_workload() {
        let external = "00".repeat(32);
        for (operation, expected) in [("wrap-all", 4), ("merge-all", 3)] {
            let command = parse_gpu_command(&[
                operation.into(),
                "/missing".into(),
                external.clone(),
                external.clone(),
                external.clone(),
            ])
            .unwrap();
            assert_eq!(expected_opening_calls(&command), expected);
        }
        let command =
            parse_gpu_command(&["register".into(), "/missing".into(), "1".into()]).unwrap();
        assert_eq!(expected_opening_calls(&command), 0);
    }

    #[test]
    fn backend_selection_requires_explicit_retained_serial_gpu_modes() {
        assert!(!parse_backend("1", "1", "0", "0").unwrap());
        assert!(parse_backend("1", "1", "0", "1").unwrap());
        for bad in ["", "true", "01", " 1", "2", "\u{ff11}"] {
            assert!(parse_backend("1", "1", "0", bad).is_err());
        }
        for fields in [
            ["0", "1", "0", "1"],
            ["1", "0", "0", "1"],
            ["1", "1", "1", "1"],
        ] {
            assert!(parse_backend(fields[0], fields[1], fields[2], fields[3]).is_err());
        }
    }

    #[test]
    fn only_gpu_work_is_admitted_before_any_io_or_device_initialization() {
        let external = "00".repeat(32);
        for verb in [
            "prepare",
            "common-height",
            "describe-registry",
            "geometry-report",
        ] {
            assert!(parse_gpu_command(&[verb.into(), "/missing".into()]).is_err());
        }
        for verb in ["check-registered", "remove-inners", "verify-root"] {
            assert!(parse_gpu_command(&[
                verb.into(),
                "/missing".into(),
                external.clone(),
                external.clone(),
                external.clone()
            ])
            .is_err());
        }
        for verb in ["wrap-all", "merge-all"] {
            let args = [
                verb.into(),
                "/missing".into(),
                external.clone(),
                external.clone(),
                external.clone(),
            ];
            assert!(parse_gpu_command(&args).is_ok());
            assert!(parse_gpu_command(&args[..4]).is_err());
        }
        assert!(parse_gpu_command(&["register".into(), "/missing".into(), "1".into()]).is_ok());
    }

    #[test]
    fn worker_resource_gate_rejects_wrong_binding_unbounded_ram_or_swap() {
        let unit = "lattica-v2-gpu-grouped-test-1.service";
        let mem = (44 * GIB).to_string();
        let total = (48 * GIB).to_string();
        assert!(validate_worker_limits(
            unit,
            unit,
            "lattica-v2-grouped.slice",
            &mem,
            "0",
            &total,
            "0"
        )
        .is_ok());
        for bad in ["0", "max", "-1", "47244640257"] {
            assert!(validate_worker_limits(
                unit,
                unit,
                "lattica-v2-grouped.slice",
                bad,
                "0",
                &total,
                "0"
            )
            .is_err());
        }
        assert!(validate_worker_limits(
            unit,
            "other.service",
            "lattica-v2-grouped.slice",
            &mem,
            "0",
            &total,
            "0"
        )
        .is_err());
        assert!(validate_worker_limits(unit, unit, "wrong.slice", &mem, "0", &total, "0").is_err());
        assert!(validate_worker_limits(
            unit,
            unit,
            "lattica-v2-grouped.slice",
            &mem,
            "1",
            &total,
            "0"
        )
        .is_err());
        assert!(validate_worker_limits(
            unit,
            unit,
            "lattica-v2-grouped.slice",
            &mem,
            "0",
            "max",
            "0"
        )
        .is_err());
        assert!(validate_worker_limits(
            unit,
            unit,
            "lattica-v2-grouped.slice",
            &mem,
            "0",
            &total,
            "1"
        )
        .is_err());
    }
}
