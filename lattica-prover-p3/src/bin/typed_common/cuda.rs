//! Explicit CUDA CLI service for the existing typed pool protocol. The
//! controller must independently admit startup, timing and resource limits.
use super::{read_json, Error, PAIRED};
use lattica_prover_p3::block_v2::{
    execution::native_worker::{self, CudaSnapshot},
    machine::{analysis, programs},
    profile,
};
use serde_json::Value;
use std::{path::Path, time::Instant};

const WORKLOAD: &str = if cfg!(feature = "block-v2-capacity-128") {
    "typed-paired-cuda-owned-depth-seven-bootstrap-v1"
} else {
    "typed-paired-cuda-owned-depth-six-bootstrap-v1"
};

fn command(args: &[String]) -> Result<u64, Error> {
    let values: Vec<_> = args.iter().skip(1).map(String::as_str).collect();
    match values.as_slice() {
        ["serve-shared-process-gpu", _, _, _, budget]
            if PAIRED && cfg!(all(target_os = "linux", feature = "stream")) => {
                budget.parse::<u64>().ok().filter(|&n| n > 0)
                    .ok_or_else(|| "missing CUDA worker budget".into())
            }
        _ => Err("CUDA CLI requires paired Linux+stream serve-shared-process-gpu DIR EXPECTED LAUNCH_DIR WORKER_BYTES".into()),
    }
}

pub(super) fn validate_owned_assignment(assignment: &Value, budget: u64) -> Result<(), Error> {
    if !PAIRED
        || budget == 0
        || assignment["backend"].as_str() != Some("cuda")
        || assignment["workload_kind"].as_str() != Some(WORKLOAD)
        || assignment["typed_ram_admission"].as_str() != Some("owned")
        || assignment["qualification_capacity_test"].as_bool() != Some(true)
        || assignment["host"]["worker_bytes"].as_u64() != Some(budget)
        || assignment["pool_job_limit"]
            .as_u64()
            .is_none_or(|n| !(1..=16384).contains(&n))
        || assignment["startup_guard"]
            .as_str()
            .is_none_or(|p| !Path::new(p).is_absolute())
    {
        return Err(
            "CUDA CLI requires its explicit owned paired workload and fenced job bound".into(),
        );
    }
    Ok(())
}

pub(super) fn require_owned_geometry(directory: &Path) -> Result<(), Error> {
    let height: usize = read_json(&directory.join("height.json"))?;
    if height != 262144 {
        return Err("CUDA CLI bootstrap requires height 262144".into());
    }
    let measured = analysis::analyze(&programs::shape(height)?).map_err(|e| format!("{e:?}"))?;
    if measured.main_width != 94
        || measured.preprocessed_width != 200
        || measured.permutation_width_base + 4 > 55
        || measured.quotient_chunks != 16
        || profile::LOG_BLOWUP != 4
        || measured.fri_ali_bits < profile::MIN_TREE_SECURITY_BITS
    {
        return Err("compiled CUDA CLI geometry differs from bootstrap model".into());
    }
    Ok(())
}

fn environment_setting(key: &str, value: &str) -> Result<(), Error> {
    if (key.starts_with("LATTICA_V2_GPU_") || key.starts_with("LATTICA_V2_QUOTIENT_"))
        && !matches!(
            key,
            "LATTICA_V2_GPU_MANAGED_BYTES" | "LATTICA_V2_GPU_CONTEXT_BYTES"
        )
        && value != "0"
    {
        return Err(format!("CUDA CLI does not consume OpenCL settings: {key}").into());
    }
    Ok(())
}

fn validate_work(stats: &CudaSnapshot, count: u64, limit: u64) -> Result<(), Error> {
    if count > limit
        || stats.live_bytes != 0
        || stats.allocations != 0
        || stats.modules != 0
        || stats.pending_commands != 0
        || stats.public_program_bytes != 0
        || stats.public_programs != 0
        || (count > 0
            && (stats.completed_commands == 0
                || stats.peak_bytes == 0
                || stats.uploaded_bytes == 0
                || stats.downloaded_bytes == 0))
    {
        return Err("CUDA CLI work count or retirement telemetry differs".into());
    }
    Ok(())
}

pub(crate) fn run(args: &[String]) -> Result<(), Error> {
    if args.len() == 2 && args[1] == "--gpu-inventory" {
        println!(
            "{}",
            serde_json::json!({"schema":"lattica-gpu-inventory-v1",
            "backend":"cuda", "devices":native_worker::cuda_inventory()?})
        );
        return Ok(());
    }
    let budget = command(args)?;
    let request = lattica_prover_p3::proving::Request::from_env()?;
    if request.policy != lattica_prover_p3::proving::Policy::GpuRequired || !request.emit_report {
        return Err("CUDA CLI qualification requires gpu-required and stage reports".into());
    }
    for (key, value) in std::env::vars() {
        environment_setting(&key, &value)?;
    }
    #[cfg(all(target_os = "linux", feature = "stream"))]
    {
        let started = Instant::now();
        // Do not read the assignment here: the library admits decoding and
        // process/allocator backing before invoking trusted CLI preparation.
        let (count, stats, limit) = super::execution::serve_owned_process(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            budget,
            &args[1..],
        )?;
        validate_work(&stats, count, limit)?;
        println!(
            "{}",
            serde_json::json!({"event":"typed_gpu_work_complete", "backend":"cuda",
            "seconds":started.elapsed().as_secs_f64(), "recursive_proofs":count,
            "spill_peak_bytes":lattica_prover_p3::spill_alloc::spill_peak_bytes(),
            "cpu_only":false, "cuda":stats,
            "owned_public_worker":true, "qualification_bootstrap":true, "production_ready":false})
        );
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", feature = "stream")))]
    {
        let _ = budget;
        Err("CUDA CLI requires Linux+stream".into())
    }
}

#[cfg(test)]
#[path = "cuda_tests.rs"]
mod tests;
