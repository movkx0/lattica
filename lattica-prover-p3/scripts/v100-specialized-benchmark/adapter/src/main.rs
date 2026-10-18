//! Container research adapter. All proving and verification use the pinned library.
#![allow(dead_code, unexpected_cfgs)]
mod grouped_common;
use std::{fs, time::Instant};

fn run() -> Result<(), grouped_common::Error> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() { return Err("missing benchmark action".into()); }
    let _spill = lattica_prover_p3::spill_alloc::SpillScope::arm();
    if args[0] != "aggregate" { return grouped_common::four_dispatch(&args); }
    #[cfg(not(feature = "gpu"))]
    return Err("aggregation requires the GPU benchmark binary".into());
    #[cfg(feature = "gpu")]
    {
        use lattica_prover_p3::block_v2::{gpu_hash, quotient_pcs};
        if std::env::var("LATTICA_BENCHMARK_CONTAINER").as_deref() != Ok("1")
            || std::env::var("LATTICA_PROVING_POLICY").as_deref() != Ok("gpu-required")
            || std::env::var("LATTICA_PROVING_REPORT").as_deref() != Ok("1")
            || std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("4")
        { return Err("benchmark controller and GPU-required reporting are mandatory".into()); }
        let limit: u64 = fs::read_to_string("/sys/fs/cgroup/memory.max")?.trim().parse()?;
        if limit > 64u64 << 30 || fs::read_to_string("/sys/fs/cgroup/memory.swap.max")?.trim() != "0" {
            return Err("bounded zero-swap container required".into());
        }
        let fusion = quotient_pcs::initialize_research_from_env()?;
        quotient_pcs::initialize_gpu_quotient_from_env(true, fusion)?;
        let init = Instant::now();
        gpu_hash::initialize_from_env()?;
        if !gpu_hash::initialize_resident_from_env()? { return Err("missing resident backend".into()); }
        let initialization_seconds = init.elapsed().as_secs_f64();
        let started = Instant::now();
        grouped_common::four_dispatch(&args)?;
        gpu_hash::drain()?;
        let seconds = started.elapsed().as_secs_f64();
        let stats = gpu_hash::report("four specialized complete").ok_or("missing GPU counters")?;
        // The owned opening path reports through per-proof device receipts.
        // This legacy host-upload opening counter must stay zero.
        if stats.opening_calls != 0 || stats.quotient_lde_commits != 3
            || stats.lde_host_output_bytes != 0 || stats.lde_device_only_commits == 0
            || stats.managed_peak_bytes > 16usize << 30 {
            return Err("GPU work counters differ from the required workload".into());
        }
        gpu_hash::shutdown()?;
        println!("specialized_benchmark_complete {}", serde_json::json!({
            "seconds": seconds, "initialization_seconds": initialization_seconds,
            "inputs": 4, "user_transactions": 4, "recursive_proofs": 3,
            "managed_gpu_peak_bytes": stats.managed_peak_bytes,
            "spill_peak_bytes": lattica_prover_p3::spill_alloc::spill_peak_bytes(),
            "tuning": std::env::var("LATTICA_V2_GPU_TUNING").unwrap_or_default(),
            "production_qualified": false
        }));
        Ok(())
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("FAILED: specialized GPU benchmark: {error}");
        std::process::exit(1);
    }
}
