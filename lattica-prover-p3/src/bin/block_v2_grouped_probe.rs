//! Opt-in CPU-only grouped-eight entry point. GPU builds are rejected before
//! setup, verification or proving. GPU work has a separate binary/controller.
mod grouped_common;

#[cfg(feature = "block-v2-wide-lanes")]
use lattica_prover_p3::block_v2::{codec, profile};
use lattica_prover_p3::{block_v2::perf::Profiler, spill_alloc};
use std::time::Instant;

fn main() {
    match lattica_prover_p3::block_v2::quotient_pcs::initialize_research_from_env() {
        Ok(enabled) => {
            println!("quotient_fusion_research enabled={enabled} production_ready=false")
        }
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    }
    // This binary has no GPU initialization or shutdown calls. Reject GPU-enabled
    // builds before setup, proof verification or any stage work; do not silently
    // treat a GPU-feature build/environment as the CPU-only registration gate.
    if cfg!(feature = "gpu") {
        eprintln!("FAILED: grouped research requires a CPU-only build without the gpu feature");
        std::process::exit(1);
    }
    match std::env::var("LATTICA_V2_GPU_RESIDENT_LDE") {
        Err(std::env::VarError::NotPresent) => {}
        Ok(value) if value == "0" => {}
        _ => {
            eprintln!("FAILED: CPU grouped runner cannot select resident GPU proving");
            std::process::exit(1);
        }
    }
    #[cfg(feature = "block-v2-wide-lanes")]
    println!("machine_layout_research name=wide23 revision=3 scalar_lanes=23 cubic_lanes=7 main_width=94 public_bank_width=32 separate_registry_required=true production_ready=false");
    #[cfg(feature = "block-v2-wide-lanes")]
    println!(
        "node_codec_research revision={} magic={} profile_bound=true production_ready=false",
        profile::NODE_CODEC_REVISION,
        std::str::from_utf8(codec::NODE_MAGIC).expect("static ASCII node magic")
    );
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = match grouped_common::parse_command(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    };
    let started = Instant::now();
    let _spill = spill_alloc::SpillScope::arm();
    let profiler = match Profiler::from_env() {
        Ok(profiler) => profiler,
        Err(error) => {
            eprintln!("FAILED: {error}");
            std::process::exit(1);
        }
    };
    let result = grouped_common::run(command, profiler.as_ref(), true);
    if let Some(profiler) = &profiler {
        profiler.report("grouped process remainder");
    }
    println!(
        "grouped_stage_elapsed_ms={} spill_peak_bytes={} cpu_only=true production_ready=false",
        started.elapsed().as_millis(),
        spill_alloc::spill_peak_bytes()
    );
    if let Err(error) = result {
        eprintln!("FAILED: {error}");
        std::process::exit(1);
    }
}
