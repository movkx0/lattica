//! Raw witness to serialized wallet proof, with verification outside timing.
//! This screen does not measure recursion, block processing or pool throughput.
use super::*;
use std::time::Instant;

#[test]
#[ignore = "requires release CUDA and LATTICA_CUDA_WALLET_BENCHMARK=1"]
fn cuda_wallet_request_benchmark() {
    assert!(
        !cfg!(debug_assertions),
        "build the benchmark with --release"
    );
    assert_eq!(
        std::env::var("LATTICA_CUDA_WALLET_BENCHMARK").as_deref(),
        Ok("1")
    );
    let started = Instant::now();
    let runtime = open_runtime(limits());
    let prover = WalletProver::new(&runtime).unwrap();
    let joinsplit_prover = prover.prepare_joinsplit(256 << 20).unwrap();
    let htlc_prover = prover.prepare_htlc(256 << 20).unwrap();
    println!(
        "LATTICA_CUDA_WALLET_PREPARATION {}",
        serde_json::json!({
            "seconds": started.elapsed().as_secs_f64(), "identity": runtime.identity(),
            "limits": { "managed_bytes": 256 << 20, "max_allocation_bytes": 64 << 20, "proof_host_bytes": 64 << 20 },
            "snapshot": runtime.snapshot(),
        })
    );
    macro_rules! compare {
        ($case:literal, $prepared:expr, $witness:expr, $air:expr, $build:path, $public:path) => {{
            let witness = $witness;
            for iteration in 0..6 {
                for native in if iteration % 2 == 0 { [false, true] } else { [true, false] } {
                    let before = runtime.snapshot();
                    let started = Instant::now();
                    let (encoded, public, report) = if native {
                        let result = $prepared.prove(&witness, Request {
                            policy: Policy::GpuRequired, emit_report: false,
                        }, 64 << 20).unwrap();
                        (postcard::to_allocvec(&result.proof).unwrap(), result.public_values, Some(result.report))
                    } else {
                        let config = crate::config::make_config();
                        let public = $public(&witness);
                        let trace = $build(&witness);
                        let proof = p3_uni_stark::prove(&config, &$air, trace, &public);
                        (postcard::to_allocvec(&proof).unwrap(), public, None)
                    };
                    let seconds = started.elapsed().as_secs_f64();
                    let after = runtime.snapshot();
                    let proof: crate::cuda_compute::NativeStarkProof<Challenge> = postcard::from_bytes(&encoded).unwrap();
                    assert_eq!(public, $public(&witness));
                    p3_uni_stark::verify(&crate::config::make_config(), &$air, &proof, &public).unwrap();
                    if let Some(report) = &report { assert!(report.stage_coverage_complete); }
                    else { assert_eq!(after, before); }
                    assert_eq!(after.live_bytes, before.live_bytes);
                    assert_eq!(after.allocations, before.allocations);
                    println!("LATTICA_CUDA_WALLET_SAMPLE {}", serde_json::json!({
                        "case": $case, "backend": if native { "cuda" } else { "cpu" },
                        "iteration": iteration, "warmup": iteration == 0, "seconds": seconds,
                        "proof_bytes": encoded.len(), "cpu_verified": true,
                        "completed_commands": after.completed_commands - before.completed_commands,
                        "device_ns": after.device_ns - before.device_ns,
                        "uploaded_bytes": after.uploaded_bytes - before.uploaded_bytes,
                        "downloaded_bytes": after.downloaded_bytes - before.downloaded_bytes,
                        "peak_managed_bytes": after.peak_bytes, "report": report,
                    }));
                }
            }
        }};
    }
    compare!(
        "joinsplit",
        joinsplit_prover,
        joinsplit(1),
        js::JoinSplitAir,
        js::build_trace,
        js::public_values
    );
    compare!(
        "htlc_redeem",
        htlc_prover,
        htlc(1),
        htlc::HtlcAir,
        htlc::build_trace,
        htlc::public_values
    );
    compare!(
        "htlc_refund",
        htlc_prover,
        htlc(2),
        htlc::HtlcAir,
        htlc::build_trace,
        htlc::public_values
    );
}
