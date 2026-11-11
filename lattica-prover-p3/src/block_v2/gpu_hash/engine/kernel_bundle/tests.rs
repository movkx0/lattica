use super::*;

#[test]
fn prover_bundle_preserves_proof_kernels_and_exact_source_census() {
    for prefix in ["", "#define LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE 1\n"] {
        for poseidon in [tuning::Poseidon::Baseline, tuning::Poseidon::Square] {
            let complete = source(false, prefix, poseidon).unwrap();
            let prover = source(true, prefix, poseidon).unwrap();
            assert!(prover.len() < complete.len());
            for kernel in [
                "device_lookup_expressions",
                "device_quotient_gather",
                "device_compiler_fold",
                "retained_merkle_paths",
                "ntt_tile_cached_tuned",
            ] {
                assert!(prover.contains(kernel), "missing {kernel}");
            }
            for &(native, part) in SOURCES {
                assert!(complete.contains(part));
                if !native {
                    assert!(prover.contains(part));
                }
            }
            assert!(!prover.contains(device::PQ_CRYPTO_KERNEL_SRC));
            assert!(!prover.contains(device::WALLET_KERNEL_SRC));
            for (only, actual) in [(false, complete), (true, prover)] {
                assert_eq!(census(only, prefix, poseidon).unwrap().bytes, actual.len());
            }
        }
    }
}

#[test]
#[ignore = "requires exclusive OpenCL GPU; compiles fresh complete and prover programs"]
fn gpu_program_bundle_fresh_compilation_comparison() {
    let _shutdown = TestShutdownGuard;
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let mut slot = ENGINE.get().unwrap().lock().unwrap();
    let engine = slot.as_mut().unwrap();
    let prefix = device::public_hash::nvidia::source_prefix(engine.pq.device());
    // A new exported kernel name forces a distinct program binary without
    // deleting or altering shared driver caches. Both variants get the same
    // tiny kernel body. Reverse order on the second pair to limit order bias.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for (index, prover) in [false, true, true, false].into_iter().enumerate() {
        let mut text = source(prover, prefix, tuning::Poseidon::Baseline).unwrap();
        let base_bytes = text.len();
        let kernel_name = format!("bundle_probe_{nonce}_{index}");
        text.push_str(&format!(
            "\n__kernel void {kernel_name}(__global ulong *x) {{ x[0] += 1ul; }}\n"
        ));
        let started = Instant::now();
        let program = ocl::Program::builder()
            .devices(engine.pq.device())
            .src(text)
            .build(engine.pq.context())
            .unwrap();
        let seconds = started.elapsed().as_secs_f64();
        // Ensure the unique exported name really survived compilation.
        let kernel = ocl::core::create_kernel(program.as_core(), &kernel_name).unwrap();
        println!(
            "GPU_PROGRAM_BUNDLE_COMPARISON {}",
            serde_json::json!({
                "index": index, "prover_only": prover, "source_bytes": base_bytes,
                "build_seconds": seconds, "fresh_exported_kernel": kernel_name,
                "scope": "program build only; same context, source arithmetic and compiler options"
            })
        );
        drop(kernel);
        drop(program);
    }
}
