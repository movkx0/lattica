//! Test-only unrolling comparison using the shared bounded kernel harness.
use super::shuffle_tests::HashKernel;
use super::*;

fn previous_kernel() -> String {
    let directive = "#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)\n#pragma unroll\n#endif\n";
    assert_eq!(KERNEL_SRC.matches(directive).count(), 3);
    KERNEL_SRC.replace(directive, "")
}

#[test]
#[ignore = "NVIDIA OpenCL GPU; serial <=3 GiB zero-swap service"]
fn gpu_unroll_matches_cpu_and_previous_hash_timing() {
    let baseline = HashKernel::for_kernels(&previous_kernel());
    let candidate = HashKernel::new(true);
    for length in [1usize, 3, 4, 5, 63, 64, 65, 4095, 4096, 4097, 4161] {
        let fields: Vec<_> = (0..length)
            .map(|i| [0, 1, GOLDILOCKS_MODULUS - 2, GOLDILOCKS_MODULUS - 1][i % 4])
            .collect();
        let expected = commitment::hash_fields(0x4c42563210, &fields).unwrap();
        for implementation in [&baseline, &candidate] {
            for cooperative in [false, true] {
                assert_eq!(implementation.hash(&fields, cooperative).0, expected);
            }
        }
    }
    let fields: Vec<_> = (0..(1 << 20) + 1)
        .map(|i| (i as u64).wrapping_mul(0x9e3779b97f4a7c15) % GOLDILOCKS_MODULUS)
        .collect();
    let expected = commitment::hash_fields(0x4c42563210, &fields).unwrap();
    for round in 0..5 {
        for is_candidate in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let implementation = if is_candidate { &candidate } else { &baseline };
            for cooperative in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = std::time::Instant::now();
                let (digest, device_ns, local_bytes) = implementation.hash(&fields, cooperative);
                let wall_ns = start.elapsed().as_nanos();
                assert_eq!(digest, expected);
                assert!(device_ns > 0 && device_ns as u128 <= wall_ns);
                println!(
                    "unroll_hash_comparison {}",
                    serde_json::json!({
                    "round":round,"candidate":is_candidate,"cooperative":cooperative,
                    "fields":fields.len(),"device_ns":device_ns,"wall_ns":wall_ns,
                    "cpu_oracle_equal":true,"global_workspace_bytes":WORKSPACE_BYTES,
                    "source_local_bytes":if cooperative {64} else {0},
                    "driver_local_bytes":local_bytes})
                );
            }
        }
    }
}
