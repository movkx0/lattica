//! Opt-in comparison with identical device-resident results and CPU audits.
//! Includes operation allocation, expansion and transfers; excludes setup,
//! result readback and result cleanup. This is not a complete proof benchmark.
use super::*;
use std::time::Instant;

const WARMUPS: usize = 2;
const SAMPLES: usize = 5;

#[test]
#[ignore = "manual CUDA primitive benchmark; set LATTICA_CUDA_RANDOM_BENCHMARK=1"]
fn cuda_random_primitive_benchmark() {
    if std::env::var("LATTICA_CUDA_RANDOM_BENCHMARK").as_deref() != Ok("1") {
        eprintln!("manual random benchmark disabled; set LATTICA_CUDA_RANDOM_BENCHMARK=1");
        return;
    }
    let runtime = runtime(64 << 20, 32 << 20);
    let started = Instant::now();
    let engine = Randoms::new(&runtime).unwrap();
    println!(
        "LATTICA_CUDA_RANDOM_PREPARATION {}",
        serde_json::json!({
            "milliseconds": started.elapsed().as_secs_f64() * 1000.0,
            "includes_nvrtc": true,
            "debug_host": cfg!(debug_assertions),
            "identity": runtime.identity(),
        })
    );
    let baseline = runtime.snapshot();
    for count in [256, 4096, 65536, BATCH_WORDS + 17] {
        for iteration in 0..WARMUPS + SAMPLES {
            let mut initial = ChaCha20Rng::from_seed([iteration as u8 + 19; 32]);
            initial.set_stream(17);
            initial.set_word_pos(15);
            let mut oracle = initial.clone();
            let expected_values = expected(&mut oracle, count);
            // Alternate paired order to reduce thermal/order bias.
            let modes = if iteration % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for native in modes {
                let mut cpu = initial.clone();
                // Both modes retain the same imported key; seed import and
                // engine preparation are outside the operation timing.
                let gpu = engine.import(initial.clone()).unwrap();
                let before = runtime.snapshot();
                let started = Instant::now();
                let output = if native {
                    gpu.sample_fields(count).unwrap().storage
                } else {
                    let values = expected(&mut cpu, count);
                    let output = runtime.allocate(count).unwrap();
                    output.write(0, &values).unwrap();
                    output
                };
                let milliseconds = started.elapsed().as_secs_f64() * 1000.0;
                let after = runtime.snapshot();
                assert_eq!(read(&output), expected_values);
                if native {
                    assert_eq!(*gpu.0.position.lock().unwrap(), oracle.get_word_pos());
                    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                    assert_eq!(
                        after.downloaded_bytes - before.downloaded_bytes,
                        count.div_ceil(BATCH_WORDS) as u64 * 8
                    );
                } else {
                    assert_eq!(cpu.get_word_pos(), oracle.get_word_pos());
                    assert_eq!(
                        after.uploaded_bytes - before.uploaded_bytes,
                        count as u64 * 8
                    );
                    assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
                }
                println!(
                    "LATTICA_CUDA_RANDOM_BENCHMARK {}",
                    serde_json::json!({
                        "case": if native { "cuda_generate_resident" } else { "cpu_generate_upload" },
                        "fields": count,
                        "iteration": iteration,
                        "warmup": iteration < WARMUPS,
                        "milliseconds": milliseconds,
                        "commands": after.completed_commands - before.completed_commands,
                        "uploaded_bytes": after.uploaded_bytes - before.uploaded_bytes,
                        "downloaded_bytes": after.downloaded_bytes - before.downloaded_bytes,
                        "copied_bytes": after.copied_bytes - before.copied_bytes,
                        "managed_peak_bytes_cumulative": after.peak_bytes,
                        "cpu_audited": true,
                    })
                );
                drop((output, gpu));
                assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
                assert_eq!(runtime.snapshot().allocations, baseline.allocations);
            }
        }
    }
}
