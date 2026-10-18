//! Opt-in native primitive timings. CPU audits are outside the timed regions.
//! These are debug-host operation timings, not proof or transaction throughput.
use super::*;
use crate::cuda_compute::Snapshot;
use std::time::Instant;

const WARMUPS: usize = 2;
const SAMPLES: usize = 5;

fn record(
    case: &str,
    iteration: usize,
    milliseconds: f64,
    before: Snapshot,
    after: Snapshot,
    detail: serde_json::Value,
) {
    println!(
        "LATTICA_CUDA_TRANSCRIPT_BENCHMARK {}",
        serde_json::json!({
            "case": case,
            "iteration": iteration,
            "warmup": iteration < WARMUPS,
            "milliseconds": milliseconds,
            "commands": after.completed_commands - before.completed_commands,
            "uploaded_bytes": after.uploaded_bytes - before.uploaded_bytes,
            "downloaded_bytes": after.downloaded_bytes - before.downloaded_bytes,
            "copied_bytes": after.copied_bytes - before.copied_bytes,
            "managed_peak_bytes_cumulative": after.peak_bytes,
            "cpu_audited": true,
            "detail": detail,
        })
    );
}

#[test]
#[ignore = "manual CUDA primitive benchmark; set LATTICA_CUDA_TRANSCRIPT_BENCHMARK=1"]
fn cuda_transcript_primitive_benchmark() {
    if std::env::var("LATTICA_CUDA_TRANSCRIPT_BENCHMARK").as_deref() != Ok("1") {
        eprintln!("manual transcript benchmark disabled; set LATTICA_CUDA_TRANSCRIPT_BENCHMARK=1");
        return;
    }
    let runtime = runtime(2 << 20, 1 << 20);
    let preparation = Instant::now();
    let engine = Transcripts::new(&runtime).unwrap();
    println!(
        "LATTICA_CUDA_TRANSCRIPT_PREPARATION {}",
        serde_json::json!({
            "milliseconds": preparation.elapsed().as_secs_f64() * 1000.0,
            "includes_nvrtc_and_public_constants": true,
            "debug_host": cfg!(debug_assertions),
            "identity": runtime.identity(),
        })
    );
    let baseline = runtime.snapshot();
    for (observations, samples) in [(64, 32), (1024, 256)] {
        // Alternating the two transfer modes keeps their inputs and run order paired.
        for iteration in 0..WARMUPS + SAMPLES {
            let words: Vec<_> = (0..observations)
                .map(|i| (iteration * 100_003 + i * 193 + 7) as u64)
                .collect();
            for resident in [iteration % 2 == 0, iteration % 2 != 0] {
                let mut actual = engine.start().unwrap();
                let mut reference = cpu();
                reference.observe_slice(&words.iter().copied().map(Val::new).collect::<Vec<_>>());
                // This input upload is deliberately outside the resident-operation timer.
                let input = if resident {
                    let input = runtime.allocate(words.len()).unwrap();
                    input.write(0, &words).unwrap();
                    Some(input)
                } else {
                    None
                };
                let before = runtime.snapshot();
                let started = Instant::now();
                let (public, device) = if let Some(input) = &input {
                    actual.observe_resident(input, 0, words.len()).unwrap();
                    (None, Some(actual.sample_resident(samples).unwrap()))
                } else {
                    actual.observe(&words).unwrap();
                    (Some(actual.sample_fields(samples).unwrap()), None)
                };
                let milliseconds = started.elapsed().as_secs_f64() * 1000.0;
                let after = runtime.snapshot();
                let output = public.unwrap_or_else(|| {
                    let mut output = vec![0; samples];
                    device.as_ref().unwrap().read(0, &mut output).unwrap();
                    output
                });
                assert_eq!(output, sample(&mut reference, samples));
                assert_eq!(actual.sample_fields(5).unwrap(), sample(&mut reference, 5));
                assert_eq!(
                    after.uploaded_bytes - before.uploaded_bytes,
                    if resident {
                        0
                    } else {
                        (observations * 8) as u64
                    }
                );
                assert_eq!(
                    after.downloaded_bytes - before.downloaded_bytes,
                    if resident { 0 } else { (samples * 8) as u64 }
                );
                record(
                    if resident {
                        "resident_exchange"
                    } else {
                        "public_exchange"
                    },
                    iteration,
                    milliseconds,
                    before,
                    after,
                    serde_json::json!({"observations": observations, "samples": samples}),
                );
                drop(device);
                drop(input);
                drop(actual);
                assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
                assert_eq!(runtime.snapshot().allocations, baseline.allocations);
            }
        }
    }
    for bits in [0, 8, 16, 20] {
        for iteration in 0..WARMUPS + SAMPLES {
            let mut actual = engine.start().unwrap();
            let mut reference = cpu();
            let words: Vec<_> = (0..64 + iteration % 4)
                .map(|i| (iteration * 100_003 + i * 193 + 7) as u64)
                .collect();
            actual.observe(&words).unwrap();
            reference.observe_slice(&words.iter().copied().map(Val::new).collect::<Vec<_>>());
            let before = runtime.snapshot();
            let started = Instant::now();
            let witness = actual.grind(bits).unwrap();
            let milliseconds = started.elapsed().as_secs_f64() * 1000.0;
            let after = runtime.snapshot();
            assert!(reference.check_witness(bits, Val::new(witness)));
            assert_eq!(actual.sample_fields(9).unwrap(), sample(&mut reference, 9));
            let batches = if bits == 0 {
                0
            } else {
                witness / limits::GRIND_BATCH as u64 + 1
            };
            assert_eq!(
                after.downloaded_bytes - before.downloaded_bytes,
                16 * batches
            );
            assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
            assert_eq!(after.live_bytes, before.live_bytes);
            record(
                "grind",
                iteration,
                milliseconds,
                before,
                after,
                serde_json::json!({"bits": bits, "witness": witness, "batches": batches}),
            );
            drop(actual);
            assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
            assert_eq!(runtime.snapshot().allocations, baseline.allocations);
        }
    }
}
