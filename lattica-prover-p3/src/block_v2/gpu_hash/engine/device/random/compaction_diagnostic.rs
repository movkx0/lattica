//! Paired synthetic-buffer diagnostic. No candidate, proof or native journal.

use super::*;
use std::{io::Write, path::PathBuf, time::Instant};

#[test]
#[ignore = "requires explicit output, OpenCL GPU and serial <=3 GiB zero-swap service"]
fn gpu_random_compaction_parallel_offsets_match_serial_offsets() {
    let output_path = PathBuf::from(
        std::env::var_os("LATTICA_RANDOM_COMPACTION_DIAGNOSTIC")
            .expect("explicit diagnostic output required"),
    );
    assert!(output_path.is_absolute() && !output_path.exists());
    let _shutdown = super::super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let mut measurements = Vec::new();
    for count in [4097usize, 65_536, BATCH_WORDS] {
        for mixed in [false, true] {
            let candidates: Vec<u64> = (0..count)
                .map(|i| {
                    if mixed && i % 257 == 0 {
                        GOLDILOCKS_MODULUS
                    } else {
                        i as u64 * 73 + 5
                    }
                })
                .collect();
            let mut cpu = Scripted {
                values: candidates.iter(),
            };
            let accepted = candidates
                .iter()
                .filter(|&&v| v < GOLDILOCKS_MODULUS)
                .count();
            let expected: Vec<u64> = (0..accepted)
                .map(|_| cpu.random::<Val>().as_canonical_u64())
                .collect();
            session.with_engine(|engine| {
                let plan = Plan::new(count + 34, 15, engine.accounting.lock().unwrap().live,
                                     engine.limits.managed_bytes, engine.max_alloc)?;
                let raw = SecretAllocation::new(engine, plan.raw_words)?;
                let counts = SecretAllocation::new(engine, plan.tiles)?;
                let offsets = SecretAllocation::new(engine, plan.tiles)?;
                let total = SecretAllocation::new(engine, 1)?;
                let output = RandomWords {
                    storage: SecretAllocation::new(engine, count + 34)?,
                    session: session.clone(), count: count + 34,
                };
                let mut words = vec![0u64; plan.raw_words];
                for (i, &sample) in candidates.iter().enumerate() {
                    for (j, word) in [sample as u32, (sample >> 32) as u32].into_iter().enumerate() {
                        let at = 15 + 2 * i + j;
                        words[at / 2] |= u64::from(word) << (32 * (at % 2));
                    }
                }
                let fence = engine.fence();
                raw.buffer().write(&words[..]).enq().map_err(|e| e.to_string())?;
                output.buffer().cmd().fill(9u64, None).enq().map_err(|e| e.to_string())?;
                fence.finish()?;
                // Warm both kernels outside measured windows, without changing
                // the queue, admitted buffers, raw values or output positions.
                for layout in [CompactionLayout::SerialOffsetsReference, CompactionLayout::Parallel] {
                    let (n, _) = compact_with_layout(engine, &raw, &counts, &offsets, &total,
                                                    &output, 15, count, 17, layout)?;
                    assert_eq!(n, accepted);
                }
                for (run, layout) in [CompactionLayout::SerialOffsetsReference, CompactionLayout::Parallel,
                                      CompactionLayout::Parallel, CompactionLayout::SerialOffsetsReference]
                    .into_iter().enumerate()
                {
                    let started = Instant::now();
                    let mut device_ns = 0u128;
                    let repetitions = 8;
                    for _ in 0..repetitions {
                        let (n, elapsed) = compact_with_layout(engine, &raw, &counts, &offsets,
                                                              &total, &output, 15, count, 17, layout)?;
                        assert_eq!(n, accepted);
                        device_ns += elapsed;
                    }
                    let wall_ns = started.elapsed().as_nanos();
                    // Readback and independent reference checks are outside the
                    // measurement. Both untouched guards must also match.
                    let mut actual = vec![0u64; count + 34];
                    output.buffer().read(&mut actual[..]).enq().map_err(|e| e.to_string())?;
                    fence.finish()?;
                    assert!(actual[..17].iter().all(|&v| v == 9));
                    assert_eq!(&actual[17..17 + accepted], &expected);
                    assert!(actual[17 + accepted..].iter().all(|&v| v == 9));
                    assert!(device_ns > 0, "GPU event timing must be enabled");
                    measurements.push(serde_json::json!({
                        "count":count, "mixed_rejections":mixed, "accepted":accepted, "run":run,
                        "layout":if matches!(layout, CompactionLayout::Parallel) {"parallel"} else {"serial"},
                        "repetitions":repetitions, "device_ns":device_ns, "wall_ns":wall_ns,
                        "matches_cpu_reference":true, "guards_unchanged":true,
                    }));
                }
                Ok(())
            }).unwrap();
        }
    }
    let result = serde_json::json!({
        "status":"passed", "measurements":measurements, "proofs_generated":0,
        "candidates_prepared":0, "native_blocks_applied":0,
        "scope":"paired synthetic GPU compaction with serial versus parallel offsets; count and scatter unchanged; no proving throughput qualification",
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .unwrap();
    serde_json::to_writer_pretty(&mut output, &result).unwrap();
    output.write_all(b"\n").unwrap();
}
