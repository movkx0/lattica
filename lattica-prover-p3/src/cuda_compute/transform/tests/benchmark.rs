//! Public synthetic matrices; CPU-oracle reads are outside the timed interval.
use super::*;
use std::time::Instant;

#[test]
#[ignore = "manual CUDA microbenchmark; set LATTICA_CUDA_TRANSFORM_BENCHMARK=1"]
fn cuda_transform_reuse_benchmark() {
    if std::env::var("LATTICA_CUDA_TRANSFORM_BENCHMARK").as_deref() != Ok("1") {
        return;
    }
    let runtime = test_runtime(768 << 20, 256 << 20);
    let transforms = Transforms::new(&runtime).unwrap();
    for (input_log, output_log, columns, extension) in [
        (10, 15, 64, Extension::Cubic),
        (12, 16, 32, Extension::Cubic),
        (12, 14, 127, Extension::Base),
    ] {
        let width = columns * extension.degree();
        let raw = raw_words((1 << input_log) * width);
        let values = raw.iter().map(|w| Val::from_u64(*w)).collect();
        let expected = Dft::default()
            .coset_lde_batch(
                RowMajorMatrix::new(values, width),
                (output_log - input_log) as usize,
                Val::from_u64(7) * Val::from_u64(11).inverse(),
            )
            .to_row_major_matrix();
        let input = runtime
            .upload_matrix(
                spec(input_log, columns, extension, RowOrder::Natural, 11),
                &raw,
            )
            .unwrap();
        for iteration in 0..6 {
            let before = runtime.snapshot();
            let started = Instant::now();
            let output = transforms
                .lde(&input, output_log, 7, RowOrder::Natural)
                .unwrap();
            let seconds = started.elapsed().as_secs_f64();
            let after = runtime.snapshot();
            let actual = output.read(output.spec().bytes()).unwrap();
            assert!(actual
                .iter()
                .zip(&expected.values)
                .all(|(a, b)| *a == b.as_canonical_u64()));
            assert_eq!(actual.len(), expected.values.len());
            drop(output);
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().pending_commands, 0);
            println!(
                "cuda_transform_benchmark {}",
                serde_json::json!({
                    "input_log": input_log, "output_log": output_log, "width": width,
                    "phase": if iteration == 0 { "warmup" } else { "measured" },
                    "iteration": iteration, "seconds": seconds,
                    "device_receipt_ns": after.device_ns - before.device_ns,
                    "commands": after.completed_commands - before.completed_commands,
                    "reuse": cfg!(feature = "gpu-cuda-transform-reuse"), "cpu_audit": "passed",
                    "scope": "interpolation/LDE including device allocation; CPU audit excluded",
                })
            );
        }
    }
}
