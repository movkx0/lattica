//! CPU-audited, opt-in comparison of equivalent arity-16 folding strategies.
//! This measures primitive costs, not FRI proofs or transaction throughput.
use super::tests::{runtime, upload, value, words};
use super::*;
use crate::config::Val;
use p3_field::ExtensionField;
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_matrix::dense::RowMajorMatrix;
use std::time::Instant;

fn compare<F: ExtensionField<Val>>(
    runtime: &Runtime,
    fri: &Fri,
    extension: Extension,
    log_rows: u32,
) {
    let values: Vec<F> = (0..1 << log_rows).map(value).collect();
    let matrix = upload(runtime, extension, log_rows, 7, &values);
    let vector = fri.rescale(&matrix).unwrap();
    let retained = runtime.snapshot();
    for iteration in 0..7 {
        let beta = value::<F>(iteration + 91);
        let oracle = TwoAdicFriFolding::<(), ()>(core::marker::PhantomData);
        let expected = words(&<_ as FriFoldingStrategy<Val, F>>::fold_matrix(
            &oracle,
            beta,
            4,
            RowMajorMatrix::new(values.clone(), 16),
        ));
        // Public fixture challenge preparation is outside both timed arms.
        // Four binary rounds use beta, beta^2, beta^4 and beta^8, exactly
        // matching the single arity-16 fold. No transcript protocol is changed.
        let challenges = runtime.allocate(4 * extension.degree()).unwrap();
        let powers: Vec<_> = (0..4).map(|i| beta.exp_power_of_2(i)).collect();
        challenges.write(0, &words(&powers)).unwrap();
        let binary: Vec<_> = (0..4)
            .map(|i| {
                fri.round(
                    extension,
                    1,
                    FieldSpan {
                        buffer: &challenges,
                        first: i * extension.degree(),
                    },
                )
                .unwrap()
            })
            .collect();
        let fused = fri
            .round(
                extension,
                4,
                FieldSpan {
                    buffer: &challenges,
                    first: 0,
                },
            )
            .unwrap();
        drop(challenges);
        let baseline = runtime.snapshot();
        let order = if iteration % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for single in order {
            let before = runtime.snapshot();
            let started = Instant::now();
            let output = if single {
                fused.fold(&vector).unwrap()
            } else {
                let mut output = binary[0].fold(&vector).unwrap();
                for round in &binary[1..] {
                    output = round.fold(&output).unwrap();
                }
                output
            };
            let milliseconds = started.elapsed().as_secs_f64() * 1000.0;
            let after = runtime.snapshot();
            assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
            assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
            assert_eq!(output.matrix.read(1 << 20).unwrap(), expected);
            println!(
                "LATTICA_CUDA_FRI_BENCHMARK {}",
                serde_json::json!({
                    "extension_degree": extension.degree(), "log_rows": log_rows,
                    "iteration": iteration, "warmup": iteration < 2,
                    "strategy": if single { "arity16" } else { "four_binary_folds" },
                    "fold_ms": milliseconds,
                    "commands": after.completed_commands - before.completed_commands,
                    "upload_bytes": after.uploaded_bytes - before.uploaded_bytes,
                    "download_bytes": after.downloaded_bytes - before.downloaded_bytes,
                    "retained_output_bytes": after.live_bytes - before.live_bytes,
                    "runtime_peak_bytes": after.peak_bytes,
                    "cpu_audited": true,
                })
            );
            drop(output);
            assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
            assert_eq!(runtime.snapshot().allocations, baseline.allocations);
        }
        drop(fused);
        drop(binary);
        assert_eq!(runtime.snapshot().live_bytes, retained.live_bytes);
        assert_eq!(runtime.snapshot().allocations, retained.allocations);
    }
}

#[test]
#[ignore = "requires CUDA and LATTICA_CUDA_FRI_BENCHMARK=1"]
fn cuda_fri_folding_benchmark() {
    assert_eq!(
        std::env::var("LATTICA_CUDA_FRI_BENCHMARK").as_deref(),
        Ok("1")
    );
    let started = Instant::now();
    let runtime = runtime(64 << 20, 16 << 20);
    let fri = Fri::new(&runtime).unwrap();
    println!(
        "LATTICA_CUDA_FRI_PREPARATION {}",
        serde_json::json!({
            "milliseconds": started.elapsed().as_secs_f64() * 1000.0,
            "profile": if cfg!(debug_assertions) { "debug-host" } else { "release-host" },
            "device": runtime.identity(),
            "managed_bytes": 64 << 20, "max_allocation_bytes": 16 << 20,
        })
    );
    for log_rows in [16, 18] {
        compare::<crate::config::Challenge>(&runtime, &fri, Extension::Quadratic, log_rows);
        compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(
            &runtime,
            &fri,
            Extension::Cubic,
            log_rows,
        );
    }
}
