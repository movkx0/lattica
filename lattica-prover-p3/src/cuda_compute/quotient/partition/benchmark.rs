//! Opt-in microbenchmark. Complete proofs and transaction throughput are outside
//! this measurement boundary. Every result is checked against the CPU oracle.
use super::{
    super::tests::{matrix, oracle, runtime, scalars},
    tests::extend,
    *,
};
use crate::{
    block_v2::{
        profile::Challenge as F,
        quotient_program::test_support::{constant, program_with_main_width, words},
    },
    config::Val,
};
use p3_field::{BasedVectorSpace, PrimeField64};
use serde_json::json;

#[test]
#[ignore = "manual CUDA microbenchmark; set LATTICA_CUDA_PARTITION_BENCHMARK=1"]
fn cuda_partitioned_quotient_benchmark() {
    if std::env::var("LATTICA_CUDA_PARTITION_BENCHMARK").as_deref() != Ok("1") {
        eprintln!("manual CUDA microbenchmark disabled");
        return;
    }
    let cold = Instant::now();
    let runtime = runtime(32 << 20, 8 << 20);
    let transforms = Transforms::new(&runtime).unwrap();
    let evaluator = Quotients::new(&runtime).unwrap();
    let prepared = evaluator
        .prepare(
            Arc::new(program_with_main_width::<F>(64)),
            Specialization::Prefer,
        )
        .unwrap();
    assert!(prepared.specialized.is_some());
    println!(
        "cuda_partition_benchmark {}",
        json!({
            "kind": "setup", "cold_seconds": cold.elapsed().as_secs_f64(),
            "program_preparation_ns": prepared.preparation_ns,
            "specialized_source_bytes": prepared.source_bytes,
            "local_bytes_per_thread": prepared.local_bytes,
            "managed_bytes": 32 << 20, "max_allocation_bytes": 8 << 20,
            "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "scope": "CUDA cubic quotient reconstruction/evaluation; not complete proving or transactions",
        })
    );
    let public = [Val::new(31), Val::new(0xffff_ffff_0000_0000)];
    let challenges = [
        constant::<F>(),
        F::from_basis_coefficients_fn(|i| Val::new(17 + i as u64)),
    ];
    let terminal = F::from_basis_coefficients_fn(|i| Val::new(29 + i as u64));
    let alpha = constant::<F>();
    let alpha_buffer = scalars(&runtime, &words(alpha));
    let parameters = scalars(
        &runtime,
        &public
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .chain(challenges.into_iter().chain([terminal]).flat_map(words))
            .collect::<Vec<_>>(),
    );
    let log_quotient = 13;
    let shift = 7;
    for (case, log_trace, logs) in [
        ("sixteen_cosets", 8, [8, 9, 7]),
        ("maximum_cosets", 4, [4, 5, 3]),
    ] {
        let (main, main_values) = matrix(
            &runtime,
            logs[0],
            64,
            Extension::Base,
            RowOrder::BitReversed,
            shift,
            17,
        );
        let (pre, pre_values) = matrix(
            &runtime,
            logs[1],
            2,
            Extension::Base,
            RowOrder::Natural,
            shift,
            19,
        );
        let (perm, perm_values) = matrix(
            &runtime,
            logs[2],
            2,
            Extension::Cubic,
            RowOrder::BitReversed,
            shift,
            23,
        );
        let inputs = QuotientInputs {
            main: Some(&main),
            preprocessed: Some(&pre),
            permutation: Some(&perm),
        };
        let expected: Vec<_> = oracle(
            log_trace,
            log_quotient,
            shift,
            64,
            &extend(main_values, 64, log_quotient - logs[0]),
            &extend(pre_values, 2, log_quotient - logs[1]),
            &extend(perm_values, 6, log_quotient - logs[2]),
            public,
            challenges,
            terminal,
            alpha,
        )
        .into_iter()
        .flat_map(words)
        .collect();
        let plan = PartitionPlan::new(
            &prepared.program,
            [Some(main.spec), Some(pre.spec), Some(perm.spec)],
            log_trace,
            log_quotient,
            shift,
            runtime.snapshot().live_bytes,
            runtime.state.budget.limits,
        )
        .unwrap();
        println!(
            "cuda_partition_benchmark {}",
            json!({
                "kind": "case", "case": case, "log_trace": log_trace,
                "log_quotient": log_quotient, "prefix_logs": logs, "main_width": 64,
                "cosets": plan.cosets, "partition_plan_peak_bytes": plan.peak_bytes,
                "materialized_main_bytes": (1usize << log_quotient) * 64 * 8,
            })
        );
        // Two unreported warmups per variant, then five alternating pairs.
        for pair in 0..7 {
            for partitioned in if pair % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let before = runtime.snapshot();
                let started = Instant::now();
                let result = if partitioned {
                    evaluator
                        .evaluate_partitioned(
                            &transforms,
                            &prepared,
                            log_trace,
                            log_quotient,
                            shift,
                            inputs,
                            &alpha_buffer,
                            Some(&parameters),
                        )
                        .unwrap()
                } else {
                    let main = transforms
                        .lde(&main, log_quotient, shift, RowOrder::BitReversed)
                        .unwrap();
                    let pre = transforms
                        .lde(&pre, log_quotient, shift, RowOrder::BitReversed)
                        .unwrap();
                    let perm = transforms
                        .lde(&perm, log_quotient, shift, RowOrder::BitReversed)
                        .unwrap();
                    evaluator
                        .evaluate(
                            &prepared,
                            log_trace,
                            QuotientInputs {
                                main: Some(&main),
                                preprocessed: Some(&pre),
                                permutation: Some(&perm),
                            },
                            &alpha_buffer,
                            Some(&parameters),
                        )
                        .unwrap()
                };
                let seconds = started.elapsed().as_secs_f64();
                let after = runtime.snapshot();
                assert_eq!(result.read(result.spec.bytes()).unwrap(), expected);
                drop(result);
                assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
                assert_eq!(runtime.snapshot().pending_commands, 0);
                if pair >= 2 {
                    println!(
                        "cuda_partition_benchmark {}",
                        json!({
                            "kind": "sample", "case": case, "pair": pair - 1,
                            "variant": if partitioned { "partitioned" } else { "materialized" },
                            "seconds": seconds, "device_ns": after.device_ns - before.device_ns,
                            "commands": after.completed_commands - before.completed_commands,
                            "uploaded_bytes": after.uploaded_bytes - before.uploaded_bytes,
                            "downloaded_bytes": after.downloaded_bytes - before.downloaded_bytes,
                            "copied_bytes": after.copied_bytes - before.copied_bytes,
                            "cpu_audit": "passed",
                        })
                    );
                }
            }
        }
    }
}
