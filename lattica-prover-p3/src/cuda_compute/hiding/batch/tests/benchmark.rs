//! Opt-in, CPU-audited measurements of streamed hidden commitments and queries.
//! Host test code is normally debug-built; these are not proof-throughput results.
use super::*;
use std::time::Instant;

const WARMUPS: usize = 2;
const SAMPLES: usize = 5;

#[test]
#[ignore = "requires CUDA and LATTICA_CUDA_HIDDEN_BENCHMARK=1"]
fn cuda_hidden_commitment_benchmark() {
    assert_eq!(
        std::env::var("LATTICA_CUDA_HIDDEN_BENCHMARK").as_deref(),
        Ok("1"),
        "set LATTICA_CUDA_HIDDEN_BENCHMARK=1"
    );
    let started = Instant::now();
    let runtime = runtime(16 << 20, 4 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    println!(
        "LATTICA_CUDA_HIDDEN_PREPARATION {}",
        serde_json::json!({
            "milliseconds": started.elapsed().as_secs_f64() * 1000.0,
            "profile": if cfg!(debug_assertions) { "debug-host" } else { "release-host" },
            "device": runtime.identity(),
            "managed_bytes": 16 << 20,
            "max_allocation_bytes": 4 << 20,
        })
    );
    for (case, log, width, extension, queries) in [
        ("quadratic", 8, 9, Extension::Quadratic, 33),
        ("wide_cubic", 10, 17, Extension::Cubic, 4),
    ] {
        let output_log = log + 1 + config::LOG_BLOWUP as u32;
        let full_rows = 1usize << output_log;
        let (trace, cpu_trace) = upload(&runtime, log, width, extension, 1, 17);
        let baseline = runtime.snapshot();
        let indices: Vec<_> = (0..queries)
            .map(|q| [full_rows - 1, 0, full_rows / 3, full_rows - 1][q % 4])
            .collect();
        for iteration in 0..WARMUPS + SAMPLES {
            // Identical randomness and inputs across tile geometries, changed
            // between iterations. Deterministic seeds are confined to this test.
            let hiding_seed = 29 + iteration as u8;
            let salt_seed = 43 + iteration as u8;
            let oracle = mmcs(rng(salt_seed), 0);
            let oracle_pcs = pcs(rng(hiding_seed), oracle.clone());
            let (expected_cap, expected_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(
                &oracle_pcs,
                [(
                    Domain::new(Val::ONE, log as usize + 1).unwrap(),
                    cpu_trace.clone(),
                )],
            );
            let dimensions: Vec<_> = oracle
                .get_matrices(&expected_data)
                .iter()
                .map(|m| m.dimensions())
                .collect();
            // Alternate ordering to expose simple drift instead of always
            // giving the same geometry the first measurement.
            let order = if iteration % 2 == 0 {
                [1, 2, 4]
            } else {
                [4, 2, 1]
            };
            for columns in order {
                let random = randoms.import(rng(hiding_seed)).unwrap();
                let salts = randoms.import(rng(salt_seed)).unwrap();
                let started = Instant::now();
                let prepared = hiding
                    .prepare_trace(&trace, &random, output_log, columns)
                    .unwrap();
                let hiding_ms = started.elapsed().as_secs_f64() * 1000.0;
                let before = runtime.snapshot();
                let started = Instant::now();
                let data = hiding
                    .commit_batch(&commitments, &[HidingInput::Trace(&prepared)], &salts, 0)
                    .unwrap();
                let cap_words = data.cap(32).unwrap();
                let commitment_ms = started.elapsed().as_secs_f64() * 1000.0;
                let after_commit = runtime.snapshot();
                let started = Instant::now();
                let actual = data
                    .open(&commitments, &hiding.transforms, &indices, 2 << 20)
                    .unwrap();
                let query_ms = started.elapsed().as_secs_f64() * 1000.0;
                let after_query = runtime.snapshot();

                // Independent CPU construction, wire equality and verification
                // are outside the operation timings, on every measured result.
                let cap = MerkleCap::new(digests(&cap_words));
                assert_eq!(cap, expected_cap);
                for (q, &index) in indices.iter().enumerate() {
                    let opened = opening(&actual, q);
                    assert_eq!(
                        postcard::to_allocvec(&opened).unwrap(),
                        postcard::to_allocvec(&oracle.open_batch(index, &expected_data)).unwrap()
                    );
                    oracle
                        .verify_batch(&cap, &dimensions, index, BatchOpeningRef::from(&opened))
                        .unwrap();
                }
                println!(
                    "LATTICA_CUDA_HIDDEN_BENCHMARK {}",
                    serde_json::json!({
                        "case": case, "iteration": iteration, "warmup": iteration < WARMUPS,
                        "input_rows": 1usize << log, "input_base_columns": width * extension.degree(),
                        "lde_rows": full_rows, "tile_columns": columns, "queries": queries,
                        "full_lde_bytes": full_rows * (width * extension.degree() + config::NUM_RANDOM_CODEWORDS) * 8,
                        "hiding_ms": hiding_ms, "commitment_ms": commitment_ms, "query_ms": query_ms,
                        "retained_commitment_bytes": after_commit.live_bytes - before.live_bytes,
                        "managed_peak_bytes_cumulative": after_query.peak_bytes,
                        "commitment_commands": after_commit.completed_commands - before.completed_commands,
                        "commitment_uploaded_bytes": after_commit.uploaded_bytes - before.uploaded_bytes,
                        "commitment_downloaded_bytes": after_commit.downloaded_bytes - before.downloaded_bytes,
                        "query_commands": after_query.completed_commands - after_commit.completed_commands,
                        "query_uploaded_bytes": after_query.uploaded_bytes - after_commit.uploaded_bytes,
                        "query_downloaded_bytes": after_query.downloaded_bytes - after_commit.downloaded_bytes,
                        "cpu_audited": true,
                    })
                );
                drop((actual, data, prepared, random, salts));
                assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
                assert_eq!(runtime.snapshot().allocations, baseline.allocations);
            }
        }
    }
}
