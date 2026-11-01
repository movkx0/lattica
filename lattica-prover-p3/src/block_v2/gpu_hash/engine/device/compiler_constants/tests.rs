use super::*;
use crate::block_v2::machine::compiler_constants::Constants;
use p3_field::{Field, TwoAdicField};

fn table(name: &str) -> Vec<Val> {
    let source = include_str!("tables.cl");
    let declaration = source.split(&format!(" {name}[")).nth(1).unwrap();
    let (length, body) = declaration.split_once("] = {").unwrap();
    let words: Vec<_> = body
        .split_once("};")
        .unwrap()
        .0
        .split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .map(|word| {
            let word = u64::from_str_radix(
                word.strip_prefix("0x").unwrap().strip_suffix("UL").unwrap(),
                16,
            )
            .unwrap();
            assert!(word < GOLDILOCKS_MODULUS);
            Val::new(word)
        })
        .collect();
    assert_eq!(words.len(), length.parse::<usize>().unwrap());
    words
}

#[test]
fn public_tables_match_independent_field_arithmetic() {
    let roots = table("compiler_inverse_roots");
    assert_eq!(roots.len(), 33);
    for (log, root) in roots.iter().enumerate() {
        assert_eq!(*root, Val::two_adic_generator(log).inverse());
    }
    let factorials = table("compiler_inverse_factorials");
    assert_eq!(factorials.len(), MAX_SELECTORS as usize);
    let mut factorial = Val::ONE;
    for (n, inverse) in factorials.iter().enumerate() {
        if n != 0 {
            factorial *= Val::from_usize(n);
        }
        assert_eq!(*inverse, factorial.inverse());
    }
    let differences = table("compiler_reciprocal_differences");
    assert_eq!(differences.len(), MAX_QUOTIENT_CHUNKS);
    assert_eq!(differences[0], Val::ZERO);
    for (n, inverse) in differences.iter().enumerate().skip(1) {
        assert_eq!(
            *inverse,
            (Val::two_adic_generator(5).exp_u64(n as u64) - Val::ONE).inverse()
        );
    }
    assert_eq!(table("compiler_inverse_coset"), [Val::GENERATOR.inverse()]);
}

#[cfg(feature = "gpu")]
fn compiler_run() -> Run {
    use crate::proving::{Capabilities, CoverageScope, Policy, Profile, Request};
    let mut caps = Capabilities::cpu(Profile::BlockV2Cubic, true, false)
        .scoped(CoverageScope::Operation, &[Stage::Preprocessing]);
    caps.set(Stage::Preprocessing, Backend::OpenCl);
    Run::new(
        "gpu_compiler_lookup_test",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        caps,
    )
    .unwrap()
}

#[cfg(feature = "gpu")]
fn initialize() -> DeviceSession {
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(super::super::super::Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    DeviceSession::new().unwrap()
}

#[cfg(feature = "gpu")]
fn live(session: &DeviceSession) -> usize {
    session
        .with_engine(|engine| Ok(engine.accounting.lock().unwrap().live))
        .unwrap()
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires OpenCL GPU; run serially in bounded service"]
fn gpu_compiler_lookup_matches_cpu_for_all_supported_domains() {
    let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
    let session = initialize();
    let before = live(&session);
    let run = compiler_run();
    let mut calls = 0;
    for log in 0..=32 {
        assert_eq!(
            session.compiler_inverse_generator(log, &run).unwrap(),
            Constants::cpu().inverse_generator(log).unwrap()
        );
        calls += 1;
        assert_eq!(live(&session), before);
    }
    // Includes partial workgroups, both signs, and translated ranges at the
    // modulus boundary. CPU uses the original product-and-invert formula.
    for count in 1..=MAX_SELECTORS as usize {
        for first in [0, 197, GOLDILOCKS_MODULUS - count as u64] {
            let last = first + count as u64 - 1;
            let mut expected = vec![Val::ZERO; count];
            Constants::cpu()
                .selectors_into(first, last, &mut expected)
                .unwrap();
            let mut actual = vec![-Val::ONE; count];
            session
                .compiler_selectors_into(first, last, &mut actual, &run)
                .unwrap();
            assert_eq!(actual, expected, "selector first={first}, count={count}");
            calls += 1;
            assert_eq!(live(&session), before);
        }
    }
    for log_chunks in 0..=MAX_QUOTIENT_CHUNKS.ilog2() as usize {
        let chunks = 1 << log_chunks;
        for height in 0..=32 - log_chunks {
            let mut expected = vec![Val::ZERO; chunks * (chunks + 1)];
            Constants::cpu()
                .quotient_into(chunks, height, &mut expected)
                .unwrap();
            let mut actual = vec![-Val::ONE; expected.len()];
            session
                .compiler_quotient_into(chunks, height, &mut actual, &run)
                .unwrap();
            assert_eq!(
                actual, expected,
                "quotient chunks={chunks}, height={height}"
            );
            calls += 1;
            assert_eq!(live(&session), before);
        }
    }
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete && report.observation_errors == 0);
    assert_eq!(report.observations.len(), 1);
    assert_eq!(report.observations[0].completed_calls, calls);
    assert_eq!(report.observations[0].device_calls, calls);

    let rejected = compiler_run();
    let stats = session.stats();
    assert!(session.compiler_inverse_generator(33, &rejected).is_err());
    for (first, last, length) in [
        (0, 64, 65),
        (4, 3, 0),
        (GOLDILOCKS_MODULUS - 1, GOLDILOCKS_MODULUS, 2),
        (0, 5, 5),
    ] {
        let mut output = vec![-Val::ONE; length];
        assert!(session
            .compiler_selectors_into(first, last, &mut output, &rejected)
            .is_err());
        assert!(output.iter().all(|v| *v == -Val::ONE));
    }
    for (chunks, height, length) in [
        (0, 0, 0),
        (3, 3, 12),
        (64, 10, 4160),
        (32, 28, 1056),
        (1, 33, 2),
        (1, usize::MAX, 2),
        (4, 3, 19),
    ] {
        let mut output = vec![-Val::ONE; length];
        assert!(session
            .compiler_quotient_into(chunks, height, &mut output, &rejected)
            .is_err());
        assert!(output.iter().all(|v| *v == -Val::ONE));
    }
    assert_eq!(session.stats(), stats);
    assert_eq!(live(&session), before);
    assert!(rejected.finish(false).unwrap().observations.is_empty());
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "component timing only; requires exclusive OpenCL GPU in bounded service"]
fn gpu_compiler_lookup_component_timing() {
    let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
    let session = initialize();
    let before = live(&session);
    const REPEATS: usize = 32;
    for (operation, size) in [
        (0, 1usize),
        (1, 8),
        (1, 32),
        (1, 64),
        (3, 4),
        (3, 16),
        (3, 32),
    ] {
        let log_root = 17
            + if operation == 3 {
                size.ilog2() as usize
            } else {
                0
            };
        let input = if operation == 1 {
            197
        } else {
            Val::two_adic_generator(log_root).as_canonical_u64()
        };
        let count = if operation == 3 {
            size * (size + 1)
        } else {
            size
        };
        let mut expected = vec![Val::ZERO; count];
        match operation {
            0 => expected[0] = Constants::cpu().inverse_generator(log_root).unwrap(),
            1 => Constants::cpu()
                .selectors_into(input, input + size as u64 - 1, &mut expected)
                .unwrap(),
            3 => Constants::cpu()
                .quotient_into(size, 17, &mut expected)
                .unwrap(),
            _ => unreachable!(),
        }
        let mut samples = Vec::new();
        // One warmup pair, followed by seven alternating reference/candidate pairs.
        for pair in 0..8 {
            for slot in 0..2 {
                let reference = (slot + pair) % 2 == 0;
                let kernel = if reference {
                    "device_compiler_constants_reference"
                } else {
                    "device_compiler_constants"
                };
                let parameter = if reference { 1 << 17 } else { log_root as u64 };
                let run = compiler_run();
                let mut actual = vec![-Val::ONE; count];
                let started = std::time::Instant::now();
                for _ in 0..REPEATS {
                    session
                        .dispatch_compiler_constants(
                            &[input],
                            operation,
                            size,
                            parameter,
                            &mut actual,
                            &run,
                            kernel,
                        )
                        .unwrap();
                }
                let wall_ns = started.elapsed().as_nanos();
                assert_eq!(actual, expected);
                assert_eq!(live(&session), before);
                let report = run.finish(true).unwrap();
                assert!(report.stage_coverage_complete && report.observation_errors == 0);
                assert_eq!(report.observations[0].completed_calls, REPEATS as u64);
                if pair != 0 {
                    samples.push(serde_json::json!({"pair": pair, "reference": reference,
                        "device_ns": report.observations[0].device_ns, "wall_ns": wall_ns}));
                }
            }
        }
        eprintln!(
            "compiler_lookup_component {}",
            serde_json::json!({
                "schema": "compiler-lookup-component-v1", "operation": operation,
                "size": size, "height": 17, "repeats": REPEATS, "samples": samples,
                "complete_ringct_workflow": false,
            })
        );
    }
}
