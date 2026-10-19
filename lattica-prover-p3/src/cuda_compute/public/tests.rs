use super::*;
use crate::{
    block_v2::{
        commitment,
        machine::{
            compiler_constants::{Constants, FoldOperation, Folding},
            programs,
        },
    },
    cuda_compute::Limits,
    proving::{Policy, Request},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;

fn runtime(limits: Limits) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").expect("assign a CUDA test GPU"),
        limits,
    )
    .unwrap()
}
fn run(stage: Stage) -> Run {
    Run::new(
        "cuda_public_test",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        PublicArithmetic::capabilities(stage).unwrap(),
    )
    .unwrap()
}
fn audited(run: Run, stage: Stage, calls: u64) {
    let report = run.finish(true).unwrap();
    assert!(report.stage_coverage_complete && report.succeeded);
    assert_eq!(report.observations.len(), 1);
    let observation = &report.observations[0];
    assert_eq!(observation.backend, Backend::Cuda);
    assert_eq!(observation.stage, stage);
    assert_eq!(observation.completed_calls, calls);
}

#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_public_hashes_match_cpu_across_stream_boundaries() {
    let runtime = runtime(Limits::default());
    let context = PublicArithmetic::new(&runtime, HOST_BYTES).unwrap();
    for stage in [Stage::PublicValues, Stage::Preprocessing] {
        for length in [
            0,
            1,
            3,
            4,
            5,
            BATCH_WORDS - 1,
            BATCH_WORDS,
            BATCH_WORDS + 1,
            2 * BATCH_WORDS,
            2 * BATCH_WORDS + 3,
        ] {
            let fields: Vec<_> = (0..length)
                .map(|i| [0, 1, MODULUS - 1, i as u64][i % 4])
                .collect();
            let run = run(stage);
            let before = runtime.snapshot();
            let hash = context
                .reported(&run, || {
                    context.hash_public_fields_reported(MODULUS - 1, &fields, &run, stage)
                })
                .unwrap();
            assert_eq!(hash, commitment::hash_fields(MODULUS - 1, &fields).unwrap());
            let after = runtime.snapshot();
            let calls = length.div_ceil(BATCH_WORDS).max(1) as u64;
            assert_eq!(after.completed_commands - before.completed_commands, calls);
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                length as u64 * 8
            );
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 32);
            assert_eq!(after.live_bytes, before.live_bytes);
            assert_eq!(after.allocations, before.allocations);
            audited(run, stage, calls);
        }
    }
    drop(context);
    let snapshot = runtime.snapshot();
    assert_eq!(
        (
            snapshot.live_bytes,
            snapshot.modules,
            snapshot.public_program_bytes
        ),
        (0, 0, 0)
    );
}

#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_public_rejects_invalid_inputs_and_wrong_reporting_scope_before_work() {
    let runtime = runtime(Limits::default());
    let context = PublicArithmetic::new(&runtime, HOST_BYTES).unwrap();
    let run = run(Stage::PublicValues);
    let other = self::run(Stage::PublicValues);
    let before = runtime.snapshot();
    assert!(context
        .hash_public_fields_reported(MODULUS, &[], &run, Stage::PublicValues)
        .is_err());
    assert!(context
        .hash_public_fields_reported(1, &[MODULUS], &run, Stage::PublicValues)
        .is_err());
    assert!(context
        .hash_public_fields_reported(1, &[1], &run, Stage::Preprocessing)
        .is_err());
    context
        .reported(&run, || {
            assert!(context
                .hash_public_fields_reported(1, &[1], &other, Stage::PublicValues)
                .is_err());
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        assert!(context
                            .hash_public_fields_reported(1, &[1], &run, Stage::PublicValues)
                            .is_err())
                    })
                    .join()
                    .unwrap();
            });
            Ok(())
        })
        .unwrap();
    assert_eq!(runtime.snapshot(), before);
    assert!(run.finish(false).unwrap().observations.is_empty());
    assert!(other.finish(false).unwrap().observations.is_empty());
    let run = self::run(Stage::PublicValues);
    let mut pass = 0;
    assert!(context
        .hash_public_stream_reported(
            1,
            |sink| {
                pass += 1;
                for _ in 0..if pass == 1 {
                    BATCH_WORDS + 1
                } else {
                    BATCH_WORDS
                } {
                    sink(7)?;
                }
                Ok(())
            },
            &run,
            Stage::PublicValues
        )
        .is_err());
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    assert_eq!(runtime.snapshot().pending_commands, 0);
    assert!(!run.finish(false).unwrap().succeeded);
}

#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_public_summary_checks_protocol_ranges_and_root_canonicality() {
    let runtime = runtime(Limits::default());
    let context = PublicArithmetic::new(&runtime, HOST_BYTES).unwrap();
    let summary = commitment::empty_subtree(
        commitment::Context {
            profile_id: [7; 32],
            chain_id: [9; 32],
        },
        commitment::DEPTH,
    )
    .unwrap();
    let original = programs::statement(summary, programs::EMPTY).map(|v| v.as_canonical_u64());
    let run = run(Stage::PublicValues);
    context
        .validate_public_summary_reported(&original, 12, &run, Stage::PublicValues)
        .unwrap();
    let mut calls = 1;
    for (index, value, message) in [
        (0, 1 << 32, "noncanonical context limb"),
        (15, u64::MAX, "noncanonical context limb"),
        (programs::MODE, 0, "node metadata range"),
        (programs::MODE, 13, "node metadata range"),
        (programs::LEVEL, 64, "node metadata range"),
        (programs::LEVEL, u64::MAX, "node metadata range"),
        (
            programs::COUNT,
            (1 << commitment::DEPTH) + 1,
            "node metadata range",
        ),
        (programs::ROOT, MODULUS, "noncanonical Goldilocks field"),
    ] {
        let mut words = original;
        words[index] = value;
        let error = context
            .validate_public_summary_reported(&words, 12, &run, Stage::PublicValues)
            .unwrap_err();
        if index == programs::ROOT {
            assert_eq!(
                error,
                commitment::CommitmentError::NonCanonicalField.to_string()
            );
        } else {
            assert_eq!(error, message);
        }
        calls += 1;
    }
    audited(run, Stage::PublicValues, calls);
}

#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_public_compiler_constants_match_cpu_at_domain_and_tile_boundaries() {
    let runtime = runtime(Limits::default());
    let context = PublicArithmetic::new(&runtime, HOST_BYTES).unwrap();
    let run = run(Stage::Preprocessing);
    let native = Constants::cuda(&context, &run);
    let reference = Constants::cpu();
    let mut calls = 0;
    context
        .reported(&run, || {
            for log in 0..=32 {
                assert_eq!(
                    native.inverse_generator(log).unwrap(),
                    reference.inverse_generator(log).unwrap()
                );
                calls += 1;
            }
            for (first, last) in [(0, 0), (1, 5), (0, 63), (MODULUS - 64, MODULUS - 1)] {
                let mut a = vec![Val::ZERO; (last - first + 1) as usize];
                let mut b = a.clone();
                native.selectors_into(first, last, &mut a).unwrap();
                reference.selectors_into(first, last, &mut b).unwrap();
                assert_eq!(a, b);
                calls += 1;
            }
            for chunks in [1usize, 2, 4, 8, 16, 32] {
                for log in [0, 8, 32 - chunks.ilog2() as usize] {
                    let mut a = vec![Val::ZERO; chunks * (chunks + 1)];
                    let mut b = a.clone();
                    native.quotient_into(chunks, log, &mut a).unwrap();
                    reference.quotient_into(chunks, log, &mut b).unwrap();
                    assert_eq!(a, b, "chunks={chunks} log={log}");
                    calls += 1;
                }
            }
            for n in [1usize, 2, 8, 128, 2048, 4096] {
                let column: Vec<_> = (0..n)
                    .map(|i| Val::new(if i % 5 == 0 { MODULUS - 1 } else { i as u64 }))
                    .collect();
                let mut a = vec![Val::ZERO; n];
                let mut b = a.clone();
                native
                    .periodic_into(&column, n.ilog2() as usize, &mut a)
                    .unwrap();
                reference
                    .periodic_into(&column, n.ilog2() as usize, &mut b)
                    .unwrap();
                assert_eq!(a, b, "period={n}");
                calls += n.div_ceil(constants::PERIOD_TILE).pow(2) as u64;
            }
            Ok(())
        })
        .unwrap();
    audited(run, Stage::Preprocessing, calls);
}

#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_public_folding_preserves_cubic_basis_zero_and_cache_provenance() {
    let runtime = runtime(Limits::default());
    let context = PublicArithmetic::new(&runtime, HOST_BYTES).unwrap();
    let run = run(Stage::Preprocessing);
    let mut native = Folding::new(Constants::cuda(&context, &run));
    let mut reference = Folding::new(Constants::cpu());
    let mut calls = 0;
    context
        .reported(&run, || {
            for a in [
                [0; 3],
                [1, 0, 0],
                [0, 1, 0],
                [MODULUS - 1, MODULUS - 2, MODULUS - 3],
                [101, 37, 65537],
            ] {
                let a = a.map(Val::new);
                let b = [3, MODULUS - 9, 19].map(Val::new);
                for operation in [
                    FoldOperation::Add,
                    FoldOperation::Mul,
                    FoldOperation::Inverse,
                    FoldOperation::CubicMul,
                    FoldOperation::CubicInverse,
                ] {
                    let expected = reference.fold(operation, a, b);
                    assert_eq!(native.fold(operation, a, b), expected);
                    let before = runtime.snapshot();
                    assert_eq!(native.fold(operation, a, b), expected);
                    assert_eq!(
                        runtime.snapshot(),
                        before,
                        "cached constant must not invent work"
                    );
                    calls += 1;
                }
            }
            assert!(native.failure().is_none());
            Ok(())
        })
        .unwrap();
    audited(run, Stage::Preprocessing, calls);
    let wrong = self::run(Stage::PublicValues);
    let mut folding = Folding::new(Constants::cuda(&context, &wrong));
    let before = runtime.snapshot();
    for operation in [FoldOperation::Add, FoldOperation::Inverse] {
        assert_eq!(
            folding.fold(operation, [Val::ONE; 3], [Val::ONE; 3]),
            Some([Val::ZERO; 3])
        );
        assert!(folding.failure().is_some());
    }
    assert_eq!(runtime.snapshot(), before);
    assert!(wrong.finish(false).unwrap().observations.is_empty());
}

#[test]
#[ignore = "requires CUDA/NVRTC; run serially"]
fn cuda_public_admission_precedes_allocations_and_rechecks_live_scratch() {
    let minimum = (CONSTANT_WORDS + SCRATCH_WORDS) * 8;
    for (bytes, allocation, count, host) in [
        (minimum - 1, BATCH_WORDS * 8, 3, HOST_BYTES),
        (minimum, BATCH_WORDS * 8 - 1, 3, HOST_BYTES),
        (minimum, BATCH_WORDS * 8, 2, HOST_BYTES),
        (minimum, BATCH_WORDS * 8, 3, HOST_BYTES - 1),
    ] {
        let runtime = runtime(Limits {
            managed_bytes: bytes,
            max_allocation_bytes: allocation,
            max_allocations: count,
            ..Limits::default()
        });
        let before = runtime.snapshot();
        assert!(PublicArithmetic::new(&runtime, host).is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let runtime = runtime(Limits {
        managed_bytes: minimum,
        max_allocation_bytes: BATCH_WORDS * 8,
        max_allocations: 3,
        ..Limits::default()
    });
    let context = PublicArithmetic::new(&runtime, HOST_BYTES).unwrap();
    let held = runtime.allocate(1).unwrap();
    let before = runtime.snapshot();
    let run = run(Stage::PublicValues);
    assert!(context
        .hash_public_fields_reported(7, &[1], &run, Stage::PublicValues)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(held);
    let digest = context
        .hash_public_fields_reported(7, &[1], &run, Stage::PublicValues)
        .unwrap();
    assert_eq!(digest, commitment::hash_fields(7, &[1]).unwrap());
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.peak_bytes, minimum);
    assert_eq!(snapshot.peak_allocations, 3);
    audited(run, Stage::PublicValues, 1);
}

#[test]
#[ignore = "requires pinned NVRTC; no device execution"]
fn cuda_public_kernels_compile_for_volta_and_blackwell() {
    for target in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, target)
            .unwrap()
            .is_empty());
    }
}
