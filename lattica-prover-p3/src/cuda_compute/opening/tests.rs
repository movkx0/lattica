use super::*;
use crate::{
    config::{Dft, Val},
    cuda_compute::{Transcript, Transcripts},
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};

pub(super) fn runtime(managed: usize, allocation: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: allocation,
            ..Limits::default()
        },
    )
    .unwrap()
}

pub(super) fn fixture(runtime: &Runtime, log: u32, width: usize, shift: u64) -> (Matrix, Vec<Val>) {
    let spec = MatrixSpec::new(log, width, Extension::Base, RowOrder::BitReversed, shift).unwrap();
    let coefficients: Vec<_> = (0..spec.words())
        .map(|i| Val::from_u64((i as u64).wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(19)))
        .collect();
    let natural = Dft::default()
        .coset_dft_batch(
            RowMajorMatrix::new(coefficients.clone(), width),
            Val::from_u64(shift),
        )
        .to_row_major_matrix();
    let raw: Vec<_> = (0..spec.rows())
        .flat_map(|row| {
            let physical = if log == 0 {
                row
            } else {
                row.reverse_bits() >> (usize::BITS - log)
            };
            (0..width).map(move |col| (physical, col))
        })
        .map(|(row, col)| natural.values[row * width + col].as_canonical_u64())
        .collect();
    (runtime.upload_matrix(spec, &raw).unwrap(), coefficients)
}

pub(super) fn words<F: ExtensionField<Val>>(values: &[F]) -> Vec<u64> {
    values
        .iter()
        .flat_map(|v| {
            v.as_basis_coefficients_slice()
                .iter()
                .map(PrimeField64::as_canonical_u64)
        })
        .collect()
}

fn oracle<F: ExtensionField<Val>>(coefficients: &[Val], width: usize, points: &[F]) -> Vec<u64> {
    let opened: Vec<F> = points
        .iter()
        .flat_map(|&point| {
            (0..width).map(move |col| {
                coefficients
                    .chunks_exact(width)
                    .rev()
                    .fold(F::ZERO, |value, row| value * point + row[col])
            })
        })
        .collect();
    words(&opened)
}

#[test]
fn opening_plans_admit_complete_storage_and_reject_invalid_shapes() {
    let spec = MatrixSpec::new(10, 2, Extension::Base, RowOrder::BitReversed, 7).unwrap();
    let limits = Limits {
        managed_bytes: 64 << 10,
        max_allocation_bytes: 16 << 10,
        ..Limits::default()
    };
    let state = Snapshot {
        live_bytes: spec.bytes(),
        allocations: 1,
        ..Snapshot::default()
    };
    let plan = EvaluationPlan::new(spec, Extension::Cubic, 7, state, limits).unwrap();
    assert!(plan.rows < spec.rows());
    assert!(plan.peak <= limits.managed_bytes);
    assert!(plan.inverse_words * 8 <= limits.max_allocation_bytes);
    assert!(plan.partial_words * 8 <= limits.max_allocation_bytes);
    for count in [0, 33, usize::MAX] {
        assert!(EvaluationPlan::new(spec, Extension::Cubic, count, state, limits).is_err());
    }
    for changed in [
        MatrixSpec {
            order: RowOrder::Natural,
            ..spec
        },
        MatrixSpec {
            extension: Extension::Cubic,
            ..spec
        },
        MatrixSpec {
            log_rows: 26,
            ..spec
        },
        MatrixSpec {
            columns: 4097,
            ..spec
        },
    ] {
        assert!(EvaluationPlan::new(changed, Extension::Cubic, 7, state, limits).is_err());
    }
    assert!(EvaluationPlan::new(spec, Extension::Base, 7, state, limits).is_err());
    assert!(EvaluationPlan::new(
        spec,
        Extension::Cubic,
        7,
        Snapshot {
            live_bytes: usize::MAX,
            ..state
        },
        limits
    )
    .is_err());
    assert!(EvaluationPlan::new(
        spec,
        Extension::Cubic,
        7,
        Snapshot {
            allocations: limits.max_allocations - 5,
            ..state
        },
        limits
    )
    .is_err());
}

fn compare<F: ExtensionField<Val>>(extension: Extension) {
    for (log, width, shift, count, managed, allocation) in [
        (0, 1, 1, 1, 1 << 20, 1 << 19),
        (3, 5, 7, 4, 1 << 20, 1 << 19),
        (8, 3, 13, 32, 4 << 20, 2 << 20),
        (10, 2, 7, 7, 64 << 10, 16 << 10),
        (17, 2, 7, 2, 16 << 20, 4 << 20),
    ] {
        let runtime = runtime(managed, allocation);
        let engine = Openings::new(&runtime).unwrap();
        let (prefix, coefficients) = fixture(&runtime, log, width, shift);
        let points: Vec<F> = (0..count)
            .map(|i| {
                F::from_basis_coefficients_fn(|j| {
                    Val::from_u64(if i % 3 == 0 {
                        if j == 0 {
                            3
                        } else {
                            0
                        }
                    } else {
                        (17 + (i % 3) * 11 + j * 7) as u64
                    })
                })
            })
            .collect();
        let raw = words(&points);
        let storage = runtime.allocate(raw.len() + 7).unwrap();
        storage.write(3, &raw).unwrap();
        let span = FieldSpan {
            buffer: &storage,
            first: 3,
        };
        let before = runtime.snapshot();
        let result = engine.evaluate(&prefix, extension, span, count).unwrap();
        let after = runtime.snapshot();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
        assert_eq!(
            after.copied_bytes - before.copied_bytes,
            (raw.len() * 8) as u64
        );
        assert_eq!(
            after.live_bytes - before.live_bytes,
            (count * extension.degree() * (width + 1)) * 8
        );
        assert_eq!(after.allocations - before.allocations, 2);
        assert_eq!(result.prefix.spec, prefix.spec);
        assert_eq!(result.count, count);
        assert_eq!(result.extension, extension);
        assert!(result
            .values(count * width * extension.degree() * 8 - 1)
            .is_err());
        assert_eq!(runtime.snapshot(), after);
        // Changing the caller's input cannot change the retained opening points.
        storage.write(3, &vec![0; raw.len()]).unwrap();
        let mut retained_points = vec![0; raw.len()];
        result.points.read(0, &mut retained_points).unwrap();
        assert_eq!(retained_points, raw);
        assert_eq!(
            result.values(4 << 20).unwrap(),
            oracle(&coefficients, width, &points)
        );
        drop(result);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert!(runtime.snapshot().peak_bytes <= managed);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_quadratic_openings_match_independent_polynomials_with_tiled_storage() {
    compare::<crate::config::Challenge>(Extension::Quadratic);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_cubic_openings_match_independent_polynomials_with_tiled_storage() {
    compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(Extension::Cubic);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_opening_bounds_and_invalid_points_release_scratch() {
    let runtime = runtime(128 << 10, 64 << 10);
    let engine = Openings::new(&runtime).unwrap();
    let (prefix, _) = fixture(&runtime, 4, 3, 7);
    let points = runtime.allocate(3).unwrap();
    points.write(0, &[17, 19, 23]).unwrap();
    let span = FieldSpan {
        buffer: &points,
        first: 0,
    };
    let before = runtime.snapshot();
    for count in [0, 2, 33, usize::MAX] {
        assert!(engine
            .evaluate(&prefix, Extension::Cubic, span, count)
            .is_err());
    }
    assert!(engine
        .evaluate(
            &prefix,
            Extension::Cubic,
            FieldSpan {
                first: usize::MAX,
                ..span
            },
            1
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let mut pressure = Vec::new();
    while runtime.snapshot().live_bytes + 8 <= 128 << 10 {
        let bytes = ((128 << 10) - runtime.snapshot().live_bytes).min(64 << 10);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    let pressured = runtime.snapshot();
    assert!(engine.evaluate(&prefix, Extension::Cubic, span, 1).is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    for point in [
        [0, 0, 0],
        [7, 0, 0],
        [crate::gpu_matrix::GOLDILOCKS_MODULUS, 0, 0],
        [0, u64::MAX, 1],
    ] {
        points.write(0, &point).unwrap();
        let before = runtime.snapshot();
        assert!(engine.evaluate(&prefix, Extension::Cubic, span, 1).is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            8
        );
    }
    points.write(0, &[17, 19, 23]).unwrap();
    engine.evaluate(&prefix, Extension::Cubic, span, 1).unwrap();
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_opening_consumes_resident_transcript_points_without_downloads() {
    type F = p3_field::extension::CubicTrinomialExtensionField<Val>;
    let runtime = runtime(4 << 20, 2 << 20);
    let engine = Openings::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    let mut transcript: Transcript = transcripts.start().unwrap();
    transcript.observe(&[17, 19, 23]).unwrap();
    let (prefix, coefficients) = fixture(&runtime, 6, 7, 7);
    let attempt = transcript.begin_attempt().unwrap();
    let before = runtime.snapshot();
    let points = transcript.sample_resident(6).unwrap();
    let opened = engine
        .evaluate(
            &prefix,
            Extension::Cubic,
            FieldSpan {
                buffer: &points,
                first: 0,
            },
            2,
        )
        .unwrap();
    assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        8
    );
    let actual = opened.values(1024).unwrap();
    let mut raw = [0; 6];
    points.read(0, &mut raw).unwrap();
    let points: Vec<F> = raw
        .chunks_exact(3)
        .map(|p| F::from_basis_coefficients_fn(|j| Val::from_u64(p[j])))
        .collect();
    assert_eq!(actual, oracle(&coefficients, 7, &points));
    attempt.complete();
}

#[test]
#[ignore = "requires NVRTC"]
fn cuda_opening_source_compiles_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
