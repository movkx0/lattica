use super::super::tests::{fixture, runtime, words};
use super::*;
use crate::config::{Dft, Val};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};

fn expected<F: ExtensionField<Val>>(
    polys: &[(Vec<Val>, usize, Vec<F>)],
    log: u32,
    shift: u64,
    alpha: F,
    first_power: u64,
) -> Vec<u64> {
    let height = 1usize << log;
    let mut output = vec![F::ZERO; height];
    let mut power = first_power;
    for (coefficients, width, points) in polys {
        let mut padded = coefficients.clone();
        padded.resize(height * width, Val::ZERO);
        let full = Dft::default()
            .coset_dft_batch(RowMajorMatrix::new(padded, *width), Val::from_u64(shift))
            .to_row_major_matrix();
        for &point in points {
            let inverses: Vec<F> = (0..height)
                .map(|natural| {
                    let x = Val::from_u64(shift)
                        * Val::from_u64(roots::root(log)).exp_u64(natural as u64);
                    (F::from(x) - point).inverse()
                })
                .collect();
            for col in 0..*width {
                let opened = coefficients
                    .chunks_exact(*width)
                    .rev()
                    .fold(F::ZERO, |v, row| v * point + row[col]);
                let weight = alpha.exp_u64(power);
                for natural in 0..height {
                    let physical = if log == 0 {
                        natural
                    } else {
                        natural.reverse_bits() >> (usize::BITS - log)
                    };
                    output[physical] += weight
                        * (F::from(full.values[natural * width + col]) - opened)
                        * inverses[natural];
                }
                power += 1;
            }
        }
    }
    words(&output)
}

fn compare<F: ExtensionField<Val>>(extension: Extension) {
    for (alpha_kind, first_power) in [(0, 0), (1, 0), (2, 19)] {
        let runtime = runtime(4 << 20, 2 << 20);
        let engine = Openings::new(&runtime).unwrap();
        let transforms = Transforms::new(&runtime).unwrap();
        let alpha = match alpha_kind {
            0 => F::ZERO,
            1 => F::ONE,
            _ => F::from_basis_coefficients_fn(|j| Val::from_u64(17 + 11 * j as u64)),
        };
        let alpha_storage = runtime.allocate(extension.degree() + 2).unwrap();
        alpha_storage.write(1, &words(&[alpha])).unwrap();
        let alpha_span = FieldSpan {
            buffer: &alpha_storage,
            first: 1,
        };
        let mut accumulator = engine
            .accumulator(8, 7, extension, alpha_span, first_power)
            .unwrap();
        // The owned alpha is independent of subsequent caller writes.
        alpha_storage
            .write(1, &vec![0; extension.degree()])
            .unwrap();
        let mut polys = Vec::new();
        for (log, width, count) in [(4, 3, 2), (3, 2, 3)] {
            let (prefix, coefficients) = fixture(&runtime, log, width, 7);
            let points: Vec<F> = (0..count)
                .map(|i| {
                    F::from_basis_coefficients_fn(|j| {
                        Val::from_u64((19 + 13 * (i % 2) + j * 11) as u64)
                    })
                })
                .collect();
            let storage = runtime.allocate(count * extension.degree()).unwrap();
            storage.write(0, &words(&points)).unwrap();
            let opening = engine
                .evaluate(
                    &prefix,
                    extension,
                    FieldSpan {
                        buffer: &storage,
                        first: 0,
                    },
                    count,
                )
                .unwrap();
            let before = runtime.snapshot();
            accumulator = accumulator.append(&transforms, &opening).unwrap();
            assert_eq!(
                runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                8
            );
            assert_eq!(
                runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
                (log.max(1) + 8) as u64 * 8
            );
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            polys.push((coefficients, width, points));
        }
        assert_eq!(accumulator.next_power, first_power + 12);
        let output = accumulator.finish().unwrap();
        assert_eq!(
            output.spec,
            MatrixSpec::new(8, 1, extension, RowOrder::BitReversed, 7).unwrap()
        );
        assert_eq!(
            output.read(1 << 20).unwrap(),
            expected(&polys, 8, 7, alpha, first_power)
        );
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_quadratic_opening_reductions_match_cpu_across_matrices_and_challenges() {
    compare::<crate::config::Challenge>(Extension::Quadratic);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_cubic_opening_reductions_match_cpu_across_matrices_and_challenges() {
    compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(Extension::Cubic);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_opening_reduction_fits_without_full_width_lde() {
    type F = p3_field::extension::CubicTrinomialExtensionField<Val>;
    let runtime = runtime(256 << 10, 128 << 10);
    let engine = Openings::new(&runtime).unwrap();
    let transforms = Transforms::new(&runtime).unwrap();
    let (prefix, coefficients) = fixture(&runtime, 7, 65, 7);
    let points: Vec<F> = (0..2)
        .map(|i| F::from_basis_coefficients_fn(|j| Val::from_u64(19 + 13 * i + j as u64 * 11)))
        .collect();
    let storage = runtime.allocate(6).unwrap();
    storage.write(0, &words(&points)).unwrap();
    let span = FieldSpan {
        buffer: &storage,
        first: 0,
    };
    let opening = engine.evaluate(&prefix, Extension::Cubic, span, 2).unwrap();
    let accumulator = engine
        .accumulator(11, 7, Extension::Cubic, span, 0)
        .unwrap();
    let plan = ReductionPlan::new(
        prefix.spec,
        accumulator.output.spec,
        2,
        runtime.snapshot(),
        runtime.state.budget.limits,
    )
    .unwrap();
    assert!(plan.peak <= 256 << 10);
    assert!(plan.rows < 1 << 11);
    assert!(runtime.allocate((1 << 11) * 65).is_err());
    let before = runtime.snapshot();
    let result = accumulator
        .append(&transforms, &opening)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        8
    );
    assert!(runtime.snapshot().peak_bytes <= 256 << 10);
    assert_eq!(
        result.read(64 << 10).unwrap(),
        expected(&[(coefficients, 65, points.clone())], 11, 7, points[0], 0)
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_opening_reduction_errors_cannot_publish_partial_accumulators() {
    let runtime = runtime(1 << 20, 1 << 19);
    let engine = Openings::new(&runtime).unwrap();
    let transforms = Transforms::new(&runtime).unwrap();
    let (prefix, _) = fixture(&runtime, 2, 3, 7);
    let points = runtime.allocate(3).unwrap();
    points.write(0, &[17, 19, 23]).unwrap();
    let span = FieldSpan {
        buffer: &points,
        first: 0,
    };
    let opening = engine.evaluate(&prefix, Extension::Cubic, span, 1).unwrap();
    let before = runtime.snapshot();
    assert!(engine
        .accumulator(26, 7, Extension::Cubic, span, 0)
        .is_err());
    assert!(engine.accumulator(6, 7, Extension::Base, span, 0).is_err());
    assert!(engine
        .accumulator(
            6,
            7,
            Extension::Cubic,
            FieldSpan {
                first: usize::MAX,
                ..span
            },
            0
        )
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(engine
        .accumulator(6, 7, Extension::Cubic, span, 0)
        .unwrap()
        .finish()
        .is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);

    let accumulator = engine.accumulator(6, 7, Extension::Cubic, span, 0).unwrap();
    let retained = runtime.snapshot().live_bytes - before.live_bytes;
    let mut pressure = Vec::new();
    while runtime.snapshot().live_bytes + 8 <= 1 << 20 {
        let bytes = ((1 << 20) - runtime.snapshot().live_bytes).min(1 << 19);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    let pressured = runtime.snapshot();
    assert!(accumulator.append(&transforms, &opening).is_err());
    assert_eq!(
        runtime.snapshot().completed_commands,
        pressured.completed_commands
    );
    assert_eq!(runtime.snapshot().uploaded_bytes, pressured.uploaded_bytes);
    assert_eq!(
        runtime.snapshot().downloaded_bytes,
        pressured.downloaded_bytes
    );
    assert_eq!(
        runtime.snapshot().live_bytes,
        pressured.live_bytes - retained
    );
    drop(pressure);
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    for (log, shift, power) in [(1, 7, 0), (6, 13, 0), (6, 7, u64::MAX - 1)] {
        assert!(engine
            .accumulator(log, shift, Extension::Cubic, span, power)
            .unwrap()
            .append(&transforms, &opening)
            .is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
    }
    let mut full = engine.accumulator(6, 7, Extension::Cubic, span, 0).unwrap();
    full.matrices = 256;
    assert!(full.append(&transforms, &opening).is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);

    // This base-field point is outside the prefix coset but inside the larger
    // reduction coset. Evaluation succeeds; reduction must reject and drop all.
    let x = (Val::from_u64(7) * Val::from_u64(roots::root(6))).as_canonical_u64();
    points.write(0, &[x, 0, 0]).unwrap();
    let on_expanded = engine.evaluate(&prefix, Extension::Cubic, span, 1).unwrap();
    let before = runtime.snapshot();
    assert!(engine
        .accumulator(6, 7, Extension::Cubic, span, 0)
        .unwrap()
        .append(&transforms, &on_expanded)
        .is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(runtime.snapshot().allocations, before.allocations);
    engine
        .accumulator(6, 7, Extension::Cubic, span, 0)
        .unwrap()
        .append(&transforms, &opening)
        .unwrap()
        .finish()
        .unwrap();
}

#[test]
fn reduction_plan_checks_every_phase_and_allocation_count() {
    let prefix = MatrixSpec::new(7, 65, Extension::Base, RowOrder::BitReversed, 7).unwrap();
    let output = MatrixSpec::new(11, 1, Extension::Cubic, RowOrder::BitReversed, 7).unwrap();
    let state = Snapshot {
        live_bytes: prefix.bytes() + output.bytes() + 4096,
        allocations: 8,
        ..Snapshot::default()
    };
    let limits = Limits {
        managed_bytes: 256 << 10,
        max_allocation_bytes: 128 << 10,
        ..Limits::default()
    };
    let plan = ReductionPlan::new(prefix, output, 2, state, limits).unwrap();
    assert!(plan.peak <= limits.managed_bytes);
    assert!(ReductionPlan::new(prefix, output, 0, state, limits).is_err());
    assert!(ReductionPlan::new(prefix, output, 33, state, limits).is_err());
    assert!(ReductionPlan::new(
        prefix,
        output,
        2,
        Snapshot {
            live_bytes: usize::MAX,
            ..state
        },
        limits
    )
    .is_err());
    assert!(ReductionPlan::new(
        prefix,
        output,
        2,
        state,
        Limits {
            max_allocations: state.allocations + 6,
            ..limits
        }
    )
    .is_err());
    assert!(ReductionPlan::new(
        prefix,
        output,
        2,
        state,
        Limits {
            managed_bytes: state.live_bytes + 1024,
            ..limits
        }
    )
    .is_err());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_single_row_opening_reduction_is_zero_for_constant_polynomials() {
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let runtime = runtime(64 << 10, 32 << 10);
        let engine = Openings::new(&runtime).unwrap();
        let transforms = Transforms::new(&runtime).unwrap();
        let (prefix, _) = fixture(&runtime, 0, 3, 13);
        let points = runtime.allocate(extension.degree()).unwrap();
        points
            .write(0, &[17, 19, 23][..extension.degree()])
            .unwrap();
        let span = FieldSpan {
            buffer: &points,
            first: 0,
        };
        let opening = engine.evaluate(&prefix, extension, span, 1).unwrap();
        let result = engine
            .accumulator(0, 13, extension, span, 0)
            .unwrap()
            .append(&transforms, &opening)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(result.read(24).unwrap(), vec![0; extension.degree()]);
    }
}
