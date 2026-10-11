use super::*;

#[test]
fn device_opening_plans_bound_tiles_all_allocations_and_aggregate_memory() {
    let spec = MatrixSpec::new(10, 17, Extension::Base, RowOrder::BitReversed, 7).unwrap();
    let limits = super::super::super::super::Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 4096,
    };
    let plan = EvaluationPlan::new(spec, 3, 3, 1234, limits, 16 << 20).unwrap();
    assert!(plan.rows.is_power_of_two() && plan.rows <= 4096);
    assert_eq!(
        plan.peak,
        1234 + (9 + 18 + 3 * 17 * 3 + 1 + plan.inverse_words + plan.partial_words) * 8
    );
    assert!((plan.inverse_words + plan.partial_words) * 8 <= limits.tile_bytes);
    assert!(EvaluationPlan::new(spec, 3, 3, limits.managed_bytes, limits, 16 << 20).is_err());
    assert!(EvaluationPlan::new(spec, 3, 3, 0, limits, 3 * 17 * 3 * 8 - 1).is_err());
    let tiny = super::super::super::super::Limits {
        tile_bytes: (3 * 3 + 3 * 17 * 3) * 8 - 1,
        ..limits
    };
    assert!(EvaluationPlan::new(spec, 3, 3, 0, tiny, 16 << 20).is_err());
    let reduction = ReductionPlan::new(spec, 14, 3, 3, 1234, limits, 16 << 20).unwrap();
    assert!(reduction.rows.is_power_of_two() && reduction.rows <= 65536);
    assert!(reduction.peak <= limits.managed_bytes);
    assert!(ReductionPlan::new(spec, 14, 3, 3, limits.managed_bytes, limits, 16 << 20).is_err());
    assert!(ReductionPlan::new(spec, 14, 3, 3, 0, limits, (1 << 14) * 24 - 1).is_err());
    assert!(checked_peak(usize::MAX, &[1], limits, 16 << 20).is_err());
}

#[test]
fn quadratic_opening_admission_and_plans_use_two_coefficients() {
    let spec = MatrixSpec::new(10, 17, Extension::Base, RowOrder::BitReversed, 7).unwrap();
    let limits = super::super::super::super::Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 128 << 10,
        staging_bytes: 4096,
    };
    assert_eq!(
        validate_prefix_extension(spec, Extension::Quadratic, &[11, 13, 17, 19]).unwrap(),
        2
    );
    for points in [
        vec![],
        vec![0, 0],
        vec![11],
        vec![11, 13, 17],
        vec![GOLDILOCKS_MODULUS, 1],
        vec![11; 66],
    ] {
        assert!(validate_prefix_extension(spec, Extension::Quadratic, &points).is_err());
    }
    assert!(validate_prefix_extension(spec, Extension::Base, &[11, 13]).is_err());
    let plan = EvaluationPlan::new(spec, 3, 2, 1234, limits, 16 << 20).unwrap();
    assert_eq!(
        plan.peak,
        1234 + (6 + 12 + 3 * 17 * 2 + 1 + plan.inverse_words + plan.partial_words) * 8
    );
    assert_eq!(plan.inverse_words, plan.rows * 3 * 2);
    assert!((plan.inverse_words + plan.partial_words) * 8 <= limits.tile_bytes);
    assert!(EvaluationPlan::new(spec, 3, 2, limits.managed_bytes, limits, 16 << 20).is_err());
    assert!(EvaluationPlan::new(spec, 3, 2, 0, limits, 3 * 17 * 2 * 8 - 1).is_err());
    let plan = ReductionPlan::new(spec, 14, 3, 2, 1234, limits, 16 << 20).unwrap();
    assert!(plan.peak <= limits.managed_bytes);
    assert!(plan.rows * 3 * 2 * 8 <= limits.tile_bytes);
    assert!(ReductionPlan::new(spec, 14, 3, 2, 0, limits, (1 << 14) * 16 - 1).is_err());
}

#[test]
fn device_opening_rejects_unsupported_prefixes_and_points_before_dispatch() {
    let spec = MatrixSpec::new(4, 3, Extension::Base, RowOrder::BitReversed, 7).unwrap();
    assert!(validate_prefix(spec, &[[11, 13, 17]]).is_ok());
    for invalid in [
        MatrixSpec {
            extension: Extension::Cubic,
            ..spec
        },
        MatrixSpec {
            order: RowOrder::Natural,
            ..spec
        },
        MatrixSpec {
            columns: MAX_WIDTH + 1,
            ..spec
        },
        MatrixSpec {
            log_rows: 22,
            ..spec
        },
    ] {
        assert!(validate_prefix(invalid, &[[11, 13, 17]]).is_err());
    }
    for points in [
        vec![],
        vec![[0; 3]],
        vec![[GOLDILOCKS_MODULUS, 1, 0]],
        vec![[11, 13, 17]; 33],
    ] {
        assert!(validate_prefix(spec, &points).is_err());
    }
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
fn device_openings_match_polynomials_and_fri_inputs_without_intermediate_readback() {
    opening_pipeline::<crate::block_v2::profile::Challenge>();
}

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB service with zero swap"]
fn quadratic_device_openings_match_polynomials_and_fri_inputs_without_intermediate_readback() {
    opening_pipeline::<crate::config::Challenge>();
}

fn opening_pipeline<Challenge: crate::block_v2::gpu_hash::FriExtension>() {
    use crate::block_v2::gpu_hash::{
        initialize_quotient_test_engine, shutdown, Limits, TestShutdownGuard,
    };
    use crate::config::Dft;
    use p3_dft::TwoAdicSubgroupDft;
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    let _shutdown = TestShutdownGuard;
    initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 128 << 10,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let degree = Challenge::DIMENSION;
    let extension = Challenge::DEVICE_EXTENSION;
    let encode = |v: [u64; 3]| v[..degree].to_vec();
    let challenge = |v: [u64; 3]| Challenge::from_basis_coefficients_fn(|i| Val::from_u64(v[i]));
    let flatten = |values: &[Challenge]| {
        values
            .iter()
            .flat_map(|v| {
                let coefficients: &[Val] = v.as_basis_coefficients_slice();
                coefficients.iter().map(|n| n.as_canonical_u64())
            })
            .collect::<Vec<_>>()
    };
    let live = |s: &DeviceSession| {
        s.plan_outputs(&[MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1).unwrap()])
            .unwrap()
            .live_bytes
    };
    let reverse = |row: usize, log: u32| {
        if log == 0 {
            row
        } else {
            row.reverse_bits() >> (usize::BITS - log)
        }
    };
    for (log_rows, widths, shift, point_count) in [
        (0u32, vec![1usize, 3], 7u64, 3usize),
        (3, vec![3, 17], 11, 32),
        (7, vec![9, 3], 7, 3),
        (10, vec![17, 1], 11, 3),
        (13, vec![3, 9], 7, 2),
    ] {
        let session = DeviceSession::new().unwrap();
        let baseline = live(&session);
        let rows = 1usize << log_rows;
        let full_log = log_rows + crate::block_v2::profile::LOG_BLOWUP as u32;
        let full_rows = 1usize << full_log;
        let points: Vec<_> = (0..point_count)
            .map(|i| {
                if i == 2 {
                    [11, 13, 17]
                } else {
                    [11 + i as u64 * 37, 13, 17 + i as u64 * 7]
                }
            })
            .collect();
        let point_words: Vec<_> = points
            .iter()
            .flat_map(|p| p[..degree].iter().copied())
            .collect();
        let point_values: Vec<_> = points.iter().copied().map(challenge).collect();
        let mut prepared = Vec::new();
        let mut references = Vec::new();
        for (index, width) in widths.iter().copied().enumerate() {
            let subgroup = RowMajorMatrix::new(
                (0..rows * width)
                    .map(|i| match (i + index) % 5 {
                        0 => Val::ZERO,
                        1 => Val::NEG_ONE,
                        2 => Val::from_u64(0xffff_fffe_0000_0001),
                        _ => Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xfedc_ba98_7654_3210)
                                .wrapping_add(index as u64 + 7),
                        ),
                    })
                    .collect(),
                width,
            );
            let coefficients = Dft::default().idft_batch(subgroup.clone());
            let low = Dft::default()
                .coset_lde_batch(subgroup.clone(), 0, Val::from_u64(shift))
                .to_row_major_matrix();
            let full = Dft::default()
                .coset_lde_batch(
                    subgroup,
                    crate::block_v2::profile::LOG_BLOWUP,
                    Val::from_u64(shift),
                )
                .to_row_major_matrix();
            let ys: Vec<Vec<_>> = point_values
                .iter()
                .map(|point| {
                    (0..width)
                        .map(|col| {
                            (0..rows).rev().fold(Challenge::ZERO, |sum, row| {
                                sum * *point + coefficients.values[row * width + col]
                            })
                        })
                        .collect()
                })
                .collect();
            let mut words = vec![0; rows * width];
            for row in 0..rows {
                for col in 0..width {
                    words[row * width + col] =
                        low.values[reverse(row, log_rows) * width + col].as_canonical_u64();
                }
            }
            let input = session
                .upload(
                    MatrixSpec::new(
                        log_rows,
                        width,
                        Extension::Base,
                        RowOrder::BitReversed,
                        shift,
                    )
                    .unwrap(),
                    &words,
                )
                .unwrap();
            let before = session.stats();
            let opening = session
                .evaluate_opening_extension(&input, extension, &point_words)
                .unwrap();
            assert_eq!(
                session.stats().downloaded_bytes - before.downloaded_bytes,
                8
            );
            assert_eq!(
                session.stats().uploaded_bytes - before.uploaded_bytes,
                (points.len() * degree * 8) as u64
            );
            assert!(session
                .opening_values_words(&opening, points.len() * width * degree * 8 - 1)
                .is_err());
            let values = session
                .opening_values_words(&opening, points.len() * width * degree * 8)
                .unwrap();
            for (actual, expected) in values.chunks_exact(width * degree).zip(&ys) {
                assert_eq!(
                    actual.to_vec(),
                    flatten(expected),
                    "claimed values: log={log_rows}, width={width}, shift={shift}"
                );
            }
            let foreign = DeviceSession::new().unwrap();
            assert!(foreign
                .evaluate_opening_extension(&input, extension, &point_words)
                .is_err());
            assert!(foreign.opening_values_words(&opening, usize::MAX).is_err());
            assert!(foreign
                .opening_accumulator_extension(full_log, extension, &encode([1, 0, 0]))
                .unwrap()
                .append(&opening)
                .is_err());
            drop(foreign);
            let before = session.stats();
            if extension == Extension::Quadratic {
                assert!(session.opening_values(&opening, usize::MAX).is_err());
            }
            assert!(session
                .evaluate_opening_extension(&input, Extension::Base, &point_words)
                .is_err());
            assert!(session
                .evaluate_opening_extension(&input, extension, &[1])
                .is_err());
            assert!(session
                .opening_accumulator_extension(full_log, extension, &[1])
                .is_err());
            assert_eq!(session.stats(), before);
            let other = if extension == Extension::Quadratic {
                Extension::Cubic
            } else {
                Extension::Quadratic
            };
            let baseline = live(&session);
            let incompatible = session
                .opening_accumulator_extension(full_log, other, &vec![1; other.degree()])
                .unwrap();
            let before = session.stats();
            assert!(incompatible.append(&opening).is_err());
            assert_eq!(session.stats(), before);
            assert_eq!(live(&session), baseline);
            drop(input); // Opening owns the device prefix, not a caller borrow.
            prepared.push(opening);
            references.push((width, full, ys));
        }
        for alpha_words in [
            [0, 0, 0],
            [GOLDILOCKS_MODULUS - 1, 5, GOLDILOCKS_MODULUS - 2],
        ] {
            let alpha = challenge(alpha_words);
            let mut accumulator = session
                .opening_accumulator_extension(full_log, extension, &encode(alpha_words))
                .unwrap();
            let before = session.stats();
            let mut expected = vec![Challenge::ZERO; full_rows];
            let mut first_power = 0;
            for (opening, (width, full, ys)) in prepared.iter().zip(&references) {
                accumulator = accumulator.append(opening).unwrap();
                for row in 0..full_rows {
                    let natural = reverse(row, full_log);
                    let x = Val::from_u64(shift)
                        * Val::two_adic_generator(full_log as usize).exp_u64(natural as u64);
                    for (p, point) in point_values.iter().enumerate() {
                        let mut power = alpha.exp_u64((first_power + p * width) as u64);
                        let inverse = (*point - x).inverse();
                        for col in 0..*width {
                            expected[row] +=
                                power * (ys[p][col] - full.values[natural * width + col]) * inverse;
                            power *= alpha;
                        }
                    }
                }
                first_power += width * points.len();
            }
            assert_eq!(
                session.stats().downloaded_bytes - before.downloaded_bytes,
                (prepared.len() * 8) as u64
            );
            assert_eq!(
                session.stats().opening_reductions - before.opening_reductions,
                prepared.len() as u64
            );
            let result = accumulator.finish().unwrap();
            assert_eq!(
                session.read(&result, result.spec().bytes()).unwrap(),
                flatten(&expected),
                "FRI input: log={log_rows}, shift={shift}, alpha={alpha_words:?}"
            );
            // The next arithmetic consumer accepts the result without upload.
            let before = session.stats();
            let folded = session.fold_fri(&result, 1, &encode([19, 23, 29])).unwrap();
            assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
            assert_eq!(session.stats().downloaded_bytes, before.downloaded_bytes);
            assert_eq!(folded.spec().rows(), full_rows / 2);
        }
        drop(prepared);
        assert_eq!(live(&session), baseline);
    }
    // Initial-coset failure and later expansion failure both drain and recover allocations.
    let session = DeviceSession::new().unwrap();
    let input = session
        .upload(
            MatrixSpec::new(3, 1, Extension::Base, RowOrder::BitReversed, 7).unwrap(),
            &[1; 8],
        )
        .unwrap();
    let baseline = live(&session);
    assert!(session
        .evaluate_opening_extension(&input, extension, &encode([7, 0, 0]))
        .err()
        .unwrap()
        .contains("prefix coset"));
    assert_eq!(live(&session), baseline);
    let x = Val::from_u64(7) * Val::two_adic_generator(7);
    let opening = session
        .evaluate_opening_extension(&input, extension, &encode([x.as_canonical_u64(), 0, 0]))
        .unwrap();
    let baseline = live(&session);
    let accumulator = session
        .opening_accumulator_extension(7, extension, &encode([5, 11, 13]))
        .unwrap();
    assert!(accumulator
        .append(&opening)
        .err()
        .unwrap()
        .contains("expanded coset"));
    assert_eq!(live(&session), baseline);
    assert!(session
        .opening_accumulator_extension(7, extension, &encode([0, 0, 0]))
        .unwrap()
        .finish()
        .is_err());
    assert_eq!(live(&session), baseline);
    drop(opening);
    drop(input);
    drop(session);
    shutdown().unwrap();
}
