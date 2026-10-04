use super::*;
use crate::block_v2::gpu_hash::engine;
use crate::config::Dft;
use p3_dft::TwoAdicSubgroupDft;
use p3_matrix::{bitrev::BitReversibleMatrix, dense::RowMajorMatrix, Matrix};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const BLOWUP: usize = crate::block_v2::profile::LOG_BLOWUP;

fn alpha() -> Challenge {
    Challenge::from_basis_coefficients_slice(&[
        Val::from_u64(2),
        Val::from_u64(3),
        Val::from_u64(4),
    ])
    .unwrap()
}

fn lde(height: usize, width: usize, shift: Val, hiding: bool) -> RowMajorMatrix<Val> {
    let mut rng = ChaCha20Rng::from_seed([71; 32]); // deterministic test fixture only
    let mut input = RowMajorMatrix::<Val>::rand(&mut rng, height, width);
    if hiding {
        let random = crate::block_v2::profile::NUM_RANDOM_CODEWORDS;
        input = input.with_random_cols(width + 2 * random, &mut rng);
        input.width = width + random;
    }
    if input.height() == 1 {
        return RowMajorMatrix::new(input.values.repeat(1 << BLOWUP), input.width);
    }
    Dft::default()
        .coset_lde_batch(input, BLOWUP, shift)
        .bit_reverse_rows()
        .to_row_major_matrix()
}

fn compressed_rows(matrix: &RowMajorMatrix<Val>) -> Vec<Challenge> {
    matrix
        .values
        .chunks_exact(matrix.width)
        .map(|row| {
            row.iter()
                .zip(alpha().powers())
                .fold(Challenge::ZERO, |sum, (value, weight)| {
                    sum + weight * *value
                })
        })
        .collect()
}

fn reconstruct(matrix: &RowMajorMatrix<Val>) -> Vec<Challenge> {
    let low_height = matrix.height() >> BLOWUP;
    let compressed = compressed_rows(&RowMajorMatrix::new(
        matrix.values[..low_height * matrix.width].to_vec(),
        matrix.width,
    ));
    if low_height == 1 {
        return vec![compressed[0]; matrix.height()];
    }
    let bits = low_height.trailing_zeros();
    let mut natural = Vec::with_capacity(low_height * 3);
    for row in 0..low_height {
        let physical = row.reverse_bits() >> (usize::BITS - bits);
        natural.extend_from_slice(
            <Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(
                &compressed[physical],
            ),
        );
    }
    Dft::default()
        .coset_lde_batch(RowMajorMatrix::new(natural, 3), BLOWUP, Val::ONE)
        .bit_reverse_rows()
        .to_row_major_matrix()
        .values
        .chunks_exact(3)
        .map(|row| Challenge::from_basis_coefficients_slice(row).unwrap())
        .collect()
}

#[test]
fn low_coset_compression_commutes_with_extension_including_hiding_columns() {
    for height in [1, 2, 8, 128] {
        for width in [1, 7, 23] {
            for shift in [Val::ONE, Val::GENERATOR, Val::from_u64(11)] {
                for hiding in [false, true] {
                    let matrix = lde(height, width, shift, hiding);
                    assert_eq!(
                        reconstruct(&matrix),
                        compressed_rows(&matrix),
                        "height={height} width={width} hiding={hiding} shift={shift:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn arbitrary_non_low_degree_rows_do_not_satisfy_reconstruction_contract() {
    let mut matrix = lde(8, 7, Val::GENERATOR, true);
    let expected = reconstruct(&matrix);
    let last = matrix.values.len() - matrix.width;
    matrix.values[last] += Val::ONE;
    assert_eq!(reconstruct(&matrix), expected, "low-coset prefix unchanged");
    assert_ne!(
        compressed_rows(&matrix),
        expected,
        "arbitrary rows are not admissible polynomials"
    );
}

#[test]
fn compact_plan_binds_blowup_transform_allocations_and_tile_bounds() {
    let values = vec![Val::ONE; 64 * 7];
    let denoms = vec![Challenge::ONE; 64];
    let inputs = [OpeningMatrix {
        values: &values,
        width: 7,
        height: values.len() / (7),
        terms: vec![OpeningTerm {
            inverse_denominators: &denoms,
            alpha_offset: Challenge::ONE,
            opened: Challenge::ZERO,
        }],
    }];
    let plan = CompactPlan::new(&inputs, BLOWUP, 64 << 10, 1 << 20).unwrap();
    assert_eq!(plan.transform_words, 64 * 3);
    assert_eq!(plan.root_words, 6);
    assert!(plan.total_bytes > plan.base.total_bytes);
    assert!(
        plan.base
            .input_words
            .max(plan.denominator_words)
            .max(plan.reduce_rows * 3)
            * 8
            <= 64 << 10
    );
    for blowup in [0, BLOWUP - 1, BLOWUP + 1, usize::MAX] {
        assert!(CompactPlan::new(&inputs, blowup, 64 << 10, 1 << 20).is_err());
    }
    assert!(CompactPlan::new(&inputs, BLOWUP, 1, 1 << 20).is_err());
    assert!(CompactPlan::new(&inputs, BLOWUP, 64 << 10, 32).is_err());
    assert!(CompactPlan::new(&[], BLOWUP, 64 << 10, 1 << 20).is_err());
}

#[test]
#[ignore = "requires an OpenCL GPU and a serial <=3 GiB service"]
fn gpu_compact_openings_match_original_and_cpu_for_real_ldes_and_all_points() {
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        engine::Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 64 << 10,
            staging_bytes: 32 << 10,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    let matrices = [
        lde(1, 1, Val::GENERATOR, false),
        lde(8, 7, Val::GENERATOR, false),
        lde(16, 23, Val::GENERATOR, true),
        lde(32, 13, Val::from_u64(11), false),
        lde(2048, 3, Val::GENERATOR, false),
    ];
    let max_height = matrices.iter().map(Matrix::height).max().unwrap();
    let denoms: Vec<_> = (0..max_height)
        .map(|row| alpha() + Val::from_usize(row))
        .collect();
    let inputs: Vec<_> = matrices
        .iter()
        .enumerate()
        .map(|(i, matrix)| OpeningMatrix {
            values: &matrix.values,
            width: matrix.width,
            height: matrix.values.len() / (matrix.width),
            terms: (0..=i % 3)
                .map(|point| OpeningTerm {
                    inverse_denominators: &denoms,
                    alpha_offset: alpha().exp_u64((13 * i + point) as u64),
                    opened: alpha() + Val::from_usize(17 + point),
                })
                .collect(),
        })
        .collect();
    let mut expected = BTreeMap::<usize, Vec<Challenge>>::new();
    for (matrix, input) in matrices.iter().zip(&inputs) {
        let target = expected
            .entry(matrix.height())
            .or_insert_with(|| vec![Challenge::ZERO; matrix.height()]);
        for (row, compressed) in compressed_rows(matrix).into_iter().enumerate() {
            for term in &input.terms {
                target[row] +=
                    term.alpha_offset * (term.opened - compressed) * term.inverse_denominators[row];
            }
        }
    }
    let expected: Vec<_> = expected.into_values().rev().collect();
    let mut guard = ENGINE.get().unwrap().lock().unwrap();
    let engine = guard.as_mut().unwrap();
    assert_eq!(engine.reduce_openings(&inputs, alpha()).unwrap(), expected);
    let before = engine.snapshot();
    assert_eq!(
        engine.compact_openings(&inputs, alpha(), BLOWUP).unwrap(),
        expected
    );
    let after = engine.snapshot();
    let uploads: usize = inputs
        .iter()
        .map(|input| {
            let height = input.values.len() / input.width;
            (height >> BLOWUP) * input.width * 8
                + input.width * 24
                + input.terms.len() * 48
                + height * input.terms.len() * 24
        })
        .sum::<usize>()
        + 16 * max_height.trailing_zeros() as usize;
    assert_eq!(
        after.opening_uploaded_bytes - before.opening_uploaded_bytes,
        uploads as u64
    );
    assert_eq!(
        after.opening_compact_calls - before.opening_compact_calls,
        1
    );
    assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
    assert!(after.opening_compact_ntt_ns > before.opening_compact_ntt_ns);
    let live = engine.accounting.lock().unwrap().live;
    let lease = engine::reserve(
        &engine.accounting,
        engine.limits.managed_bytes - live,
        engine.limits.managed_bytes,
    )
    .unwrap();
    let allocations = engine.snapshot().allocations;
    assert!(engine.compact_openings(&inputs, alpha(), BLOWUP).is_err());
    assert_eq!(engine.snapshot().allocations, allocations);
    drop(lease);
    assert_eq!(
        engine.compact_openings(&inputs, alpha(), BLOWUP).unwrap(),
        expected
    );
}

#[test]
#[ignore = "requires LATTICA_V2_OPENING_PROFILE=1, an OpenCL GPU and a serial <=3 GiB service"]
fn gpu_compact_large_low_degree_input_matches_closed_form_reference() {
    assert_eq!(
        std::env::var("LATTICA_V2_OPENING_PROFILE").as_deref(),
        Ok("1")
    );
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        engine::Limits {
            managed_bytes: 128 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 16 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    let height = 1usize << 20;
    let width = 200;
    let prepare = Instant::now();
    let mut coset: Vec<_> = Val::two_adic_generator(height.trailing_zeros() as usize)
        .powers()
        .take(height)
        .map(|x| Val::GENERATOR * x)
        .collect();
    p3_util::reverse_slice_index_bits(&mut coset);
    let scale = Val::from_u64(u64::MAX - 917);
    let constant = Val::from_u64(u64::MAX - 13);
    let columns: Vec<_> = (0..width)
        .map(|col| Val::from_usize(col) * Val::from_u64(Val::ORDER_U64 / 2 + 17))
        .collect();
    let mut values = Vec::with_capacity(height * width);
    for x in &coset {
        let base = constant + scale * *x;
        values.extend(columns.iter().map(|col| base + *col));
    }
    let denominators: Vec<_> = (0..height)
        .map(|row| alpha() + Val::from_usize(row + 1))
        .collect();
    let input = OpeningMatrix {
        values: &values,
        width,
        height: values.len() / (width),
        terms: vec![
            OpeningTerm {
                inverse_denominators: &denominators,
                alpha_offset: alpha(),
                opened: Challenge::from_u64(13),
            },
            OpeningTerm {
                inverse_denominators: &denominators,
                alpha_offset: alpha() * alpha(),
                opened: Challenge::from_u64(17),
            },
        ],
    };
    let (weights, column_sum) = alpha().powers().zip(&columns).fold(
        (Challenge::ZERO, Challenge::ZERO),
        |(sum, weighted), (weight, col)| (sum + weight, weighted + weight * *col),
    );
    let prepare_ns = prepare.elapsed().as_nanos();
    let before = engine::report("compact large diagnostic before").unwrap();
    let measured = Instant::now();
    let actual = super::super::reduce_lde(std::slice::from_ref(&input), alpha(), BLOWUP).unwrap();
    let reduce_ns = measured.elapsed().as_nanos();
    let after = engine::report("compact large diagnostic after").unwrap();
    assert_eq!(actual.len(), 1);
    assert_eq!(actual[0].len(), height);
    for (row, actual) in actual[0].iter().enumerate() {
        let compressed = weights * (constant + scale * coset[row]) + column_sum;
        let expected = input.terms.iter().fold(Challenge::ZERO, |sum, term| {
            sum + term.alpha_offset * (term.opened - compressed) * term.inverse_denominators[row]
        });
        assert_eq!(*actual, expected, "row {row}");
    }
    let compact = engine::switch("LATTICA_V2_GPU_OPENING_COMPACT").unwrap();
    let input_rows = if compact { height >> BLOWUP } else { height };
    let expected_bytes = input_rows * width * 8
        + width * 24
        + input.terms.len() * 48
        + height * input.terms.len() * 24
        + if compact {
            height.trailing_zeros() as usize * 16
        } else {
            0
        };
    assert_eq!(
        after.opening_uploaded_bytes - before.opening_uploaded_bytes,
        expected_bytes as u64
    );
    assert_eq!(
        after.opening_downloaded_bytes - before.opening_downloaded_bytes,
        (height * 24) as u64
    );
    assert_eq!(
        after.opening_compact_calls - before.opening_compact_calls,
        u64::from(compact)
    );
    assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
    assert!(after.managed_peak_bytes <= 128 << 20);
    println!("opening_compact_large_input=PASS compact={compact} height={height} width={width} input_bytes={} checked_rows={height} prepare_ns={prepare_ns} reduce_ns={reduce_ns} isolated_component=true degree_bounded=true full_proof=false production_ready=false", values.len() * 8);
}
