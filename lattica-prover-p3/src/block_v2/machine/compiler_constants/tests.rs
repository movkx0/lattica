use super::*;

/// Original quadratic interpolation, retained only as an independent oracle
/// for coefficient order, inverse-root direction, and normalization.
fn periodic_dft(column: &[Val]) -> Vec<Val> {
    let n = column.len();
    let generator_inv = Val::two_adic_generator(n.ilog2() as usize).inverse();
    let inv_n = Val::from_usize(n).inverse();
    (0..n)
        .map(|k| {
            let step = generator_inv.exp_u64(k as u64);
            let mut power = Val::ONE;
            let mut sum = Val::ZERO;
            for &value in column {
                sum += power * value;
                power *= step;
            }
            sum * inv_n
        })
        .collect()
}

fn assert_matches_dft(column: &[Val]) {
    let expected = periodic_dft(column);
    let log_n = column.len().ilog2() as usize;
    // The containing trace height must not change the periodic coefficients.
    for log_height in [log_n, log_n + 1, 32] {
        let mut output = vec![-Val::ONE; column.len()];
        Constants::cpu()
            .periodic_into(column, log_height, &mut output)
            .unwrap();
        assert_eq!(
            output,
            expected,
            "n={}, log_height={log_height}",
            column.len()
        );
    }
}

#[test]
fn periodic_fft_matches_dft_for_constant_impulse_and_random_columns() {
    // Deterministic test data only; this generator is not protocol randomness.
    let mut seed = 0x6ae1_4c93_2b07_d8f5_u64;
    for log_n in 0..=10 {
        let n = 1 << log_n;
        assert_matches_dft(&vec![Val::ZERO; n]);
        assert_matches_dft(&vec![Val::from_u64(17); n]);
        for position in [0, n / 2, n - 1] {
            let mut impulse = vec![Val::ZERO; n];
            impulse[position] = -Val::ONE;
            assert_matches_dft(&impulse);
        }
        let random: Vec<_> = (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                Val::from_u64(seed)
            })
            .collect();
        assert_matches_dft(&random);
    }
}

#[test]
fn periodic_fft_single_value_is_unchanged_at_all_allowed_heights() {
    for log_height in 0..=32 {
        for value in [Val::ZERO, Val::ONE, -Val::ONE, Val::from_u64(0xabc0_1234)] {
            let mut output = [Val::ZERO];
            Constants::cpu()
                .periodic_into(&[value], log_height, &mut output)
                .unwrap();
            assert_eq!(output, [value]);
        }
    }
}

#[test]
fn periodic_fft_rejects_invalid_shapes_before_writing_output() {
    for (input_len, log_height, output_len) in [
        (0, 0, 0),
        (0, 0, 1),
        (3, 2, 3),
        (4, 1, 4),
        (4, 2, 3),
        (4, 2, 5),
        (1, 33, 1),
        (1, usize::MAX, 1),
    ] {
        let input = vec![Val::ONE; input_len];
        let original = vec![Val::from_u64(37); output_len];
        let mut output = original.clone();
        assert!(matches!(
            Constants::cpu().periodic_into(&input, log_height, &mut output),
            Err(CompileError::Shape("periodic column height"))
        ));
        assert_eq!(output, original);
    }
}
