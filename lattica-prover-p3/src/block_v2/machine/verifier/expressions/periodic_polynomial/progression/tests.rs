use super::*;

fn column(n: usize, starts: &[usize], step: usize, count: usize) -> Vec<Val> {
    let mut result = vec![Val::ZERO; n];
    for &start in starts {
        for i in 0..count {
            let index = start + step * i;
            assert_eq!(result[index], Val::ZERO, "test supports must be disjoint");
            result[index] = Val::ONE;
        }
    }
    result
}

#[test]
fn gaussian_coefficients_match_independent_products_and_reject_root_order() {
    for n in [16usize, 32, 64, 128] {
        let generator = Val::two_adic_generator(n.ilog2() as usize);
        for step in [1usize, 2, 3, 4, 7] {
            for first in [0usize, 1, 3] {
                for count in [1usize, 2, 3, 7] {
                    if first + (count - 1) * step >= n || count >= order(n, step) {
                        continue;
                    }
                    let part = Progression { first, step, count };
                    let mut actual = vec![Val::ZERO; count + 1];
                    let mut derivative = actual.clone();
                    coefficients(n, part, &mut actual, &mut derivative).unwrap();
                    // Independent ordinary polynomial multiplication, ascending.
                    let mut expected = vec![Val::ONE];
                    for i in 0..count {
                        let root = generator.exp_u64((first + step * i) as u64);
                        let mut next = vec![Val::ZERO; expected.len() + 1];
                        for (j, &coefficient) in expected.iter().enumerate() {
                            next[j] -= root * coefficient;
                            next[j + 1] += coefficient;
                        }
                        expected = next;
                    }
                    expected.reverse();
                    assert_eq!(actual, expected);
                    for j in 0..count {
                        assert_eq!(derivative[j], expected[j] * Val::from_usize(count - j));
                    }
                }
            }
        }
        let count = n / 4;
        let mut c = vec![Val::ZERO; count + 1];
        let mut d = c.clone();
        assert!(coefficients(
            n,
            Progression {
                first: 0,
                step: 4,
                count
            },
            &mut c,
            &mut d
        )
        .is_err());
    }
}

#[test]
fn large_geometric_coefficients_match_direct_root_products() {
    let n = 65536usize;
    let part = Progression {
        first: 18,
        step: 19,
        count: 2048,
    };
    let mut c = vec![Val::ZERO; part.count + 1];
    let mut d = c.clone();
    coefficients(n, part, &mut c, &mut d).unwrap();
    let generator = Val::two_adic_generator(16);
    for point in [
        Val::ZERO,
        Val::ONE,
        Val::from_u64(1234567),
        generator.exp_u64(part.first as u64),
        generator.exp_u64((part.first + part.step * (part.count - 1)) as u64),
    ] {
        let expected = (0..part.count).fold(Val::ONE, |value, i| {
            value * (point - generator.exp_u64((part.first + part.step * i) as u64))
        });
        let actual = c
            .iter()
            .fold(Val::ZERO, |value, &coefficient| value * point + coefficient);
        assert_eq!(actual, expected);
    }
}

#[test]
fn detector_checks_complete_support_values_and_uses_bounded_progressions() {
    let sample = column(65536, &[2, 9, 12, 15], 19, 2048);
    let found = plan(&sample, Val::ZERO, 8192).unwrap();
    assert_eq!(found.len, 4);
    assert_eq!(
        found.parts[..4].iter().map(|p| p.first).collect::<Vec<_>>(),
        [2, 9, 12, 15]
    );
    assert!(found.parts[..4]
        .iter()
        .all(|p| p.step == 19 && p.count == 2048));
    let negative = column(65536, &[28, 31, 32, 34, 35, 36], 38, 1024);
    let negative_plan = plan(&negative, Val::ZERO, 6144).unwrap();
    assert_eq!(negative_plan.len, 6);
    assert!(negative_plan.parts[..6]
        .iter()
        .all(|p| p.step == 38 && p.count == 1024));
    let mut changed_weight = sample.clone();
    changed_weight[2 + 19 * 100] = Val::from_u64(2);
    assert!(plan(&changed_weight, Val::ZERO, 8192).is_none());
    assert!(plan(&sample, Val::ZERO, 8191).is_none());
    let mut gap = sample.clone();
    gap[2 + 19 * 100] = Val::ZERO;
    assert!(plan(&gap, Val::ZERO, 8191).is_none());
    let coset = column(128, &[0], 8, 16);
    assert!(plan(&coset, Val::ZERO, 16).is_none());
    assert!(plan(&vec![Val::ONE; 128], Val::ONE, 0).is_none());
}

// Independent direct Fourier interpolation, with no q-binomial coefficients
// or rational selector identities in the oracle.
fn interpolant(column: &[Val]) -> Vec<Val> {
    let n = column.len();
    let inverse_generator = Val::two_adic_generator(n.ilog2() as usize).inverse();
    let inverse_n = Val::from_usize(n).inverse();
    (0..n)
        .map(|k| {
            let step = inverse_generator.exp_u64(k as u64);
            let mut power = Val::ONE;
            let mut coefficient = Val::ZERO;
            for &sample in column {
                coefficient += sample * power;
                power *= step;
            }
            coefficient * inverse_n
        })
        .collect()
}

#[test]
fn rational_progressions_unions_and_fallbacks_match_every_subgroup_root() {
    let single = column(256, &[3], 5, 16);
    let union = column(512, &[1, 2], 7, 16);
    let four = column(1024, &[0, 1, 4, 6], 9, 16);
    let complement: Vec<_> = single
        .iter()
        .map(|&x| Val::from_u64(7) - x * Val::from_u64(7))
        .collect();
    let coset = column(128, &[0], 8, 16);
    let mut singleton = vec![Val::ZERO; 128];
    singleton[37] = Val::ONE;
    for (samples, rational) in [
        (single, true),
        (union, true),
        (four, true),
        (complement, true),
        (coset, false),
        (singleton, false),
        (vec![Val::from_u64(7); 128], false),
    ] {
        let n = samples.len();
        let log_height = n.ilog2() as usize + 1;
        let mut builder = ProgramBuilder::new(6).unwrap();
        if rational {
            let baseline = if samples[0] == Val::from_u64(7) {
                samples[0]
            } else {
                Val::ZERO
            };
            let deviations = samples.iter().filter(|&&v| v != baseline).count();
            assert!(plan(&samples, baseline, deviations).is_some());
        }
        let actual = super::super::super::periodic_value(
            &mut builder,
            &samples,
            [Wire(0), Wire(1), Wire(2)],
            log_height,
            Constants::cpu(),
        )
        .unwrap();
        builder.ext_assert_equal(actual, [Wire(3), Wire(4), Wire(5)]);
        let program = builder.finish(None).unwrap();
        let generator = Val::two_adic_generator(log_height);
        let native_coefficients = interpolant(&samples);
        let outside = [
            Challenge::ZERO,
            Challenge::from_basis_coefficients_slice(&[
                Val::from_u64(17),
                Val::from_u64(3),
                Val::from_u64(11),
            ])
            .unwrap(),
            Challenge::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::NEG_ONE]).unwrap(),
        ];
        for (index, point) in (0..2 * n)
            .map(|i| Challenge::from(generator.exp_u64(i as u64)))
            .chain(outside)
            .enumerate()
        {
            let expected = if index < 2 * n {
                Challenge::from(samples[index % n])
            } else {
                let x = point.square();
                native_coefficients
                    .iter()
                    .rev()
                    .fold(Challenge::ZERO, |value, &coefficient| {
                        value * x + coefficient
                    })
            };
            let mut public = point.as_basis_coefficients_slice().to_vec();
            public.extend_from_slice(expected.as_basis_coefficients_slice());
            // Every support root executes the P=0 branch without a zero inverse.
            program.evaluate(&public, &[]).unwrap();
            public[3] += Val::ONE;
            assert!(program.evaluate(&public, &[]).is_err());
        }
    }
}

#[test]
fn extension_zero_uses_constrained_fermat_operations() {
    let mut builder = ProgramBuilder::new(4).unwrap();
    let zero = extension_zero(&mut builder, [Wire(0), Wire(1), Wire(2)]);
    builder.assert_equal(zero, Wire(3));
    let program = builder.finish(None).unwrap();
    for coefficients in [
        [Val::ZERO; 3],
        [Val::ONE, Val::ZERO, Val::ZERO],
        [Val::NEG_ONE, Val::ZERO, Val::ZERO],
        [Val::ZERO, Val::NEG_ONE, Val::ZERO],
        [Val::ZERO, Val::ZERO, Val::from_u64(71)],
        [Val::from_u64(9), Val::from_u64(13), Val::from_u64(123)],
    ] {
        let mut public = coefficients.to_vec();
        public.push(Val::from_bool(coefficients.iter().all(|&x| x == Val::ZERO)));
        program.evaluate(&public, &[]).unwrap();
        public[3] = Val::ONE - public[3];
        assert!(program.evaluate(&public, &[]).is_err());
    }
}
