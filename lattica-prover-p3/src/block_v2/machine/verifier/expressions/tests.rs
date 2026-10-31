use super::*;
use p3_field::{Field, TwoAdicField};

// Independent direct DFT oracle, deliberately retaining the simple quadratic
// formulation so the optimized compiler and CPU FFT cannot share a bug here.
fn reference_periodic(column: &[Val], zeta: Challenge, log_height: usize) -> Challenge {
    let n = column.len();
    let generator = Val::two_adic_generator(n.ilog2() as usize).inverse();
    let inverse_n = Val::from_usize(n).inverse();
    let point = zeta.exp_u64((1u64 << log_height) / n as u64);
    let mut result = Challenge::ZERO;
    for k in (0..n).rev() {
        let step = generator.exp_u64(k as u64);
        let mut power = Val::ONE;
        let mut coefficient = Val::ZERO;
        for &sample in column {
            coefficient += sample * power;
            power *= step;
        }
        result = result * point + coefficient * inverse_n;
    }
    result
}

#[test]
fn periodic_sparse_constant_repeated_and_dense_match_independent_dft() {
    let mut endpoint = vec![Val::ZERO; 128];
    endpoint[37] = Val::from_u64(9);
    let mut endpoints = endpoint.clone();
    endpoints[91] = Val::from_u64(5);
    let mut first_endpoint = vec![Val::ZERO; 128];
    first_endpoint[0] = Val::from_u64(4);
    let complement: Vec<_> = endpoint.iter().map(|&v| Val::from_u64(7) - v).collect();
    let complement_two: Vec<_> = endpoints.iter().map(|&v| Val::from_u64(11) - v).collect();
    let dense: Vec<_> = (0..32)
        .map(|i| Val::from_usize((i * i * 17 + i * 29 + 5) % 101))
        .collect();
    let cases = [
        vec![Val::ZERO],
        vec![Val::from_u64(13); 128],
        endpoint,
        endpoints,
        first_endpoint,
        complement,
        complement_two,
        dense,
        vec![
            Val::from_u64(2),
            Val::from_u64(5),
            Val::from_u64(7),
            Val::ZERO,
        ]
        .repeat(32),
    ];
    for column in cases {
        let log_height = column.len().ilog2() as usize + 2;
        let mut builder = ProgramBuilder::new(6).unwrap();
        let output = periodic_value(
            &mut builder,
            &column,
            [Wire(0), Wire(1), Wire(2)],
            log_height,
            Constants::cpu(),
        )
        .unwrap();
        builder.ext_assert_equal(output, [Wire(3), Wire(4), Wire(5)]);
        let program = builder.finish(None).unwrap();
        let generator = Val::two_adic_generator(log_height);
        // Includes every subgroup point, zero, and genuinely extension-valued
        // challenges. In particular, the endpoint's removable singularity is
        // tested instead of relying on the full verifier to exclude it.
        let points = (0..(1usize << log_height))
            .map(|i| Challenge::from(generator.exp_u64(i as u64)))
            .chain([
                Challenge::ZERO,
                Challenge::from_basis_coefficients_slice(&[
                    Val::from_u64(17),
                    Val::from_u64(3),
                    Val::from_u64(11),
                ])
                .unwrap(),
            ]);
        // Compute coefficients only once for the subgroup cases: their exact
        // expected value is directly the original AIR column sample.
        for (index, point) in points.enumerate() {
            let expected = if index < (1usize << log_height) {
                Challenge::from(column[index % column.len()])
            } else {
                reference_periodic(&column, point, log_height)
            };
            let mut public = point.as_basis_coefficients_slice().to_vec();
            public.extend_from_slice(expected.as_basis_coefficients_slice());
            program.evaluate(&public, &[]).unwrap();
            public[3] += Val::ONE;
            assert!(program.evaluate(&public, &[]).is_err());
        }
    }
}

#[test]
fn large_endpoint_evaluation_uses_logarithmic_program_and_preserves_subgroup_values() {
    let mut column = vec![Val::ZERO; 32768];
    column[24575] = Val::ONE;
    let mut builder = ProgramBuilder::new(3).unwrap();
    let output = periodic_value(
        &mut builder,
        &column,
        [Wire(0), Wire(1), Wire(2)],
        15,
        Constants::cpu(),
    )
    .unwrap();
    let program = builder.finish(None).unwrap();
    assert!(
        program.active_rows() < 256,
        "{} rows",
        program.active_rows()
    );
    let generator = Val::two_adic_generator(15);
    for index in [0, 1, 24574, 24575, 24576, 32767] {
        let values = program
            .evaluate(&[generator.exp_u64(index), Val::ZERO, Val::ZERO], &[])
            .unwrap();
        assert_eq!(
            output.map(|w| values[w.0]),
            [Val::from_bool(index == 24575), Val::ZERO, Val::ZERO]
        );
    }
}

#[test]
fn borrowed_and_repeated_values_match_materialized_indexing() {
    let pattern = [[Wire(1), Wire(2), Wire(3)], [Wire(3), Wire(1), Wire(2)]];
    for width in 0..=pattern.len() {
        for copies in [0, 1, 2, 9] {
            let materialized = pattern[..width].repeat(copies);
            let repeated = Values::repeat(&pattern[..width], copies).unwrap();
            let borrowed = Values::Slice(&materialized);
            for index in (0..=materialized.len()).chain([usize::MAX]) {
                assert_eq!(repeated.get(index), materialized.get(index));
                assert_eq!(borrowed.get(index), materialized.get(index));
            }
        }
    }
    assert!(Values::repeat(&pattern, usize::MAX).is_err());
    // Empty patterns remain empty without indexing or modulo panics.
    assert!(Values::repeat(&[], usize::MAX).unwrap().get(0).is_none());
}

#[test]
fn periodic_output_geometry_and_quotient_bounds_reject_before_emission() {
    let mut b = ProgramBuilder::new(0).unwrap();
    let zeta = [Wire(0); 3];
    assert!(periodic_values_into(
        &mut b,
        &[vec![Val::ONE]],
        zeta,
        3,
        Constants::cpu(),
        &mut []
    )
    .is_err());
    assert!(
        periodic_values_into(&mut b, &[], zeta, usize::MAX, Constants::cpu(), &mut []).is_err()
    );
    let chunks = vec![vec![zeta; 3]; super::super::pcs::MAX_MATRICES * 2];
    assert!(quotient_with_constants(&mut b, &chunks, zeta, 3, Constants::cpu()).is_err());
    assert_eq!(
        b.finish(None).unwrap(),
        ProgramBuilder::new(0).unwrap().finish(None).unwrap()
    );
}
