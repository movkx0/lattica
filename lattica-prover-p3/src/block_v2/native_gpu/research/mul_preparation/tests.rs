use super::*;
use super::super::super::arithmetic::ArithmeticSpec;

#[test]
fn source_geometry_matches_unchanged_device_product_for_every_count() {
    for modulus in [Q, QHAT] {
        for count in 1..=MAX_POLYNOMIALS {
            let descriptor = MulDescriptor::new(modulus, count).unwrap();
            let plan = MulPreparationPlan::new(descriptor).unwrap();
            let g = plan.geometry();
            let native = ArithmeticSpec::mul(modulus, count, &descriptor.terms()).unwrap();
            assert_eq!((g.rows(), g.width(), g.public_values(), g.raw_words()),
                (native.rows(), native.width(), native.public_words, native.raw_input_words()));
            assert_eq!(g.geometry_words(), native.geometry.len());
            assert_eq!(g.periodic_columns(), 21 + count);
            assert_eq!(g.period(), g.rows());
            let d = plan.device();
            assert_eq!(d.endpoint_bytes, count * 12 * 8);
            assert_eq!(d.public_bytes, count * 12 * 8);
            assert_eq!(d.status_bytes, count * 8);
            assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
                + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
            assert_eq!(d.largest_allocation_bytes, d.trace_bytes);
        }
    }
}

#[test]
fn product_descriptor_rejects_nonreference_modulus_count_and_schedule_index() {
    for count in [0, 129, 256, usize::MAX] {
        assert_eq!(MulDescriptor::new(Q, count), Err(Error::UnsupportedProfile));
    }
    for modulus in [0, 1, Q - 1, Q + 1, QHAT - 1, u64::MAX] {
        assert_eq!(MulDescriptor::new(modulus, 1), Err(Error::UnsupportedProfile));
    }
    assert!(MulDescriptor::new(Q, 3).is_ok());
    let kind = MulDescriptor::new(Q, 1).unwrap();
    assert!(kind.term(1023).is_ok());
    assert_eq!(kind.term(1024), Err(Error::UnsupportedProfile));
    assert_eq!(kind.term(usize::MAX), Err(Error::UnsupportedProfile));
}

#[test]
fn product_periodic_columns_preserve_block_and_polynomial_boundaries() {
    for modulus in [Q, QHAT] {
        for count in [1, 3, 16, 128] {
            let g = MulGeometry::for_kind(MulDescriptor::new(modulus, count).unwrap());
            for poly in 0..count {
                let base = poly * ROWS_PER_POLYNOMIAL;
                assert_eq!(g.periodic_value(0, base), Ok(Val::ONE));
                assert_eq!(g.periodic_value(1, base + 1), Ok(Val::ONE));
                assert_eq!(g.periodic_value(3, base + 2), Ok(Val::ONE));
                assert_eq!(g.periodic_value(3, base + 17), Ok(Val::ONE));
                assert_eq!(g.periodic_value(2, base + 18), Ok(Val::ONE));
                assert_eq!(g.periodic_value(4, base + 18), Ok(Val::ZERO));
                assert_eq!(g.periodic_value(6, base + 18), Ok(Val::ONE));
                let end = base + ROWS_PER_POLYNOMIAL - 1;
                assert_eq!(g.periodic_value(21 + poly, end), Ok(Val::ONE));
                assert_eq!(g.periodic_value(5, end), Ok(Val::from_bool(poly + 1 < count)));
            }
            for index in 0..g.periodic_columns() {
                for row in [count * ROWS_PER_POLYNOMIAL, g.rows() - 1] {
                    assert_eq!(g.periodic_value(index, row), Ok(Val::ZERO));
                }
            }
            assert_eq!(g.periodic_value(g.periodic_columns(), 0), Err(Error::UnsupportedProfile));
            assert_eq!(g.periodic_value(0, g.rows()), Err(Error::UnsupportedProfile));
        }
    }
}
