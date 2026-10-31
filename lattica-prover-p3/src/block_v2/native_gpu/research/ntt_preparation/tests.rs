use super::*;
use super::super::super::arithmetic::ArithmeticSpec;

#[test]
fn source_geometry_matches_unchanged_device_ntt_for_all_admitted_counts() {
    for modulus in [Q, QHAT] {
        for count in 1..=MAX_POLYNOMIALS {
            let descriptor = NttDescriptor::new(modulus, count).unwrap();
            let plan = NttPreparationPlan::new(descriptor).unwrap();
            let g = plan.geometry();
            let native = ArithmeticSpec::ntt(modulus, count,
                &descriptor.steps(), &descriptor.permutation()).unwrap();
            assert_eq!((g.rows(), g.width(), g.public_values(), g.raw_words()),
                (native.rows(), native.width(), native.public_words, native.raw_input_words()));
            assert_eq!(g.geometry_words(), native.geometry.len());
            assert_eq!(g.periodic_columns(), 9 + 2 * count);
            assert_eq!(g.period(), g.rows());
            let d = plan.device();
            assert_eq!(d.endpoint_bytes, count * 8 * 8);
            assert_eq!(d.public_bytes, count * 8 * 8);
            assert_eq!(d.status_bytes, count * 8);
            assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
                + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
            assert_eq!(d.largest_allocation_bytes, d.trace_bytes);
        }
    }
}

#[test]
fn ntt_descriptor_rejects_wrong_modulus_and_outside_unchanged_count_domain() {
    for count in [0, 129, 256, usize::MAX] {
        assert_eq!(NttDescriptor::new(Q, count), Err(Error::UnsupportedProfile));
    }
    for modulus in [0, 1, Q - 1, Q + 1, QHAT - 1, u64::MAX] {
        assert_eq!(NttDescriptor::new(modulus, 1), Err(Error::UnsupportedProfile));
    }
    assert!(NttDescriptor::new(Q, 3).is_ok());
    let kind = NttDescriptor::new(Q, 1).unwrap();
    assert!(kind.step(767).is_ok());
    assert_eq!(kind.step(768), Err(Error::UnsupportedProfile));
    assert_eq!(kind.step(usize::MAX), Err(Error::UnsupportedProfile));
}

#[test]
fn ntt_periodic_metadata_preserves_polynomial_boundaries_and_zero_padding() {
    for modulus in [Q, QHAT] {
        for count in [1, 3, 64, 128] {
            let kind = NttDescriptor::new(modulus, count).unwrap();
            let g = NttGeometry::for_kind(kind);
            for poly in 0..count {
                let base = poly * ROWS_PER_POLYNOMIAL;
                assert_eq!(g.periodic_value(5, base + 63), Ok(Val::ONE));
                assert_eq!(g.periodic_value(4, base + 64), Ok(Val::ONE));
                assert_eq!(g.periodic_value(4, base + 831), Ok(Val::ONE));
                assert_eq!(g.periodic_value(5, base + 832), Ok(Val::ONE));
                assert_eq!(g.periodic_value(9 + poly, base + 63), Ok(Val::ONE));
                assert_eq!(g.periodic_value(9 + count + poly, base + 895), Ok(Val::ONE));
                assert_eq!(g.periodic_value(8, base + 895), Ok(Val::ZERO));
                assert_eq!(g.periodic_value(7, base + 895), Ok(Val::from_bool(poly + 1 < count)));
                for index in 0..4 {
                    assert_eq!(g.periodic_value(index, base + 64), Ok(Val::from_u64(kind.step(0).unwrap()[index])));
                    assert_eq!(g.periodic_value(index, base + 831), Ok(Val::from_u64(kind.step(767).unwrap()[index])));
                }
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
