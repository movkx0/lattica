use super::*;
use super::super::super::arithmetic::ArithmeticSpec;

#[test]
fn source_geometry_matches_unchanged_device_arithmetic_for_all_admitted_profiles() {
    for modulus in [Q, QHAT] {
        for count in [1, 2, 4, 8, 16, 32, 64] {
            for operation in [AffineOperation::Add, AffineOperation::Subtract,
                AffineOperation::SignedToCanonical { bound: 1 },
                AffineOperation::SignedToCanonical { bound: 565 },
                AffineOperation::SignedToCanonical { bound: (modulus - 1).min(i32::MAX as u64) as u32 }]
            {
                let descriptor = AffineDescriptor::new(operation, modulus, count).unwrap();
                let plan = AffinePreparationPlan::new(descriptor).unwrap();
                let g = plan.geometry();
                let native = ArithmeticSpec::affine(modulus, count, operation.code(), operation.bound()).unwrap();
                assert_eq!((g.rows(), g.width(), g.public_values(), g.raw_words()),
                    (native.rows(), native.width(), native.public_words, native.raw_input_words()));
                assert_eq!(g.geometry_words(), native.geometry.len());
                let d = plan.device();
                assert_eq!(d.endpoint_bytes, count * 12 * 8);
                assert_eq!(d.public_bytes, 4 * 8);
                assert_eq!(d.status_bytes, count * 8);
                assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
                    + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
                assert_eq!(d.largest_allocation_bytes, d.trace_bytes);
            }
        }
    }
}

#[test]
fn descriptor_refuses_unadmitted_counts_moduli_and_signed_bounds() {
    for count in [0, 3, 65, 128, usize::MAX] {
        assert_eq!(AffineDescriptor::new(AffineOperation::Add, Q, count), Err(Error::UnsupportedProfile));
    }
    for modulus in [0, 1, Q - 1, Q + 1, u64::MAX] {
        assert_eq!(AffineDescriptor::new(AffineOperation::Add, modulus, 1), Err(Error::UnsupportedProfile));
    }
    for bound in [0, Q as u32, u32::MAX] {
        assert_eq!(AffineDescriptor::new(AffineOperation::SignedToCanonical { bound }, Q, 1), Err(Error::UnsupportedProfile));
    }
}

#[test]
fn periodic_boundaries_keep_conversion_right_roots_disabled() {
    let conversion = AffineGeometry::for_kind(AffineDescriptor::new(
        AffineOperation::SignedToCanonical { bound: 565 }, Q, 64).unwrap());
    let add = AffineGeometry::for_kind(AffineDescriptor::new(AffineOperation::Add, Q, 64).unwrap());
    assert_eq!(conversion.period(), 512);
    assert_eq!(conversion.periodic_value(1, 1), Ok(Val::ZERO));
    assert_eq!(add.periodic_value(1, 1), Ok(Val::ONE));
    assert_eq!(conversion.periodic_value(4, 257), Ok(Val::ZERO));
    assert_eq!(add.periodic_value(4, 257), Ok(Val::ONE));
    assert_eq!(conversion.periodic_value(7, 511), Ok(Val::ONE));
    assert_eq!(conversion.periodic_value(6, 255), Ok(Val::ZERO));
    assert_eq!(conversion.periodic_value(8, 256), Ok(Val::ONE));
    assert_eq!(conversion.periodic_value(9, 0), Err(Error::UnsupportedProfile));
    assert_eq!(conversion.periodic_value(0, 512), Err(Error::UnsupportedProfile));
}
