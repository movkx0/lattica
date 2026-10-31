use super::*;
use super::super::super::arithmetic::ArithmeticSpec;

#[test]
fn permutation_source_geometry_and_six_buffers_match_unchanged_device() {
    for operation in [PermutationOperation::AutomorphismQ, PermutationOperation::InverseChallenge] {
        let descriptor = PermutationDescriptor::new(operation);
        let plan = PermutationPreparationPlan::new(descriptor).unwrap();
        let g = plan.geometry();
        let spec = ArithmeticSpec::permutation(operation.code(), &descriptor.sources(), &descriptor.factors()).unwrap();
        assert_eq!((g.rows(), g.width(), g.public_values(), g.raw_words()),
            (spec.rows(), spec.width(), spec.public_words, spec.raw_input_words()));
        assert_eq!((g.rows(), g.public_values(), g.periodic_columns(), g.period()), (256, 8, 134, 256));
        assert_eq!(g.geometry_words(), spec.geometry.len());
        let d = plan.device();
        assert_eq!(d.endpoint_bytes, 64);
        assert_eq!(d.public_bytes, 64);
        assert_eq!(d.status_bytes, 8);
        assert_eq!(d.raw_bytes, 256 * 8);
        assert_eq!(d.geometry_bytes, (32 + 2 * 256) * 8);
        assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
            + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
        assert_eq!(d.largest_allocation_bytes, d.trace_bytes);
    }
}

#[test]
fn permutation_descriptor_refuses_unknown_kind_and_schedule_indices() {
    for code in [0, 3, 256, u64::MAX] { assert_eq!(PermutationDescriptor::from_code(code), Err(Error::UnsupportedProfile)); }
    for operation in [PermutationOperation::AutomorphismQ, PermutationOperation::InverseChallenge] {
        let descriptor = PermutationDescriptor::new(operation);
        assert_eq!(PermutationDescriptor::from_code(operation.code()).unwrap(), descriptor);
        assert_eq!(descriptor.source_index(256), Err(Error::UnsupportedProfile));
        assert_eq!(descriptor.factor(usize::MAX), Err(Error::UnsupportedProfile));
        let g = PermutationGeometry::for_kind(descriptor);
        assert_eq!(g.periodic_value(134, 0), Err(Error::UnsupportedProfile));
        assert_eq!(g.periodic_value(0, 256), Err(Error::UnsupportedProfile));
        let mut sources = descriptor.sources();
        sources.sort_unstable();
        assert_eq!(sources, core::array::from_fn(|i| i as u64));
    }
}

#[test]
fn permutation_periodic_hash_transitions_and_inverse_signs_are_fixed() {
    let descriptor = PermutationDescriptor::new(PermutationOperation::InverseChallenge);
    let g = PermutationGeometry::for_kind(descriptor);
    for row in 0..256 {
        assert_eq!(g.periodic_value(128, row), Ok(Val::from_bool(row < 64)));
        assert_eq!(g.periodic_value(129, row), Ok(Val::from_bool((64..128).contains(&row))));
        assert_eq!(descriptor.source_index(row), Ok(3 * row % 256));
        assert_eq!(descriptor.factor(row), Ok(if (86..171).contains(&row) { Val::NEG_ONE } else { Val::ONE }));
        for lane in 0..4 {
            let expected = if (64..128).contains(&row) { descriptor.factor(4 * (row - 64) + lane).unwrap() } else { Val::ZERO };
            assert_eq!(g.periodic_value(130 + lane, row), Ok(expected));
        }
    }
}
