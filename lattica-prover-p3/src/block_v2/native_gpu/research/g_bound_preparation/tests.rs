use super::*;
use super::super::super::arithmetic::ArithmeticSpec;

#[test]
fn g_bound_source_geometry_and_six_buffers_match_unchanged_device() {
    for bound in [6_825_771, 1_137_628] {
        let descriptor = GBoundDescriptor::new(bound).unwrap();
        let plan = GBoundPreparationPlan::new(descriptor).unwrap();
        let g = plan.geometry();
        let spec = ArithmeticSpec::g_bound(descriptor.f_bound(), descriptor.g_bound(),
            &descriptor.schedule(), descriptor.psi_128(), descriptor.inverse_psi_128()).unwrap();
        assert_eq!((g.rows(), g.width(), g.public_values(), g.raw_words()),
            (spec.rows(), spec.width(), spec.public_words, spec.raw_input_words()));
        assert_eq!((g.rows(), g.width(), g.public_values(), g.periodic_columns(), g.period()),
            (4096, 850, 8, 39, 128));
        assert_eq!(g.geometry_words(), spec.geometry.len());
        let d = plan.device();
        assert_eq!(d.endpoint_bytes, 64);
        assert_eq!(d.public_bytes, 64);
        assert_eq!(d.status_bytes, 8);
        assert_eq!(d.raw_bytes, 512 * 8);
        assert_eq!(d.geometry_bytes, (32 + 39 * 128) * 8);
        assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
            + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
        assert_eq!(d.largest_allocation_bytes, d.trace_bytes);
    }
}

#[test]
fn g_bound_descriptor_rejects_unpinned_bounds_and_schedule_indices() {
    for bound in [0, 1, 6_825_770, 6_825_772, 1_137_627, 1_137_629, u32::MAX] {
        assert_eq!(GBoundDescriptor::new(bound), Err(Error::UnsupportedProfile));
    }
    for (bound, expected_f) in [(6_825_771, 5086), (1_137_628, 565)] {
        let descriptor = GBoundDescriptor::new(bound).unwrap();
        assert_eq!(descriptor.f_bound(), expected_f);
        assert!(descriptor.maximum_integer_difference() < 0xffff_ffff_0000_0001);
        let g = GBoundGeometry::for_kind(descriptor);
        assert!(g.periodic_value(38, 127).is_ok());
        assert_eq!(g.periodic_value(39, 0), Err(Error::UnsupportedProfile));
        assert_eq!(g.periodic_value(0, 128), Err(Error::UnsupportedProfile));
        assert_eq!(g.periodic_value(usize::MAX, usize::MAX), Err(Error::UnsupportedProfile));
    }
}

#[test]
fn g_bound_schedule_preserves_hash_and_block_transitions() {
    let g = GBoundGeometry::for_kind(GBoundDescriptor::new(6_825_771).unwrap());
    for row in 0..128 {
        assert_eq!(g.periodic_value(34, row), Ok(Val::from_usize(row)));
        assert_eq!(g.periodic_value(35, row), Ok(Val::from_usize(4 * (row % 64))));
        assert_eq!(g.periodic_value(36, row), Ok(Val::from_bool(row < 64)));
        assert_eq!(g.periodic_value(37, row), Ok(Val::from_bool(row == 63)));
        assert_eq!(g.periodic_value(38, row), Ok(Val::from_bool(row == 127)));
    }
}
