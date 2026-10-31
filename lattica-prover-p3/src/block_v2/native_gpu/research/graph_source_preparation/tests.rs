use super::*;

#[test]
fn fixed_source_geometries_include_all_six_device_allocations() {
    for (kind, rows, width, publics, periods, raw, words) in [
        (GraphSourceKind::Statement, 16384, 496, 8, 2, 50713, 12),
        (GraphSourceKind::PrivateProof, 8192, 469, 4, 3, 23304, 4),
    ] {
        let plan = GraphSourcePreparationPlan::new(kind).unwrap();
        let geometry = plan.geometry();
        assert_eq!((geometry.rows(), geometry.width(), geometry.public_values(),
            geometry.periodic_columns(), geometry.raw_words(), geometry.geometry_words()),
            (rows, width, publics, periods, raw, words));
        let device = plan.device();
        assert_eq!(device.trace_bytes, rows * width * 8);
        assert_eq!(device.generation_peak_bytes,
            (rows * width + 2 * publics + raw + words + 1) * 8);
        assert_eq!(device.largest_allocation_bytes, device.trace_bytes);
        assert_eq!(device.generated_output_bytes().unwrap(), device.trace_bytes + publics * 8);
        assert!(plan.host().required_host_bytes() > plan.host().prepared_partition_bytes().unwrap());
    }
}

#[test]
fn source_periodic_columns_are_exact_and_reject_out_of_range_reads() {
    for kind in [GraphSourceKind::Statement, GraphSourceKind::PrivateProof] {
        let geometry = GraphSourcePreparationPlan::new(kind).unwrap().geometry();
        for column in 0..geometry.periodic_columns() {
            for row in 0..64 {
                let expected = match (kind, column) {
                    (GraphSourceKind::Statement, 0) => row == 3,
                    (GraphSourceKind::Statement, 1) => row == 2,
                    (GraphSourceKind::PrivateProof, 0) => row == 0,
                    (GraphSourceKind::PrivateProof, 1) => row == 63,
                    (GraphSourceKind::PrivateProof, 2) => row < 2,
                    _ => unreachable!(),
                };
                assert_eq!(geometry.periodic_value(column, row).unwrap(), Val::from_bool(expected));
            }
        }
        assert_eq!(geometry.periodic_value(geometry.periodic_columns(), 0), Err(Error::UnsupportedProfile));
        assert_eq!(geometry.periodic_value(0, 64), Err(Error::UnsupportedProfile));
    }
}
