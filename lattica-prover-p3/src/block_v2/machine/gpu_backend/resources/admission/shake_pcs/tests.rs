use super::*;
use crate::block_v2::gpu_hash::{
    device::{Extension, MatrixSpec, QuotientCommitShape, RowOrder, TraceCommitShape},
    engine::retained_storage::{RetainedTreeStorageMode, Selection},
};
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn native_geometry_refuses_wrong_width_rows_and_profile_before_allocation() {
    for (rows, width) in [(0, 517), (2048, 517), (8192, 517), (4097, 518), (4096, 519)] {
        assert!(Geometry::new(rows, width).is_err());
    }
    for (rows, width) in [(4096, 517), (4096, 518), (1 << 20, 518)] {
        let (geometry, requests) = measure(|| Geometry::new(rows, width).unwrap());
        assert_eq!(
            (requests.calls, requests.bytes, requests.overflow),
            (0, 0, false)
        );
        assert_eq!((geometry.rows, geometry.main_width), (rows, width));
    }
}

#[test]
fn native_adapter_census_is_pure_and_dominates_each_base_field_wrapper_dimension() {
    for (rows, width) in [(4096, 517), (4096, 518), (1 << 20, 518)] {
        let g = Geometry::new(rows, width).unwrap();
        let (census, requests) = measure(|| preopening::Preopening::new(g).unwrap());
        assert_eq!(
            (requests.calls, requests.bytes, requests.overflow),
            (0, 0, false)
        );
        assert_eq!(census.transform_count, 66);
        assert!(census.maximum_log_rows <= 25 && census.maximum_ntt_groups <= 5);
        assert!(census.native_adapter_backing > 216 * 8 + 3 * 8);
        assert_eq!(
            census.host_bytes,
            census.scaled_base_field_lde_backing
                + census.scaled_device_wrapper_backing
                + census.native_adapter_backing
        );
        let trace = TraceCommitShape::new(
            MatrixSpec::new(rows.ilog2(), width, Extension::Base, RowOrder::Natural, 1).unwrap(),
            4,
        )
        .unwrap();
        assert_eq!((trace.height, trace.width), (rows * 2, width + 4));
        assert_eq!(trace.allocation_bytes().len(), 2);
        // uni::prove doubles the trace domain for hiding, then splits the
        // quotient into twice the normalized degree's chunk count. Those two
        // factors cancel in each quotient chunk's height. Trace commitment
        // height above doubles; quotient commitment does not double it again.
        for log_chunks in 0..=4 {
            let log_ext_degree = rows.ilog2() + 1;
            let chunks = 1usize << (log_chunks + 1);
            let source = MatrixSpec::new(
                log_ext_degree + log_chunks,
                1,
                Extension::Cubic,
                RowOrder::Natural,
                7,
            )
            .unwrap();
            assert_eq!(source.rows(), rows * chunks);
            let quotient = QuotientCommitShape::new(source, chunks, 4).unwrap();
            assert_eq!(
                (quotient.chunks, quotient.height, quotient.width),
                (chunks, rows, 7)
            );
            assert_eq!(quotient.random_words, rows * chunks * 4);
            assert_eq!(quotient.mask_words, rows * 7 * (chunks - 1));
        }
    }
}

#[test]
fn cubic_three_round_opening_accounts_for_all_thirty_four_matrix_capacities() {
    let limits = Limits {
        managed_bytes: 8 << 30,
        tile_bytes: 128 << 20,
        staging_bytes: 64 << 20,
    };
    let trees = Selection {
        mode: RetainedTreeStorageMode::HostBacking,
        host_bytes: 8 << 30,
    };
    for width in [517, 518] {
        let planned = opening::native_plan(
            4096,
            width,
            engine::retained_query_base_bytes(limits).unwrap(),
            24 << 30,
            limits,
            8 << 30,
            trees,
        )
        .unwrap();
        assert!(planned.host_bound_complete);
        assert!(planned.host_workspace_peak_bytes > 0);
        assert!(planned.retained_host_metadata_bytes > 0);
        assert!(planned.required_tree_host_bytes <= trees.host_bytes);
        assert!(planned.opening_device_peak_bytes <= limits.managed_bytes);
        assert!(planned.fri_device_peak_bytes <= limits.managed_bytes);
        assert!(planned.query_device_peak_bytes <= limits.managed_bytes);
        assert!(opening::native_plan(4096, width, 0, 1, limits, 8 << 30, trees).is_err());
        assert!(opening::native_plan(4096, width, 0, 24 << 30, limits, 1, trees).is_err());
    }
}
