use super::*;

fn spec(log: u32, columns: usize) -> MatrixSpec {
    MatrixSpec::new(log, columns, Extension::Base, RowOrder::BitReversed, 7).unwrap()
}

#[test]
fn query_plan_bounds_complete_scratch_and_host_results() {
    for log in [0, 4, 12, 22, 25] {
        for width in [1, 7, 4096] {
            for queries in [1, 17, 256] {
                for remaining in [128, 1 << 20, 64 << 20, 1 << 30, usize::MAX] {
                    for max_allocation in [64, 1 << 20, 1 << 30] {
                        if let Ok(p) = QueryPlan::new(
                            spec(log.min(8), width),
                            log,
                            queries,
                            remaining,
                            max_allocation,
                            usize::MAX,
                        ) {
                            assert!((1..=width).contains(&p.columns));
                            assert!(p.workspace_bytes <= remaining);
                            assert!(p.workspace_bytes <= PREFERRED_SCRATCH || p.columns == 1);
                            assert!(p.height * p.columns * 8 <= max_allocation);
                            assert!(queries * p.columns * 8 <= max_allocation);
                            assert!(p.height * p.columns <= u32::MAX as usize);
                            assert_eq!(
                                p.workspace_bytes,
                                (p.inverse_words
                                    + p.forward_words
                                    + 2
                                    + queries
                                    + p.columns * (2 * p.height + queries))
                                    * 8
                            );
                            assert_eq!(
                                p.host_peak_bytes,
                                queries * (width + p.columns) * 8 + HOST_METADATA
                            );
                            assert!(QueryPlan::new(
                                spec(log.min(8), width),
                                log,
                                queries,
                                remaining,
                                max_allocation,
                                p.host_peak_bytes - 1
                            )
                            .is_err());
                        }
                    }
                }
            }
        }
    }
    assert!(QueryPlan::new(spec(4, 2), 8, 1, 1024, 1 << 20, 1 << 20).is_err());
    assert!(QueryPlan::new(spec(4, 2), 8, 256, 1 << 20, 1024, 1 << 20).is_err());
    assert!(QueryPlan::new(spec(4, 2), 8, 0, usize::MAX, usize::MAX, usize::MAX).is_err());
    assert!(QueryPlan::new(spec(4, 2), 8, 257, usize::MAX, usize::MAX, usize::MAX).is_err());
}

#[test]
fn query_geometry_rejects_incompatible_profiles_and_indices() {
    assert!(geometry(spec(4, 2), 8, &[255, 0, 255]).is_ok());
    assert!(geometry(spec(0, 1), 0, &[0]).is_ok());
    for (input, log, indices) in [
        (spec(4, 2), 8, vec![]),
        (spec(4, 2), 8, vec![256]),
        (spec(4, 2), 8, vec![0; 257]),
        (spec(4, 2), 3, vec![0]),
        (spec(4, 2), 26, vec![0]),
        (spec(4, 2), u32::MAX, vec![0]),
        (spec(4, 4097), 8, vec![0]),
        (
            MatrixSpec::new(4, 2, Extension::Cubic, RowOrder::BitReversed, 7).unwrap(),
            8,
            vec![0],
        ),
        (
            MatrixSpec::new(4, 2, Extension::Base, RowOrder::Natural, 7).unwrap(),
            8,
            vec![0],
        ),
    ] {
        assert!(geometry(input, log, &indices).is_err());
    }
}

#[test]
fn query_plan_batches_tall_prefixes_and_shrinks_under_pressure() {
    // Full-size recursive PCS domains used to force one transform per column.
    let input = spec(19, 98);
    for queries in [1, 128, 256] {
        let wide = QueryPlan::new(input, 23, queries, 3 << 30, 1 << 30, 1 << 20).unwrap();
        assert_eq!(wide.columns, 16);
        assert!(wide.workspace_bytes <= PREFERRED_SCRATCH);
        let exact =
            QueryPlan::new(input, 23, queries, wide.workspace_bytes, 1 << 30, 1 << 20).unwrap();
        assert_eq!(exact.columns, 16);
        let below = QueryPlan::new(
            input,
            23,
            queries,
            wide.workspace_bytes - 1,
            1 << 30,
            1 << 20,
        )
        .unwrap();
        assert_eq!(below.columns, 15);
    }
    // The larger preference must not become a minimum memory requirement.
    let narrow = QueryPlan::new(input, 23, 128, 256 << 20, 1 << 30, 1 << 20).unwrap();
    assert_eq!(narrow.columns, 1);
    assert!(narrow.workspace_bytes <= 256 << 20);
    assert!(QueryPlan::new(input, 23, 128, 128 << 20, 1 << 30, 1 << 20).is_err());
}
