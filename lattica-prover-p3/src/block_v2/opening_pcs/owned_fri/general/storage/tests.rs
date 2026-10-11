use super::*;
type Cubic = crate::block_v2::profile::Challenge;
type Quadratic = crate::config::Challenge;

fn geometry(heights: &[usize], arity: usize, final_len: usize) -> Geometry<'_> {
    Geometry {
        input_heights: heights,
        log_blowup: 4,
        log_final_len: final_len,
        max_log_arity: arity,
        queries: 128,
        initial_rounds: 1,
    }
}

#[test]
fn schedule_preserves_binary_nonbinary_mixing_and_final_polynomials() {
    for (heights, arity, final_len, expected) in [
        (
            &[10][..],
            1,
            0,
            vec![(9, 1), (8, 1), (7, 1), (6, 1), (5, 1), (4, 1)],
        ),
        (&[10][..], 4, 0, vec![(6, 4), (4, 2)]),
        (&[14, 11, 8][..], 4, 0, vec![(11, 3), (8, 3), (4, 4)]),
        (&[16][..], 4, 8, vec![(12, 4)]),
        (&[8, 4][..], 4, 0, vec![(4, 4)]),
        (&[4][..], 1, 0, vec![]),
    ] {
        let plan = Plan::new::<Cubic>(
            geometry(heights, arity, final_len),
            1 << 20,
            HOST_QUERY_ALLOWANCE,
        )
        .unwrap();
        assert_eq!(
            plan.layers()
                .iter()
                .map(|s| (s.log_height, s.log_arity))
                .collect::<Vec<_>>(),
            expected
        );
        let quadratic = Plan::new::<Quadratic>(
            geometry(heights, arity, final_len),
            1 << 20,
            HOST_QUERY_ALLOWANCE,
        )
        .unwrap();
        assert_eq!(plan.layers(), quadratic.layers());
        assert!(plan.total_bytes > quadratic.total_bytes);
    }
}

#[test]
fn combined_limit_counts_retained_initial_queries_and_fri_assembly() {
    let initial = 1 << 20;
    let plan = Plan::new::<Cubic>(geometry(&[25], 1, 0), initial, HOST_QUERY_ALLOWANCE).unwrap();
    assert!(plan.fri_query_bytes > 0 && plan.assembly_bytes > 0);
    assert!(Plan::new::<Cubic>(geometry(&[25], 1, 0), initial, initial).is_err());
    assert!(Plan::new::<Cubic>(geometry(&[25], 1, 0), initial, plan.total_bytes - 1).is_err());
    assert_eq!(
        Plan::new::<Cubic>(geometry(&[25], 1, 0), initial, plan.total_bytes)
            .unwrap()
            .total_bytes,
        plan.total_bytes
    );
}

#[test]
fn invalid_storage_geometry_rejects_without_allocating() {
    for heights in [
        &[][..],
        &[26][..],
        &[usize::MAX][..],
        &[3][..],
        &[10, 10][..],
        &[8, 10][..],
    ] {
        assert!(Plan::new::<Cubic>(geometry(heights, 1, 0), 0, HOST_QUERY_ALLOWANCE).is_err());
    }
    for (arity, final_len) in [(0, 0), (5, 0), (1, 17), (1, usize::MAX), (1, 6)] {
        assert!(
            Plan::new::<Cubic>(geometry(&[10], arity, final_len), 0, HOST_QUERY_ALLOWANCE).is_err()
        );
    }
    for queries in [0, profile::NUM_QUERIES + 1, usize::MAX] {
        let mut g = geometry(&[10], 1, 0);
        g.queries = queries;
        assert!(Plan::new::<Cubic>(g, 0, HOST_QUERY_ALLOWANCE).is_err());
    }
    for count in [257, usize::MAX] {
        let mut g = geometry(&[10], 1, 0);
        g.initial_rounds = count;
        assert!(Plan::new::<Cubic>(g, 0, HOST_QUERY_ALLOWANCE).is_err());
    }
    let mut g = geometry(&[10], 1, 0);
    g.initial_rounds = 0;
    assert!(Plan::new::<Cubic>(g, 1, HOST_QUERY_ALLOWANCE).is_err());
    for limit in [HOST_QUERY_ALLOWANCE + 1, usize::MAX] {
        assert!(Plan::new::<Cubic>(geometry(&[10], 1, 0), 0, limit).is_err());
    }
    assert!(Plan::new::<Cubic>(geometry(&[10], 1, 0), usize::MAX, HOST_QUERY_ALLOWANCE).is_err());
}

#[test]
fn maximum_layer_count_and_zero_initial_rounds_have_finite_plans() {
    let heights: Vec<_> = (4..=25).rev().collect();
    let mut g = geometry(&heights, 4, 0);
    g.initial_rounds = 0;
    let plan = Plan::new::<Cubic>(g, 0, HOST_QUERY_ALLOWANCE).unwrap();
    assert_eq!(plan.layer_count, 21);
    assert!(plan.layers().iter().all(|l| l.log_arity == 1));
    assert_eq!(plan.initial_query_bytes, 0);
    assert!(plan.total_bytes < HOST_QUERY_ALLOWANCE);
}

fn census<F: FriExtension>() {
    for queries in [1, 96, 128] {
        for height in [0usize, 6, 25] {
            for arity in [2, 16] {
                let mut batch = FriData::proof_vector(queries).unwrap();
                let mut raw = FriData::proof_vector::<u64>(queries * arity * F::DIMENSION).unwrap();
                raw.resize(raw.capacity(), 0);
                let mut raw_salts = FriData::proof_vector::<u64>(queries * 4).unwrap();
                raw_salts.resize(queries * 4, 0);
                let indices = [vec![0u64; queries], vec![0u64; queries]];
                for _ in 0..queries {
                    let mut row = FriData::proof_vector(arity).unwrap();
                    row.resize(arity, F::ZERO);
                    let mut salt = FriData::proof_vector(4).unwrap();
                    salt.resize(4, Val::ZERO);
                    let mut path =
                        FriData::proof_vector(height.saturating_sub(profile::CAP_HEIGHT)).unwrap();
                    path.resize(path.capacity(), [Val::ZERO; 4]);
                    let mut rows = FriData::proof_vector(1).unwrap();
                    rows.push(row);
                    let mut salts = FriData::proof_vector(1).unwrap();
                    salts.push(salt);
                    batch.push(BatchOpening::<F, FriExtensionMmcs<F>>::new(
                        rows,
                        (salts, path),
                    ));
                }
                let mut bytes = (raw.capacity()
                    + raw_salts.capacity()
                    + indices.iter().map(Vec::capacity).sum::<usize>())
                    * 8
                    + batch.capacity() * size_of::<BatchOpening<F, FriExtensionMmcs<F>>>();
                for opening in batch {
                    let (rows, (salts, path)) = opening.unpack();
                    bytes += rows.capacity() * size_of::<Vec<F>>()
                        + salts.capacity() * size_of::<Vec<Val>>()
                        + path.capacity() * size_of::<[Val; 4]>();
                    bytes += rows
                        .iter()
                        .map(|row| row.capacity() * size_of::<F>())
                        .sum::<usize>();
                    bytes += salts
                        .iter()
                        .map(|salt| salt.capacity() * size_of::<Val>())
                        .sum::<usize>();
                }
                assert_eq!(
                    bytes,
                    FriData::query_host_bytes::<F>(height, arity, queries).unwrap()
                );
            }
        }
    }
}

#[test]
fn cubic_query_plan_covers_actual_backing_capacities() {
    census::<Cubic>();
}
#[test]
fn quadratic_query_plan_covers_actual_backing_capacities() {
    census::<Quadratic>();
}

#[test]
fn malformed_queries_and_excessive_vectors_reject_before_allocation() {
    for (height, arity, queries) in [
        (26, 2, 1),
        (4, 0, 1),
        (4, 1, 1),
        (4, 3, 1),
        (4, 32, 1),
        (4, 2, 0),
        (4, 2, 129),
    ] {
        assert!(FriData::query_host_bytes::<Cubic>(height, arity, queries).is_err());
    }
    assert!(FriData::proof_vector::<u64>(usize::MAX).is_err());
    assert!(FriData::proof_vector::<[u8; 1024]>(1 << 21).is_err());
    for count in [0, 1, 128, 256] {
        assert_eq!(
            FriData::proof_vector::<u64>(count).unwrap().capacity(),
            count
        );
    }
}
