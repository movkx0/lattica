//! Future public-only qualification: raw symbolic inference bypasses the hint.
//! These checks allocate symbolic DAGs; run serially under an admitted external
//! host/process guard. They generate no witness, proof, AES block, or GPU work.
use super::*;
use p3_air::symbolic::{get_max_constraint_degree, AirLayout};

fn assert_exact_degree(air: &AesLaneAir) {
    // This opt-in records operator admission; it does not impose a memory limit.
    assert_eq!(
        std::env::var("PQ_AES_DEGREE_AUDIT_ADMITTED").as_deref(),
        Ok("1"),
        "symbolic degree audit requires admission under an external host/process guard",
    );
    let layout = AirLayout::from_air::<Val>(air);
    // This helper constructs raw constraints; it does not read the degree hint.
    let inferred = get_max_constraint_degree::<Val, AesLaneAir>(air, layout);
    assert_eq!(inferred, 7);
    assert_eq!(air.max_constraint_degree(), Some(inferred));
    for is_zk in [0usize, 1] {
        let expected = (inferred + is_zk).max(2) - 1;
        let expected_log_chunks = expected.next_power_of_two().ilog2() as usize;
        assert_eq!(expected_log_chunks, 3);
        assert_eq!(
            p3_uni_stark::get_log_num_quotient_chunks::<Val, AesLaneAir>(
                air, layout, is_zk,
            ),
            expected_log_chunks,
        );
    }
}

#[test]
#[ignore = "symbolic DAG allocation requires explicit admitted host/process limits"]
fn whole_stream_degree_hint_matches_raw_symbolic() {
    // Both halves of the final block, exact byte/block boundaries, and padded
    // three-block traces. Zero constants also exercise symbolic simplification.
    for output_len in [1, 8, 9, 16, 17, 24, 25, 33] {
        let air = AesLaneAir::new(Descriptor {
            domain: 0,
            start_counter: 0,
            output_len,
        })
        .unwrap();
        assert_exact_degree(&air);
    }
}

#[test]
#[ignore = "symbolic DAG allocation requires explicit admitted host/process limits"]
fn segmented_degree_hint_matches_raw_symbolic() {
    // Later segments omit the global initial accumulator constraint. Include
    // short/full final blocks, a padded segment and a segment ending midstream.
    for (output_len, first_block, blocks) in [
        (17, 1, 1),
        (24, 1, 1),
        (25, 1, 1),
        (32, 1, 1),
        (49, 1, 3),
        (65, 1, 3),
    ] {
        let air = AesLaneAir::segment(
            Descriptor {
                domain: u64::MAX,
                start_counter: u32::MAX,
                output_len,
            },
            first_block,
            blocks,
        )
        .unwrap();
        assert_exact_degree(&air);
    }
}
