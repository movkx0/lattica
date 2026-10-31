//! Future public-only qualification: direct symbolic inference bypasses hints.
//! These checks allocate symbolic DAGs, so run serially under an admitted host
//! allowance after the frozen benchmark ends. No witness or proof is generated.
use super::*;
use p3_air::symbolic::{get_max_constraint_degree, AirLayout, SymbolicAirBuilder};

fn assert_exact_degree<A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>>(air: &A) {
    // Explicit opt-in records operator admission; it is not a memory limit.
    // The runner must retain its external host/process guard.
    assert_eq!(
        std::env::var("PQ_SHAKE_DEGREE_AUDIT_ADMITTED").as_deref(),
        Ok("1"),
        "symbolic degree audit requires explicit admission under an external host/process guard",
    );
    let layout = AirLayout::from_air::<Val>(air);
    // This helper calls get_all_symbolic_constraints directly, not the hint.
    let inferred = get_max_constraint_degree::<Val, A>(air, layout);
    assert_eq!(inferred, 7);
    assert_eq!(air.max_constraint_degree(), Some(inferred));
    for is_zk in [0usize, 1] {
        let expected = (inferred + is_zk).max(2) - 1;
        let expected_log_chunks = expected.next_power_of_two().ilog2() as usize;
        assert_eq!(
            p3_uni_stark::get_log_num_quotient_chunks::<Val, A>(air, layout, is_zk),
            expected_log_chunks,
        );
    }
}

#[test]
#[ignore = "public symbolic DAG allocation; run serially after the benchmark freeze"]
fn single_shake_degree_matches_independent_symbolic_inference() {
    for descriptor in [
        Descriptor { input_len: 0, output_len: 0 },
        Descriptor { input_len: 1, output_len: 1 },
        Descriptor { input_len: RATE - 1, output_len: RATE },
        Descriptor { input_len: RATE, output_len: RATE },
        Descriptor { input_len: RATE + 3, output_len: RATE * 3 + 1 },
    ] {
        for permutation in 0..descriptor.permutations().unwrap() {
            let air = LaneShakeAir::new(descriptor, permutation).unwrap();
            assert_exact_degree(&air);
            assert_eq!(
                batch::ShakeSegmentAir::Single(air).max_constraint_degree(),
                Some(MAX_CONSTRAINT_DEGREE),
            );
        }
    }
}

#[test]
#[ignore = "public symbolic DAG allocation; run serially after the benchmark freeze"]
fn batch_shake_degree_and_segment_dispatch_match_symbolic_inference() {
    let absorb = Descriptor { input_len: RATE * 8 + 3, output_len: 1 };
    let squeeze = Descriptor { input_len: 3, output_len: RATE * 10 + 1 };
    for count in [1, 2, 4, 8] {
        for air in [
            batch::BatchShakeAir::full_absorb(absorb, 0, count).unwrap(),
            batch::BatchShakeAir::full_squeeze(squeeze, 1, count).unwrap(),
        ] {
            assert_exact_degree(&air);
            let segment = batch::ShakeSegmentAir::Batch(air);
            assert_exact_degree(&segment);
        }
    }
}
