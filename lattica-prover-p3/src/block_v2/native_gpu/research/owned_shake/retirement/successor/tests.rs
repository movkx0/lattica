use super::*;
use crate::block_v2::native_gpu::ShakeTraceSpec;

fn singleton(input_len: usize, output_len: usize, first: usize) -> ShakePreparationGeometry {
    ShakePreparationPlan::singleton(ShakeTraceSpec {
        input_len,
        output_len,
        first_permutation: first,
        permutations: 1,
    })
    .unwrap()
    .geometry()
}

#[test]
fn preissued_pair_and_odd_tail_require_the_actual_consecutive_native() {
    let a = singleton(137, 137, 0);
    let b = singleton(137, 137, 1);
    let c = singleton(137, 137, 2);
    assert!(geometry_follows(a, b, false).is_ok());
    assert!(geometry_follows(a, c, false).is_ok());
    assert!(geometry_follows(a, b, true).is_ok());
    assert!(geometry_follows(b, c, true).is_ok());
    for (previous, next) in [(a, a), (b, a), (a, c), (c, b)] {
        assert_eq!(geometry_follows(previous, next, true), Err(Error::Geometry));
    }
}

#[test]
fn changed_descriptor_or_native_batch_never_enters_singleton_continuation() {
    let first = singleton(137, 137, 0);
    let changed_input = singleton(138, 137, 1);
    let changed_output = singleton(137, 138, 1);
    for next in [changed_input, changed_output] {
        assert_eq!(geometry_follows(first, next, false), Err(Error::Geometry));
    }
    // Two complete absorb blocks keep this a valid homogeneous batch. The
    // continuation must reject its batch geometry, not its preparation plan.
    let batch = ShakePreparationPlan::batch(ShakeTraceSpec {
        input_len: 272,
        output_len: 137,
        first_permutation: 0,
        permutations: 2,
    })
    .unwrap()
    .geometry();
    assert_eq!(
        geometry_follows(batch, singleton(272, 137, 2), false),
        Err(Error::Geometry)
    );
}
