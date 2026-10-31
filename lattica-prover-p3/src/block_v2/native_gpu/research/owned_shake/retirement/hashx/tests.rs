use super::*;
use crate::block_v2::native_gpu::ShakeTraceSpec;

fn shape(index: usize) -> ShakePreparationGeometry {
    let (first, count) = match index {
        0..=6 => (16 * index, 16),
        7 => (112, 8),
        8 => (120, 1),
        9 => (121, 1),
        _ => panic!("outside exact HashX source"),
    };
    let spec = ShakeTraceSpec {
        input_len: 16_416,
        output_len: 137,
        first_permutation: first,
        permutations: count,
    };
    if count == 1 {
        ShakePreparationPlan::singleton(spec)
    } else {
        ShakePreparationPlan::batch(spec)
    }
    .unwrap()
    .geometry()
}

#[test]
fn exact_hashx_batches_padding_and_squeezing_close_consecutive_coverage() {
    for ordinal in 0..10 {
        assert_eq!(index(shape(ordinal)), Ok(ordinal));
        if ordinal > 0 {
            assert_eq!(consecutive(shape(ordinal - 1), shape(ordinal)), Ok(()));
        }
    }
    assert_eq!(shape(9).first_permutation() + shape(9).permutations(), 122);
    for (previous, next) in [(0, 0), (0, 2), (7, 6), (7, 9), (9, 8)] {
        assert_eq!(
            consecutive(shape(previous), shape(next)),
            Err(Error::Geometry)
        );
    }
}

#[test]
fn changed_descriptor_and_smaller_batch_are_not_the_active_source() {
    for (input_len, output_len, count) in [(16_417, 137, 16), (16_416, 138, 16), (16_416, 137, 8)] {
        let other = ShakePreparationPlan::batch(ShakeTraceSpec {
            input_len,
            output_len,
            first_permutation: 0,
            permutations: count,
        })
        .unwrap()
        .geometry();
        assert_eq!(index(other), Err(Error::Geometry));
    }
}

#[test]
fn equal_source_metadata_does_not_identify_an_original_attempt() {
    let first = Rc::new(Attempt(0));
    let same = Rc::clone(&first);
    let other = Rc::new(Attempt(0));
    assert!(Rc::ptr_eq(&first, &same));
    assert!(!Rc::ptr_eq(&first, &other));
    assert_eq!(Rc::strong_count(&first), 2);
    drop(same);
    assert_eq!(Rc::strong_count(&first), 1);
    assert!(
        NativeHashxPhase::additional_host_bytes().unwrap()
            > 8 * size_of::<[Option<NativeHashxSuccessor>; 9]>()
    );
}
