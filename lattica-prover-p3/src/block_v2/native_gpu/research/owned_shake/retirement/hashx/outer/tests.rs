use super::*;
use crate::block_v2::native_gpu::ShakeTraceSpec;

#[test]
fn outer_bridge_source_requires_the_last_exact_hashx_segment() {
    for ordinal in 0..10 {
        let (first, count) = match ordinal {
            0..=6 => (ordinal * 16, 16),
            7 => (112, 8),
            8 => (120, 1),
            _ => (121, 1),
        };
        let spec = ShakeTraceSpec {
            input_len: 16_416,
            output_len: 137,
            first_permutation: first,
            permutations: count,
        };
        let geometry = if count == 1 {
            ShakePreparationPlan::singleton(spec)
        } else {
            ShakePreparationPlan::batch(spec)
        }
        .unwrap()
        .geometry();
        assert_eq!(final_source(geometry).is_ok(), ordinal == 9);
    }
    let other = ShakePreparationPlan::singleton(ShakeTraceSpec {
        input_len: 16_416,
        output_len: 138,
        first_permutation: 121,
        permutations: 1,
    })
    .unwrap()
    .geometry();
    assert_eq!(final_source(other), Err(Error::Geometry));
    assert!(
        PreissuedHashxOuterBackend::additional_host_bytes().unwrap()
            > 8 * size_of::<PreissuedHashxOuterBackend>()
    );
    // No original reservation, backend, accepted proof or retirement is forged.
}
