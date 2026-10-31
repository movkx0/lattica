use super::*;

fn air(first_block: usize, blocks: usize) -> AesLaneAir {
    AesLaneAir::segment(aes_lane_air::Descriptor {
        domain: 17,
        start_counter: u32::MAX,
        output_len: (first_block + blocks) * 16 - 3,
    }, first_block, blocks).unwrap()
}

#[test]
fn independent_aes_census_covers_every_unchanged_padded_native_shape() {
    for blocks in 1..=64 {
        let air = air(64, blocks);
        let plan = Plan::new(&air).unwrap();
        assert_eq!(plan.shape.width, 417);
        assert_eq!(plan.shape.height, (blocks * 1024).next_power_of_two());
        assert!(plan.bounds.cumulative_requested_bytes + plan.bounds.entry_frame_bytes <= COMPONENT_BYTES);
        assert!(plan.bounds.air_bytes > 0);
        assert!(plan.bounds.periodic_construction_bytes > 0);
        assert!(plan.bounds.periodic_evaluation_bytes > 0);
        assert_eq!(Plan::component_requirement(), Requirements::single(
            Category::IndependentVerifier, Bytes { host: 64 << 20, device: 0 }));
    }
}

#[test]
fn independent_aes_census_rejects_tampered_height_and_overlarge_segments() {
    let mut valid = air(0, 5);
    valid.height /= 2;
    assert!(Plan::new(&valid).is_err());
    valid.height *= 4;
    assert!(Plan::new(&valid).is_err());
    let overlarge = air(0, 65);
    assert!(Plan::new(&overlarge).is_err());
    let mut invalid = air(0, 1);
    invalid.first_block = 1;
    assert!(Plan::new(&invalid).is_err());
}

#[test]
fn verifier_shape_keeps_counter_wrap_and_partial_final_blocks() {
    for output_len in [1, 15, 16, 17, 31, 1023, 1024] {
        let descriptor = aes_lane_air::Descriptor {
            domain: 19, start_counter: u32::MAX, output_len,
        };
        let first = descriptor.blocks() - 1;
        let air = AesLaneAir::segment(descriptor, first, 1).unwrap();
        let plan = Plan::new(&air).unwrap();
        assert_eq!(plan.shape.height, 1024);
        assert_eq!(air.descriptor.start_counter, u32::MAX);
    }
}
