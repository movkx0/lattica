use super::*;

#[test]
fn crypto_trace_geometry_accounts_all_scratch_before_device_access() {
    let cases = [
        (0, 32, 49, 1, 3, 4096, 417, 12),
        (1, 32, 33, 0, 3, 64, 3084, 8),
        (2, 135, 137, 0, 1, 4096, 517, 216),
        (3, 8 * 136 + 5, 9 * 136 + 1, 0, 8, 32768, 518, 216),
        (4, 136, 272, 0, 3, 128, 4033, 216),
    ];
    for (kind, input, output, first, units, rows, width, public) in cases {
        let plan =
            CryptoPlan::new(kind, input, output, first, units, 7, u32::MAX, 1 << 20).unwrap();
        assert_eq!(plan.specs[0].rows(), rows);
        assert_eq!(plan.specs[0].columns(), width);
        assert_eq!(plan.specs[1].columns(), public);
        let bytes = plan.specs.iter().map(|s| s.bytes()).sum::<usize>();
        let maximum = plan.specs.iter().map(|s| s.bytes()).max().unwrap();
        assert!(MemoryPlan::new(&plan.specs, 0, bytes, maximum).is_ok());
        assert!(MemoryPlan::new(&plan.specs, 0, bytes - 1, maximum).is_err());
        assert!(MemoryPlan::new(&plan.specs, 1, bytes, maximum).is_err());
        assert!(MemoryPlan::new(&plan.specs, 0, bytes, maximum - 1).is_err());
    }
    for (kind, input, output, first, units) in [
        (5, 0, 0, 0, 1),
        (0, 31, 16, 0, 1),
        (0, 32, 0, 0, 1),
        (1, 32, 33, 1, 2),
        (2, 0, 1, 0, 2),
        (3, 136, 137, 0, 2),
        (3, 1024, 1, 0, 3),
        (4, 0, 1, 0, 0),
        (4, 0, 1, 1, 1),
    ] {
        assert!(CryptoPlan::new(kind, input, output, first, units, 0, 0, 1 << 20).is_err());
    }
    assert!(CryptoPlan::new(0, 32, 16, 0, 1, 0, 0, 0).is_err());
}

#[test]
fn aes_lane_checkpoints_are_included_in_scrubbed_scratch_admission() {
    let plan = CryptoPlan::new(0, 32, 1024, 7, 3, 0, 0, 1 << 20).unwrap();
    // One GPU-built 256-entry S-box witness table; no per-row duplicate table.
    assert_eq!(AES_TABLE_WORDS, 256 * 66);
    assert_eq!(
        plan.specs[3].words(),
        AES_TABLE_WORDS + 10 * 16 + 4 * 8 + 64 + 3 * 122 + 4 * 3 + 28
    );
    assert_eq!(plan.pose_count, 1);
}

#[test]
fn aes_lane_checkpoint_capacity_covers_padding_without_widening_wide_aes() {
    assert_eq!(AES_LANE_STATE_WORDS, 118);
    assert_eq!(aes_lane_checkpoint_words(1, 1).unwrap(), 153);
    assert_eq!(aes_lane_checkpoint_words(5, 8).unwrap(), 662);
    assert!(aes_lane_checkpoint_words(usize::MAX, 1).is_err());
    assert!(aes_lane_checkpoint_words(1, usize::MAX).is_err());
    let lane = CryptoPlan::new(0, 32, 257, 7, 5, 0, u32::MAX, 1 << 20).unwrap();
    assert_eq!(lane.rows, 8192);
    assert_eq!(
        lane.specs[3].words(),
        AES_TABLE_WORDS + 12 * 16 + 6 * 8 + 64 + 662
    );
    let wide = CryptoPlan::new(1, 32, 33, 0, 3, 0, u32::MAX, 1 << 20).unwrap();
    assert_eq!(wide.specs[3].words(), AES_TABLE_WORDS + 3 * 16 + 4 * 8 + 64);
    let bytes = lane.specs.iter().map(|spec| spec.bytes()).sum::<usize>();
    let maximum = lane.specs.iter().map(|spec| spec.bytes()).max().unwrap();
    assert!(MemoryPlan::new(&lane.specs, 0, bytes, maximum).is_ok());
    assert!(MemoryPlan::new(&lane.specs, 0, bytes - 662 * 8, maximum).is_err());
}
