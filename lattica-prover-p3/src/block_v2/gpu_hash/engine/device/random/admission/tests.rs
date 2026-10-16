use super::super::{MAX_OUTPUT_WORDS, STREAM_WORDS};
use super::*;

#[test]
fn sequential_retention_and_replay_have_distinct_exact_storage_boundaries() {
    // With 88 bytes already live, these draws allocate 216, 4272 and 160
    // bytes respectively. Retained outputs add 64 then 2056 bytes before
    // subsequent draws. The middle draw sets the peak in both modes.
    for (retain, peak, retained) in [(true, 4424, 2128), (false, 4360, 0)] {
        let plan =
            FieldStoragePlan::new([8, 257, 1].into_iter(), &[24], retain, 15, 64, peak, 2176)
                .unwrap();
        assert_eq!(plan.peak_bytes, peak);
        assert_eq!(plan.retained_output_bytes, retained);
        assert_eq!(plan.max_allocation_bytes, 2176);
        assert_eq!(plan.requests, 3);
        assert_eq!(plan.largest_request_words, 257);
        assert_eq!(plan.minimum_end_position, 15 + 2 * (8 + 257 + 1));
        assert!(FieldStoragePlan::new(
            [8, 257, 1].into_iter(),
            &[24],
            retain,
            15,
            64,
            peak - 1,
            2176
        )
        .is_err());
    }
    assert!(
        FieldStoragePlan::new([8, 257, 1].into_iter(), &[24], true, 15, 64, 4360, 2176).is_err()
    );
}

#[test]
fn raw_expansion_can_exceed_output_and_is_checked_as_its_own_allocation() {
    // Eight samples need 64 output bytes but 128 raw bytes for arbitrary
    // u32 cursor alignment, plus three eight-byte compaction buffers.
    assert!(FieldStoragePlan::new([8].into_iter(), &[], true, 1, 0, 216, 127).is_err());
    let plan = FieldStoragePlan::new([8].into_iter(), &[], true, 1, 0, 216, 128).unwrap();
    assert_eq!(plan.peak_bytes, 216);
    assert_eq!(plan.max_allocation_bytes, 128);
    assert_eq!(plan.retained_output_bytes, 64);
}

#[test]
fn batch_stream_bound_uses_every_request_without_claiming_rejection_consumption() {
    let count = 8 + 257 + 1;
    for retain in [false, true] {
        let p = FieldStoragePlan::new(
            [8, 257, 1].into_iter(),
            &[],
            retain,
            STREAM_WORDS - 2 * count,
            0,
            usize::MAX,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(p.minimum_end_position, STREAM_WORDS);
        assert!(FieldStoragePlan::new(
            [8, 257, 1].into_iter(),
            &[],
            retain,
            STREAM_WORDS - 2 * count + 1,
            0,
            usize::MAX,
            usize::MAX
        )
        .is_err());
    }
}

#[test]
fn malformed_requests_pending_buffers_and_aggregate_overflow_reject() {
    for requests in [
        vec![],
        vec![0],
        vec![1, 0],
        vec![MAX_OUTPUT_WORDS + 1],
        vec![1; 513],
    ] {
        assert!(FieldStoragePlan::new(
            requests.into_iter(),
            &[],
            false,
            0,
            0,
            usize::MAX,
            usize::MAX
        )
        .is_err());
    }
    assert!(FieldStoragePlan::new([1].into_iter(), &[256], false, 0, 0, usize::MAX, 255).is_err());
    assert!(FieldStoragePlan::new([1].into_iter(), &[256], false, 0, 0, 255, usize::MAX).is_err());
    assert!(FieldStoragePlan::new(
        [1].into_iter(),
        &[1],
        false,
        0,
        usize::MAX,
        usize::MAX,
        usize::MAX
    )
    .is_err());
    assert!(FieldStoragePlan::new(
        [1].into_iter(),
        &[],
        false,
        0,
        usize::MAX,
        usize::MAX,
        usize::MAX
    )
    .is_err());
    assert!(FieldStoragePlan::new(
        [1].into_iter(),
        &[],
        false,
        u128::MAX,
        0,
        usize::MAX,
        usize::MAX
    )
    .is_err());
    assert!(FieldStoragePlan::new([1; 512].into_iter(), &[], false, 0, 0, 160, 128).is_ok());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_shared_preflight_preserves_stream_and_rejects_before_device_work() {
    use crate::block_v2::gpu_hash::engine::{self, device::DeviceSession};
    use crate::config::Val;
    use p3_field::PrimeField64;
    use rand::{RngExt, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        engine::Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 8 << 20,
            staging_bytes: 1 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    let session = DeviceSession::new().unwrap();
    let mut cpu = ChaCha20Rng::from_seed([117; 32]);
    cpu.set_word_pos(15);
    let random = session.import_random_stream(cpu.clone()).unwrap();
    let before = session.stats();
    for requests in [
        vec![],
        vec![0],
        vec![257, 0],
        vec![MAX_OUTPUT_WORDS + 1],
        vec![1; 513],
    ] {
        assert!(random.preflight_fields(&requests, &[]).is_err());
        assert!(random.preflight_salt_replay(&requests, &[]).is_err());
    }
    assert!(random.preflight_fields(&[257], &[usize::MAX]).is_err());
    // Retaining eight 8 MiB outputs cannot fit; sequential replay can.
    assert!(random.preflight_fields(&[1 << 20; 8], &[]).is_err());
    random.preflight_salt_replay(&[1 << 20; 8], &[]).unwrap();
    random.preflight_fields(&[257, 19], &[32]).unwrap();
    assert_eq!(session.stats(), before);
    assert_eq!(random.0.cursor.lock().unwrap().position, 15);
    for count in [257, 19] {
        let expected: Vec<_> = (0..count)
            .map(|_| cpu.random::<Val>().as_canonical_u64())
            .collect();
        let actual = random
            .sample_fields(count)
            .unwrap()
            .read_for_test(count * 8)
            .unwrap();
        assert_eq!(actual, expected);
    }
    assert_eq!(random.0.cursor.lock().unwrap().position, cpu.get_word_pos());
    eprintln!("gpu_shared_random_preflight rejected_without_device_work=true retained_and_replay_distinct=true cpu_reference_words=276");
}
