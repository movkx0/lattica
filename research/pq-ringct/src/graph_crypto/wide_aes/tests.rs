use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn request(key: [u8; 32], operation: usize, descriptor: aes_air::Descriptor) -> Request {
    Request::new(
        [19; 32],
        operation,
        0,
        RequestDescriptor::Aes(descriptor),
        Payload::Aes(key),
        Policy::default(),
    )
    .unwrap()
}

fn small_request() -> Request {
    request(
        [7; 32],
        5,
        aes_air::Descriptor {
            domain: 0x4368,
            start_counter: u32::MAX,
            output_len: 31,
        },
    )
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tools/pq-wide-aes-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn whole_wide_aes_commitments_match_original_air_for_truncation_and_counter_wrap() {
    for output_len in [1, 17, 31] {
        let request = request(
            [7; 32],
            5,
            aes_air::Descriptor {
                domain: 0x4368,
                start_counter: u32::MAX,
                output_len,
            },
        );
        let factory = request.wide_aes(1 << 30).unwrap();
        let witness = factory.air.generate([7; 32]).unwrap();
        assert!(factory.expected_public.get().is_none());
        assert_eq!(*factory.expected_public_cpu(), witness.public_values);
        assert_eq!(witness.output, request.output_bytes_hint());
        let serial = aes_lane_air::AesLaneAir::new(factory.descriptor())
            .unwrap()
            .generate([7; 32])
            .unwrap();
        assert_eq!(serial.output, witness.output);
        assert_eq!(
            &serial.public_values
                [aes_lane_air::INPUT_COMMITMENT..aes_lane_air::INPUT_COMMITMENT + 4],
            &witness.public_values[..4],
        );
        assert_eq!(
            &serial.public_values[aes_lane_air::OUTPUT_END..aes_lane_air::OUTPUT_END + 4],
            &witness.public_values[4..],
        );
    }
}

#[test]
fn whole_wide_aes_identity_binds_payload_profile_request_descriptor_and_layout() {
    let original = small_request();
    let key = original.wide_aes(1 << 30).unwrap().cache_key().unwrap();
    assert_eq!(
        key,
        small_request()
            .wide_aes(1 << 30)
            .unwrap()
            .cache_key()
            .unwrap()
    );
    assert_ne!(key, original.cache_key(0).unwrap());
    for field in 0..7 {
        let mut changed = small_request();
        match field {
            0 => changed.payload = Payload::Aes([8; 32]),
            1 => changed.profile[0] ^= 1,
            2 => changed.index += 1,
            3..=5 => {
                let RequestDescriptor::Aes(mut d) = changed.descriptor else {
                    unreachable!()
                };
                match field {
                    3 => d.domain += 1,
                    4 => d.start_counter = 0,
                    _ => d.output_len += 1,
                }
                changed = request([7; 32], 5, d);
            }
            // Changing only admission leaves the exact native statement unchanged.
            _ => {
                assert_eq!(key, changed.wide_aes(2 << 30).unwrap().cache_key().unwrap());
                continue;
            }
        }
        assert_ne!(key, changed.wide_aes(1 << 30).unwrap().cache_key().unwrap());
    }
}

#[test]
fn whole_wide_aes_admission_estimates_exact_complete_requests_without_traces() {
    for (length, blocks, height, estimate) in [
        (2572, 161, 4096, 5_387_583_488),
        (4788, 300, 8192, 10_238_296_064),
    ] {
        let request = request(
            [7; 32],
            5,
            aes_air::Descriptor {
                domain: 0x4368,
                start_counter: 0,
                output_len: length,
            },
        );
        assert!(request.wide_aes(0).is_err());
        assert!(request.wide_aes(estimate - 1).is_err());
        let factory = request.wide_aes(estimate).unwrap();
        assert_eq!(factory.descriptor().blocks(), blocks);
        assert_eq!(factory.geometry().height, height);
        assert_eq!(factory.geometry().width, aes_air::WIDTH);
        assert_eq!(
            factory.geometry().uncalibrated_peak_estimate_bytes,
            estimate
        );
        assert_eq!(request.wide_aes(8 << 30).is_ok(), blocks == 161);
        assert!(request.wide_aes(16 << 30).is_ok());
    }
    let shake = Request::new(
        [19; 32],
        5,
        0,
        RequestDescriptor::Shake(shake_air::Descriptor {
            input_len: 1,
            output_len: 1,
        }),
        Payload::Shake(vec![7]),
        Policy::default(),
    )
    .unwrap();
    assert!(shake.wide_aes(16 << 30).is_err());
}

#[test]
fn missing_malformed_and_oversized_wide_aes_cache_entries_fail_without_proving() {
    let directory = Directory::new();
    let cache = ProofCache::new(&directory.0, 128).unwrap();
    let request = small_request();
    let factory = request.wide_aes(1 << 30).unwrap();
    assert!(cache.load_wide_aes(&factory).unwrap().is_none());
    let path = cache.entry_path(&factory.cache_key().unwrap());
    assert!(cache.import_wide_aes(&factory, &path).is_err());
    for bytes in [b"not a proof".to_vec(), vec![b' '; 129]] {
        std::fs::write(&path, bytes).unwrap();
        assert!(cache.load_wide_aes(&factory).is_err());
        assert!(cache.load_or_prove_wide_aes(&factory).is_err());
        assert!(cache.import_wide_aes(&factory, &path).is_err());
    }
}
