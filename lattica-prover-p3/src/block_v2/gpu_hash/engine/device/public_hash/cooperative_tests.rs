//! Full protocol-oracle checks and an alternating device-only kernel comparison.
use super::tests::{initialize, live};
use super::*;

#[test]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_public_hash_cooperative_matches_cpu_and_serial_with_fixed_workspace() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    for length in [63usize, 64, 65, 127, 128, 129, 4095, 4096, 4097, 4160, 4161] {
        let fields: Vec<_> = (0..length)
            .map(|i| [0, 1, GOLDILOCKS_MODULUS - 1, GOLDILOCKS_MODULUS - 2][i % 4])
            .collect();
        for domain in [0, GOLDILOCKS_MODULUS - 1] {
            let expected = commitment::hash_fields(domain, &fields).unwrap();
            for cooperative in [false, true] {
                let before = session.stats();
                assert_eq!(hash(&session, domain, &fields, cooperative), expected);
                let after = session.stats();
                assert_eq!(
                    after.uploaded_bytes - before.uploaded_bytes,
                    length as u64 * 8
                );
                assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 32);
                assert_eq!(
                    after.public_hash_permutations - before.public_hash_permutations,
                    length.div_ceil(4) as u64
                );
                assert_eq!(live(&session), baseline);
            }
        }
    }
    let fields: Vec<_> = (0..(1 << 20) + 1)
        .map(|i| ((i as u64).wrapping_mul(0x9e3779b97f4a7c15)) % GOLDILOCKS_MODULUS)
        .collect();
    let expected = commitment::hash_fields(0x4c42563210, &fields).unwrap();
    for round in 0..3 {
        for cooperative in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let before = session.stats();
            let start = std::time::Instant::now();
            assert_eq!(hash(&session, 0x4c42563210, &fields, cooperative), expected);
            let after = session.stats();
            assert_eq!(live(&session), baseline);
            println!(
                "public_hash_lane_comparison {}",
                serde_json::json!({
                    "round":round, "cooperative":cooperative, "fields":fields.len(),
                    "device_ns":after.public_hash_device_ns - before.public_hash_device_ns,
                    "wall_ns":start.elapsed().as_nanos(), "cpu_oracle_equal":true,
                    "global_workspace_bytes":WORKSPACE_BYTES, "static_local_bytes":if cooperative {64} else {0}
                })
            );
        }
    }
}

fn hash(session: &DeviceSession, domain: u64, fields: &[u64], cooperative: bool) -> [u64; 4] {
    session
        .hash_public_stream_kernel(
            domain,
            |emit| {
                for &field in fields {
                    emit(field)?;
                }
                Ok(())
            },
            |_| Ok(()),
            cooperative,
        )
        .unwrap()
}
