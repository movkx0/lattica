use super::*;
use crate::block_v2::profile;
use crate::config::{Dft, MyCompress, MyHash};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{coset::TwoAdicMultiplicativeCoset, PrimeCharacteristicRing};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_matrix::bitrev::BitReversibleMatrix;
use rand::SeedableRng;

fn mmcs(gpu: bool) -> CandidateMmcs {
    let perm = default_goldilocks_poseidon2_8();
    let mut mmcs = CandidateMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm),
        profile::CAP_HEIGHT,
        ChaCha20Rng::from_seed([101; 32]),
    );
    mmcs.gpu = gpu;
    mmcs
}

#[test]
#[ignore = "requires OpenCL GPU and retained trees; run serially in a <=3 GiB zero-swap service"]
fn owned_pcs_queries_match_cpu_after_host_lde_storage_is_removed() {
    query_equivalence(false);
}

#[test]
#[ignore = "requires OpenCL GPU and retained trees; run serially in a <=3 GiB zero-swap service"]
fn device_only_pcs_commitments_read_only_caps_and_preserve_cpu_queries() {
    query_equivalence(true);
}

fn query_equivalence(device_only: bool) {
    let _shutdown = engine::TestShutdownGuard;
    engine::initialize_mode(
        Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 1 << 20,
            staging_bytes: 64 << 10,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
    // The existing commitment executor requires at least two source rows;
    // the one-row query primitive is covered by device::query::tests.
    for (log, widths) in [(1, vec![1]), (5, vec![3, 7, 33]), (12, vec![65])] {
        for bits in [0, profile::LOG_BLOWUP] {
            for preprocessing in [false, true] {
                let mut gpu = mmcs(true);
                gpu.device_only = device_only;
                let cpu = mmcs(false);
                let session = DeviceSession::new().unwrap();
                let matrices: Vec<_> = widths
                    .iter()
                    .map(|&width| {
                        RowMajorMatrix::new(
                            (0..(1 << log) * width)
                                .map(|i| {
                                    Val::from_u64((i as u64).wrapping_mul(0xffff_ffff_0000_0000))
                                })
                                .collect(),
                            width,
                        )
                    })
                    .collect();
                let expected_inputs: Vec<_> = matrices
                    .iter()
                    .map(|m| {
                        Dft::default()
                            .coset_lde_batch(m.clone(), profile::LOG_BLOWUP, Val::GENERATOR)
                            .bit_reverse_rows()
                            .to_row_major_matrix()
                    })
                    .collect();
                let (expected_cap, expected) = cpu.commit(expected_inputs);
                let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, log).unwrap();
                let before_commit = engine::report("owned query oracle before commit").unwrap();
                let (cap, mut data) = gpu
                    .commit_resident_retained_owned(
                        matrices.into_iter().map(|m| (domain, m)).collect(),
                        profile::LOG_BLOWUP,
                        128 << 20,
                        None,
                        bits,
                        Some((&session, preprocessing)),
                    )
                    .unwrap();
                assert_eq!(cap, expected_cap);
                if device_only {
                    let after_commit = engine::report("device PCS oracle after commit").unwrap();
                    assert_eq!(
                        after_commit.lde_host_output_bytes,
                        before_commit.lde_host_output_bytes
                    );
                    assert_eq!(
                        after_commit.lde_host_reordered_bytes,
                        before_commit.lde_host_reordered_bytes
                    );
                    assert_eq!(
                        after_commit.lde_device_only_commits
                            - before_commit.lde_device_only_commits,
                        1
                    );
                    let ProverData::DeviceOnly { tree, .. } = &data else {
                        panic!("device-only selection must never materialize host LDEs");
                    };
                    assert_eq!(
                        after_commit.downloaded_bytes - before_commit.downloaded_bytes,
                        (tree.cap().len() * 4 * 8) as u64,
                        "commitment downloads only its cap"
                    );
                    assert_eq!(
                        gpu.get_matrix_heights(&data),
                        cpu.get_matrix_heights(&expected)
                    );
                    use std::panic::{catch_unwind, AssertUnwindSafe};
                    assert!(catch_unwind(AssertUnwindSafe(|| gpu.get_matrices(&data))).is_err());
                    assert!(catch_unwind(AssertUnwindSafe(|| gpu.open_batch(0, &data))).is_err());
                    assert!(catch_unwind(AssertUnwindSafe(
                        || gpu.commit(vec![RowMajorMatrix::new(vec![Val::ONE; 8], 1)])
                    ))
                    .is_err());
                }
                let dimensions = data.owned_dimensions().unwrap().to_vec();
                // Poison even host geometry: the new route may use only its
                // independently recorded commitment dimensions/device prefixes.
                match &mut data {
                    ProverData::GpuRetained { matrices, .. } => matrices.clear(),
                    ProverData::Compact(d) => d.prefixes.clear(),
                    ProverData::DeviceOnly { .. } if device_only => {}
                    _ => panic!("expected a retained GPU commitment"),
                }
                let height = (1 << log) << profile::LOG_BLOWUP;
                let indices = vec![height - 1, 0, height / 2, height - 1, 1];
                let imported = DeviceSession::new().unwrap();
                let query_session = if preprocessing { &imported } else { &session };
                if !preprocessing {
                    assert!(gpu
                        .open_owned_queries(&imported, &data, &indices, 64 << 20)
                        .is_err());
                }
                let before = query_session.stats();
                assert!(gpu
                    .open_owned_queries(query_session, &data, &[], 64 << 20)
                    .is_err());
                assert!(gpu
                    .open_owned_queries(query_session, &data, &[height], 64 << 20)
                    .is_err());
                assert!(gpu
                    .open_owned_queries(query_session, &data, &indices, 0)
                    .is_err());
                assert!(cpu
                    .open_owned_queries(query_session, &data, &indices, 64 << 20)
                    .is_err());
                assert_eq!(before, query_session.stats());
                let actual = gpu
                    .open_owned_queries(query_session, &data, &indices, 64 << 20)
                    .unwrap();
                let after = query_session.stats();
                assert_eq!(
                    after.query_reconstructions - before.query_reconstructions,
                    widths.len() as u64
                );
                assert_eq!(
                    after.query_value_bytes - before.query_value_bytes,
                    (indices.len() * widths.iter().sum::<usize>() * 8) as u64
                );
                assert_eq!(
                    after.uploaded_bytes - before.uploaded_bytes,
                    (widths.len() * (log.max(1) + log + profile::LOG_BLOWUP + indices.len()) * 8)
                        as u64
                );
                for (&index, opening) in indices.iter().zip(actual) {
                    assert_eq!(
                        postcard::to_allocvec(&opening).unwrap(),
                        postcard::to_allocvec(&cpu.open_batch(index, &expected)).unwrap()
                    );
                    gpu.verify_batch(&cap, &dimensions, index, (&opening).into())
                        .unwrap();
                }
                // Both implementations still use their original salt stream.
                // Query reconstruction, including rejected queries, cannot draw.
                let next = RowMajorMatrix::new(vec![Val::ONE; 64], 4);
                let mut next_gpu = gpu.clone();
                next_gpu.device_only = false;
                assert_eq!(
                    next_gpu.commit(vec![next.clone()]).0,
                    cpu.commit(vec![next]).0
                );
            }
        }
    }
    engine::shutdown().unwrap();
}
