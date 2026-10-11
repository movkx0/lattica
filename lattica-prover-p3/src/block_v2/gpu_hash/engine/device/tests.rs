use super::*;

fn cubic(log_rows: u32) -> MatrixSpec {
    MatrixSpec::new(log_rows, 1, Extension::Cubic, RowOrder::BitReversed, 1).unwrap()
}

#[test]
fn storage_plans_count_extension_coefficients_and_all_simultaneously_live_buffers() {
    let input = cubic(10);
    let output = input.cubic_fold_output().unwrap();
    assert_eq!(input.bytes(), 1024 * 3 * 8);
    let live = input.bytes() + 4096; // Input plus other engine allocations.
    let plan = MemoryPlan::new(&[output], live, live + output.bytes(), output.bytes()).unwrap();
    assert_eq!(plan.peak_bytes, live + output.bytes());
    assert!(MemoryPlan::new(&[output], live, plan.peak_bytes - 1, output.bytes()).is_err());
    assert!(MemoryPlan::new(&[output], live, plan.peak_bytes, output.bytes() - 1).is_err());
    assert!(MemoryPlan::new(&[output, output], live, plan.peak_bytes, output.bytes()).is_err());
    assert!(MemoryPlan::new(&[output], usize::MAX, usize::MAX, output.bytes()).is_err());
    assert!(MemoryPlan::new(&[], 0, usize::MAX, usize::MAX).is_err());
}

#[test]
fn matrix_domains_reject_invalid_geometry_and_unsupported_fold_profiles() {
    for (log, columns, shift) in [(33, 1, 1), (1, 0, 1), (1, 1, 0), (1, 1, GOLDILOCKS_MODULUS)] {
        assert!(
            MatrixSpec::new(log, columns, Extension::Cubic, RowOrder::BitReversed, shift).is_err()
        );
    }
    assert!(MatrixSpec::new(
        32,
        u32::MAX as usize,
        Extension::Cubic,
        RowOrder::Natural,
        1
    )
    .is_err());
    for spec in [
        cubic(0),
        cubic(26),
        MatrixSpec::new(2, 1, Extension::Quadratic, RowOrder::BitReversed, 1).unwrap(),
        MatrixSpec::new(2, 1, Extension::Cubic, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(2, 2, Extension::Cubic, RowOrder::BitReversed, 1).unwrap(),
        MatrixSpec::new(2, 1, Extension::Cubic, RowOrder::BitReversed, 7).unwrap(),
    ] {
        assert!(spec.cubic_fold_output().is_err());
    }
    assert_eq!(cubic(1).cubic_fold_output().unwrap(), cubic(0));
    let base = MatrixSpec::new(3, 5, Extension::Base, RowOrder::Natural, 7).unwrap();
    assert_eq!(
        (base.rows(), base.columns(), base.words(), base.shift()),
        (8, 5, 40, 7)
    );
}

#[test]
fn compile_time_roots_match_the_pinned_cpu_field_on_every_domain() {
    use crate::config::Val;
    use p3_field::{Field, PrimeField64, TwoAdicField};
    for log in 0..=32 {
        assert_eq!(
            super::super::fri_fold::inverse_root(log),
            Val::two_adic_generator(log as usize)
                .inverse()
                .as_canonical_u64()
        );
    }
}

#[test]
fn device_allocation_charges_follow_ownership_and_cannot_be_counted_as_trees() {
    let accounting = Arc::new(Mutex::new(super::super::Accounting::default()));
    let mut lease = super::super::reserve(&accounting, 128, 256).unwrap();
    lease.mark_device().unwrap();
    assert!(lease.mark_device().is_err());
    assert!(lease.mark_retained().is_err());
    let state = *accounting.lock().unwrap();
    assert_eq!(
        (
            state.live,
            state.device_live,
            state.device_buffers,
            state.retained_live
        ),
        (128, 128, 1, 0)
    );
    drop(lease);
    let state = *accounting.lock().unwrap();
    assert_eq!(
        (
            state.live,
            state.device_live,
            state.device_buffers,
            state.device_peak
        ),
        (0, 0, 0, 128)
    );
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires OpenCL GPU, retained trees; run serially in a bounded service"]
fn resident_fold_commit_chain_matches_cpu_caps_and_paths_with_only_cap_readback() {
    use super::super::{initialize_mode, shutdown, Limits, TestShutdownGuard, TransferMode};
    use crate::{
        block_v2::profile::Challenge,
        config::{MyCompress, MyHash},
    };
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
    let _shutdown = TestShutdownGuard;
    initialize_mode(
        Limits {
            managed_bytes: 4 << 20,
            tile_bytes: 64 << 10,
            staging_bytes: 4096,
        },
        TransferMode::Serial,
    )
    .unwrap();
    let cpu = TwoAdicFriFolding::<(), ()>(std::marker::PhantomData);
    let perm = default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm);
    for log in [1, 2, 4, 10] {
        for cap_height in [0, 2] {
            let session = DeviceSession::new().unwrap();
            let values: Vec<_> = (0..1usize << log)
                .map(|i| {
                    Challenge::from_basis_coefficients_fn(|j| {
                        Val::from_u64((i * 71 + j * 19) as u64)
                    })
                })
                .collect();
            let words: Vec<u64> = values
                .iter()
                .flat_map(|v| {
                    v.as_basis_coefficients_slice()
                        .iter()
                        .map(|x: &Val| x.as_canonical_u64())
                })
                .collect();
            let input = session.upload(cubic(log), &words).unwrap();
            let folded = session.fold_cubic(&input, [17, 18, 19]).unwrap();
            let beta = Challenge::from_basis_coefficients_fn(|j| Val::from_u64(17 + j as u64));
            let expected =
                <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<Val, Challenge>>::fold_matrix(
                    &cpu,
                    beta,
                    1,
                    RowMajorMatrixView::new(&values, 2),
                );
            let height = folded.spec.rows();
            let salt_words: Vec<u64> = (0..height * 4).map(|i| (i * 39 + 17) as u64).collect();
            let salts = session
                .upload(
                    MatrixSpec::new(log - 1, 4, Extension::Base, RowOrder::BitReversed, 1).unwrap(),
                    &salt_words,
                )
                .unwrap();
            let transfer_before = session.stats();
            let commitment = session.commit(&folded, &salts, cap_height).unwrap();
            let mut layers: Vec<Vec<[Val; 4]>> = vec![(0..height)
                .map(|row| {
                    hash.hash_iter(
                        expected[row]
                            .as_basis_coefficients_slice()
                            .iter()
                            .copied()
                            .chain(
                                salt_words[row * 4..row * 4 + 4]
                                    .iter()
                                    .map(|x| Val::from_u64(*x)),
                            ),
                    )
                })
                .collect()];
            while layers.last().unwrap().len() > 1 {
                layers.push(
                    layers
                        .last()
                        .unwrap()
                        .chunks_exact(2)
                        .map(|pair| compress.compress([pair[0], pair[1]]))
                        .collect(),
                );
            }
            let path_len = height.ilog2() as usize - cap_height.min(height.ilog2() as usize);
            assert_eq!(commitment.cap(), layers[path_len]);
            assert_eq!(
                session.stats().uploaded_bytes,
                transfer_before.uploaded_bytes
            );
            assert_eq!(
                session.stats().downloaded_bytes,
                (commitment.cap().len() * 32) as u64
            );
            for index in [0, height / 2, height - 1] {
                let path: Vec<_> = layers[..path_len]
                    .iter()
                    .enumerate()
                    .map(|(level, values)| values[(index >> level) ^ 1])
                    .collect();
                assert_eq!(commitment.open(index).unwrap(), path);
            }
            assert!(commitment.open(height).is_err());
            if log > 1 {
                // The committed vector remains available to the next device
                // stage without reconstruction or an upload of its contents.
                let before = session.stats();
                let next = session.fold_cubic(&folded, [17, 18, 19]).unwrap();
                assert_eq!(next.spec, cubic(log - 2));
                assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
                assert_eq!(session.stats().downloaded_bytes, before.downloaded_bytes);
            }
            drop(input);
            drop(folded);
            drop(salts);
            drop(session);
            assert!(
                shutdown().is_err(),
                "the commitment keeps the context alive"
            );
            assert!(commitment.open(0).is_ok());
        }
    }
    shutdown().unwrap();
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires OpenCL GPU; run serially in a bounded service"]
fn resident_folds_match_reference_without_intermediate_transfers_and_preserve_ownership() {
    use super::super::{initialize_mode, shutdown, Limits, TestShutdownGuard, TransferMode};
    use crate::{block_v2::profile::Challenge, config::Val};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
    use p3_matrix::dense::RowMajorMatrixView;
    let _shutdown = TestShutdownGuard;
    initialize_mode(
        Limits {
            managed_bytes: 4 << 20,
            tile_bytes: 64 << 10,
            staging_bytes: 4096,
        },
        TransferMode::Serial,
    )
    .unwrap();
    let cpu = TwoAdicFriFolding::<(), ()>(std::marker::PhantomData);
    let fold_cpu = |beta, values: &[Challenge]| {
        <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<Val, Challenge>>::fold_matrix(
            &cpu,
            beta,
            1,
            RowMajorMatrixView::new(values, 2),
        )
    };
    let encode = |values: &[Challenge]| -> Vec<u64> {
        values
            .iter()
            .flat_map(|v| {
                v.as_basis_coefficients_slice()
                    .iter()
                    .map(|x: &Val| x.as_canonical_u64())
            })
            .collect()
    };
    for log in [1, 2, 4, 14] {
        for beta_words in [[0, 0, 0], [1, 0, 0], [17, 18, 19]] {
            let session = DeviceSession::new().unwrap();
            let beta = Challenge::from_basis_coefficients_fn(|i| Val::from_u64(beta_words[i]));
            let values: Vec<_> = (0..1usize << log)
                .map(|i| {
                    Challenge::from_basis_coefficients_fn(|j| {
                        Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xffff_ffff_0000_0000)
                                .wrapping_add(j as u64),
                        )
                    })
                })
                .collect();
            let spec = cubic(log);
            let input = session.upload(spec, &encode(&values)).unwrap();
            let other = DeviceSession::new().unwrap();
            assert!(other.fold_cubic(&input, beta_words).is_err());
            assert!(other.read(&input, spec.bytes()).is_err());
            assert!(session.read(&input, spec.bytes() - 1).is_err());
            assert!(session
                .fold_cubic(&input, [GOLDILOCKS_MODULUS, 0, 0])
                .is_err());
            assert!(shutdown().is_err());
            let first = session.fold_cubic(&input, beta_words).unwrap();
            let mut expected = fold_cpu(beta, &values);
            let final_output = if log > 1 {
                expected = fold_cpu(beta, &expected);
                session.fold_cubic(&first, beta_words).unwrap()
            } else {
                first
            };
            let stats = session.stats();
            assert_eq!(stats.uploaded_bytes, spec.bytes() as u64);
            assert_eq!(stats.downloaded_bytes, 0);
            assert_eq!(stats.cubic_folds, if log > 1 { 2 } else { 1 });
            assert_eq!(
                session
                    .read(&final_output, final_output.spec.bytes())
                    .unwrap(),
                encode(&expected)
            );
            assert_eq!(
                session.stats().downloaded_bytes,
                final_output.spec.bytes() as u64
            );
        }
    }
    shutdown().unwrap();
}
