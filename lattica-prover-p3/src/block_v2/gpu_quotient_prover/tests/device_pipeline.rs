use super::*;

#[test]
#[ignore = "requires OpenCL GPU and retained trees; run serially in a <=3 GiB service with zero swap"]
fn device_lde_quotient_commit_matches_cpu_and_avoids_intermediate_readback() {
    device_pipeline(false);
}

#[test]
#[ignore = "requires OpenCL GPU and retained trees; run serially in a <=3 GiB service with zero swap"]
fn partitioned_device_quotient_matches_cpu_caps_paths_and_transfer_bounds() {
    device_pipeline(true);
}

fn device_pipeline(partitioned: bool) {
    use crate::block_v2::gpu_hash::{
        device::{DeviceSession, Extension, MatrixSpec, RowOrder},
        initialize_quotient_test_engine, shutdown, Limits, TestShutdownGuard,
    };
    use crate::config::{Dft, MyCompress, MyHash};
    use p3_dft::TwoAdicSubgroupDft;
    use p3_field::{coset::TwoAdicMultiplicativeCoset as Domain, PrimeField64};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
    use p3_uni_stark::StarkGenericConfig;
    use std::{sync::Arc, time::Instant};
    let _shutdown = TestShutdownGuard;
    initialize_quotient_test_engine(Limits {
        managed_bytes: if partitioned { 12 << 20 } else { 256 << 20 },
        tile_bytes: if partitioned { 4 << 20 } else { 16 << 20 },
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let (air, lookups) = fixture();
    let gadget = LogUpGadget::new();
    let layout = AirLayout::from_air::<Val>(&air);
    let program = Arc::new(Program::compile(&air, layout, &lookups, &gadget).unwrap());
    let initializer = DeviceSession::new().unwrap();
    let prepared = initializer.prepare_quotient(program.clone()).unwrap();
    assert_eq!(initializer.stats().prepared_quotient_programs, 1);
    drop(initializer);
    // Public prepared code survives its creating attempt, but pins its context.
    assert!(shutdown().is_err());
    let config = profile::make_config();
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(permutation.clone());
    let compress = MyCompress::new(permutation);
    // Force the unsplit output plus its equally-sized transform scratch to
    // exceed 12 MiB for either AIR layout. A fixed 2^12 output fit the narrower
    // preprocessing trace, so it did not exercise admission rejection there.
    let oversized_rows = (12usize << 20) / (2 * 8 * air.preprocessed_width()) + 1;
    let oversized_log = oversized_rows.next_power_of_two().ilog2().max(12);
    let geometries: &[(u32, u32)] = if partitioned {
        &[(0, 3), (3, 5), (4, 8), (10, oversized_log)]
    } else {
        &[(0, 3), (3, 5), (4, 12)]
    };
    for &(log_trace, log_quotient) in geometries {
        let session = DeviceSession::new().unwrap();
        let height = 1usize << log_quotient;
        let matrix = |width, salt: u64| {
            RowMajorMatrix::new(
                (0..(1 << log_trace) * width)
                    .map(|i| {
                        Val::from_u64(
                            (i as u64)
                                .wrapping_mul(0xffff_ffff_0000_0000)
                                .wrapping_add(salt),
                        )
                    })
                    .collect(),
                width,
            )
        };
        let main = matrix(air.width(), 17);
        let pre = matrix(air.preprocessed_width(), 19);
        let perm = matrix((lookups.len() + 1) * 3, 23);
        let transform = |matrix: &RowMajorMatrix<Val>, extension: Extension, order, shift| {
            let words: Vec<_> = matrix
                .values
                .iter()
                .map(|v: &Val| v.as_canonical_u64())
                .collect();
            let input = session
                .upload(
                    MatrixSpec::new(
                        log_trace,
                        matrix.width / extension.degree(),
                        extension,
                        RowOrder::Natural,
                        1,
                    )
                    .unwrap(),
                    &words,
                )
                .unwrap();
            session
                .lde(
                    &input,
                    if partitioned { log_trace } else { log_quotient },
                    shift,
                    order,
                )
                .unwrap()
        };
        let device_main = transform(&main, Extension::Base, RowOrder::BitReversed, 7);
        let device_pre = transform(&pre, Extension::Base, RowOrder::Natural, 7);
        let device_perm = transform(&perm, Extension::Cubic, RowOrder::BitReversed, 7);
        assert_eq!(session.stats().downloaded_bytes, 0);
        if partitioned && log_trace == 10 {
            // The former contiguous expansion cannot fit this engine budget;
            // the bounded route below must still produce identical results.
            let before = session
                .plan_outputs(&[device_pre.spec()])
                .unwrap()
                .live_bytes;
            assert!(session
                .lde(&device_pre, log_quotient, 7, RowOrder::Natural)
                .is_err());
            assert_eq!(
                session
                    .plan_outputs(&[device_pre.spec()])
                    .unwrap()
                    .live_bytes,
                before
            );
        }
        let cpu_lde = |m| {
            Dft::default()
                .coset_lde_batch(m, (log_quotient - log_trace) as usize, Val::from_u64(7))
                .to_row_major_matrix()
        };
        let cpu_main = cpu_lde(main.clone());
        let cpu_pre = cpu_lde(pre.clone());
        let cpu_perm = cpu_lde(perm.clone());
        for alpha_index in 0..2 {
            // Reusing prepared code must not reuse any proof's sampled values.
            let challenges: Vec<_> = (0..lookups.len() * gadget.num_challenges())
                .map(|i| {
                    profile::Challenge::from_basis_coefficients_fn(|j| {
                        Val::from_u64((i * 19 + j + 7 + alpha_index) as u64)
                    })
                })
                .collect();
            let terminals = [profile::Challenge::from_basis_coefficients_fn(|i| {
                Val::from_u64(29 + i as u64)
            })];
            let public = [Val::from_u64(alpha_index as u64 + 1)];
            let mut parameters: Vec<_> = public.iter().map(|x| x.as_canonical_u64()).collect();
            parameters.extend(challenges.iter().chain(&terminals).flat_map(|x| {
                x.as_basis_coefficients_slice()
                    .iter()
                    .map(|v: &Val| v.as_canonical_u64())
            }));
            let alpha = if alpha_index == 0 {
                profile::Challenge::ZERO
            } else {
                profile::Challenge::from_basis_coefficients_fn(|i| Val::from_u64(31 + i as u64))
            };
            let expected = p3_batch_stark::prover::quotient_values::<profile::Config, _, _, _>(
                config.pcs(),
                &air,
                &public,
                layout,
                Domain::new(Val::ONE, log_trace as usize).unwrap(),
                Domain::new(Val::from_u64(7), log_quotient as usize).unwrap(),
                &cpu_main,
                Some(&cpu_perm),
                &lookups,
                &terminals,
                &gadget,
                &challenges,
                Some(&cpu_pre),
                alpha,
            );
            let a: &[Val] = alpha.as_basis_coefficients_slice();
            let alpha_words = [
                a[0].as_canonical_u64(),
                a[1].as_canonical_u64(),
                a[2].as_canonical_u64(),
            ];
            let before = session.stats();
            let started = Instant::now();
            let quotient = if partitioned {
                session
                    .quotient_cubic_partitioned(
                        &prepared,
                        log_trace,
                        log_quotient,
                        7,
                        &device_main,
                        Some(&device_pre),
                        Some(&device_perm),
                        alpha_words,
                        &parameters,
                    )
                    .unwrap()
            } else {
                session
                    .quotient_cubic(
                        &prepared,
                        log_trace,
                        &device_main,
                        Some(&device_pre),
                        Some(&device_perm),
                        alpha_words,
                        &parameters,
                    )
                    .unwrap()
            };
            let elapsed = started.elapsed().as_nanos();
            let after = session.stats();
            let calls = if partitioned {
                1u64 << (log_quotient - log_trace)
            } else {
                1
            };
            let scalar_input = if partitioned { 16 } else { 0 };
            let scalar_output = if partitioned { 8 * calls } else { 0 };
            assert_eq!(
                after.scalar_input_bytes - before.scalar_input_bytes,
                scalar_input
            );
            assert_eq!(
                after.scalar_output_bytes - before.scalar_output_bytes,
                scalar_output
            );
            assert_eq!(
                after.downloaded_bytes - before.downloaded_bytes,
                8 * calls + scalar_output
            );
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                (parameters.len() * 8) as u64 * calls
                    + (calls - 1) * 3 * 2 * u64::from(log_trace.max(1)) * 8
                    + scalar_input
            );
            assert_eq!(
                after.quotient_evaluations,
                before.quotient_evaluations + calls
            );
            assert_eq!(after.prepared_quotient_programs, 0);
            let salt_words: Vec<u64> = (0..height * 4).map(|i| (i * 39 + 17) as u64).collect();
            let salts = session
                .upload(
                    MatrixSpec::new(log_quotient, 4, Extension::Base, RowOrder::Natural, 7)
                        .unwrap(),
                    &salt_words,
                )
                .unwrap();
            let before_commit = session.stats();
            let committed = session.commit(&quotient, &salts, 2).unwrap();
            let after_commit = session.stats();
            assert_eq!(after_commit.uploaded_bytes, before_commit.uploaded_bytes);
            assert_eq!(
                after_commit.downloaded_bytes - before_commit.downloaded_bytes,
                (committed.cap().len() * 32) as u64
            );
            // Reference work below is independent of the device pipeline.
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
                                    .map(|v| Val::from_u64(*v)),
                            ),
                    )
                })
                .collect()];
            while layers.last().unwrap().len() > 4 {
                layers.push(
                    layers
                        .last()
                        .unwrap()
                        .chunks_exact(2)
                        .map(|p| compress.compress([p[0], p[1]]))
                        .collect(),
                );
            }
            assert_eq!(committed.cap(), layers.last().unwrap());
            for row in [0, 1, height / 2, height - 1] {
                let expected_path: Vec<_> = layers[..layers.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, layer)| layer[(row >> level) ^ 1])
                    .collect();
                assert_eq!(committed.open(row).unwrap(), expected_path);
            }
            let expected_words: Vec<_> = expected
                .iter()
                .flat_map(|x| {
                    x.as_basis_coefficients_slice()
                        .iter()
                        .map(|v: &Val| v.as_canonical_u64())
                })
                .collect();
            assert_eq!(
                session.read(&quotient, quotient.spec().bytes()).unwrap(),
                expected_words
            );
            assert!(DeviceSession::new()
                .unwrap()
                .quotient_cubic(
                    &prepared,
                    log_trace,
                    &device_main,
                    Some(&device_pre),
                    Some(&device_perm),
                    alpha_words,
                    &parameters
                )
                .is_err());
            assert!(session
                .quotient_cubic(
                    &prepared,
                    log_trace,
                    &device_main,
                    None,
                    Some(&device_perm),
                    alpha_words,
                    &parameters
                )
                .is_err());
            assert!(session
                .quotient_cubic(
                    &prepared,
                    log_trace,
                    &device_main,
                    Some(&device_pre),
                    Some(&device_perm),
                    [u64::MAX, 0, 0],
                    &parameters
                )
                .is_err());
            eprintln!("device_quotient_comparison rows={height} alpha_index={alpha_index} quotient_call_ns={elapsed} matrix_transfer_bytes=0");
            if log_trace == 0 && alpha_index == 1 {
                let overlap_main = transform(&main, Extension::Base, RowOrder::Natural, 1);
                let overlap_pre = transform(&pre, Extension::Base, RowOrder::Natural, 1);
                let overlap_perm = transform(&perm, Extension::Cubic, RowOrder::Natural, 1);
                let live = session
                    .plan_outputs(&[overlap_main.spec()])
                    .unwrap()
                    .live_bytes;
                let error = session
                    .quotient_cubic(
                        &prepared,
                        log_trace,
                        &overlap_main,
                        Some(&overlap_pre),
                        Some(&overlap_perm),
                        alpha_words,
                        &parameters,
                    )
                    .err()
                    .unwrap();
                assert!(error.contains("overlaps"), "{error}");
                assert_eq!(
                    session
                        .plan_outputs(&[overlap_main.spec()])
                        .unwrap()
                        .live_bytes,
                    live
                );
            }
        }
    }
    drop(prepared);
    shutdown().unwrap();
}
