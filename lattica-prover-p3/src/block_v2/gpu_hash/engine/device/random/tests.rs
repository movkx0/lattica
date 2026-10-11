use super::*;
use p3_field::PrimeField64;
use rand::{RngExt, SeedableRng};

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_random_snapshots_copy_positions_without_copying_or_reading_device_keys() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    for position in [0, 15, (1u128 << 36) - 1] {
        let mut cpu = ChaCha20Rng::from_seed([97; 32]);
        cpu.set_stream(7);
        cpu.set_word_pos(position);
        let gpu = session.import_random_stream(cpu.clone()).unwrap();
        let expected: Vec<_> = (0..19)
            .map(|_| cpu.random::<Val>().as_canonical_u64())
            .collect();
        assert_eq!(
            gpu.sample_fields(19)
                .unwrap()
                .read_for_test(19 * 8)
                .unwrap(),
            expected
        );
        let before = session.stats();
        let snapshot = gpu.snapshot().unwrap();
        let mut cpu_snapshot = cpu.clone();
        assert_eq!(session.stats(), before);
        assert!(Arc::ptr_eq(&gpu.0.seed, &snapshot.0.seed));
        assert!(!Arc::ptr_eq(&gpu.0, &snapshot.0));
        let shared = gpu.clone();
        for stream in [&gpu, &shared] {
            let expected: Vec<_> = (0..37)
                .map(|_| cpu.random::<Val>().as_canonical_u64())
                .collect();
            assert_eq!(
                stream
                    .sample_fields(37)
                    .unwrap()
                    .read_for_test(37 * 8)
                    .unwrap(),
                expected
            );
        }
        // The snapshot preserves the earlier position and survives all original
        // handles, whose drop must not scrub the shared immutable key early.
        drop((gpu, shared));
        let expected: Vec<_> = (0..257)
            .map(|_| cpu_snapshot.random::<Val>().as_canonical_u64())
            .collect();
        assert_eq!(
            snapshot
                .sample_fields(257)
                .unwrap()
                .read_for_test(257 * 8)
                .unwrap(),
            expected
        );
    }
    let gpu = session
        .import_random_stream(ChaCha20Rng::from_seed([99; 32]))
        .unwrap();
    let independent = gpu.snapshot().unwrap();
    assert!(gpu.sample_fields_inner(257, Some(1)).is_err());
    let before = session.stats();
    assert!(gpu.clone().snapshot().is_err());
    assert_eq!(session.stats(), before);
    assert!(independent.sample_fields(1).is_ok());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_public_salts_match_fixed_reference_stream_and_reuse_only_public_storage() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let stream = session.public_preprocessing_salt_stream().unwrap();
    let mut cpu = ChaCha20Rng::from_seed([0; 32]);
    let before = session.stats();
    for (height, count) in [(0, 1), (3, 1), (1 << 26, 1), (8, 0), (8, 257), (1 << 24, 1)] {
        assert!(stream.generate(height, count).is_err());
    }
    assert!(stream.preflight(8, 1, &[usize::MAX]).is_err());
    assert_eq!(session.stats(), before);
    let shared = stream.clone();
    for (height, count) in [(1usize, 1usize), (2, 3), (256, 2), (16384, 3)] {
        let before = session.stats();
        let matrices = shared.generate(height, count).unwrap();
        let after = session.stats();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            after.random_status_bytes - before.random_status_bytes
        );
        let next_session = DeviceSession::new().unwrap();
        for public in &matrices {
            let expected: Vec<_> = (0..height * 4)
                .map(|_| cpu.random::<Val>().as_canonical_u64())
                .collect();
            let alias = next_session.import_public_salts(public).unwrap();
            assert_eq!(
                next_session.read(&alias, public.spec().bytes()).unwrap(),
                expected
            );
            assert!(session.alias_private(&alias).is_err());
            // Even a trusted public salt alias cannot be recast as a trace.
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                alias.into_public_preprocessing();
            }))
            .is_err());
        }
    }
    let before = session.stats();
    let snapshot = stream.snapshot().unwrap();
    assert_eq!(session.stats(), before);
    let mut fork_cpu = cpu.clone();
    let original = stream.generate(8, 2).unwrap();
    drop((original, stream, shared));
    let fork = snapshot.generate(8, 2).unwrap();
    for public in fork {
        let expected: Vec<_> = (0..32)
            .map(|_| fork_cpu.random::<Val>().as_canonical_u64())
            .collect();
        let imported = session.import_public_salts(&public).unwrap();
        let raw = imported.storage.buffer.clone();
        drop(public);
        assert_eq!(session.read(&imported, 256).unwrap(), expected);
        drop(imported);
        session
            .with_engine(|engine| {
                let mut words = vec![1u64; 32];
                let fence = engine.fence();
                raw.read(&mut words).enq().map_err(|e| e.to_string())?;
                fence.finish()?;
                assert!(words.iter().all(|&n| n == 0));
                Ok(())
            })
            .unwrap();
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_random_matrices_retain_secret_cleanup_until_the_last_alias() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let random = session
        .import_random_stream(ChaCha20Rng::from_seed([93; 32]))
        .unwrap();
    let seeded = super::super::super::report("random matrix seeded").unwrap();
    let stats = session.stats();
    for spec in [
        MatrixSpec::new(3, 1, Extension::Cubic, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(26, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(3, 4097, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(24, 4, Extension::Base, RowOrder::Natural, 1).unwrap(),
    ] {
        assert!(random.sample_matrix(spec).is_err());
    }
    assert_eq!(random.0.cursor.lock().unwrap().position, 0);
    assert_eq!(session.stats(), stats);
    let spec = MatrixSpec::new(3, 7, Extension::Base, RowOrder::Natural, 1).unwrap();
    let matrix = random.sample_matrix(spec).unwrap();
    let alias = session.alias_private(&matrix).unwrap();
    let expected = session.read(&matrix, spec.bytes()).unwrap();
    assert!(expected.iter().any(|&n| n != 0));
    // Test-only raw handle lets us observe the scrub after the last typed owner
    // has gone. Production code cannot escape its allocation guard this way.
    let raw = matrix.storage.buffer.clone();
    drop(matrix);
    assert_eq!(session.read(&alias, spec.bytes()).unwrap(), expected);
    let rejected = session.alias_private(&alias).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rejected.into_public_preprocessing();
    }))
    .is_err());
    assert_eq!(session.read(&alias, spec.bytes()).unwrap(), expected);
    drop(alias);
    assert_eq!(
        super::super::super::report("random matrix released")
            .unwrap()
            .device_matrix_live_bytes,
        seeded.device_matrix_live_bytes
    );
    session
        .with_engine(|engine| {
            let mut words = vec![1u64; spec.words()];
            let fence = engine.fence();
            raw.read(&mut words).enq().map_err(|e| e.to_string())?;
            fence.finish()?;
            assert!(words.iter().all(|&n| n == 0));
            Ok(())
        })
        .unwrap();
}

#[test]
fn random_plan_covers_offset_scratch_and_rejects_overflow_or_stream_wrap() {
    for count in [
        1,
        7,
        8,
        255,
        256,
        257,
        BATCH_WORDS - 1,
        BATCH_WORDS,
        BATCH_WORDS + 1,
        MAX_OUTPUT_WORDS,
    ] {
        for position in [0, 1, 15, 63, 1 << 40, STREAM_WORDS - 2 * count as u128] {
            let p = Plan::new(count, position, 4096, usize::MAX, usize::MAX).unwrap();
            assert_eq!(p.output_words, count);
            assert_eq!(p.batch_words, count.min(BATCH_WORDS));
            assert!(p.tiles * TILE_WORDS >= p.batch_words);
            assert!(p.raw_words * 2 >= p.batch_words * 2 + 15);
            assert_eq!(
                p.peak_bytes,
                4096 + 8 * (count + p.raw_words + 2 * p.tiles + 1)
            );
            assert!(Plan::new(count, position, 4096, p.peak_bytes - 1, usize::MAX).is_err());
            assert!(Plan::new(
                count,
                position,
                4096,
                usize::MAX,
                count.max(p.raw_words) * 8 - 1
            )
            .is_err());
        }
    }
    for (count, position) in [
        (0, 0),
        (MAX_OUTPUT_WORDS + 1, 0),
        (usize::MAX, 0),
        (1, STREAM_WORDS),
        (1, STREAM_WORDS - 1),
        (1, u128::MAX),
    ] {
        assert!(Plan::new(count, position, 0, usize::MAX, usize::MAX).is_err());
    }
    assert!(Plan::new(1, 0, usize::MAX, usize::MAX, usize::MAX).is_err());
}

#[cfg(feature = "gpu")]
fn initialize() {
    super::super::super::initialize_mode(
        super::super::super::Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 8 << 20,
        },
        super::super::super::TransferMode::Serial,
    )
    .unwrap();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_random_streams_match_chacha_fields_positions_and_shared_clones() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    for seed in [[0; 32], [255; 32], core::array::from_fn(|i| i as u8)] {
        for stream in [0, 7, u64::MAX] {
            for position in [0, 1, 15, 63, 64, (1 << 36) - 1, STREAM_WORDS - 2048] {
                let mut cpu = ChaCha20Rng::from_seed(seed);
                cpu.set_stream(stream);
                cpu.set_word_pos(position);
                let gpu = session.import_random_stream(cpu.clone()).unwrap();
                assert_eq!(format!("{gpu:?}"), "DeviceRandom(<redacted>)");
                let shared = gpu.clone();
                for (i, count) in [1, 3, 7, 129, 257].into_iter().enumerate() {
                    let before = session.stats();
                    let samples = if i % 2 == 0 { &gpu } else { &shared }
                        .sample_fields(count)
                        .unwrap();
                    let after = session.stats();
                    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                    assert_eq!(
                        after.downloaded_bytes - before.downloaded_bytes,
                        after.random_status_bytes - before.random_status_bytes
                    );
                    assert_eq!(after.random_fields - before.random_fields, count as u64);
                    let expected: Vec<_> = (0..count)
                        .map(|_| cpu.random::<Val>().as_canonical_u64())
                        .collect();
                    assert!(samples.read_for_test(count * 8).unwrap() == expected);
                    assert_eq!(gpu.0.cursor.lock().unwrap().position, cpu.get_word_pos());
                }
            }
        }
    }
    let mut cpu = ChaCha20Rng::from_seed([39; 32]);
    cpu.set_word_pos(15);
    let gpu = session.import_random_stream(cpu.clone()).unwrap();
    let count = BATCH_WORDS + 257;
    let samples = gpu.sample_fields(count).unwrap();
    let expected: Vec<_> = (0..count)
        .map(|_| cpu.random::<Val>().as_canonical_u64())
        .collect();
    assert!(samples.read_for_test(count * 8).unwrap() == expected);
    assert_eq!(gpu.0.cursor.lock().unwrap().position, cpu.get_word_pos());
}

struct Scripted<'a> {
    values: std::slice::Iter<'a, u64>,
}
impl rand::TryRng for Scripted<'_> {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("field reference uses u64")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(*self.values.next().unwrap())
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        panic!("field reference uses u64")
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_random_rejection_compaction_preserves_reference_order_and_scrubs_secrets() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    for count in [1usize, 255, 256, 257, 4097] {
        for offset in [0u32, 1, 15] {
            for all_rejected in [false, true] {
                let candidates: Vec<_> = (0..count)
                    .map(|i| {
                        if all_rejected {
                            GOLDILOCKS_MODULUS
                        } else {
                            [
                                0,
                                GOLDILOCKS_MODULUS - 1,
                                GOLDILOCKS_MODULUS,
                                GOLDILOCKS_MODULUS + 1,
                                u64::MAX,
                                1,
                            ][i % 6]
                        }
                    })
                    .collect();
                let accepted = candidates
                    .iter()
                    .filter(|&&n| n < GOLDILOCKS_MODULUS)
                    .count();
                let mut cpu = Scripted {
                    values: candidates.iter(),
                };
                let expected: Vec<_> = (0..accepted)
                    .map(|_| cpu.random::<Val>().as_canonical_u64())
                    .collect();
                session
                    .with_engine(|engine| {
                        let plan = Plan::new(
                            count,
                            0,
                            engine.accounting.lock().unwrap().live,
                            engine.limits.managed_bytes,
                            engine.max_alloc,
                        )?;
                        let raw = SecretAllocation::new(engine, plan.raw_words)?;
                        let counts = SecretAllocation::new(engine, plan.tiles)?;
                        let offsets = SecretAllocation::new(engine, plan.tiles)?;
                        let total = SecretAllocation::new(engine, 1)?;
                        let output = RandomWords {
                            storage: SecretAllocation::new(engine, count)?,
                            session: session.clone(),
                            count,
                        };
                        let mut words = vec![0u64; plan.raw_words];
                        for (i, &n) in candidates.iter().enumerate() {
                            for (j, word) in [n as u32, (n >> 32) as u32].into_iter().enumerate() {
                                let at = offset as usize + 2 * i + j;
                                words[at / 2] |= u64::from(word) << (32 * (at % 2));
                            }
                        }
                        let fence = engine.fence();
                        raw.buffer()
                            .write(&words[..])
                            .enq()
                            .map_err(|e| e.to_string())?;
                        output
                            .buffer()
                            .cmd()
                            .fill(9u64, None)
                            .enq()
                            .map_err(|e| e.to_string())?;
                        let (n, _) = compact(
                            engine, &raw, &counts, &offsets, &total, &output, offset, count, 0,
                        )?;
                        assert_eq!(n, accepted);
                        let mut actual = vec![0u64; count];
                        output
                            .buffer()
                            .read(&mut actual[..])
                            .enq()
                            .map_err(|e| e.to_string())?;
                        fence.finish()?;
                        assert_eq!(&actual[..accepted], &expected);
                        assert!(actual[accepted..].iter().all(|&n| n == 9));
                        output.storage.scrub();
                        output
                            .buffer()
                            .read(&mut actual[..])
                            .enq()
                            .map_err(|e| e.to_string())?;
                        fence.finish()?;
                        assert!(actual.iter().all(|&n| n == 0));
                        Ok(())
                    })
                    .unwrap();
            }
        }
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_random_admission_retires_failed_streams_and_releases_private_storage() {
    use super::super::super::report;
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = report("random before streams").unwrap();
    let gpu = session
        .import_random_stream(ChaCha20Rng::from_seed([55; 32]))
        .unwrap();
    let shared = gpu.clone();
    let seeded = report("random seeded").unwrap();
    let stats = session.stats();
    for count in [0, MAX_OUTPUT_WORDS + 1, 1 << 27] {
        assert!(gpu.sample_fields(count).is_err());
        assert_eq!(gpu.0.cursor.lock().unwrap().position, 0);
    }
    assert_eq!(session.stats(), stats);
    let samples = shared.sample_fields(17).unwrap();
    assert!(samples
        .check_session(&DeviceSession::new().unwrap())
        .is_err());
    assert!(samples.read_for_test(17 * 8 - 1).is_err());
    drop(samples);
    assert_eq!(
        report("random samples released")
            .unwrap()
            .device_matrix_live_bytes,
        seeded.device_matrix_live_bytes
    );
    assert!(gpu.sample_fields_inner(257, Some(1)).is_err());
    assert!(gpu.0.cursor.lock().unwrap().poisoned);
    let failed = session.stats();
    assert!(shared.sample_fields(1).is_err());
    assert_eq!(session.stats(), failed);
    assert_eq!(
        report("random failure released")
            .unwrap()
            .device_matrix_live_bytes,
        seeded.device_matrix_live_bytes
    );
    drop((gpu, shared));
    assert_eq!(
        report("random stream released")
            .unwrap()
            .device_matrix_live_bytes,
        baseline.device_matrix_live_bytes
    );
    let mut cpu = ChaCha20Rng::from_seed([31; 32]);
    cpu.set_word_pos(STREAM_WORDS - 2);
    let gpu = session.import_random_stream(cpu.clone()).unwrap();
    let expected = cpu.random::<Val>().as_canonical_u64();
    let words = gpu.sample_fields(1).unwrap();
    assert_eq!(words.read_for_test(8).unwrap(), vec![expected]);
    assert_eq!(gpu.0.cursor.lock().unwrap().position, STREAM_WORDS);
    let exhausted = session.stats();
    assert!(gpu.sample_fields(1).is_err());
    assert_eq!(session.stats(), exhausted);
}
