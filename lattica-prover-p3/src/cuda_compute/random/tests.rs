use super::*;
use crate::{
    config::{MyCompress, MyHash, Val},
    cuda_compute::{Commitments, Limits},
    gpu_matrix::{RowOrder, GOLDILOCKS_MODULUS as P},
    gpu_random::MAX_OUTPUT_WORDS,
};
use p3_field::PrimeField64;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rand::{Rng, RngExt, SeedableRng};

mod benchmark;

fn runtime(managed: usize, allocation: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: allocation,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn expected(rng: &mut ChaCha20Rng, count: usize) -> Vec<u64> {
    (0..count)
        .map(|_| rng.random::<Val>().as_canonical_u64())
        .collect()
}
fn read(buffer: &Buffer) -> Vec<u64> {
    let mut values = vec![0; buffer.len()];
    buffer.read(0, &mut values).unwrap();
    values
}

#[test]
fn random_bounds_and_consumed_host_rng_wipe_are_explicit() {
    let plan = Plan::new(8, 15, 0, 216, 128).unwrap();
    assert_eq!(plan.peak_bytes, 216);
    assert_eq!(plan.raw_words, 16);
    assert!(Plan::new(8, 15, 0, 215, 128).is_err());
    assert!(Plan::new(8, 15, 0, 216, 127).is_err());
    for (count, position) in [
        (0, 0),
        (MAX_OUTPUT_WORDS + 1, 0),
        (usize::MAX, 0),
        (1, STREAM_WORDS),
        (1, STREAM_WORDS + 1),
    ] {
        assert!(Plan::new(count, position, 0, usize::MAX, usize::MAX).is_err());
    }
    assert!(Plan::new(1, STREAM_WORDS - 2, 0, 216, 128).is_ok());
    assert_eq!(accepted_words(0, 17).unwrap(), 0);
    assert_eq!(accepted_words(17, 17).unwrap(), 17);
    assert!(accepted_words(18, 17).is_err());
    let mut rng = ChaCha20Rng::from_seed([97; 32]);
    rng.next_u64(); // Include populated host block backing in the wipe.
    let mut storage = ImportStorage(Box::new(std::mem::MaybeUninit::new(rng)));
    // SAFETY: the initialized RNG is dropped exactly once before its storage
    // is scrubbed. ImportStorage only owns bytes and never drops the RNG.
    unsafe { storage.0.assume_init_drop() };
    storage.scrub();
    // SAFETY: scrub initialized every byte, including padding; the allocation
    // remains live, and the dead RNG is never accessed as a typed value.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            storage.0.as_ptr().cast::<u8>(),
            std::mem::size_of::<ChaCha20Rng>(),
        )
    };
    assert!(bytes.iter().all(|&byte| byte == 0));
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_random_fields_match_rand_chacha_at_offsets_counters_and_batch_boundaries() {
    let runtime = runtime(32 << 20, 16 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    for seed in [0, 97] {
        for stream in [0, 17, u64::MAX] {
            for position in [0, 1, 15, (1u128 << 36) - 1, STREAM_WORDS - 514] {
                let mut cpu = ChaCha20Rng::from_seed([seed; 32]);
                cpu.set_stream(stream);
                cpu.set_word_pos(position);
                let before = runtime.snapshot();
                let gpu = engine.import(cpu.clone()).unwrap();
                assert_eq!(
                    runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
                    32
                );
                let before = runtime.snapshot();
                let values = gpu.sample_fields(257).unwrap();
                let after = runtime.snapshot();
                assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
                assert_eq!(
                    values.read_for_test(257 * 8).unwrap(),
                    expected(&mut cpu, 257)
                );
                assert_eq!(*gpu.0.position.lock().unwrap(), position + 514);
                if position == STREAM_WORDS - 514 {
                    let before = runtime.snapshot();
                    assert!(gpu.sample_fields(1).is_err());
                    assert_eq!(runtime.snapshot(), before);
                }
            }
        }
    }
    let mut cpu = ChaCha20Rng::from_seed([59; 32]);
    cpu.set_word_pos(15);
    let gpu = engine.import(cpu.clone()).unwrap();
    let before = runtime.snapshot();
    let values = gpu.sample_fields(BATCH_WORDS + 17).unwrap();
    assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        16
    );
    assert_eq!(
        values.read_for_test((BATCH_WORDS + 17) * 8).unwrap(),
        expected(&mut cpu, BATCH_WORDS + 17)
    );
    assert_eq!(*gpu.0.position.lock().unwrap(), cpu.get_word_pos());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_random_compaction_preserves_dense_rejection_order_and_guards() {
    let runtime = runtime(32 << 20, 16 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    for count in [1, 127, 128, 129, 255, 256, 257, 4097, BATCH_WORDS] {
        for offset in [0usize, 1, 15] {
            let candidates: Vec<_> = (0..count)
                .map(|i| match i % 5 {
                    0 => P,
                    1 => u64::MAX,
                    2 => 0,
                    3 => P - 1,
                    _ => i as u64,
                })
                .collect();
            let mut packed = vec![0u64; (offset + count * 2).div_ceil(2)];
            for (i, &value) in candidates.iter().enumerate() {
                for (word, part) in [value as u32, (value >> 32) as u32].into_iter().enumerate() {
                    let at = offset + 2 * i + word;
                    packed[at / 2] |= (part as u64) << ((at % 2) * 32);
                }
            }
            let raw = runtime.allocate(packed.len()).unwrap();
            raw.write(0, &packed).unwrap();
            let counts = runtime.allocate(count.div_ceil(TILE_WORDS)).unwrap();
            let offsets = runtime.allocate(counts.len()).unwrap();
            let total = runtime.allocate(1).unwrap();
            let output = runtime.allocate(count + 2).unwrap();
            output.write(0, &vec![37; count + 2]).unwrap();
            let accepted = engine
                .compact(
                    &raw,
                    &counts,
                    &offsets,
                    &total,
                    &output,
                    offset as u32,
                    count,
                    1,
                )
                .unwrap();
            let expected: Vec<_> = candidates.into_iter().filter(|&v| v < P).collect();
            assert_eq!(accepted, expected.len());
            let values = read(&output);
            assert_eq!(&values[1..1 + accepted], expected);
            assert_eq!(values[0], 37);
            assert!(values[1 + accepted..].iter().all(|&v| v == 37));
            let before = runtime.snapshot();
            assert!(engine
                .compact(
                    &raw,
                    &counts,
                    &counts,
                    &total,
                    &output,
                    offset as u32,
                    count,
                    1
                )
                .is_err());
            assert_eq!(runtime.snapshot(), before);
        }
    }
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_random_clones_share_cursor_snapshots_share_key_and_failures() {
    let runtime = runtime(4 << 20, 2 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let mut cpu = ChaCha20Rng::from_seed([71; 32]);
    cpu.set_word_pos(15);
    cpu.set_stream(7);
    let gpu = engine.import(cpu.clone()).unwrap();
    let clone = gpu.clone();
    let before = runtime.snapshot();
    let snapshot = gpu.snapshot().unwrap();
    let mut snapshot_cpu = cpu.clone();
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(gpu.0.key.pointer(), snapshot.0.key.pointer());
    assert!(!Arc::ptr_eq(&gpu.0, &snapshot.0));
    assert!(Arc::ptr_eq(&gpu.0, &clone.0));
    for shared in [&gpu, &clone] {
        assert_eq!(
            shared
                .sample_fields(37)
                .unwrap()
                .read_for_test(296)
                .unwrap(),
            expected(&mut cpu, 37)
        );
    }
    drop((gpu, clone));
    assert_eq!(
        snapshot
            .sample_fields(257)
            .unwrap()
            .read_for_test(2056)
            .unwrap(),
        expected(&mut snapshot_cpu, 257)
    );
    assert_eq!(format!("{snapshot:?}"), "CudaRandom(<redacted>)");
    let sibling = snapshot.snapshot().unwrap();
    let before = runtime.snapshot();
    assert!(snapshot.sample(129, Fault::AfterBatch).is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert!(sibling.sample_fields(1).is_err());
    assert!(sibling.snapshot().is_err());
    let fresh = engine.import(ChaCha20Rng::from_seed([73; 32])).unwrap();
    assert!(fresh.sample_fields(1).is_ok());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_random_rejection_exhaustion_status_errors_and_unwind_retire_attempts() {
    let runtime = runtime(4 << 20, 2 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    for fault in [
        Fault::RejectAll,
        Fault::InvalidStatus,
        Fault::PanicAfterBatch,
    ] {
        let gpu = engine.import(ChaCha20Rng::from_seed([79; 32])).unwrap();
        let fork = gpu.snapshot().unwrap();
        let before = runtime.snapshot();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gpu.sample(129, fault)));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(runtime.snapshot().completed_commands > before.completed_commands);
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert!(fork.check_live().is_err());
        assert!(gpu.snapshot().is_err());
    }
    let mut last = ChaCha20Rng::from_seed([83; 32]);
    last.set_word_pos(STREAM_WORDS - 2);
    let gpu = engine.import(last).unwrap();
    assert!(gpu.sample(1, Fault::RejectAll).is_err());
    assert_eq!(*gpu.0.position.lock().unwrap(), STREAM_WORDS);
    assert!(gpu.check_live().is_err());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_random_preflight_and_stream_state_limits_reject_without_consumption() {
    let runtime = runtime(64 << 10, 32 << 10);
    let engine = Randoms::new(&runtime).unwrap();
    let gpu = engine.import(ChaCha20Rng::from_seed([89; 32])).unwrap();
    let before = runtime.snapshot();
    for count in [0, 4096, MAX_OUTPUT_WORDS + 1, usize::MAX] {
        assert!(gpu.sample_fields(count).is_err());
    }
    for spec in [
        MatrixSpec::new(1, 1, Extension::Quadratic, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(1, 1, Extension::Cubic, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(26, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(1, 4097, Extension::Base, RowOrder::Natural, 1).unwrap(),
    ] {
        assert!(gpu.sample_matrix(spec).is_err());
    }
    assert!(gpu.preflight_fields(&[], &[]).is_err());
    assert!(gpu.preflight_fields(&[8], &[usize::MAX]).is_err());
    assert!(gpu.preflight_fields(&[1; 513], &[]).is_err());
    assert!(gpu.preflight_fields(&[1], &[0; 513]).is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(*gpu.0.position.lock().unwrap(), 0);
    engine.states.store(MAX_STREAM_STATES, Ordering::Release);
    assert!(gpu.snapshot().is_err());
    assert!(engine.import(ChaCha20Rng::from_seed([91; 32])).is_err());
    assert_eq!(runtime.snapshot(), before);
    engine.states.store(1, Ordering::Release);
    let mut filler = Vec::new();
    while runtime.snapshot().live_bytes < 64 << 10 {
        let n = ((64 << 10) - runtime.snapshot().live_bytes) / 8;
        filler.push(runtime.allocate(n.min(4096)).unwrap());
    }
    let before = runtime.snapshot();
    assert!(gpu.sample_fields(1).is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(filler);
    assert!(gpu.sample_fields(1).is_ok());
    runtime.state.fail();
    assert!(gpu.sample_fields(1).is_err());
    assert!(gpu.snapshot().is_err());
}

#[test]
#[ignore = "requires CUDA and NVRTC; native salt generation/commitment, not complete hiding PCS"]
fn cuda_generated_private_salts_feed_commitments_without_sample_readback() {
    let runtime = runtime(4 << 20, 2 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let commits = Commitments::new(&runtime).unwrap();
    let mut cpu = ChaCha20Rng::from_seed([101; 32]);
    let gpu = engine.import(cpu.clone()).unwrap();
    let input_words: Vec<_> = (0..32 * 3).map(|i| i as u64 * 17 + 7).collect();
    let input = runtime
        .upload_matrix(
            MatrixSpec::new(5, 3, Extension::Base, RowOrder::Natural, 1).unwrap(),
            &input_words,
        )
        .unwrap();
    let before = runtime.snapshot();
    let salts = gpu
        .sample_matrix(MatrixSpec::new(5, 4, Extension::Base, RowOrder::Natural, 1).unwrap())
        .unwrap();
    let alias = salts.clone();
    let tree = commits.commit_salted(&input, &salts, 0).unwrap();
    assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        8
    );
    let expected_salts = expected(&mut cpu, 128);
    let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(permutation.clone());
    let compress = MyCompress::new(permutation);
    let mut layer: Vec<[Val; 4]> = input_words
        .chunks_exact(3)
        .zip(expected_salts.chunks_exact(4))
        .map(|(a, b)| hash.hash_iter(a.iter().chain(b).copied().map(Val::new)))
        .collect();
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|p| compress.compress([p[0], p[1]]))
            .collect();
    }
    assert_eq!(
        tree.cap(32).unwrap(),
        layer[0]
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect::<Vec<_>>()
    );
    let live = runtime.snapshot().live_bytes;
    drop(salts);
    assert_eq!(runtime.snapshot().live_bytes, live);
    assert_eq!(alias.read(128 * 8).unwrap(), expected_salts);
    drop(alias);
    assert_eq!(runtime.snapshot().live_bytes, live - 128 * 8);
}

#[test]
#[ignore = "requires pinned NVRTC but no GPU context"]
fn cuda_random_kernels_compile_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_random_batches_are_atomic_across_stream_aliases() {
    let runtime = runtime(4 << 20, 2 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let mut cpu = ChaCha20Rng::from_seed([37; 32]);
    let random = engine.import(cpu.clone()).unwrap();
    let requests = [257, 511, 17];
    let results = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..2)
            .map(|_| {
                let alias = random.clone();
                scope.spawn(move || {
                    alias
                        .sample_fields_batch(&requests, &[])
                        .unwrap()
                        .iter()
                        .flat_map(|s| s.read_for_test(s.len() * 8).unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        jobs.into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    let expected: Vec<Vec<u64>> = (0..2)
        .map(|_| {
            (0..requests.iter().sum::<usize>())
                .map(|_| cpu.random::<Val>().as_canonical_u64())
                .collect()
        })
        .collect();
    assert!(results == expected || results == [expected[1].clone(), expected[0].clone()]);
    assert_eq!(*random.0.position.lock().unwrap(), cpu.get_word_pos());
}
