use super::*;
use crate::{
    config::{MyCompress, MyHash, Val},
    cuda_compute::{Commitments, Limits},
    gpu_matrix::RowOrder,
};
use p3_field::PrimeField64;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rand::{RngExt, SeedableRng};

fn runtime(managed: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: managed / 2,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn spec(log_rows: u32) -> MatrixSpec {
    MatrixSpec::new(log_rows, 4, Extension::Base, RowOrder::BitReversed, 1).unwrap()
}
fn expected(rng: &mut ChaCha20Rng, count: usize) -> Vec<u64> {
    (0..count)
        .map(|_| rng.random::<Val>().as_canonical_u64())
        .collect()
}

#[test]
fn replay_geometry_and_workspace_share_the_existing_protocol_bounds() {
    for log in [0, 8, 18, 25] {
        let s = spec(log);
        validate_salt_replay_spec(s).unwrap();
        assert!(crate::gpu_random::salt_replay_workspace_bytes(s.words()).unwrap() > s.bytes());
    }
    for s in [
        MatrixSpec::new(8, 3, Extension::Base, RowOrder::BitReversed, 1).unwrap(),
        MatrixSpec::new(8, 4, Extension::Quadratic, RowOrder::BitReversed, 1).unwrap(),
        MatrixSpec::new(8, 4, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(8, 4, Extension::Base, RowOrder::BitReversed, 7).unwrap(),
        spec(26),
    ] {
        assert!(validate_salt_replay_spec(s).is_err());
    }
    for words in [0, usize::MAX] {
        assert!(crate::gpu_random::salt_replay_workspace_bytes(words).is_err());
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_salt_replay_preserves_original_draws_active_cursor_and_query_order() {
    let runtime = runtime(4 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    for log in [0, 8] {
        let s = spec(log);
        for start in [0, 15, (1u128 << 36) - 1] {
            let mut cpu = ChaCha20Rng::from_seed([73; 32]);
            cpu.set_stream(7);
            cpu.set_word_pos(start);
            let random = engine.import(cpu.clone()).unwrap();
            let before = runtime.snapshot();
            let recipes = random.prepare_salt_replay(s, 3).unwrap();
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
            assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
            assert_eq!(
                runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                24
            );
            let references: Vec<_> = (0..3).map(|_| expected(&mut cpu, s.words())).collect();
            assert_eq!(*random.0.position.lock().unwrap(), cpu.get_word_pos());
            assert_eq!(
                random
                    .sample_fields(257)
                    .unwrap()
                    .read_for_test(257 * 8)
                    .unwrap(),
                expected(&mut cpu, 257)
            );
            // Replays must not acquire the active cursor: this guard remains held.
            let active = random.0.position.lock().unwrap();
            let saved = *active;
            for (recipe, reference) in recipes.iter().zip(&references) {
                let before = runtime.snapshot();
                let samples = recipe.materialize().unwrap();
                assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
                assert_eq!(
                    runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                    8
                );
                assert_eq!(samples.read(s.bytes()).unwrap(), *reference);
                drop(samples);
                let indices = [
                    (s.rows() - 1) as u64,
                    0,
                    (s.rows() - 1) as u64,
                    (s.rows() / 2) as u64,
                ];
                let before = runtime.snapshot();
                let queried = recipe.query_rows(&indices, 128).unwrap();
                let wanted: Vec<_> = indices
                    .iter()
                    .flat_map(|&row| {
                        reference[row as usize * 4..row as usize * 4 + 4]
                            .iter()
                            .copied()
                    })
                    .collect();
                assert_eq!(queried, wanted);
                assert_eq!(
                    runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
                    32
                );
                assert_eq!(
                    runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                    8 + 128
                );
                assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
                assert_eq!(*active, saved);
            }
            drop(active);
            drop(recipes);
            assert_eq!(engine.states.load(Ordering::Acquire), 1);
        }
    }
    assert_eq!(engine.states.load(Ordering::Acquire), 0);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_salt_recipe_batch_is_atomic_and_replays_can_run_concurrently() {
    let runtime = runtime(4 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let random = engine.import(ChaCha20Rng::from_seed([79; 32])).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let (recipes, other) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            random.prepare_salt_replay(spec(2), 3).unwrap()
        });
        let b = scope.spawn(|| {
            barrier.wait();
            random.sample_fields(7).unwrap()
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    let first = recipes[0].start;
    assert!(first == 0 || first == 14);
    for (i, recipe) in recipes.iter().enumerate() {
        assert_eq!(recipe.start, first + i as u128 * 32);
        assert_eq!(recipe.end, recipe.start + 32);
    }
    assert_eq!(*random.0.position.lock().unwrap(), 110);
    let mut cpu = ChaCha20Rng::from_seed([79; 32]);
    cpu.set_word_pos(if first == 0 { 96 } else { 0 });
    assert_eq!(other.read_for_test(56).unwrap(), expected(&mut cpu, 7));
    let (a, b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| recipes[1].query_rows(&[3, 0, 3], 96).unwrap());
        let b = scope.spawn(|| recipes[1].query_rows(&[3, 0, 3], 96).unwrap());
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(a, b);
    cpu.set_word_pos(recipes[1].start);
    let reference = expected(&mut cpu, 16);
    assert_eq!(
        a,
        [
            reference[12..16].to_vec(),
            reference[0..4].to_vec(),
            reference[12..16].to_vec()
        ]
        .concat()
    );
    assert_eq!(*random.0.position.lock().unwrap(), 110);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_salt_replay_remains_available_at_the_original_stream_end() {
    let runtime = runtime(4 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let s = spec(4);
    let mut cpu = ChaCha20Rng::from_seed([107; 32]);
    cpu.set_stream(u64::MAX);
    cpu.set_word_pos(STREAM_WORDS - s.words() as u128 * 2);
    let random = engine.import(cpu.clone()).unwrap();
    let (salts, recipe) = random.sample_salt_with_replay(s).unwrap();
    let reference = expected(&mut cpu, s.words());
    assert_eq!(salts.read(s.bytes()).unwrap(), reference);
    drop(salts);
    assert_eq!(recipe.end, STREAM_WORDS);
    let before = runtime.snapshot();
    assert!(random.sample_fields(1).is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(
        recipe.materialize().unwrap().read(s.bytes()).unwrap(),
        reference
    );
    assert_eq!(*random.0.position.lock().unwrap(), STREAM_WORDS);
    assert_eq!(format!("{recipe:?}"), "CudaReplaySalts(<redacted>)");
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_salt_replay_metadata_and_workspace_admission_precede_consumption() {
    let runtime = runtime(64 << 10);
    let engine = Randoms::new(&runtime).unwrap();
    let random = engine.import(ChaCha20Rng::from_seed([83; 32])).unwrap();
    let s = spec(8);
    let before = runtime.snapshot();
    for count in [0, MAX_REPLAY_MATRICES + 1, usize::MAX] {
        assert!(random.prepare_salt_replay(s, count).is_err());
    }
    assert!(random.prepare_salt_replay(spec(12), 1).is_err());
    assert!(random
        .preflight_salt_replay(&[s.words()], &[usize::MAX])
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(*random.0.position.lock().unwrap(), 0);
    // A partially reserved recipe batch rolls back without drawing any fields.
    engine
        .states
        .store(MAX_STREAM_STATES - 1, Ordering::Release);
    assert!(random.prepare_salt_replay(s, 2).is_err());
    assert_eq!(engine.states.load(Ordering::Acquire), MAX_STREAM_STATES - 1);
    engine.states.store(1, Ordering::Release);
    assert_eq!(runtime.snapshot(), before);
    let recipes = random.prepare_salt_replay(s, MAX_REPLAY_MATRICES).unwrap();
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert!(runtime.snapshot().peak_bytes <= 64 << 10);
    assert_eq!(
        engine.states.load(Ordering::Acquire),
        1 + MAX_REPLAY_MATRICES
    );
    let position = *random.0.position.lock().unwrap();
    let before = runtime.snapshot();
    for indices in [vec![s.rows() as u64], vec![0; MAX_QUERIES + 1]] {
        assert!(recipes[0].query_rows(&indices, usize::MAX).is_err());
    }
    assert!(recipes[0].query_rows(&[0], 31).is_err());
    assert!(recipes[0].query_rows(&[], 0).unwrap().is_empty());
    assert_eq!(runtime.snapshot(), before);
    let mut filler = Vec::new();
    while runtime.snapshot().live_bytes < 64 << 10 {
        let words = ((64 << 10) - runtime.snapshot().live_bytes) / 8;
        filler.push(runtime.allocate(words.min(4096)).unwrap());
    }
    let before = runtime.snapshot();
    assert!(recipes[0].materialize().is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(*random.0.position.lock().unwrap(), position);
    random.check_live().unwrap();
    drop(filler);
    assert!(recipes[0].query_rows(&[0], 32).is_ok());
    drop(recipes);
    assert_eq!(engine.states.load(Ordering::Acquire), 1);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_salt_replay_faults_and_downstream_failures_retire_the_whole_group() {
    let runtime = runtime(4 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    for mode in 0..7 {
        let failure = Arc::new(AtomicBool::new(false));
        let random = engine
            .import_shared(ChaCha20Rng::from_seed([89; 32]), failure.clone())
            .unwrap();
        let sibling = engine
            .import_shared(ChaCha20Rng::from_seed([91; 32]), failure)
            .unwrap();
        let (samples, mut recipe) = random.sample_salt_with_replay(spec(4)).unwrap();
        drop(samples);
        let position = *random.0.position.lock().unwrap();
        match mode {
            0 => assert!(recipe.materialize_with_fault(Fault::AfterBatch).is_err()),
            1 => assert!(recipe.materialize_with_fault(Fault::InvalidStatus).is_err()),
            2 => assert!(recipe.materialize_with_fault(Fault::RejectAll).is_err()),
            3 => assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || recipe.materialize_with_fault(Fault::PanicAfterBatch)
            ))
            .is_err()),
            4 => {
                recipe.end += 2;
                assert!(recipe.materialize().is_err());
            }
            5 => assert!(recipe
                .with_materialized::<()>(|_| Err("injected consumer failure".into()))
                .is_err()),
            6 => assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || recipe.with_materialized::<()>(|_| panic!("injected consumer unwind"))
            ))
            .is_err()),
            _ => unreachable!(),
        }
        assert_eq!(*random.0.position.lock().unwrap(), position);
        let before = runtime.snapshot();
        assert!(random.sample_fields(1).is_err());
        assert!(sibling.sample_fields(1).is_err());
        assert!(recipe.materialize().is_err());
        assert!(recipe.query_rows(&[], 0).is_err());
        assert_eq!(runtime.snapshot(), before);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_replayed_salts_commit_and_open_against_independent_cpu_merkle_oracles() {
    let runtime = runtime(4 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let commits = Commitments::new(&runtime).unwrap();
    for (extension, shift) in [
        (Extension::Base, 1),
        (Extension::Base, 7),
        (Extension::Quadratic, 7),
        (Extension::Cubic, 7),
        (Extension::Cubic, 13),
    ] {
        let input_spec = MatrixSpec::new(5, 3, extension, RowOrder::BitReversed, shift).unwrap();
        let input_words: Vec<_> = (0..input_spec.words()).map(|i| i as u64 * 17 + 7).collect();
        let input = runtime.upload_matrix(input_spec, &input_words).unwrap();
        let mut cpu = ChaCha20Rng::from_seed([97; 32]);
        cpu.set_word_pos(15);
        let random = engine.import(cpu.clone()).unwrap();
        let (salts, recipe) = random.sample_salt_with_replay(spec(5)).unwrap();
        let original_salts = Matrix {
            spec: MatrixSpec::new(5, 4, Extension::Base, RowOrder::BitReversed, shift).unwrap(),
            buffer: salts.buffer.clone(),
        };
        let original = commits.commit_salted(&input, &original_salts, 0).unwrap();
        drop((salts, original_salts));
        let before = runtime.snapshot();
        let replayed = commits.commit_replayed(&input, &recipe, 0).unwrap();
        assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            8
        );
        let salt_words = expected(&mut cpu, 128);
        let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
        let hash = MyHash::new(permutation.clone());
        let compress = MyCompress::new(permutation);
        let mut layer: Vec<[Val; 4]> = input_words
            .chunks_exact(3 * extension.degree())
            .zip(salt_words.chunks_exact(4))
            .map(|(a, b)| hash.hash_iter(a.iter().chain(b).copied().map(Val::new)))
            .collect();
        let indices = [31, 0, 31, 17];
        let mut expected_paths = vec![Vec::new(); indices.len()];
        let mut query_indices = indices;
        while layer.len() > 1 {
            for (i, row) in query_indices.iter_mut().enumerate() {
                expected_paths[i].extend(
                    layer[(*row ^ 1) as usize]
                        .iter()
                        .map(PrimeField64::as_canonical_u64),
                );
                *row /= 2;
            }
            layer = layer
                .chunks_exact(2)
                .map(|pair| compress.compress([pair[0], pair[1]]))
                .collect();
        }
        let root: Vec<_> = layer[0]
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect();
        assert_eq!(original.cap(32).unwrap(), root);
        assert_eq!(replayed.cap(32).unwrap(), root);
        assert_eq!(
            commits.open(&replayed, &indices, 4 * 5 * 4 * 8).unwrap(),
            expected_paths.concat()
        );
        assert_eq!(
            recipe.query_rows(&indices, 128).unwrap(),
            indices
                .iter()
                .flat_map(|&r| salt_words[r as usize * 4..r as usize * 4 + 4]
                    .iter()
                    .copied())
                .collect::<Vec<_>>()
        );
        assert_eq!(*random.0.position.lock().unwrap(), cpu.get_word_pos());
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_replayed_commitment_admits_hashing_peak_before_private_replay() {
    let runtime = runtime(64 << 10);
    let engine = Randoms::new(&runtime).unwrap();
    let commits = Commitments::new(&runtime).unwrap();
    let random = engine.import(ChaCha20Rng::from_seed([101; 32])).unwrap();
    let s = spec(8);
    let input_spec = MatrixSpec::new(8, 1, Extension::Base, RowOrder::BitReversed, 1).unwrap();
    let input = runtime
        .upload_matrix(input_spec, &vec![7; input_spec.words()])
        .unwrap();
    let (salts, recipe) = random.sample_salt_with_replay(s).unwrap();
    drop(salts);
    // Leave room for sampling (~16 KiB), but not salts + tree + sponge (~40 KiB).
    let filler = runtime.allocate(24 << 10 >> 3).unwrap();
    recipe.preflight(&[]).unwrap();
    let before = runtime.snapshot();
    assert!(commits.commit_replayed(&input, &recipe, 0).is_err());
    assert_eq!(runtime.snapshot(), before);
    random.check_live().unwrap();
    drop(filler);
    assert!(commits.commit_replayed(&input, &recipe, 0).is_ok());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_salt_query_gather_covers_multiple_blocks_and_the_query_limit() {
    let runtime = runtime(4 << 20);
    let engine = Randoms::new(&runtime).unwrap();
    let mut cpu = ChaCha20Rng::from_seed([127; 32]);
    let random = engine.import(cpu.clone()).unwrap();
    let (salts, recipe) = random.sample_salt_with_replay(spec(8)).unwrap();
    drop(salts);
    let reference = expected(&mut cpu, 1024);
    for count in [1, 31, 32, 33, MAX_QUERIES] {
        let indices: Vec<_> = (0..count).map(|i| (i * 97 % 256) as u64).collect();
        let wanted: Vec<_> = indices
            .iter()
            .flat_map(|&row| {
                reference[row as usize * 4..row as usize * 4 + 4]
                    .iter()
                    .copied()
            })
            .collect();
        let before = runtime.snapshot();
        assert_eq!(recipe.query_rows(&indices, count * 32).unwrap(), wanted);
        let after = runtime.snapshot();
        assert_eq!(
            after.uploaded_bytes - before.uploaded_bytes,
            count as u64 * 8
        );
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            8 + count as u64 * 32
        );
        assert_eq!(after.live_bytes, before.live_bytes);
        assert_eq!(after.allocations, before.allocations);
        assert_eq!(*random.0.position.lock().unwrap(), cpu.get_word_pos());
    }
}
