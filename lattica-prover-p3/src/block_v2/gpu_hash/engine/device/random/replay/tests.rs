use super::*;
use crate::block_v2::gpu_hash::engine;
use p3_field::PrimeField64;
use rand::{RngExt, SeedableRng};

fn spec(log_rows: u32) -> MatrixSpec {
    MatrixSpec::new(log_rows, 4, Extension::Base, RowOrder::BitReversed, 1).unwrap()
}

#[test]
fn replay_geometry_and_workspace_are_bounded() {
    for log_rows in [0, 8, 18, 25] {
        let s = spec(log_rows);
        validate_spec(s).unwrap();
        assert!(salt_replay_workspace_bytes(s.words()).unwrap() > s.bytes());
    }
    for s in [
        MatrixSpec::new(8, 3, Extension::Base, RowOrder::BitReversed, 1).unwrap(),
        MatrixSpec::new(8, 4, Extension::Quadratic, RowOrder::BitReversed, 1).unwrap(),
        MatrixSpec::new(8, 4, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(8, 4, Extension::Base, RowOrder::BitReversed, 7).unwrap(),
    ] {
        assert!(validate_spec(s).is_err());
    }
    assert!(salt_replay_workspace_bytes(0).is_err());
    assert!(salt_replay_workspace_bytes(usize::MAX).is_err());
}

#[cfg(feature = "gpu")]
fn initialize() {
    engine::initialize_mode(
        engine::Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 8 << 20,
            staging_bytes: 1 << 20,
        },
        engine::TransferMode::Serial,
    )
    .unwrap();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_salt_replay_matches_cpu_and_preserves_the_active_stream() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let s = spec(8);
    for position in [0, 15, (1u128 << 36) - 1] {
        let mut cpu = ChaCha20Rng::from_seed([73; 32]);
        cpu.set_stream(7);
        cpu.set_word_pos(position);
        let random = session.import_random_stream(cpu.clone()).unwrap();
        let before = session.stats();
        let recipes = random.prepare_salt_replay(s, 3).unwrap();
        let after = session.stats();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            after.random_status_bytes - before.random_status_bytes
        );
        let expected: Vec<Vec<_>> = (0..3)
            .map(|_| {
                (0..s.words())
                    .map(|_| cpu.random::<Val>().as_canonical_u64())
                    .collect()
            })
            .collect();
        assert_eq!(random.0.cursor.lock().unwrap().position, cpu.get_word_pos());
        let next: Vec<_> = (0..257)
            .map(|_| cpu.random::<Val>().as_canonical_u64())
            .collect();
        assert_eq!(
            random
                .clone()
                .sample_fields(257)
                .unwrap()
                .read_for_test(257 * 8)
                .unwrap(),
            next
        );
        let end = random.0.cursor.lock().unwrap().position;
        for (recipe, values) in recipes.iter().zip(&expected) {
            // Holding the active cursor while replaying proves that replay
            // cannot depend on that cursor or invert its engine lock order.
            let _cursor = random.0.cursor.lock().unwrap();
            let matrix = recipe.materialize(&session).unwrap();
            assert_eq!(session.read(&matrix, s.bytes()).unwrap(), *values);
        }
        assert_eq!(random.0.cursor.lock().unwrap().position, end);
        drop(random);
        for (recipe, values) in recipes.iter().zip(&expected) {
            let matrix = recipe.materialize(&session).unwrap();
            assert_eq!(session.read(&matrix, s.bytes()).unwrap(), *values);
        }
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_salt_replay_retains_only_key_bytes_and_scrubs_outputs() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = engine::report("salt replay baseline").unwrap();
    let random = session
        .import_random_stream(ChaCha20Rng::from_seed([81; 32]))
        .unwrap();
    let seed_buffer = random.0.seed.buffer().clone();
    let seeded = engine::report("salt replay seed").unwrap();
    let s = spec(18);
    assert!(s.bytes() * 9 > 64 << 20);
    assert!(random.preflight_fields(&vec![s.words(); 9], &[]).is_err());
    let recipes = random.prepare_salt_replay(s, 9).unwrap();
    let retained = engine::report("salt replay nine recipes").unwrap();
    assert_eq!(retained.managed_live_bytes, seeded.managed_live_bytes);
    assert_eq!(
        retained.device_matrix_live_bytes,
        seeded.device_matrix_live_bytes
    );
    assert!(retained.managed_peak_bytes < 64 << 20);
    drop(random);
    for recipe in &recipes {
        let matrix = recipe.materialize(&session).unwrap();
        let buffer = matrix.storage.buffer.clone();
        let values = session
            .gather_rows(&matrix, &[0, s.rows() - 1], 1024)
            .unwrap();
        assert_eq!(values.len(), 8);
        drop(matrix);
        let mut wiped = vec![1u64; s.words()];
        buffer.read(&mut wiped[..]).enq().unwrap();
        session
            .with_engine(|engine| engine.pq.queue().finish().map_err(|e| e.to_string()))
            .unwrap();
        assert!(wiped.iter().all(|&v| v == 0));
        assert_eq!(
            engine::report("salt replay temporary released")
                .unwrap()
                .managed_live_bytes,
            seeded.managed_live_bytes
        );
    }
    drop(session);
    assert!(engine::shutdown().unwrap_err().contains("still live"));
    drop(recipes);
    let mut wiped_seed = [1u64; 4];
    seed_buffer.read(&mut wiped_seed[..]).enq().unwrap();
    // Blocking read above is ordered after the final owner's scrub and drain.
    assert_eq!(wiped_seed, [0; 4]);
    assert_eq!(
        engine::report("salt replay released")
            .unwrap()
            .managed_live_bytes,
        baseline.managed_live_bytes
    );
    drop(seed_buffer);
    engine::shutdown().unwrap();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_salt_replay_rejects_wrong_sessions_and_poisoned_records() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let random = session
        .import_random_stream(ChaCha20Rng::from_seed([83; 32]))
        .unwrap();
    let seeded = engine::report("salt replay failure seed")
        .unwrap()
        .managed_live_bytes;
    let s = spec(8);
    let before = session.stats();
    for count in [0, 257] {
        assert!(random.prepare_salt_replay(s, count).is_err());
    }
    assert_eq!(session.stats(), before);
    let mut recipes = random.prepare_salt_replay(s, 3).unwrap();
    let other = DeviceSession::new().unwrap();
    let before = session.stats();
    assert!(recipes[0].materialize(&other).is_err());
    assert_eq!(session.stats(), before);
    assert!(session
        .with_engine(|engine| recipes[0].materialize_inner(engine, Some(1)))
        .is_err());
    let failed = session.stats();
    assert!(recipes[0].materialize(&session).is_err());
    assert_eq!(session.stats(), failed);
    assert_eq!(
        engine::report("salt replay failure cleanup")
            .unwrap()
            .managed_live_bytes,
        seeded
    );
    // A consumption mismatch also fails without returning a partial matrix.
    recipes[1].end += 2;
    assert!(recipes[1].materialize(&session).is_err());
    let failed = session.stats();
    assert!(recipes[1].materialize(&session).is_err());
    assert_eq!(session.stats(), failed);
    assert_eq!(
        engine::report("salt replay mismatch cleanup")
            .unwrap()
            .managed_live_bytes,
        seeded
    );
    assert!(recipes[2].materialize(&session).is_ok());
    assert!(random.sample_fields(1).is_ok());
}
