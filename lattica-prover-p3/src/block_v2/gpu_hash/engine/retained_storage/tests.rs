use super::*;

fn host_quota(limit: usize) -> Arc<HostQuota> {
    HostQuota::new(Selection {
        mode: RetainedTreeStorageMode::HostBacking,
        host_bytes: limit,
    })
}

#[test]
fn host_tree_selection_preserves_default_and_rejects_ambiguous_limits() {
    assert_eq!(
        Selection::parse(None, None).unwrap(),
        Selection {
            mode: RetainedTreeStorageMode::Device,
            host_bytes: 0,
        }
    );
    assert_eq!(
        Selection::parse(Some("device"), None).unwrap(),
        Selection::parse(None, None).unwrap()
    );
    for (mode, host) in [
        (Some("other"), None),
        (None, Some("1")),
        (Some("device"), Some("0")),
        (Some("host"), None),
        (Some("host"), Some("0")),
        (Some("host"), Some("34359738369")),
        (Some("host"), Some("-1")),
        (Some("host"), Some("1GiB")),
    ] {
        assert!(Selection::parse(mode, host).is_err());
    }
    #[cfg(feature = "gpu")]
    assert_eq!(
        Selection::parse(Some("host"), Some("8589934592"))
            .unwrap()
            .host_bytes,
        8 << 30
    );
    #[cfg(not(feature = "gpu"))]
    assert!(Selection::parse(Some("host"), Some("8589934592")).is_err());
}

#[test]
fn host_tree_quota_accounts_simultaneous_reservations_and_moves() {
    let quota = host_quota(100);
    let first = quota.reserve(60).unwrap();
    let second = quota.reserve(40).unwrap();
    assert_eq!(quota.live(), 100);
    assert_eq!(quota.peak.load(Ordering::Relaxed), 100);
    assert_eq!(quota.trees.load(Ordering::Relaxed), 2);
    assert!(quota.reserve(1).is_err());
    assert!(quota.reserve(usize::MAX).is_err());
    let moved = [Some(first), Some(second)];
    assert_eq!(quota.live(), 100);
    drop(moved);
    assert_eq!(quota.live(), 0);
    assert_eq!(quota.trees.load(Ordering::Relaxed), 0);
    assert!(quota.reserve(0).is_err());
    assert!(HostQuota::new(Selection {
        mode: RetainedTreeStorageMode::Device,
        host_bytes: 0
    })
    .reserve(1)
    .is_err());
}

#[test]
fn host_tree_quota_cleans_up_during_unwind_and_concurrent_release() {
    let quota = host_quota(1024);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _one = quota.reserve(512).unwrap();
        let _two = quota.reserve(512).unwrap();
        panic!("injected host tree construction unwind");
    }));
    assert!(failed.is_err());
    assert_eq!(quota.live(), 0);
    let owned = quota.reserve(1024).unwrap();
    let worker = std::thread::spawn(move || drop(owned));
    worker.join().unwrap();
    assert_eq!(quota.live(), 0);
    assert_eq!(quota.trees.load(Ordering::Relaxed), 0);
    assert_eq!(quota.peak.load(Ordering::Relaxed), 1024);
}

#[test]
fn host_tree_backing_counts_cap_header_and_spare_capacity() {
    let layout = retained_layout(512, 6, usize::MAX).unwrap();
    let expected =
        layout.elements * 8 + layout.cap_rows * 32 + core::mem::size_of::<RetainedTree>();
    assert_eq!(host_charge(layout).unwrap(), expected);
    let quota = host_quota(expected);
    let reservation = quota.reserve(expected).unwrap();
    let mut words = Vec::new();
    words.try_reserve_exact(layout.elements).unwrap();
    words.resize(8, 0);
    let storage = Storage::Host(HostBacking {
        words,
        _reservation: reservation,
    });
    assert_eq!(storage.host_backing_bytes().unwrap(), layout.elements * 8);
    assert_eq!(quota.live(), expected);
    drop(storage);
    assert_eq!(quota.live(), 0);
    assert!(retained_layout(0, 6, usize::MAX).is_err());
    assert!(retained_layout(513, 6, usize::MAX).is_err());
    assert!(host_charge(RetainedLayout {
        elements: usize::MAX,
        cap_offset: 0,
        cap_rows: 1,
        path_len: 0
    })
    .is_err());
}

#[test]
fn cached_preprocessing_bound_adds_host_tree_without_reducing_other_storage() {
    use crate::block_v2::gpu_hash::cache_metadata::{bound_with_tree_storage, METADATA_BYTES};
    let device = Selection {
        mode: RetainedTreeStorageMode::Device,
        host_bytes: 0,
    };
    let host = Selection {
        mode: RetainedTreeStorageMode::HostBacking,
        host_bytes: 8 << 30,
    };
    for rows in [8, 1 << 18, 1 << 19] {
        let tree = host.charged_tree_bytes(rows * 32, 6).unwrap() as u64;
        assert_eq!(
            bound_with_tree_storage(rows as u64, true, device).unwrap(),
            METADATA_BYTES
        );
        assert_eq!(
            bound_with_tree_storage(rows as u64, true, host).unwrap(),
            METADATA_BYTES + tree
        );
        assert_eq!(
            bound_with_tree_storage(rows as u64, false, host).unwrap(),
            METADATA_BYTES + tree + rows as u64 * 1024
        );
    }
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires isolated OpenCL process, host tree storage, retained trees and query gather"]
fn gpu_host_tree_batch_preserves_paths_and_releases_upload_after_failure() {
    let limits = Limits {
        managed_bytes: 32 * MIB,
        tile_bytes: 64 * 1024,
        staging_bytes: 32 * 1024,
    };
    assert_eq!(
        Selection::from_env().unwrap().mode,
        RetainedTreeStorageMode::HostBacking
    );
    initialize_mode(limits, TransferMode::Serial).unwrap();
    struct Restore(Option<Engine>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(engine) = self.0.take() {
                *ENGINE.get().unwrap().lock().unwrap() = Some(engine);
                shutdown().unwrap();
            }
        }
    }
    let mut restore = Restore(ENGINE.get().unwrap().lock().unwrap().take());
    let engine = restore.0.as_mut().unwrap();
    let fill = |row: usize, values: &mut [u64]| {
        for (column, value) in values.iter_mut().enumerate() {
            *value = (row * 17 + column) as u64;
        }
    };
    let tree = engine.hash_rows_retained(512, 17, 6, fill).unwrap();
    assert!(matches!(&tree.storage, Storage::Host(_)));
    assert_eq!(engine.accounting.lock().unwrap().retained_live, 0);
    assert_eq!(
        engine.tree_storage.live(),
        host_charge(tree.layout).unwrap()
    );
    let reference = engine.hash_rows(512, 17, fill).unwrap();
    assert_eq!(tree.cap(), reference[tree.layout.path_len].as_slice());
    let indices: [usize; 128] = core::array::from_fn(|i| [511, 0, 17, 17, 255, 64, 511][i % 7]);
    // Establish the persistent bounded query buffer before before/after checks.
    let first = engine.open_retained(&tree, indices[0]).unwrap();
    let before = engine.snapshot();
    let count = engine.retained_query_count;
    let paths = engine.open_retained_batch(&tree, &indices).unwrap();
    let after = engine.snapshot();
    assert_eq!(paths[0], first);
    for (&index, path) in indices.iter().zip(&paths) {
        let expected: Vec<_> = reference[..tree.layout.path_len]
            .iter()
            .enumerate()
            .map(|(level, layer)| layer[(index >> level) ^ 1])
            .collect();
        assert_eq!(*path, expected);
    }
    assert_eq!(
        after.uploaded_bytes - before.uploaded_bytes,
        (tree.layout.elements * 8) as u64
    );
    assert_eq!(engine.retained_query_count - count, 128);
    assert_eq!(after.managed_live_bytes, before.managed_live_bytes);
    assert!(after.managed_peak_bytes <= limits.managed_bytes);
    for invalid in [&[][..], &[512][..]] {
        let before = engine.snapshot();
        assert!(engine.open_retained_batch(&tree, invalid).is_err());
        let after = engine.snapshot();
        assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
        assert_eq!(before.managed_live_bytes, after.managed_live_bytes);
    }
    let too_many = [0; 257];
    assert!(engine.open_retained_batch(&tree, &too_many).is_err());
    let before = engine.snapshot().managed_live_bytes;
    engine.fail_retained_query_after_enqueue = true;
    assert!(engine.open_retained_batch(&tree, &[255, 0]).is_err());
    assert_eq!(engine.snapshot().managed_live_bytes, before);
    assert_eq!(
        engine.tree_storage.live(),
        host_charge(tree.layout).unwrap()
    );
    assert_eq!(
        engine.open_retained_batch(&tree, &[indices[0]]).unwrap()[0],
        first
    );
    drop(tree);
    assert_eq!(engine.tree_storage.live(), 0);
    let short = engine.hash_rows_retained(8, 17, 6, fill).unwrap();
    let before = engine.snapshot();
    let count = engine.retained_query_count;
    assert_eq!(
        engine.open_retained_batch(&short, &[7, 0, 7, 3]).unwrap(),
        vec![Vec::<[Val; 4]>::new(); 4]
    );
    assert_eq!(engine.snapshot().uploaded_bytes, before.uploaded_bytes);
    assert_eq!(engine.retained_query_count, count);
    assert_eq!(
        engine.snapshot().managed_live_bytes,
        before.managed_live_bytes
    );
    drop(short);
    assert_eq!(engine.tree_storage.live(), 0);
    eprintln!("host_tree_batch_qualification queries=128 repeated_unsorted=true upload_batches=1 actual_gpu_gather=true query_failure_cleanup=true host_live_after_drop=0");
}

#[cfg(feature = "gpu")]
#[test]
#[ignore = "requires isolated OpenCL process with default device tree storage"]
fn device_tree_batch_preserves_scalar_paths_without_uploading() {
    let _shutdown = TestShutdownGuard;
    assert_eq!(
        Selection::from_env().unwrap().mode,
        RetainedTreeStorageMode::Device
    );
    initialize_mode(
        Limits {
            managed_bytes: 32 * MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        },
        TransferMode::Serial,
    )
    .unwrap();
    {
        let mut slot = ENGINE.get().unwrap().lock().unwrap();
        let engine = slot.as_mut().unwrap();
        let tree = engine
            .hash_rows_retained(512, 17, 6, |row, values| {
                for (column, value) in values.iter_mut().enumerate() {
                    *value = (row * 17 + column) as u64;
                }
            })
            .unwrap();
        assert!(matches!(&tree.storage, Storage::Device(_)));
        let indices: [usize; 128] = core::array::from_fn(|i| [511, 0, 17, 17, 255, 64, 511][i % 7]);
        let scalar: Vec<_> = indices
            .iter()
            .map(|&i| engine.open_retained(&tree, i).unwrap())
            .collect();
        let before = engine.snapshot();
        assert_eq!(engine.open_retained_batch(&tree, &indices).unwrap(), scalar);
        assert_eq!(engine.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            engine.snapshot().managed_live_bytes,
            before.managed_live_bytes
        );
        assert_eq!(engine.tree_storage.live(), 0);
        drop(tree);
    }
    shutdown().unwrap();
}
