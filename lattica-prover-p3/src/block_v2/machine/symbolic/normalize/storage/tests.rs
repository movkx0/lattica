use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[test]
fn exact_arrays_strings_and_arcs_admit_before_callbacks() {
    let arc = size_of::<u64>() + 4 * size_of::<usize>();
    let storage = Storage::limited(16 + 3 + arc, false);
    assert_eq!(storage.vector(2, |i| Ok(i as u64)).unwrap(), vec![0, 1]);
    assert_eq!(storage.string("bus").unwrap(), "bus");
    assert_eq!(*storage.arc(|| Ok(7u64)).unwrap(), 7);
    assert_eq!(storage.state.get().bytes, storage.limit);
    assert_eq!(storage.state.get().allocations, 3);
    let mut calls = 0;
    assert!(Storage::limited(15, false)
        .vector(2, |_| {
            calls += 1;
            Ok(0u64)
        })
        .is_err());
    assert!(Storage::limited(arc - 1, false)
        .arc(|| {
            calls += 1;
            Ok(0u64)
        })
        .is_err());
    assert_eq!(calls, 0);
    assert!(Storage::limited(2, false).string("bus").is_err());
}

#[test]
fn rejected_or_overflowed_storage_stays_failed_even_after_buffers_drop() {
    let storage = Storage::limited(16, false);
    let values = storage.vector(2, |_| Ok(0u64)).unwrap();
    drop(values);
    assert!(storage.single(0u64).is_err());
    assert!(storage.capacity::<u64>(0).is_err());
    assert!(storage.string("").is_err());
    assert_eq!(storage.state.get().bytes, 16);
    for count in [MAX_NODES + 1, usize::MAX] {
        let storage = Storage::new(false);
        let mut calls = 0;
        assert!(storage
            .vector(count, |_| {
                calls += 1;
                Ok(0u64)
            })
            .is_err());
        assert_eq!(calls, 0);
        assert!(storage.check().is_err());
    }
}

#[test]
fn traversal_growth_accounts_for_both_arrays_and_preserves_on_rejection() {
    let storage = Storage::limited(12 * size_of::<u64>(), false);
    let mut values = Vec::new();
    for i in 0..8 {
        storage.push(&mut values, i as u64).unwrap();
    }
    assert_eq!(storage.state.get().bytes, (4 + 8) * size_of::<u64>());
    assert_eq!(storage.state.get().allocations, 2);
    let pointer = values.as_ptr();
    assert!(storage.push(&mut values, 8).is_err());
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(values, (0..8).collect::<Vec<_>>());
}

#[test]
fn identity_map_handles_collisions_replacement_and_growth_without_losing_values() {
    let storage = Storage::new(false);
    let keys = (0..10000)
        .filter(|&k| Map::<u64>::hash(k) & 15 == 0)
        .take(200)
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 200);
    let mut map = Map::new(&storage);
    for (i, key) in keys.iter().enumerate() {
        map.insert(*key, i as u64).unwrap();
    }
    assert_eq!(map.len(), keys.len());
    assert!(map.get(usize::MAX).is_none());
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(map.get(*key), Some(&(i as u64)));
    }
    let before = storage.state.get();
    map.insert(keys[0], 1234).unwrap();
    assert_eq!(map.get(keys[0]), Some(&1234));
    assert_eq!(storage.state.get().bytes, before.bytes);
    assert_eq!(map.len(), keys.len());
    assert_eq!(map.slots.len(), 512);
    assert_eq!(
        storage.state.get().bytes,
        (16 + 32 + 64 + 128 + 256 + 512) * size_of::<Option<(usize, u64)>>()
    );
}

#[test]
fn rejected_map_growth_keeps_old_entries_and_skips_new_allocation() {
    let bytes = 16 * size_of::<Option<(usize, u64)>>();
    let storage = Storage::limited(bytes, false);
    let mut map = Map::new(&storage);
    for i in 0..8 {
        map.insert(i, i as u64).unwrap();
    }
    let pointer = map.slots.as_ptr();
    assert!(map.insert(8, 8).is_err());
    assert_eq!(map.slots.as_ptr(), pointer);
    assert_eq!(map.len(), 8);
    for i in 0..8 {
        assert_eq!(map.get(i), Some(&(i as u64)));
    }
    assert_eq!(storage.state.get().bytes, bytes);
    assert!(map.insert(0, 9).is_err());
    assert_eq!(map.get(0), Some(&0));
}

struct Dropped(Arc<AtomicUsize>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn partial_array_errors_and_unwinds_drop_initialized_values() {
    for unwind in [false, true] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let storage = Storage::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            storage.vector(4, |i| {
                if i == 2 {
                    if unwind {
                        panic!("injected normalization unwind");
                    }
                    return Err(Storage::error());
                }
                Ok(Dropped(dropped.clone()))
            })
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert_eq!(storage.state.get().bytes, 4 * size_of::<Dropped>());
    }
}

#[test]
fn map_growth_moves_values_without_cloning_or_dropping_them() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let storage = Storage::new(false);
    let mut map = Map::new(&storage);
    for key in 0..40 {
        map.insert(key, Dropped(dropped.clone())).unwrap();
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    map.insert(0, Dropped(dropped.clone())).unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    drop(map);
    assert_eq!(dropped.load(Ordering::SeqCst), 41);
}

#[test]
fn map_node_limit_rejects_without_further_growth() {
    let storage = Storage::new(false);
    let mut map = Map::new(&storage);
    for key in 0..MAX_NODES {
        map.insert(key, key).unwrap();
    }
    let bytes = storage.state.get().bytes;
    assert_eq!(map.slots.len(), 2 * MAX_NODES);
    assert!(map.insert(MAX_NODES, MAX_NODES).is_err());
    assert_eq!(map.len(), MAX_NODES);
    assert_eq!(storage.state.get().bytes, bytes);
}
