//! Scoped numerical source geometry. No proof, witness, registration or admission
//! token can enter this cache. The caller must reserve its fixed storage first.
use super::{CompileError, ConstructionLimits, VerifierHeightEnvelope};
use crate::block_v2::profile;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};

pub const HEIGHT_ENVELOPE_CACHE_ENTRIES: usize = 64;
pub const HEIGHT_ENVELOPE_CACHE_RESERVED_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Default, serde::Serialize, PartialEq, Eq)]
pub struct HeightEnvelopeCacheStatistics {
    pub hits: u64,
    pub table_hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub failed_computations: u64,
    pub planning_ns: u128,
    pub entries: usize,
    pub reserved_host_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    source: [u8; 32],
    profile: [u8; 32],
    crypto: [usize; 6],
    lanes: [usize; 3],
    publics: usize,
    height: usize,
    limits: [usize; 4],
}
impl Key {
    fn new(
        source: [u8; 32],
        publics: usize,
        height: usize,
        limits: ConstructionLimits,
        auxiliary: usize,
    ) -> Self {
        Self {
            source,
            profile: profile::CANDIDATE_PROFILE_ID,
            crypto: [
                profile::NUM_QUERIES,
                profile::LOG_BLOWUP,
                profile::CAP_HEIGHT,
                profile::NUM_RANDOM_CODEWORDS,
                profile::QUERY_POW_BITS as usize,
                profile::CHALLENGE_FIELD_BITS as usize,
            ],
            lanes: [super::LANES, super::EXT_LANES, super::PUBLICS_PER_ROW],
            publics,
            height,
            limits: [
                limits.max_requested_program_bytes,
                limits.max_wires,
                limits.max_input_values,
                auxiliary,
            ],
        }
    }
}
#[derive(Clone, Copy)]
struct Entry {
    key: Key,
    value: VerifierHeightEnvelope,
    used: u64,
}
struct Cache {
    precomputed: bool,
    read_only: bool,
    source: [u8; 32],
    entries: [Option<Entry>; HEIGHT_ENVELOPE_CACHE_ENTRIES],
    clock: u64,
    statistics: HeightEnvelopeCacheStatistics,
}
// Covers the TLS owner, construction/move frames, keys and return copies.
const _: () = assert!(
    8 * core::mem::size_of::<Cache>() + super::precomputed::RESERVED_BYTES
        <= HEIGHT_ENVELOPE_CACHE_RESERVED_BYTES
);
thread_local! { static CACHE: RefCell<Option<Cache>> = const { RefCell::new(None) }; }
thread_local! { static LOOKUP_ONLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// Immutable numeric lookup inputs. A reader cannot start a compiler on a miss.
pub struct HeightEnvelopeCacheSnapshot {
    source: [u8; 32],
    entries: [Option<Entry>; HEIGHT_ENVELOPE_CACHE_ENTRIES],
    clock: u64,
}

/// One thread-bound workflow scope. Nested scopes refuse; drop clears all
/// numerical entries, including when source construction fails or unwinds.
pub struct HeightEnvelopeCacheScope {
    _thread: PhantomData<Rc<()>>,
}
impl HeightEnvelopeCacheScope {
    /// Resolve only cached or source-qualified precomputed numbers. This lets
    /// a coordinator prepare snapshots without nesting a compiler worker pool.
    pub fn lookup_only<T>(operation: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                LOOKUP_ONLY.with(|slot| slot.set(self.0));
            }
        }
        let restore = Restore(LOOKUP_ONLY.with(|slot| slot.replace(true)));
        let result = operation();
        drop(restore);
        result
    }
    pub fn snapshot() -> Result<HeightEnvelopeCacheSnapshot, CompileError> {
        CACHE.with(|slot| {
            let cache = slot.try_borrow().map_err(|_| busy())?;
            let cache = cache.as_ref().filter(|c| !c.read_only).ok_or_else(busy)?;
            Ok(HeightEnvelopeCacheSnapshot {
                source: cache.source,
                entries: cache.entries,
                clock: cache.clock,
            })
        })
    }
    pub fn begin_read_only(snapshot: &HeightEnvelopeCacheSnapshot) -> Result<Self, CompileError> {
        let scope = Self::begin_selected(snapshot.source, false)?;
        CACHE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let cache = slot.as_mut().expect("new numeric reader");
            cache.entries = snapshot.entries;
            cache.clock = snapshot.clock;
            cache.read_only = true;
        });
        Ok(scope)
    }
    pub fn take_worker_statistics(&self) -> HeightEnvelopeCacheStatistics {
        CACHE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let cache = slot.as_mut().expect("live numeric reader");
            assert!(cache.read_only);
            core::mem::take(&mut cache.statistics)
        })
    }
    pub fn absorb_worker(statistics: HeightEnvelopeCacheStatistics) -> Result<(), CompileError> {
        if statistics.misses != 0
            || statistics.evictions != 0
            || statistics.failed_computations != 0
        {
            return Err(CompileError::Shape(
                "read-only geometry worker performed a computation",
            ));
        }
        CACHE.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
            let cache = slot.as_mut().filter(|c| !c.read_only).ok_or_else(busy)?;
            cache.statistics.hits = cache
                .statistics
                .hits
                .checked_add(statistics.hits)
                .ok_or_else(overflow)?;
            cache.statistics.planning_ns = cache
                .statistics
                .planning_ns
                .checked_add(statistics.planning_ns)
                .ok_or_else(overflow)?;
            Ok(())
        })
    }
    pub fn begin(compiled_source: [u8; 32]) -> Result<Self, CompileError> {
        Self::begin_selected(compiled_source, false)
    }
    /// Enable source- and profile-qualified static numeric tables, with dynamic fallback.
    pub fn begin_with_precomputed(compiled_source: [u8; 32]) -> Result<Self, CompileError> {
        Self::begin_selected(compiled_source, true)
    }
    fn begin_selected(compiled_source: [u8; 32], precomputed: bool) -> Result<Self, CompileError> {
        CACHE.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
            if slot.is_some() || compiled_source == [0; 32] {
                return Err(busy());
            }
            *slot = Some(Cache {
                precomputed,
                read_only: false,
                source: compiled_source,
                entries: [None; HEIGHT_ENVELOPE_CACHE_ENTRIES],
                clock: 0,
                statistics: HeightEnvelopeCacheStatistics {
                    reserved_host_bytes: HEIGHT_ENVELOPE_CACHE_RESERVED_BYTES,
                    ..Default::default()
                },
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    pub fn statistics(&self) -> HeightEnvelopeCacheStatistics {
        CACHE.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("live geometry scope")
                .statistics
        })
    }
}
impl Drop for HeightEnvelopeCacheScope {
    fn drop(&mut self) {
        CACHE.with(|slot| {
            if let Some(cache) = slot.borrow_mut().take() {
                let s = cache.statistics;
                use std::io::Write;
                let _ = writeln!(std::io::stderr().lock(), "source_geometry_cache hits={} misses={} evictions={} failed={} entries={} planning_ns={} reserved_host_bytes={}",
                    s.hits, s.misses, s.evictions, s.failed_computations, s.entries, s.planning_ns, s.reserved_host_bytes);
            }
        });
    }
}
fn busy() -> CompileError {
    CompileError::ResourceAdmission("source geometry cache scope unavailable")
}
fn overflow() -> CompileError {
    CompileError::ResourceAdmission("source geometry cache counter overflow")
}

pub(super) fn memoized(
    publics: usize,
    height: usize,
    limits: ConstructionLimits,
    auxiliary: usize,
    build: impl FnOnce() -> Result<VerifierHeightEnvelope, CompileError>,
) -> Result<VerifierHeightEnvelope, CompileError> {
    let started = Instant::now();
    let key = CACHE.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
        let Some(cache) = slot.as_mut() else {
            if LOOKUP_ONLY.with(|slot| slot.get()) {
                return Err(busy());
            }
            return Ok(None);
        };
        cache.clock = cache.clock.checked_add(1).ok_or_else(overflow)?;
        let key = Key::new(cache.source, publics, height, limits, auxiliary);
        if let Some(entry) = cache
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.key == key)
        {
            entry.used = cache.clock;
            cache.statistics.hits = cache.statistics.hits.checked_add(1).ok_or_else(overflow)?;
            cache.statistics.planning_ns = cache
                .statistics
                .planning_ns
                .checked_add(started.elapsed().as_nanos())
                .ok_or_else(overflow)?;
            return Ok(Some((key, Some(entry.value), cache.precomputed)));
        }
        if cache.read_only {
            return Err(CompileError::Shape("unresolved geometry worker descriptor"));
        }
        if LOOKUP_ONLY.with(|slot| slot.get())
            && (!cache.precomputed
                || super::precomputed::lookup(publics, height, limits, auxiliary)?.is_none())
        {
            return Err(CompileError::Shape(
                "geometry descriptor requires deferred compilation",
            ));
        }
        cache.statistics.misses = cache
            .statistics
            .misses
            .checked_add(1)
            .ok_or_else(overflow)?;
        Ok(Some((key, None, cache.precomputed)))
    })?;
    if let Some((_, Some(value), _)) = key {
        return Ok(value);
    }
    let mut table_hit = false;
    let result = if key.as_ref().is_some_and(|(_, _, tables)| *tables) {
        super::precomputed::lookup(publics, height, limits, auxiliary).and_then(|value| match value
        {
            Some(value) => {
                table_hit = true;
                Ok(value)
            }
            None => build(),
        })
    } else {
        build()
    };
    if let Some((key, _, _)) = key {
        CACHE.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
            let cache = slot
                .as_mut()
                .filter(|cache| cache.source == key.source)
                .ok_or_else(busy)?;
            cache.statistics.planning_ns = cache
                .statistics
                .planning_ns
                .checked_add(started.elapsed().as_nanos())
                .ok_or_else(overflow)?;
            if let Ok(value) = result.as_ref() {
                if table_hit {
                    cache.statistics.table_hits = cache
                        .statistics
                        .table_hits
                        .checked_add(1)
                        .ok_or_else(overflow)?;
                }
                let index = if let Some(index) = cache.entries.iter().position(Option::is_none) {
                    cache.statistics.entries += 1;
                    index
                } else {
                    cache.statistics.evictions = cache
                        .statistics
                        .evictions
                        .checked_add(1)
                        .ok_or_else(overflow)?;
                    cache
                        .entries
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, entry)| entry.as_ref().unwrap().used)
                        .unwrap()
                        .0
                };
                cache.entries[index] = Some(Entry {
                    key,
                    value: *value,
                    used: cache.clock,
                });
            } else {
                cache.statistics.failed_computations = cache
                    .statistics
                    .failed_computations
                    .checked_add(1)
                    .ok_or_else(overflow)?;
            }
            Ok::<_, CompileError>(())
        })?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lookup_only_defers_compilation_and_restores_after_unwind() {
        let scope = HeightEnvelopeCacheScope::begin([23; 32]).unwrap();
        assert!(HeightEnvelopeCacheScope::lookup_only(|| memoized(
            28,
            8,
            limits(),
            512 << 20,
            || panic!("lookup-only scope compiled")
        ))
        .is_err());
        assert_eq!(scope.statistics().misses, 0);
        assert!(
            std::panic::catch_unwind(|| HeightEnvelopeCacheScope::lookup_only(|| panic!(
                "injected lookup unwind"
            )))
            .is_err()
        );
        let expected = value(28);
        assert_eq!(
            memoized(28, 8, limits(), 512 << 20, || Ok(expected)).unwrap(),
            expected
        );
        assert_eq!(
            HeightEnvelopeCacheScope::lookup_only(|| memoized(
                28,
                8,
                limits(),
                512 << 20,
                || panic!("cached descriptor compiled")
            ))
            .unwrap(),
            expected
        );
        assert_eq!((scope.statistics().hits, scope.statistics().misses), (1, 1));
    }
    #[test]
    fn numeric_reader_cannot_start_a_compiler_or_hide_its_hits() {
        let scope = HeightEnvelopeCacheScope::begin([23; 32]).unwrap();
        let expected = value(28);
        memoized(28, 8, limits(), 512 << 20, || Ok(expected)).unwrap();
        let snapshot = HeightEnvelopeCacheScope::snapshot().unwrap();
        let statistics = std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    let reader = HeightEnvelopeCacheScope::begin_read_only(&snapshot).unwrap();
                    assert_eq!(
                        memoized(28, 8, limits(), 512 << 20, || panic!(
                            "read-only hit compiled"
                        ))
                        .unwrap(),
                        expected
                    );
                    let statistics = reader.take_worker_statistics();
                    assert!(memoized(28, 16, limits(), 512 << 20, || panic!(
                        "read-only miss compiled"
                    ))
                    .is_err());
                    statistics
                })
                .join()
                .unwrap()
        });
        HeightEnvelopeCacheScope::absorb_worker(statistics).unwrap();
        assert_eq!((scope.statistics().hits, scope.statistics().misses), (1, 1));
    }
    fn limits() -> ConstructionLimits {
        ConstructionLimits {
            max_requested_program_bytes: 2 << 30,
            max_wires: super::super::MAX_WIRES,
            max_input_values: 1 << 20,
        }
    }
    // Inert numerical fixture; no program or proof is constructed by these tests.
    fn value(publics: usize) -> VerifierHeightEnvelope {
        VerifierHeightEnvelope {
            public_values: publics,
            maximum_child_height: 8,
            heights_enumerated: 1,
            operations: Default::default(),
            wire_upper_bound: 1,
            input_values_upper_bound: 1,
            selection_hint_words_upper_bound: 0,
            planner_requested_program_bytes_peak: 0,
            planning_storage: super::super::PlanningStorage {
                symbolic_workspace_bytes: 0,
                symbolic_retained_bytes: 0,
                template_retained_bytes: 0,
                template_construction_bytes: 0,
                input_backing_bytes: 0,
                returned_wire_bytes: 0,
                helper_bytes: 0,
                auxiliary_peak_bytes: 0,
                total_requested_bytes: 0,
            },
        }
    }
    fn get(publics: usize) -> VerifierHeightEnvelope {
        memoized(publics, 8, limits(), 512 << 20, || Ok(value(publics))).unwrap()
    }
    #[test]
    fn cache_requires_an_exact_source_geometry_and_construction_key() {
        let scope = HeightEnvelopeCacheScope::begin([1; 32]).unwrap();
        assert!(HeightEnvelopeCacheScope::begin([1; 32]).is_err());
        assert_eq!(get(28), get(28));
        assert_eq!(scope.statistics().hits, 1);
        for (publics, height, limits, auxiliary) in [
            (29, 8, limits(), 512 << 20),
            (28, 16, limits(), 512 << 20),
            (
                28,
                8,
                ConstructionLimits {
                    max_requested_program_bytes: 1 << 30,
                    ..limits()
                },
                512 << 20,
            ),
            (
                28,
                8,
                ConstructionLimits {
                    max_wires: 1024,
                    ..limits()
                },
                512 << 20,
            ),
            (
                28,
                8,
                ConstructionLimits {
                    max_input_values: 512,
                    ..limits()
                },
                512 << 20,
            ),
            (28, 8, limits(), 256 << 20),
        ] {
            memoized(publics, height, limits, auxiliary, || Ok(value(publics))).unwrap();
        }
        assert_eq!(scope.statistics().misses, 7);
        drop(scope);
        let next = HeightEnvelopeCacheScope::begin([2; 32]).unwrap();
        get(28);
        assert_eq!(next.statistics().hits, 0);
        assert_eq!(next.statistics().misses, 1);
    }
    #[test]
    fn deterministic_lru_is_bounded_and_errors_are_not_cached() {
        let scope = HeightEnvelopeCacheScope::begin([1; 32]).unwrap();
        for public in 0..HEIGHT_ENVELOPE_CACHE_ENTRIES {
            get(public);
        }
        get(0); // Keep zero, evict one.
        get(64);
        let before = scope.statistics();
        get(0);
        assert_eq!(scope.statistics().hits, before.hits + 1);
        get(1);
        assert_eq!(scope.statistics().misses, before.misses + 1);
        assert_eq!(scope.statistics().entries, HEIGHT_ENVELOPE_CACHE_ENTRIES);
        assert_eq!(scope.statistics().evictions, 2);
        for _ in 0..2 {
            assert!(memoized(999, 8, limits(), 512 << 20, || Err(busy())).is_err());
        }
        assert_eq!(scope.statistics().failed_computations, 2);
        assert_eq!(scope.statistics().entries, HEIGHT_ENVELOPE_CACHE_ENTRIES);
    }
    #[test]
    fn unwinding_retires_cache_and_counter_overflow_refuses() {
        let _ = std::panic::catch_unwind(|| {
            let _scope = HeightEnvelopeCacheScope::begin([1; 32]).unwrap();
            get(28);
            panic!("source construction failed");
        });
        let scope = HeightEnvelopeCacheScope::begin([1; 32]).unwrap();
        assert_eq!(scope.statistics().entries, 0);
        CACHE.with(|slot| slot.borrow_mut().as_mut().unwrap().clock = u64::MAX);
        assert!(memoized(28, 8, limits(), 512 << 20, || panic!(
            "must refuse before compilation"
        ))
        .is_err());
    }
    #[cfg(all(
        not(debug_assertions),
        target_arch = "x86_64",
        feature = "block-v2-wide-lanes"
    ))]
    #[test]
    fn real_source_bounds_match_without_and_with_cache_and_still_enforce_admission() {
        use super::super::verifier_height_envelope;
        let expected = verifier_height_envelope(25, 8, limits(), 512 << 20).unwrap();
        let scope = HeightEnvelopeCacheScope::begin([3; 32]).unwrap();
        for _ in 0..2 {
            assert_eq!(
                verifier_height_envelope(25, 8, limits(), 512 << 20).unwrap(),
                expected
            );
        }
        assert_eq!((scope.statistics().hits, scope.statistics().misses), (1, 1));
        // A cached large-budget result must never satisfy a smaller reservation.
        assert!(verifier_height_envelope(25, 8, limits(), 0).is_err());
        assert_eq!(scope.statistics().failed_computations, 1);
    }
}
