//! Scoped numeric native bounds. Keys include every closed descriptor field;
//! no AIR, witness, proof, program or admission owner is retained.
use super::key::DescriptorKey;
use super::{CompileError, ConstructionLimits, NativeCoreBound};
use sha3::{Digest, Sha3_256};
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};

pub(crate) const RESERVED_BYTES: usize = 1 << 20;
const ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Default, serde::Serialize, PartialEq, Eq)]
pub(crate) struct Statistics {
    pub hits: u64,
    pub table_hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub failed_computations: u64,
    pub planning_ns: u128,
    pub entries: usize,
    pub reserved_host_bytes: usize,
    pub cohorts: u64,
    pub jobs_started: u64,
    pub peak_workers: usize,
    pub periodic_preparations: u64,
    pub budget_reductions: u64,
    pub admitted_host_bytes_peak: usize,
    pub threads_spawned: u64,
    pub pinned_workers: u64,
    pub affinity_failures: u64,
    pub queue_refills: u64,
    pub workspace_reuses: u64,
    pub maintenance_jobs: u64,
    pub completions_drained: u64,
    pub admission_stalls: u64,
    pub trimmed_compiler_bytes: u64,
    pub idle_compiler_bytes_peak: usize,
    pub phase_extra_bytes_peak: usize,
    pub preparation_ns: u128,
    pub coordinator_wait_ns: u128,
    pub retained_worker_bytes_peak: usize,
}
const FAMILIES: [&str; 13] = [
    "aes",
    "shake",
    "transcript",
    "sparse",
    "uniform",
    "statement",
    "private",
    "affine",
    "ntt",
    "mul",
    "g_bound",
    "permutation",
    "linear_map",
];
#[derive(Clone, Copy, Default, Debug, serde::Serialize)]
pub(crate) struct FamilyStatistics {
    pub requests: u64,
    pub cache_hits: u64,
    pub table_hits: u64,
    pub cold_misses: u64,
    pub compile_ns: u128,
}
#[derive(Clone, Copy, Default, Debug, serde::Serialize)]
pub(crate) struct Miss {
    pub descriptor_key: [u8; 32],
    pub family: usize,
    pub occurrences: u64,
    pub compile_ns: u128,
}
const HOT_MISSES: usize = 32;
#[derive(Clone, Copy)]
struct Entry {
    key: [u8; 32],
    value: NativeCoreBound,
    used: u64,
}
struct Cache {
    source: [u8; 32],
    precomputed: bool,
    entries: [Option<Entry>; ENTRIES],
    clock: u64,
    statistics: Statistics,
    families: [FamilyStatistics; 13],
    expensive: [Option<Miss>; HOT_MISSES],
}
const _: () = assert!(
    8 * (core::mem::size_of::<Cache>() + core::mem::size_of::<[super::precomputed::Row; 256]>())
        <= RESERVED_BYTES
);
thread_local! { static CACHE: RefCell<Option<Cache>> = const { RefCell::new(None) }; }

pub(crate) struct Scope {
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub(crate) fn begin(source: [u8; 32]) -> Result<Self, CompileError> {
        Self::open(source, false)
    }
    pub(crate) fn begin_with_precomputed(source: [u8; 32]) -> Result<Self, CompileError> {
        Self::open(source, true)
    }
    fn open(source: [u8; 32], precomputed: bool) -> Result<Self, CompileError> {
        CACHE.with(|slot| {
            let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
            if slot.is_some() || source == [0; 32] {
                return Err(busy());
            }
            *slot = Some(Cache {
                source,
                precomputed,
                entries: [None; ENTRIES],
                clock: 0,
                families: [FamilyStatistics::default(); 13],
                expensive: [None; HOT_MISSES],
                statistics: Statistics {
                    reserved_host_bytes: RESERVED_BYTES,
                    ..Default::default()
                },
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    pub(crate) fn miss_statistics(&self) -> ([FamilyStatistics; 13], [Option<Miss>; HOT_MISSES]) {
        CACHE.with(|slot| {
            let c = slot.borrow();
            let c = c.as_ref().expect("live native metadata scope");
            (c.families, c.expensive)
        })
    }
    pub(crate) fn statistics(&self) -> Statistics {
        CACHE.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("live native metadata scope")
                .statistics
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CACHE.with(|slot| {
            if let Some(cache) = slot.borrow_mut().take() {
                let s = cache.statistics;
                // Numeric descriptor digests only: no witness, setup seed or
                // source owner is retained or logged. Fixed-size top-cost list.
                for (name, stats) in FAMILIES.iter().zip(cache.families) {
                    if stats.requests != 0 { eprintln!("NATIVE_METADATA_FAMILY {}", serde_json::json!({"family":name,"statistics":stats})); }
                }
                for miss in cache.expensive.iter().flatten() {
                    eprintln!("NATIVE_METADATA_EXPENSIVE_MISS {}", serde_json::json!(miss));
                }

                use std::io::Write;
                let _ = writeln!(std::io::stderr().lock(), "native_metadata_cache hits={} misses={} evictions={} failed={} entries={} planning_ns={} reserved_host_bytes={}",
                    s.hits, s.misses, s.evictions, s.failed_computations, s.entries, s.planning_ns, s.reserved_host_bytes);
            }
        });
    }
}
fn busy() -> CompileError {
    CompileError::ResourceAdmission("native metadata cache scope unavailable")
}
fn overflow() -> CompileError {
    CompileError::ResourceAdmission("native metadata cache counter overflow")
}

pub(super) fn record_cohort(s: super::cohort::Statistics) -> Result<(), CompileError> {
    CACHE.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
        if let Some(c) = slot.as_mut() {
            macro_rules! add { ($($field:ident),+) => { $(c.statistics.$field = c.statistics.$field.checked_add(s.$field).ok_or_else(overflow)?;)+ }; }
            add!(cohorts, jobs_started, periodic_preparations, budget_reductions, threads_spawned, pinned_workers, affinity_failures, queue_refills, workspace_reuses, maintenance_jobs, completions_drained, admission_stalls, trimmed_compiler_bytes, preparation_ns, coordinator_wait_ns);
            c.statistics.idle_compiler_bytes_peak = c.statistics.idle_compiler_bytes_peak.max(s.idle_compiler_bytes_peak);
            c.statistics.phase_extra_bytes_peak = c.statistics.phase_extra_bytes_peak.max(s.phase_extra_bytes_peak);
            c.statistics.retained_worker_bytes_peak = c.statistics.retained_worker_bytes_peak.max(s.retained_worker_bytes_peak);
            c.statistics.planning_ns = c.statistics.planning_ns.checked_add(s.wall_ns).ok_or_else(overflow)?;
            c.statistics.failed_computations = c.statistics.failed_computations.checked_add(s.failed_cohorts).ok_or_else(overflow)?;
            c.statistics.peak_workers = c.statistics.peak_workers.max(s.peak_workers);
            c.statistics.admitted_host_bytes_peak = c.statistics.admitted_host_bytes_peak.max(s.admitted_host_bytes_peak);
        }
        Ok(())
    })
}

pub(super) fn key<D: DescriptorKey>(
    source: [u8; 32],
    family: u8,
    descriptor: &D,
    limits: ConstructionLimits,
    auxiliary: usize,
) -> [u8; 32] {
    let started = super::profiling::start();
    let mut stream = Sha3_256::new();
    stream.update(b"ringct/native-numeric-metadata/v2\0");
    stream.update(source);
    stream.update(lattica_prover_p3::block_v2::profile::CANDIDATE_PROFILE_ID);
    stream.update([family]);
    for value in [
        limits.max_requested_program_bytes,
        limits.max_wires,
        limits.max_input_values,
        auxiliary,
    ] {
        stream.update((value as u64).to_le_bytes());
    }
    descriptor.encode(&mut stream);
    let digest = stream.finalize().into();
    super::profiling::finish(super::profiling::Phase::Key, started);
    digest
}

pub(super) struct Pending {
    key: Option<[u8; 32]>,
    miss: Option<(usize, [u8; 32])>,
    started: Instant,
    pub value: Option<NativeCoreBound>,
}
impl Pending {
    pub(super) fn publish(
        self,
        result: Result<NativeCoreBound, CompileError>,
    ) -> Result<NativeCoreBound, CompileError> {
        let elapsed = self.started.elapsed().as_nanos();
        self.publish_time(result, elapsed, elapsed)
    }
    pub(super) fn publish_cohort(
        self,
        result: Result<NativeCoreBound, CompileError>,
        compile_ns: u128,
    ) -> Result<NativeCoreBound, CompileError> {
        // The coordinator records wall time once for the joined group; queued
        // lookups must not each count the same group duration again.
        self.publish_time(result, 0, compile_ns)
    }
    fn publish_time(
        self,
        result: Result<NativeCoreBound, CompileError>,
        elapsed: u128,
        compile_ns: u128,
    ) -> Result<NativeCoreBound, CompileError> {
        if let Some(key) = self.key {
            CACHE.with(|slot| {
                let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
                let c = slot.as_mut().ok_or_else(busy)?;
                c.statistics.planning_ns = c
                    .statistics
                    .planning_ns
                    .checked_add(elapsed)
                    .ok_or_else(overflow)?;
                if let Some((family, descriptor_key)) = self.miss {
                    let total = &mut c.families[family].compile_ns;
                    *total = total.checked_add(compile_ns).ok_or_else(overflow)?;
                    if let Some(existing) = c
                        .expensive
                        .iter_mut()
                        .flatten()
                        .find(|m| m.descriptor_key == descriptor_key)
                    {
                        existing.occurrences =
                            existing.occurrences.checked_add(1).ok_or_else(overflow)?;
                        existing.compile_ns = existing
                            .compile_ns
                            .checked_add(compile_ns)
                            .ok_or_else(overflow)?;
                    } else {
                        let index =
                            c.expensive
                                .iter()
                                .position(Option::is_none)
                                .unwrap_or_else(|| {
                                    c.expensive
                                        .iter()
                                        .enumerate()
                                        .min_by_key(|(_, m)| m.unwrap().compile_ns)
                                        .unwrap()
                                        .0
                                });
                        if c.expensive[index].is_none_or(|m| compile_ns > m.compile_ns) {
                            c.expensive[index] = Some(Miss {
                                descriptor_key,
                                family,
                                occurrences: 1,
                                compile_ns,
                            });
                        }
                    }
                }
                if let Ok(value) = result.as_ref() {
                    let index = if let Some(i) = c
                        .entries
                        .iter()
                        .position(|e| e.is_some_and(|e| e.key == key))
                    {
                        i
                    } else if let Some(i) = c.entries.iter().position(Option::is_none) {
                        c.statistics.entries += 1;
                        i
                    } else {
                        c.statistics.evictions =
                            c.statistics.evictions.checked_add(1).ok_or_else(overflow)?;
                        c.entries
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, e)| e.unwrap().used)
                            .unwrap()
                            .0
                    };
                    c.entries[index] = Some(Entry {
                        key,
                        value: *value,
                        used: c.clock,
                    });
                } else {
                    c.statistics.failed_computations = c
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
}
pub(super) fn select<D: DescriptorKey>(
    family: u8,
    descriptor: &D,
    limits: ConstructionLimits,
    auxiliary: usize,
    storage: super::NativePlanningStorage,
) -> Result<Pending, CompileError> {
    let started = Instant::now();
    CACHE.with(|slot| {
        let mut slot = slot.try_borrow_mut().map_err(|_| busy())?;
        let Some(c) = slot.as_mut() else {
            return Ok(Pending {
                key: None,
                miss: None,
                value: None,
                started,
            });
        };
        let key = key(c.source, family, descriptor, limits, auxiliary);
        let family_index = descriptor.family();
        c.families[family_index].requests += 1;
        let mut miss = None;
        let lookup_started = super::profiling::start();
        c.clock = c.clock.checked_add(1).ok_or_else(overflow)?;
        let value = if let Some(e) = c.entries.iter_mut().flatten().find(|e| e.key == key) {
            e.used = c.clock;
            c.statistics.hits = c.statistics.hits.checked_add(1).ok_or_else(overflow)?;
            c.families[family_index].cache_hits += 1;
            Some(e.value)
        } else {
            c.statistics.misses = c.statistics.misses.checked_add(1).ok_or_else(overflow)?;
            let table = c
                .precomputed
                .then(|| super::precomputed::lookup(family, descriptor, limits, storage))
                .flatten();
            if table.is_some() {
                c.families[family_index].table_hits += 1;
                c.statistics.table_hits = c
                    .statistics
                    .table_hits
                    .checked_add(1)
                    .ok_or_else(overflow)?;
            }
            if table.is_none() {
                c.families[family_index].cold_misses += 1;
                miss = Some((family_index, super::key::descriptor(family, descriptor)));
            }
            table
        };
        super::profiling::finish(super::profiling::Phase::Lookup, lookup_started);
        Ok(Pending {
            key: Some(key),
            miss,
            value,
            started,
        })
    })
}
pub(super) fn memoized<D: DescriptorKey>(
    family: u8,
    descriptor: &D,
    limits: ConstructionLimits,
    auxiliary: usize,
    storage: super::NativePlanningStorage,
    build: impl FnOnce() -> Result<NativeCoreBound, CompileError>,
) -> Result<NativeCoreBound, CompileError> {
    let pending = select(family, descriptor, limits, auxiliary, storage)?;
    let result = match pending.value {
        Some(v) => Ok(v),
        None => build(),
    };
    pending.publish(result)
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
