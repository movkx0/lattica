//! Bounded process-local reuse of public AIR programs. Each cache belongs to one
//! evaluator/runtime; handles retain their device and host charges after cache
//! retirement. No witness, challenge, random seed, or proof parameter is cached.
use super::*;
use crate::cuda_compute::{
    budget::{MAX_PUBLIC_PROGRAMS, MAX_PUBLIC_PROGRAM_BYTES},
    compiler::{self, ToolchainIdentity},
    Identity, Snapshot,
};
use serde::Serialize;
use std::sync::Mutex;

const MAX_ENTRIES: usize = 32;
// Include the compiler itself: changes to block sizing, liveness or emission
// invalidate prepared programs even when the public AIR bytes are unchanged.
const GENERATOR: &str = include_str!("../../block_v2/quotient_program/specialize.rs");

#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheLimits {
    pub entries: usize,
    pub host_bytes: usize,
    pub device_bytes: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            entries: 8,
            host_bytes: 32 << 20,
            device_bytes: 8 << 20,
        }
    }
}

impl CacheLimits {
    pub(super) fn validate(self, runtime: Limits) -> Result<()> {
        if !(1..=MAX_ENTRIES).contains(&self.entries)
            || self.host_bytes == 0
            || self.host_bytes > MAX_PUBLIC_PROGRAM_BYTES
            || self.device_bytes == 0
            || self.device_bytes > runtime.managed_bytes
        {
            return Err("invalid CUDA public program cache limits".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct CacheSnapshot {
    pub entries: usize,
    pub host_bytes: usize,
    pub device_bytes: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

struct Entry {
    key: [u8; 32],
    used: u128,
    prepared: Arc<PreparedQuotient>,
}

struct State {
    entries: [Option<Entry>; MAX_ENTRIES],
    clock: u128,
    hits: u64,
    misses: u64,
    evictions: u64,
}

pub(super) struct ProgramCache {
    namespace: [u8; 32],
    limits: CacheLimits,
    state: Mutex<State>,
}

/// Conservatively charge a complete inline cache table per retained program,
/// plus both Arc headers and the prepared handle. The table never grows and
/// source-generation/compiler temporary storage is separately bounded.
pub(super) fn program_host_bytes(program: &Program) -> Result<usize> {
    program
        .instructions
        .capacity()
        .checked_mul(8)
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<Program>()
                    + std::mem::size_of::<PreparedQuotient>()
                    + std::mem::size_of::<ProgramCache>()
                    + 4 * std::mem::size_of::<usize>(),
            )
        })
        .filter(|bytes| *bytes <= MAX_PROGRAM_HOST_BYTES)
        .ok_or_else(|| "CUDA quotient public program exceeds host allowance".into())
}

fn bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn namespace(
    identity: &Identity,
    toolchain: ToolchainIdentity,
    options: &[String],
    generator: &str,
    kernels: &str,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    bytes(
        &mut hash,
        b"lattica-cuda-public-program-cache-v1/process-local",
    );
    for word in [
        toolchain.version[0] as u64,
        toolchain.version[1] as u64,
        toolchain.library_instance as u64,
        identity.compute_capability as u64,
        identity.driver_api as u64,
        identity.multiprocessors as u64,
        identity.max_threads_per_multiprocessor as u64,
    ] {
        hash.update(&word.to_le_bytes());
    }
    bytes(&mut hash, identity.uuid.as_bytes());
    hash.update(&(options.len() as u64).to_le_bytes());
    for option in options {
        bytes(&mut hash, option.as_bytes());
    }
    bytes(&mut hash, generator.as_bytes());
    bytes(&mut hash, kernels.as_bytes());
    *hash.finalize().as_bytes()
}

fn key(
    namespace: [u8; 32],
    profile: [u8; 32],
    program: &Program,
    mode: Specialization,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(&namespace);
    hash.update(&profile);
    hash.update(&[match mode {
        Specialization::Generic => 0,
        Specialization::Prefer => 1,
    }]);
    let layout = &program.layout;
    for word in [
        program.extension.degree(),
        program.instructions.len(),
        program.registers,
        program.constraints,
        program.row_words,
        program.parameter_words,
        layout.preprocessed_width,
        layout.main_width,
        layout.num_public_values,
        layout.permutation_width,
        layout.num_permutation_challenges,
        layout.num_permutation_values,
        layout.num_periodic_columns,
    ] {
        hash.update(&(word as u64).to_le_bytes());
    }
    for word in &program.instructions {
        hash.update(&word.to_le_bytes());
    }
    *hash.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug)]
struct Charge {
    host: usize,
    device: usize,
    modules: usize,
}

#[derive(Clone, Copy)]
struct Retained {
    charge: Charge,
    used: u128,
    reclaimable: bool,
}

fn fits(
    cache: CacheSnapshot,
    global: Snapshot,
    request: Charge,
    limits: CacheLimits,
    runtime: Limits,
) -> bool {
    let within = |current: usize, extra: usize, limit: usize| {
        current.checked_add(extra).is_some_and(|n| n <= limit)
    };
    within(cache.entries, 1, limits.entries)
        && within(cache.host_bytes, request.host, limits.host_bytes)
        && within(cache.device_bytes, request.device, limits.device_bytes)
        && within(global.public_programs, 1, MAX_PUBLIC_PROGRAMS)
        && within(
            global.public_program_bytes,
            request.host,
            MAX_PUBLIC_PROGRAM_BYTES,
        )
        && within(global.live_bytes, request.device, runtime.managed_bytes)
        && within(global.allocations, 1, runtime.max_allocations)
        && within(global.modules, request.modules, runtime.max_modules)
        && request.device <= runtime.max_allocation_bytes
}

/// Plan every eviction before retiring anything. An impossible request leaves
/// existing entries intact, including when non-cache allocations use the budget.
fn evictions(
    entries: [Option<Retained>; MAX_ENTRIES],
    mut global: Snapshot,
    request: Charge,
    limits: CacheLimits,
    runtime: Limits,
) -> Result<[bool; MAX_ENTRIES]> {
    let mut cache = CacheSnapshot::default();
    for entry in entries.iter().flatten() {
        cache.entries += 1;
        cache.host_bytes += entry.charge.host;
        cache.device_bytes += entry.charge.device;
    }
    let mut order: [usize; MAX_ENTRIES] = std::array::from_fn(|i| i);
    order.sort_unstable_by_key(|&i| entries[i].map(|entry| entry.used).unwrap_or(u128::MAX));
    let mut remove = [false; MAX_ENTRIES];
    for index in order {
        if fits(cache, global, request, limits, runtime) {
            return Ok(remove);
        }
        let Some(entry) = entries[index].filter(|entry| entry.reclaimable) else {
            continue;
        };
        remove[index] = true;
        cache.entries -= 1;
        cache.host_bytes -= entry.charge.host;
        cache.device_bytes -= entry.charge.device;
        global.public_programs -= 1;
        global.public_program_bytes -= entry.charge.host;
        global.live_bytes -= entry.charge.device;
        global.allocations -= 1;
        global.modules -= entry.charge.modules;
    }
    if fits(cache, global, request, limits, runtime) {
        Ok(remove)
    } else {
        Err("CUDA public program cache has insufficient unpinned capacity".into())
    }
}

impl State {
    fn tick(&mut self) -> u128 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    fn snapshot(&self) -> CacheSnapshot {
        let mut snapshot = CacheSnapshot {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            ..CacheSnapshot::default()
        };
        for entry in self.entries.iter().flatten() {
            snapshot.entries += 1;
            snapshot.host_bytes += entry.prepared.host_bytes;
            snapshot.device_bytes += entry.prepared.code.len() * 8;
        }
        snapshot
    }
}

impl ProgramCache {
    pub(super) fn new(runtime: &Runtime, limits: CacheLimits) -> Result<Self> {
        Ok(Self {
            namespace: namespace(
                runtime.identity(),
                compiler::identity()?,
                &compiler::options(runtime.identity().compute_capability),
                GENERATOR,
                SOURCE,
            ),
            limits,
            state: Mutex::new(State {
                entries: std::array::from_fn(|_| None),
                clock: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
            }),
        })
    }
}

impl Quotients {
    /// `profile` binds the caller's public proof profile. Cache keys also cover
    /// every program word/layout field, specialization policy, emitter/kernels,
    /// compiler options, exact loaded NVRTC instance, GPU and driver identity.
    /// Entries cannot be reused in another process/runtime. Held handles pin
    /// entries; callers should drop them when their proof or preparation ends.
    pub(crate) fn prepare_cached(
        &self,
        profile: [u8; 32],
        program: Arc<Program>,
        mode: Specialization,
    ) -> Result<Arc<PreparedQuotient>> {
        // Metadata hits must also fail closed after a runtime fault. Release
        // the queue lock before acquiring the cache lock (retirement uses it).
        drop(self.runtime.state.enter()?);
        program.validate_quotient()?;
        let host = program_host_bytes(&program)?;
        let request = Charge {
            host,
            device: program.instructions.len() * 8,
            // Prefer may temporarily load a specialization and later reject its
            // private-memory use. Reserve for that peak even if fallback wins.
            modules: usize::from(mode == Specialization::Prefer),
        };
        let key = key(self.cache.namespace, profile, &program, mode);
        // Single-flight preparation per evaluator. No caller can evict a hit
        // or compile a second copy while this bounded preparation is running.
        let mut state = self
            .cache
            .state
            .lock()
            .map_err(|_| "CUDA program cache poisoned")?;
        let used = state.tick();
        if let Some(index) = state
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|e| e.key == key))
        {
            state.hits = state.hits.saturating_add(1);
            let entry = state.entries[index].as_mut().unwrap();
            entry.used = used;
            return Ok(entry.prepared.clone());
        }
        state.misses = state.misses.saturating_add(1);
        let retained = std::array::from_fn(|i| {
            state.entries[i].as_ref().map(|entry| Retained {
                charge: Charge {
                    host: entry.prepared.host_bytes,
                    device: entry.prepared.code.len() * 8,
                    modules: usize::from(entry.prepared.specialized.is_some()),
                },
                used: entry.used,
                reclaimable: Arc::strong_count(&entry.prepared) == 1,
            })
        });
        let remove = evictions(
            retained,
            self.runtime.snapshot(),
            request,
            self.cache.limits,
            self.runtime.state.budget.limits,
        )?;
        for (index, remove) in remove.into_iter().enumerate() {
            if remove {
                // Native erasure/unload completes before its charges can fund
                // the next preparation. Active handles were excluded above.
                drop(state.entries[index].take());
                state.evictions = state.evictions.saturating_add(1);
            }
        }
        let prepared = Arc::new(self.prepare(program, mode)?);
        let slot = state
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or("CUDA cache slot accounting failed")?;
        *slot = Some(Entry {
            key,
            used,
            prepared: prepared.clone(),
        });
        Ok(prepared)
    }

    pub(crate) fn prepared_cache_snapshot(&self) -> Result<CacheSnapshot> {
        Ok(self
            .cache
            .state
            .lock()
            .map_err(|_| "CUDA program cache poisoned")?
            .snapshot())
    }

    /// Active handles remain valid and charged after cache retirement. This
    /// drops cache ownership only; it never forcibly revokes a proof's handle.
    pub(crate) fn clear_prepared_cache(&self) -> Result<()> {
        let mut state = self
            .cache
            .state
            .lock()
            .map_err(|_| "CUDA program cache poisoned")?;
        for entry in &mut state.entries {
            drop(entry.take());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
