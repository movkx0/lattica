//! Heap-request accounting for one program builder. Caller-owned proof data,
//! cached programs, fixed folding scratch and allocator/driver overhead have
//! separate enclosing reservations. These counters are not physical RSS.
use super::{Constants, ExecutionError, Op, Program, Row, Wire, MAX_WIRES};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::mem::size_of;
pub(super) mod packed;

pub(super) fn packing_bytes(
    operations: &Vec<Op>,
    rows: usize,
    indexed: usize,
    wires: usize,
) -> Result<usize, ExecutionError> {
    let bytes = |n: usize, width: usize| n.checked_mul(width).ok_or(ExecutionError::TooLarge);
    let mut total = size_of::<Program>() + 1024; // bounded read/write temporaries
    for amount in [
        bytes(operations.capacity(), size_of::<Op>())?,
        bytes(rows, size_of::<Row>())?,
        bytes(indexed, size_of::<u32>())?,
        bytes(wires, size_of::<u32>() + size_of::<bool>())?,
    ] {
        total = total.checked_add(amount).ok_or(ExecutionError::TooLarge)?;
    }
    for op in operations {
        if let Op::SelectHint { entries, bits, .. } = op {
            // Packed rows reference these source vectors without cloning them.
            for n in [entries.capacity(), bits.capacity()] {
                total = total
                    .checked_add(bytes(n, size_of::<Wire>())?)
                    .ok_or(ExecutionError::TooLarge)?;
            }
        }
    }
    Ok(total)
}

/// Release geometric growth slack before allocating packed rows. Charge the
/// entire old/new operation-array overlap before reserving or moving anything.
/// Hint buffers move with their operations and are never cloned here.
pub(super) fn compact_operations(
    operations: &mut Vec<Op>,
    memory: &mut Budget,
) -> Result<(), ExecutionError> {
    if operations.len() == operations.capacity() {
        return Ok(());
    }
    let next_bytes = operations
        .len()
        .checked_mul(size_of::<Op>())
        .ok_or(ExecutionError::TooLarge)?;
    let peak = packing_bytes(operations, 0, 0, 0)?
        .checked_add(next_bytes)
        .ok_or(ExecutionError::TooLarge)?;
    if !memory.packing(peak) {
        memory.report("compaction_rejected");
        return Err(ExecutionError::TooLarge);
    }
    let mut next = Vec::new();
    next.try_reserve_exact(operations.len())
        .map_err(|_| ExecutionError::TooLarge)?;
    next.append(operations);
    *operations = next;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct Budget {
    pub(super) limit: Option<usize>,
    pub(super) wire_limit: usize,
    pub(super) input_limit: usize,
    pub(super) live: usize,
    pub(super) peak: usize,
    pub(super) failed: bool,
    pub(super) byte_limit_exceeded: bool,
}

impl Budget {
    pub(super) fn new(constants: Constants<'_>, publics: usize) -> Result<Self, ExecutionError> {
        let mut result = Self {
            limit: None,
            wire_limit: MAX_WIRES,
            input_limit: MAX_WIRES - publics,
            live: 0,
            peak: 0,
            failed: false,
            byte_limit_exceeded: false,
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if matches!(constants, Constants::Device(..)) {
            if let Some(bounds) = super::super::gpu_backend::resources::construction_bounds()
                .map_err(|_| ExecutionError::TooLarge)?
            {
                result.limit = Some(
                    usize::try_from(bounds.program_host_bytes)
                        .map_err(|_| ExecutionError::TooLarge)?,
                );
                result.wire_limit =
                    usize::try_from(bounds.wires).map_err(|_| ExecutionError::TooLarge)?;
                result.input_limit = usize::try_from(bounds.input_values)
                    .ok()
                    .and_then(|n| n.checked_sub(publics))
                    .ok_or(ExecutionError::TooLarge)?;
                if publics > result.wire_limit {
                    return Err(ExecutionError::TooLarge);
                }
            }
        }
        #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
        let _ = constants;
        #[cfg(feature = "gpu-cuda")]
        if let Constants::Cuda(context, _) = constants {
            if let Some(bounds) = context.construction_limits() {
                result.limit = Some(bounds.program_host_bytes);
                result.wire_limit = bounds.wires;
                result.input_limit = bounds
                    .input_values
                    .checked_sub(publics)
                    .ok_or(ExecutionError::TooLarge)?;
                if publics > result.wire_limit {
                    return Err(ExecutionError::TooLarge);
                }
            }
        }
        Ok(result)
    }

    pub(super) fn reject(&mut self) -> bool {
        self.failed = true;
        false
    }

    pub(super) fn reserve(&mut self, bytes: usize) -> bool {
        if self.failed {
            return false;
        }
        let Some(next) = self.live.checked_add(bytes) else {
            return self.reject();
        };
        if self.limit.is_some_and(|limit| next > limit) {
            self.byte_limit_exceeded = true;
            return self.reject();
        }
        self.live = next;
        self.peak = self.peak.max(next);
        true
    }

    pub(super) fn release(&mut self, bytes: usize) {
        self.live = self
            .live
            .checked_sub(bytes)
            .expect("construction reservation underflow");
    }

    pub(super) fn packing(&mut self, bytes: usize) -> bool {
        // All interning tables have been dropped. `bytes` covers remaining
        // source operations/hints, exact indexed rows and reference scratch.
        self.live = 0;
        self.reserve(bytes)
    }

    pub(super) fn report(&self, phase: &str) {
        if let Some(limit) = self.limit {
            eprintln!("bounded_program_construction phase={phase} limit_bytes={limit} admitted_peak_bytes={} live_bytes={} rejected={}", self.peak, self.live, self.failed);
        }
    }

    pub(super) fn push(&mut self, operations: &mut Vec<Op>, op: Op) {
        if self.failed {
            return;
        }
        if operations.len() == operations.capacity() {
            let Some(capacity) = operations.capacity().checked_mul(2).map(|n| n.max(4)) else {
                self.reject();
                return;
            };
            let Some(bytes) = capacity.checked_mul(size_of::<Op>()) else {
                self.reject();
                return;
            };
            // The complete old and new arrays coexist while moving operations.
            // A realloc that happened to grow in place must not weaken the cap.
            if !self.reserve(bytes) {
                return;
            }
            let mut next = Vec::new();
            if next.try_reserve_exact(capacity).is_err() {
                self.release(bytes);
                self.reject();
                return;
            }
            let old_bytes = operations.capacity() * size_of::<Op>();
            next.append(operations);
            *operations = next;
            self.release(old_bytes);
        }
        operations.push(op);
    }
}

/// Interning needs get/insert only. Explicit slot storage makes allocation
/// sizes and old/new growth overlap independent of std HashMap internals.
/// RandomState hashes integer metadata; full-key equality resolves collisions.
static NEXT_MAP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
/// An empty probe carries no allocation permission. Its private identity and
/// generation bind it to one unchanged table; stale probes use normal insert.
pub(super) struct Vacant<K> {
    key: K,
    slot: usize,
    tag: u8,
    identity: u64,
    generation: u64,
}
pub(super) struct Map<K, V> {
    slots: Vec<Option<(K, V)>>,
    // Zero is vacant; an occupied byte contains seven high hash bits. Keep
    // payloads initialized so reset can clear only these dense bytes safely.
    control: Vec<u8>,
    entries: usize,
    hash: RandomState,
    identity: u64,
    generation: u64,
}

impl<K: Copy + Eq + Hash, V: Copy> Map<K, V> {
    pub(super) fn new() -> Self {
        Self {
            slots: Vec::new(),
            control: Vec::new(),
            entries: 0,
            hash: RandomState::new(),
            identity: NEXT_MAP
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |id| id.checked_add(1),
                )
                .expect("compiler map identity exhausted"),
            generation: 0,
        }
    }

    fn index(&self, key: &K) -> (usize, u8) {
        let hash = self.hash.hash_one(key);
        let tag = ((hash >> 57) as u8) | 0x80;
        if self.slots.is_empty() {
            return (0, tag);
        }
        let mask = self.slots.len() - 1;
        let mut index = hash as usize & mask;
        loop {
            let control = self.control[index];
            if control == 0
                || (control == tag
                    && self.slots[index]
                        .as_ref()
                        .is_some_and(|(stored, _)| stored == key))
            {
                return (index, tag);
            }
            index = (index + 1) & mask;
        }
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        if self.slots.is_empty() {
            return None;
        }
        let (index, _) = self.index(key);
        (self.control[index] != 0).then(|| &self.slots[index].as_ref().unwrap().1)
    }

    pub(super) fn probe(&self, key: K) -> Result<V, Vacant<K>> {
        let (slot, tag) = self.index(&key);
        if self.control.get(slot).is_some_and(|&control| control != 0) {
            return Ok(self.slots[slot].unwrap().1);
        }
        Err(Vacant {
            key,
            slot,
            tag,
            identity: self.identity,
            generation: self.generation,
        })
    }
    pub(super) fn insert_vacant(
        &mut self,
        vacant: Vacant<K>,
        value: V,
        budget: &mut Budget,
    ) -> Option<V> {
        if budget.failed {
            return None;
        }
        if vacant.identity != self.identity
            || vacant.generation != self.generation
            || self.entries == self.slots.len() / 8 * 7
        {
            return self.insert(vacant.key, value, budget);
        }
        // An unchanged generation guarantees the probed slot is still empty.
        let Some(next) = self.generation.checked_add(1) else {
            budget.reject();
            return None;
        };
        self.slots[vacant.slot] = Some((vacant.key, value));
        self.control[vacant.slot] = vacant.tag;
        self.entries += 1;
        self.generation = next;
        None
    }

    pub(super) fn clear(&mut self, budget: &mut Budget) -> usize {
        let bytes = self
            .retained_bytes()
            .expect("admitted compiler map backing");
        drop(std::mem::take(&mut self.slots));
        drop(std::mem::take(&mut self.control));
        self.entries = 0;
        self.generation = self.generation.checked_add(1).unwrap_or_else(|| {
            budget.reject();
            u64::MAX
        });
        budget.release(bytes);
        bytes
    }
    /// A numeric worker can retain this backing under its original compiler
    /// reservation. Clear all keys and invalidate outstanding probes; the next
    /// builder must charge the complete capacity before using it.
    pub(super) fn reset_retained(&mut self) -> Option<usize> {
        self.generation = self.generation.checked_add(1)?;
        self.control.fill(0);
        self.entries = 0;
        self.retained_bytes()
    }

    pub(super) fn retained_bytes(&self) -> Option<usize> {
        self.slots
            .capacity()
            .checked_mul(size_of::<Option<(K, V)>>())
            .and_then(|n| n.checked_add(self.control.capacity()))
    }

    pub(super) fn insert(&mut self, key: K, value: V, budget: &mut Budget) -> Option<V> {
        if budget.failed {
            return None;
        }
        // Reuse the empty slot found by the initial probe unless growth moves
        // the table. Full-key equality and randomized hashing are unchanged.
        let mut slot = None;
        if !self.slots.is_empty() {
            let (index, tag) = self.index(&key);
            slot = Some((index, tag));
            if self.control[index] != 0 {
                let previous = self.slots[index].unwrap().1;
                self.slots[index] = Some((key, value));
                return Some(previous);
            }
        }
        if self.entries == self.slots.len() / 8 * 7 {
            let Some(capacity) = self.slots.len().checked_mul(2).map(|n| n.max(8)) else {
                budget.reject();
                return None;
            };
            let Some(bytes) = capacity.checked_mul(size_of::<Option<(K, V)>>() + 1) else {
                budget.reject();
                return None;
            };
            if !budget.reserve(bytes) {
                return None;
            }
            let mut next = Vec::new();
            let mut control = Vec::new();
            if next.try_reserve_exact(capacity).is_err()
                || control.try_reserve_exact(capacity).is_err()
            {
                drop(next);
                drop(control);
                budget.release(bytes);
                budget.reject();
                return None;
            }
            next.resize(capacity, None);
            control.resize(capacity, 0);
            let old_bytes = self
                .retained_bytes()
                .expect("admitted compiler map backing");
            let old = std::mem::replace(&mut self.slots, next);
            let old_control = std::mem::replace(&mut self.control, control);
            for (entry, &occupied) in old.iter().zip(&old_control) {
                if occupied != 0 {
                    let (stored, value) = entry.unwrap();
                    let (index, tag) = self.index(&stored);
                    self.slots[index] = Some((stored, value));
                    self.control[index] = tag;
                }
            }
            drop(old);
            drop(old_control);
            budget.release(old_bytes);
            slot = None;
        }
        let (index, tag) = slot.unwrap_or_else(|| self.index(&key));
        let Some(next) = self.generation.checked_add(1) else {
            budget.reject();
            return None;
        };
        self.slots[index] = Some((key, value));
        self.control[index] = tag;
        self.entries += 1;
        self.generation = next;
        None
    }
}

pub(super) struct Set(Map<Wire, ()>);
impl Set {
    pub(super) fn new() -> Self {
        Self(Map::new())
    }
    pub(super) fn insert(&mut self, key: Wire, budget: &mut Budget) -> bool {
        let existed = self.0.insert(key, (), budget).is_some();
        !budget.failed && !existed
    }
    pub(super) fn reset_retained(&mut self) -> Option<usize> {
        self.0.reset_retained()
    }
}

#[cfg(test)]
mod tests;
