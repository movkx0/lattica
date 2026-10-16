//! Heap-request accounting for one program builder. Caller-owned proof data,
//! cached programs, fixed folding scratch and allocator/driver overhead have
//! separate enclosing reservations. These counters are not physical RSS.
use super::{Constants, ExecutionError, Op, Program, Row, Wire, MAX_WIRES};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::mem::size_of;

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
pub(super) struct Map<K, V> {
    slots: Vec<Option<(K, V)>>,
    entries: usize,
    hash: RandomState,
}

impl<K: Copy + Eq + Hash, V: Copy> Map<K, V> {
    pub(super) fn new() -> Self {
        Self {
            slots: Vec::new(),
            entries: 0,
            hash: RandomState::new(),
        }
    }

    fn index(&self, key: &K) -> usize {
        let mask = self.slots.len() - 1;
        let mut index = self.hash.hash_one(key) as usize & mask;
        loop {
            match &self.slots[index] {
                Some((stored, _)) if stored != key => index = (index + 1) & mask,
                _ => return index,
            }
        }
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        if self.slots.is_empty() {
            return None;
        }
        self.slots[self.index(key)].as_ref().map(|(_, value)| value)
    }

    pub(super) fn clear(&mut self, budget: &mut Budget) -> usize {
        let bytes = self.slots.capacity() * size_of::<Option<(K, V)>>();
        drop(std::mem::take(&mut self.slots));
        self.entries = 0;
        budget.release(bytes);
        bytes
    }

    pub(super) fn insert(&mut self, key: K, value: V, budget: &mut Budget) -> Option<V> {
        if budget.failed {
            return None;
        }
        if !self.slots.is_empty() {
            let index = self.index(&key);
            if let Some((_, previous)) = self.slots[index] {
                self.slots[index] = Some((key, value));
                return Some(previous);
            }
        }
        if self.entries == self.slots.len() / 8 * 7 {
            let Some(capacity) = self.slots.len().checked_mul(2).map(|n| n.max(8)) else {
                budget.reject();
                return None;
            };
            let Some(bytes) = capacity.checked_mul(size_of::<Option<(K, V)>>()) else {
                budget.reject();
                return None;
            };
            if !budget.reserve(bytes) {
                return None;
            }
            let mut next = Vec::new();
            if next.try_reserve_exact(capacity).is_err() {
                budget.release(bytes);
                budget.reject();
                return None;
            }
            next.resize(capacity, None);
            let old = std::mem::replace(&mut self.slots, next);
            for &(stored, value) in old.iter().flatten() {
                let index = self.index(&stored);
                self.slots[index] = Some((stored, value));
            }
            let old_bytes = old.capacity() * size_of::<Option<(K, V)>>();
            drop(old);
            budget.release(old_bytes);
        }
        let index = self.index(&key);
        self.slots[index] = Some((key, value));
        self.entries += 1;
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
}

#[cfg(test)]
mod tests;
