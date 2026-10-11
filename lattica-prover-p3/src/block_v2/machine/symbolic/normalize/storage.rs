//! One normalization's cumulative requested storage, including discarded
//! nodes, retired growth arrays and returned output. This is not an RSS or
//! caller-lifetime bound. An explicit reference ties every memo to its quota.
use super::{CompileError, MAX_NODES};
use std::{cell::Cell, mem::size_of, sync::Arc};

pub(in crate::block_v2::machine::symbolic) const HOST_BYTES: usize = 64 << 20;
const _: () = assert!(HOST_BYTES as u64 <= super::super::HOST_BYTES);

#[derive(Clone, Copy, Default)]
struct State {
    bytes: usize,
    allocations: usize,
    arcs: usize,
    failed: bool,
}
#[derive(Clone, Copy)]
enum Purpose {
    Normalization,
    LookupPacking,
}
pub(in crate::block_v2::machine::symbolic) struct Storage {
    limit: usize,
    state: Cell<State>,
    report: bool,
    purpose: Purpose,
}
impl Storage {
    pub(in crate::block_v2::machine::symbolic) fn new(report: bool) -> Self {
        Self {
            limit: HOST_BYTES,
            state: Cell::default(),
            report,
            purpose: Purpose::Normalization,
        }
    }
    pub(in crate::block_v2::machine::symbolic) fn lookup(report: bool) -> Self {
        let mut storage = Self::new(report);
        storage.purpose = Purpose::LookupPacking;
        storage
    }
    pub(in crate::block_v2::machine::symbolic) fn lookup_limited(
        limit: usize,
        report: bool,
    ) -> Self {
        let mut storage = Self::lookup(report);
        storage.limit = limit;
        storage
    }
    #[cfg(test)]
    pub(in crate::block_v2::machine::symbolic) fn admitted_bytes(&self) -> usize {
        self.state.get().bytes
    }
    pub(in crate::block_v2::machine::symbolic) fn limited(limit: usize, report: bool) -> Self {
        Self {
            limit,
            state: Cell::default(),
            report,
            purpose: Purpose::Normalization,
        }
    }
    fn error() -> CompileError {
        CompileError::Shape("symbolic normalization allowance")
    }
    fn allowance_error(&self) -> CompileError {
        match self.purpose {
            Purpose::Normalization => Self::error(),
            Purpose::LookupPacking => CompileError::Shape("symbolic lookup packing allowance"),
        }
    }
    fn fail(&self) -> CompileError {
        self.state.set(State {
            failed: true,
            ..self.state.get()
        });
        self.allowance_error()
    }
    pub(super) fn check(&self) -> Result<(), CompileError> {
        if self.state.get().failed {
            Err(self.allowance_error())
        } else {
            Ok(())
        }
    }
    fn reserve(&self, bytes: usize, allocations: usize, arcs: usize) -> Result<(), CompileError> {
        self.check()?;
        let mut state = self.state.get();
        state.bytes = state
            .bytes
            .checked_add(bytes)
            .filter(|&n| n <= self.limit)
            .ok_or_else(|| self.fail())?;
        state.allocations = state
            .allocations
            .checked_add(allocations)
            .ok_or_else(|| self.fail())?;
        state.arcs = state.arcs.checked_add(arcs).ok_or_else(|| self.fail())?;
        self.state.set(state);
        Ok(())
    }
    fn allocate<T>(&self, count: usize, max: usize) -> Result<Vec<T>, CompileError> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .filter(|_| count <= max)
            .ok_or_else(|| self.fail())?;
        self.reserve(bytes, usize::from(count != 0), 0)?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| self.fail())?;
        if values.capacity() != count {
            return Err(self.fail());
        }
        Ok(values)
    }
    /// The caller fills at most `count` entries; initial capacity is exact.
    pub(in crate::block_v2::machine::symbolic) fn capacity<T>(
        &self,
        count: usize,
    ) -> Result<Vec<T>, CompileError> {
        self.allocate(count, MAX_NODES)
    }
    pub(in crate::block_v2::machine::symbolic) fn vector<T>(
        &self,
        count: usize,
        mut value: impl FnMut(usize) -> Result<T, CompileError>,
    ) -> Result<Vec<T>, CompileError> {
        let mut values = self.capacity(count)?;
        for i in 0..count {
            values.push(value(i)?);
            self.check()?;
        }
        Ok(values)
    }
    pub(in crate::block_v2::machine::symbolic) fn single<T>(
        &self,
        value: T,
    ) -> Result<Vec<T>, CompileError> {
        let mut values = self.capacity(1)?;
        values.push(value);
        Ok(values)
    }
    pub(in crate::block_v2::machine::symbolic) fn push<T>(
        &self,
        values: &mut Vec<T>,
        value: T,
    ) -> Result<(), CompileError> {
        self.check()?;
        if values.len() >= MAX_NODES {
            return Err(self.fail());
        }
        if values.len() == values.capacity() {
            let count = values
                .capacity()
                .checked_mul(2)
                .map(|n| n.max(4).min(MAX_NODES))
                .ok_or_else(|| self.fail())?;
            let mut next = self.capacity(count)?;
            next.append(values);
            *values = next;
        }
        values.push(value);
        Ok(())
    }
    pub(super) fn arc<T>(
        &self,
        value: impl FnOnce() -> Result<T, CompileError>,
    ) -> Result<Arc<T>, CompileError> {
        // Conservatively include Arc counters/padding. Allocator bookkeeping
        // remains part of the enclosing process allowance.
        let bytes = size_of::<T>()
            .checked_add(4 * size_of::<usize>())
            .ok_or_else(|| self.fail())?;
        self.reserve(bytes, 1, 1)?;
        let value = value()?;
        self.check()?;
        Ok(Arc::new(value))
    }
    pub(in crate::block_v2::machine::symbolic) fn string(
        &self,
        value: &str,
    ) -> Result<String, CompileError> {
        if value.len() > MAX_NODES {
            return Err(self.fail());
        }
        self.reserve(value.len(), usize::from(!value.is_empty()), 0)?;
        let mut output = String::new();
        output
            .try_reserve_exact(value.len())
            .map_err(|_| self.fail())?;
        if output.capacity() != value.len() {
            return Err(self.fail());
        }
        output.push_str(value);
        Ok(output)
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        if self.report {
            let state = self.state.get();
            let label = match self.purpose {
                Purpose::Normalization => "bounded_symbolic_normalization",
                Purpose::LookupPacking => "bounded_symbolic_lookup_packing",
            };
            eprintln!("{label} admitted_bytes={} allocations={} arc_admissions={} limit_bytes={} rejected={} unwinding={}",
                state.bytes, state.allocations, state.arcs, self.limit, state.failed, std::thread::panicking());
        }
    }
}

/// Pointer identity map, without iteration-dependent output or structural
/// interning. Load is at most one half and every backing array is explicit.
pub(in crate::block_v2::machine::symbolic) struct Map<'a, V> {
    storage: &'a Storage,
    slots: Vec<Option<(usize, V)>>,
    len: usize,
}
impl<'a, V> Map<'a, V> {
    pub(in crate::block_v2::machine::symbolic) fn new(storage: &'a Storage) -> Self {
        Self {
            storage,
            slots: Vec::new(),
            len: 0,
        }
    }
    pub(in crate::block_v2::machine::symbolic) fn len(&self) -> usize {
        self.len
    }
    fn hash(key: usize) -> usize {
        let mut value = key as u64;
        value ^= value >> 33;
        value = value.wrapping_mul(0xff51afd7ed558ccd);
        value ^= value >> 33;
        value = value.wrapping_mul(0xc4ceb9fe1a85ec53);
        (value ^ (value >> 33)) as usize
    }
    fn index(&self, key: usize) -> usize {
        let mut index = Self::hash(key) & (self.slots.len() - 1);
        while self.slots[index]
            .as_ref()
            .is_some_and(|(old, _)| *old != key)
        {
            index = (index + 1) & (self.slots.len() - 1);
        }
        index
    }
    pub(in crate::block_v2::machine::symbolic) fn get(&self, key: usize) -> Option<&V> {
        if self.slots.is_empty() {
            return None;
        }
        self.slots[self.index(key)].as_ref().map(|(_, value)| value)
    }
    pub(in crate::block_v2::machine::symbolic) fn insert(
        &mut self,
        key: usize,
        value: V,
    ) -> Result<(), CompileError> {
        self.storage.check()?;
        if !self.slots.is_empty() {
            let index = self.index(key);
            if self.slots[index].is_some() {
                self.slots[index] = Some((key, value));
                return Ok(());
            }
        }
        if self.len >= MAX_NODES {
            return Err(self.storage.fail());
        }
        if self.len >= self.slots.len() / 2 {
            let count = self
                .slots
                .len()
                .checked_mul(2)
                .map(|n| n.max(16))
                .ok_or_else(|| self.storage.fail())?;
            let mut slots = self.storage.allocate(count, 2 * MAX_NODES)?;
            slots.resize_with(count, || None);
            let mut next = Self {
                storage: self.storage,
                slots,
                len: self.len,
            };
            for entry in &mut self.slots {
                if let Some((key, value)) = entry.take() {
                    let index = next.index(key);
                    next.slots[index] = Some((key, value));
                }
            }
            *self = next;
        }
        let index = self.index(key);
        self.slots[index] = Some((key, value));
        self.len += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
