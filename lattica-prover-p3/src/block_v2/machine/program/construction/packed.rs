//! Compact only compiler-map backing. Public wires, instructions and manifests
//! keep their existing representation. Checked conversion prevents truncation.
//! Unrepresentable wires bypass interning; the unchanged operation validator
//! reports InvalidWire, rather than misclassifying it as allocation failure.
use super::super::{Val, Wire, MAX_WIRES};
use super::{Budget, Map as RawMap, Vacant as RawVacant};
use std::{hash::Hash, marker::PhantomData, num::NonZeroU32};

pub(in super::super) trait Compact: Copy {
    type Stored: Copy + Eq + Hash;
    fn store(self) -> Option<Self::Stored>;
    fn load(value: Self::Stored) -> Self;
}
macro_rules! identity {
    ($($t:ty),*) => { $(impl Compact for $t {
        type Stored = Self;
        fn store(self) -> Option<Self> { Some(self) }
        fn load(value: Self) -> Self { value }
    })* };
}
identity!(u8, u64, Val, ());
impl Compact for Wire {
    type Stored = NonZeroU32;
    fn store(self) -> Option<NonZeroU32> {
        // Reserve zero for vacant slots. The public wire zero encodes as one.
        if self.0 >= MAX_WIRES {
            return None;
        }
        NonZeroU32::new(u32::try_from(self.0).ok()?.checked_add(1)?)
    }
    fn load(value: NonZeroU32) -> Self {
        Wire((value.get() - 1) as usize)
    }
}
impl<A: Compact, B: Compact, C: Compact> Compact for (A, B, C) {
    type Stored = (A::Stored, B::Stored, C::Stored);
    fn store(self) -> Option<Self::Stored> {
        Some((self.0.store()?, self.1.store()?, self.2.store()?))
    }
    fn load(value: Self::Stored) -> Self {
        (A::load(value.0), B::load(value.1), C::load(value.2))
    }
}
impl<T: Compact, const N: usize> Compact for [T; N] {
    type Stored = [T::Stored; N];
    fn store(self) -> Option<Self::Stored> {
        let values = self.map(T::store);
        values
            .iter()
            .all(Option::is_some)
            .then(|| values.map(Option::unwrap))
    }
    fn load(value: Self::Stored) -> Self {
        value.map(T::load)
    }
}

pub(in super::super) enum Vacant<K: Compact> {
    Valid(RawVacant<K::Stored>),
    Invalid,
}
pub(in super::super) struct Map<K: Compact, V: Compact> {
    inner: RawMap<K::Stored, V::Stored>,
    _types: PhantomData<(K, V)>,
}
impl<K: Compact, V: Compact> Map<K, V> {
    pub(in super::super) fn new() -> Self {
        Self {
            inner: RawMap::new(),
            _types: PhantomData,
        }
    }
    pub(in super::super) fn get(&self, key: &K) -> Option<V> {
        self.inner.get(&key.store()?).copied().map(V::load)
    }
    pub(in super::super) fn probe(&self, key: K) -> Result<V, Vacant<K>> {
        let Some(key) = key.store() else {
            return Err(Vacant::Invalid);
        };
        self.inner.probe(key).map(V::load).map_err(Vacant::Valid)
    }
    pub(in super::super) fn insert(&mut self, key: K, value: V, budget: &mut Budget) -> Option<V> {
        let (Some(key), Some(value)) = (key.store(), value.store()) else {
            return None;
        };
        self.inner.insert(key, value, budget).map(V::load)
    }
    pub(in super::super) fn insert_vacant(
        &mut self,
        entry: Vacant<K>,
        value: V,
        budget: &mut Budget,
    ) -> Option<V> {
        let (Vacant::Valid(entry), Some(value)) = (entry, value.store()) else {
            return None;
        };
        self.inner.insert_vacant(entry, value, budget).map(V::load)
    }
    pub(in super::super) fn reset_retained(&mut self) -> Option<usize> {
        self.inner.reset_retained()
    }
    pub(in super::super) fn retained_bytes(&self) -> Option<usize> {
        self.inner.retained_bytes()
    }
    pub(in super::super) fn release_retained(&mut self) -> Option<usize> {
        let bytes = self.retained_bytes()?;
        *self = Self::new();
        Some(bytes)
    }
}
pub(in super::super) struct Set(Map<Wire, ()>);
impl Set {
    pub(in super::super) fn new() -> Self {
        Self(Map::new())
    }
    pub(in super::super) fn insert(&mut self, key: Wire, budget: &mut Budget) -> bool {
        let existed = self.0.insert(key, (), budget).is_some();
        !budget.failed && !existed
    }
    pub(in super::super) fn reset_retained(&mut self) -> Option<usize> {
        self.0.reset_retained()
    }
    pub(in super::super) fn retained_bytes(&self) -> Option<usize> {
        self.0.retained_bytes()
    }
    pub(in super::super) fn release_retained(&mut self) -> Option<usize> {
        self.0.release_retained()
    }
}

#[cfg(test)]
mod tests;
