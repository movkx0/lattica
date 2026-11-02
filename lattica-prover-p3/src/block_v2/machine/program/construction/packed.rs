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
// Fixed-size compiler keys are prefix-free by type. Encode a tuple in one
// hasher write instead of repeatedly entering SipHash for individual words.
// RandomState and authoritative full-key equality remain unchanged. The
// transparent wrapper preserves the original tuple layout and wire niches.
pub(in super::super) trait KeyBytes {
    const BYTES: usize;
    fn encode(&self, out: &mut [u8]);
}
impl KeyBytes for u8 {
    const BYTES: usize = 1;
    fn encode(&self, out: &mut [u8]) {
        out[0] = *self;
    }
}
impl KeyBytes for NonZeroU32 {
    const BYTES: usize = 4;
    fn encode(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.get().to_le_bytes());
    }
}
impl<T: KeyBytes, const N: usize> KeyBytes for [T; N] {
    const BYTES: usize = T::BYTES * N;
    fn encode(&self, out: &mut [u8]) {
        if T::BYTES == 0 {
            return;
        }
        for (part, value) in out.chunks_exact_mut(T::BYTES).zip(self) {
            value.encode(part);
        }
    }
}
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct Triple<A, B, C>((A, B, C));
impl<A: KeyBytes + Hash, B: KeyBytes + Hash, C: KeyBytes + Hash> Hash for Triple<A, B, C> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = A::BYTES + B::BYTES + C::BYTES;
        if bytes > 32 {
            self.0.hash(state);
            return;
        }
        let mut encoded = [0u8; 32];
        self.0 .0.encode(&mut encoded[..A::BYTES]);
        self.0
             .1
            .encode(&mut encoded[A::BYTES..A::BYTES + B::BYTES]);
        self.0 .2.encode(&mut encoded[A::BYTES + B::BYTES..bytes]);
        state.write(&encoded[..bytes]);
    }
}
impl<A: Compact, B: Compact, C: Compact> Compact for (A, B, C)
where
    A::Stored: KeyBytes,
    B::Stored: KeyBytes,
    C::Stored: KeyBytes,
{
    type Stored = Triple<A::Stored, B::Stored, C::Stored>;
    fn store(self) -> Option<Self::Stored> {
        Some(Triple((self.0.store()?, self.1.store()?, self.2.store()?)))
    }
    fn load(value: Self::Stored) -> Self {
        (
            A::load(value.0 .0),
            B::load(value.0 .1),
            C::load(value.0 .2),
        )
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

/// Exact negative lookup filter for compiler-proven constants. Only public
/// wire identities enter this bitmap; witness values never affect it. Charge
/// its full capacity and old/new growth overlap just like the underlying map.
pub(in super::super) struct KnownConstants {
    values: Map<Wire, Val>,
    present: Vec<u64>,
    active: bool,
}

impl KnownConstants {
    pub(in super::super) fn new() -> Self {
        Self {
            values: Map::new(),
            present: Vec::new(),
            active: false,
        }
    }

    #[inline]
    pub(in super::super) fn get(&self, key: &Wire) -> Option<Val> {
        if self.present.get(key.0 / 64).copied().unwrap_or(0) & (1u64 << (key.0 % 64)) == 0 {
            return None;
        }
        self.values.get(key)
    }

    pub(in super::super) fn insert(&mut self, key: Wire, value: Val, budget: &mut Budget) {
        if budget.failed || key.0 >= MAX_WIRES {
            return;
        }
        let word = key.0 / 64;
        if word >= self.present.len() {
            let capacity = (word + 1).next_power_of_two().max(4);
            let bytes = capacity * size_of::<u64>();
            if !budget.reserve(bytes) {
                return;
            }
            let mut next = Vec::new();
            if next.try_reserve_exact(capacity).is_err() {
                budget.release(bytes);
                budget.reject();
                return;
            }
            let old_bytes = self.present.capacity() * size_of::<u64>();
            next.append(&mut self.present);
            next.resize(capacity, 0);
            self.present = next;
            budget.release(old_bytes);
        }
        self.present[word] |= 1u64 << (key.0 % 64);
        self.active = true;
        self.values.insert(key, value, budget);
    }

    pub(in super::super) fn reset_retained(&mut self) -> Option<usize> {
        self.values.reset_retained()?;
        if self.active {
            self.present.fill(0);
            self.active = false;
        }
        self.retained_bytes()
    }

    pub(in super::super) fn retained_bytes(&self) -> Option<usize> {
        self.values
            .retained_bytes()?
            .checked_add(self.present.capacity().checked_mul(size_of::<u64>())?)
    }

    pub(in super::super) fn release_retained(&mut self) -> Option<usize> {
        let bytes = self.retained_bytes()?;
        *self = Self::new();
        Some(bytes)
    }
}
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
