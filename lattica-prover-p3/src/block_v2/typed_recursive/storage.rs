//! Fixed session ownership, independent of the selected number of live keys.
//! This is logical Rust storage; stacks, allocator overhead and driver state
//! still require the enclosing worker's phase plan and OS enforcement.

use super::*;

pub(crate) const SESSION_HOST_BYTES: u64 = 1 << 20;
pub(super) const REGISTRY_HOST_BYTES: usize = 64 << 10;
// Inline binding plans are included in size_of::<Session>(). Reserve bounded
// capability-vector backing for every possible cached compilation receipt too.
pub(super) const COMPILATION_RECEIPT_BYTES: usize = 4 << 10;

// Session fields and registry backing remain live while bounded identity setup
// borrows that registry. Proof work starts after setup releases its workspace.
// Stacks, allocator/runtime overhead and caller owners remain separate.
pub(crate) const SESSION_STARTUP_HOST_BYTES: u64 =
    SESSION_HOST_BYTES + programs::registry_setup::INITIAL_STORAGE_BYTES as u64;

pub(super) fn admit_startup(total: u64) -> Result<(), Error> {
    if total < SESSION_STARTUP_HOST_BYTES {
        return Err("typed session requires RAM for bounded registry setup".into());
    }
    Ok(())
}

/// Shared by session admission and the process configuration before launch.
pub(crate) fn active_memory_bytes(total: u64, idle_cache: u64) -> Result<u64, Error> {
    total
        .checked_sub(SESSION_HOST_BYTES)
        .and_then(|free| free.checked_sub(idle_cache))
        .filter(|free| *free != 0)
        .ok_or_else(|| "typed session requires RAM beyond session and idle cache storage".into())
}

/// All slots are inline, including unused ones. No growth or shrink operation
/// can leave an uncharged vector allocation behind.
pub(super) struct Cache<T, const N: usize> {
    entries: [Option<T>; N],
    len: usize,
}

impl<T, const N: usize> Cache<T, N> {
    pub(super) fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries[..self.len]
            .iter()
            .map(|entry| entry.as_ref().unwrap())
    }

    pub(super) fn last(&self) -> Option<&T> {
        self.len
            .checked_sub(1)
            .and_then(|i| self.entries[i].as_ref())
    }

    pub(super) fn push(&mut self, entry: T) -> Result<(), Error> {
        if self.len == N {
            return Err("typed cache slot capacity".into());
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    pub(super) fn remove(&mut self, index: usize) -> T {
        assert!(index < self.len);
        let entry = self.entries[index].take().unwrap();
        self.entries[index..self.len].rotate_left(1);
        self.len -= 1;
        entry
    }

    pub(super) fn clear(&mut self) {
        while self.len != 0 {
            self.len -= 1;
            self.entries[self.len] = None;
        }
    }
}

impl<T, const N: usize> core::ops::Index<usize> for Cache<T, N> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.len);
        self.entries[index].as_ref().unwrap()
    }
}

pub(super) fn registry_backing<const N: usize>(registry: &Registry<N>) -> Result<usize, Error> {
    if !matches!(N, 5 | 6 | 12) {
        return Err("unsupported typed registry size".into());
    }
    let backing = registry
        .caps
        .iter()
        .try_fold(0usize, |bytes, cap| {
            bytes.checked_add(
                cap.capacity()
                    .checked_mul(core::mem::size_of::<[Val; 4]>())?,
            )
        })
        .ok_or("typed registry storage overflow")?;
    let bytes = core::mem::size_of::<Registry<N>>()
        .checked_add(backing)
        .ok_or("typed registry storage overflow")?;
    if bytes > REGISTRY_HOST_BYTES {
        return Err("typed registry storage allowance".into());
    }
    Ok(backing)
}

pub(super) fn admit_session<const N: usize>(registry: &Registry<N>) -> Result<u64, Error> {
    let bytes = core::mem::size_of::<Session<N>>()
        .checked_add(registry_backing(registry)?)
        .and_then(|bytes| bytes.checked_add(N.checked_mul(COMPILATION_RECEIPT_BYTES)?))
        .ok_or("typed session storage overflow")? as u64;
    if bytes > SESSION_HOST_BYTES {
        return Err("typed session storage allowance".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    fn registry<const N: usize>() -> Registry<N> {
        Registry {
            height: 2048,
            caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
        }
    }

    #[test]
    fn fixed_slots_preserve_lru_and_release_all_values() {
        struct Entry(u8, Rc<Cell<usize>>);
        impl Drop for Entry {
            fn drop(&mut self) {
                self.1.set(self.1.get() + 1);
            }
        }
        let dropped = Rc::new(Cell::new(0));
        let mut cache = Cache::<Entry, 3>::new();
        for id in 0..3 {
            cache.push(Entry(id, dropped.clone())).unwrap();
        }
        assert!(cache.push(Entry(3, dropped.clone())).is_err());
        assert_eq!(dropped.get(), 1);
        let hit = cache.remove(1);
        cache.push(hit).unwrap();
        assert_eq!(cache.iter().map(|e| e.0).collect::<Vec<_>>(), [0, 2, 1]);
        assert_eq!(cache.last().unwrap().0, 1);
        drop(cache.remove(0));
        assert_eq!(dropped.get(), 2);
        cache.clear();
        assert_eq!(dropped.get(), 4);
        assert_eq!(cache.len(), 0);
        assert!(cache.entries.iter().all(Option::is_none));
        cache.push(Entry(4, dropped.clone())).unwrap();
        drop(cache);
        assert_eq!(dropped.get(), 5);
    }

    #[test]
    fn registry_spare_capacity_is_charged_before_identity() {
        let mut registry = registry::<12>();
        let original = registry.id().unwrap();
        let normal = registry_backing(&registry).unwrap();
        registry.caps[0].reserve_exact(256);
        assert!(registry_backing(&registry).unwrap() > normal);
        assert_eq!(registry.id().unwrap(), original);
        registry.caps[0].reserve_exact(REGISTRY_HOST_BYTES / core::mem::size_of::<[Val; 4]>());
        assert!(registry_backing(&registry).is_err());
        assert!(registry.id().is_err());
        assert!(Session::new(registry, original, 512 << 20).is_err());
    }

    #[test]
    fn registry_storage_accepts_last_fitting_root_and_rejects_the_next() {
        let mut registry = registry::<12>();
        let pin = registry.id().unwrap();
        let other = core::mem::size_of::<Registry<12>>()
            + registry.caps[1..]
                .iter()
                .map(|c| c.capacity() * 32)
                .sum::<usize>();
        let roots = (REGISTRY_HOST_BYTES - other) / 32;
        let mut cap = Vec::with_capacity(roots);
        cap.extend_from_slice(&registry.caps[0]);
        registry.caps[0] = cap;
        assert_eq!(registry.id().unwrap(), pin);
        let bytes = registry_backing(&registry).unwrap() + core::mem::size_of::<Registry<12>>();
        assert!(bytes <= REGISTRY_HOST_BYTES && bytes + 32 > REGISTRY_HOST_BYTES);
        let mut cap = Vec::with_capacity(roots + 1);
        cap.extend_from_slice(&registry.caps[0]);
        registry.caps[0] = cap;
        assert!(registry.id().is_err());
        assert!(registry_backing(&self::registry::<4>()).is_err());
    }

    fn session<const N: usize>() {
        let registry = registry::<N>();
        let pin = registry.id().unwrap();
        let census = admit_session(&registry).unwrap();
        assert!(census <= SESSION_HOST_BYTES);
        assert!(
            census
                >= (core::mem::size_of::<Session<N>>()
                    + registry_backing(&registry).unwrap()
                    + N * COMPILATION_RECEIPT_BYTES) as u64
        );
        eprintln!("typed_session_storage keys={N} bytes={census} limit={SESSION_HOST_BYTES}");
        assert!(Session::new(registry.clone(), pin, SESSION_HOST_BYTES).is_err());
        let mut session = Session::new(registry, pin, SESSION_STARTUP_HOST_BYTES).unwrap();
        let active = SESSION_STARTUP_HOST_BYTES - SESSION_HOST_BYTES;
        assert!(session.configure_cache(N, active).is_err());
        assert_eq!(session.cache_entries, 1);
        session.configure_cache(N, active - 1).unwrap();
        assert_eq!(session.cache_entries, N);
        assert_eq!(admit_session(&session.registry).unwrap(), census);
        session.configure_cache(1, 0).unwrap();
        assert_eq!(session.cache_entries, 1);
        assert_eq!(session.cache_reserve_bytes, 0);
        assert_eq!(admit_session(&session.registry).unwrap(), census);
        assert!(session.configure_cache(0, 0).is_err());
        assert!(session.configure_cache(N + 1, 1).is_err());
        assert!(session.configure_cache(1, 1).is_err());
        assert!(session.configure_cache(N, 0).is_err());
        assert!(session.configure_cache(N, u64::MAX).is_err());
        assert_eq!(session.cache_entries, 1);
    }

    #[test]
    fn supported_sessions_cover_all_slots_and_budget_boundaries() {
        session::<5>();
        session::<6>();
        session::<12>();
    }
}
