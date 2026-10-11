//! Test-only, allocation-free observation of requests on the calling thread.
//! This is an oracle for source-derived bounds, never a production admission rule.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Requests {
    pub(crate) bytes: usize,
    pub(crate) calls: usize,
    pub(crate) largest: usize,
    pub(crate) overflow: bool,
}

thread_local! {
    static CURRENT: Cell<Option<Requests>> = const { Cell::new(None) };
}

pub(super) fn observe(bytes: usize) {
    if GLOBAL_ON.load(Ordering::Acquire) {
        if GLOBAL_BYTES
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(bytes)
            })
            .is_err()
        {
            GLOBAL_OVERFLOW.store(true, Ordering::Relaxed);
        }
        if GLOBAL_CALLS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .is_err()
        {
            GLOBAL_OVERFLOW.store(true, Ordering::Relaxed);
        }
        GLOBAL_LARGEST.fetch_max(bytes, Ordering::Relaxed);
    }
    let _ = CURRENT.try_with(|slot| {
        if let Some(mut requests) = slot.get() {
            match requests.bytes.checked_add(bytes) {
                Some(total) => requests.bytes = total,
                None => requests.overflow = true,
            }
            match requests.calls.checked_add(1) {
                Some(total) => requests.calls = total,
                None => requests.overflow = true,
            }
            requests.largest = requests.largest.max(bytes);
            slot.set(Some(requests));
        }
    });
}

struct Scope;
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|slot| slot.set(None));
    }
}

pub(crate) fn measure<T>(work: impl FnOnce() -> T) -> (T, Requests) {
    CURRENT.with(|slot| {
        assert!(
            slot.get().is_none(),
            "allocation request observations cannot nest"
        );
        slot.set(Some(Requests::default()));
    });
    let scope = Scope;
    let value = work();
    let requests = CURRENT.with(|slot| slot.get().unwrap());
    drop(scope);
    (value, requests)
}

// Test-only process-wide requests for scoped Rayon work. Callers must finish
// every child job before returning and run tests serially. This does not count
// live bytes or exclude unrelated background requests; source bounds remain
// authoritative. The allocator hook takes no locks and allocates nothing.
static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static GLOBAL_ON: AtomicBool = AtomicBool::new(false);
static GLOBAL_BYTES: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_CALLS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_LARGEST: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_OVERFLOW: AtomicBool = AtomicBool::new(false);

struct GlobalScope;
impl Drop for GlobalScope {
    fn drop(&mut self) {
        GLOBAL_ON.store(false, Ordering::Release);
    }
}

pub(crate) fn measure_all<T>(work: impl FnOnce() -> T) -> (T, Requests) {
    let _lock = GLOBAL_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    GLOBAL_BYTES.store(0, Ordering::Relaxed);
    GLOBAL_CALLS.store(0, Ordering::Relaxed);
    GLOBAL_LARGEST.store(0, Ordering::Relaxed);
    GLOBAL_OVERFLOW.store(false, Ordering::Relaxed);
    let scope = GlobalScope;
    GLOBAL_ON.store(true, Ordering::Release);
    let value = work();
    drop(scope);
    let requests = Requests {
        bytes: GLOBAL_BYTES.load(Ordering::Acquire),
        calls: GLOBAL_CALLS.load(Ordering::Acquire),
        largest: GLOBAL_LARGEST.load(Ordering::Acquire),
        overflow: GLOBAL_OVERFLOW.load(Ordering::Acquire),
    };
    (value, requests)
}
