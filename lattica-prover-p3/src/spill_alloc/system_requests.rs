//! Ownership of requests delegated by SpillAlloc to System. These are requested
//! bytes, not malloc usable sizes, arena ownership, retained pages or RSS.
//! No allocation, libc query, lock or environment lookup occurs on the hot path.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) static SYSTEM: Counter = Counter::new();

pub(super) struct Counter {
    live: AtomicUsize,
    peak: AtomicUsize,
    invalid: AtomicBool,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct Snapshot {
    pub live_requested_bytes: usize,
    pub peak_requested_bytes: usize,
    pub accounting_valid: bool,
}

impl Counter {
    const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            invalid: AtomicBool::new(false),
        }
    }

    #[inline]
    pub(super) fn allocated(&self, bytes: usize) {
        match self
            .live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(bytes)
            }) {
            Ok(previous) => {
                self.peak.fetch_max(previous + bytes, Ordering::Relaxed);
            }
            Err(_) => self.invalid.store(true, Ordering::Relaxed),
        }
    }

    #[inline]
    pub(super) fn deallocated(&self, bytes: usize) {
        if self
            .live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_sub(bytes)
            })
            .is_err()
        {
            // Never wrap an inconsistent census into a plausible byte count.
            // Diagnostic failure must not affect allocation/free semantics.
            self.invalid.store(true, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Snapshot {
        let live = self.live.load(Ordering::Relaxed);
        Snapshot {
            live_requested_bytes: live,
            // An allocator thread may still be publishing this observed live
            // value to peak. Both values are process-wide, non-atomic samples.
            peak_requested_bytes: self.peak.load(Ordering::Relaxed).max(live),
            accounting_valid: !self.invalid.load(Ordering::Relaxed),
        }
    }
}

pub(crate) fn snapshot() -> Snapshot {
    SYSTEM.snapshot()
}

#[cfg(test)]
mod allocator_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_thread_ownership_keeps_live_and_peak_bytes() {
        let counter = Counter::new();
        let held = std::sync::Barrier::new(5);
        let release = std::sync::Barrier::new(5);
        std::thread::scope(|scope| {
            for bytes in [13, 4096, 8192, 65536] {
                let (counter, held, release) = (&counter, &held, &release);
                scope.spawn(move || {
                    counter.allocated(bytes);
                    held.wait();
                    release.wait();
                    counter.deallocated(bytes);
                });
            }
            held.wait();
            let sample = counter.snapshot();
            assert_eq!(sample.live_requested_bytes, 13 + 4096 + 8192 + 65536);
            assert_eq!(sample.peak_requested_bytes, sample.live_requested_bytes);
            assert!(sample.accounting_valid);
            release.wait();
        });
        let sample = counter.snapshot();
        assert_eq!(sample.live_requested_bytes, 0);
        assert_eq!(sample.peak_requested_bytes, 13 + 4096 + 8192 + 65536);
        assert!(sample.accounting_valid);
    }

    #[test]
    fn overflow_and_unmatched_release_invalidate_without_wrapping() {
        for overflow in [false, true] {
            let counter = Counter::new();
            if overflow {
                counter.allocated(usize::MAX);
                counter.allocated(1);
                assert_eq!(counter.snapshot().live_requested_bytes, usize::MAX);
                counter.deallocated(usize::MAX);
            } else {
                counter.deallocated(1);
            }
            counter.allocated(7);
            counter.deallocated(7);
            let sample = counter.snapshot();
            assert_eq!(sample.live_requested_bytes, 0);
            assert!(!sample.accounting_valid);
        }
    }

    #[test]
    fn system_request_snapshot_does_not_allocate() {
        let (sample, requests) = super::super::allocation_requests::measure(snapshot);
        assert!(sample.accounting_valid);
        assert_eq!((requests.calls, requests.bytes), (0, 0));
        assert!(!requests.overflow);
    }
}
