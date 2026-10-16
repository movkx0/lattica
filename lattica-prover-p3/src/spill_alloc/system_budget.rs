//! Admission for live and in-flight SpillAlloc-to-System requests. Reserve
//! before calling System and release only after failure or physical free.
//! This excludes System metadata/retention, foreign allocations and mappings.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Publish activation in the same atomic word as the reservation. An allocation
// racing activation must retry against the published limit before calling System.
const ACTIVE: usize = 1 << (usize::BITS - 1);
const MAX_BYTES: usize = ACTIVE - 1;

pub(super) static SYSTEM: Budget = Budget::new();

pub(super) struct Budget {
    state: AtomicUsize,
    limit: AtomicUsize,
    peak: AtomicUsize,
    rejected: AtomicUsize,
    invalid: AtomicBool,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct Snapshot {
    pub limit_bytes: Option<usize>,
    pub reserved_request_bytes: usize,
    pub peak_reserved_request_bytes: usize,
    pub rejected_requests: usize,
    pub accounting_valid: bool,
}

impl Budget {
    pub(super) const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            limit: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            invalid: AtomicBool::new(false),
        }
    }

    /// One installation attempt per process. A rejected installation never
    /// authorizes startup; a successful limit cannot be widened or removed.
    pub(super) fn install(&self, limit: usize) -> Result<(), &'static str> {
        if limit == 0 || limit > MAX_BYTES {
            return Err("invalid Rust System request limit");
        }
        self.limit
            .compare_exchange(0, limit, Ordering::Relaxed, Ordering::Relaxed)
            .map_err(|_| "Rust System request limit already configured")?;
        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & ACTIVE != 0 || state > limit || self.invalid.load(Ordering::Relaxed) {
                    None
                } else {
                    Some(state | ACTIVE)
                }
            })
            .map_err(|_| "existing Rust System requests exceed or invalidate admission")?;
        Ok(())
    }

    #[inline]
    pub(super) fn reserve(&self, bytes: usize) -> bool {
        let result = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if self.invalid.load(Ordering::Relaxed) {
                    return None;
                }
                let next = (state & MAX_BYTES).checked_add(bytes)?;
                let limit = if state & ACTIVE != 0 {
                    self.limit.load(Ordering::Relaxed)
                } else {
                    MAX_BYTES
                };
                (next <= limit).then_some((state & ACTIVE) | next)
            });
        match result {
            Ok(previous) => {
                self.peak
                    .fetch_max((previous & MAX_BYTES) + bytes, Ordering::Relaxed);
                true
            }
            Err(_) => {
                let _ = self
                    .rejected
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        Some(n.saturating_add(1))
                    });
                false
            }
        }
    }

    #[inline]
    pub(super) fn release(&self, bytes: usize) {
        if self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & MAX_BYTES)
                    .checked_sub(bytes)
                    .map(|next| (state & ACTIVE) | next)
            })
            .is_err()
        {
            self.invalid.store(true, Ordering::Relaxed);
        }
    }

    pub(super) fn invalidate(&self) {
        self.invalid.store(true, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        let state = self.state.load(Ordering::Acquire);
        let reserved = state & MAX_BYTES;
        Snapshot {
            limit_bytes: (state & ACTIVE != 0).then(|| self.limit.load(Ordering::Relaxed)),
            reserved_request_bytes: reserved,
            peak_reserved_request_bytes: self.peak.load(Ordering::Relaxed).max(reserved),
            rejected_requests: self.rejected.load(Ordering::Relaxed),
            accounting_valid: !self.invalid.load(Ordering::Relaxed),
        }
    }
}

pub(crate) fn snapshot() -> Snapshot {
    SYSTEM.snapshot()
}

/// Install before creating Rayon or GPU state, retaining the cap through exit.
pub(crate) fn admit_worker(limit: usize) -> Result<(), &'static str> {
    SYSTEM.install(limit)?;
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!(
            "bounded_system_requests {}",
            serde_json::json!({
                "schema": "lattica-system-request-budget-v1", "pid": std::process::id(),
                "boundary": "before_rayon", "snapshot": snapshot(),
                "reserves_before_system": true, "includes_in_flight": true,
                "immutable_until_exit": true, "is_rss_bound": false,
                "is_complete_allocator_bound": false,
            })
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
