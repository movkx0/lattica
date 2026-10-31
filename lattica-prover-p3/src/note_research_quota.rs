//! Shared payload ownership for isolated private-note research. This ledger is
//! independent of GPU features and production transaction acceptance. It does
//! not claim process RSS, driver memory, allocator overhead or thread stacks.
//! Decoder, producer and verifier owners must retain their tokens until every
//! payload covered by those tokens has been destroyed or transferred.
use serde::Serialize;
use std::{cell::Cell, rc::Rc};

const MAX_ALLOWANCE_BYTES: u64 = 32 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimit;

impl core::fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("private-note shared host allowance exceeded")
    }
}
impl std::error::Error for ResourceLimit {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct QuotaSnapshot {
    pub allowance_bytes: usize,
    pub ledger_bytes: usize,
    pub live_reserved_bytes: usize,
    pub peak_reserved_bytes: usize,
    pub cumulative_reserved_bytes: usize,
    pub admitted_attempts: usize,
    pub rejected_attempts: usize,
}

/// Only `new` can construct this ledger. Its private counters cannot be
/// replaced by a caller-supplied byte receipt. Rc keeps all derived tokens on
/// one thread and alive even after the original decoding session is dropped.
pub struct Quota {
    limit: usize,
    live: Cell<usize>,
    peak: Cell<usize>,
    total: Cell<usize>,
    admitted: Cell<usize>,
    rejected: Cell<usize>,
}

#[repr(C)]
struct RcAllocation<T> {
    strong: Cell<usize>,
    weak: Cell<usize>,
    value: T,
}

/// Actual Rc allocation request, including both counters and alignment. The
/// enclosing Quota/Reservation handles remain in their owning object census.
pub const LEDGER_BYTES: usize = core::mem::size_of::<RcAllocation<Quota>>();

impl Quota {
    pub fn new(limit: usize) -> Result<Rc<Self>, ResourceLimit> {
        if limit < LEDGER_BYTES || limit as u64 > MAX_ALLOWANCE_BYTES {
            return Err(ResourceLimit);
        }
        Ok(Rc::new(Self {
            limit,
            live: Cell::new(LEDGER_BYTES),
            peak: Cell::new(LEDGER_BYTES),
            total: Cell::new(LEDGER_BYTES),
            admitted: Cell::new(0),
            rejected: Cell::new(0),
        }))
    }

    pub fn reserve(self: &Rc<Self>, bytes: usize) -> Result<Reservation, ResourceLimit> {
        let result = (|| {
            let live = self.live.get().checked_add(bytes).ok_or(ResourceLimit)?;
            let total = self.total.get().checked_add(bytes).ok_or(ResourceLimit)?;
            let admitted = self.admitted.get().checked_add(1).ok_or(ResourceLimit)?;
            if live > self.limit {
                return Err(ResourceLimit);
            }
            // Do not mutate any accepted accounting until every check passes.
            self.live.set(live);
            self.peak.set(self.peak.get().max(live));
            self.total.set(total);
            self.admitted.set(admitted);
            Ok(Reservation {
                quota: Rc::clone(self),
                bytes,
            })
        })();
        if result.is_err() {
            self.rejected.set(self.rejected.get().saturating_add(1));
        }
        result
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        QuotaSnapshot {
            allowance_bytes: self.limit,
            ledger_bytes: LEDGER_BYTES,
            live_reserved_bytes: self.live.get(),
            peak_reserved_bytes: self.peak.get(),
            cumulative_reserved_bytes: self.total.get(),
            admitted_attempts: self.admitted.get(),
            rejected_attempts: self.rejected.get(),
        }
    }
}

/// Move-only, non-Send ownership issued by the shared ledger. There is no
/// public constructor, Clone implementation, mutable byte setter or raw Rc
/// escape. Core proving can consume a token and test its source-derived
/// requirements instead of accepting an unauthenticated numeric preclaim.
#[must_use = "retain the token through destruction of its charged payload"]
pub struct Reservation {
    quota: Rc<Quota>,
    bytes: usize,
}

impl Reservation {
    pub fn reserved_bytes(&self) -> usize {
        self.bytes
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        self.quota.snapshot()
    }

    pub fn reserve_related(&self, bytes: usize) -> Result<Self, ResourceLimit> {
        self.quota.reserve(bytes)
    }

    /// Transfer existing ownership without creating new capacity or increasing
    /// reservation statistics. The remaining owner keeps its old charge on
    /// refusal. Zero-byte tokens may deliberately keep the same ledger alive.
    pub fn split_off(&mut self, bytes: usize) -> Result<Self, ResourceLimit> {
        let remaining = self.bytes.checked_sub(bytes).ok_or(ResourceLimit)?;
        let split = Self {
            quota: Rc::clone(&self.quota),
            bytes,
        };
        self.bytes = remaining;
        Ok(split)
    }

    pub fn same_ledger(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.quota, &other.quota)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // Each byte is owned by exactly one non-cloneable token, including
        // tokens created by checked splitting. Rc keeps the ledger alive.
        self.quota.live.set(self.quota.live.get() - self.bytes);
    }
}

#[cfg(test)]
mod tests;
