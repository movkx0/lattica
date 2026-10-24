//! Reservation ownership for a serial worker; not an allocation measurement.
//!
//! A trusted planner must derive every requested footprint before allocation
//! or dispatch, including simultaneous output and temporary storage. These
//! counters cannot establish that derivation. The enclosing worker must also
//! charge this fixed ledger/token bookkeeping and allocator/process overhead.
//! No default execution path creates this ledger or changes its cache policy.
//!
//! The ledger is deliberately local to one serial worker, like ProvingContext.
//! Its Rc keeps accounting alive until the last reservation drops; no RefCell
//! borrow escapes an operation. Owners must move tokens with their data, keep
//! them live through asynchronous work, and drop them only after completion or
//! failure cleanup has released the corresponding data.
use std::{cell::RefCell, fmt, rc::Rc};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bytes {
    pub(crate) host: u64,
    pub(crate) device: u64,
}

impl Bytes {
    pub(crate) const ZERO: Self = Self { host: 0, device: 0 };

    fn checked_add(self, other: Self) -> Result<Self, Error> {
        Ok(Self {
            host: self.host.checked_add(other.host).ok_or(Error::Overflow)?,
            device: self
                .device
                .checked_add(other.device)
                .ok_or(Error::Overflow)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            host: self.host.checked_sub(other.host)?,
            device: self.device.checked_sub(other.device)?,
        })
    }

    fn maxima(self, other: Self) -> Self {
        Self {
            host: self.host.max(other.host),
            device: self.device.max(other.device),
        }
    }
}

/// Enclosing worker allowances, not extra storage added to existing limits.
/// A caller that accounts for other worker storage elsewhere must subtract it
/// before creating this ledger. There is no implicit idle-cache allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkerAllowance {
    pub(crate) host: u64,
    pub(crate) device: u64,
}

impl WorkerAllowance {
    fn bytes(self) -> Bytes {
        Bytes {
            host: self.host,
            device: self.device,
        }
    }
}

pub(crate) const CATEGORY_COUNT: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Category {
    NativeProof,
    RecursiveProof,
    RegisteredMetadata,
    CompilerInputs,
    SymbolicCompiler,
    Report,
    IndependentVerifier,
    /// Backend, endpoint, preprocessing and prover scratch when a trusted
    /// planner has bounded the complete phase. This name supplies no bound.
    PhaseScratch,
}

impl Category {
    pub(crate) const ALL: [Self; CATEGORY_COUNT] = [
        Self::NativeProof,
        Self::RecursiveProof,
        Self::RegisteredMetadata,
        Self::CompilerInputs,
        Self::SymbolicCompiler,
        Self::Report,
        Self::IndependentVerifier,
        Self::PhaseScratch,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Overflow,
    ExceedsWorkerAllowance {
        requested: Bytes,
        remaining: Bytes,
    },
    SplitExceedsReservation {
        category: Category,
        requested: Bytes,
        available: Bytes,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "retained resource admission: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Fixed-size, allocation-free requests. Copying a request conveys no memory
/// ownership or admission; only a successful ledger call issues a reservation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Requirements([Bytes; CATEGORY_COUNT]);

impl Requirements {
    pub(crate) const fn single(category: Category, bytes: Bytes) -> Self {
        let mut values = [Bytes::ZERO; CATEGORY_COUNT];
        values[category as usize] = bytes;
        Self(values)
    }

    /// Add a component only if both the category and full request still fit
    /// their integer representation. Failure leaves the request unchanged.
    pub(crate) fn add(&mut self, category: Category, bytes: Bytes) -> Result<(), Error> {
        let mut next = *self;
        next.0[category as usize] = next.0[category as usize].checked_add(bytes)?;
        next.total()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn get(self, category: Category) -> Bytes {
        self.0[category as usize]
    }

    pub(crate) fn total(self) -> Result<Bytes, Error> {
        self.0.into_iter().try_fold(Bytes::ZERO, Bytes::checked_add)
    }

    fn subtract(self, requested: Self) -> Result<Self, Error> {
        let mut remaining = self;
        for category in Category::ALL {
            remaining.0[category as usize] = self
                .get(category)
                .checked_sub(requested.get(category))
                .ok_or(Error::SplitExceedsReservation {
                    category,
                    requested: requested.get(category),
                    available: self.get(category),
                })?;
        }
        Ok(remaining)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CategoryCounters {
    pub(crate) current: Bytes,
    pub(crate) peak: Bytes,
}

/// Requested reservations only. Host/device peaks are independent maxima,
/// not necessarily values observed at the same instant. Category peaks need
/// not sum to the overall peak because category lifetimes may differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) allowance: WorkerAllowance,
    pub(crate) current: Bytes,
    pub(crate) peak: Bytes,
    pub(crate) categories: [CategoryCounters; CATEGORY_COUNT],
}

impl Snapshot {
    fn remaining(self) -> Bytes {
        self.allowance
            .bytes()
            .checked_sub(self.current)
            .expect("private ledger allowance invariant")
    }

    fn admitted(mut self, requested: Requirements) -> Result<Self, Error> {
        let total = requested.total()?;
        let next = self.current.checked_add(total)?;
        let remaining = self.remaining();
        if total.host > remaining.host || total.device > remaining.device {
            return Err(Error::ExceedsWorkerAllowance {
                requested: total,
                remaining,
            });
        }
        for category in Category::ALL {
            let counters = &mut self.categories[category as usize];
            counters.current = counters.current.checked_add(requested.get(category))?;
            counters.peak = counters.peak.maxima(counters.current);
        }
        self.current = next;
        self.peak = self.peak.maxima(next);
        Ok(self)
    }

    fn released(mut self, released: Requirements) -> Self {
        self.current = self
            .current
            .checked_sub(released.total().expect("private reservation sum invariant"))
            .expect("private reservation ownership invariant");
        for category in Category::ALL {
            let counters = &mut self.categories[category as usize];
            counters.current = counters
                .current
                .checked_sub(released.get(category))
                .expect("private reservation category invariant");
        }
        self
    }
}

/// Cloning a ledger handle shares the same allowance and counters. It does
/// not copy reservations or create a second worker allowance.
#[derive(Clone, Debug)]
pub(crate) struct Ledger(Rc<RefCell<Snapshot>>);

impl Ledger {
    pub(crate) fn new(allowance: WorkerAllowance) -> Self {
        Self(Rc::new(RefCell::new(Snapshot {
            allowance,
            current: Bytes::ZERO,
            peak: Bytes::ZERO,
            categories: [CategoryCounters::default(); CATEGORY_COUNT],
        })))
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        *self.0.borrow()
    }

    pub(crate) fn remaining(&self) -> Bytes {
        self.snapshot().remaining()
    }

    pub(crate) fn reserve(&self, category: Category, bytes: Bytes) -> Result<Reservation, Error> {
        self.admit_phase(Requirements::single(category, bytes))
    }

    /// Atomically reserve every output/temporary component before a phase.
    /// Existing tokens remain charged, so nested phases and retained children
    /// reduce the available host and device allowances independently. The
    /// planner must include all simultaneous new storage; no estimate, cache
    /// eviction, fallback, allocation or proof dispatch occurs here.
    pub(crate) fn admit_phase(&self, requested: Requirements) -> Result<Reservation, Error> {
        let mut state = self.0.borrow_mut();
        let next = state.admitted(requested)?;
        *state = next;
        Ok(Reservation {
            ledger: Rc::clone(&self.0),
            reserved: requested,
        })
    }
}

/// Non-Clone ownership of admitted storage. Attach this to the matching data
/// owner and keep it until that owner's allocations/work have been released.
/// Dropping the token early cannot make still-owned allocations safe.
#[must_use = "keep this reservation with the owner until data and work are released"]
#[derive(Debug)]
pub(crate) struct Reservation {
    ledger: Rc<RefCell<Snapshot>>,
    reserved: Requirements,
}

impl Reservation {
    pub(crate) fn requirements(&self) -> Requirements {
        self.reserved
    }

    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        Rc::ptr_eq(&self.ledger, &ledger.0)
    }

    /// Move a category-wise subset into another owner without releasing or
    /// re-reserving bytes. Refusal preserves this token and all counters.
    pub(crate) fn split(&mut self, requested: Requirements) -> Result<Self, Error> {
        let remaining = self.reserved.subtract(requested)?;
        let child = Self {
            ledger: Rc::clone(&self.ledger),
            reserved: requested,
        };
        self.reserved = remaining;
        Ok(child)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.ledger.borrow_mut();
        *state = state.released(self.reserved);
    }
}

#[cfg(test)]
mod tests;
