//! Managed capacity held across a serial proof, including its existing live
//! allocations. This is not a shape/peak predictor or physical VRAM/RSS bound.
//! Allocation leases still own actual buffers after the capacity owner ends.
use super::Accounting;
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex},
    thread::{self, ThreadId},
};

#[derive(Debug, Clone, Copy)]
pub(super) struct State {
    generation: u64,
    owner: ThreadId,
    ceiling: usize,
    outside_live: usize,
}

impl State {
    /// Existing allocations are included once in the proof's total envelope.
    /// New allocations on another thread may use only unreserved capacity.
    pub(super) fn check(
        &self,
        live: usize,
        bytes: usize,
        limit: usize,
    ) -> Result<Option<u64>, String> {
        if self.owner == thread::current().id() {
            let owned = live
                .checked_sub(self.outside_live)
                .and_then(|n| n.checked_add(bytes))
                .ok_or("GPU proof capacity accounting overflow")?;
            if owned > self.ceiling {
                return Err("GPU proof managed capacity exceeded".into());
            }
            Ok(None)
        } else {
            let committed = self
                .ceiling
                .checked_add(self.outside_live)
                .and_then(|n| n.checked_add(bytes))
                .ok_or("GPU reserved capacity accounting overflow")?;
            if committed > limit {
                return Err("GPU managed capacity is reserved by another proof".into());
            }
            Ok(Some(self.generation))
        }
    }

    pub(super) fn charge_outside(&mut self, generation: u64, bytes: usize) {
        debug_assert_eq!(generation, self.generation);
        // check() has already checked the enclosing sum under this same lock.
        self.outside_live += bytes;
    }

    pub(super) fn release_outside(&mut self, generation: u64, bytes: usize) {
        if generation == self.generation {
            self.outside_live -= bytes;
        }
    }
}

/// The allocating caller must keep the owner on its original thread. A later
/// thread may drop an actual allocation; its generation prevents that drop
/// from changing a newer reservation's outside-allocation accounting.
pub(super) struct Lease {
    accounting: Arc<Mutex<Accounting>>,
    generation: u64,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Lease {
    pub(super) fn new(
        accounting: Arc<Mutex<Accounting>>,
        ceiling: usize,
        limit: usize,
    ) -> Result<Self, String> {
        Self::new_checked(accounting, ceiling, limit, |_| Ok(()))
    }

    /// Check a complete request against the same live snapshot used to grant
    /// its owner. Refusal must not consume a generation or change counters.
    /// The callback is metadata-only and must not reenter the allocator.
    pub(super) fn new_checked(
        accounting: Arc<Mutex<Accounting>>,
        ceiling: usize,
        limit: usize,
        admit: impl FnOnce(usize) -> Result<(), String>,
    ) -> Result<Self, String> {
        let generation = {
            let mut a = accounting.lock().map_err(|_| "GPU accounting poisoned")?;
            if ceiling == 0 || ceiling > limit || a.live > ceiling {
                return Err("GPU proof capacity cannot include existing allocations".into());
            }
            if a.proof_capacity.is_some() {
                return Err("GPU proof capacity already has an owner".into());
            }
            admit(a.live)?;
            let generation = a
                .capacity_generation
                .checked_add(1)
                .ok_or("GPU proof capacity generation exhausted")?;
            a.proof_capacity = Some(State {
                generation,
                owner: thread::current().id(),
                ceiling,
                outside_live: 0,
            });
            a.capacity_generation = generation;
            generation
        };
        Ok(Self {
            accounting,
            generation,
            _thread_bound: PhantomData,
        })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // The allocator cannot be reused after poisoning. Do not double-panic
        // during unwinding or alter actual allocation ownership/counters here.
        if let Ok(mut a) = self.accounting.lock() {
            if a.proof_capacity
                .as_ref()
                .is_some_and(|c| c.generation == self.generation)
            {
                a.proof_capacity = None;
            }
        }
    }
}

#[cfg(test)]
mod tests;
