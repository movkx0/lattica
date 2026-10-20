//! Bounded, context-local timing events. Only consumed completion receipts may
//! return events; cached and in-flight pairs share the same reservation limit.
use super::{budget::Reservation, cleanup, device::State, error, Result};
use cudarc::driver::{result, sys, CudaContext};
use std::sync::{Arc, Mutex};

pub(super) struct Pool {
    idle: Mutex<Vec<Pair>>,
}

pub(super) struct Pair {
    pub start: sys::CUevent,
    pub end: sys::CUevent,
    context: Arc<CudaContext>,
    _reservation: Reservation,
}

// The owning State serializes access and binds this pair's CUDA context.
unsafe impl Send for Pair {}

impl Pool {
    pub fn new(capacity: usize) -> Self {
        // Limits::validate caps this at 64 before runtime construction.
        Self {
            idle: Mutex::new(Vec::with_capacity(capacity)),
        }
    }

    /// Caller holds the owning State's queue guard and has bound its context.
    pub fn take(&self, state: &State) -> Result<Pair> {
        let cached = self
            .idle
            .lock()
            .map_err(|_| "CUDA event pool poisoned")?
            .pop();
        if let Some(pair) = cached {
            state.budget.event_pair_used(false)?;
            return Ok(pair);
        }
        let reservation = state.budget.event_pair()?;
        let start = result::event::create(sys::CUevent_flags::CU_EVENT_DEFAULT).map_err(error)?;
        let end = match result::event::create(sys::CUevent_flags::CU_EVENT_DEFAULT) {
            Ok(end) => end,
            Err(error_value) => {
                cleanup(
                    unsafe { result::event::destroy(start).map_err(error) },
                    "partial timing event creation",
                );
                return Err(error(error_value));
            }
        };
        let pair = Pair {
            start,
            end,
            context: state.context.clone(),
            _reservation: reservation,
        };
        state.budget.event_pair_used(true)?;
        Ok(pair)
    }

    /// Called only after synchronization, timestamp collection and reporting.
    /// cuEventRecord may overwrite captured state, so no live receipt can share
    /// these handles with a later command or proof attempt.
    pub fn recycle(&self, pair: Pair) -> Result<()> {
        let mut idle = self.idle.lock().map_err(|_| "CUDA event pool poisoned")?;
        if idle.len() == idle.capacity() {
            return Err("CUDA event pool exceeds admitted host storage".into());
        }
        idle.push(pair);
        Ok(())
    }

    pub fn clear(&self) {
        // Also retire cached native handles after a failed/unwinding attempt.
        self.idle.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        cleanup(
            self.context.bind_to_thread().map_err(error),
            "timing event context",
        );
        cleanup(
            unsafe { result::event::destroy(self.start).map_err(error) },
            "start event destroy",
        );
        cleanup(
            unsafe { result::event::destroy(self.end).map_err(error) },
            "end event destroy",
        );
        // The reservation remains charged through both native destructions.
    }
}
