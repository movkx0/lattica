use super::{
    budget::{Reservation, Transfer},
    cleanup,
    device::State,
    error, Result, Runtime,
};
use cudarc::driver::{result, sys};
use std::{ops::Range, sync::Arc};

/// A bounded allocation of 64-bit words. Clones retain the same allocation;
/// every operation is ordered on its owning runtime's stream.
#[derive(Clone)]
pub(crate) struct Buffer {
    allocation: Arc<Allocation>,
}

struct Allocation {
    pointer: sys::CUdeviceptr,
    words: usize,
    // Reservations are released after native cleanup and before the context.
    _reservation: Reservation,
    state: Arc<State>,
}

impl Runtime {
    pub(crate) fn allocate(&self, words: usize) -> Result<Buffer> {
        let bytes = words
            .checked_mul(8)
            .ok_or("CUDA allocation size overflow")?;
        let reservation = self.state.budget.allocation(bytes)?;
        let guard = self.state.enter()?;
        let required = bytes
            .checked_add(self.state.budget.limits.headroom_bytes)
            .ok_or("CUDA allocation admission overflow")?;
        if self.state.context.mem_get_info().map_err(error)?.0 < required {
            return Err("CUDA allocation would consume required free memory headroom".into());
        }
        // Use synchronous allocations initially. An asynchronous allocator's
        // retained pool must be charged before it can replace this path.
        let pointer = unsafe { result::malloc_sync(bytes).map_err(error)? };
        let allocated = Buffer {
            allocation: Arc::new(Allocation {
                pointer,
                words,
                _reservation: reservation,
                state: self.state.clone(),
            }),
        };
        // CUDA's legacy "synchronous" device memset may return before the
        // device operation completes. Our compute stream is nonblocking, so it
        // does not inherit default-stream dependencies. Finish initialization
        // before a caller can launch on that stream or expose private storage.
        let initialized = unsafe { result::memset_d8_sync(pointer, 0, bytes).map_err(error) }
            .and_then(|()| self.state.context.synchronize().map_err(error));
        drop(guard);
        initialized?;
        Ok(allocated)
    }
}

impl Buffer {
    pub(crate) fn len(&self) -> usize {
        self.allocation.words
    }
    pub(super) fn pointer(&self) -> sys::CUdeviceptr {
        self.allocation.pointer
    }
    pub(super) fn owner(&self) -> &Arc<State> {
        &self.allocation.state
    }

    fn range(&self, first: usize, words: usize) -> Result<Range<usize>> {
        let end = first
            .checked_add(words)
            .filter(|n| *n <= self.len())
            .ok_or("CUDA transfer exceeds buffer bounds")?;
        Ok(first..end)
    }

    pub(crate) fn write(&self, first: usize, words: &[u64]) -> Result<()> {
        let range = self.range(first, words.len())?;
        if words.is_empty() {
            return Ok(());
        }
        let state = self.owner();
        let _guard = state.enter()?;
        state.drain()?;
        // The blocking copy keeps the borrowed host slice alive through DMA.
        // Pageable host copies may return after staging but before DMA. Drain
        // that default-stream transfer before the nonblocking compute stream.
        unsafe { result::memcpy_htod_sync(self.pointer() + (range.start * 8) as u64, words) }
            .and_then(|()| state.context.synchronize())
            .map_err(|e| {
                state.fail();
                error(e)
            })?;
        state.budget.transferred(Transfer::Upload, words.len() * 8)
    }

    pub(crate) fn read(&self, first: usize, words: &mut [u64]) -> Result<()> {
        let range = self.range(first, words.len())?;
        if words.is_empty() {
            return Ok(());
        }
        let state = self.owner();
        let _guard = state.enter()?;
        state.drain()?;
        unsafe { result::memcpy_dtoh_sync(words, self.pointer() + (range.start * 8) as u64) }
            .map_err(|e| {
                state.fail();
                error(e)
            })?;
        state
            .budget
            .transferred(Transfer::Download, words.len() * 8)
    }

    pub(crate) fn copy_from(
        &self,
        first: usize,
        source: &Self,
        source_first: usize,
        words: usize,
    ) -> Result<()> {
        let target = self.range(first, words)?;
        let input = source.range(source_first, words)?;
        if !Arc::ptr_eq(self.owner(), source.owner()) {
            return Err("CUDA device copy crosses runtime ownership".into());
        }
        if words == 0 {
            return Ok(());
        }
        if self.pointer() == source.pointer()
            && target.start < input.end
            && input.start < target.end
        {
            return Err("overlapping CUDA copies are not supported".into());
        }
        let state = self.owner();
        let _guard = state.enter()?;
        state.drain()?;
        unsafe {
            result::memcpy_dtod_sync(
                self.pointer() + (target.start * 8) as u64,
                source.pointer() + (input.start * 8) as u64,
                words * 8,
            )
        }
        .and_then(|()| state.context.synchronize())
        .map_err(|e| {
            state.fail();
            error(e)
        })?;
        state.budget.transferred(Transfer::Copy, words * 8)
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        let _guard = self.state.cleanup_lock();
        cleanup(self.state.drain(), "buffer drain");
        // All allocations are private by default. Clearing completes before
        // native free, budget release, or another attempt can reuse memory.
        cleanup(
            unsafe { result::memset_d8_sync(self.pointer, 0, self.words * 8).map_err(error) },
            "buffer clear",
        );
        cleanup(
            self.state.context.synchronize().map_err(error),
            "buffer clear completion",
        );
        cleanup(
            unsafe { result::free_sync(self.pointer).map_err(error) },
            "buffer free",
        );
    }
}
