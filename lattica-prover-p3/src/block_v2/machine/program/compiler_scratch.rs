//! Scoped compiler storage shares the operation/memo construction allowance.
//! The callback receives a slice: it cannot grow or retain the backing array.
use super::ScopedProgramBuilder;
use crate::block_v2::machine::verifier::CompileError;

fn reject(b: &mut ScopedProgramBuilder<'_>) -> CompileError {
    b.memory.reject();
    b.memory.report("rejected");
    CompileError::Shape("compiler scratch allowance")
}

struct Scratch<'a, 'backend, T> {
    builder: &'a mut ScopedProgramBuilder<'backend>,
    values: Vec<T>,
    bytes: usize,
    label: &'static str,
}

impl<T> Drop for Scratch<'_, '_, T> {
    fn drop(&mut self) {
        // Free the backing allocation before its reservation becomes reusable.
        drop(core::mem::take(&mut self.values));
        let before = self.builder.memory.live;
        self.builder.memory.release(self.bytes);
        if let Some(limit) = self.builder.memory.limit {
            eprintln!("bounded_compiler_scratch_release kind={} released_bytes={} live_before={} live_after={} peak_bytes={} limit_bytes={}",
                self.label, self.bytes, before, self.builder.memory.live,
                self.builder.memory.peak, limit);
        }
    }
}

impl ScopedProgramBuilder<'_> {
    pub(in super::super) fn with_compiler_scratch<T: Copy, R>(
        &mut self,
        label: &'static str,
        count: usize,
        initial: T,
        body: impl FnOnce(&mut Self, &mut [T]) -> Result<R, CompileError>,
    ) -> Result<R, CompileError> {
        let bytes = count
            .checked_mul(core::mem::size_of::<T>())
            .ok_or_else(|| reject(self))?;
        if !self.memory.reserve(bytes) {
            return Err(reject(self));
        }
        let mut values = Vec::new();
        if values.try_reserve_exact(count).is_err() || values.capacity() != count {
            self.memory.release(bytes);
            return Err(reject(self));
        }
        values.resize(count, initial);
        let mut scratch = Scratch {
            builder: self,
            values,
            bytes,
            label,
        };
        let result = body(scratch.builder, &mut scratch.values);
        drop(scratch);
        if self.resource_failure().is_some() {
            Err(reject(self))
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests;
