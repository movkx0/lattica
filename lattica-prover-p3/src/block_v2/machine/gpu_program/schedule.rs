//! Compact host launch metadata retained after device instruction upload.

use super::{add, mul, ExecutionError, WitnessProgram};
use core::mem::size_of;
use core::ops::Range;

pub(crate) struct WitnessSchedule {
    pub(crate) waves: Box<[Range<usize>]>,
    pub(crate) wires: usize,
    pub(crate) publics: usize,
    pub(crate) witnesses: usize,
    pub(crate) height: usize,
    pub(crate) trace_width: usize,
    pub(crate) preprocessing_width: usize,
}

impl WitnessSchedule {
    /// Inline schedule plus its one exact-capacity allocation. A compiler
    /// produces at most one wave per operation, so callers can plan without
    /// constructing dependency scratch or inspecting private witness values.
    pub(crate) fn storage_bound(waves: usize) -> Result<usize, ExecutionError> {
        add(size_of::<Self>(), mul(waves, size_of::<Range<usize>>())?)
    }

    pub(crate) fn try_new(
        program: &WitnessProgram,
        allowance: usize,
    ) -> Result<Self, ExecutionError> {
        if Self::storage_bound(program.waves.len())? > allowance {
            return Err(ExecutionError::TooLarge);
        }
        let mut waves = Vec::new();
        waves
            .try_reserve_exact(program.waves.len())
            .map_err(|_| ExecutionError::TooLarge)?;
        if waves.capacity() != program.waves.len() {
            return Err(ExecutionError::TooLarge);
        }
        waves.extend_from_slice(&program.waves);
        Ok(Self {
            waves: waves.into_boxed_slice(),
            wires: program.wires,
            publics: program.publics,
            witnesses: program.witnesses,
            height: program.height,
            trace_width: program.trace_width(),
            preprocessing_width: program.preprocessing_width(),
        })
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        // Construction already checked this sum; Box length cannot grow.
        Self::storage_bound(self.waves.len()).expect("admitted witness schedule")
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
