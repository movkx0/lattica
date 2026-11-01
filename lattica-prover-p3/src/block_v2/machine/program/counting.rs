//! Numeric compiler sink. It retains the normal folding/interning decisions,
//! but never retains instructions, hint payloads, packed rows or a Program.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct ProgramCounts {
    pub scalar: usize,
    pub cubic: usize,
    pub poseidon: usize,
    pub wires: usize,
    pub witnesses: usize,
    pub hint_words: usize,
    pub active_rows: usize,
    pub padded_rows: usize,
    pub requested_bytes_peak: usize,
}

pub(super) struct Counter {
    counts: ProgramCounts,
    defined: usize,
    reads: u64,
    error: Option<ExecutionError>,
}
impl Counter {
    pub(super) fn new(publics: usize) -> Self {
        Self {
            counts: ProgramCounts::default(),
            defined: publics,
            reads: 0,
            error: None,
        }
    }
    pub(super) fn operations(&self) -> usize {
        self.counts.scalar + self.counts.cubic + self.counts.poseidon
    }
    fn observe(&mut self, op: &Op, allocated: usize) -> Result<(), ExecutionError> {
        let valid = |wire: Wire| wire.0 < self.defined;
        match op {
            Op::Bit { source, bit, .. } if !valid(*source) || *bit >= 64 => {
                return Err(ExecutionError::InvalidWire)
            }
            Op::SelectHint { entries, bits, .. } => {
                if bits.len() > 24
                    || entries.len() != 1usize << bits.len()
                    || entries.iter().chain(bits).any(|&w| !valid(w))
                {
                    return Err(ExecutionError::InvalidWire);
                }
                self.counts.hint_words = self
                    .counts
                    .hint_words
                    .checked_add(entries.len())
                    .and_then(|n| n.checked_add(bits.len()))
                    .ok_or(ExecutionError::TooLarge)?;
            }
            _ => {}
        }
        let reads = op.reads();
        if reads.iter().any(|&w| !valid(w)) {
            return Err(ExecutionError::InvalidWire);
        }
        // A bound on all reads also bounds every individual u32 reference
        // count. The supported row domain is much smaller than this ceiling.
        self.reads = self
            .reads
            .checked_add(reads.len() as u64)
            .filter(|&n| n <= u32::MAX as u64)
            .ok_or(ExecutionError::TooLarge)?;
        for wire in op.writes() {
            if wire.0 != self.defined || wire.0 >= allocated {
                return Err(ExecutionError::InvalidWire);
            }
            self.defined += 1;
        }
        if self.defined != allocated {
            return Err(ExecutionError::InvalidWire);
        }
        let count = match op {
            Op::Poseidon { .. } => &mut self.counts.poseidon,
            Op::CubicMul { .. } | Op::CubicInverse { .. } => &mut self.counts.cubic,
            _ => &mut self.counts.scalar,
        };
        *count = count.checked_add(1).ok_or(ExecutionError::TooLarge)?;
        Ok(())
    }
}

impl ScopedProgramBuilder<'_> {
    pub(in super::super) fn new_counting(
        publics: usize,
        limits: ConstructionLimits,
    ) -> Result<Self, ExecutionError> {
        let mut builder = Self::new_with_construction_limits(publics, limits)?;
        builder.counter = Some(Counter::new(publics));
        Ok(builder)
    }
    pub(super) fn count_operation(&mut self, op: &Op) {
        if self.memory.failed {
            return;
        }
        let counter = self.counter.as_mut().expect("counting sink");
        if let Err(error) = counter.observe(op, self.wires) {
            counter.error = Some(error);
            self.memory.reject();
        }
    }
    pub(super) fn count_hint(
        &mut self,
        count: usize,
        bits: &[Wire],
        mut entry: impl FnMut(usize) -> Wire,
    ) -> Wire {
        if self.memory.failed {
            return Wire(0);
        }
        let defined = self.counter.as_ref().expect("counting sink").defined;
        if bits.len() > 24
            || count != 1usize << bits.len()
            || bits.iter().any(|w| w.0 >= defined)
            || (0..count).any(|i| entry(i).0 >= defined)
        {
            self.counter.as_mut().unwrap().error = Some(ExecutionError::InvalidWire);
            self.memory.reject();
            return Wire(0);
        }
        let out = self.allocate();
        if self.memory.failed {
            return out;
        }
        // SelectHint has no authenticated bus reads. Its dependencies were
        // checked above and its one scalar opcode defines the allocated wire.
        self.count_operation(&Op::Input { index: 0, out });
        let counter = self.counter.as_mut().unwrap();
        match counter
            .counts
            .hint_words
            .checked_add(count)
            .and_then(|n| n.checked_add(bits.len()))
        {
            Some(words) => counter.counts.hint_words = words,
            None => {
                counter.error = Some(ExecutionError::TooLarge);
                self.memory.reject();
            }
        }
        out
    }
    pub(in super::super) fn finish_counts(self) -> Result<ProgramCounts, ExecutionError> {
        let counter = self.counter.as_ref().ok_or(ExecutionError::ProvingPolicy)?;
        if let Some(error) = counter.error.or_else(|| self.resource_failure()) {
            return Err(error);
        }
        if self.folding.failure().is_some() {
            return Err(ExecutionError::CompilerBackend);
        }
        if counter.defined != self.wires {
            return Err(ExecutionError::InvalidWire);
        }
        let mut counts = counter.counts;
        counts.wires = self.wires;
        counts.witnesses = self.witnesses;
        counts.active_rows = self
            .publics
            .div_ceil(PUBLICS_PER_ROW)
            .checked_add(counts.poseidon)
            .and_then(|n| n.checked_add(counts.scalar.div_ceil(LANES)))
            .and_then(|n| n.checked_add(counts.cubic.div_ceil(EXT_LANES)))
            .ok_or(ExecutionError::TooLarge)?;
        counts.padded_rows = counts
            .active_rows
            .max(8)
            .checked_next_power_of_two()
            .filter(|&n| n <= 1 << 24)
            .ok_or(ExecutionError::InvalidHeight)?;
        counts.requested_bytes_peak = self.memory.peak;
        self.memory.report("counted");
        Ok(counts)
    }
}

#[cfg(test)]
mod tests;
