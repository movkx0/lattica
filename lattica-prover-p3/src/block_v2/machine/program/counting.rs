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
    // Fixed-size ports let optimized callers count a known opcode without
    // materializing the general WirePorts/Op representations. Validation and
    // read-count overflow checks are identical to the full compiler sink.
    #[inline(always)]
    fn ports<const R: usize, const W: usize, const KIND: u8>(
        &mut self,
        reads: [Wire; R],
        writes: [Wire; W],
        allocated: usize,
    ) -> Result<(), ExecutionError> {
        if reads.iter().any(|w| w.0 >= self.defined) {
            return Err(ExecutionError::InvalidWire);
        }
        self.reads = self
            .reads
            .checked_add(R as u64)
            .filter(|&n| n <= u32::MAX as u64)
            .ok_or(ExecutionError::TooLarge)?;
        for wire in writes {
            if wire.0 != self.defined || wire.0 >= allocated {
                return Err(ExecutionError::InvalidWire);
            }
            self.defined += 1;
        }
        if self.defined != allocated {
            return Err(ExecutionError::InvalidWire);
        }
        let count = match KIND {
            1 => &mut self.counts.cubic,
            2 => &mut self.counts.poseidon,
            _ => &mut self.counts.scalar,
        };
        *count = count.checked_add(1).ok_or(ExecutionError::TooLarge)?;
        Ok(())
    }
    #[inline(always)]
    fn observe(&mut self, op: &Op, allocated: usize) -> Result<(), ExecutionError> {
        match op {
            Op::Input { out, .. } | Op::Constant { out, .. } => {
                self.ports::<0, 1, 0>([], [*out], allocated)
            }
            Op::Bit { source, bit, out } => {
                if source.0 >= self.defined || *bit >= 64 {
                    return Err(ExecutionError::InvalidWire);
                }
                self.ports::<0, 1, 0>([], [*out], allocated)
            }
            Op::SelectHint { entries, bits, out } => {
                if bits.len() > 24
                    || entries.len() != 1usize << bits.len()
                    || entries.iter().chain(bits).any(|w| w.0 >= self.defined)
                {
                    return Err(ExecutionError::InvalidWire);
                }
                self.counts.hint_words = self
                    .counts
                    .hint_words
                    .checked_add(entries.len())
                    .and_then(|n| n.checked_add(bits.len()))
                    .ok_or(ExecutionError::TooLarge)?;
                self.ports::<0, 1, 0>([], [*out], allocated)
            }
            Op::Add { a, b, out } | Op::Mul { a, b, out } => {
                self.ports::<2, 1, 0>([*a, *b], [*out], allocated)
            }
            Op::Equal { a, b } => self.ports::<2, 0, 0>([*a, *b], [], allocated),
            Op::Boolean { a } => self.ports::<1, 0, 0>([*a], [], allocated),
            Op::Inverse { a, out } => self.ports::<1, 1, 0>([*a], [*out], allocated),
            Op::Select { bit, a, b, out } => {
                self.ports::<3, 1, 0>([*a, *b, *bit], [*out], allocated)
            }
            Op::CubicMul { a, b, out } => {
                self.ports::<6, 3, 1>([a[0], a[1], a[2], b[0], b[1], b[2]], *out, allocated)
            }
            Op::CubicInverse { a, out } => self.ports::<3, 3, 1>(*a, *out, allocated),
            Op::Poseidon { input, output } => self.ports::<8, 8, 2>(
                input.map(|w| Wire(w as usize)),
                output.map(|w| Wire(w as usize)),
                allocated,
            ),
        }
    }
}

impl ScopedProgramBuilder<'_> {
    #[inline(always)]
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
}

impl ScopedProgramBuilder<'static> {
    pub(in super::super) fn finish_counts(self) -> Result<ProgramCounts, ExecutionError> {
        let result = self.counts_result();
        WORKSPACE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some(state) = slot
                .as_mut()
                .filter(|s| Some(s.generation) == self.counting_workspace)
            {
                state.leased = false;
                if result.is_ok() {
                    state.cached = Some(self);
                }
            }
        });
        result
    }
    fn counts_result(&self) -> Result<ProgramCounts, ExecutionError> {
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

use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
};
struct WorkspaceState {
    generation: u64,
    cap: usize,
    dynamic: bool,
    leased: bool,
    cached: Option<ScopedProgramBuilder<'static>>,
    reuses: u64,
}
thread_local! {
    static WORKSPACE: RefCell<Option<WorkspaceState>> = const { RefCell::new(None) };
    static GENERATION: Cell<u64> = const { Cell::new(0) };
}
/// Recycles only numeric compiler interning tables within one CPU worker phase.
/// Fixed workspaces reserve `cap` for the entire scope. Dynamic workspaces
/// require an active-job grant before compilation and an exact retained-byte
/// charge while idle. The enclosing scheduler owns both reservations.
/// No instructions, witness values, proof material or numeric results are cached.
/// Transferable, cleared numeric compiler storage. No program, backend,
/// witness, descriptor or allocation authority crosses worker lifetimes.
/// Its owner must keep every retained byte reserved until it is dropped.
pub struct CountingBacking {
    constants: CompactMap<u64, Wire>,
    known: KnownConstants,
    expressions: CompactMap<(u8, Wire, Wire), Wire>,
    booleans: ConstructionSet,
    cubic_expressions: CompactMap<(u8, [Wire; 3], [Wire; 3]), [Wire; 3]>,
    selections: CompactMap<(Wire, Wire, Wire), Wire>,
    permutations: CompactMap<[Wire; 8], [Wire; 8]>,
}
impl CountingBacking {
    pub fn retained_bytes(&self) -> Result<usize, ExecutionError> {
        [
            self.constants.retained_bytes(),
            self.known.retained_bytes(),
            self.expressions.retained_bytes(),
            self.booleans.retained_bytes(),
            self.cubic_expressions.retained_bytes(),
            self.selections.retained_bytes(),
            self.permutations.retained_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes.ok_or(ExecutionError::TooLarge)?)
                .ok_or(ExecutionError::TooLarge)
        })
    }
}

pub struct CountingWorkspace {
    _thread: PhantomData<Rc<()>>,
}
impl CountingWorkspace {
    pub fn begin(cap: usize) -> Result<Self, ExecutionError> {
        if cap == 0 {
            return Err(ExecutionError::ProvingPolicy);
        }
        Self::create(cap, false)
    }
    /// Starts with no compiler buffers and no active allocation permission.
    pub fn begin_dynamic() -> Result<Self, ExecutionError> {
        Self::create(0, true)
    }
    fn create(cap: usize, dynamic: bool) -> Result<Self, ExecutionError> {
        WORKSPACE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            if slot.is_some() {
                return Err(ExecutionError::ProvingPolicy);
            }
            let generation = GENERATION.with(|g| {
                let next = g.get().checked_add(1).ok_or(ExecutionError::TooLarge)?;
                g.set(next);
                Ok(next)
            })?;
            *slot = Some(WorkspaceState {
                generation,
                cap,
                dynamic,
                leased: false,
                cached: None,
                reuses: 0,
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
    /// Export only idle dynamic backing. Clear occupancy before transfer;
    /// the old thread can no longer lease these buffers.
    pub fn take_backing(&self) -> Result<Option<CountingBacking>, ExecutionError> {
        WORKSPACE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            let state = slot.as_mut().ok_or(ExecutionError::ProvingPolicy)?;
            if !state.dynamic || state.leased || state.cap != 0 {
                return Err(ExecutionError::ProvingPolicy);
            }
            let Some(mut cached) = state.cached.take() else {
                return Ok(None);
            };
            cached
                .constants
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            cached
                .known
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            cached
                .expressions
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            cached
                .booleans
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            cached
                .cubic_expressions
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            cached
                .selections
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            cached
                .permutations
                .reset_retained()
                .ok_or(ExecutionError::TooLarge)?;
            Ok(Some(CountingBacking {
                constants: cached.constants,
                known: cached.known,
                expressions: cached.expressions,
                booleans: cached.booleans,
                cubic_expressions: cached.cubic_expressions,
                selections: cached.selections,
                permutations: cached.permutations,
            }))
        })
    }
    /// The caller retains the backing's existing charge; activation separately
    /// admits growth. Restoring into an occupied or leased workspace is refused.
    pub fn restore_backing(&self, backing: CountingBacking) -> Result<(), ExecutionError> {
        WORKSPACE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            let state = slot.as_mut().ok_or(ExecutionError::ProvingPolicy)?;
            if !state.dynamic || state.leased || state.cap != 0 || state.cached.is_some() {
                return Err(ExecutionError::ProvingPolicy);
            }
            let mut cached = ScopedProgramBuilder::new(0)?;
            cached.constants = backing.constants;
            cached.known = backing.known;
            cached.expressions = backing.expressions;
            cached.booleans = backing.booleans;
            cached.cubic_expressions = backing.cubic_expressions;
            cached.selections = backing.selections;
            cached.permutations = backing.permutations;
            state.cached = Some(cached);
            Ok(())
        })
    }
    pub fn reuses(&self) -> u64 {
        WORKSPACE.with(|slot| slot.borrow().as_ref().map_or(0, |s| s.reuses))
    }
    pub fn retained_bytes(&self) -> Result<usize, ExecutionError> {
        WORKSPACE.with(|slot| {
            let state = slot
                .try_borrow()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            let state = state.as_ref().ok_or(ExecutionError::ProvingPolicy)?;
            if state.leased {
                return Err(ExecutionError::ProvingPolicy);
            }
            state
                .cached
                .as_ref()
                .map_or(Ok(0), ScopedProgramBuilder::retained_counting_bytes)
        })
    }
    /// Caller charges max(cap, previously reported retained bytes) before this
    /// call. Shrinking occurs before any new compiler allocation can be made.
    pub fn activate(&self, cap: usize) -> Result<usize, ExecutionError> {
        WORKSPACE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            let state = slot.as_mut().ok_or(ExecutionError::ProvingPolicy)?;
            if !state.dynamic || state.leased || state.cap != 0 || cap == 0 {
                return Err(ExecutionError::ProvingPolicy);
            }
            let released = if let Some(cached) = state.cached.as_mut() {
                let before = cached.retained_counting_bytes()?;
                before - cached.trim_counting_maps(cap)?
            } else {
                0
            };
            state.cap = cap;
            Ok(released)
        })
    }
    /// Revokes growth permission and reports the exact requested map backing.
    /// A failed or abandoned builder cannot release this accounting authority.
    pub fn deactivate(&self) -> Result<usize, ExecutionError> {
        WORKSPACE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            let state = slot.as_mut().ok_or(ExecutionError::ProvingPolicy)?;
            if !state.dynamic || state.leased || state.cap == 0 {
                return Err(ExecutionError::ProvingPolicy);
            }
            let retained = state
                .cached
                .as_ref()
                .map_or(Ok(0), ScopedProgramBuilder::retained_counting_bytes)?;
            if retained > state.cap {
                return Err(ExecutionError::TooLarge);
            }
            state.cap = 0;
            Ok(retained)
        })
    }
    /// Runs on the owning idle worker. Credit is returned only after the maps
    /// have actually been dropped; no RSS observation authorizes admission.
    pub fn trim_idle(&self, limit: usize) -> Result<usize, ExecutionError> {
        WORKSPACE.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| ExecutionError::ProvingPolicy)?;
            let state = slot.as_mut().ok_or(ExecutionError::ProvingPolicy)?;
            if !state.dynamic || state.leased || state.cap != 0 {
                return Err(ExecutionError::ProvingPolicy);
            }
            state
                .cached
                .as_mut()
                .map_or(Ok(0), |cached| cached.trim_counting_maps(limit))
        })
    }
}
impl Drop for CountingWorkspace {
    fn drop(&mut self) {
        WORKSPACE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
impl ScopedProgramBuilder<'static> {
    fn retained_counting_bytes(&self) -> Result<usize, ExecutionError> {
        [
            self.constants.retained_bytes(),
            self.known.retained_bytes(),
            self.expressions.retained_bytes(),
            self.booleans.retained_bytes(),
            self.cubic_expressions.retained_bytes(),
            self.selections.retained_bytes(),
            self.permutations.retained_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes.ok_or(ExecutionError::TooLarge)?)
                .ok_or(ExecutionError::TooLarge)
        })
    }
    fn trim_counting_maps(&mut self, limit: usize) -> Result<usize, ExecutionError> {
        let mut total = self.retained_counting_bytes()?;
        while total > limit {
            let sizes = [
                self.constants.retained_bytes(),
                self.known.retained_bytes(),
                self.expressions.retained_bytes(),
                self.booleans.retained_bytes(),
                self.cubic_expressions.retained_bytes(),
                self.selections.retained_bytes(),
                self.permutations.retained_bytes(),
            ];
            let index = sizes
                .iter()
                .enumerate()
                .max_by_key(|(_, bytes)| **bytes)
                .unwrap()
                .0;
            let released = match index {
                0 => self.constants.release_retained(),
                1 => self.known.release_retained(),
                2 => self.expressions.release_retained(),
                3 => self.booleans.release_retained(),
                4 => self.cubic_expressions.release_retained(),
                5 => self.selections.release_retained(),
                _ => self.permutations.release_retained(),
            }
            .ok_or(ExecutionError::TooLarge)?;
            if released == 0 {
                return Err(ExecutionError::TooLarge);
            }
            total = total
                .checked_sub(released)
                .ok_or(ExecutionError::TooLarge)?;
        }
        Ok(total)
    }
    pub(in super::super) fn new_counting(
        publics: usize,
        limits: ConstructionLimits,
    ) -> Result<Self, ExecutionError> {
        // Construct the empty builder first: validation allocates no interning backing.
        let mut builder = Self::new_with_construction_limits(publics, limits)?;
        WORKSPACE.with(|slot| -> Result<(), ExecutionError> {
            let mut slot = slot.try_borrow_mut().map_err(|_| ExecutionError::ProvingPolicy)?;
            let Some(state) = slot.as_mut() else { return Ok(()); };
            if state.leased || limits.max_requested_program_bytes > state.cap {
                return Err(ExecutionError::ProvingPolicy);
            }
            if let Some(mut cached) = state.cached.take() {
                let mut bytes = Some(0usize);
                macro_rules! reset { ($($field:ident),+) => { $(
                    bytes = bytes.and_then(|n| cached.$field.reset_retained().and_then(|b| n.checked_add(b)));
                )+ }; }
                reset!(constants, known, expressions, booleans, cubic_expressions, selections, permutations);
                // Evict if the next job has a smaller cap. Never overlap old
                // backing with new allocations; the empty builder owns none.
                if bytes.is_some_and(|n| n <= limits.max_requested_program_bytes) {
                    if !builder.memory.reserve(bytes.unwrap()) { return Err(ExecutionError::TooLarge); }
                    macro_rules! reuse { ($($field:ident),+) => { $(
                        std::mem::swap(&mut builder.$field, &mut cached.$field);
                    )+ }; }
                    reuse!(constants, known, expressions, booleans, cubic_expressions, selections, permutations);
                    state.reuses += 1;
                }
            }
            state.leased = true;
            builder.counting_workspace = Some(state.generation);
            Ok(())
        })?;
        builder.counter = Some(Counter::new(publics));
        Ok(builder)
    }
}
#[cfg(test)]
mod tests;
