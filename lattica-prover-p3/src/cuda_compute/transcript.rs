//! Resident Poseidon2 duplex state with bounded snapshots and shared retirement.
//! A failed mutating operation retires its entire family; there is no CPU replay.
use super::{Argument, Buffer, Kernel, Launch, Limits, Result, Runtime};
use crate::{gpu_matrix::GOLDILOCKS_MODULUS, transcript_limits as limits};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, MutexGuard,
};

pub(super) const SOURCE: &str = concat!(
    include_str!("field.cuh"),
    include_str!("poseidon2.cuh"),
    include_str!("transcript.cu")
);
const SINGLE: Launch = Launch {
    blocks: 1,
    threads: 1,
    shared_bytes: 0,
};

// The CUDA kernels' private state layout is fixed by the pinned duplex ABI.
const _: () = assert!(limits::STATE_WORDS == 18 && limits::LIVE_STATES > 0);
const _: () = assert!(limits::BATCH_WORDS <= u32::MAX as usize);
const _: () = assert!(limits::GRIND_BATCH <= 1 << 16 && limits::GRIND_TILE == 256);

struct Family {
    failed: Mutex<bool>,
    states: AtomicUsize,
    limit: usize,
}

struct Slot(Arc<Family>);
impl Slot {
    fn acquire(&self) -> Result<Self> {
        self.0
            .states
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                if live < self.0.limit {
                    live.checked_add(1)
                } else {
                    None
                }
            })
            .map_err(|_| "CUDA transcript snapshot limit exhausted")?;
        Ok(Self(self.0.clone()))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.states.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Execution<'a> {
    failed: MutexGuard<'a, bool>,
    started: bool,
    complete: bool,
}
impl<'a> Execution<'a> {
    fn new(family: &'a Family) -> Result<Self> {
        let failed = family
            .failed
            .lock()
            .map_err(|_| "CUDA transcript family poisoned")?;
        if *failed {
            return Err("CUDA transcript family has been retired".into());
        }
        Ok(Self {
            failed,
            started: false,
            complete: false,
        })
    }
    fn begin(&mut self) {
        self.started = true;
    }
    fn finish(mut self) {
        self.complete = true;
    }
}
impl Drop for Execution<'_> {
    fn drop(&mut self) {
        if self.started && !self.complete {
            *self.failed = true;
        }
    }
}

pub(crate) struct TranscriptAttempt {
    family: Arc<Family>,
    complete: bool,
}
impl TranscriptAttempt {
    pub(crate) fn complete(mut self) {
        self.complete = true;
    }
}
impl Drop for TranscriptAttempt {
    fn drop(&mut self) {
        if !self.complete {
            *self.family.failed.lock().unwrap_or_else(|p| p.into_inner()) = true;
        }
    }
}

pub(crate) struct Transcripts {
    runtime: Runtime,
    constants: Buffer,
    observe: Kernel,
    sample: Kernel,
    candidates: Kernel,
    reduce: Kernel,
    commit: Kernel,
}

pub(crate) struct Transcript {
    // Erasure and native completion precede release of the live-state slot.
    state: Buffer,
    slot: Slot,
    engine: Arc<Transcripts>,
    #[cfg(test)]
    fault: Option<Fault>,
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CudaTranscript(<device-owned>)")
    }
}

pub(super) fn admission(
    words: &[usize],
    live: usize,
    allocations: usize,
    limits: Limits,
) -> Result<usize> {
    if live > limits.managed_bytes
        || words.len() > 3
        || allocations
            .checked_add(words.len())
            .is_none_or(|n| n > limits.max_allocations)
    {
        return Err("CUDA transcript allocation count exceeds allowance".into());
    }
    words.iter().try_fold(live, |total, &words| {
        let bytes = words
            .checked_mul(8)
            .filter(|&n| n != 0 && n <= limits.max_allocation_bytes)
            .ok_or("CUDA transcript allocation exceeds allowance")?;
        total
            .checked_add(bytes)
            .filter(|&n| n <= limits.managed_bytes)
            .ok_or_else(|| "CUDA transcript operation exceeds managed allowance".into())
    })
}

fn bit_mask(bits: usize) -> Result<u64> {
    if bits >= usize::BITS as usize || bits >= 64 || (1u64 << bits) >= GOLDILOCKS_MODULUS {
        return Err("CUDA transcript sample bit width is invalid".into());
    }
    Ok((1u64 << bits) - 1)
}

fn launch(count: usize) -> Launch {
    Launch {
        blocks: count.div_ceil(128) as u32,
        threads: 128,
        shared_bytes: 0,
    }
}

impl Transcripts {
    pub(crate) fn new(runtime: &Runtime) -> Result<Arc<Self>> {
        let module = runtime.compile(SOURCE)?;
        let result = Self {
            runtime: runtime.clone(),
            constants: super::commitment::poseidon_constants(runtime)?,
            observe: module.kernel("transcript_observe")?,
            sample: module.kernel("transcript_sample")?,
            candidates: module.kernel("transcript_grind_candidates")?,
            reduce: module.kernel("transcript_grind_reduce")?,
            commit: module.kernel("transcript_grind_commit")?,
        };
        for kernel in [
            &result.observe,
            &result.sample,
            &result.candidates,
            &result.reduce,
            &result.commit,
        ] {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA transcript exceeds private memory allowance".into());
            }
        }
        Ok(Arc::new(result))
    }

    fn admit(&self, words: &[usize]) -> Result<usize> {
        let snapshot = self.runtime.snapshot();
        admission(
            words,
            snapshot.live_bytes,
            snapshot.allocations,
            self.runtime.state.budget.limits,
        )
    }

    pub(crate) fn start(self: &Arc<Self>) -> Result<Transcript> {
        self.admit(&[limits::STATE_WORDS])?;
        let state = self.runtime.allocate(limits::STATE_WORDS)?;
        Ok(Transcript {
            state,
            slot: Slot(Arc::new(Family {
                failed: Mutex::new(false),
                states: AtomicUsize::new(1),
                limit: limits::LIVE_STATES,
            })),
            engine: self.clone(),
            #[cfg(test)]
            fault: None,
        })
    }
}

impl Transcript {
    pub(crate) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        if !Arc::ptr_eq(&self.engine.runtime.state, &runtime.state) {
            return Err("CUDA transcript belongs to another runtime".into());
        }
        self.check_live()
    }

    pub(crate) fn check_live(&self) -> Result<()> {
        let execution = Execution::new(&self.slot.0)?;
        drop(self.engine.runtime.state.enter()?);
        execution.finish();
        Ok(())
    }

    pub(crate) fn retire(&self) {
        *self.slot.0.failed.lock().unwrap_or_else(|p| p.into_inner()) = true;
    }

    pub(crate) fn begin_attempt(&self) -> Result<TranscriptAttempt> {
        self.check_live()?;
        Ok(TranscriptAttempt {
            family: self.slot.0.clone(),
            complete: false,
        })
    }

    pub(crate) fn check_scalars(&self, scalars: &super::Scalars) -> Result<()> {
        if !Arc::ptr_eq(&self.engine.runtime.state, &scalars.runtime.state) {
            return Err("CUDA scalar engine belongs to another transcript runtime".into());
        }
        self.check_live()
    }

    /// Scalar derivation cannot mutate or observe the duplex state. Any failure
    /// still retires this attempt family, including unwinds after a device write.
    pub(crate) fn derive_scalars<T>(
        &self,
        scalars: &super::Scalars,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.check_scalars(scalars)?;
        let mut execution = Execution::new(&self.slot.0)?;
        execution.begin();
        let result = operation()?;
        execution.finish();
        Ok(result)
    }

    pub(crate) fn snapshot(&self) -> Result<Self> {
        let mut execution = Execution::new(&self.slot.0)?;
        drop(self.engine.runtime.state.enter()?);
        self.engine.admit(&[limits::STATE_WORDS])?;
        let slot = self.slot.acquire()?;
        let state = self.engine.runtime.allocate(limits::STATE_WORDS)?;
        execution.begin();
        state.copy_from(0, &self.state, 0, limits::STATE_WORDS)?;
        #[cfg(test)]
        self.maybe_fail(Fault::Snapshot)?;
        let result = Self {
            state,
            slot,
            engine: self.engine.clone(),
            #[cfg(test)]
            fault: None,
        };
        execution.finish();
        Ok(result)
    }

    pub(crate) fn observe(&mut self, words: &[u64]) -> Result<()> {
        if words.len() > limits::BATCH_WORDS || words.iter().any(|&word| word >= GOLDILOCKS_MODULUS)
        {
            return Err("CUDA transcript observations must be bounded canonical fields".into());
        }
        let mut execution = Execution::new(&self.slot.0)?;
        drop(self.engine.runtime.state.enter()?);
        if !words.is_empty() {
            self.engine.admit(&[words.len()])?;
            let input = self.engine.runtime.allocate(words.len())?;
            execution.begin();
            input.write(0, words)?;
            self.observe_kernel(&input, 0, words.len())?;
            #[cfg(test)]
            self.maybe_fail(Fault::Observe)?;
        }
        execution.finish();
        Ok(())
    }

    /// Observe public device values directly. Canonicalization is on CUDA;
    /// private state never aliases an input buffer or leaves the device.
    pub(crate) fn observe_resident(
        &mut self,
        input: &Buffer,
        first: usize,
        count: usize,
    ) -> Result<()> {
        if count > limits::BATCH_WORDS
            || first.checked_add(count).is_none_or(|end| end > input.len())
            || !Arc::ptr_eq(input.owner(), &self.engine.runtime.state)
            || input.pointer() == self.state.pointer()
        {
            return Err(
                "CUDA resident transcript observation has invalid ownership or bounds".into(),
            );
        }
        let mut execution = Execution::new(&self.slot.0)?;
        drop(self.engine.runtime.state.enter()?);
        if count != 0 {
            execution.begin();
            self.observe_kernel(input, first, count)?;
            #[cfg(test)]
            self.maybe_fail(Fault::Observe)?;
        }
        execution.finish();
        Ok(())
    }

    fn observe_kernel(&self, input: &Buffer, first: usize, count: usize) -> Result<()> {
        // One lane owns the entire state. The admitted input range, distinct
        // state and immutable constants remain alive until completion.
        unsafe {
            self.engine.observe.launch(
                SINGLE,
                &[
                    Argument::Buffer(&self.state),
                    Argument::Buffer(input),
                    Argument::U64(first as u64),
                    Argument::U32(count as u32),
                    Argument::Buffer(&self.engine.constants),
                ],
            )?
        }
        .finish()?;
        Ok(())
    }

    pub(crate) fn sample_resident(&mut self, count: usize) -> Result<Buffer> {
        self.sample(count, u64::MAX, None)
    }

    pub(crate) fn sample_fields(&mut self, count: usize) -> Result<Vec<u64>> {
        self.sample_public(count, u64::MAX)
    }

    pub(crate) fn sample_bits(&mut self, bits: usize, count: usize) -> Result<Vec<u64>> {
        self.sample_public(count, bit_mask(bits)?)
    }

    fn sample_public(&mut self, count: usize, mask: u64) -> Result<Vec<u64>> {
        if !(1..=limits::BATCH_WORDS).contains(&count) {
            return Err("invalid CUDA transcript sample count".into());
        }
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(super::error)?;
        values.resize(count, 0);
        self.sample(count, mask, Some(&mut values))?;
        Ok(values)
    }

    fn sample(&mut self, count: usize, mask: u64, download: Option<&mut [u64]>) -> Result<Buffer> {
        if !(1..=limits::BATCH_WORDS).contains(&count) {
            return Err("invalid CUDA transcript sample count".into());
        }
        let mut execution = Execution::new(&self.slot.0)?;
        drop(self.engine.runtime.state.enter()?);
        self.engine.admit(&[count])?;
        let output = self.engine.runtime.allocate(count)?;
        execution.begin();
        // One lane serializes exactly count samples and owns all output words.
        unsafe {
            self.engine.sample.launch(
                SINGLE,
                &[
                    Argument::Buffer(&self.state),
                    Argument::Buffer(&output),
                    Argument::U32(count as u32),
                    Argument::U64(mask),
                    Argument::Buffer(&self.engine.constants),
                ],
            )?
        }
        .finish()?;
        if let Some(values) = download {
            output.read(0, values)?;
            if values
                .iter()
                .any(|&word| word >= GOLDILOCKS_MODULUS || word & !mask != 0)
            {
                return Err("CUDA transcript returned invalid public samples".into());
            }
        }
        #[cfg(test)]
        self.maybe_fail(Fault::Sample)?;
        execution.finish();
        Ok(output)
    }

    /// Zero-bit grinding is a no-op; zero-bit sampling above still consumes.
    pub(crate) fn grind(&mut self, bits: usize) -> Result<u64> {
        self.grind_bounded(bits, limits::GRIND_BATCH, limits::GRIND_CANDIDATES)
    }

    fn grind_bounded(&mut self, bits: usize, batch: usize, candidates: usize) -> Result<u64> {
        if bits > limits::GRIND_BITS
            || !(1..=limits::GRIND_BATCH).contains(&batch)
            || !(1..=limits::GRIND_CANDIDATES).contains(&candidates)
        {
            return Err("CUDA grinding difficulty or candidate bounds exceed allowance".into());
        }
        let mut execution = Execution::new(&self.slot.0)?;
        drop(self.engine.runtime.state.enter()?);
        if bits == 0 {
            execution.finish();
            return Ok(0);
        }
        let mask = bit_mask(bits)?;
        let batch = batch.min(candidates);
        let tiles = batch.div_ceil(limits::GRIND_TILE);
        self.engine.admit(&[batch, tiles, 2])?;
        let output = self.engine.runtime.allocate(batch)?;
        let minima = self.engine.runtime.allocate(tiles)?;
        let status = self.engine.runtime.allocate(2)?;
        for base in (0..candidates).step_by(batch) {
            let count = batch.min(candidates - base);
            let tiles = count.div_ceil(limits::GRIND_TILE);
            execution.begin();
            // Candidate lanes read immutable state; reduction partitions the
            // exact range, and the one-lane commit verifies before mutation.
            unsafe {
                self.engine.candidates.launch(
                    launch(count),
                    &[
                        Argument::Buffer(&self.state),
                        Argument::Buffer(&output),
                        Argument::U64(base as u64),
                        Argument::U32(count as u32),
                        Argument::U64(mask),
                        Argument::Buffer(&self.engine.constants),
                    ],
                )?
            }
            .finish()?;
            unsafe {
                self.engine.reduce.launch(
                    launch(tiles),
                    &[
                        Argument::Buffer(&output),
                        Argument::Buffer(&minima),
                        Argument::U32(count as u32),
                        Argument::U32(limits::GRIND_TILE as u32),
                    ],
                )?
            }
            .finish()?;
            unsafe {
                self.engine.commit.launch(
                    SINGLE,
                    &[
                        Argument::Buffer(&self.state),
                        Argument::Buffer(&minima),
                        Argument::Buffer(&status),
                        Argument::U32(tiles as u32),
                        Argument::U64(mask),
                        Argument::Buffer(&self.engine.constants),
                    ],
                )?
            }
            .finish()?;
            let mut result = [0; 2];
            status.read(0, &mut result)?;
            #[cfg(test)]
            self.maybe_fail(Fault::Grind)?;
            match result {
                [u64::MAX, 0] => (),
                [witness, 1] if (base as u64..(base + count) as u64).contains(&witness) => {
                    execution.finish();
                    return Ok(witness);
                }
                _ => return Err("CUDA grinding returned invalid witness/status".into()),
            }
        }
        Err("CUDA grinding candidate budget exhausted; retire proof attempt".into())
    }

    #[cfg(test)]
    fn maybe_fail(&self, at: Fault) -> Result<()> {
        if self.fault == Some(Fault::PanicSample) && at == Fault::Sample {
            panic!("injected CUDA transcript unwind after sampling");
        }
        if self.fault == Some(at) {
            Err("injected CUDA transcript failure".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Snapshot,
    Observe,
    Sample,
    Grind,
    PanicSample,
}

#[cfg(test)]
mod tests;
