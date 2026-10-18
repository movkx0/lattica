//! Exact, private ChaCha20 field streams. Only the imported seed and public
//! cursor/status metadata cross the host boundary; no CPU sample fallback.
use super::{Argument, Buffer, Kernel, Launch, Matrix, Result, Runtime};
use crate::{
    gpu_matrix::{Extension, MatrixSpec},
    gpu_random::{FieldStoragePlan, Plan, BATCH_WORDS, MAX_REJECTIONS, STREAM_WORDS, TILE_WORDS},
};
use rand_chacha::ChaCha20Rng;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

pub(super) const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("random.cu"));
mod replay;
pub(crate) use replay::ReplaySalts;
const MAX_STREAM_STATES: usize = 4096;
const LANES: u32 = 128;
const _: () = assert!(TILE_WORDS == 256 && BATCH_WORDS / TILE_WORDS == 4096);
// MaybeUninit permits wiping the entire dead object's storage after its normal
// destructor, including cached blocks and padding, without constructing invalid
// Rust values. A separate field guard also wipes if the destructor unwinds.
struct ImportStorage(Box<std::mem::MaybeUninit<ChaCha20Rng>>);
impl ImportStorage {
    fn scrub(&mut self) {
        let first = self.0.as_mut_ptr().cast::<u8>();
        for offset in 0..std::mem::size_of::<ChaCha20Rng>() {
            // SAFETY: this storage owns the full object; no typed access follows
            // its destruction. Every byte is writable, including padding.
            unsafe {
                std::ptr::write_volatile(first.add(offset), 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}
impl Drop for ImportStorage {
    fn drop(&mut self) {
        self.scrub();
    }
}
struct ImportedRng(ImportStorage);
impl ImportedRng {
    fn new(rng: ChaCha20Rng) -> Self {
        Self(ImportStorage(Box::new(std::mem::MaybeUninit::new(rng))))
    }
    fn rng(&self) -> &ChaCha20Rng {
        // SAFETY: construction initializes the value; destruction is exclusive.
        unsafe { self.0 .0.assume_init_ref() }
    }
}
impl Drop for ImportedRng {
    fn drop(&mut self) {
        // SAFETY: the initialized RNG is dropped once. The field guard owns only
        // MaybeUninit bytes, scrubs them, and then frees the allocation.
        unsafe {
            self.0 .0.assume_init_drop();
        }
    }
}
struct SeedBytes([u8; 32]);
impl Drop for SeedBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}
struct SeedWords([u64; 4]);
impl Drop for SeedWords {
    fn drop(&mut self) {
        for word in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(word, 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

pub(crate) struct Randoms {
    runtime: Runtime,
    chacha: Kernel,
    counts: Kernel,
    offsets: Kernel,
    scatter: Kernel,
    gather: Kernel,
    states: AtomicUsize,
}
struct Slot(Arc<Randoms>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.states.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Stream {
    // The private key is erased on its last buffer alias before slot retirement.
    key: Buffer,
    stream: u64,
    position: Mutex<u128>,
    failed: Arc<AtomicBool>,
    slot: Slot,
}
#[derive(Clone)]
pub(crate) struct DeviceRandom(Arc<Stream>);
impl std::fmt::Debug for DeviceRandom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CudaRandom(<redacted>)")
    }
}
pub(crate) struct RandomWords {
    storage: Buffer,
}
impl std::fmt::Debug for RandomWords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CudaRandomWords(<device-owned>)")
    }
}
impl RandomWords {
    pub(crate) fn len(&self) -> usize {
        self.storage.len()
    }
    pub(super) fn buffer(&self) -> &Buffer {
        &self.storage
    }
    #[cfg(test)]
    pub(crate) fn read_for_test(&self, allowance: usize) -> Result<Vec<u64>> {
        if self.len().checked_mul(8).is_none_or(|n| n > allowance) {
            return Err("CUDA random test readback exceeds allowance".into());
        }
        let mut output = vec![0; self.len()];
        self.storage.read(0, &mut output)?;
        Ok(output)
    }
}
struct Attempt<'a> {
    failed: &'a AtomicBool,
    started: bool,
    complete: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.started && !self.complete {
            self.failed.store(true, Ordering::Release);
        }
    }
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    AfterBatch,
    #[cfg(test)]
    PanicAfterBatch,
    #[cfg(test)]
    RejectAll,
    #[cfg(test)]
    InvalidStatus,
}
fn accepted_words(value: u64, count: usize) -> Result<usize> {
    if value > count as u64 {
        return Err("CUDA random compaction returned invalid status".into());
    }
    Ok(value as usize)
}

impl Randoms {
    pub(crate) fn new(runtime: &Runtime) -> Result<Arc<Self>> {
        let module = runtime.compile(SOURCE)?;
        let result = Self {
            runtime: runtime.clone(),
            chacha: module.kernel("device_random_chacha20")?,
            counts: module.kernel("device_random_counts")?,
            offsets: module.kernel("device_random_offsets")?,
            scatter: module.kernel("device_random_scatter")?,
            gather: module.kernel("device_random_gather")?,
            states: AtomicUsize::new(0),
        };
        for kernel in [
            &result.chacha,
            &result.counts,
            &result.offsets,
            &result.scatter,
            &result.gather,
        ] {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA random kernel exceeds private memory allowance".into());
            }
        }
        Ok(Arc::new(result))
    }
    fn slot(self: &Arc<Self>) -> Result<Slot> {
        self.states
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_STREAM_STATES).then(|| n + 1)
            })
            .map_err(|_| "CUDA random stream-state allowance exhausted")?;
        Ok(Slot(self.clone()))
    }
    pub(crate) fn import(self: &Arc<Self>, rng: ChaCha20Rng) -> Result<DeviceRandom> {
        self.import_shared(rng, Arc::new(AtomicBool::new(false)))
    }
    pub(crate) fn import_shared(
        self: &Arc<Self>,
        rng: ChaCha20Rng,
        failed: Arc<AtomicBool>,
    ) -> Result<DeviceRandom> {
        let rng = ImportedRng::new(rng);
        if failed.load(Ordering::Acquire) {
            return Err("CUDA randomness proof group has retired".into());
        }
        let slot = self.slot()?;
        let bytes = SeedBytes(rng.rng().get_seed());
        let mut words = SeedWords([0; 4]);
        for (word, bytes) in words.0.iter_mut().zip(bytes.0.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        let key = self.runtime.allocate(4)?;
        key.write(0, &words.0)?;
        if failed.load(Ordering::Acquire) {
            return Err("CUDA randomness proof group retired during import".into());
        }
        Ok(DeviceRandom(Arc::new(Stream {
            key,
            stream: rng.rng().get_stream(),
            position: Mutex::new(rng.rng().get_word_pos()),
            failed,
            slot,
        })))
    }
    fn admit_allocations(&self, extra: usize) -> Result<()> {
        if self
            .runtime
            .snapshot()
            .allocations
            .checked_add(extra)
            .is_none_or(|n| n > self.runtime.state.budget.limits.max_allocations)
        {
            return Err("CUDA random allocation count exceeds allowance".into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn compact(
        &self,
        raw: &Buffer,
        counts: &Buffer,
        offsets: &Buffer,
        total: &Buffer,
        output: &Buffer,
        offset: u32,
        count: usize,
        first: usize,
    ) -> Result<usize> {
        let tiles = count.div_ceil(TILE_WORDS);
        if count == 0
            || count > BATCH_WORDS
            || offset >= 16
            || counts.len() < tiles
            || offsets.len() < tiles
            || total.len() != 1
            || first.checked_add(count).is_none_or(|n| n > output.len())
            || (offset as usize + count * 2).div_ceil(2) > raw.len()
        {
            return Err("CUDA random compaction geometry exceeds admission".into());
        }
        let buffers = [raw, counts, offsets, total, output];
        for (index, buffer) in buffers.iter().enumerate() {
            if !Arc::ptr_eq(buffer.owner(), &self.runtime.state)
                || buffers[..index]
                    .iter()
                    .any(|other| other.pointer() == buffer.pointer())
            {
                return Err(
                    "CUDA random compaction requires distinct buffers owned by its runtime".into(),
                );
            }
        }
        // Fixed 128-lane blocks cover two ordered candidates each. All scan
        // storage is bounded and every accepted output has a unique position.
        unsafe {
            self.counts.launch(
                Launch {
                    blocks: tiles as u32,
                    threads: LANES,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(raw),
                    Argument::Buffer(counts),
                    Argument::U32(offset),
                    Argument::U32(count as u32),
                ],
            )?
        }
        .finish()?;
        unsafe {
            self.offsets.launch(
                Launch {
                    blocks: 1,
                    threads: LANES,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(counts),
                    Argument::Buffer(offsets),
                    Argument::Buffer(total),
                    Argument::U32(tiles as u32),
                ],
            )?
        }
        .finish()?;
        unsafe {
            self.scatter.launch(
                Launch {
                    blocks: tiles as u32,
                    threads: LANES,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(raw),
                    Argument::Buffer(offsets),
                    Argument::Buffer(output),
                    Argument::U32(offset),
                    Argument::U32(count as u32),
                    Argument::U64(first as u64),
                ],
            )?
        }
        .finish()?;
        let mut accepted = [u64::MAX];
        total.read(0, &mut accepted)?;
        accepted_words(accepted[0], count)
    }
}

impl DeviceRandom {
    pub(super) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        if !Arc::ptr_eq(&self.0.slot.0.runtime.state, &runtime.state) {
            return Err("CUDA random stream belongs to another runtime".into());
        }
        self.check_live()
    }

    /// Cover downstream consumers as well as sampling with the proof-family
    /// retirement guard. Callers validate public shapes and budgets first.
    pub(super) fn with_attempt<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.check_live()?;
        let mut attempt = Attempt {
            failed: &self.0.failed,
            started: true,
            complete: false,
        };
        let result = f()?;
        self.check_live()?;
        attempt.complete = true;
        Ok(result)
    }

    /// Reserve one contiguous draw sequence for polynomial hiding. Holding the
    /// cursor across all requests prevents another alias from interleaving the
    /// random-column draws and quotient masks. No consumer runs under this lock.
    pub(super) fn sample_fields_batch(
        &self,
        requests: &[usize],
        pending: &[usize],
    ) -> Result<Vec<RandomWords>> {
        let mut position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.preflight_at(*position, requests, pending, true)?;
        self.with_attempt(|| {
            requests
                .iter()
                .map(|&count| self.sample_at(&mut position, count, Fault::None))
                .collect()
        })
    }

    pub(crate) fn check_live(&self) -> Result<()> {
        if self.0.failed.load(Ordering::Acquire) {
            return Err("CUDA random family retired; use fresh proof configuration".into());
        }
        drop(self.0.slot.0.runtime.state.enter()?);
        Ok(())
    }
    pub(crate) fn retire(&self) {
        self.0.failed.store(true, Ordering::Release);
    }
    pub(crate) fn snapshot(&self) -> Result<Self> {
        let position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.check_live()?;
        let slot = self.0.slot.0.slot()?;
        Ok(Self(Arc::new(Stream {
            key: self.0.key.clone(),
            stream: self.0.stream,
            position: Mutex::new(*position),
            failed: self.0.failed.clone(),
            slot,
        })))
    }
    pub(crate) fn preflight_fields(&self, requests: &[usize], pending: &[usize]) -> Result<()> {
        let position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.preflight_at(*position, requests, pending, true)
    }
    fn preflight_at(
        &self,
        position: u128,
        requests: &[usize],
        pending: &[usize],
        retain_outputs: bool,
    ) -> Result<()> {
        self.check_live()?;
        if pending.len() > 512 {
            return Err("CUDA random pending allocation count exceeds allowance".into());
        }
        let engine = &self.0.slot.0;
        let state = engine.runtime.snapshot();
        let limits = engine.runtime.state.budget.limits;
        FieldStoragePlan::new(
            requests.iter().copied(),
            pending,
            retain_outputs,
            position,
            state.live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        let outputs = if retain_outputs { requests.len() } else { 1 };
        engine.admit_allocations(outputs + pending.len() + 4)
    }
    pub(crate) fn sample_matrix(&self, spec: MatrixSpec) -> Result<Matrix> {
        if spec.extension() != Extension::Base || spec.rows() > 1 << 25 || spec.columns() > 4096 {
            return Err("CUDA random matrix requires bounded base-field geometry".into());
        }
        let samples = self.sample_fields(spec.words())?;
        Ok(Matrix {
            spec,
            buffer: samples.storage,
        })
    }
    pub(crate) fn sample_fields(&self, count: usize) -> Result<RandomWords> {
        self.sample(count, Fault::None)
    }

    fn sample(&self, count: usize, _fault: Fault) -> Result<RandomWords> {
        let mut position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.sample_at(&mut position, count, _fault)
    }
    // The active caller holds its cursor lock. Replay callers use an independent
    // local cursor; every path still shares the same proof-family failure flag.
    fn sample_at(&self, position: &mut u128, count: usize, _fault: Fault) -> Result<RandomWords> {
        self.check_live()?;
        let engine = &self.0.slot.0;
        let runtime = &engine.runtime;
        let limits = runtime.state.budget.limits;
        let plan = Plan::new(
            count,
            *position,
            runtime.snapshot().live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        engine.admit_allocations(5)?;
        let output = RandomWords {
            storage: runtime.allocate(plan.output_words)?,
        };
        let raw = runtime.allocate(plan.raw_words)?;
        let counts = runtime.allocate(plan.tiles)?;
        let offsets = runtime.allocate(plan.tiles)?;
        let total = runtime.allocate(1)?;
        let mut attempt = Attempt {
            failed: &self.0.failed,
            started: false,
            complete: false,
        };
        let (mut written, mut draws) = (0usize, 0u64);
        while written < count {
            self.check_live()?;
            let candidates = (count - written).min(plan.batch_words);
            if draws + candidates as u64 > count as u64 + MAX_REJECTIONS {
                return Err("CUDA random rejection bound exceeded".into());
            }
            if candidates as u128 * 2 > STREAM_WORDS - *position {
                return Err("CUDA random stream exhausted during rejection".into());
            }
            let offset = (*position % 16) as u32;
            let blocks = (offset as usize + candidates * 2).div_ceil(16);
            attempt.started = true;
            // The checked word range proves the 64-bit block counter cannot wrap.
            unsafe {
                engine.chacha.launch(
                    Launch {
                        blocks: blocks.div_ceil(128) as u32,
                        threads: 128,
                        shared_bytes: 0,
                    },
                    &[
                        Argument::Buffer(&self.0.key),
                        Argument::Buffer(&raw),
                        Argument::U64((*position / 16) as u64),
                        Argument::U64(self.0.stream),
                        Argument::U32(blocks as u32),
                    ],
                )?
            }
            .finish()?;
            #[cfg(test)]
            if matches!(_fault, Fault::RejectAll) {
                raw.write(0, &vec![u64::MAX; raw.len()])?;
            }
            let accepted = engine.compact(
                &raw,
                &counts,
                &offsets,
                &total,
                &output.storage,
                offset,
                candidates,
                written,
            )?;
            #[cfg(test)]
            if matches!(_fault, Fault::InvalidStatus) {
                accepted_words(u64::MAX, candidates)?;
            }
            *position += candidates as u128 * 2;
            draws += candidates as u64;
            written += accepted;
            #[cfg(test)]
            match _fault {
                Fault::AfterBatch => return Err("injected CUDA random failure after batch".into()),
                Fault::PanicAfterBatch => panic!("injected CUDA random unwind after batch"),
                _ => (),
            }
        }
        self.check_live()?;
        attempt.complete = true;
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
