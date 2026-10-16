//! Device-owned Poseidon2 duplex state. Only public observations, challenges,
//! query indices and PoW witnesses cross the host boundary. Snapshots copy the
//! state on device and share failure retirement, never a mutable sample cursor.
use super::random::SecretAllocation;
use super::*;
use crate::block_v2::challenger::resources as limits;
use crate::block_v2::challenger::storage as host_storage_plan;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::MutexGuard;
mod host_storage;

const STATE_WORDS: usize = limits::STATE_WORDS;
pub(crate) const MAX_TRANSCRIPT_WORDS: usize = limits::BATCH_WORDS;
const GRIND_BATCH: usize = limits::GRIND_BATCH;
const GRIND_TILE: usize = limits::GRIND_TILE;
// The maintained profile uses 16 bits. A finite budget keeps a faulty or
// pathological transcript from occupying a worker indefinitely. No fallback.
const MAX_GRIND_BITS: usize = limits::GRIND_BITS;
const MAX_GRIND_CANDIDATES: usize = limits::GRIND_CANDIDATES;

struct StateSlot {
    live: Arc<AtomicUsize>,
    limit: usize,
}
impl StateSlot {
    fn new(limit: usize) -> Result<Self, String> {
        if limit == 0 {
            return Err("GPU transcript requires a live-state reservation".into());
        }
        Ok(Self {
            live: Arc::new(AtomicUsize::new(1)),
            limit,
        })
    }
    fn acquire(&self) -> Result<Self, String> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                if live < self.limit {
                    live.checked_add(1)
                } else {
                    None
                }
            })
            .map_err(|_| "GPU transcript live-state reservation exhausted")?;
        Ok(Self {
            live: self.live.clone(),
            limit: self.limit,
        })
    }
}
impl Drop for StateSlot {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

fn admit(engine: &Engine, words: &[usize]) -> Result<usize, String> {
    memory_plan(
        words,
        engine
            .accounting
            .lock()
            .map_err(|_| "GPU accounting poisoned")?
            .live,
        engine.limits.managed_bytes,
        engine.max_alloc,
    )
}

fn memory_plan(
    words: &[usize],
    live: usize,
    limit: usize,
    max_alloc: usize,
) -> Result<usize, String> {
    if words.is_empty() || words.len() > 3 || live > limit {
        return Err("invalid GPU transcript allocation plan".into());
    }
    let mut peak = live;
    for &count in words {
        let bytes = count
            .checked_mul(8)
            .filter(|n| *n != 0)
            .ok_or("GPU transcript allocation overflow or empty buffer")?;
        peak = peak
            .checked_add(bytes)
            .ok_or("GPU transcript live-byte overflow")?;
        if bytes > max_alloc || peak > limit {
            return Err("GPU transcript state and scratch exceed admission".into());
        }
    }
    Ok(peak)
}

fn bit_mask(bits: usize) -> Result<u64, String> {
    if bits >= usize::BITS as usize || bits >= 64 || (1u64 << bits) >= GOLDILOCKS_MODULUS {
        return Err("GPU transcript sample bit count is invalid".into());
    }
    Ok((1u64 << bits) - 1)
}

struct Execution<'a> {
    failed: MutexGuard<'a, bool>,
    started: bool,
    completed: bool,
}
impl<'a> Execution<'a> {
    fn new(family: &'a Mutex<bool>) -> Result<Self, String> {
        let failed = family
            .lock()
            .map_err(|_| "GPU transcript family lock poisoned")?;
        if *failed {
            return Err("GPU transcript family is unusable after execution failure".into());
        }
        Ok(Self {
            failed,
            started: false,
            completed: false,
        })
    }
    fn begin(&mut self) {
        self.started = true;
    }
    fn finish(mut self) {
        self.completed = true;
    }
}
impl Drop for Execution<'_> {
    fn drop(&mut self) {
        if self.started && !self.completed {
            *self.failed = true;
        }
    }
}

pub(crate) struct DeviceTranscript {
    state: SecretAllocation,
    // Fields drop in declaration order: scrub and free state before returning
    // its slot, including while another thread requests a snapshot.
    slot: StateSlot,
    session: DeviceSession,
    failed: Arc<Mutex<bool>>,
    // Return the host charge only after the state and shared family handles
    // have been dropped. All states, including future snapshots, own a charge.
    _host_storage: HostScope,
    #[cfg(test)]
    fault: Option<Fault>,
}

pub(super) fn state_host_backing() -> Result<usize, String> {
    // Charging shared counters/attempt metadata for every state is conservative.
    host_storage::family_bytes(1)
}

/// Whole-proof retirement, including failures outside transcript operations.
/// The guard holds no mutex while the proof runs or its snapshots are used.
pub(crate) struct TranscriptAttempt {
    failed: Arc<Mutex<bool>>,
    completed: bool,
}
impl TranscriptAttempt {
    pub(crate) fn complete(mut self) {
        self.completed = true;
    }
}
impl Drop for TranscriptAttempt {
    fn drop(&mut self) {
        if !self.completed {
            if let Ok(mut failed) = self.failed.lock() {
                *failed = true;
            }
        }
    }
}
impl core::fmt::Debug for DeviceTranscript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeviceTranscript(<device-owned>)")
    }
}

impl DeviceSession {
    pub(crate) fn new_transcript(&self) -> Result<DeviceTranscript, String> {
        self.new_transcript_bounded(usize::MAX)
    }

    pub(crate) fn new_transcript_bounded(&self, limit: usize) -> Result<DeviceTranscript, String> {
        let host_storage = self.reserve_transcript_host(host_storage_plan::Plan {
            bytes: state_host_backing()?,
        })?;
        let slot = StateSlot::new(limit)?;
        #[cfg(not(feature = "gpu"))]
        return Err("GPU transcript is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            admit(engine, &[STATE_WORDS])?;
            let state = SecretAllocation::new(engine, STATE_WORDS)?;
            let fence = engine.fence();
            state
                .buffer()
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            self.session.stats.lock().unwrap().transcript_creations += 1;
            Ok(DeviceTranscript {
                state,
                slot,
                session: self.clone(),
                failed: Arc::new(Mutex::new(false)),
                _host_storage: host_storage,
                #[cfg(test)]
                fault: None,
            })
        })
    }
}

impl DeviceTranscript {
    pub(crate) fn reserve_host_storage(
        &self,
        plan: host_storage_plan::Plan,
    ) -> Result<HostScope, String> {
        self.session.reserve_transcript_host(plan)
    }

    pub(crate) fn session(&self) -> DeviceSession {
        self.session.clone()
    }
    /// Scalar derivations belong to the same failure family as the sampled
    /// challenges. The duplex state itself is not observed or advanced here.
    pub(crate) fn derive_scalars<T>(
        &self,
        operation: impl FnOnce(&DeviceSession) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut execution = Execution::new(&self.failed)?;
        execution.begin();
        self.session.with_engine(|_| Ok(()))?;
        let result = operation(&self.session)?;
        execution.finish();
        Ok(result)
    }

    pub(crate) fn retire(&self) {
        if let Ok(mut failed) = self.failed.lock() {
            *failed = true;
        }
    }

    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        if !Arc::ptr_eq(&self.session.session, &session.session) {
            return Err("GPU transcript belongs to another proof session".into());
        }
        let execution = Execution::new(&self.failed)?;
        self.session.with_engine(|_| Ok(()))?;
        execution.finish();
        Ok(())
    }

    pub(crate) fn begin_attempt(&self) -> Result<TranscriptAttempt, String> {
        self.check_session(&self.session)?;
        Ok(TranscriptAttempt {
            failed: self.failed.clone(),
            completed: false,
        })
    }

    /// Independent state, with common retirement if any related execution fails.
    pub(crate) fn snapshot(&self) -> Result<Self, String> {
        #[cfg(not(feature = "gpu"))]
        return Err("GPU transcript snapshots are not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            let host_storage = self.reserve_host_storage(host_storage_plan::Plan {
                bytes: state_host_backing()?,
            })?;
            let mut execution = Execution::new(&self.failed)?;
            let slot = self.slot.acquire()?;
            let snapshot = self.session.with_engine(|engine| {
                admit(engine, &[STATE_WORDS])?;
                let state = SecretAllocation::new(engine, STATE_WORDS)?;
                let fence = engine.fence();
                let mut event = compute::Event::empty();
                execution.begin();
                // SAFETY: both independent buffers have exactly STATE_WORDS words.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_transcript_copy")
                        .arg(self.state.buffer())
                        .arg(state.buffer())
                        .global_work_size(STATE_WORDS)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let ns = engine.timeline.record("device_transcript_copy", &event)?;
                fence.finish()?;
                {
                    let mut stats = self.session.session.stats.lock().unwrap();
                    stats.transcript_snapshots += 1;
                    stats.transcript_device_ns += ns;
                }
                #[cfg(test)]
                self.maybe_fail(Fault::Snapshot)?;
                Ok(Self {
                    state,
                    slot,
                    session: self.session.clone(),
                    failed: self.failed.clone(),
                    _host_storage: host_storage,
                    #[cfg(test)]
                    fault: None,
                })
            })?;
            execution.finish();
            Ok(snapshot)
        }
    }

    /// Admission is atomic for one bounded batch, including empty no-op input.
    pub(crate) fn observe(&mut self, words: &[u64]) -> Result<(), String> {
        let mut scope = self.reserve_host_storage(host_storage_plan::Plan::observation()?)?;
        self.observe_scoped(words, &mut scope)
    }

    pub(crate) fn observe_scoped(
        &mut self,
        words: &[u64],
        scope: &mut HostScope,
    ) -> Result<(), String> {
        self.session
            .check_transcript_host(scope, host_storage_plan::Plan::observation()?)?;
        if words.len() > MAX_TRANSCRIPT_WORDS || words.iter().any(|&n| n >= GOLDILOCKS_MODULUS) {
            return Err("GPU transcript observations must be bounded canonical fields".into());
        }
        #[cfg(not(feature = "gpu"))]
        return Err("GPU transcript absorption is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            let mut execution = Execution::new(&self.failed)?;
            self.session.with_engine(|engine| {
                if words.is_empty() {
                    return Ok(());
                }
                admit(engine, &[words.len()])?;
                let input = SecretAllocation::new(engine, words.len())?;
                let fence = engine.fence();
                let mut event = compute::Event::empty();
                execution.begin();
                input
                    .buffer()
                    .write(words)
                    .enq()
                    .map_err(|e| e.to_string())?;
                // SAFETY: lengths are bounded, state is private to this operation,
                // and the fence drains host upload and all kernels before return.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_transcript_observe")
                        .arg(self.state.buffer())
                        .arg(input.buffer())
                        .arg(words.len() as u32)
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .global_work_size(1usize)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let ns = engine
                    .timeline
                    .record("device_transcript_observe", &event)?;
                fence.finish()?;
                engine.stats.uploaded_bytes += words.len() as u64 * 8;
                {
                    let mut stats = self.session.session.stats.lock().unwrap();
                    stats.uploaded_bytes += words.len() as u64 * 8;
                    stats.transcript_observations += 1;
                    stats.transcript_observed_fields += words.len() as u64;
                    stats.transcript_device_ns += ns;
                }
                #[cfg(test)]
                self.maybe_fail(Fault::Observe)?;
                Ok(())
            })?;
            execution.finish();
            Ok(())
        }
    }

    pub(crate) fn sample_fields(&mut self, count: usize) -> Result<Vec<u64>, String> {
        self.sample(count, u64::MAX)
    }

    pub(crate) fn sample_fields_scoped(
        &mut self,
        count: usize,
        scope: &mut HostScope,
    ) -> Result<Vec<u64>, String> {
        self.sample_scoped(count, u64::MAX, scope)
    }

    /// Even zero-bit sampling consumes a field, as upstream does.
    pub(crate) fn sample_bits(&mut self, bits: usize, count: usize) -> Result<Vec<u64>, String> {
        self.sample(count, bit_mask(bits)?)
    }

    pub(crate) fn sample_bits_scoped(
        &mut self,
        bits: usize,
        count: usize,
        scope: &mut HostScope,
    ) -> Result<Vec<u64>, String> {
        self.sample_scoped(count, bit_mask(bits)?, scope)
    }

    fn sample(&mut self, count: usize, mask: u64) -> Result<Vec<u64>, String> {
        let mut scope = self.reserve_host_storage(host_storage_plan::Plan::sample(count)?)?;
        self.sample_scoped(count, mask, &mut scope)
    }

    fn sample_scoped(
        &mut self,
        count: usize,
        mask: u64,
        scope: &mut HostScope,
    ) -> Result<Vec<u64>, String> {
        if count == 0 || count > MAX_TRANSCRIPT_WORDS {
            return Err("GPU transcript sampling requires 1..4096 fields".into());
        }
        self.session
            .check_transcript_host(scope, host_storage_plan::Plan::sample(count)?)?;
        #[cfg(not(feature = "gpu"))]
        return Err("GPU transcript sampling is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            let mut execution = Execution::new(&self.failed)?;
            let values = self.session.with_engine(|engine| {
                admit(engine, &[count])?;
                let mut values = host_storage_plan::zeroed_words(count)?;
                let output = SecretAllocation::new(engine, count)?;
                let fence = engine.fence();
                let mut event = compute::Event::empty();
                execution.begin();
                // SAFETY: bounded output and private state remain alive until drained.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_transcript_sample")
                        .arg(self.state.buffer())
                        .arg(output.buffer())
                        .arg(count as u32)
                        .arg(mask)
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .global_work_size(1usize)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let ns = engine.timeline.record("device_transcript_sample", &event)?;
                output
                    .buffer()
                    .read(&mut values[..])
                    .enq()
                    .map_err(|e| e.to_string())?;
                fence.finish()?;
                engine.stats.downloaded_bytes += count as u64 * 8;
                {
                    let mut stats = self.session.session.stats.lock().unwrap();
                    stats.downloaded_bytes += count as u64 * 8;
                    stats.transcript_public_bytes += count as u64 * 8;
                    stats.transcript_samples += 1;
                    stats.transcript_sampled_fields += count as u64;
                    stats.transcript_device_ns += ns;
                }
                if values
                    .iter()
                    .any(|&n| n >= GOLDILOCKS_MODULUS || n & !mask != 0)
                {
                    return Err("GPU transcript returned an invalid public sample".into());
                }
                #[cfg(test)]
                self.maybe_fail(Fault::Sample)?;
                Ok(values)
            })?;
            #[cfg(test)]
            if self.fault == Some(Fault::Unwind) {
                panic!("injected unwind after GPU transcript sampling");
            }
            execution.finish();
            Ok(values)
        }
    }

    /// Returns the minimum valid witness and applies check_witness on device.
    /// Zero-bit grinding is a no-op, unlike zero-bit sampling.
    pub(crate) fn grind(&mut self, bits: usize) -> Result<u64, String> {
        self.grind_bounded(bits, GRIND_BATCH, MAX_GRIND_CANDIDATES)
    }

    fn grind_bounded(
        &mut self,
        bits: usize,
        batch: usize,
        candidates: usize,
    ) -> Result<u64, String> {
        let mask = bit_mask(bits)?;
        if bits > MAX_GRIND_BITS
            || batch == 0
            || batch > GRIND_BATCH
            || candidates == 0
            || candidates > MAX_GRIND_CANDIDATES
        {
            return Err("GPU grinding exceeds bit count or candidate bounds".into());
        }
        let _host_storage = self.reserve_host_storage(host_storage_plan::Plan::grind()?)?;
        #[cfg(not(feature = "gpu"))]
        return Err("GPU transcript grinding is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            let mut execution = Execution::new(&self.failed)?;
            let witness = self.session.with_engine(|engine| {
                if bits == 0 { return Ok(0); }
                let batch = batch.min(candidates);
                let tiles = batch.div_ceil(GRIND_TILE);
                let peak = admit(engine, &[batch, tiles, 2])?;
                let output = SecretAllocation::new(engine, batch)?;
                let minima = SecretAllocation::new(engine, tiles)?;
                let status = SecretAllocation::new(engine, 2)?;
                let mut result = [0u64; 2];
                let fence = engine.fence();
                let mut elapsed = 0;
                for base in (0..candidates).step_by(batch) {
                    let count = batch.min(candidates - base);
                    let tiles = count.div_ceil(GRIND_TILE);
                    execution.begin();
                    let ns = grind_batch(engine, self.state.buffer(), output.buffer(),
                        minima.buffer(), status.buffer(), base, count, tiles, mask)?;
                    elapsed += ns;
                    status.buffer().read(&mut result[..]).enq().map_err(|e| e.to_string())?;
                    engine.pq.queue().finish().map_err(|e| e.to_string())?;
                    engine.stats.downloaded_bytes += 16;
                    {
                        let mut stats = self.session.session.stats.lock().unwrap();
                        stats.downloaded_bytes += 16;
                        stats.grinding_batches += 1;
                        stats.grinding_candidates += count as u64;
                        stats.grinding_status_bytes += 16;
                        stats.grinding_device_ns += ns;
                    }
                    #[cfg(test)]
                    self.maybe_fail(Fault::Grind)?;
                    match result {
                        [u64::MAX, 0] => (),
                        [witness, 1] if (base as u64..(base + count) as u64).contains(&witness) => {
                            fence.finish()?;
                            self.session.session.stats.lock().unwrap().grinding_calls += 1;
                            eprintln!("bounded_gpu_grinding bits={bits} candidates={} batches={} status_readback_bytes={} device_ns={elapsed} managed_peak_plan_bytes={peak}",
                                base + count, base / batch + 1, (base / batch + 1) * 16);
                            return Ok(witness);
                        }
                        _ => return Err("GPU grinding returned invalid witness/status".into()),
                    }
                }
                Err("GPU grinding candidate budget exhausted; retire proof attempt".into())
            })?;
            execution.finish();
            Ok(witness)
        }
    }
}

#[cfg(feature = "gpu")]
#[allow(clippy::too_many_arguments)]
fn grind_batch(
    engine: &mut Engine,
    state: &compute::Buffer<u64>,
    output: &compute::Buffer<u64>,
    minima: &compute::Buffer<u64>,
    status: &compute::Buffer<u64>,
    base: usize,
    count: usize,
    tiles: usize,
    mask: u64,
) -> Result<u128, String> {
    let mut event = compute::Event::empty();
    // SAFETY: caller admits and owns all bounded buffers and the queue fence;
    // base+count <= 2^26 is canonical and fits every kernel index.
    unsafe {
        engine
            .pq
            .kernel_builder("device_transcript_grind_candidates")
            .arg(state)
            .arg(output)
            .arg(base as u64)
            .arg(count as u32)
            .arg(mask)
            .arg(&engine.constants[0].buffer)
            .arg(&engine.constants[1].buffer)
            .arg(&engine.constants[2].buffer)
            .arg(&engine.constants[3].buffer)
            .global_work_size(count)
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    let mut ns = engine
        .timeline
        .record("device_transcript_grind_candidates", &event)?;
    event = compute::Event::empty();
    unsafe {
        engine
            .pq
            .kernel_builder("device_transcript_grind_reduce")
            .arg(output)
            .arg(minima)
            .arg(count as u32)
            .global_work_size(tiles)
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    ns += engine
        .timeline
        .record("device_transcript_grind_reduce", &event)?;
    event = compute::Event::empty();
    unsafe {
        engine
            .pq
            .kernel_builder("device_transcript_grind_commit")
            .arg(state)
            .arg(minima)
            .arg(status)
            .arg(tiles as u32)
            .arg(mask)
            .arg(&engine.constants[0].buffer)
            .arg(&engine.constants[1].buffer)
            .arg(&engine.constants[2].buffer)
            .arg(&engine.constants[3].buffer)
            .global_work_size(1usize)
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    ns += engine
        .timeline
        .record("device_transcript_grind_commit", &event)?;
    Ok(ns)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Observe,
    Sample,
    Snapshot,
    Grind,
    Unwind,
}
#[cfg(test)]
impl DeviceTranscript {
    fn maybe_fail(&self, point: Fault) -> Result<(), String> {
        if self.fault == Some(point) {
            return Err("injected failure after GPU transcript execution".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
