//! Private, shared device random streams. Host code handles seed acquisition,
//! stream positions and bounded loop control; all expansion, field rejection
//! and stable sample compaction runs on GPU. No host RNG fallback exists.
use super::*;
use rand_chacha::ChaCha20Rng;

mod admission;
pub(crate) use admission::FieldStoragePlan;
mod public_salts;
pub(crate) use public_salts::PublicSaltStream;
pub use public_salts::PublicSalts;
mod replay;
pub(crate) use replay::salt_replay_workspace_bytes;
pub use replay::ReplaySalts;

pub(super) use crate::gpu_random::{
    Plan, BATCH_WORDS, MAX_OUTPUT_WORDS, MAX_REJECTIONS, STREAM_WORDS, TILE_WORDS,
};
#[cfg(feature = "gpu")]
const COMPACTION_LANES: usize = TILE_WORDS / 2;

/// Wipes secret state and samples before their reservations are released.
/// It owns its queue so cleanup works during unwinding and engine shutdown.
pub(super) struct SecretAllocation {
    allocation: Arc<Allocation>,
    queue: compute::Queue,
}

impl SecretAllocation {
    pub(super) fn new(engine: &Engine, words: usize) -> Result<Self, String> {
        let mut allocation = allocation(
            &engine.pq,
            &engine.accounting,
            engine.limits,
            engine.max_alloc,
            words,
            compute::flags::MEM_READ_WRITE,
        )?;
        allocation._lease.mark_device()?;
        Ok(Self {
            allocation: Arc::new(allocation),
            queue: engine.pq.queue().clone(),
        })
    }
    pub(super) fn buffer(&self) -> &compute::Buffer<u64> {
        &self.allocation.buffer
    }
    fn scrub(&self) {
        if let Err(error) = self.buffer().cmd().fill(0u64, None).enq() {
            super::super::fatal_cleanup("random_scrub", error);
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("random_scrub_drain", error);
        }
    }
}
impl Drop for SecretAllocation {
    fn drop(&mut self) {
        self.scrub();
    }
}

struct SeedBytes([u8; 32]);
impl Drop for SeedBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: each byte belongs to this live, exclusively borrowed seed.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
struct SeedWords([u64; 4]);
impl Drop for SeedWords {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: as above; do not elide clearing the upload staging copy.
            unsafe {
                std::ptr::write_volatile(word, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

struct Cursor {
    position: u128,
    poisoned: bool,
}
struct Stream {
    seed: Arc<SecretAllocation>,
    stream: u64,
    cursor: Mutex<Cursor>,
    session: DeviceSession,
}

/// Clone shares a cursor; it never copies or replays a random stream.
#[derive(Clone)]
pub(crate) struct DeviceRandom(Arc<Stream>);

fn retained_stream_host_backing() -> usize {
    use crate::block_v2::gpu_hash::cache_metadata::arc_bytes;
    arc_bytes::<Stream>() + arc_bytes::<SecretAllocation>() + arc_bytes::<Allocation>()
}

#[cfg(all(test, feature = "stream"))]
#[test]
fn retained_salt_stream_backing_matches_allocator_requests() {
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;
    let (_owned, requests) = measure(|| {
        (
            Arc::new(MaybeUninit::<Stream>::uninit()),
            Arc::new(MaybeUninit::<SecretAllocation>::uninit()),
            Arc::new(MaybeUninit::<Allocation>::uninit()),
        )
    });
    assert_eq!(retained_stream_host_backing(), requests.bytes);
    assert_eq!(requests.calls, 3);
    assert!(!requests.overflow);
    eprintln!(
        "retained_salt_stream_census planned_bytes={} independent_bytes={}",
        retained_stream_host_backing(),
        requests.bytes
    );
}
impl core::fmt::Debug for DeviceRandom {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeviceRandom(<redacted>)")
    }
}

/// Only field samples from DeviceRandom can construct this private buffer.
/// It is neither a host Matrix nor promotable to public preprocessing.
pub(crate) struct RandomWords {
    storage: SecretAllocation,
    session: DeviceSession,
    count: usize,
}

// The existing host-reference route and the device generator share only this
// read-only kernel interface. Generated buffers retain their scrub-on-drop owner.
pub(super) enum SampleBuffer {
    Uploaded(Allocation),
    Generated(RandomWords),
}
impl SampleBuffer {
    pub(super) fn buffer(&self) -> &compute::Buffer<u64> {
        match self {
            Self::Uploaded(allocation) => &allocation.buffer,
            Self::Generated(words) => words.buffer(),
        }
    }
}
impl RandomWords {
    pub(crate) fn len(&self) -> usize {
        self.count
    }
    pub(super) fn buffer(&self) -> &compute::Buffer<u64> {
        self.storage.buffer()
    }
    pub(super) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        if !Arc::ptr_eq(&self.session.session, &session.session) {
            return Err("random samples belong to another proof session".into());
        }
        Ok(())
    }
    fn into_matrix(self, spec: MatrixSpec) -> DeviceMatrix {
        let guard = Arc::new(self.storage);
        DeviceMatrix {
            storage: Arc::clone(&guard.allocation),
            private_random: Some(guard),
            session: self.session.session,
            spec,
        }
    }
    #[cfg(test)]
    pub(crate) fn read_for_test(&self, allowance: usize) -> Result<Vec<u64>, String> {
        if self.count.checked_mul(8).is_none_or(|n| n > allowance) {
            return Err("random readback exceeds test allowance".into());
        }
        self.session.with_engine(|engine| {
            let mut words = vec![0; self.count];
            let fence = engine.fence();
            self.buffer()
                .read(&mut words[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.downloaded_bytes += self.count as u64 * 8;
            self.session.session.stats.lock().unwrap().downloaded_bytes += self.count as u64 * 8;
            Ok(words)
        })
    }
}

impl DeviceSession {
    /// Imports only the abstract seed/stream/word position, without expanding
    /// any host randomness. Ownership of the source RNG is consumed.
    pub(crate) fn import_random_stream(&self, rng: ChaCha20Rng) -> Result<DeviceRandom, String> {
        #[cfg(not(feature = "gpu"))]
        {
            let _ = rng;
            return Err("device random expansion is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let bytes = SeedBytes(rng.get_seed());
            let mut words = SeedWords([0; 4]);
            for (word, bytes) in words.0.iter_mut().zip(bytes.0.chunks_exact(8)) {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }
            let seed = Arc::new(SecretAllocation::new(engine, 4)?);
            let fence = engine.fence();
            seed.buffer()
                .write(&words.0[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            engine.stats.uploaded_bytes += 32;
            let mut stats = self.session.stats.lock().unwrap();
            stats.uploaded_bytes += 32;
            stats.random_streams += 1;
            Ok(DeviceRandom(Arc::new(Stream {
                seed,
                stream: rng.get_stream(),
                cursor: Mutex::new(Cursor {
                    position: rng.get_word_pos(),
                    poisoned: false,
                }),
                session: self.clone(),
            })))
        })
    }
}

#[cfg(feature = "gpu")]
fn compact(
    engine: &mut Engine,
    raw: &SecretAllocation,
    counts: &SecretAllocation,
    offsets: &SecretAllocation,
    total: &SecretAllocation,
    output: &RandomWords,
    offset: u32,
    count: usize,
    output_start: usize,
) -> Result<(usize, u128), String> {
    compact_with_layout(
        engine,
        raw,
        counts,
        offsets,
        total,
        output,
        offset,
        count,
        output_start,
        CompactionLayout::Parallel,
    )
}

#[cfg(feature = "gpu")]
#[derive(Clone, Copy)]
enum CompactionLayout {
    Parallel,
    #[cfg(test)]
    SerialOffsetsReference,
}

#[cfg(feature = "gpu")]
fn compact_with_layout(
    engine: &mut Engine,
    raw: &SecretAllocation,
    counts: &SecretAllocation,
    offsets: &SecretAllocation,
    total: &SecretAllocation,
    output: &RandomWords,
    offset: u32,
    count: usize,
    output_start: usize,
    layout: CompactionLayout,
) -> Result<(usize, u128), String> {
    // The offset kernel has 4096 local scan entries. Fail before any dispatch
    // if a caller bypasses the bounded batch plan.
    if count == 0 || count > BATCH_WORDS {
        return Err("random compaction exceeds bounded offset scan".into());
    }
    let tiles = count.div_ceil(TILE_WORDS);
    let count_kernel = "device_random_counts";
    let scatter_kernel = "device_random_scatter";
    let (offset_kernel, parallel_offsets) = match layout {
        CompactionLayout::Parallel => ("device_random_offsets", true),
        #[cfg(test)]
        CompactionLayout::SerialOffsetsReference => {
            ("device_random_offsets_serial_reference", false)
        }
    };
    let work_items = tiles * COMPACTION_LANES;
    let mut elapsed = 0;
    let mut event = compute::Event::empty();
    // SAFETY: the caller's Plan admits all raw words, tile counters and the
    // output suffix. Ordered kernels compute disjoint, stable scatter ranges.
    unsafe {
        let mut kernel = engine.pq.kernel_builder(count_kernel);
        kernel
            .arg(raw.buffer())
            .arg(counts.buffer())
            .arg(offset)
            .arg(count as u32)
            .global_work_size(work_items);
        kernel.local_work_size(COMPACTION_LANES);
        kernel
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    elapsed += engine.timeline.record(count_kernel, &event)?;
    event = compute::Event::empty();
    unsafe {
        let mut kernel = engine.pq.kernel_builder(offset_kernel);
        kernel
            .arg(counts.buffer())
            .arg(offsets.buffer())
            .arg(total.buffer())
            .arg(tiles as u32)
            .global_work_size(if parallel_offsets {
                COMPACTION_LANES
            } else {
                1
            });
        if parallel_offsets {
            kernel.local_work_size(COMPACTION_LANES);
        }
        kernel
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    elapsed += engine.timeline.record(offset_kernel, &event)?;
    event = compute::Event::empty();
    unsafe {
        let mut kernel = engine.pq.kernel_builder(scatter_kernel);
        kernel
            .arg(raw.buffer())
            .arg(offsets.buffer())
            .arg(output.buffer())
            .arg(offset)
            .arg(count as u32)
            .arg(output_start as u64)
            .global_work_size(work_items);
        kernel.local_work_size(COMPACTION_LANES);
        kernel
            .build()
            .map_err(|e| e.to_string())?
            .cmd()
            .enew(&mut event)
            .enq()
            .map_err(|e| e.to_string())?;
    }
    elapsed += engine.timeline.record(scatter_kernel, &event)?;
    let mut accepted = [0u64];
    total
        .buffer()
        .read(&mut accepted[..])
        .enq()
        .map_err(|e| e.to_string())?;
    engine.pq.queue().finish().map_err(|e| e.to_string())?;
    if accepted[0] > count as u64 {
        return Err("invalid GPU random status".into());
    }
    Ok((accepted[0] as usize, elapsed))
}

impl DeviceRandom {
    /// Admit an ordered set of retained sample buffers and any other pending
    /// stage inputs before drawing. Execution still replans under the lock.
    pub(crate) fn preflight_fields(
        &self,
        requests: &[usize],
        pending: &[usize],
    ) -> Result<(), String> {
        self.preflight_field_storage(requests, pending, true)
    }

    fn preflight_field_storage(
        &self,
        requests: &[usize],
        pending: &[usize],
        retain_outputs: bool,
    ) -> Result<(), String> {
        if requests.is_empty() || requests.len() > 512 {
            return Err("GPU random batch requires 1..512 requests".into());
        }
        let cursor = self
            .0
            .cursor
            .lock()
            .map_err(|_| "GPU random cursor poisoned")?;
        if cursor.poisoned {
            return Err("GPU random stream has failed".into());
        }
        self.0.session.with_engine(|engine| {
            let live = engine
                .accounting
                .lock()
                .map_err(|_| "GPU accounting poisoned")?
                .live;
            FieldStoragePlan::new(
                requests.iter().copied(),
                pending,
                retain_outputs,
                cursor.position,
                live,
                engine.limits.managed_bytes,
                engine.max_alloc,
            )?;
            Ok(())
        })
    }

    /// Explicit construction-time snapshot, unlike the shared active cursor
    /// returned by Clone. The immutable device key is shared, never read back.
    pub(crate) fn snapshot(&self) -> Result<Self, String> {
        let cursor = self
            .0
            .cursor
            .lock()
            .map_err(|_| "GPU random cursor poisoned")?;
        if cursor.poisoned {
            return Err("cannot snapshot a failed GPU random stream".into());
        }
        Ok(Self(Arc::new(Stream {
            seed: self.0.seed.clone(),
            stream: self.0.stream,
            cursor: Mutex::new(Cursor {
                position: cursor.position,
                poisoned: false,
            }),
            session: self.0.session.clone(),
        })))
    }

    pub(crate) fn sample_matrix(&self, spec: MatrixSpec) -> Result<DeviceMatrix, String> {
        if spec.extension() != Extension::Base || spec.rows() > 1 << 25 || spec.columns() > 4096 {
            return Err("random matrix requires bounded base-field geometry".into());
        }
        Ok(self.sample_fields(spec.words())?.into_matrix(spec))
    }

    pub(crate) fn sample_fields(&self, count: usize) -> Result<RandomWords, String> {
        self.sample_fields_inner(
            count,
            #[cfg(test)]
            None,
        )
    }

    fn sample_fields_inner(
        &self,
        count: usize,
        #[cfg(test)] fail_after_batch: Option<usize>,
    ) -> Result<RandomWords, String> {
        #[cfg(not(feature = "gpu"))]
        {
            let _ = count;
            return Err("device random expansion is not implemented on Metal".into());
        }
        #[cfg(feature = "gpu")]
        {
            let mut cursor = self
                .0
                .cursor
                .lock()
                .map_err(|_| "GPU random stream lock poisoned")?;
            self.0.session.with_engine(|engine| {
                self.sample_fields_in_engine(
                    &mut cursor,
                    engine,
                    count,
                    #[cfg(test)]
                    fail_after_batch,
                )
            })
        }
    }

    // The caller holds the stream cursor before acquiring the engine. Replay
    // instead supplies its own local cursor while the engine is already held.
    #[cfg(feature = "gpu")]
    fn sample_fields_in_engine(
        &self,
        cursor: &mut Cursor,
        engine: &mut Engine,
        count: usize,
        #[cfg(test)] fail_after_batch: Option<usize>,
    ) -> Result<RandomWords, String> {
        if cursor.poisoned {
            return Err("GPU random stream is unusable after execution failure".into());
        }
        let mut started = false;
        let result = (|| {
            let plan = Plan::new(
                count,
                cursor.position,
                engine.accounting.lock().unwrap().live,
                engine.limits.managed_bytes,
                engine.max_alloc,
            )?;
            let output = RandomWords {
                storage: SecretAllocation::new(engine, plan.output_words)?,
                session: self.0.session.clone(),
                count,
            };
            let raw = SecretAllocation::new(engine, plan.raw_words)?;
            let counts = SecretAllocation::new(engine, plan.tiles)?;
            let offsets = SecretAllocation::new(engine, plan.tiles)?;
            let total = SecretAllocation::new(engine, 1)?;
            let fence = engine.fence();
            let mut written = 0;
            let mut batches = 0;
            let mut draws = 0;
            let mut elapsed = 0;
            while written < count {
                let candidates = (count - written).min(plan.batch_words);
                if draws + candidates as u64 > count as u64 + MAX_REJECTIONS {
                    return Err("GPU random rejection bound exceeded".into());
                }
                if (candidates as u128) * 2 > STREAM_WORDS - cursor.position {
                    return Err("GPU random stream exhausted during field rejection".into());
                }
                let offset = (cursor.position % 16) as u32;
                let blocks = (offset as usize + candidates * 2).div_ceil(16);
                let mut event = compute::Event::empty();
                started = true;
                // SAFETY: Plan covers all blocks; the checked stream bound
                // prohibits counter wrap. Key and output stay live/drained.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("device_random_chacha20")
                        .arg(self.0.seed.buffer())
                        .arg(raw.buffer())
                        .arg((cursor.position / 16) as u64)
                        .arg(self.0.stream)
                        .arg(blocks as u32)
                        .global_work_size(blocks)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let block_ns = engine.timeline.record("device_random_chacha20", &event)?;
                let (accepted, compact_ns) = compact(
                    engine, &raw, &counts, &offsets, &total, &output, offset, candidates, written,
                )?;
                elapsed += block_ns + compact_ns;
                cursor.position += (candidates as u128) * 2;
                written += accepted;
                batches += 1;
                draws += candidates as u64;
                engine.stats.downloaded_bytes += 8;
                {
                    let mut stats = self.0.session.session.stats.lock().unwrap();
                    stats.downloaded_bytes += 8;
                    stats.random_status_bytes += 8;
                    stats.random_draw_words += candidates as u64;
                    stats.random_device_ns += block_ns + compact_ns;
                }
                #[cfg(test)]
                if fail_after_batch == Some(batches as usize) {
                    return Err("injected failure after GPU random batch".into());
                }
            }
            fence.finish()?;
            let mut stats = self.0.session.session.stats.lock().unwrap();
            stats.random_calls += 1;
            stats.random_fields += count as u64;
            eprintln!("bounded_gpu_random fields={count} draws={draws} batches={batches} sample_upload_bytes=0 sample_readback_bytes=0 status_readback_bytes={} device_ns={elapsed} managed_peak_plan_bytes={}", batches * 8, plan.peak_bytes);
            Ok(output)
        })();
        if result.is_err() && started {
            cursor.poisoned = true;
        }
        result
    }
}

#[cfg(test)]
mod tests;
