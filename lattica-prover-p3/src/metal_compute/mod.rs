//! Native Metal transport for the bounded block-v2 engine.
//!
//! The small builder surface matches the operations used by the shared scheduler.
//! There is no OpenCL runtime or CPU kernel fallback. Kernel commands are native
//! Metal commands; host reads/writes are blocking. The measured worker uses serial
//! mode, with asynchronous device commands retained for failure-drain guarantees.
use objc2::{
    rc::{autoreleasepool, Retained},
    runtime::ProtocolObject,
};
use objc2_foundation::{NSRange, NSString};
use objc2_metal::*;
use std::{
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Instant,
};

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}

type Result<T> = std::result::Result<T, String>;
type Object<T> = Retained<ProtocolObject<T>>;
const TRANSFER_BYTES: usize = 8 << 20;
// A single larger Metal blit fill was observed to leave bytes beyond 4 GiB
// unchanged on Apple Silicon. Bound each command, not the buffer allocation.
const MAX_FILL_BYTES: usize = 1 << 30;
const MAX_PENDING_COMMANDS: usize = 256;
pub(crate) mod backing;
pub(crate) mod diagnostics;
pub mod resident;
pub(crate) fn transfer_budget(managed_bytes: usize) -> usize {
    TRANSFER_BYTES.min(managed_bytes / 64).max(8)
}
const KERNELS: &[&str] = &[
    "ntt_tile",
    "ntt_tile_cached",
    "ntt_tile_prefix",
    "ntt_tile_cached_prefix",
    "diagonal_probe",
    "ntt_tables",
    "prefix_scatter",
    "quotient_eval",
    "leaf_hash",
    "compress_layer",
    "retained_merkle_path",
    "query_gather",
    "lde_absorb",
    "lde_leaf_finalize",
    "quotient_mask",
    "opening_reduce",
    "opening_compress_low",
    "opening_reduce_compact",
    "arithmetic_probe",
];

pub mod flags {
    pub type MemFlags = u32;
    pub const MEM_READ_ONLY: MemFlags = 1;
    pub const MEM_READ_WRITE: MemFlags = 2;
    pub const MEM_ALLOC_HOST_PTR: MemFlags = 4;
    pub const MAP_READ: u32 = 1;
    pub const MAP_WRITE: u32 = 2;
}
pub mod enums {
    pub enum EventInfo {
        CommandExecutionStatus,
    }
    #[derive(Debug, PartialEq, Eq)]
    pub enum CommandExecutionStatus {
        Complete,
        Submitted,
    }
    #[derive(Debug, PartialEq, Eq)]
    pub enum EventInfoResult {
        CommandExecutionStatus(CommandExecutionStatus),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryMode {
    Shared,
    Copy,
}
impl MemoryMode {
    fn from_env() -> Result<Self> {
        match std::env::var("LATTICA_V2_METAL_MEMORY") {
            Err(std::env::VarError::NotPresent) => Ok(Self::Shared),
            Ok(s) if s == "shared" => Ok(Self::Shared),
            Ok(s) if s == "copy" => Ok(Self::Copy),
            _ => Err("LATTICA_V2_METAL_MEMORY must be shared or copy".into()),
        }
    }
}

#[derive(Default)]
struct Accounting {
    live: usize,
    peak: usize,
    buffers: u64,
    kernels: u64,
    kernel_ns: u128,
    kernel_commands: u64,
    blits: u64,
    blit_ns: u128,
    host_copy_bytes: u64,
    host_copy_ns: u128,
    transfer_blit_bytes: u64,
}
struct Budget {
    // Resident workers account allocations without enforcing a planning estimate.
    limit: Option<usize>,
    counters: Mutex<Accounting>,
}
struct NativeAllocation {
    _backing: backing::Ticket,
    bytes: usize,
    budget: Arc<Budget>,
}
impl NativeAllocation {
    fn new(bytes: usize, budget: &Arc<Budget>) -> Result<Self> {
        let mut a = budget
            .counters
            .lock()
            .map_err(|_| "Metal accounting poisoned")?;
        let next = a
            .live
            .checked_add(bytes)
            .ok_or("Metal allocation overflow")?;
        if budget.limit.is_some_and(|limit| next > limit) {
            return Err("Metal managed allocation cap exceeded (includes transfer staging)".into());
        }
        let backing = backing::charge(bytes).ok_or("Metal backing accounting overflow")?;
        a.live = next;
        a.peak = a.peak.max(next);
        a.buffers += 1;
        Ok(Self {
            _backing: backing,
            bytes,
            budget: budget.clone(),
        })
    }
}
impl Drop for NativeAllocation {
    fn drop(&mut self) {
        self.budget.counters.lock().unwrap().live -= self.bytes;
    }
}

#[derive(Clone)]
pub struct Queue(Arc<QueueInner>);
pub(crate) struct QueueInner {
    device: Object<dyn MTLDevice>,
    queue: Object<dyn MTLCommandQueue>,
    last: Mutex<Option<Object<dyn MTLCommandBuffer>>>,
    pending: Mutex<Vec<(Object<dyn MTLCommandBuffer>, u64)>>,
    batch: Mutex<Option<Batch>>,
    batch_limit: usize,
    transfer: Object<dyn MTLBuffer>,
    // This mutex serializes use of the single finite transfer buffer.
    transfer_lock: Mutex<()>,
    _transfer_allocation: NativeAllocation,
    budget: Arc<Budget>,
    mode: MemoryMode,
    operation_lock: Mutex<()>,
}
struct Batch {
    phase: &'static str,
    state: Arc<BatchState>,
    dispatches: u64,
}
pub struct BatchState {
    command: Object<dyn MTLCommandBuffer>,
    committed: AtomicBool,
}
unsafe impl Send for BatchState {}
unsafe impl Sync for BatchState {}
// Metal devices/queues/resources support cross-thread use. Encoding and host
// transfers are serialized by operation_lock; transfer staging and the last
// submitted command have their own locks. Mapped slices require the caller's
// unsafe exclusive-map contract and the bounded engine's global mutex.
unsafe impl Send for QueueInner {}
unsafe impl Sync for QueueInner {}
impl Queue {
    fn command(&self, dependency: Option<&Event>) -> Result<Object<dyn MTLCommandBuffer>> {
        let command = autoreleasepool(|_| self.0.queue.commandBuffer())
            .ok_or("Metal command buffer unavailable")?;
        if let Some(Event::User(event)) = dependency {
            command.encodeWaitForEvent_value(ProtocolObject::<dyn MTLEvent>::from_ref(&**event), 1);
        } else if let Some(event) = dependency {
            event.wait_for()?;
        }
        Ok(command)
    }
    fn submit(
        &self,
        command: Object<dyn MTLCommandBuffer>,
        kernel: bool,
        phase: &'static str,
    ) -> Result<Event> {
        self.flush()?;
        self.commit(command.clone(), u64::from(kernel), phase)?;
        Ok(Event::Commands(vec![command]))
    }
    fn commit(
        &self,
        command: Object<dyn MTLCommandBuffer>,
        dispatches: u64,
        phase: &'static str,
    ) -> Result<()> {
        if self.0.pending.lock().unwrap().len() >= MAX_PENDING_COMMANDS {
            self.finish()?;
        }
        diagnostics::submitted(command_address(&command), phase, dispatches);
        command.commit();
        *self.0.last.lock().unwrap() = Some(command.clone());
        self.0
            .pending
            .lock()
            .unwrap()
            .push((command.clone(), dispatches));
        Ok(())
    }
    pub fn finish(&self) -> Result<()> {
        self.flush()?;
        let last = self
            .0
            .last
            .lock()
            .map_err(|_| "Metal queue poisoned")?
            .take();
        if let Some(command) = last {
            wait_command(&command)?;
        }
        let pending = std::mem::take(
            &mut *self
                .0
                .pending
                .lock()
                .map_err(|_| "Metal pending accounting poisoned")?,
        );
        for (command, dispatches) in pending {
            wait_command(&command)?;
            let start = command.GPUStartTime();
            let end = command.GPUEndTime();
            let ns = ((end - start) * 1e9).max(0.0) as u128;
            diagnostics::retired(command_address(&command), start, end);
            let mut a = self.0.budget.counters.lock().unwrap();
            if dispatches != 0 {
                a.kernels += dispatches;
                a.kernel_commands += 1;
                a.kernel_ns += ns;
            } else {
                a.blits += 1;
                a.blit_ns += ns;
            }
        }
        Ok(())
    }
    pub fn flush(&self) -> Result<()> {
        let batch = self
            .0
            .batch
            .lock()
            .map_err(|_| "Metal batch poisoned")?
            .take();
        if let Some(batch) = batch {
            self.commit(batch.state.command.clone(), batch.dispatches, batch.phase)?;
            batch.state.committed.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn compute_command(
        &self,
        phase: &'static str,
        dependency: Option<&Event>,
    ) -> Result<(Object<dyn MTLCommandBuffer>, Option<Event>)> {
        if self.0.batch_limit == 1 || dependency.is_some() {
            self.flush()?;
            return Ok((self.command(dependency)?, None));
        }
        let change = self
            .0
            .batch
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|b| b.phase != phase || b.dispatches >= self.0.batch_limit as u64);
        if change {
            self.flush()?;
        }
        let mut slot = self.0.batch.lock().unwrap();
        if slot.is_none() {
            *slot = Some(Batch {
                phase,
                dispatches: 0,
                state: Arc::new(BatchState {
                    command: self.command(None)?,
                    committed: AtomicBool::new(false),
                }),
            });
        }
        let batch = slot.as_mut().unwrap();
        let timing_owner = batch.dispatches == 0;
        batch.dispatches += 1;
        Ok((
            batch.state.command.clone(),
            Some(Event::Batch {
                queue: Arc::downgrade(&self.0),
                state: batch.state.clone(),
                timing_owner,
            }),
        ))
    }
    #[cfg(test)]
    pub fn enqueue_marker(&self, event: Option<&Event>) -> Result<Event> {
        self.submit(self.command(event)?, false, "marker")
    }
}

impl Drop for QueueInner {
    fn drop(&mut self) {
        // Last queue owner: commit and drain even if an incomplete batch has no
        // event consumer (cancellation or early-return paths).
        if let Some(batch) = self.batch.get_mut().unwrap().take() {
            diagnostics::submitted(
                command_address(&batch.state.command),
                batch.phase,
                batch.dispatches,
            );
            batch.state.command.commit();
            if let Err(error) = wait_command(&batch.state.command) {
                eprintln!("FAILED Metal batch retirement: {error}");
                std::process::abort();
            }
        }
        for (command, _) in self.pending.get_mut().unwrap().drain(..) {
            if let Err(error) = wait_command(&command) {
                eprintln!("FAILED Metal queue retirement: {error}");
                std::process::abort();
            }
        }
    }
}

fn command_address(command: &ProtocolObject<dyn MTLCommandBuffer>) -> usize {
    command as *const _ as *const () as usize
}

fn wait_command(command: &ProtocolObject<dyn MTLCommandBuffer>) -> Result<()> {
    let started = diagnostics::enabled().then(diagnostics::clock_ns);
    command.waitUntilCompleted();
    if let Some(started) = started {
        diagnostics::waited(command_address(command), started, diagnostics::clock_ns());
    }
    if command.status() == MTLCommandBufferStatus::Error {
        return Err(format!("Metal execution failed: {:?}", command.error()));
    }
    if command.status() != MTLCommandBufferStatus::Completed {
        return Err("Metal command did not complete".into());
    }
    Ok(())
}

#[derive(Clone)]
pub enum Event {
    Empty,
    Host,
    Commands(Vec<Object<dyn MTLCommandBuffer>>),
    User(Object<dyn MTLSharedEvent>),
    Batch {
        queue: Weak<QueueInner>,
        state: Arc<BatchState>,
        timing_owner: bool,
    },
}
// Events expose only completion/status on committed command buffers. User
// events use Metal's explicitly thread-safe shared-event signal operation.
unsafe impl Send for Event {}
unsafe impl Sync for Event {}
impl Event {
    pub fn empty() -> Self {
        Self::Empty
    }
    #[cfg(test)]
    pub fn user(device: &ProtocolObject<dyn MTLDevice>) -> Result<Self> {
        Ok(Self::User(
            device
                .newSharedEvent()
                .ok_or("Metal shared event unavailable")?,
        ))
    }
    #[cfg(test)]
    pub fn set_complete(&self) -> Result<()> {
        match self {
            Self::User(event) => {
                event.setSignaledValue(1);
                Ok(())
            }
            _ => Err("not a user event".into()),
        }
    }
    pub fn wait_for(&self) -> Result<()> {
        match self {
            Self::Batch { queue, state, .. } => {
                if !state.committed.load(Ordering::Acquire) {
                    Queue(queue.upgrade().ok_or("Metal queue retired before batch")?).flush()?;
                }
                wait_command(&state.command)
            }
            Self::Empty => Err("uninitialized Metal event".into()),
            Self::Commands(commands) => {
                for c in commands {
                    wait_command(c)?;
                }
                Ok(())
            }
            Self::User(e) => {
                if e.signaledValue() >= 1 {
                    Ok(())
                } else {
                    Err("host wait on unsignaled Metal user event".into())
                }
            }
            Self::Host => Ok(()),
        }
    }
    pub(crate) fn device_intervals(&self) -> Result<Vec<(u64, u64)>> {
        self.wait_for()?;
        let batch_commands;
        let commands = match self {
            Self::Commands(commands) => Some(commands),
            Self::Batch {
                state,
                timing_owner: true,
                ..
            } => {
                batch_commands = vec![state.command.clone()];
                Some(&batch_commands)
            }
            _ => None,
        };
        if let Some(commands) = commands {
            if commands.is_empty() {
                return Err("empty Metal command event".into());
            }
            commands
                .iter()
                .map(|command| {
                    let start = command.GPUStartTime();
                    let end = command.GPUEndTime();
                    if !start.is_finite() || !end.is_finite() || end < start || start <= 0.0 {
                        return Err("Metal GPU timestamps unavailable".into());
                    }
                    Ok(((start * 1e9) as u64, (end * 1e9) as u64))
                })
                .collect()
        } else {
            // Shared-buffer memcpy is host work, never masquerade as GPU time.
            Ok(Vec::new())
        }
    }
    #[cfg(test)]
    fn duration(&self) -> Result<u128> {
        Ok(self
            .device_intervals()?
            .into_iter()
            .map(|(start, end)| u128::from(end - start))
            .sum())
    }
    #[cfg(test)]
    pub fn info(&self, _: enums::EventInfo) -> Result<enums::EventInfoResult> {
        let complete = match self {
            Self::Host => true,
            Self::Batch { state, .. } => {
                state.command.status() == MTLCommandBufferStatus::Completed
            }
            Self::Commands(cs) => cs
                .iter()
                .all(|c| c.status() == MTLCommandBufferStatus::Completed),
            Self::User(e) => e.signaledValue() >= 1,
            Self::Empty => false,
        };
        Ok(enums::EventInfoResult::CommandExecutionStatus(
            if complete {
                enums::CommandExecutionStatus::Complete
            } else {
                enums::CommandExecutionStatus::Submitted
            },
        ))
    }
}

pub struct ProQue {
    queue: Queue,
    pipelines: HashMap<&'static str, Object<dyn MTLComputePipelineState>>,
    compile_ns: u128,
    tables: Arc<Mutex<resident::Tables>>,
    workgroup: usize,
    optimized: bool,
    tuning: resident::Tuning,
}
impl ProQue {
    pub fn new(index: usize, managed_bytes: usize) -> Result<Self> {
        autoreleasepool(|_| Self::new_inner(index, managed_bytes))
    }
    fn new_inner(index: usize, managed_bytes: usize) -> Result<Self> {
        if index != 0 {
            return Err("Metal currently selects the system default device at index 0".into());
        }
        resident::validate()?;
        if resident::enabled() {
            backing::activate();
        }
        let optimized = match std::env::var("LATTICA_V2_METAL_KERNEL_VARIANT").as_deref() {
            Ok("reference") => false,
            Ok("optimized") => true,
            Err(std::env::VarError::NotPresent) => false,
            _ => return Err("Metal kernel variant must be reference or optimized".into()),
        };
        let workgroup = resident::workgroup()?;
        let tuning = resident::Tuning::from_env(optimized)?;
        let batch_limit = match std::env::var("LATTICA_V2_METAL_BATCH").as_deref() {
            Ok("1") => 1,
            Ok("8") => 8,
            Err(std::env::VarError::NotPresent) => {
                if resident::enabled() {
                    8
                } else {
                    1
                }
            }
            _ => return Err("Metal batch must be 1 or 8".into()),
        };
        let mode = MemoryMode::from_env()?;
        let device = MTLCreateSystemDefaultDevice().ok_or("Metal GPU unavailable")?;
        if !device.hasUnifiedMemory() {
            return Err("this Metal experiment requires a unified-memory GPU".into());
        }
        let command_queue = device
            .newCommandQueue()
            .ok_or("Metal command queue unavailable")?;
        let budget = Arc::new(Budget {
            limit: if resident::enabled() {
                None
            } else {
                Some(managed_bytes)
            },
            counters: Mutex::new(Accounting::default()),
        });
        // Reserve the same finite staging allowance in both modes. There are no
        // per-transfer allocations and no unaccounted private-buffer mirrors.
        let transfer_bytes = transfer_budget(managed_bytes);
        let transfer_allocation = NativeAllocation::new(transfer_bytes, &budget)?;
        let transfer = device
            .newBufferWithLength_options(transfer_bytes, MTLResourceOptions::StorageModeShared)
            .ok_or("Metal transfer allocation failed")?;
        let started = Instant::now();
        let options = MTLCompileOptions::new();
        #[allow(deprecated)]
        options.setFastMathEnabled(false);
        let library = device
            .newLibraryWithSource_options_error(
                &NSString::from_str(&format!(
                    "#define LATTICA_OPTIMIZED {}\n#define LATTICA_SPECIALIZED_DIAGONAL {}\n{}",
                    u8::from(optimized),
                    u8::from(tuning.specialized_diagonal),
                    include_str!("kernels.metal")
                )),
                Some(&options),
            )
            .map_err(|e| format!("Metal shader compilation: {e}"))?;
        let mut pipelines = HashMap::new();
        for &name in KERNELS {
            let function = library
                .newFunctionWithName(&NSString::from_str(name))
                .ok_or_else(|| format!("missing Metal kernel {name}"))?;
            let pipeline = device
                .newComputePipelineStateWithFunction_error(&function)
                .map_err(|e| format!("Metal pipeline {name}: {e}"))?;
            pipelines.insert(name, pipeline);
        }
        let compile_ns = started.elapsed().as_nanos();
        let tables = Arc::new(Mutex::new(resident::Tables::default()));
        let managed_limit = budget
            .limit
            .map_or_else(|| "none".to_owned(), |n| n.to_string());
        println!("metal_initialized backend=metal memory={mode:?} unified_memory=true compile_ns={compile_ns} transfer_staging_bytes={transfer_bytes} managed_limit_bytes={managed_limit} workspace_allowance_bytes={managed_bytes}");
        Ok(Self {
            queue: Queue(Arc::new(QueueInner {
                device,
                queue: command_queue,
                last: Mutex::new(None),
                pending: Mutex::new(Vec::new()),
                batch: Mutex::new(None),
                batch_limit,
                transfer,
                transfer_lock: Mutex::new(()),
                _transfer_allocation: transfer_allocation,
                budget,
                mode,
                operation_lock: Mutex::new(()),
            })),
            pipelines,
            compile_ns,
            tables,
            workgroup,
            optimized,
            tuning,
        })
    }
    pub fn workgroup(&self) -> usize {
        self.workgroup
    }
    pub fn ntt_tile_log2(&self) -> usize {
        self.tuning.ntt_tile_log2
    }
    pub fn prefix_fusion(&self) -> bool {
        self.tuning.prefix_fusion
    }
    pub fn queue(&self) -> &Queue {
        &self.queue
    }
    pub fn context(&self) -> &ProtocolObject<dyn MTLDevice> {
        &self.queue.0.device
    }
    pub fn max_buffer_length(&self) -> usize {
        self.context().maxBufferLength()
    }
    pub fn recommended_working_set(&self) -> usize {
        self.context().recommendedMaxWorkingSetSize() as usize
    }
    pub fn device_name(&self) -> String {
        self.context().name().to_string()
    }
    pub fn check_memory_mode(&self) -> Result<()> {
        if MemoryMode::from_env()? != self.queue.0.mode {
            return Err("Metal memory mode cannot change after initialization".into());
        }
        Ok(())
    }
    pub fn transfer_bytes(&self) -> usize {
        self.queue.0.transfer.length()
    }
    pub fn kernel_builder<'a>(&'a self, name: &'a str) -> KernelBuilder<'a> {
        KernelBuilder {
            runtime: self,
            name,
            args: Vec::new(),
            global: 0,
            local: None,
        }
    }
    pub fn report(&self) {
        self.queue
            .finish()
            .expect("Metal telemetry requires completed commands");
        diagnostics::report();
        let (live, peak) = backing::snapshot();
        println!("metal_backing live_bytes={live} peak_bytes={peak} limit_bytes=none shared_aliases_charged_once=true small_runtime_and_driver_in_rss_headroom=true");
        let tables = self.tables.lock().unwrap();
        let a = self.queue.0.budget.counters.lock().unwrap();
        println!("metal_tuning poseidon_diagonal={} ntt_tables={} ntt_tile_log2={} prefix_store={} quotient={}",
            if self.tuning.specialized_diagonal { "specialized" } else { "reference" },
            self.tuning.ntt_tables, self.tuning.ntt_tile_log2,
            if self.tuning.prefix_fusion { "fused" } else { "separate" },
            if self.tuning.gpu_quotient { "gpu" } else { "cpu" });
        println!("metal_resident pipeline={} kernel_variant={} workgroup={} batch_limit={} kernel_commands={} table_hits={} table_misses={} table_evictions={}", if resident::enabled() { "resident" } else { "reference" }, if self.optimized { "optimized" } else { "reference" }, self.workgroup, self.queue.0.batch_limit, a.kernel_commands, tables.hits, tables.misses, tables.evictions);
        println!("metal_checkpoint memory={:?} compile_ns={} managed_live_bytes={} managed_peak_bytes={} allocation_count={} driver_current_allocated_bytes={} kernel_calls={} kernel_ns={} blit_calls={} blit_ns={} host_copy_bytes={} host_copy_ns={} transfer_blit_bytes={} transfer_staging_bytes={}", self.queue.0.mode, self.compile_ns, a.live, a.peak, a.buffers, self.context().currentAllocatedSize(), a.kernels, a.kernel_ns, a.blits, a.blit_ns, a.host_copy_bytes, a.host_copy_ns, a.transfer_blit_bytes, self.transfer_bytes());
    }
}

struct BufferInner {
    raw: Object<dyn MTLBuffer>,
    queue: Queue,
    shared: bool,
    _allocation: NativeAllocation,
}
// CPU accesses and command encoding go through the queue's operation lock.
// Native command buffers retain these resources until execution completes.
unsafe impl Send for BufferInner {}
unsafe impl Sync for BufferInner {}
impl Drop for BufferInner {
    fn drop(&mut self) {
        // Native command buffers retain resource objects. Finish before returning
        // the corresponding budget permit, including failure/unwind paths.
        if let Err(e) = self.queue.finish() {
            eprintln!("FAILED Metal buffer cleanup: {e}");
            std::process::abort();
        }
    }
}
pub struct Buffer<T> {
    inner: Arc<BufferInner>,
    len: usize,
    _type: PhantomData<T>,
}
impl<T> Clone for Buffer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            len: self.len,
            _type: PhantomData,
        }
    }
}
impl Buffer<u64> {
    pub fn builder() -> BufferBuilder {
        BufferBuilder {
            queue: None,
            flags: 0,
            len: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn write<'a>(&'a self, source: &'a [u64]) -> Write<'a> {
        Write {
            buffer: self,
            source,
            offset: 0,
            event: None,
        }
    }
    pub fn read<'a>(&'a self, destination: &'a mut [u64]) -> Read<'a> {
        Read {
            buffer: self,
            destination,
            offset: 0,
            event: None,
        }
    }
    pub fn map(&self) -> MapBuilder<'_> {
        MapBuilder {
            buffer: self,
            len: self.len,
        }
    }
    pub fn cmd(&self) -> BufferCommand<'_> {
        BufferCommand {
            source: self,
            destination: None,
            count: self.len,
            offset: 0,
            fill: None,
            event: None,
            dependency: None,
        }
    }
    fn bounds(&self, offset: usize, len: usize) -> Result<()> {
        if offset.checked_add(len).is_none_or(|n| n > self.len) {
            Err("Metal transfer out of bounds".into())
        } else {
            Ok(())
        }
    }
    fn transfer(
        &self,
        pointer: *mut u8,
        offset: usize,
        bytes: usize,
        upload: bool,
    ) -> Result<Event> {
        let q = &self.inner.queue;
        let _operation =
            q.0.operation_lock
                .lock()
                .map_err(|_| "Metal operation poisoned")?;
        q.finish()?;
        let _guard =
            q.0.transfer_lock
                .lock()
                .map_err(|_| "Metal transfer poisoned")?;
        let mut commands = Vec::new();
        for start in (0..bytes).step_by(q.0.transfer.length()) {
            let count = (bytes - start).min(q.0.transfer.length());
            if self.inner.shared {
                let time = Instant::now();
                // SAFETY: checked byte ranges; serial queue drained above; the
                // caller's host slice is live for this blocking operation.
                unsafe {
                    let gpu = self
                        .inner
                        .raw
                        .contents()
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset + start);
                    let host = pointer.add(start);
                    if upload {
                        std::ptr::copy_nonoverlapping(host, gpu, count);
                    } else {
                        std::ptr::copy_nonoverlapping(gpu, host, count);
                    }
                }
                let mut a = q.0.budget.counters.lock().unwrap();
                a.host_copy_bytes += count as u64;
                a.host_copy_ns += time.elapsed().as_nanos();
            } else {
                let staging = q.0.transfer.contents().as_ptr().cast::<u8>();
                if upload {
                    let time = Instant::now();
                    unsafe {
                        std::ptr::copy_nonoverlapping(pointer.add(start), staging, count);
                    }
                    let mut a = q.0.budget.counters.lock().unwrap();
                    a.host_copy_bytes += count as u64;
                    a.host_copy_ns += time.elapsed().as_nanos();
                }
                let command = q.command(None)?;
                let encoder = autoreleasepool(|_| command.blitCommandEncoder())
                    .ok_or("Metal blit encoder unavailable")?;
                unsafe {
                    if upload {
                        encoder.copyFromBuffer_sourceOffset_toBuffer_destinationOffset_size(
                            &q.0.transfer,
                            0,
                            &self.inner.raw,
                            offset + start,
                            count,
                        );
                    } else {
                        encoder.copyFromBuffer_sourceOffset_toBuffer_destinationOffset_size(
                            &self.inner.raw,
                            offset + start,
                            &q.0.transfer,
                            0,
                            count,
                        );
                    }
                }
                encoder.endEncoding();
                let event = q.submit(command.clone(), false, "transfer_copy")?;
                event.wait_for()?;
                q.finish()?;
                commands.push(command);
                q.0.budget.counters.lock().unwrap().transfer_blit_bytes += count as u64;
                if !upload {
                    let time = Instant::now();
                    unsafe {
                        std::ptr::copy_nonoverlapping(staging, pointer.add(start), count);
                    }
                    let mut a = q.0.budget.counters.lock().unwrap();
                    a.host_copy_bytes += count as u64;
                    a.host_copy_ns += time.elapsed().as_nanos();
                }
            }
        }
        Ok(if commands.is_empty() {
            Event::Host
        } else {
            Event::Commands(commands)
        })
    }
}
pub struct BufferBuilder {
    queue: Option<Queue>,
    flags: u32,
    len: usize,
}
impl BufferBuilder {
    pub fn queue(mut self, queue: Queue) -> Self {
        self.queue = Some(queue);
        self
    }
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
    pub fn len(mut self, len: usize) -> Self {
        self.len = len;
        self
    }
    pub fn build(self) -> Result<Buffer<u64>> {
        let queue = self.queue.ok_or("missing Metal buffer queue")?;
        let bytes = self
            .len
            .checked_mul(8)
            .ok_or("Metal buffer length overflow")?;
        if bytes == 0 || bytes > queue.0.device.maxBufferLength() {
            return Err("Metal buffer size limit".into());
        }
        let allocation = NativeAllocation::new(bytes, &queue.0.budget)?;
        let shared =
            queue.0.mode == MemoryMode::Shared || self.flags & flags::MEM_ALLOC_HOST_PTR != 0;
        let options = if shared {
            MTLResourceOptions::StorageModeShared
        } else {
            MTLResourceOptions::StorageModePrivate
        };
        let raw = queue
            .0
            .device
            .newBufferWithLength_options(bytes, options)
            .ok_or("Metal buffer allocation failed")?;
        Ok(Buffer {
            inner: Arc::new(BufferInner {
                raw,
                queue,
                shared,
                _allocation: allocation,
            }),
            len: self.len,
            _type: PhantomData,
        })
    }
}

pub struct Write<'a> {
    buffer: &'a Buffer<u64>,
    source: &'a [u64],
    offset: usize,
    event: Option<&'a mut Event>,
}
impl<'a> Write<'a> {
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = n;
        self
    }
    pub fn queue(self, _: &Queue) -> Self {
        self
    }
    pub unsafe fn block(self, _: bool) -> Self {
        self
    }
    pub fn enew(mut self, e: &'a mut Event) -> Self {
        self.event = Some(e);
        self
    }
    pub fn enq(self) -> Result<()> {
        self.buffer.bounds(self.offset, self.source.len())?;
        let e = self.buffer.transfer(
            self.source.as_ptr().cast_mut().cast(),
            self.offset * 8,
            self.source.len() * 8,
            true,
        )?;
        if let Some(out) = self.event {
            *out = e;
        }
        Ok(())
    }
}
pub struct Read<'a> {
    buffer: &'a Buffer<u64>,
    destination: &'a mut [u64],
    offset: usize,
    event: Option<&'a mut Event>,
}
impl<'a> Read<'a> {
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = n;
        self
    }
    pub fn enew(mut self, e: &'a mut Event) -> Self {
        self.event = Some(e);
        self
    }
    pub fn enq(self) -> Result<()> {
        self.buffer.bounds(self.offset, self.destination.len())?;
        let e = self.buffer.transfer(
            self.destination.as_mut_ptr().cast(),
            self.offset * 8,
            self.destination.len() * 8,
            false,
        )?;
        if let Some(out) = self.event {
            *out = e;
        }
        Ok(())
    }
}
pub struct MapBuilder<'a> {
    buffer: &'a Buffer<u64>,
    len: usize,
}
impl MapBuilder<'_> {
    pub fn flags(self, _: u32) -> Self {
        self
    }
    pub fn len(mut self, n: usize) -> Self {
        self.len = n;
        self
    }
    pub unsafe fn enq(self) -> Result<MemMap<u64>> {
        if !self.buffer.inner.shared || self.len > self.buffer.len {
            return Err("Metal mapping requires shared storage and valid bounds".into());
        }
        self.buffer.inner.queue.finish()?;
        Ok(MemMap {
            buffer: self.buffer.clone(),
            len: self.len,
        })
    }
}
pub struct MemMap<T> {
    buffer: Buffer<T>,
    len: usize,
}
impl Deref for MemMap<u64> {
    type Target = [u64];
    fn deref(&self) -> &[u64] {
        unsafe {
            std::slice::from_raw_parts(self.buffer.inner.raw.contents().as_ptr().cast(), self.len)
        }
    }
}
impl DerefMut for MemMap<u64> {
    fn deref_mut(&mut self) -> &mut [u64] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.buffer.inner.raw.contents().as_ptr().cast(),
                self.len,
            )
        }
    }
}
pub struct Unmap<'a> {
    queue: Queue,
    event: Option<&'a mut Event>,
}
impl MemMap<u64> {
    pub fn unmap(&self) -> Unmap<'_> {
        Unmap {
            queue: self.buffer.inner.queue.clone(),
            event: None,
        }
    }
}
impl<'a> Unmap<'a> {
    pub fn enew(mut self, e: &'a mut Event) -> Self {
        self.event = Some(e);
        self
    }
    pub fn enq(self) -> Result<()> {
        self.queue.finish()?;
        if let Some(e) = self.event {
            *e = Event::Host;
        }
        Ok(())
    }
}

pub struct BufferCommand<'a> {
    source: &'a Buffer<u64>,
    destination: Option<&'a Buffer<u64>>,
    count: usize,
    offset: usize,
    fill: Option<u64>,
    event: Option<&'a mut Event>,
    dependency: Option<&'a Event>,
}
impl<'a> BufferCommand<'a> {
    pub fn fill(mut self, value: u64, count: Option<usize>) -> Self {
        self.fill = Some(value);
        self.count = count.unwrap_or(self.source.len);
        self
    }
    pub fn copy(
        mut self,
        to: &'a Buffer<u64>,
        offset: Option<usize>,
        count: Option<usize>,
    ) -> Self {
        self.destination = Some(to);
        self.offset = offset.unwrap_or(0);
        self.count = count.unwrap_or(self.source.len);
        self
    }
    pub fn enew(mut self, e: &'a mut Event) -> Self {
        self.event = Some(e);
        self
    }
    pub fn ewait(mut self, e: &'a Event) -> Self {
        self.dependency = Some(e);
        self
    }
    pub fn enq(self) -> Result<()> {
        self.source.bounds(0, self.count)?;
        let q = &self.source.inner.queue;
        let _operation =
            q.0.operation_lock
                .lock()
                .map_err(|_| "Metal operation poisoned")?;
        let command = q.command(self.dependency)?;
        let encoder = autoreleasepool(|_| command.blitCommandEncoder())
            .ok_or("Metal blit encoder unavailable")?;
        if let Some(value) = self.fill {
            if value != 0 {
                return Err("Metal bounded engine only admits zero fill".into());
            }
            let bytes = self.count * 8;
            for offset in (0..bytes).step_by(MAX_FILL_BYTES) {
                encoder.fillBuffer_range_value(
                    &self.source.inner.raw,
                    NSRange::new(offset, (bytes - offset).min(MAX_FILL_BYTES)),
                    0,
                );
            }
        } else {
            let destination = self.destination.ok_or("missing Metal copy destination")?;
            destination.bounds(self.offset, self.count)?;
            unsafe {
                encoder.copyFromBuffer_sourceOffset_toBuffer_destinationOffset_size(
                    &self.source.inner.raw,
                    0,
                    &destination.inner.raw,
                    self.offset * 8,
                    self.count * 8,
                );
            }
        }
        encoder.endEncoding();
        let event = q.submit(command, false, "buffer_blit")?;
        // Enqueues gated by test user events must remain asynchronous, so the
        // engine can exercise its existing failure-after-submission fences.
        if let Some(out) = self.event {
            *out = event;
        }
        Ok(())
    }
}

pub enum Arg {
    Buffer(Buffer<u64>),
    U32(u32),
    U64(u64),
    Local(usize),
}
impl From<&Buffer<u64>> for Arg {
    fn from(v: &Buffer<u64>) -> Self {
        Self::Buffer(v.clone())
    }
}
impl From<u32> for Arg {
    fn from(v: u32) -> Self {
        Self::U32(v)
    }
}
impl From<u64> for Arg {
    fn from(v: u64) -> Self {
        Self::U64(v)
    }
}
pub struct KernelBuilder<'a> {
    runtime: &'a ProQue,
    name: &'a str,
    args: Vec<Arg>,
    global: usize,
    local: Option<usize>,
}
impl KernelBuilder<'_> {
    pub fn arg(mut self, arg: impl Into<Arg>) -> Self {
        self.args.push(arg.into());
        self
    }
    pub fn arg_local<T>(mut self, count: usize) -> Self {
        self.args.push(Arg::Local(count * std::mem::size_of::<T>()));
        self
    }
    pub fn global_work_size(mut self, n: usize) -> Self {
        self.global = n;
        self
    }
    pub fn local_work_size(mut self, n: usize) -> Self {
        self.local = Some(n);
        self
    }
    pub fn build(self) -> Result<Kernel> {
        let pipeline = self
            .runtime
            .pipelines
            .get(self.name)
            .ok_or_else(|| format!("unsupported Metal kernel {}", self.name))?
            .clone();
        let local = self.local.unwrap_or(
            self.runtime
                .workgroup
                .min(pipeline.maxTotalThreadsPerThreadgroup())
                .min(self.global),
        );
        if self.global == 0 || local == 0 || local > pipeline.maxTotalThreadsPerThreadgroup() {
            return Err("Metal dispatch geometry".into());
        }
        if self.local.is_some() && self.global % local != 0 {
            return Err("Metal tiled dispatch is not a whole number of groups".into());
        }
        Ok(Kernel {
            queue: self.runtime.queue.clone(),
            pipeline,
            args: self.args,
            global: self.global,
            local,
            tiled: self.local.is_some(),
            phase: KERNELS.iter().copied().find(|n| *n == self.name).unwrap(),
        })
    }
}
pub struct Kernel {
    queue: Queue,
    pipeline: Object<dyn MTLComputePipelineState>,
    args: Vec<Arg>,
    global: usize,
    local: usize,
    tiled: bool,
    phase: &'static str,
}
impl Kernel {
    pub fn cmd(&self) -> KernelCommand<'_> {
        KernelCommand {
            kernel: self,
            event: None,
            dependency: None,
        }
    }
}
pub struct KernelCommand<'a> {
    kernel: &'a Kernel,
    event: Option<&'a mut Event>,
    dependency: Option<&'a Event>,
}
impl<'a> KernelCommand<'a> {
    pub fn enew(mut self, e: &'a mut Event) -> Self {
        self.event = Some(e);
        self
    }
    pub fn ewait(mut self, e: &'a Event) -> Self {
        self.dependency = Some(e);
        self
    }
    pub unsafe fn enq(self) -> Result<()> {
        let k = self.kernel;
        let _operation = k
            .queue
            .0
            .operation_lock
            .lock()
            .map_err(|_| "Metal operation poisoned")?;
        let (command, batch_event) = k.queue.compute_command(k.phase, self.dependency)?;
        let encoder = autoreleasepool(|_| command.computeCommandEncoder())
            .ok_or("Metal compute encoder unavailable")?;
        encoder.setComputePipelineState(&k.pipeline);
        for (index, arg) in k.args.iter().enumerate() {
            match arg {
                Arg::Buffer(buffer) => unsafe {
                    encoder.setBuffer_offset_atIndex(Some(&buffer.inner.raw), 0, index)
                },
                Arg::U32(value) => unsafe {
                    encoder.setBytes_length_atIndex(NonNull::from(value).cast(), 4, index)
                },
                Arg::U64(value) => unsafe {
                    encoder.setBytes_length_atIndex(NonNull::from(value).cast(), 8, index)
                },
                Arg::Local(bytes) => {
                    if *bytes + k.pipeline.staticThreadgroupMemoryLength()
                        > k.queue.0.device.maxThreadgroupMemoryLength()
                    {
                        return Err("Metal threadgroup memory limit".into());
                    }
                    unsafe { encoder.setThreadgroupMemoryLength_atIndex(*bytes, 0) }
                }
            }
        }
        let group = MTLSize {
            width: k.local,
            height: 1,
            depth: 1,
        };
        if k.tiled {
            encoder.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: k.global / k.local,
                    height: 1,
                    depth: 1,
                },
                group,
            );
        } else {
            encoder.dispatchThreads_threadsPerThreadgroup(
                MTLSize {
                    width: k.global,
                    height: 1,
                    depth: 1,
                },
                group,
            );
        }
        encoder.endEncoding();
        let event = if let Some(event) = batch_event {
            event
        } else {
            k.queue.submit(command, true, k.phase)?
        };
        if let Some(out) = self.event {
            *out = event;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
