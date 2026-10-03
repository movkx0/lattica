//! One serialized OpenCL context, with aggregate allocation accounting and a
//! process-lifetime exclusive lease shared by all candidate hashing jobs of a user.
use crate::config::Val;
pub mod lde_execute;
pub mod lde_plan;
mod lde_readback;
pub(crate) mod opening_reduce;
use ocl::{Buffer, Event, ProQue, Queue};
use p3_field::PrimeCharacteristicRing;
use rayon::prelude::*;
use std::{
    fs::File,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

const MIB: usize = 1 << 20;
const GIB: usize = 1 << 30;
const CONSTANT_BYTES: usize = (32 + 22 + 32 + 8) * 8;
/// Managed allocations deliberately leave 4 GiB below the 12 GiB job target for
/// driver/context overhead. Driver allocations are measured separately by the runner.
pub const MAX_MANAGED_BYTES: usize = 8 * GIB;
const DRIVER_RESERVE_BYTES: usize = 4 * GIB;
const MAX_DEVICE_EVENTS: usize = 65_536;
const QUERY_ELEMENTS: usize = 32 * 4;
const RETAINED_PATH_KERNEL: &str = r#"
__kernel void retained_merkle_path(
    __global const ulong *tree, __global ulong *output,
    uint height, uint index, uint path_len
) {
    uint level = get_global_id(0);
    if (level >= path_len) return;
    ulong rows = ((ulong)height) >> level;
    ulong preceding = 2ul * (ulong)height - 2ul * rows;
    ulong sibling = (((ulong)index) >> level) ^ 1ul;
    ulong offset = (preceding + sibling) * 4ul;
    for (uint word = 0; word < 4; ++word)
        output[level * 4 + word] = tree[offset + word];
}
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetainedLayout {
    elements: usize,
    cap_offset: usize,
    cap_rows: usize,
    path_len: usize,
}

fn retained_layout(
    height: usize,
    cap_height: usize,
    max_alloc: usize,
) -> Result<RetainedLayout, String> {
    if !height.is_power_of_two() || height > u32::MAX as usize {
        return Err("unsupported retained-tree height".into());
    }
    let depth = height.ilog2() as usize;
    let cap_bits = cap_height.min(depth);
    let cap_rows = 1usize << cap_bits;
    let nodes = height
        .checked_mul(2)
        .and_then(|n| n.checked_sub(1))
        .ok_or("retained-tree size overflow")?;
    let elements = nodes
        .checked_mul(4)
        .ok_or("retained-tree elements overflow")?;
    if elements
        .checked_mul(8)
        .ok_or("retained-tree bytes overflow")?
        > max_alloc
    {
        return Err("retained tree exceeds device per-allocation limit".into());
    }
    let cap_offset = (height - cap_rows)
        .checked_mul(8)
        .ok_or("retained cap offset overflow")?;
    Ok(RetainedLayout {
        elements,
        cap_offset,
        cap_rows,
        path_len: depth - cap_bits,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransferMode {
    Serial,
    Overlap,
}
impl TransferMode {
    fn slots(self) -> usize {
        match self {
            Self::Serial => 1,
            Self::Overlap => 2,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Serial => "serial",
            Self::Overlap => "overlap",
        }
    }
}
fn switch(name: &str) -> Result<bool, String> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(v) if v == "0" => Ok(false),
        Ok(v) if v == "1" => Ok(true),
        _ => Err(format!("{name} must be 0 or 1")),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub managed_bytes: usize,
    pub tile_bytes: usize,
    pub staging_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            managed_bytes: MAX_MANAGED_BYTES,
            tile_bytes: 128 * MIB,
            staging_bytes: 64 * MIB,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), String> {
        if self.managed_bytes > MAX_MANAGED_BYTES
            || self.managed_bytes == 0
            || self.tile_bytes == 0
            || self.tile_bytes > 128 * MIB
            || self.staging_bytes < 8
            || self.staging_bytes > 64 * MIB
            || self.staging_bytes % 8 != 0
        {
            return Err("invalid bounded GPU limits".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct Plan {
    rows: usize,
    input: usize,
    leaves: usize,
    parents: usize,
    bytes: usize,
}
#[cfg(test)]
fn plan(height: usize, width: usize, limits: Limits, max_alloc: usize) -> Result<Plan, String> {
    plan_slots(height, width, limits, max_alloc, 1)
}
fn plan_slots(
    height: usize,
    width: usize,
    limits: Limits,
    max_alloc: usize,
    slots: usize,
) -> Result<Plan, String> {
    limits.validate()?;
    if !matches!(slots, 1 | 2) || limits.staging_bytes % (slots * 8) != 0 {
        return Err("invalid GPU staging-pool geometry".into());
    }
    if !height.is_power_of_two()
        || height > u32::MAX as usize
        || width == 0
        || width > u32::MAX as usize
    {
        return Err("unsupported GPU row geometry".into());
    }
    let row_bytes = width.checked_mul(8).ok_or("GPU row size overflow")?;
    // tile_bytes and staging_bytes bound the WHOLE pool, not each slot.
    let slot_staging = limits.staging_bytes / slots;
    let slot_input = limits.tile_bytes / slots;
    // Downloads decode a complete four-field digest at a time. A narrow input
    // row alone is not a sufficient lower bound on staging-slot capacity.
    if slot_staging < core::mem::size_of::<[u64; 4]>() {
        return Err("GPU staging slot cannot hold one digest".into());
    }
    if row_bytes > slot_staging || row_bytes > slot_input {
        return Err("GPU row exceeds bounded staging/tile slot capacity".into());
    }
    let rows = height.min(slot_input.min(max_alloc) / row_bytes);
    if rows == 0 {
        return Err("GPU device allocation cap cannot hold one row".into());
    }
    let input = rows.checked_mul(width).ok_or("GPU input overflow")?;
    let leaves = height.checked_mul(4).ok_or("GPU leaves overflow")?;
    let parents = (height / 2)
        .max(1)
        .checked_mul(4)
        .ok_or("GPU parents overflow")?;
    let mut bytes = CONSTANT_BYTES
        .checked_add(limits.staging_bytes)
        .ok_or("GPU budget overflow")?;
    for (elements, copies) in [(input, slots), (leaves, 1), (parents, 1)] {
        let allocation = elements.checked_mul(8).ok_or("GPU allocation overflow")?;
        if allocation > max_alloc {
            return Err("GPU allocation exceeds device limit".into());
        }
        bytes = bytes
            .checked_add(allocation.checked_mul(copies).ok_or("GPU pool overflow")?)
            .ok_or("GPU total overflow")?;
    }
    if slot_staging > max_alloc || bytes > limits.managed_bytes {
        return Err("GPU aggregate allocation budget exceeded".into());
    }
    Ok(Plan {
        rows,
        input,
        leaves,
        parents,
        bytes,
    })
}

#[derive(Default, Debug, Clone, Copy)]
struct Accounting {
    live: usize,
    peak: usize,
    allocations: u64,
    retained_live: usize,
    retained_peak: usize,
    retained_trees: usize,
}

struct Lease {
    bytes: usize,
    accounting: Arc<Mutex<Accounting>>,
    retained: bool,
}
impl Lease {
    fn mark_retained(&mut self) -> Result<(), String> {
        if self.retained || self.bytes == 0 {
            return Err("invalid retained allocation lease".into());
        }
        let mut a = self.accounting.lock().unwrap();
        let next = a
            .retained_live
            .checked_add(self.bytes)
            .ok_or("retained allocation accounting overflow")?;
        let trees = a
            .retained_trees
            .checked_add(1)
            .ok_or("retained tree count overflow")?;
        if next > a.live {
            return Err("retained allocation exceeds live reservation".into());
        }
        a.retained_live = next;
        a.retained_peak = a.retained_peak.max(a.retained_live);
        a.retained_trees = trees;
        self.retained = true;
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut a = self.accounting.lock().unwrap();
        // A tree can be dropped by another thread while Engine is reporting or
        // replacing its workspace. Release both views in one critical section:
        // a separate retained lease would expose inconsistent intermediate totals.
        a.live -= self.bytes;
        if self.retained {
            a.retained_live -= self.bytes;
            a.retained_trees -= 1;
        }
    }
}
fn reserve(
    accounting: &Arc<Mutex<Accounting>>,
    bytes: usize,
    limit: usize,
) -> Result<Lease, String> {
    let mut a = accounting.lock().unwrap();
    let next = a.live.checked_add(bytes).ok_or("GPU accounting overflow")?;
    if next > limit {
        return Err("GPU aggregate allocation budget exceeded".into());
    }
    a.live = next;
    a.peak = a.peak.max(next);
    a.allocations += 1;
    Ok(Lease {
        bytes,
        accounting: accounting.clone(),
        retained: false,
    })
}
// Drop the OpenCL handle before releasing its budget reservation. No public clones.
struct Allocation {
    buffer: Buffer<u64>,
    _lease: Lease,
}
struct Staging {
    map: ocl::MemMap<u64>,
    _allocation: Allocation,
}
fn fatal_cleanup(stage: &str, error: impl std::fmt::Display) -> ! {
    // Continuing after an uncertain drain/unmap could release accounting while
    // the driver still owns allocations or borrows mapped host memory. Do not
    // turn such a failure into a recoverable adapter panic.
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "bounded_gpu_cleanup=FAIL stage={stage} error={error}; aborting worker"
    );
    std::process::abort();
}
impl Drop for Staging {
    fn drop(&mut self) {
        // MemMap's default Drop merely enqueues an unmap and ignores failures.
        // Wait before its backing allocation, reservation and job lease drop.
        let mut event = Event::empty();
        if let Err(error) = self.map.unmap().enew(&mut event).enq() {
            fatal_cleanup("staging_unmap_enqueue", error);
        }
        if let Err(error) = event.wait_for() {
            fatal_cleanup("staging_unmap_wait", error);
        }
    }
}
struct Workspace {
    input: Vec<Allocation>,
    a: Allocation,
    b: Allocation,
}

impl Workspace {
    fn bytes(&self) -> usize {
        (self.input.iter().map(|a| a.buffer.len()).sum::<usize>()
            + self.a.buffer.len()
            + self.b.buffer.len())
            * 8
    }
    fn fits(&self, p: Plan, slots: usize) -> bool {
        self.input.len() == slots
            && self.input.iter().all(|input| input.buffer.len() >= p.input)
            && self.a.buffer.len() >= p.leaves
            && self.b.buffer.len() >= p.parents
    }
}

/// A synchronous, immutable device tree. No unaccounted buffer clones escape.
/// Buffer and reservations drop before the shared process/context lease.
pub struct RetainedTree {
    storage: Allocation,
    height: usize,
    layout: RetainedLayout,
    cap: Vec<[Val; 4]>,
    _job_lease: Arc<File>,
}
impl RetainedTree {
    pub(super) fn cap(&self) -> &[[Val; 4]] {
        &self.cap
    }

    pub(super) fn open(&self, index: usize, cap_height: usize) -> Result<Vec<[Val; 4]>, String> {
        if index >= self.height
            || retained_layout(self.height, cap_height, usize::MAX)? != self.layout
        {
            return Err("retained-tree opening geometry mismatch".into());
        }
        let mut slot = ENGINE
            .get()
            .ok_or("GPU hashing was not initialized")?
            .lock()
            .map_err(|_| "GPU engine poisoned")?;
        let engine = slot.as_mut().ok_or("GPU hashing was shut down")?;
        if !Arc::ptr_eq(&engine._job_lease, &self._job_lease) {
            return Err("retained tree belongs to another GPU context".into());
        }
        engine.open_retained(self, index)
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Snapshot {
    pub commits: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub upload_and_marshal_ns: u128,
    pub download_and_decode_ns: u128,
    pub marshal_ns: u128,
    pub upload_wall_ns: u128,
    pub download_wall_ns: u128,
    pub decode_ns: u128,
    pub leaf_kernel_ns: u128,
    pub compress_kernel_ns: u128,
    pub hashing_wall_ns: u128,
    pub managed_live_bytes: usize,
    pub managed_peak_bytes: usize,
    pub allocations: u64,
    pub staging_bytes: usize,
    pub upload_device_ns: u128,
    pub download_device_ns: u128,
    pub upload_wait_ns: u128,
    pub slot_wait_ns: u128,
    pub tiles: u64,
    pub lde_commits: u64,
    pub lde_column_tiles: u64,
    pub lde_transform_ns: u128,
    pub lde_sponge_ns: u128,
    pub lde_wall_ns: u128,
    pub lde_host_reorder_ns: u128,
    pub lde_parallel_decode_bytes: u64,
    pub lde_parallel_decode_chunks: u64,
    pub quotient_lde_commits: u64,
    pub quotient_mask_ns: u128,
    pub lde_host_reordered_bytes: u64,
    pub lde_host_workspace_peak_bytes: usize,
    pub opening_calls: u64,
    pub opening_tiles: u64,
    pub opening_uploaded_bytes: u64,
    pub opening_downloaded_bytes: u64,
    pub opening_kernel_ns: u128,
    pub opening_wall_ns: u128,
    // Host spans and OpenCL event durations use different clocks and overlap.
    // These diagnose the opening consumer; they are not additive proof time.
    pub opening_marshal_ns: u128,
    pub opening_upload_api_ns: u128,
    pub opening_upload_device_ns: u128,
    pub opening_kernel_build_ns: u128,
    pub opening_kernel_enqueue_ns: u128,
    pub opening_kernel_wait_ns: u128,
    pub opening_download_api_ns: u128,
    pub opening_download_device_ns: u128,
    pub opening_decode_ns: u128,
    pub opening_pinned_uploaded_bytes: u64,
    pub opening_pinned_upload_chunks: u64,
    pub opening_compact_calls: u64,
    pub opening_compact_saved_input_bytes: u64,
    pub opening_compact_compress_ns: u128,
    pub opening_compact_ntt_ns: u128,
}

#[derive(Clone, Copy)]
struct DeviceInterval {
    kind: &'static str,
    start: u64,
    end: u64,
}
struct DeviceTimeline {
    enabled: bool,
    events: Vec<DeviceInterval>,
    dropped: u64,
}
impl DeviceTimeline {
    fn record(&mut self, kind: &'static str, event: &Event) -> Result<u128, String> {
        let (start, end) = event_range(event)?;
        self.record_interval(kind, start, end)
    }
    fn record_interval(
        &mut self,
        kind: &'static str,
        start: u64,
        end: u64,
    ) -> Result<u128, String> {
        let duration = end.checked_sub(start).ok_or("nonmonotonic GPU timeline")?;
        if self.enabled {
            if self.events.len() < MAX_DEVICE_EVENTS {
                self.events.push(DeviceInterval { kind, start, end });
            } else {
                self.dropped += 1;
            }
        }
        Ok(u128::from(duration))
    }
}

// All asynchronous writes borrow persistently mapped host storage. On any error
// or unwind, drain BOTH queues before that storage can be reused or released.
struct QueueFence {
    copy: Queue,
    compute: Queue,
    #[cfg(test)]
    fail_drain: bool,
}
impl QueueFence {
    fn finish(&self) -> Result<(), String> {
        #[cfg(test)]
        if self.fail_drain {
            return Err("injected queue drain failure".into());
        }
        let a = self.copy.finish();
        let b = self.compute.finish();
        a.and(b).map_err(|e| e.to_string())
    }
}
impl Drop for QueueFence {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            fatal_cleanup("queue_drain", error);
        }
    }
}

struct Engine {
    pq: ProQue,
    copy_queue: Queue,
    mode: TransferMode,
    timeline: DeviceTimeline,
    limits: Limits,
    max_alloc: usize,
    constants: [Allocation; 4],
    // Each mapping is dropped before its allocation. ENGINE serializes all access.
    staging: Vec<Staging>,
    workspace: Option<Workspace>,
    query: Option<Allocation>,
    retain_trees: bool,
    retained_copy_device_ns: u128,
    retained_query_device_ns: u128,
    retained_query_count: u64,
    retained_query_wall_ns: u128,
    #[cfg(test)]
    fail_retained_after_copy: bool,
    #[cfg(test)]
    panic_retained_after_copy: bool,
    #[cfg(test)]
    retained_copy_gate: Option<Event>,
    #[cfg(test)]
    retained_copy_submitted: Option<std::sync::mpsc::Sender<()>>,
    #[cfg(test)]
    fail_retained_query_after_enqueue: bool,
    #[cfg(test)]
    retained_query_submitted: Option<std::sync::mpsc::Sender<()>>,
    accounting: Arc<Mutex<Accounting>>,
    stats: Snapshot,
    #[cfg(test)]
    fail_lde_after_enqueue: Option<bool>,
    #[cfg(test)]
    fail_opening_after_enqueue: Option<bool>,
    #[cfg(test)]
    opening_gate: Option<Event>,
    #[cfg(test)]
    opening_submitted: Option<std::sync::mpsc::Sender<()>>,
    #[cfg(test)]
    lde_gate: Option<Event>,
    #[cfg(test)]
    lde_submitted: Option<std::sync::mpsc::Sender<()>>,
    #[cfg(test)]
    fail_next_upload: bool,
    #[cfg(test)]
    injected_event: Option<Event>,
    _job_lease: Arc<File>,
}
impl Drop for Engine {
    fn drop(&mut self) {
        // Covers normal shutdown and unexpected unwinding of a locally owned
        // engine. Staging::drop subsequently waits for each explicit unmap.
        drop(self.fence());
    }
}
static ENGINE: OnceLock<Mutex<Option<Engine>>> = OnceLock::new();
static INITIALIZE: Mutex<()> = Mutex::new(());

#[cfg(target_os = "linux")]
fn job_lease() -> Result<File, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let uid = unsafe { libc::geteuid() };
    // A fixed location: differing TMPDIR values must not bypass job serialization.
    let dir = std::path::Path::new("/tmp").join(format!("lattica-v2-gpu-lease-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.to_string()),
    }
    let meta = std::fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
        return Err("GPU lease directory must be private and owned by the current user".into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join("exclusive.lock"))
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o777 != 0o600 {
        return Err("invalid GPU lease file".into());
    }
    file.try_lock()
        .map_err(|e| format!("another candidate GPU hashing process holds the lease: {e}"))?;
    Ok(file)
}
#[cfg(not(target_os = "linux"))]
fn job_lease() -> Result<File, String> {
    Err("bounded GPU hashing currently requires Linux".into())
}

fn allocation(
    pq: &ProQue,
    accounting: &Arc<Mutex<Accounting>>,
    limits: Limits,
    max_alloc: usize,
    elements: usize,
    flags: ocl::flags::MemFlags,
) -> Result<Allocation, String> {
    let bytes = elements.checked_mul(8).ok_or("GPU buffer size overflow")?;
    if bytes == 0 || bytes > max_alloc {
        return Err("GPU per-allocation limit exceeded".into());
    }
    let lease = reserve(accounting, bytes, limits.managed_bytes)?;
    let buffer = Buffer::builder()
        .queue(pq.queue().clone())
        .flags(flags)
        .len(elements)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(Allocation {
        buffer,
        _lease: lease,
    })
}

pub(super) fn initialize(limits: Limits) -> Result<(), String> {
    let mode = if switch("LATTICA_V2_GPU_PIPELINE")? {
        TransferMode::Overlap
    } else {
        TransferMode::Serial
    };
    initialize_mode(limits, mode)
}

pub(super) fn initialize_mode(limits: Limits, mode: TransferMode) -> Result<(), String> {
    let retain_trees = switch("LATTICA_V2_GPU_RETAIN_TREES")?;
    let _guard = INITIALIZE
        .lock()
        .map_err(|_| "GPU initialization poisoned")?;
    if let Some(engine) = ENGINE.get() {
        if let Some(engine) = engine.lock().map_err(|_| "GPU engine poisoned")?.as_ref() {
            return if engine.limits == limits
                && engine.mode == mode
                && engine.retain_trees == retain_trees
            {
                Ok(())
            } else {
                Err("GPU limits/mode cannot change after initialization".into())
            };
        }
    }
    limits.validate()?;
    let lease = job_lease()?; // BEFORE creating a context or allocating anything on the device.
    let mut devices = Vec::new();
    for platform in ocl::Platform::list() {
        for device in ocl::Device::list(platform, Some(ocl::flags::DEVICE_TYPE_GPU))
            .map_err(|e| e.to_string())?
        {
            devices.push((platform, device));
        }
    }
    let index: usize = match std::env::var("LATTICA_V2_GPU_DEVICE") {
        Err(std::env::VarError::NotPresent) => 0,
        Ok(v) => v
            .parse()
            .map_err(|_| "LATTICA_V2_GPU_DEVICE must be an index")?,
        Err(e) => return Err(e.to_string()),
    };
    let (platform, device) = *devices
        .get(index)
        .ok_or("selected OpenCL GPU is unavailable")?;
    use ocl::core::{DeviceInfo, DeviceInfoResult};
    let max_alloc = match device
        .info(DeviceInfo::MaxMemAllocSize)
        .map_err(|e| e.to_string())?
    {
        DeviceInfoResult::MaxMemAllocSize(n) => {
            usize::try_from(n).map_err(|_| "GPU max allocation overflow")?
        }
        _ => return Err("GPU allocation limit unavailable".into()),
    };
    let global = match device
        .info(DeviceInfo::GlobalMemSize)
        .map_err(|e| e.to_string())?
    {
        DeviceInfoResult::GlobalMemSize(n) => {
            usize::try_from(n).map_err(|_| "GPU memory size overflow")?
        }
        _ => return Err("GPU global memory unavailable".into()),
    };
    if limits
        .managed_bytes
        .checked_add(DRIVER_RESERVE_BYTES)
        .ok_or("GPU limit overflow")?
        > global
    {
        return Err("GPU lacks capacity for the managed budget plus driver reserve".into());
    }
    plan_slots(1, 1, limits, max_alloc, mode.slots())?;
    let pq = ProQue::builder()
        .platform(platform)
        .device(device)
        .src(format!(
            "{}\n{}\n{}\n{}",
            crate::gpu::KERNEL_SRC,
            RETAINED_PATH_KERNEL,
            lde_execute::KERNEL_SRC,
            opening_reduce::KERNEL_SRC
        ))
        .queue_properties(ocl::flags::QUEUE_PROFILING_ENABLE)
        .dims(1)
        .build()
        .map_err(|e| e.to_string())?;
    let accounting = Arc::new(Mutex::new(Accounting::default()));
    let (rci, rcp, rcf, diag) = crate::gpu::poseidon2_consts();
    let mut constants = Vec::new();
    for values in [rci, rcp, rcf, diag] {
        let a = allocation(
            &pq,
            &accounting,
            limits,
            max_alloc,
            values.len(),
            ocl::flags::MEM_READ_ONLY,
        )?;
        a.buffer.write(&values).enq().map_err(|e| e.to_string())?;
        constants.push(a);
    }
    let copy_queue = if mode == TransferMode::Overlap {
        Queue::new(
            pq.context(),
            device,
            Some(ocl::flags::QUEUE_PROFILING_ENABLE),
        )
        .map_err(|e| e.to_string())?
    } else {
        pq.queue().clone()
    };
    let timeline_enabled = switch("LATTICA_PROFILE_TIMELINE")?;
    let mut staging = Vec::new();
    for _ in 0..mode.slots() {
        let a = allocation(
            &pq,
            &accounting,
            limits,
            max_alloc,
            limits.staging_bytes / mode.slots() / 8,
            ocl::flags::MEM_READ_WRITE | ocl::flags::MEM_ALLOC_HOST_PTR,
        )?;
        // SAFETY: persistent CPU mapping; QueueFence protects every DMA use.
        let map = unsafe {
            a.buffer
                .map()
                .flags(ocl::flags::MAP_READ | ocl::flags::MAP_WRITE)
                .len(limits.staging_bytes / mode.slots() / 8)
                .enq()
                .map_err(|e| e.to_string())?
        };
        staging.push(Staging {
            map,
            _allocation: a,
        });
    }
    pq.queue().finish().map_err(|e| e.to_string())?;
    println!(
        "bounded_gpu_initialized device_index={index} name={:?} global_bytes={global} max_allocation_bytes={max_alloc} managed_limit_bytes={} driver_reserve_bytes={DRIVER_RESERVE_BYTES} tile_bytes={} staging_bytes={} contexts=1 job_lease=exclusive",
        device.name().map_err(|e| e.to_string())?,
        limits.managed_bytes,
        limits.tile_bytes,
        limits.staging_bytes
    );
    println!(
        "bounded_gpu_transfer_mode mode={} slots={} queues={} input_pool_bytes={} staging_pool_bytes={} timeline={}",
        mode.name(),
        mode.slots(),
        mode.slots(),
        limits.tile_bytes,
        limits.staging_bytes,
        timeline_enabled
    );
    let engine = Engine {
        pq,
        copy_queue,
        mode,
        timeline: DeviceTimeline {
            enabled: timeline_enabled,
            events: Vec::new(),
            dropped: 0,
        },
        limits,
        max_alloc,
        constants: constants.try_into().ok().unwrap(),
        staging,
        workspace: None,
        query: None,
        retain_trees,
        retained_copy_device_ns: 0,
        retained_query_device_ns: 0,
        retained_query_count: 0,
        retained_query_wall_ns: 0,
        #[cfg(test)]
        fail_retained_after_copy: false,
        #[cfg(test)]
        panic_retained_after_copy: false,
        #[cfg(test)]
        retained_copy_gate: None,
        #[cfg(test)]
        retained_copy_submitted: None,
        #[cfg(test)]
        fail_retained_query_after_enqueue: false,
        #[cfg(test)]
        retained_query_submitted: None,
        accounting,
        stats: Snapshot::default(),
        #[cfg(test)]
        fail_lde_after_enqueue: None,
        #[cfg(test)]
        fail_opening_after_enqueue: None,
        #[cfg(test)]
        opening_gate: None,
        #[cfg(test)]
        opening_submitted: None,
        #[cfg(test)]
        lde_gate: None,
        #[cfg(test)]
        lde_submitted: None,
        #[cfg(test)]
        fail_next_upload: false,
        #[cfg(test)]
        injected_event: None,
        _job_lease: Arc::new(lease),
    };
    *ENGINE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "GPU engine poisoned")? = Some(engine);
    Ok(())
}

pub(super) fn preflight(height: usize, width: usize) -> Result<(), String> {
    let guard = ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let e = guard.as_ref().ok_or("GPU hashing was shut down")?;
    let p = plan_slots(height, width, e.limits, e.max_alloc, e.mode.slots())?;
    if e.retain_trees {
        e.admit_retained(p, height)?;
    }
    Ok(())
}

/// Snapshot only: not a memory reservation, arithmetic backend or proof result.
/// A future executor must replan/reserve under this mutex before device work.
pub fn plan_coset_lde_commit(
    inputs: &[lde_plan::InputShape],
    cap_height: usize,
    host_output_budget_bytes: usize,
) -> Result<lde_plan::LdeCommitPlan, String> {
    let guard = ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    let engine = guard.as_ref().ok_or("GPU hashing shut down")?;
    if !engine.retain_trees {
        return Err("resident LDE planning requires retained commitments".into());
    }
    let live = engine
        .accounting
        .lock()
        .map_err(|_| "GPU accounting poisoned")?
        .live;
    let old_workspace = engine.workspace.as_ref().map_or(0, Workspace::bytes);
    lde_plan::LdeCommitPlan::new(
        inputs,
        cap_height,
        engine.limits,
        engine.max_alloc,
        engine.mode.slots(),
        live,
        old_workspace,
        host_output_budget_bytes,
    )
}

pub(super) fn retention_enabled() -> Result<bool, String> {
    let slot = ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?;
    Ok(slot
        .as_ref()
        .ok_or("GPU hashing was shut down")?
        .retain_trees)
}

fn retained_peak(
    live: usize,
    old_workspace: usize,
    next_workspace: usize,
    tree_bytes: usize,
    query_reserve: usize,
    limit: usize,
) -> Result<usize, String> {
    let peak = live
        .checked_sub(old_workspace)
        .and_then(|n| n.checked_add(next_workspace))
        .and_then(|n| n.checked_add(tree_bytes))
        .and_then(|n| n.checked_add(query_reserve))
        .ok_or("retained-tree admission accounting overflow")?;
    if peak > limit {
        return Err("retained trees exceed whole-job GPU budget".into());
    }
    Ok(peak)
}

fn event_range(event: &Event) -> Result<(u64, u64), String> {
    use ocl::enums::{ProfilingInfo, ProfilingInfoResult};
    event.wait_for().map_err(|e| e.to_string())?;
    let start = match event
        .profiling_info(ProfilingInfo::Start)
        .map_err(|e| e.to_string())?
    {
        ProfilingInfoResult::Start(n) => n,
        _ => return Err("missing GPU start timestamp".into()),
    };
    let end = match event
        .profiling_info(ProfilingInfo::End)
        .map_err(|e| e.to_string())?
    {
        ProfilingInfoResult::End(n) => n,
        _ => return Err("missing GPU end timestamp".into()),
    };
    end.checked_sub(start).ok_or("nonmonotonic GPU clock")?;
    Ok((start, end))
}

impl Engine {
    fn download_buffer(
        &mut self,
        source: &Buffer<u64>,
        offset: usize,
        rows: usize,
    ) -> Result<Vec<[Val; 4]>, String> {
        let started = Instant::now();
        let mut output = vec![[Val::ZERO; 4]; rows];
        let rows_per_chunk = self.staging[0].map.len() / 4;
        for (chunk, dst) in output.chunks_mut(rows_per_chunk).enumerate() {
            let elements = dst.len() * 4;
            let transfer = Instant::now();
            let mut event = Event::empty();
            source
                .read(&mut self.staging[0].map[..elements])
                .offset(offset + chunk * rows_per_chunk * 4)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.download_wall_ns += transfer.elapsed().as_nanos();
            self.stats.download_device_ns += self.timeline.record("download", &event)?;
            let decode = Instant::now();
            dst.par_iter_mut()
                .zip(self.staging[0].map[..elements].par_chunks_exact(4))
                .for_each(|(dst, src)| *dst = core::array::from_fn(|i| Val::new(src[i])));
            self.stats.decode_ns += decode.elapsed().as_nanos();
            self.stats.downloaded_bytes += elements as u64 * 8;
        }
        self.stats.download_and_decode_ns += started.elapsed().as_nanos();
        Ok(output)
    }

    fn copy_retained_layer(
        &mut self,
        output: &Buffer<u64>,
        from_a: bool,
        offset: usize,
        rows: usize,
    ) -> Result<(), String> {
        let w = self.workspace.as_ref().unwrap();
        let source = if from_a { &w.a.buffer } else { &w.b.buffer };
        let mut event = Event::empty();
        let command = source
            .cmd()
            .copy(output, Some(offset), Some(rows * 4))
            .enew(&mut event);
        #[cfg(test)]
        let command = if let Some(gate) = self.retained_copy_gate.as_ref() {
            command.ewait(gate)
        } else {
            command
        };
        command.enq().map_err(|e| e.to_string())?;
        #[cfg(test)]
        {
            let fail = std::mem::take(&mut self.fail_retained_after_copy);
            let unwind = std::mem::take(&mut self.panic_retained_after_copy);
            if fail || unwind {
                self.injected_event = Some(event.clone());
                if let Some(notify) = self.retained_copy_submitted.take() {
                    use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
                    // The test's gate is still unreleased. Establish pending
                    // work before asking its helper to permit completion.
                    assert!(!matches!(
                        event.info(EventInfo::CommandExecutionStatus).unwrap(),
                        EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
                    ));
                    notify.send(()).unwrap();
                }
                if unwind {
                    panic!("injected unwind after retained copy submission");
                }
                return Err("injected retained-tree copy failure".into());
            }
        }
        self.retained_copy_device_ns += self.timeline.record("retain_copy", &event)?;
        Ok(())
    }

    fn hash_rows_retained(
        &mut self,
        height: usize,
        width: usize,
        cap_height: usize,
        fill: impl Fn(usize, &mut [u64]) + Sync,
    ) -> Result<RetainedTree, String> {
        if !self.retain_trees {
            return Err("GPU tree retention is not enabled".into());
        }
        let started = Instant::now();
        let p = plan_slots(
            height,
            width,
            self.limits,
            self.max_alloc,
            self.mode.slots(),
        )?;
        let layout = retained_layout(height, cap_height, self.max_alloc)?;
        self.admit_retained(p, height)?;
        self.workspace(p)?;
        let mut storage = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            layout.elements,
            ocl::flags::MEM_READ_WRITE,
        )?;
        storage._lease.mark_retained()?;
        // Declared AFTER the owned device allocation: on error or unwind the
        // queues drain before its OpenCL handle or budget reservation is dropped.
        let fence = self.fence();
        match self.mode {
            TransferMode::Serial => self.hash_leaves_serial(height, width, p, &fill)?,
            TransferMode::Overlap => self.hash_leaves_overlap(height, width, p, &fill)?,
        }
        let cap = self.finish_retained_layers(&storage, height, layout)?;
        fence.finish()?;
        self.stats.commits += 1;
        self.stats.hashing_wall_ns += started.elapsed().as_nanos();
        Ok(RetainedTree {
            storage,
            height,
            layout,
            cap,
            _job_lease: self._job_lease.clone(),
        })
    }

    // Caller owns storage and a queue fence declared after that allocation.
    fn finish_retained_layers(
        &mut self,
        storage: &Allocation,
        height: usize,
        layout: RetainedLayout,
    ) -> Result<Vec<[Val; 4]>, String> {
        self.copy_retained_layer(&storage.buffer, true, 0, height)?;
        let mut n = height;
        let mut from_a = true;
        let mut offset = height * 4;
        while n > 1 {
            n /= 2;
            let w = self.workspace.as_ref().unwrap();
            let (src, dst) = if from_a {
                (&w.a.buffer, &w.b.buffer)
            } else {
                (&w.b.buffer, &w.a.buffer)
            };
            let mut event = Event::empty();
            // SAFETY: the same bounded, distinct ping-pong buffers as the host
            // tree path; each retained copy finishes before its source is reused.
            unsafe {
                self.pq
                    .kernel_builder("compress_layer")
                    .arg(src)
                    .arg(dst)
                    .arg(n as u32)
                    .arg(&self.constants[0].buffer)
                    .arg(&self.constants[1].buffer)
                    .arg(&self.constants[2].buffer)
                    .arg(&self.constants[3].buffer)
                    .global_work_size(n)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.stats.compress_kernel_ns += self.timeline.record("compress", &event)?;
            from_a = !from_a;
            self.copy_retained_layer(&storage.buffer, from_a, offset, n)?;
            offset += n * 4;
        }
        debug_assert_eq!(offset, layout.elements);
        let cap = self.download_buffer(&storage.buffer, layout.cap_offset, layout.cap_rows)?;
        Ok(cap)
    }

    fn open_retained(
        &mut self,
        tree: &RetainedTree,
        index: usize,
    ) -> Result<Vec<[Val; 4]>, String> {
        if index >= tree.height
            || tree.layout.path_len * 4 > QUERY_ELEMENTS
            || !Arc::ptr_eq(&self._job_lease, &tree._job_lease)
        {
            return Err("retained-tree query context or bounds mismatch".into());
        }
        let started = Instant::now();
        if tree.layout.path_len == 0 {
            return Ok(Vec::new());
        }
        if self.query.is_none() {
            self.query = Some(allocation(
                &self.pq,
                &self.accounting,
                self.limits,
                self.max_alloc,
                QUERY_ELEMENTS,
                ocl::flags::MEM_READ_WRITE,
            )?);
        }
        let fence = self.fence();
        let query = &self.query.as_ref().unwrap().buffer;
        let mut event = Event::empty();
        // SAFETY: opening geometry and context were checked by RetainedTree.
        // One work-item writes four words per level, bounded by QUERY_ELEMENTS.
        unsafe {
            self.pq
                .kernel_builder("retained_merkle_path")
                .arg(&tree.storage.buffer)
                .arg(query)
                .arg(tree.height as u32)
                .arg(index as u32)
                .arg(tree.layout.path_len as u32)
                .global_work_size(tree.layout.path_len)
                .build()
                .map_err(|e| e.to_string())?
                .cmd()
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_retained_query_after_enqueue) {
            self.injected_event = Some(event.clone());
            if let Some(notify) = self.retained_query_submitted.take() {
                use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
                assert!(!matches!(
                    event.info(EventInfo::CommandExecutionStatus).unwrap(),
                    EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
                ));
                notify.send(()).unwrap();
            }
            return Err("injected retained-tree query failure".into());
        }
        self.retained_query_device_ns += self.timeline.record("path_gather", &event)?;
        // The clone is internal and synchronous; the accounted owner remains
        // in Engine until both queues are drained during shutdown.
        let source = self.query.as_ref().unwrap().buffer.clone();
        let output = self.download_buffer(&source, 0, tree.layout.path_len)?;
        fence.finish()?;
        self.retained_query_count += 1;
        self.retained_query_wall_ns += started.elapsed().as_nanos();
        Ok(output)
    }

    fn admit_retained(&self, p: Plan, height: usize) -> Result<(), String> {
        let layout = retained_layout(height, 0, self.max_alloc)?;
        let old_workspace = self.workspace.as_ref().map_or(0, Workspace::bytes);
        let next_workspace = if self
            .workspace
            .as_ref()
            .is_some_and(|w| w.fits(p, self.mode.slots()))
        {
            old_workspace
        } else {
            p.bytes - CONSTANT_BYTES - self.limits.staging_bytes
        };
        let live = self.accounting.lock().unwrap().live;
        retained_peak(
            live,
            old_workspace,
            next_workspace,
            layout.elements * 8,
            if self.query.is_none() {
                QUERY_ELEMENTS * 8
            } else {
                0
            },
            self.limits.managed_bytes,
        )?;
        Ok(())
    }

    fn fence(&self) -> QueueFence {
        QueueFence {
            copy: self.copy_queue.clone(),
            compute: self.pq.queue().clone(),
            #[cfg(test)]
            fail_drain: false,
        }
    }
    fn workspace(&mut self, p: Plan) -> Result<(), String> {
        if self.workspace.as_ref().is_some_and(|w| {
            w.input.len() == self.mode.slots()
                && w.input.iter().all(|input| input.buffer.len() >= p.input)
                && w.a.buffer.len() >= p.leaves
                && w.b.buffer.len() >= p.parents
        }) {
            return Ok(());
        }
        self.fence().finish()?;
        // Release every old allocation before replacement; no geometric over-allocation.
        self.workspace = None;
        let alloc = |n| {
            allocation(
                &self.pq,
                &self.accounting,
                self.limits,
                self.max_alloc,
                n,
                ocl::flags::MEM_READ_WRITE,
            )
        };
        self.workspace = Some(Workspace {
            input: (0..self.mode.slots())
                .map(|_| alloc(p.input))
                .collect::<Result<Vec<_>, _>>()?,
            a: alloc(p.leaves)?,
            b: alloc(p.parents)?,
        });
        let a = self.accounting.lock().unwrap();
        debug_assert_eq!(
            a.live,
            p.bytes + a.retained_live + self.query.as_ref().map_or(0, |q| q.buffer.len() * 8)
        );
        Ok(())
    }

    fn download(&mut self, from_a: bool, rows: usize) -> Result<Vec<[Val; 4]>, String> {
        let started = Instant::now();
        let workspace = self.workspace.as_ref().unwrap();
        let source = if from_a {
            &workspace.a.buffer
        } else {
            &workspace.b.buffer
        };
        let mut output = vec![[Val::ZERO; 4]; rows];
        let rows_per_chunk = self.staging[0].map.len() / 4;
        for (chunk, dst) in output.chunks_mut(rows_per_chunk).enumerate() {
            let elements = dst.len() * 4;
            let transfer = Instant::now();
            let mut event = Event::empty();
            source
                .read(&mut self.staging[0].map[..elements])
                .offset(chunk * rows_per_chunk * 4)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.download_wall_ns += transfer.elapsed().as_nanos();
            self.stats.download_device_ns += self.timeline.record("download", &event)?;
            let decode = Instant::now();
            dst.par_iter_mut()
                .zip(self.staging[0].map[..elements].par_chunks_exact(4))
                .for_each(|(dst, src)| *dst = core::array::from_fn(|i| Val::new(src[i])));
            self.stats.decode_ns += decode.elapsed().as_nanos();
            self.stats.downloaded_bytes += elements as u64 * 8;
        }
        self.stats.download_and_decode_ns += started.elapsed().as_nanos();
        Ok(output)
    }

    fn hash_leaves_serial(
        &mut self,
        height: usize,
        width: usize,
        p: Plan,
        fill: &(impl Fn(usize, &mut [u64]) + Sync),
    ) -> Result<(), String> {
        let mut row0 = 0;
        while row0 < height {
            let nr = p.rows.min(height - row0);
            let upload = Instant::now();
            let w = self.workspace.as_ref().unwrap();
            let chunk_rows = self.staging[0].map.len() / width;
            let mut done = 0;
            while done < nr {
                let rows = chunk_rows.min(nr - done);
                let marshal = Instant::now();
                self.staging[0].map[..rows * width]
                    .par_chunks_mut(width)
                    .enumerate()
                    .for_each(|(i, dst)| fill(row0 + done + i, dst));
                self.stats.marshal_ns += marshal.elapsed().as_nanos();
                let transfer = Instant::now();
                let mut transfer_event = Event::empty();
                w.input[0]
                    .buffer
                    .write(&self.staging[0].map[..rows * width])
                    .offset(done * width)
                    .enew(&mut transfer_event)
                    .enq()
                    .map_err(|e| e.to_string())?;
                self.stats.upload_wall_ns += transfer.elapsed().as_nanos();
                self.stats.upload_device_ns += self.timeline.record("upload", &transfer_event)?;
                self.stats.uploaded_bytes += (rows * width * 8) as u64;
                done += rows;
            }
            self.stats.upload_and_marshal_ns += upload.elapsed().as_nanos();
            let mut event = Event::empty();
            // SAFETY: plan checks u32 geometry and every buffer/offset; input is
            // filled synchronously, the in-order queue completes before reuse.
            unsafe {
                self.pq
                    .kernel_builder("leaf_hash")
                    .arg(&w.input[0].buffer)
                    .arg(&w.a.buffer)
                    .arg(row0 as u32)
                    .arg(nr as u32)
                    .arg(width as u32)
                    .arg(&self.constants[0].buffer)
                    .arg(&self.constants[1].buffer)
                    .arg(&self.constants[2].buffer)
                    .arg(&self.constants[3].buffer)
                    .global_work_size(nr)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.stats.leaf_kernel_ns += self.timeline.record("leaf", &event)?;
            self.stats.tiles += 1;
            row0 += nr;
        }
        Ok(())
    }

    fn hash_leaves_overlap(
        &mut self,
        height: usize,
        width: usize,
        p: Plan,
        fill: &(impl Fn(usize, &mut [u64]) + Sync),
    ) -> Result<(), String> {
        let mut kernels: [Option<Event>; 2] = [None, None];
        let mut uploads: [Option<Event>; 2] = [None, None];
        let mut row0 = 0;
        let mut tile = 0;
        while row0 < height {
            let slot = tile % 2;
            // The device input slot cannot be overwritten until its prior kernel ends.
            if let Some(event) = kernels[slot].take() {
                let wait = Instant::now();
                event.wait_for().map_err(|e| e.to_string())?;
                self.stats.slot_wait_ns += wait.elapsed().as_nanos();
                self.stats.leaf_kernel_ns += self.timeline.record("leaf", &event)?;
            }
            if let Some(event) = uploads[slot].take() {
                self.finish_upload(&event)?;
            }
            let nr = p.rows.min(height - row0);
            let upload = Instant::now();
            let chunk_rows = self.staging[slot].map.len() / width;
            let mut done = 0;
            while done < nr {
                // The CPU must not modify a mapped source while DMA reads it.
                if let Some(event) = uploads[slot].take() {
                    self.finish_upload(&event)?;
                }
                let rows = chunk_rows.min(nr - done);
                let marshal = Instant::now();
                self.staging[slot].map[..rows * width]
                    .par_chunks_mut(width)
                    .enumerate()
                    .for_each(|(i, dst)| fill(row0 + done + i, dst));
                self.stats.marshal_ns += marshal.elapsed().as_nanos();
                let mut event = Event::empty();
                let transfer = Instant::now();
                // SAFETY: the mapping is persistent, and is not reused until the
                // event completes. The caller's QueueFence also drains on unwind.
                unsafe {
                    self.workspace.as_ref().unwrap().input[slot]
                        .buffer
                        .write(&self.staging[slot].map[..rows * width])
                        .queue(&self.copy_queue)
                        .offset(done * width)
                        .block(false)
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                self.stats.upload_wall_ns += transfer.elapsed().as_nanos();
                self.stats.uploaded_bytes += (rows * width * 8) as u64;
                uploads[slot] = Some(event);
                self.copy_queue.flush().map_err(|e| e.to_string())?;
                #[cfg(test)]
                if std::mem::take(&mut self.fail_next_upload) {
                    self.injected_event = uploads[slot].clone();
                    return Err("injected failure after asynchronous upload".into());
                }
                done += rows;
            }
            self.stats.upload_and_marshal_ns += upload.elapsed().as_nanos();
            let w = self.workspace.as_ref().unwrap();
            let mut event = Event::empty();
            // SAFETY: the input and output ranges are admitted. The cross-queue
            // event orders the whole in-order upload stream before this kernel.
            unsafe {
                self.pq
                    .kernel_builder("leaf_hash")
                    .arg(&w.input[slot].buffer)
                    .arg(&w.a.buffer)
                    .arg(row0 as u32)
                    .arg(nr as u32)
                    .arg(width as u32)
                    .arg(&self.constants[0].buffer)
                    .arg(&self.constants[1].buffer)
                    .arg(&self.constants[2].buffer)
                    .arg(&self.constants[3].buffer)
                    .global_work_size(nr)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .ewait(uploads[slot].as_ref().unwrap())
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            kernels[slot] = Some(event);
            self.pq.queue().flush().map_err(|e| e.to_string())?;
            self.stats.tiles += 1;
            row0 += nr;
            tile += 1;
        }
        // Downloads reuse slot zero's host mapping, so both streams must be done.
        for slot in 0..2 {
            if let Some(event) = kernels[slot].take() {
                let wait = Instant::now();
                event.wait_for().map_err(|e| e.to_string())?;
                self.stats.slot_wait_ns += wait.elapsed().as_nanos();
                self.stats.leaf_kernel_ns += self.timeline.record("leaf", &event)?;
            }
            if let Some(event) = uploads[slot].take() {
                self.finish_upload(&event)?;
            }
        }
        Ok(())
    }
    fn finish_upload(&mut self, event: &Event) -> Result<(), String> {
        let wait = Instant::now();
        event.wait_for().map_err(|e| e.to_string())?;
        self.stats.upload_wait_ns += wait.elapsed().as_nanos();
        self.stats.upload_device_ns += self.timeline.record("upload", event)?;
        Ok(())
    }

    fn hash_rows(
        &mut self,
        height: usize,
        width: usize,
        fill: impl Fn(usize, &mut [u64]) + Sync,
    ) -> Result<Vec<Vec<[Val; 4]>>, String> {
        let started = Instant::now();
        let fence = self.fence();
        let p = plan_slots(
            height,
            width,
            self.limits,
            self.max_alloc,
            self.mode.slots(),
        )?;
        self.workspace(p)?;
        match self.mode {
            TransferMode::Serial => self.hash_leaves_serial(height, width, p, &fill)?,
            TransferMode::Overlap => self.hash_leaves_overlap(height, width, p, &fill)?,
        }
        let mut layers = vec![self.download(true, height)?];
        let mut n = height;
        let mut from_a = true;
        while n > 1 {
            n /= 2;
            let w = self.workspace.as_ref().unwrap();
            let (src, dst) = if from_a {
                (&w.a.buffer, &w.b.buffer)
            } else {
                (&w.b.buffer, &w.a.buffer)
            };
            let mut event = Event::empty();
            // SAFETY: distinct ping-pong buffers, n output rows, previous layer complete.
            unsafe {
                self.pq
                    .kernel_builder("compress_layer")
                    .arg(src)
                    .arg(dst)
                    .arg(n as u32)
                    .arg(&self.constants[0].buffer)
                    .arg(&self.constants[1].buffer)
                    .arg(&self.constants[2].buffer)
                    .arg(&self.constants[3].buffer)
                    .global_work_size(n)
                    .build()
                    .map_err(|e| e.to_string())?
                    .cmd()
                    .enew(&mut event)
                    .enq()
                    .map_err(|e| e.to_string())?;
            }
            self.stats.compress_kernel_ns += self.timeline.record("compress", &event)?;
            from_a = !from_a;
            layers.push(self.download(from_a, n)?);
        }
        fence.finish()?;
        self.stats.commits += 1;
        self.stats.hashing_wall_ns += started.elapsed().as_nanos();
        Ok(layers)
    }
    fn snapshot(&self) -> Snapshot {
        let a = self.accounting.lock().unwrap();
        Snapshot {
            managed_live_bytes: a.live,
            managed_peak_bytes: a.peak,
            allocations: a.allocations,
            staging_bytes: self.limits.staging_bytes,
            ..self.stats
        }
    }
}

pub(super) fn hash_rows(
    height: usize,
    width: usize,
    fill: impl Fn(usize, &mut [u64]) + Sync,
) -> Result<Vec<Vec<[Val; 4]>>, String> {
    ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?
        .as_mut()
        .ok_or("GPU hashing was shut down")?
        .hash_rows(height, width, fill)
}
pub(super) fn hash_rows_retained(
    height: usize,
    width: usize,
    cap_height: usize,
    fill: impl Fn(usize, &mut [u64]) + Sync,
) -> Result<RetainedTree, String> {
    ENGINE
        .get()
        .ok_or("GPU hashing was not initialized")?
        .lock()
        .map_err(|_| "GPU engine poisoned")?
        .as_mut()
        .ok_or("GPU hashing was shut down")?
        .hash_rows_retained(height, width, cap_height, fill)
}

pub fn report(label: &str) -> Option<Snapshot> {
    let mut guard = ENGINE.get()?.lock().expect("GPU engine poisoned");
    let e = guard.as_mut()?;
    let s = e.snapshot();
    {
        let a = e.accounting.lock().unwrap();
        println!(
            "bounded_gpu_retention_checkpoint label={label:?} enabled={} counters=cumulative retained_live_bytes={} retained_peak_bytes={} retained_trees={} copy_device_ns={} query_device_ns={} query_wall_ns={} queries={}",
            e.retain_trees,
            a.retained_live,
            a.retained_peak,
            a.retained_trees,
            e.retained_copy_device_ns,
            e.retained_query_device_ns,
            e.retained_query_wall_ns,
            e.retained_query_count
        );
    }
    println!(
        "bounded_gpu_checkpoint label={label:?} counters=cumulative commits={} uploaded_bytes={} downloaded_bytes={} upload_and_marshal_ns={} download_and_decode_ns={} leaf_kernel_ns={} compress_kernel_ns={} hashing_wall_ns={} managed_live_bytes={} managed_peak_bytes={} allocations={} staging_bytes={} marshal_ns={} upload_wall_ns={} download_wall_ns={} decode_ns={}",
        s.commits,
        s.uploaded_bytes,
        s.downloaded_bytes,
        s.upload_and_marshal_ns,
        s.download_and_decode_ns,
        s.leaf_kernel_ns,
        s.compress_kernel_ns,
        s.hashing_wall_ns,
        s.managed_live_bytes,
        s.managed_peak_bytes,
        s.allocations,
        s.staging_bytes,
        s.marshal_ns,
        s.upload_wall_ns,
        s.download_wall_ns,
        s.decode_ns
    );
    println!(
        "bounded_gpu_pipeline_checkpoint label={label:?} mode={} counters=cumulative upload_device_ns={} download_device_ns={} upload_api_ns={} upload_wait_ns={} slot_wait_ns={} tiles={}",
        e.mode.name(),
        s.upload_device_ns,
        s.download_device_ns,
        s.upload_wall_ns,
        s.upload_wait_ns,
        s.slot_wait_ns,
        s.tiles
    );
    println!(
        "bounded_gpu_lde_checkpoint label={label:?} counters=cumulative commits={} column_tiles={} transform_device_ns={} sponge_device_ns={} wall_ns={} host_reorder_ns={} host_reordered_bytes={} host_workspace_peak_bytes={}",
        s.lde_commits,
        s.lde_column_tiles,
        s.lde_transform_ns,
        s.lde_sponge_ns,
        s.lde_wall_ns,
        s.lde_host_reorder_ns,
        s.lde_host_reordered_bytes,
        s.lde_host_workspace_peak_bytes
    );
    println!(
        "bounded_gpu_quotient_checkpoint label={label:?} counters=cumulative commits={} mask_ns={}",
        s.quotient_lde_commits, s.quotient_mask_ns
    );
    println!(
        "bounded_gpu_readback_checkpoint label={label:?} counters=cumulative parallel_decode_bytes={} parallel_decode_chunks={}",
        s.lde_parallel_decode_bytes, s.lde_parallel_decode_chunks
    );
    println!(
        "bounded_gpu_opening_checkpoint label={label:?} counters=cumulative calls={} tiles={} uploaded_bytes={} downloaded_bytes={} kernel_ns={} wall_ns={}",
        s.opening_calls,
        s.opening_tiles,
        s.opening_uploaded_bytes,
        s.opening_downloaded_bytes,
        s.opening_kernel_ns,
        s.opening_wall_ns
    );
    println!(
        "bounded_gpu_opening_host_checkpoint label={label:?} counters=cumulative marshal_ns={} upload_api_ns={} upload_device_ns={} kernel_build_ns={} kernel_enqueue_ns={} kernel_wait_ns={} download_api_ns={} download_device_ns={} decode_ns={} timings=nonadditive",
        s.opening_marshal_ns,
        s.opening_upload_api_ns,
        s.opening_upload_device_ns,
        s.opening_kernel_build_ns,
        s.opening_kernel_enqueue_ns,
        s.opening_kernel_wait_ns,
        s.opening_download_api_ns,
        s.opening_download_device_ns,
        s.opening_decode_ns
    );
    println!(
        "bounded_gpu_opening_upload_checkpoint label={label:?} counters=cumulative pinned_uploaded_bytes={} pinned_chunks={}",
        s.opening_pinned_uploaded_bytes, s.opening_pinned_upload_chunks
    );
    println!(
        "bounded_gpu_opening_compact_checkpoint label={label:?} counters=cumulative calls={} saved_input_bytes={} compress_ns={} ntt_ns={} timings=nonadditive",
        s.opening_compact_calls, s.opening_compact_saved_input_bytes,
        s.opening_compact_compress_ns, s.opening_compact_ntt_ns
    );
    if e.timeline.enabled {
        println!(
            "gpu_timeline_checkpoint label={label:?} events={} dropped={} clock=opencl_device",
            e.timeline.events.len(),
            e.timeline.dropped
        );
        for event in e.timeline.events.drain(..) {
            println!(
                "gpu_timeline_interval label={label:?} kind={} start_ns={} end_ns={} clock=opencl_device",
                event.kind, event.start, event.end
            );
        }
        e.timeline.dropped = 0;
    }
    Some(s)
}

/// Quiescent research-runner teardown. Release device objects while retaining the
/// exclusive lease; do not rely on asynchronous driver cleanup at process exit.
pub fn shutdown() -> Result<(), String> {
    let _initialize = INITIALIZE
        .lock()
        .map_err(|_| "GPU initialization poisoned")?;
    let Some(slot) = ENGINE.get() else {
        return Ok(());
    };
    let mut slot = slot.lock().map_err(|_| "GPU engine poisoned")?;
    if let Some(engine) = slot.as_ref() {
        if Arc::strong_count(&engine._job_lease) != 1 {
            return Err("GPU shutdown refused: retained Merkle trees are still live".into());
        }
        engine.fence().finish()?;
    }
    if let Some(engine) = slot.take() {
        let accounting = engine.accounting.clone();
        drop(engine); // job lease is the last field dropped.
        let live = accounting.lock().unwrap().live;
        if live != 0 {
            return Err("GPU allocations survived shutdown".into());
        }
        println!("bounded_gpu_shutdown managed_live_bytes=0 lease_released=true");
    }
    Ok(())
}

#[cfg(test)]
pub(super) struct TestShutdownGuard;
#[cfg(test)]
impl Drop for TestShutdownGuard {
    fn drop(&mut self) {
        if let Err(error) = shutdown() {
            fatal_cleanup("test_adapter_shutdown", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(accounting: &Arc<Mutex<Accounting>>) -> Accounting {
        // Release the mutex before asserting: a failed assertion must not
        // poison accounting and trigger a second panic while leases drop.
        *accounting.lock().unwrap()
    }

    // Keep assertion failures from leaving an engine detached from the checked
    // shutdown path. The guard is declared before any returned tree handles.
    struct TestEngine(Option<Engine>);
    impl TestEngine {
        fn take() -> Self {
            Self(Some(ENGINE.get().unwrap().lock().unwrap().take().unwrap()))
        }
    }
    impl std::ops::Deref for TestEngine {
        type Target = Engine;
        fn deref(&self) -> &Engine {
            self.0.as_ref().unwrap()
        }
    }
    impl std::ops::DerefMut for TestEngine {
        fn deref_mut(&mut self) -> &mut Engine {
            self.0.as_mut().unwrap()
        }
    }
    impl Drop for TestEngine {
        fn drop(&mut self) {
            if let Some(engine) = self.0.take() {
                {
                    let mut slot = ENGINE.get().unwrap().lock().unwrap();
                    if slot.is_some() {
                        fatal_cleanup("test_engine_restore", "unexpected replacement engine");
                    }
                    *slot = Some(engine);
                }
                if let Err(error) = shutdown() {
                    fatal_cleanup("test_engine_shutdown", error);
                }
            }
        }
    }

    #[test]
    #[ignore = "requires OpenCL GPU and LATTICA_V2_GPU_RETAIN_TREES=1; run serially in <=3 GiB service"]
    fn gpu_lde_error_and_unwind_drain_before_transform_reservations_release() {
        use lde_execute::LdeInput;
        use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
        use p3_field::Field;
        use p3_matrix::dense::RowMajorMatrix;
        let limits = Limits {
            managed_bytes: 16 * MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        };
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        let mut e = TestEngine::take();
        let evaluations = RowMajorMatrix::new(vec![Val::ONE; 128 * 7], 7);
        let salts = RowMajorMatrix::new(vec![Val::ONE; 512 * 4], 4);
        let inputs = [LdeInput {
            evaluations: &evaluations,
            salts: &salts,
            added_bits: 2,
            shift: Val::GENERATOR,
        }];
        let p = plan_slots(512, 11, limits, e.max_alloc, 2).unwrap();
        e.workspace(p).unwrap();
        let before = e.snapshot().managed_live_bytes;
        // Invalid host admission must not allocate, consume GPU work or replace
        // the old workspace.
        let allocations = e.snapshot().allocations;
        assert!(e.coset_lde_commit(&inputs, 6, 8).is_err());
        assert_eq!(e.snapshot().allocations, allocations);
        assert_eq!(e.snapshot().managed_live_bytes, before);
        for unwind in [false, true] {
            let (gate, notify, release) = delayed_gate(&e);
            e.lde_gate = Some(gate);
            e.lde_submitted = Some(notify);
            e.fail_lde_after_enqueue = Some(unwind);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                e.coset_lde_commit(&inputs, 6, MIB)
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert!(matches!(
                e.injected_event
                    .take()
                    .unwrap()
                    .info(EventInfo::CommandExecutionStatus)
                    .unwrap(),
                EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
            ));
            release.join();
            e.lde_gate = None;
            assert_eq!(e.snapshot().managed_live_bytes, before);
            assert_eq!(counters(&e.accounting).retained_trees, 0);
        }
        let output = e.coset_lde_commit(&inputs, 6, MIB).unwrap();
        assert_eq!(counters(&e.accounting).retained_trees, 1);
        assert!(e.open_retained(&output.tree, 511).is_ok());
        drop(output);
        // A retained query buffer may now be live, but every transform/sponge
        // temporary and the failed attempts' trees have gone.
        assert_eq!(e.snapshot().managed_live_bytes, before + QUERY_ELEMENTS * 8);
        assert_eq!(counters(&e.accounting).retained_trees, 0);
    }

    #[test]
    #[ignore = "requires an OpenCL GPU and a serial <=3 GiB service"]
    fn gpu_opening_error_and_unwind_drain_before_allocations_release() {
        use crate::block_v2::profile::Challenge;
        use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
        use opening_reduce::{OpeningMatrix, OpeningTerm};
        let limits = Limits {
            managed_bytes: 16 * MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        };
        initialize_mode(limits, TransferMode::Serial).unwrap();
        let mut e = TestEngine::take();
        let values = vec![Val::ONE; 128 * 7];
        let denominators = vec![Challenge::ONE; 128];
        let inputs = [OpeningMatrix {
            values: &values,
            width: 7,
            terms: vec![OpeningTerm {
                inverse_denominators: &denominators,
                alpha_offset: Challenge::ONE,
                opened: Challenge::ZERO,
            }],
        }];
        let before = e.snapshot().managed_live_bytes;
        for unwind in [false, true] {
            let (gate, notify, release) = delayed_gate(&e);
            e.opening_gate = Some(gate);
            e.opening_submitted = Some(notify);
            e.fail_opening_after_enqueue = Some(unwind);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                e.reduce_openings(&inputs, Challenge::ONE)
            }));
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert!(matches!(
                e.injected_event
                    .take()
                    .unwrap()
                    .info(EventInfo::CommandExecutionStatus)
                    .unwrap(),
                EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
            ));
            release.join();
            e.opening_gate = None;
            assert_eq!(e.snapshot().managed_live_bytes, before);
            assert_eq!(counters(&e.accounting).retained_trees, 0);
        }
        let result = e.reduce_openings(&inputs, Challenge::ONE).unwrap();
        assert_eq!(result, vec![vec![-Challenge::from_u64(7); 128]]);
        assert_eq!(e.snapshot().managed_live_bytes, before);
    }

    #[test]
    #[ignore = "requires an OpenCL GPU and a serial <=3 GiB service"]
    fn gpu_compact_opening_compression_and_ntt_failures_drain_before_release() {
        use crate::block_v2::profile::Challenge;
        use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
        use opening_reduce::{OpeningMatrix, OpeningTerm};
        initialize_mode(
            Limits {
                managed_bytes: 16 * MIB,
                tile_bytes: 64 * 1024,
                staging_bytes: 32 * 1024,
            },
            TransferMode::Serial,
        )
        .unwrap();
        let mut engine = TestEngine::take();
        let values = vec![Val::ONE; 128 * 7];
        let denominators = vec![Challenge::ONE; 128];
        let inputs = [OpeningMatrix {
            values: &values,
            width: 7,
            terms: vec![OpeningTerm {
                inverse_denominators: &denominators,
                alpha_offset: Challenge::ONE,
                opened: Challenge::ZERO,
            }],
        }];
        let before = engine.snapshot().managed_live_bytes;
        for ntt in [false, true] {
            for unwind in [false, true] {
                let (gate, notify, release) = delayed_gate(&engine);
                if ntt {
                    engine.lde_gate = Some(gate);
                    engine.lde_submitted = Some(notify);
                    engine.fail_lde_after_enqueue = Some(unwind);
                } else {
                    engine.opening_gate = Some(gate);
                    engine.opening_submitted = Some(notify);
                    engine.fail_opening_after_enqueue = Some(unwind);
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    engine.reduce_openings_low_degree(
                        &inputs,
                        Challenge::ONE,
                        crate::block_v2::profile::LOG_BLOWUP,
                    )
                }));
                if unwind {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_err());
                }
                assert!(matches!(
                    engine
                        .injected_event
                        .take()
                        .unwrap()
                        .info(EventInfo::CommandExecutionStatus)
                        .unwrap(),
                    EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
                ));
                release.join();
                engine.lde_gate = None;
                engine.opening_gate = None;
                assert_eq!(engine.snapshot().managed_live_bytes, before);
                assert_eq!(counters(&engine.accounting).retained_trees, 0);
            }
        }
        assert_eq!(
            engine
                .reduce_openings_low_degree(
                    &inputs,
                    Challenge::ONE,
                    crate::block_v2::profile::LOG_BLOWUP
                )
                .unwrap(),
            vec![vec![-Challenge::from_u64(7); 128]]
        );
        assert_eq!(engine.snapshot().managed_live_bytes, before);
    }

    struct GateWorker {
        cancel: std::sync::mpsc::Sender<()>,
        thread: Option<std::thread::JoinHandle<bool>>,
    }
    impl GateWorker {
        fn join(mut self) {
            assert!(self.thread.take().unwrap().join().unwrap());
        }
    }
    impl Drop for GateWorker {
        fn drop(&mut self) {
            if let Some(worker) = self.thread.take() {
                // Even an earlier assertion failure must release the gate and
                // join its helper before the engine's teardown waits on queues.
                let _ = self.cancel.send(());
                let _ = worker.join();
            }
        }
    }
    fn delayed_gate(e: &Engine) -> (Event, std::sync::mpsc::Sender<()>, GateWorker) {
        let gate = Event::user(e.pq.context()).unwrap();
        let release_gate = gate.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let notified = rx.recv_timeout(std::time::Duration::from_secs(30)).is_ok();
            std::thread::sleep(std::time::Duration::from_millis(30));
            if let Err(error) = release_gate.set_complete() {
                fatal_cleanup("test_gate_release", error);
            }
            notified
        });
        (
            gate,
            tx.clone(),
            GateWorker {
                cancel: tx,
                thread: Some(worker),
            },
        )
    }

    #[test]
    fn retained_layout_covers_caps_and_every_path_boundary() {
        for height in [1usize, 2, 8, 64, 4096, 1 << 24] {
            for cap in [0usize, 1, 6, 32] {
                let layout = retained_layout(height, cap, usize::MAX).unwrap();
                assert_eq!(layout.elements, (height * 2 - 1) * 4);
                assert!(layout.cap_offset + layout.cap_rows * 4 <= layout.elements);
                let mut offset = 0;
                let mut rows = height;
                for level in 0..layout.path_len {
                    assert_eq!(offset, (2 * height - 2 * (height >> level)) * 4);
                    for index in [0, height / 2, height - 1] {
                        let sibling = (index >> level) ^ 1;
                        assert!(sibling < rows);
                        assert!(offset + sibling * 4 + 4 <= layout.elements);
                    }
                    offset += rows * 4;
                    rows /= 2;
                }
                assert_eq!((offset, rows), (layout.cap_offset, layout.cap_rows));
                assert!(retained_layout(height, cap, layout.elements * 8 - 1).is_err());
            }
        }
        for height in [0, 3, usize::MAX] {
            assert!(retained_layout(height, 0, usize::MAX).is_err());
        }
    }

    #[test]
    fn retained_admission_counts_previous_trees_workspace_and_query_reserve() {
        assert_eq!(retained_peak(600, 100, 150, 200, 32, 900).unwrap(), 882);
        assert!(retained_peak(600, 100, 150, 200, 32, 881).is_err());
        assert_eq!(retained_peak(600, 100, 100, 200, 0, 800).unwrap(), 800);
        assert!(retained_peak(600, 601, 0, 0, 0, 1000).is_err());
        assert!(retained_peak(usize::MAX, 0, 1, 1, 1, usize::MAX).is_err());
        let accounting = Arc::new(Mutex::new(Accounting::default()));
        let mut first = reserve(&accounting, 100, 300).unwrap();
        let mut second = reserve(&accounting, 200, 300).unwrap();
        first.mark_retained().unwrap();
        second.mark_retained().unwrap();
        assert!(first.mark_retained().is_err());
        assert_eq!(counters(&accounting).retained_trees, 2);
        drop(first);
        assert_eq!(counters(&accounting).retained_live, 200);
        assert_eq!(counters(&accounting).live, 200);
        drop(second);
        let a = counters(&accounting);
        assert_eq!(
            (a.retained_live, a.retained_peak, a.retained_trees),
            (0, 300, 0)
        );
        assert_eq!(a.live, 0);
    }

    #[test]
    fn retained_reservations_drop_atomically_under_concurrent_observation() {
        let accounting = Arc::new(Mutex::new(Accounting::default()));
        let leases: Vec<_> = (0..64)
            .map(|_| {
                let mut lease = reserve(&accounting, 32, 2048).unwrap();
                lease.mark_retained().unwrap();
                lease
            })
            .collect();
        let gate = Arc::new(std::sync::Barrier::new(2));
        let worker_gate = gate.clone();
        let worker = std::thread::spawn(move || {
            worker_gate.wait();
            for lease in leases {
                drop(lease);
                std::thread::yield_now();
            }
        });
        gate.wait();
        loop {
            let a = counters(&accounting);
            assert_eq!(a.live, a.retained_live);
            assert_eq!(a.retained_live, a.retained_trees * 32);
            let done = a.retained_trees == 0;
            if done {
                break;
            }
            std::thread::yield_now();
        }
        worker.join().unwrap();
        let a = counters(&accounting);
        assert_eq!((a.live, a.retained_live, a.retained_trees), (0, 0, 0));
        assert_eq!((a.peak, a.retained_peak), (2048, 2048));
    }
    #[test]
    #[ignore = "requires OpenCL GPU and LATTICA_V2_GPU_RETAIN_TREES=1; run serially"]
    fn gpu_retained_copy_error_and_unwind_release_reservations() {
        use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
        let limits = Limits {
            managed_bytes: 32 * MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        };
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        let mut e = TestEngine::take();
        assert!(e.retain_trees);
        let p = plan_slots(512, 17, limits, e.max_alloc, 2).unwrap();
        e.workspace(p).unwrap();
        let before = e.snapshot().managed_live_bytes;
        let fill = |row: usize, out: &mut [u64]| {
            for (col, value) in out.iter_mut().enumerate() {
                *value = (row * 17 + col) as u64;
            }
        };
        let (gate, notify, release) = delayed_gate(&e);
        e.retained_copy_gate = Some(gate);
        e.retained_copy_submitted = Some(notify);
        e.fail_retained_after_copy = true;
        assert!(e.hash_rows_retained(512, 17, 6, fill).is_err());
        assert!(matches!(
            e.injected_event
                .take()
                .unwrap()
                .info(EventInfo::CommandExecutionStatus)
                .unwrap(),
            EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
        ));
        release.join();
        e.retained_copy_gate = None;
        assert_eq!(e.snapshot().managed_live_bytes, before);
        assert_eq!(counters(&e.accounting).retained_live, 0);
        let (gate, notify, release) = delayed_gate(&e);
        e.retained_copy_gate = Some(gate);
        e.retained_copy_submitted = Some(notify);
        e.panic_retained_after_copy = true;
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = e.hash_rows_retained(512, 17, 6, fill);
        }));
        assert!(interrupted.is_err());
        assert!(matches!(
            e.injected_event
                .take()
                .unwrap()
                .info(EventInfo::CommandExecutionStatus)
                .unwrap(),
            EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
        ));
        release.join();
        e.retained_copy_gate = None;
        assert_eq!(e.snapshot().managed_live_bytes, before);
        assert_eq!(counters(&e.accounting).retained_trees, 0);
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = e.hash_rows_retained(512, 17, 6, |row, out| {
                if row == 5 {
                    panic!("injected retained hash unwind");
                }
                fill(row, out);
            });
        }));
        assert!(interrupted.is_err());
        assert_eq!(e.snapshot().managed_live_bytes, before);
        assert_eq!(counters(&e.accounting).retained_trees, 0);
        let tree = e.hash_rows_retained(512, 17, 6, fill).unwrap();
        let host = e.hash_rows(512, 17, fill).unwrap();
        assert_eq!(tree.cap(), host[tree.layout.path_len].as_slice());
        for index in [0usize, 63, 64, 255, 511] {
            let expected: Vec<_> = host[..tree.layout.path_len]
                .iter()
                .enumerate()
                .map(|(level, layer)| layer[(index >> level) ^ 1])
                .collect();
            assert_eq!(e.open_retained(&tree, index).unwrap(), expected);
        }
        assert!(e.open_retained(&tree, 512).is_err());
        drop(tree);
        assert_eq!(counters(&e.accounting).retained_live, 0);
        assert!(e.snapshot().managed_peak_bytes <= limits.managed_bytes);
        drop(e);
    }

    #[test]
    #[ignore = "requires OpenCL GPU and LATTICA_V2_GPU_RETAIN_TREES=1; run serially"]
    fn gpu_retained_query_error_drains_pending_kernel_and_preserves_tree() {
        use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
        let limits = Limits {
            managed_bytes: 32 * MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        };
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        let mut e = TestEngine::take();
        let tree = e
            .hash_rows_retained(512, 17, 6, |row, values| {
                for (col, value) in values.iter_mut().enumerate() {
                    *value = (row * 17 + col) as u64;
                }
            })
            .unwrap();
        let expected = e.open_retained(&tree, 255).unwrap();
        let before = e.snapshot().managed_live_bytes;
        let queries = e.retained_query_count;
        let (gate, notify, release) = delayed_gate(&e);
        let marker = e.pq.queue().enqueue_marker(Some(&gate)).unwrap();
        e.retained_query_submitted = Some(notify);
        e.fail_retained_query_after_enqueue = true;
        assert!(e.open_retained(&tree, 255).is_err());
        assert!(matches!(
            e.injected_event
                .take()
                .unwrap()
                .info(EventInfo::CommandExecutionStatus)
                .unwrap(),
            EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
        ));
        release.join();
        drop(marker);
        drop(gate);
        assert_eq!(e.snapshot().managed_live_bytes, before);
        assert_eq!(e.retained_query_count, queries);
        assert_eq!(counters(&e.accounting).retained_trees, 1);
        assert_eq!(e.open_retained(&tree, 255).unwrap(), expected);
        drop(tree);
        assert_eq!(counters(&e.accounting).retained_trees, 0);
        drop(e);
    }

    #[test]
    #[ignore = "requires OpenCL GPU and LATTICA_V2_GPU_RETAIN_TREES=1; run serially"]
    fn gpu_retained_admission_rejects_live_trees_and_recovers_after_drop() {
        let limits = Limits {
            managed_bytes: MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        };
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        let mut e = TestEngine::take();
        let fill = |row: usize, out: &mut [u64]| {
            for (col, value) in out.iter_mut().enumerate() {
                *value = (row * 17 + col) as u64;
            }
        };
        // The ordinary workspace and one retained tree fit in one MiB. A
        // second live tree, not the standalone geometry, causes rejection.
        let p = plan_slots(8192, 17, limits, e.max_alloc, 2).unwrap();
        e.admit_retained(p, 8192).unwrap();
        let tree = e.hash_rows_retained(8192, 17, 6, fill).unwrap();
        let expected_cap = tree.cap().to_vec();
        let before = e.snapshot();
        assert!(e.admit_retained(p, 8192).is_err());
        assert!(e
            .hash_rows_retained(8192, 17, 6, |_, _| panic!("admission ran the filler"))
            .is_err());
        assert_eq!(e.snapshot().managed_live_bytes, before.managed_live_bytes);
        assert_eq!(e.snapshot().commits, before.commits);
        drop(tree);
        e.admit_retained(p, 8192).unwrap();
        let replacement = e.hash_rows_retained(8192, 17, 6, fill).unwrap();
        assert_eq!(replacement.cap(), expected_cap.as_slice());
        assert!(e.snapshot().managed_peak_bytes <= limits.managed_bytes);
        drop(replacement);
        drop(e);
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires OpenCL GPU and retained trees; run serially with LimitCORE=0"]
    fn gpu_failed_drain_aborts_worker_and_releases_job_lease() {
        use std::io::Read;
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Child, Command, Stdio};
        const CHILD: &str = "LATTICA_GPU_DRAIN_FAILURE_TEST_CHILD";
        let limits = Limits {
            managed_bytes: MIB,
            tile_bytes: 64 * 1024,
            staging_bytes: 32 * 1024,
        };
        if std::env::var(CHILD).as_deref() == Ok("1") {
            initialize_mode(limits, TransferMode::Overlap).unwrap();
            let mut e = TestEngine::take();
            let _tree = e
                .hash_rows_retained(8192, 17, 6, |row, out| out.fill(row as u64))
                .unwrap();
            let mut fence = e.fence();
            fence.fail_drain = true;
            drop(fence);
            panic!("failed drain returned instead of aborting the worker");
        }
        struct Worker(Child);
        impl Drop for Worker {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        shutdown().unwrap();
        let mut worker = Worker(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "block_v2::gpu_hash::engine::tests::gpu_failed_drain_aborts_worker_and_releases_job_lease",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(status) = worker.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "drain-failure child timed out");
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let mut stderr = String::new();
        worker
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGABRT), "{stderr}");
        assert!(stderr.contains("bounded_gpu_cleanup=FAIL stage=queue_drain"));
        drop(worker);
        // A new process/context can reacquire the cooperative lease. This is
        // not a claim of instantaneous physical-driver memory reclamation.
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        let mut e = TestEngine::take();
        let tree = e
            .hash_rows_retained(8192, 17, 6, |row, out| out.fill(row as u64))
            .unwrap();
        drop(tree);
        drop(e);
    }

    #[test]
    fn device_timeline_is_bounded_and_rejects_nonmonotonic_intervals() {
        let mut timeline = DeviceTimeline {
            enabled: true,
            events: Vec::new(),
            dropped: 0,
        };
        for i in 0..MAX_DEVICE_EVENTS + 2 {
            assert_eq!(
                timeline
                    .record_interval("upload", i as u64, i as u64 + 3)
                    .unwrap(),
                3
            );
        }
        assert_eq!(timeline.events.len(), MAX_DEVICE_EVENTS);
        assert_eq!(timeline.dropped, 2);
        assert!(timeline.record_interval("download", 5, 4).is_err());
        assert_eq!(timeline.events.len(), MAX_DEVICE_EVENTS);
        timeline.enabled = false;
        assert_eq!(timeline.record_interval("download", 3, 9).unwrap(), 6);
        assert_eq!(timeline.dropped, 2);
    }

    #[test]
    fn two_slot_pool_preserves_aggregate_bounds_and_rejects_oversized_rows() {
        let limits = Limits::default();
        for width in [7, 33, 98, 176] {
            let serial = plan_slots(1 << 24, width, limits, 4 * GIB, 1).unwrap();
            let overlap = plan_slots(1 << 24, width, limits, 4 * GIB, 2).unwrap();
            assert!(overlap.input * 2 * 8 <= limits.tile_bytes);
            assert!(overlap.bytes <= serial.bytes + 16 * width);
            assert!(overlap.bytes < GIB);
            assert!(plan_slots(
                1 << 24,
                width,
                Limits {
                    managed_bytes: overlap.bytes - 1,
                    ..limits
                },
                4 * GIB,
                2
            )
            .is_err());
        }
        for slots in [0, 3, usize::MAX] {
            assert!(plan_slots(8, 1, limits, 4 * GIB, slots).is_err());
        }
        assert!(plan_slots(
            8,
            1,
            Limits {
                staging_bytes: 8,
                ..limits
            },
            4 * GIB,
            2
        )
        .is_err());
        assert!(plan_slots(8, limits.staging_bytes / 16 + 1, limits, 4 * GIB, 2).is_err());
    }

    #[test]
    #[ignore = "requires an OpenCL GPU; run serially under a <=3 GiB cap"]
    fn gpu_async_error_and_unwind_drain_before_buffer_reuse() {
        use ocl::enums::{CommandExecutionStatus, EventInfo, EventInfoResult};
        let limits = Limits {
            managed_bytes: 256 * MIB,
            tile_bytes: 16 * 1024,
            staging_bytes: 8 * 1024,
        };
        let fill = |row: usize, values: &mut [u64]| {
            for (col, value) in values.iter_mut().enumerate() {
                *value = (row * 41 + col) as u64;
            }
        };
        initialize_mode(limits, TransferMode::Serial).unwrap();
        let expected = {
            let mut e = TestEngine::take();
            e.hash_rows(128, 33, fill).unwrap()
        };
        shutdown().unwrap();
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        {
            let mut owned = TestEngine::take();
            let e: &mut Engine = &mut owned;
            let (gate, notify, release) = delayed_gate(e);
            let marker = e.copy_queue.enqueue_marker(Some(&gate)).unwrap();
            notify.send(()).unwrap();
            e.fail_next_upload = true;
            assert!(e.hash_rows(128, 33, fill).is_err());
            let event = e.injected_event.take().unwrap();
            assert!(matches!(
                event.info(EventInfo::CommandExecutionStatus).unwrap(),
                EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete)
            ));
            release.join();
            drop(event);
            drop(marker);
            drop(gate);
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                e.hash_rows(128, 33, |row, values| {
                    assert!(
                        row < 32,
                        "injected marshal panic after first tile submission"
                    );
                    fill(row, values);
                })
            }));
            assert!(panic.is_err());
            assert_eq!(e.hash_rows(128, 33, fill).unwrap(), expected);
            assert!(e.snapshot().managed_peak_bytes <= limits.managed_bytes);
        }
        shutdown().unwrap();
        // Reinitialization acquires the lease only after the prior buffers are gone.
        initialize_mode(limits, TransferMode::Overlap).unwrap();
        shutdown().unwrap();
    }

    #[test]
    fn checked_plan_enforces_aggregate_and_single_allocation_limits() {
        let limits = Limits::default();
        let p = plan(1 << 24, 176, limits, 4 * GIB).unwrap();
        assert!(p.bytes < GIB);
        assert_ne!((1 << 24) % p.rows, 0); // actual wide quotient uses a tiled remainder.
        assert!(plan(
            1 << 24,
            176,
            Limits {
                managed_bytes: p.bytes - 1,
                ..limits
            },
            4 * GIB
        )
        .is_err());
        assert!(plan(1 << 24, 176, limits, 256 * MIB).is_err());
        for (h, w) in [(0, 1), (3, 1), (1, 0), (usize::MAX, 1), (1, usize::MAX)] {
            assert!(plan(h, w, limits, 4 * GIB).is_err());
        }
        assert!(plan(
            1,
            1,
            Limits {
                managed_bytes: MAX_MANAGED_BYTES + 1,
                ..limits
            },
            4 * GIB
        )
        .is_err());
    }

    #[test]
    fn staging_pool_admits_a_complete_digest_in_each_slot() {
        for slots in [1usize, 2] {
            for staging_bytes in [8usize, 16, 24, 32, 40, 48, 56, 64] {
                let expected = staging_bytes % (slots * 8) == 0
                    && staging_bytes / slots >= core::mem::size_of::<[u64; 4]>();
                let result = plan_slots(
                    1,
                    1,
                    Limits {
                        staging_bytes,
                        ..Limits::default()
                    },
                    4 * GIB,
                    slots,
                );
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "slots={slots} staging={staging_bytes}"
                );
            }
        }
    }

    #[test]
    fn reservations_fail_before_allocation_and_release_on_error() {
        let accounting = Arc::new(Mutex::new(Accounting::default()));
        let one = reserve(&accounting, 700, 1000).unwrap();
        assert!(reserve(&accounting, 301, 1000).is_err());
        assert!(reserve(&accounting, usize::MAX, 1000).is_err());
        assert_eq!(counters(&accounting).live, 700);
        drop(one);
        assert_eq!(counters(&accounting).live, 0);
        let _two = reserve(&accounting, 1000, 1000).unwrap();
        assert_eq!(counters(&accounting).peak, 1000);
    }
}
