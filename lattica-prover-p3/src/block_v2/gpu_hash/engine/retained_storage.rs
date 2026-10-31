//! Immutable host backing for completed GPU digest trees. Construction keeps
//! the original device allocation; only completed trees may move to the host.
//! A query batch uploads one tree and runs the unchanged device gather kernel.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const MODE_ENV: &str = "LATTICA_V2_GPU_RETAINED_TREE_STORAGE";
const HOST_ENV: &str = "LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES";
const MAX_HOST_BYTES: usize = 32 << 30;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedTreeStorageMode {
    #[default]
    Device,
    HostBacking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Selection {
    pub mode: RetainedTreeStorageMode,
    pub host_bytes: usize,
}

impl Selection {
    fn parse(mode: Option<&str>, host: Option<&str>) -> Result<Self, String> {
        let mode = match mode {
            None | Some("device") => RetainedTreeStorageMode::Device,
            Some("host") => RetainedTreeStorageMode::HostBacking,
            _ => return Err("retained tree storage must be device or host".into()),
        };
        let host_bytes = match (mode, host) {
            (RetainedTreeStorageMode::Device, None) => 0,
            (RetainedTreeStorageMode::HostBacking, Some(value)) => value
                .parse::<usize>()
                .ok()
                .filter(|&bytes| bytes > 0 && bytes <= MAX_HOST_BYTES)
                .ok_or("host tree quota must be positive and at most 32 GiB")?,
            _ => return Err("host tree quota is required exactly for host storage".into()),
        };
        if mode == RetainedTreeStorageMode::HostBacking && !cfg!(feature = "gpu") {
            return Err("host tree storage is qualified only for OpenCL".into());
        }
        Ok(Self { mode, host_bytes })
    }

    pub(crate) fn from_env() -> Result<Self, String> {
        fn value(name: &str) -> Result<Option<String>, String> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(_) => Err("retained tree storage selection must be Unicode".into()),
            }
        }
        Self::parse(value(MODE_ENV)?.as_deref(), value(HOST_ENV)?.as_deref())
    }

    pub(crate) fn charged_tree_bytes(self, height: usize, cap: usize) -> Result<usize, String> {
        if self.mode == RetainedTreeStorageMode::Device {
            return Ok(0);
        }
        let layout = retained_layout(height, cap, usize::MAX)?;
        host_charge(layout)
    }
}

fn host_charge(layout: RetainedLayout) -> Result<usize, String> {
    let cap = layout
        .cap_rows
        .checked_mul(core::mem::size_of::<[Val; 4]>())
        .ok_or("host tree cap charge overflow")?;
    layout
        .elements
        .checked_mul(core::mem::size_of::<u64>())
        .and_then(|bytes| bytes.checked_add(cap))
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<RetainedTree>()))
        .ok_or_else(|| "host tree charge overflow".into())
}

pub(super) struct HostQuota {
    selection: Selection,
    live: AtomicUsize,
    peak: AtomicUsize,
    trees: AtomicUsize,
}

pub(super) struct HostReservation {
    bytes: usize,
    quota: Arc<HostQuota>,
}

impl HostQuota {
    pub(super) fn new(selection: Selection) -> Arc<Self> {
        Arc::new(Self {
            selection,
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            trees: AtomicUsize::new(0),
        })
    }

    pub(super) fn selection(&self) -> Selection {
        self.selection
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<HostReservation, String> {
        if bytes == 0 || self.selection.mode != RetainedTreeStorageMode::HostBacking {
            return Err("host tree reservation requires selected host storage".into());
        }
        let previous = self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                live.checked_add(bytes)
                    .filter(|&next| next <= self.selection.host_bytes)
            })
            .map_err(|_| "live host trees exceed their reserved worker allowance")?;
        self.peak.fetch_max(previous + bytes, Ordering::Relaxed);
        self.trees.fetch_add(1, Ordering::Relaxed);
        Ok(HostReservation {
            bytes,
            quota: Arc::clone(self),
        })
    }

    pub(super) fn report(&self, label: &str) {
        eprintln!("bounded_retained_tree_storage label={label:?} mode={:?} host_limit_bytes={} host_live_charged_bytes={} host_peak_charged_bytes={} host_trees={} original_device_construction_peak=true",
            self.selection.mode, self.selection.host_bytes,
            self.live.load(Ordering::Acquire), self.peak.load(Ordering::Relaxed),
            self.trees.load(Ordering::Relaxed));
    }

    pub(super) fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
}

impl Drop for HostReservation {
    fn drop(&mut self) {
        let previous = self.quota.live.fetch_sub(self.bytes, Ordering::AcqRel);
        debug_assert!(previous >= self.bytes);
        let trees = self.quota.trees.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(trees > 0);
    }
}

pub(super) struct HostBacking {
    // Payload is destroyed before its reservation on normal/error/unwind paths.
    words: Vec<u64>,
    _reservation: HostReservation,
}

pub(super) enum Storage {
    Device(Allocation),
    Host(HostBacking),
}

impl Storage {
    pub(super) fn host_backing_bytes(&self) -> Result<usize, String> {
        match self {
            Self::Device(_) => Ok(0),
            Self::Host(host) => host
                .words
                .capacity()
                .checked_mul(core::mem::size_of::<u64>())
                .ok_or_else(|| "host tree backing overflow".into()),
        }
    }
}

impl Engine {
    /// Reserve the entire future host owner before constructing its GPU tree.
    pub(super) fn reserve_host_tree(
        &self,
        layout: RetainedLayout,
    ) -> Result<Option<HostReservation>, String> {
        match self.tree_storage.selection.mode {
            RetainedTreeStorageMode::Device => Ok(None),
            RetainedTreeStorageMode::HostBacking => {
                self.tree_storage.reserve(host_charge(layout)?).map(Some)
            }
        }
    }

    /// All GPU hash/copy work must have completed before entry. A new fence
    /// keeps both payloads alive through every download and failure cleanup.
    pub(super) fn retain_completed_tree(
        &mut self,
        device: Allocation,
        reservation: Option<HostReservation>,
        layout: RetainedLayout,
    ) -> Result<Storage, String> {
        let Some(reservation) = reservation else {
            if self.tree_storage.selection.mode != RetainedTreeStorageMode::Device {
                return Err("host tree lost its pre-construction reservation".into());
            }
            return Ok(Storage::Device(device));
        };
        if !Arc::ptr_eq(&reservation.quota, &self.tree_storage)
            || reservation.bytes != host_charge(layout)?
            || device.buffer.len() != layout.elements
        {
            return Err("host tree reservation or source geometry mismatch".into());
        }
        let mut host = HostBacking {
            words: Vec::new(),
            _reservation: reservation,
        };
        host.words
            .try_reserve_exact(layout.elements)
            .map_err(|_| "host tree backing allocation failed")?;
        if host.words.capacity() != layout.elements {
            return Err("host tree capacity exceeds its reservation".into());
        }
        host.words.resize(layout.elements, 0);
        let fence = self.fence();
        let started = Instant::now();
        let chunk_words = self.staging[0].map.len();
        for (chunk, output) in host.words.chunks_mut(chunk_words).enumerate() {
            let mut event = Event::empty();
            let transfer = Instant::now();
            device
                .buffer
                .read(&mut self.staging[0].map[..output.len()])
                .offset(chunk * chunk_words)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.download_wall_ns += transfer.elapsed().as_nanos();
            self.stats.download_device_ns += self.timeline.record("tree_offload", &event)?;
            output.copy_from_slice(&self.staging[0].map[..output.len()]);
            self.stats.downloaded_bytes += (output.len() * 8) as u64;
        }
        fence.finish()?;
        self.stats.download_and_decode_ns += started.elapsed().as_nanos();
        eprintln!("bounded_retained_tree_offload payload_bytes={} charged_host_bytes={} actual_gpu_hashing=true device_tree_released_after_download=true",
            host.words.len() * 8, host._reservation.bytes);
        drop(device);
        Ok(Storage::Host(host))
    }

    fn upload_host_tree(&mut self, tree: &HostBacking) -> Result<Allocation, String> {
        let output = allocation(
            &self.pq,
            &self.accounting,
            self.limits,
            self.max_alloc,
            tree.words.len(),
            compute::flags::MEM_READ_ONLY,
        )?;
        let fence = self.fence();
        let started = Instant::now();
        let chunk_words = self.staging[0].map.len();
        for (chunk, words) in tree.words.chunks(chunk_words).enumerate() {
            self.staging[0].map[..words.len()].copy_from_slice(words);
            let mut event = Event::empty();
            let transfer = Instant::now();
            output
                .buffer
                .write(&self.staging[0].map[..words.len()])
                .offset(chunk * chunk_words)
                .enew(&mut event)
                .enq()
                .map_err(|e| e.to_string())?;
            self.stats.upload_wall_ns += transfer.elapsed().as_nanos();
            self.stats.upload_device_ns += self.timeline.record("tree_reload", &event)?;
            self.stats.uploaded_bytes += (words.len() * 8) as u64;
        }
        fence.finish()?;
        self.stats.upload_and_marshal_ns += started.elapsed().as_nanos();
        Ok(output)
    }

    pub(super) fn open_retained_batch(
        &mut self,
        tree: &RetainedTree,
        indices: &[usize],
    ) -> Result<Vec<Vec<[Val; 4]>>, String> {
        if indices.is_empty()
            || indices.len() > 256
            || indices.iter().any(|&index| index >= tree.height)
            || tree.layout.path_len * 4 > QUERY_ELEMENTS
            || !Arc::ptr_eq(&self._job_lease, &tree._job_lease)
        {
            return Err("retained tree batch context or geometry mismatch".into());
        }
        if tree.layout.path_len == 0 {
            // A cap containing every leaf has empty authentication paths.
            // Preserve multiplicity without inventing an upload or GPU gather.
            let mut output = Vec::new();
            output
                .try_reserve_exact(indices.len())
                .map_err(|_| "tree query batch allocation")?;
            if output.capacity() != indices.len() {
                return Err("tree query batch capacity exceeds its geometry".into());
            }
            output.resize_with(indices.len(), Vec::new);
            return Ok(output);
        }
        // Plan reload and the lazily-created query buffer together, before
        // either allocation. The engine mutex prevents another allocation
        // from consuming the admitted room between this check and upload.
        let upload = match &tree.storage {
            Storage::Device(_) => 0,
            Storage::Host(host) => host
                .words
                .len()
                .checked_mul(8)
                .ok_or("retained tree query upload overflow")?,
        };
        let query = if self.query.is_none() && tree.layout.path_len != 0 {
            QUERY_ELEMENTS * 8
        } else {
            0
        };
        let live = self.accounting.lock().unwrap().live;
        if upload > self.max_alloc
            || query > self.max_alloc
            || live
                .checked_add(upload)
                .and_then(|n| n.checked_add(query))
                .is_none_or(|n| n > self.limits.managed_bytes)
        {
            return Err("retained tree query batch exceeds managed memory".into());
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(indices.len())
            .map_err(|_| "tree query batch allocation")?;
        if output.capacity() != indices.len() {
            return Err("tree query batch capacity exceeds its geometry".into());
        }
        let uploaded = match &tree.storage {
            Storage::Device(_) => None,
            Storage::Host(host) => Some(self.upload_host_tree(host)?),
        };
        let source = match (&tree.storage, uploaded.as_ref()) {
            (Storage::Device(device), None) => &device.buffer,
            (Storage::Host(_), Some(device)) => &device.buffer,
            _ => return Err("retained tree query storage mismatch".into()),
        };
        // Every scalar gather drains before it returns; uploaded stays owned
        // until the entire batch succeeds or a failing gather drains on drop.
        for &index in indices {
            output.push(self.open_retained_buffer(tree, source, index)?);
        }
        if let Some(device) = uploaded {
            eprintln!("bounded_retained_tree_query_upload queries={} uploaded_bytes={} actual_gpu_gather=true uploads_per_tree_batch=1",
                indices.len(), device.buffer.len() * 8);
            drop(device);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
