//! A per-run shared, read-only copy of PUBLIC preprocessing prefixes on Linux and macOS.
//! The filename is only a lookup hint. Every cache hit is checked word-for-word
//! against fresh GPU readback before it can enter prover data. Salts, commitment
//! trees, witnesses and hiding RNG state are never shared by this module.
use crate::block_v2::worker_memory::MEMORY_BACKEND;
use super::{engine::lde_execute::LdeInput, engine::lde_readback::ColumnReadback};
use crate::{block_v2::worker_memory, config::Val};
use p3_field::PrimeField64;
use std::{
    collections::hash_map::DefaultHasher,
    fs::{File, OpenOptions},
    hash::{Hash, Hasher},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    ptr::NonNull,
};

fn pool_bytes(dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if !matches!(path.extension().and_then(|s| s.to_str()), Some("prefix" | "partial")) { continue; }
        let m = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            // An aborted writer unmaps before removing its partial file.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        };
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.nlink() != 1 {
            return Err("invalid shared preprocessing pool entry".into());
        }
        total = total.checked_add(m.len()).ok_or("shared preprocessing pool overflow")?;
    }
    Ok(total)
}

#[cfg(test)]
fn check_pool_capacity(dir: &Path, requested: u64, capacity: u64) -> Result<(), String> {
    let total = pool_bytes(dir)?.checked_add(requested).ok_or("shared preprocessing pool overflow")?;
    if total > capacity { return Err("shared preprocessing pool capacity exceeded".into()); }
    Ok(())
}

/// Caller holds the capacity lock and the new key's exclusive writer lock.
/// Each mapped reader holds a separate shared reader lease, so successful exclusive
/// acquisition proves unlink cannot leave hidden live mappings outside the cap.
fn reserve_pool_capacity(dir: &Path, requested: u64, capacity: u64) -> Result<(), String> {
    let mut total = pool_bytes(dir)?.checked_add(requested).ok_or("shared preprocessing pool overflow")?;
    if total <= capacity { return Ok(()); }
    if requested > capacity { return Err("public prefix exceeds shared preprocessing capacity".into()); }
    let mut candidates = std::fs::read_dir(dir).map_err(|e| e.to_string())?
        .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
    candidates.sort();
    for path in candidates {
        if path.extension().and_then(|s| s.to_str()) != Some("prefix") { continue; }
        let key = path.file_stem().and_then(|s| s.to_str()).ok_or("invalid public prefix filename")?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_hexdigit()) { continue; }
        let lease = worker_memory::lock_file(&dir.join(format!("{key}.lock")))?;
        if !worker_memory::lock(&lease, true)? { continue; }
        let readers = worker_memory::lock_file(&dir.join(format!("{key}.readers.lock")))?;
        if !worker_memory::lock(&readers, true)? { continue; }
        let m = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o400 || m.nlink() != 1 {
            return Err("invalid public prefix eviction candidate".into());
        }
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        total = total.checked_sub(m.len()).ok_or("shared preprocessing capacity accounting")?;
        eprintln!("{MEMORY_BACKEND}_shared_preprocessing_evicted pid={} key={key} inode={} bytes={} clock_ns={}",
            std::process::id(), m.ino(), m.len(), worker_memory::clock_ns());
        if total <= capacity { return Ok(()); }
    }
    Err("shared preprocessing capacity is occupied by live readers or writers".into())
}

fn shared_lock(file: &File) -> Result<(), String> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } == 0 { return Ok(()); }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted { return Err(e.to_string()); }
    }
}

struct Mapping {
    pointer: NonNull<Val>,
    elements: usize,
    file: File,
}
impl Mapping {
    fn new(file: File, elements: usize, write: bool) -> Result<Self, String> {
        let bytes = elements
            .checked_mul(8)
            .filter(|&b| b > 0 && b <= isize::MAX as usize)
            .ok_or("shared preprocessing size overflow")?;
        if file.metadata().map_err(|e| e.to_string())?.len() != bytes as u64 {
            return Err("shared preprocessing file length differs".into());
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | if write { libc::PROT_WRITE } else { 0 },
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self {
            pointer: NonNull::new(ptr.cast()).unwrap(),
            elements,
            file,
        })
    }
    fn values(&self) -> &[Val] {
        const {
            assert!(size_of::<Val>() == 8 && align_of::<Val>() == align_of::<u64>());
        }
        // Goldilocks is repr(transparent) and every u64 is a valid representation.
        // mmap is page-aligned. The mapping owns this complete byte range.
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.elements) }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), self.elements * 8);
        }
    }
}

pub(crate) struct SharedPrefix {
    // Drop the mapping before its shared lease, including on unwind.
    mapping: Mapping,
    _reader_lease: File,
}
// Published mappings have PROT_READ, no mutable API and no mutable aliases.
unsafe impl Send for SharedPrefix {}
unsafe impl Sync for SharedPrefix {}
impl SharedPrefix {
    pub(crate) fn values(&self) -> &[Val] {
        self.mapping.values()
    }
}

pub(super) struct SharedReadback {
    mapping: Option<Mapping>,
    _cache_lease: Option<File>,
    _writer_lock: Option<File>,
    partial: Option<PathBuf>,
    ready: PathBuf,
    height: usize,
    width: usize,
    columns: usize,
    initialized: usize,
}
impl SharedReadback {
    pub(super) fn for_public_input(
        input: &LdeInput<'_>,
        height: usize,
        columns: usize,
    ) -> Result<Option<Self>, String> {
        let Some(dir) = std::env::var_os(crate::block_v2::worker_memory::env_name("SHARED_PREPROCESSING_DIR")) else {
            return Ok(None);
        };
        let mut key = DefaultHasher::new();
        // A lookup key, NOT an authenticity check: fresh GPU output is compared
        // in full on every hit. Changed input/geometry gets a separate mapping.
        (
            "lattica-apple-public-prefix-v1",
            height,
            input.evaluations.width,
            input.added_bits,
            input.shift.as_canonical_u64(),
        )
            .hash(&mut key);
        let values = &input.evaluations.values;
        let bytes =
            unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), values.len() * 8) };
        bytes.hash(&mut key);
        Self::open(
            &PathBuf::from(dir),
            &format!("{:016x}", key.finish()),
            height,
            input.evaluations.width,
            columns,
        )
        .map(Some)
    }

    fn open(
        dir: &Path,
        key: &str,
        height: usize,
        width: usize,
        columns: usize,
    ) -> Result<Self, String> {
        let elements = height
            .checked_mul(width)
            .filter(|&n| n > 0 && n <= isize::MAX as usize / 8)
            .ok_or("invalid shared preprocessing dimensions")?;
        if columns == 0 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid shared preprocessing key/columns".into());
        }
        worker_memory::private_directory(dir)?;
        let lock = worker_memory::lock_file(&dir.join(format!("{key}.lock")))?;
        worker_memory::lock(&lock, false)?;
        // A separate shared lease avoids non-atomic flock EX-to-SH conversion.
        // Eviction acquires both locks nonblockingly; mappings retain the reader
        // lease until after munmap, even if publication or validation fails.
        let reader_lease = worker_memory::lock_file(&dir.join(format!("{key}.readers.lock")))?;
        shared_lock(&reader_lease)?;
        let ready = dir.join(format!("{key}.prefix"));
        let open = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&ready);
        let (mapping, partial, writer_lock) = match open {
            Ok(file) => {
                let m = file.metadata().map_err(|e| e.to_string())?;
                if !m.is_file()
                    || m.uid() != unsafe { libc::geteuid() }
                    || m.mode() & 0o777 != 0o400
                    || m.nlink() != 1
                {
                    return Err("invalid shared preprocessing file ownership/mode".into());
                }
                (Mapping::new(file, elements, false)?, None, None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Serialize different public keys while reserving the finite cache pool.
                let capacity_lock = worker_memory::lock_file(&dir.join("capacity.lock"))?;
                worker_memory::lock(&capacity_lock, false)?;
                if let Some(capacity) = std::env::var_os(worker_memory::env_name("SHARED_PREPROCESSING_MAX_BYTES")) {
                    let capacity: u64 = capacity.to_str().and_then(|v| v.parse().ok())
                        .filter(|n| *n > 0).ok_or("invalid shared preprocessing capacity")?;
                    reserve_pool_capacity(dir, (elements * 8) as u64, capacity)?;
                }
                let path = dir.join(format!(
                    "{key}.{}.{}.partial",
                    std::process::id(),
                    worker_memory::clock_ns()
                ));
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)
                    .map_err(|e| e.to_string())?;
                let result = file
                    .set_len((elements * 8) as u64)
                    .map_err(|e| e.to_string())
                    .and_then(|_| Mapping::new(file, elements, true));
                let mapping = match result {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = std::fs::remove_file(path);
                        return Err(e);
                    }
                };
                drop(capacity_lock);
                (
                    mapping,
                    Some(path),
                    Some(lock),
                )
            }
            Err(e) => return Err(e.to_string()),
        };
        let cache_hit = partial.is_none();
        let readback = Self {
            mapping: Some(mapping),
            _cache_lease: Some(reader_lease),
            _writer_lock: writer_lock,
            partial,
            ready,
            height,
            width,
            columns: columns.min(width),
            initialized: 0,
        };
        eprintln!("{MEMORY_BACKEND}_shared_preprocessing pid={} key={key} cache_hit={cache_hit} bytes={} inode={} validation=fresh_gpu_readback",
            std::process::id(), elements * 8, readback.mapping.as_ref().unwrap().file.metadata().map_err(|e| e.to_string())?.ino());
        Ok(readback)
    }
    pub(super) fn finish(mut self) -> Result<SharedPrefix, String> {
        if self.initialized != self.height * self.width {
            return Err("shared preprocessing readback incomplete".into());
        }
        let mapping = self.mapping.as_ref().unwrap();
        if let Some(path) = &self.partial {
            if unsafe {
                libc::mprotect(
                    mapping.pointer.as_ptr().cast(),
                    mapping.elements * 8,
                    libc::PROT_READ,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            mapping
                .file
                .set_permissions(std::fs::Permissions::from_mode(0o400))
                .map_err(|e| e.to_string())?;
            // MAP_SHARED writes are already coherent between processes. Atomic
            // publication under flock exposes only a completely initialized file.
            let capacity_lock = worker_memory::lock_file(&self.ready.parent().unwrap().join("capacity.lock"))?;
            worker_memory::lock(&capacity_lock, false)?;
            std::fs::rename(path, &self.ready).map_err(|e| e.to_string())?;
            self.partial = None;
        }
        eprintln!("{MEMORY_BACKEND}_shared_preprocessing_ready pid={} inode={} bytes={} validation=complete clock_ns={}",
            std::process::id(), mapping.file.metadata().map_err(|e| e.to_string())?.ino(),
            mapping.elements * 8, worker_memory::clock_ns());
        Ok(SharedPrefix {
            mapping: self.mapping.take().unwrap(),
            _reader_lease: self._cache_lease.take().unwrap(),
        })
    }
}
impl ColumnReadback for SharedReadback {
    fn height(&self) -> usize {
        self.height
    }
    fn uses_parallel_decode(&self, _: usize) -> bool {
        false
    }
    fn append_rows(
        &mut self,
        first: usize,
        columns: usize,
        row0: usize,
        raw: &[u64],
    ) -> Result<(), String> {
        if first >= self.width
            || first % self.columns != 0
            || columns != self.columns.min(self.width - first)
            || raw.is_empty()
            || raw.len() % columns != 0
            || row0
                .checked_add(raw.len() / columns)
                .is_none_or(|end| end > self.height)
            || first
                .checked_mul(self.height)
                .and_then(|n| row0.checked_mul(columns).and_then(|m| n.checked_add(m)))
                != Some(self.initialized)
            || self
                .initialized
                .checked_add(raw.len())
                .is_none_or(|n| n > self.height * self.width)
        {
            return Err("shared preprocessing readback bounds/order".into());
        }
        let mapping = self.mapping.as_ref().unwrap();
        for (row, words) in raw.chunks_exact(columns).enumerate() {
            let offset = (row0 + row) * self.width + first;
            for (col, &word) in words.iter().enumerate() {
                let value = Val::new(word);
                if self.partial.is_some() {
                    // Exclusive writer; no slice of this mapping escapes before
                    // all bands complete and mprotect seals the entire mapping.
                    unsafe {
                        mapping.pointer.as_ptr().add(offset + col).write(value);
                    }
                } else if mapping.values()[offset + col] != value {
                    return Err("shared preprocessing differs from fresh GPU readback".into());
                }
            }
        }
        self.initialized += raw.len();
        Ok(())
    }
}
impl Drop for SharedReadback {
    fn drop(&mut self) {
        drop(self.mapping.take());
        if let Some(path) = &self.partial {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    fn fill(mut r: SharedReadback) -> SharedPrefix {
        r.append_rows(0, 2, 0, &[1, 2, 4, 5]).unwrap();
        r.append_rows(2, 1, 0, &[3, 6]).unwrap();
        r.finish().unwrap()
    }
    #[test]
    fn shared_prefix_pool_counts_ready_and_incomplete_files() {
        let dir = std::env::temp_dir().join(format!("lattica-prefix-capacity-{}", std::process::id()));
        worker_memory::private_directory(&dir).unwrap();
        std::fs::write(dir.join("a.prefix"), [0u8; 24]).unwrap();
        std::fs::write(dir.join("b.partial"), [0u8; 8]).unwrap();
        assert!(check_pool_capacity(&dir, 16, 48).is_ok());
        assert!(check_pool_capacity(&dir, 17, 48).is_err());
        assert!(check_pool_capacity(&dir, u64::MAX, 48).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn shared_prefix_eviction_requires_all_reader_leases_to_retire() {
        let dir = std::env::temp_dir().join(format!("lattica-prefix-eviction-{}", std::process::id()));
        worker_memory::private_directory(&dir).unwrap();
        let first = fill(SharedReadback::open(&dir, "a", 2, 3, 2).unwrap());
        let second = fill(SharedReadback::open(&dir, "a", 2, 3, 2).unwrap());
        assert!(reserve_pool_capacity(&dir, 48, 48).is_err());
        drop(first);
        assert!(reserve_pool_capacity(&dir, 48, 48).is_err());
        assert_eq!(second.values().len(), 6);
        drop(second);
        reserve_pool_capacity(&dir, 48, 48).unwrap();
        assert!(!dir.join("a.prefix").exists());
        let writer = SharedReadback::open(&dir, "b", 2, 3, 2).unwrap();
        assert!(reserve_pool_capacity(&dir, 48, 48).is_err());
        drop(writer);
        reserve_pool_capacity(&dir, 48, 48).unwrap();
        let replacement = fill(SharedReadback::open(&dir, "c", 2, 3, 2).unwrap());
        assert_eq!(replacement.values().len(), 6);
        drop(replacement);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn shared_prefix_publication_validation_and_readonly_reuse() {
        let dir =
            std::env::temp_dir().join(format!("lattica-shared-prefix-test-{}", std::process::id()));
        worker_memory::private_directory(&dir).unwrap();
        let incomplete = SharedReadback::open(&dir, "a", 2, 3, 2).unwrap();
        assert!(!dir.join("a.prefix").exists());
        drop(incomplete);
        assert!(!dir.join("a.prefix").exists());
        let first = fill(SharedReadback::open(&dir, "a", 2, 3, 2).unwrap());
        let reader = SharedReadback::open(&dir, "a", 2, 3, 2).unwrap();
        assert!(reader.partial.is_none());
        let second = fill(reader);
        assert_eq!(first.values(), second.values());
        assert_eq!(
            first.mapping.file.metadata().unwrap().ino(),
            second.mapping.file.metadata().unwrap().ino()
        );
        assert_eq!(
            first.mapping.file.metadata().unwrap().permissions().mode() & 0o777,
            0o400
        );
        let mut bad = SharedReadback::open(&dir, "a", 2, 3, 2).unwrap();
        assert!(bad
            .append_rows(0, 2, 0, &[9, 2, 4, 5])
            .unwrap_err()
            .contains("differs"));
        assert!(SharedReadback::open(&dir, "a", 3, 3, 2).is_err());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("shared_prefix_child")
            .arg("--test-threads=1")
            .env("LATTICA_TEST_SHARED_PREFIX", &dir)
            .status()
            .unwrap();
        assert!(child.success());
        drop((bad, first, second));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn shared_prefix_child() {
        let Some(dir) = std::env::var_os("LATTICA_TEST_SHARED_PREFIX") else {
            return;
        };
        let r = SharedReadback::open(&PathBuf::from(dir), "a", 2, 3, 2).unwrap();
        assert!(r.partial.is_none());
        assert_eq!(fill(r).values(), &[1, 2, 3, 4, 5, 6].map(Val::from_u64));
    }
}
