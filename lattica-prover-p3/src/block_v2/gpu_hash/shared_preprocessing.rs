//! A per-run shared, read-only copy of PUBLIC preprocessing prefixes on macOS.
//! The filename is only a lookup hint. Every cache hit is checked word-for-word
//! against fresh GPU readback before it can enter prover data. Salts, commitment
//! trees, witnesses and hiding RNG state are never shared by this module.
use super::{engine::lde_execute::LdeInput, engine::lde_readback::ColumnReadback};
use crate::{block_v2::apple_memory, config::Val};
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
    mapping: Mapping,
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
        let Some(dir) = std::env::var_os("LATTICA_APPLE_SHARED_PREPROCESSING_DIR") else {
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
        apple_memory::private_directory(dir)?;
        let lock = apple_memory::lock_file(&dir.join(format!("{key}.lock")))?;
        apple_memory::lock(&lock, false)?;
        let ready = dir.join(format!("{key}.prefix"));
        let open = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&ready);
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
                let path = dir.join(format!(
                    "{key}.{}.{}.partial",
                    std::process::id(),
                    crate::metal_compute::diagnostics::clock_ns()
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
                (
                    mapping,
                    Some(path),
                    Some(lock.try_clone().map_err(|e| e.to_string())?),
                )
            }
            Err(e) => return Err(e.to_string()),
        };
        eprintln!("apple_shared_preprocessing pid={} key={key} cache_hit={} bytes={} inode={} validation=fresh_gpu_readback",
            std::process::id(), partial.is_none(), elements * 8, mapping.file.metadata().map_err(|e| e.to_string())?.ino());
        Ok(Self {
            mapping: Some(mapping),
            _writer_lock: writer_lock,
            partial,
            ready,
            height,
            width,
            columns: columns.min(width),
            initialized: 0,
        })
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
            std::fs::rename(path, &self.ready).map_err(|e| e.to_string())?;
            self.partial = None;
        }
        Ok(SharedPrefix {
            mapping: self.mapping.take().unwrap(),
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
    fn shared_prefix_publication_validation_and_readonly_reuse() {
        let dir =
            std::env::temp_dir().join(format!("lattica-shared-prefix-test-{}", std::process::id()));
        apple_memory::private_directory(&dir).unwrap();
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
