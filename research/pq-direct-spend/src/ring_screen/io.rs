//! Bounded paths, streaming reports and exact-capacity artifact disk reads.
use super::*;
use serde::Serialize;
use std::{
    ffi::{c_char, CStr},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) const MAX_OUTPUT_BYTES: usize = 1024;
const MAX_REPORT_BYTES: usize = 1 << 20;
const NAMES: [&str; 7] = [
    "compilation-failure.json",
    "proving-failure.json",
    "proving.json",
    "proof.bin",
    "verification-failure.json",
    "verification.json",
    "workflow.json",
];
const LABELS: [&str; CASES] = [
    "case-0", "case-1", "case-2", "case-3", "case-4", "case-5", "case-6",
];

unsafe extern "C" {
    fn getenv(name: *const c_char) -> *const c_char;
}

pub(super) fn environment<const N: usize>(name: &CStr) -> Result<([u8; N], usize)> {
    // The exact ignored test is run with --test-threads=1 in a fresh guarded
    // process. This module never mutates the environment. getenv borrows its
    // NUL-terminated value; reading stops at NUL or the fixed byte ceiling.
    let ptr = unsafe { getenv(name.as_ptr()) };
    if ptr.is_null() {
        return Err("required direct-ring screen environment is absent".into());
    }
    let mut value = [0; N];
    for i in 0..N {
        let next = unsafe { *ptr.add(i) } as u8;
        if next == 0 {
            return Ok((value, i));
        }
        value[i] = next;
    }
    Err("direct-ring screen environment exceeds its source bound".into())
}

pub(super) fn guarded_output() -> Result<PathBuf> {
    guarded_output_selected(false)
}

#[cfg(feature = "gpu-identity-reuse-experiment")]
pub(super) fn identity_output() -> Result<PathBuf> {
    guarded_output_selected(true)
}

fn guarded_output_selected(identity: bool) -> Result<PathBuf> {
    for (name, expected) in [
        (
            if identity {
                c"LATTICA_DIRECT_RING_IDENTITY_QUALIFICATION"
            } else {
                c"LATTICA_DIRECT_RING_SCREEN_QUALIFICATION"
            },
            b"1".as_slice(),
        ),
        (c"LATTICA_PROVING_POLICY", b"gpu-required".as_slice()),
        (c"LATTICA_PROVING_REPORT", b"1".as_slice()),
        (c"LATTICA_V2_GPU_PUBLIC_HASH", b"baseline".as_slice()),
        (c"LATTICA_V2_GPU_RETAINED_TREE_STORAGE", b"host".as_slice()),
        (
            c"LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES",
            b"8589934592".as_slice(),
        ),
        (c"LATTICA_V2_GPU_MANAGED_BYTES", b"8589934592".as_slice()),
        (c"LATTICA_V2_GPU_CONTEXT_BYTES", b"4294967296".as_slice()),
        (c"LATTICA_V2_HOST_OUTPUT_BYTES", b"34359738368".as_slice()),
        (c"LATTICA_V2_GPU_LDE_WORKSPACE_BYTES", b"0".as_slice()),
    ] {
        let (actual, len) = environment::<32>(name)?;
        if &actual[..len] != expected {
            return Err("direct-ring screen requires the exact baseline host-tree profile".into());
        }
    }
    let (bytes, len) = environment::<{ MAX_OUTPUT_BYTES + 1 }>(if identity {
        c"LATTICA_DIRECT_RING_IDENTITY_OUTPUT_DIR"
    } else {
        c"LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR"
    })?;
    let value = std::str::from_utf8(&bytes[..len])?;
    validate_output(value)?;
    exact_path(Path::new(value), None)
}

pub(super) fn validate_output(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_OUTPUT_BYTES
        || !path.is_absolute()
        || value.split('/').any(|part| part == "." || part == "..")
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        || path.file_name().is_none()
    {
        return Err("screen output must be a bounded absolute fresh directory path".into());
    }
    Ok(())
}

fn exact_path(parent: &Path, name: Option<&str>) -> Result<PathBuf> {
    let length = parent
        .as_os_str()
        .len()
        .checked_add(name.map_or(0, |s| s.len() + 1))
        .ok_or(Error::ResourceLimit)?;
    if length > MAX_OUTPUT_BYTES + 64 {
        return Err(Error::ResourceLimit.into());
    }
    let mut result = PathBuf::new();
    result.try_reserve_exact(length)?;
    if result.capacity() != length {
        return Err("path allocator exceeded source capacity".into());
    }
    result.push(parent);
    if let Some(name) = name {
        result.push(name);
    }
    Ok(result)
}

pub(super) struct Paths {
    pub directory: PathBuf,
    pub files: [PathBuf; 7],
}

impl Paths {
    pub fn new(root: &Path, case: usize) -> Result<Self> {
        let directory = exact_path(root, Some(LABELS.get(case).ok_or(Error::Geometry)?))?;
        let mut files = std::array::from_fn(|_| PathBuf::new());
        for (file, name) in files.iter_mut().zip(NAMES) {
            *file = exact_path(&directory, Some(name))?;
        }
        Ok(Self { directory, files })
    }

    pub fn capacity_bytes(&self) -> usize {
        self.directory.capacity() + self.files.iter().map(|p| p.capacity()).sum::<usize>()
    }
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other(
                "screen report exceeds serialized ceiling",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub(super) fn report(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = LimitedWriter {
        inner: file,
        remaining: MAX_REPORT_BYTES,
    };
    serde_json::to_writer(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.inner.sync_all()?;
    Ok(())
}

pub(super) fn root_report(root: &Path, name: &'static str, value: &impl Serialize) -> Result<()> {
    report(&exact_path(root, Some(name))?, value)
}

pub(super) fn write_packet(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn read_packet(path: &Path, allowance: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let length = usize::try_from(metadata.len())?;
    if !metadata.is_file()
        || length > ring_circuit::artifact::MAX_ENCODED_BYTES
        || length > allowance
    {
        return Err("artifact exceeds bounded read allowance".into());
    }
    let mut packet = Vec::new();
    packet.try_reserve_exact(length)?;
    if packet.capacity() != length {
        return Err("artifact reader capacity exceeded admission".into());
    }
    packet.resize(length, 0);
    file.read_exact(&mut packet)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err("artifact changed during bounded read".into());
    }
    Ok(packet)
}
