//! Admission for a wallet-owned local GPU process, separate from the public
//! recursive worker protocol. The assignment contains resource metadata only;
//! private witnesses never enter the public DAG, its transport or artifact store.
use crate::proving::{Policy, Request};
use serde::Deserialize;
use std::{ffi::OsString, sync::OnceLock};

mod runtime;

pub(crate) const ENV: &str = "LATTICA_WALLET_WORKER_BUDGET";
const MAX_ASSIGNMENT_BYTES: u64 = 8192;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Budget {
    schema: String,
    service: String,
    gpu_uuid: String,
    host_bytes: u64,
    threads: u32,
    managed_gpu_bytes: u64,
    context_gpu_bytes: u64,
    host_output_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Assignment {
    path: OsString,
    budget: Budget,
    file_device: u64,
    file_inode: u64,
    cgroup_device: u64,
    cgroup_inode: u64,
}

pub(crate) struct Prepared(Option<Assignment>);
static ASSIGNMENT: OnceLock<Option<Assignment>> = OnceLock::new();

impl Prepared {
    pub(crate) fn initialize_runtime(&self) -> Result<(), String> {
        runtime::initialize(self.0.as_ref())
    }
}

pub(crate) fn is_assigned() -> bool {
    std::env::var_os(ENV).is_some()
        || ASSIGNMENT.get().is_some_and(Option::is_some)
        || runtime::is_pinned()
}

pub(crate) fn prepare() -> Result<Prepared, String> {
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some() {
        return Err("public recursive workers cannot admit private wallet inputs".into());
    }
    let selected = std::env::var_os(ENV).map(load).transpose()?;
    if ASSIGNMENT.get().is_some_and(|current| *current != selected) {
        return Err("wallet worker assignment cannot change within a process".into());
    }
    runtime::check_assignment(selected.as_ref())?;
    Ok(Prepared(selected))
}

pub(crate) fn finish(prepared: Prepared) -> Result<(), String> {
    let current = prepare()?;
    if current.0 != prepared.0 {
        return Err("wallet worker assignment changed during startup".into());
    }
    runtime::check_ready(current.0.as_ref())?;
    if let Err(value) = ASSIGNMENT.set(prepared.0) {
        if ASSIGNMENT.get() != Some(&value) {
            return Err("wallet worker assignment changed during startup".into());
        }
    }
    Ok(())
}

pub(crate) fn admit(request: Request) -> Result<(), String> {
    let selected = prepare()?;
    if selected.0.is_some() {
        if request.policy != Policy::GpuRequired || ASSIGNMENT.get() != Some(&selected.0) {
            return Err(
                "private wallet workers require completed native startup and GPU-required proving"
                    .into(),
            );
        }
        runtime::check_ready(selected.0.as_ref())?;
    }
    Ok(())
}

/// Pin the selected engine and its exclusive device lease across preparation.
/// DeviceSession already prevents shutdown while its context reference is live.
/// This does not reserve per-proof matrix or host allocation capacity.
pub(crate) fn retain_gpu_context() -> Result<super::gpu_hash::device::DeviceSession, String> {
    if !super::leaf::gpu_wallet_selected() {
        return Err("private wallet GPU backend is not selected".into());
    }
    let context = super::gpu_hash::device::DeviceSession::new()?;
    super::gpu_hash::require_resident_backend()?;
    Ok(context)
}

pub(crate) fn require_gpu_resources() -> Result<(), String> {
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some()
        || super::resident_pcs::try_host_output_budget()? < super::machine::symbolic::HOST_BYTES as usize
    {
        return Err("private wallet request has no admitted host/resource contract".into());
    }
    Ok(())
}

pub(crate) fn admit_gpu(
    request: Request,
) -> Result<super::gpu_hash::device::DeviceSession, String> {
    let context = retain_gpu_context()?;
    require_gpu_resources()?;
    admit(request)?;
    Ok(context)
}

/// Retain the existing managed-device ceiling across an entire serial proof.
/// Input wrappers use admit_gpu() only to pin the context; the actual prover
/// owns this capacity once, so nested ABI/export wrappers do not reserve twice.
pub(crate) fn admit_gpu_proof(
    request: Request,
    minimum: super::gpu_hash::device::WalletProofMinimum,
) -> Result<super::gpu_hash::device::ProofCapacity, String> {
    admit_gpu(request)?.reserve_wallet_proof_capacity(minimum)
}

impl Budget {
    fn validate(&self) -> Result<(), String> {
        let service = self
            .service
            .strip_prefix("lattica-wallet-")
            .and_then(|s| s.strip_suffix(".service"))
            .ok_or("wallet worker service namespace")?;
        if self.schema != "lattica-wallet-local-gpu-v1"
            || service.is_empty()
            || self.service.len() > 200
            || !service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.gpu_uuid.len() != 40
            || !self.gpu_uuid.starts_with("GPU-")
            || !self.gpu_uuid[4..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
            || self.host_bytes == 0
            || self.host_bytes > i64::MAX as u64
            || self.threads == 0
            || self.threads > 256
            || self.managed_gpu_bytes == 0
            || self.managed_gpu_bytes > super::gpu_hash::Limits::default().managed_bytes as u64
            || self.context_gpu_bytes < 512 * (1 << 20)
            || self.context_gpu_bytes > i64::MAX as u64
            || self
                .managed_gpu_bytes
                .checked_add(self.context_gpu_bytes)
                .is_none()
            || self.host_output_bytes < super::machine::symbolic::HOST_BYTES as u64
            || self.host_output_bytes > self.host_bytes
        {
            return Err("invalid wallet worker resource assignment".into());
        }
        runtime::Limits::for_budget(self)?;
        Ok(())
    }

    fn environment(&self) -> Result<(), String> {
        if Request::from_env().map_err(|e| e.to_string())?.policy != Policy::GpuRequired
            || std::env::var("LATTICA_GPU_DEVICE_UUID").as_deref() != Ok(&self.gpu_uuid)
        {
            return Err("wallet worker policy/device differs from assignment".into());
        }
        for (name, expected) in [
            ("LATTICA_V2_GPU_MANAGED_BYTES", self.managed_gpu_bytes),
            ("LATTICA_V2_GPU_CONTEXT_BYTES", self.context_gpu_bytes),
            ("LATTICA_V2_HOST_OUTPUT_BYTES", self.host_output_bytes),
            ("RAYON_NUM_THREADS", u64::from(self.threads)),
        ] {
            if std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok()) != Some(expected) {
                return Err(format!("wallet worker {name} differs from assignment"));
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn load(_: OsString) -> Result<Assignment, String> {
    Err("wallet worker admission requires Linux cgroup v2 and OpenCL".into())
}

#[cfg(target_os = "linux")]
fn load(path: OsString) -> Result<Assignment, String> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };
    let path_ref = Path::new(&path);
    if !path_ref.is_absolute() {
        return Err("wallet worker assignment path must be absolute".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path_ref)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    // SAFETY: geteuid takes no arguments and returns the current effective UID.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7177 != 0
        || metadata.mode() & 0o400 == 0
        || metadata.len() == 0
        || metadata.len() > MAX_ASSIGNMENT_BYTES
    {
        return Err("wallet worker assignment must be a bounded, owner-only regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_ASSIGNMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("wallet worker assignment changed or exceeded its byte bound".into());
    }
    let budget: Budget =
        serde_json::from_slice(&bytes).map_err(|_| "invalid wallet worker assignment encoding")?;
    budget.validate()?;
    budget.environment()?;
    let (cgroup_device, cgroup_inode) = runtime_limits(&budget)?;
    Ok(Assignment {
        path,
        budget,
        file_device: metadata.dev(),
        file_inode: metadata.ino(),
        cgroup_device,
        cgroup_inode,
    })
}

fn finite(value: &str) -> Result<u64, String> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("wallet worker limit must be finite decimal".into());
    }
    value
        .parse()
        .map_err(|_| "wallet worker limit overflow".into())
}

fn cpu_limit(value: &str, threads: u32) -> Result<(), String> {
    let mut parts = value.split_whitespace();
    let quota = finite(parts.next().ok_or("wallet worker CPU quota missing")?)?;
    let period = finite(parts.next().ok_or("wallet worker CPU period missing")?)?;
    if parts.next().is_some()
        || quota == 0
        || !(1000..=1_000_000).contains(&period)
        || quota
            > period
                .checked_mul(u64::from(threads))
                .ok_or("wallet worker CPU quota overflow")?
    {
        return Err("wallet worker CPU quota exceeds assignment".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn runtime_limits(budget: &Budget) -> Result<(u64, u64), String> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Component, Path, PathBuf},
    };
    fn text(path: &Path, limit: u64) -> Result<String, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("wallet worker runtime control is not a regular file".into());
        }
        let mut value = String::new();
        file.take(limit + 1)
            .read_to_string(&mut value)
            .map_err(|e| e.to_string())?;
        if value.len() as u64 > limit {
            return Err("wallet worker runtime control byte bound".into());
        }
        Ok(value)
    }
    let membership = text(Path::new("/proc/self/cgroup"), 8192)?;
    let relative = membership
        .strip_suffix('\n')
        .unwrap_or(&membership)
        .strip_prefix("0::/")
        .ok_or("wallet worker requires unified cgroup v2")?;
    if relative.is_empty()
        || relative.bytes().any(|b| b.is_ascii_control())
        || relative
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || Path::new(relative).components().count() > 64
        || Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || Path::new(relative).file_name().and_then(|s| s.to_str()) != Some(&budget.service)
    {
        return Err("wallet worker does not occupy its assigned service".into());
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/sys/fs/cgroup")
        .map_err(|e| e.to_string())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes the correctly sized output on success.
    if unsafe { libc::fstatfs(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: the preceding successful call initialized stat.
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err("wallet worker runtime mount is not cgroup v2".into());
    }
    let directory = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd())).join(relative);
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    let memory = finite(&text(&directory.join("memory.max"), 64)?)?;
    if memory == 0
        || memory > budget.host_bytes
        || finite(&text(&directory.join("memory.swap.max"), 64)?)? != 0
    {
        return Err("wallet worker memory/swap limits exceed assignment".into());
    }
    cpu_limit(&text(&directory.join("cpu.max"), 128)?, budget.threads)?;
    let mut core = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the correctly sized output on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, core.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: the preceding successful call initialized core.
    if unsafe { core.assume_init() }.rlim_cur != 0 {
        return Err("wallet workers require core dumps disabled".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod admission_tests;
