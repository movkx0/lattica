//! Single-task CPU process entry point. This is not a durable OS supervisor.
//! cgroup limits and the launch guard are complementary; result publication is
//! never an acknowledgement of process exit, verifier drain or host eligibility.
use super::{
    artifact_store::{fd_path, hex, open_directory, safe_file_flags},
    launch::{Token, WorkerGate},
    transport::{running_image_fingerprint, Mode, WorkerTask},
    worker::CpuWorker,
};
use crate::block_v2::recursive::Error;
use std::{
    fs::OpenOptions,
    io::Read,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const AGGREGATE_SLICE: &str = "lattica-v2-grouped.slice";
const TASK_OVERHEAD_BYTES: u64 = 16 * (1 << 20);
static ENTERED: AtomicBool = AtomicBool::new(false);

fn read_bounded(path: &Path, limit: usize) -> Result<String, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(safe_file_flags())
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("runtime control is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("runtime control byte bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}
fn finite(value: &str) -> Result<u64, Error> {
    let text = value.strip_suffix('\n').unwrap_or(value);
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("runtime limit must be a finite decimal".into());
    }
    Ok(text.parse()?)
}
fn cgroup_path(contents: &str, service: &str) -> Result<PathBuf, Error> {
    let value = contents.strip_suffix('\n').unwrap_or(contents);
    let path = value
        .strip_prefix("0::")
        .ok_or("unified cgroup v2 required")?;
    if path.len() > 4096
        || !path.starts_with('/')
        || path.bytes().any(|b| b.is_ascii_control())
        || path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(path).components().count() > 64
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || Path::new(path).file_name().and_then(|s| s.to_str()) != Some(service)
    {
        return Err("runtime cgroup does not name this exact lease service".into());
    }
    Ok(PathBuf::from(path.trim_start_matches('/')))
}
fn limit(dir: &Path, name: &str) -> Result<u64, Error> {
    finite(&read_bounded(&dir.join(name), 64)?)
}
fn cpu_limit(value: &str, threads: u32) -> Result<(), Error> {
    let mut parts = value.split_whitespace();
    let quota = finite(parts.next().ok_or("CPU quota missing")?)?;
    let period = finite(parts.next().ok_or("CPU period missing")?)?;
    if parts.next().is_some()
        || quota == 0
        || !(1000..=1_000_000).contains(&period)
        || quota
            > period
                .checked_mul(u64::from(threads))
                .ok_or("CPU quota overflow")?
    {
        return Err("CPU quota exceeds reservation".into());
    }
    Ok(())
}
fn check_resources(token: &Token) -> Result<(), Error> {
    let relative = cgroup_path(
        &read_bounded(Path::new("/proc/self/cgroup"), 8192)?,
        &token.service_name(),
    )?;
    let root = open_directory(Path::new("/sys/fs/cgroup"))?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes the correctly sized output; read it only on success.
    if unsafe { libc::fstatfs(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful fstatfs initialized stat.
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err("runtime mount is not cgroup2".into());
    }
    let directory = fd_path(&root).join(&relative);
    let resources = token.resources();
    let ram = limit(&directory, "memory.max")?;
    if ram == 0 || ram > resources.ram_bytes || limit(&directory, "memory.swap.max")? != 0 {
        return Err("worker memory/swap enforcement does not fit lease".into());
    }
    cpu_limit(
        &read_bounded(&directory.join("cpu.max"), 128)?,
        resources.threads,
    )?;
    let tasks = limit(&directory, "pids.max")?;
    if tasks == 0 || tasks > u64::from(resources.threads) + 8 {
        return Err("worker task limit exceeds bounded thread allowance".into());
    }
    let mut aggregate = false;
    for parent in relative.ancestors().skip(1) {
        if parent.file_name().and_then(|s| s.to_str()) == Some(AGGREGATE_SLICE) {
            let path = fd_path(&root).join(parent);
            let ram = limit(&path, "memory.max")?;
            if ram == 0 || ram > 48 * (1 << 30) || limit(&path, "memory.swap.max")? != 0 {
                return Err("aggregate memory/swap enforcement".into());
            }
            aggregate = true;
            break;
        }
    }
    if !aggregate {
        return Err("worker is outside the reserved aggregate slice".into());
    }
    let mut core = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit writes the correctly sized output; read only on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, core.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful getrlimit initialized core.
    if unsafe { core.assume_init() }.rlim_cur != 0 {
        return Err("worker requires core dumps disabled".into());
    }
    Ok(())
}
fn require_single_thread() -> Result<(), Error> {
    let status = read_bounded(Path::new("/proc/self/status"), 64 * 1024)?;
    let count = status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .ok_or("thread count unavailable")?;
    if count.trim() != "1" {
        return Err("worker initialization must be single-threaded".into());
    }
    Ok(())
}

/// Run exactly one task and return only after cleanup/publication. The executable
/// exits immediately afterward; the supervisor must observe its actual exit.
///
/// # Safety
/// Call only from a dedicated, initially single-threaded process, before any
/// thread can access environment variables or initialize the spill allocator.
/// This installs process-global environment, Rayon state and a terminating alarm.
pub unsafe fn run_task_single_threaded(path: &Path) -> Result<(), Error> {
    require_single_thread()?;
    if ENTERED.swap(true, Ordering::SeqCst) {
        return Err("CPU worker process is single-use".into());
    }
    let task = WorkerTask::open(path)?;
    // SAFETY: this dedicated process uses the default terminating SIGALRM action.
    // It is a local upper bound, not a replacement for whole-cgroup supervision.
    unsafe {
        libc::alarm(task.spec.config.timeout_seconds);
    }
    if running_image_fingerprint()? != task.spec.config.executable {
        return Err("running CPU worker image differs from pinned image".into());
    }
    check_resources(&task.token)?;
    let identity = super::os_worker::capture_current(
        &task.token.service_name(),
        task.spec.config.executable,
        path,
    )?;
    task.publish_worker_start(&identity)?;
    let mut worker = CpuWorker::new(task.spec.config.registry.clone(), task.spec.config.pin)?;
    let guard = WorkerGate::enter(&task.spec.launch_path, &task.token, &task.request)?;
    let resources = task.token.resources();
    if task.spec.config.mode == Mode::Prove {
        let spill = resources
            .scratch_bytes
            .checked_sub(TASK_OVERHEAD_BYTES)
            .filter(|n| *n != 0)
            .ok_or("scratch reservation lacks metadata margin")?;
        let path = fd_path(&task.scratch);
        if path.as_os_str().len() > 255 {
            return Err("spill path length".into());
        }
        if crate::spill_alloc::spill_stats() != (0, 0) {
            return Err("worker inherited spill allocations".into());
        }
        // SAFETY: dedicated process, single-threaded until the Rayon pool below.
        unsafe {
            std::env::set_var("LATTICA_SPILL_DIR", path);
            std::env::set_var("LATTICA_SPILL_MAX_BYTES", spill.to_string());
        }
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(resources.threads as usize)
        .build_global()?;
    match task.spec.config.mode {
        Mode::Check => {
            worker.check_packet(&guard, &task.request, task.spec.config.chain)?;
            println!(
                "cpu_task=INPUTS_VERIFIED_NO_PROOF lease={}",
                hex(&task.token.key())
            );
        }
        Mode::Prove => {
            let response = {
                let _spill = crate::spill_alloc::SpillScope::arm();
                worker.execute_packet(&guard, &task.request, task.spec.config.chain)?
            };
            if crate::spill_alloc::spill_stats() != (0, 0) {
                return Err("worker spill cleanup incomplete".into());
            }
            task.publish_result(&guard, &response)?;
            println!(
                "cpu_task=RESULT_PUBLISHED_UNVERIFIED lease={} bytes={} spill_peak_bytes={}",
                hex(&task.token.key()),
                response.len(),
                crate::spill_alloc::spill_peak_bytes()
            );
        }
    }
    // The guard remains held through cleanup, publication and bounded logging.
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_limits_reject_unbounded_or_excessive_values() {
        assert_eq!(finite("48\n").unwrap(), 48);
        for value in ["", "max", "-1", "+1", " 1", "1\n2", "18446744073709551616"] {
            assert!(finite(value).is_err());
        }
        cpu_limit("800000 100000\n", 8).unwrap();
        for value in [
            "max 100000",
            "800001 100000",
            "1 0",
            "1 100000 extra",
            "0 100000",
        ] {
            assert!(cpu_limit(value, 8).is_err());
        }
    }
    #[test]
    fn cgroup_requires_exact_service_and_normalized_unified_path() {
        let service = "lattica-v2-worker-abc.service";
        assert!(cgroup_path(
            &format!("0::/user.slice/{AGGREGATE_SLICE}/{service}\n"),
            service
        )
        .is_ok());
        for path in [
            "0::/wrong.service",
            "1::/lattica-v2-worker-abc.service",
            "0::/../lattica-v2-worker-abc.service",
            "0:://lattica-v2-worker-abc.service",
            "0::/./lattica-v2-worker-abc.service",
            "0::/lattica-v2-worker-abc.service\n0::/other",
        ] {
            assert!(cgroup_path(path, service).is_err());
        }
    }
}
