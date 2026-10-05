//! Linux/systemd observation for the experimental local worker supervisor.
//!
//! A durable launch record must fence future dispatch before exit observations
//! authorize release. Missing units, lost command responses and timeouts alone
//! are NOT stop receipts. This module never acknowledges scheduler stop or
//! accepts a proof. Same-uid processes, cgroup names and the kernel are trusted.
use super::{
    artifact_store::{fd_path, open_directory, safe_file_flags},
    transport,
};
use crate::block_v2::recursive::Error;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const MAX_CONTROL_BYTES: usize = 64 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Exact observed process birth and cgroup instance. Local recovery metadata,
/// not a proof-validity ticket or permission to launch/stop arbitrary services.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub(super) boot: [u8; 16],
    pub(super) invocation: [u8; 16],
    pub(super) pid: u32,
    pub(super) start_ticks: u64,
    pub(super) group: String,
    pub(super) device: u64,
    pub(super) inode: u64,
}
impl Identity {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn invocation(&self) -> [u8; 16] {
        self.invocation
    }
    pub fn cgroup(&self) -> &str {
        &self.group
    }
    pub fn boot_id(&self) -> [u8; 16] {
        self.boot
    }
    pub(super) fn validate(&self, name: &str) -> Result<(), Error> {
        group_path(&self.group, name)?;
        if self.boot == [0; 16]
            || self.invocation == [0; 16]
            || !(2..=i32::MAX as u32).contains(&self.pid)
            || self.start_ticks == 0
            || self.inode == 0
        {
            return Err("invalid persisted OS identity".into());
        }
        Ok(())
    }
}

/// Handles cannot be reconstructed from a PID alone. A recovered process must
/// match its boot, birth time, unit invocation and cgroup inode before capture.
pub struct LiveProcess {
    identity: Identity,
    pidfd: File,
    group: File,
}
impl LiveProcess {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn quiescent(&self) -> Result<bool, Error> {
        Ok(pidfd_exited(&self.pidfd)? && group_quiescent(&self.group)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Service {
    load: String,
    active: String,
    sub: String,
    pid: u32,
    control_pid: u32,
    invocation: Option<[u8; 16]>,
    group: String,
}

fn read_bounded(path: &Path, bound: usize) -> Result<Vec<u8>, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(safe_file_flags())
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("OS observation requires regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err("OS observation byte bound".into());
    }
    Ok(bytes)
}
fn text_file(path: &Path, bound: usize) -> Result<String, Error> {
    Ok(String::from_utf8(read_bounded(path, bound)?)?)
}
fn hex16(value: &str) -> Result<[u8; 16], Error> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("OS identity must be 32 canonical hex characters".into());
    }
    let mut out = [0; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    if out == [0; 16] {
        return Err("zero OS identity".into());
    }
    Ok(out)
}
pub(super) fn boot_id() -> Result<[u8; 16], Error> {
    let value = text_file(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    parse_boot_id(&value)
}
fn parse_boot_id(value: &str) -> Result<[u8; 16], Error> {
    let value = value.strip_suffix('\n').unwrap_or(&value);
    if value.len() != 36 || [8, 13, 18, 23].iter().any(|i| value.as_bytes()[*i] != b'-') {
        return Err("kernel boot UUID shape".into());
    }
    hex16(&value.replace('-', ""))
}

#[cfg(feature = "stream")]
pub(super) fn current_controller() -> Result<String, Error> {
    let value = text_file(Path::new("/proc/self/cgroup"), 8192)?;
    let path = value
        .strip_suffix('\n')
        .unwrap_or(&value)
        .strip_prefix("0::")
        .ok_or("supervisor requires unified cgroup")?;
    let name = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("controller unit missing")?;
    if name.len() > 256
        || !name.starts_with("lattica-v2-")
        || !name.ends_with(".service")
        || name.starts_with("lattica-v2-worker-")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err("supervisor requires a dedicated lattica-v2 controller service".into());
    }
    Ok(name.to_owned())
}
fn unit_name(name: &str) -> Result<(), Error> {
    let key = name
        .strip_prefix("lattica-v2-worker-")
        .and_then(|s| s.strip_suffix(".service"))
        .ok_or("unexpected worker service namespace")?;
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical worker service key".into());
    }
    Ok(())
}
fn group_path(group: &str, name: &str) -> Result<PathBuf, Error> {
    unit_name(name)?;
    if group.len() > 4096
        || !group.starts_with('/')
        || group.bytes().any(|b| b.is_ascii_control())
        || group
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(group).components().count() > 64
        || Path::new(group)
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || Path::new(group).file_name().and_then(|s| s.to_str()) != Some(name)
    {
        return Err("worker cgroup path substitution".into());
    }
    Ok(Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))
}
fn proc_start_from_stat(bytes: &[u8], pid: u32) -> Result<u64, Error> {
    let text = std::str::from_utf8(bytes)?;
    let left = text.find('(').ok_or("proc stat comm start")?;
    if text[..left].trim_end() != pid.to_string() {
        return Err("proc stat PID substitution".into());
    }
    let right = text.rfind(')').ok_or("proc stat comm end")?;
    if right <= left || !text[right + 1..].starts_with(' ') {
        return Err("proc stat comm shape".into());
    }
    let word = text[right + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or("proc stat start time missing")?;
    if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
        return Err("proc stat start time".into());
    }
    let ticks = word.parse()?;
    if ticks == 0 {
        return Err("zero process birth time".into());
    }
    Ok(ticks)
}
fn proc_start(pid: u32) -> Result<u64, Error> {
    if !(2..=i32::MAX as u32).contains(&pid) {
        return Err("invalid observed PID".into());
    }
    proc_start_from_stat(
        &read_bounded(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?,
        pid,
    )
}
fn pidfd(pid: u32) -> Result<File, Error> {
    if !(2..=i32::MAX as u32).contains(&pid) {
        return Err("invalid pidfd PID".into());
    }
    // SAFETY: pidfd_open has scalar arguments; flags=0 and positive PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful syscall returned one new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn pidfd_exited(file: &File) -> Result<bool, Error> {
    let mut poll = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, valid descriptor, no blocking timeout.
    let result = unsafe { libc::poll(&mut poll, 1, 0) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if poll.revents & libc::POLLNVAL != 0 {
        return Err("invalid process handle".into());
    }
    Ok(result == 1 && poll.revents & libc::POLLIN != 0)
}
fn group_quiescent(group: &File) -> Result<bool, Error> {
    if group.metadata()?.nlink() == 0 {
        return Ok(true);
    }
    let value = text_file(&fd_path(group).join("cgroup.events"), 4096)?;
    parse_population(&value)
}
fn parse_population(value: &str) -> Result<bool, Error> {
    let mut populated = None;
    for line in value.lines() {
        if let Some(value) = line.strip_prefix("populated ") {
            if populated.is_some() {
                return Err("duplicate cgroup population".into());
            }
            populated = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err("cgroup population value".into()),
            });
        }
    }
    populated
        .map(|value| !value)
        .ok_or_else(|| "cgroup population missing".into())
}
fn parse_service(value: &str) -> Result<Service, Error> {
    if value.len() > MAX_CONTROL_BYTES {
        return Err("service observation byte bound".into());
    }
    let mut fields = BTreeMap::new();
    for line in value.lines() {
        let (key, value) = line.split_once('=').ok_or("service property syntax")?;
        if !matches!(
            key,
            "LoadState"
                | "ActiveState"
                | "SubState"
                | "MainPID"
                | "ControlPID"
                | "ControlGroup"
                | "InvocationID"
        ) || fields.insert(key, value).is_some()
        {
            return Err("unexpected/duplicate service property".into());
        }
    }
    let get = |key| fields.get(key).copied().ok_or("missing service property");
    let number = |key| -> Result<u32, Error> {
        let s = get(key)?;
        if s.is_empty()
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("service PID canonicality".into());
        }
        let pid = s.parse()?;
        if pid > i32::MAX as u32 {
            return Err("service PID range".into());
        }
        Ok(pid)
    };
    let invocation = match get("InvocationID")? {
        "" => None,
        value => Some(hex16(value)?),
    };
    Ok(Service {
        load: get("LoadState")?.to_owned(),
        active: get("ActiveState")?.to_owned(),
        sub: get("SubState")?.to_owned(),
        pid: number("MainPID")?,
        control_pid: number("ControlPID")?,
        invocation,
        group: get("ControlGroup")?.to_owned(),
    })
}

fn nonblocking(file: &impl AsRawFd) -> Result<(), Error> {
    // SAFETY: fcntl operates on the live pipe descriptor and integer flags.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn drain(input: &mut impl Read, output: &mut Vec<u8>) -> Result<bool, Error> {
    let mut buffer = [0; 4096];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if output
                    .len()
                    .checked_add(n)
                    .is_none_or(|len| len > MAX_CONTROL_BYTES)
                {
                    return Err("control command output bound".into());
                }
                output.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
/// Only controls owned systemctl helper processes; never kills a worker by PID.
fn control(args: &[&str]) -> Result<(ExitStatus, String), Error> {
    let mut child = Command::new("/usr/bin/systemctl")
        .args(args)
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = (|| -> Result<(ExitStatus, String), Error> {
        let mut stdout = child.stdout.take().ok_or("control stdout missing")?;
        let mut stderr = child.stderr.take().ok_or("control stderr missing")?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        loop {
            let a = drain(&mut stdout, &mut out)?;
            let b = drain(&mut stderr, &mut err)?;
            if let Some(status) = child.try_wait()? {
                if a && b {
                    return Ok((status, String::from_utf8(out)?));
                }
            }
            if Instant::now() >= deadline {
                return Err("control command observation timeout; outcome uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
pub(super) fn service(name: &str) -> Result<Service, Error> {
    unit_name(name)?;
    let (exit, text) = control(&[
        "--user",
        "--no-pager",
        "show",
        "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID",
        name,
    ])?;
    let observed = parse_service(&text)?;
    if !exit.success() && observed.load != "not-found" {
        return Err("service observation failed".into());
    }
    Ok(observed)
}

/// Capture only the exact expected executable/task in the named service.
/// None means not currently observable, NOT that work is stopped or unlaunched.
pub fn observe(name: &str, image: [u8; 32], task: &Path) -> Result<Option<LiveProcess>, Error> {
    transport::absolute_path(task)?;
    let observed = service(name)?;
    if observed.load != "loaded" || observed.active != "active" || observed.sub != "running" {
        return Ok(None);
    }
    let invocation = observed
        .invocation
        .ok_or("live worker has no invocation identity")?;
    let birth =
        proc_start(observed.pid).map_err(|e| format!("capture worker process birth: {e}"))?;
    let boot = boot_id()?;
    let handle = pidfd(observed.pid).map_err(|e| format!("capture worker pidfd: {e}"))?;
    let group = open_directory(&group_path(&observed.group, name)?)
        .map_err(|e| format!("capture worker cgroup: {e}"))?;
    let metadata = group.metadata()?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes the provided correctly sized output; read on success.
    if unsafe { libc::fstatfs(group.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fstatfs initialized stat on success.
    if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err("observed group is not cgroup2".into());
    }
    // Intentional kernel-owned proc symlink, never an arbitrary filesystem link.
    let running = File::open(format!("/proc/{}/exe", observed.pid))
        .map_err(|e| format!("capture kernel executable for PID {}: {e}", observed.pid))?;
    if transport::fingerprint(running)
        .map_err(|e| format!("capture executable fingerprint: {e}"))?
        != image
    {
        return Err("observed executable substitution".into());
    }
    let args = read_bounded(
        &PathBuf::from(format!("/proc/{}/cmdline", observed.pid)),
        16384,
    )?;
    let words: Vec<_> = args.split(|b| *b == 0).collect();
    use std::os::unix::ffi::OsStrExt;
    if words.len() != 4
        || words[1] != b"--task"
        || words[2] != task.as_os_str().as_bytes()
        || !words[3].is_empty()
    {
        return Err("observed worker command substitution".into());
    }
    let process_group = text_file(
        &PathBuf::from(format!("/proc/{}/cgroup", observed.pid)),
        8192,
    )?;
    if process_group.strip_suffix('\n').unwrap_or(&process_group)
        != format!("0::{}", observed.group)
    {
        return Err("observed process cgroup substitution".into());
    }
    if service(name)? != observed || proc_start(observed.pid)? != birth || boot_id()? != boot {
        return Err("worker identity changed during capture".into());
    }
    Ok(Some(LiveProcess {
        identity: Identity {
            boot,
            invocation,
            pid: observed.pid,
            start_ticks: birth,
            group: observed.group,
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        pidfd: handle,
        group,
    }))
}

/// Capture this worker itself before publishing its durable startup identity.
/// This uses the same kernel, executable, argv and service checks as observation;
/// another process in the named unit cannot publish on its main process's behalf.
#[cfg(feature = "stream")]
pub(super) fn capture_current(name: &str, image: [u8; 32], task: &Path) -> Result<Identity, Error> {
    let live =
        observe(name, image, task)?.ok_or("worker cannot capture its own service identity")?;
    if live.identity.pid != std::process::id() {
        return Err("worker startup identity is not the current process".into());
    }
    Ok(live.identity)
}

/// Requires a previously captured identity and a durable future-dispatch fence.
/// This observes disappearance of that exact process/cgroup, not a new service
/// with the same name. The caller still must drain coordinator verification.
pub fn exited(identity: &Identity, name: &str) -> Result<bool, Error> {
    identity.validate(name)?;
    if boot_id()? != identity.boot {
        return Ok(true);
    }
    match proc_start(identity.pid) {
        Ok(birth) if birth == identity.start_ticks => return Ok(false),
        Ok(_) => (), // PID reuse: do not stop or inspect the unrelated new process.
        Err(error) => match error.downcast_ref::<std::io::Error>() {
            Some(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(error),
        },
    }
    let group = match open_directory(&group_path(&identity.group, name)?) {
        Ok(file) => file,
        Err(error) => match error.downcast_ref::<std::io::Error>() {
            Some(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            _ => return Err(error),
        },
    };
    let metadata = group.metadata()?;
    if metadata.dev() != identity.device || metadata.ino() != identity.inode {
        return Err("worker cgroup instance replaced; retain reservation".into());
    }
    group_quiescent(&group)
}

/// Revoke the durable launch permit BEFORE calling this. Success of the control
/// request alone is not a stop receipt; follow with exact process/cgroup checks.
/// The exclusive supervisor must never dispatch this service name again. systemd
/// has no compare-and-stop operation: same-UID namespace mutation is not covered.
pub fn request_stop(identity: &Identity, name: &str) -> Result<(), Error> {
    identity.validate(name)?;
    if boot_id()? != identity.boot {
        return Ok(());
    }
    let observed = service(name)?;
    if observed.load == "not-found" {
        return Ok(());
    }
    if observed.invocation != Some(identity.invocation) || observed.group != identity.group {
        return Err("refuse to stop a different worker invocation".into());
    }
    let (status, _) = control(&["--user", "--no-pager", "--no-block", "stop", name])?;
    if !status.success() {
        return Err("worker stop request outcome uncertain".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "os_worker_tests.rs"]
mod tests;
