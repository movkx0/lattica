//! Disconnected bounded process-memory observation for guarded note research.
//! The caller owns synchronization, physical identity, host reservation and the
//! trusted driver reserve. A successful sample is evidence, not admission.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};

#[cfg(test)]
mod tests;

pub(crate) const OUTPUT_BYTES: usize = 8192;
// Pinned Rust 1.96/x86_64 requested backing for the fixed Command program,
// argv, cleared environment and overlapping environment-map leaves. This is
// separate from inline owners, the output array, helper RSS, libc and driver
// storage, which remain obligations of the enclosing guarded worker.
pub(crate) const COMMAND_REQUESTED_BYTES: usize = 4 * 1024;
const MAX_ROWS: usize = 64;
const MIB: usize = 1 << 20;
const EXECUTABLE: &str = "/usr/bin/nvidia-smi";
const ARGUMENTS: [&str; 2] = [
    "--query-compute-apps=pid,gpu_uuid,used_memory",
    "--format=csv,noheader,nounits",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidRequest,
    Spawn,
    MissingPipe,
    Read,
    OutputLimit,
    Exit(i32),
    Utf8,
    RowLimit,
    Malformed,
    MissingProcess,
    DuplicateProcess,
    WrongDevice,
    Overflow,
    Envelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Observation {
    pub(crate) pid: u32,
    pub(crate) process_bytes: usize,
    pub(crate) rows_examined: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Checkpoint {
    pub(crate) observation: Observation,
    pub(crate) managed_live_bytes: usize,
    pub(crate) context_difference_bytes: usize,
    pub(crate) managed_limit_bytes: usize,
    pub(crate) context_reserve_bytes: usize,
    pub(crate) total_limit_bytes: usize,
}

impl Observation {
    /// Compare a synchronized managed snapshot with the observed process total.
    /// The difference includes driver caches and measurement granularity; it is
    /// not an exact driver allocation census or a proof of unseen peak usage.
    pub(crate) fn checkpoint(
        self,
        managed_live_bytes: usize,
        managed_limit_bytes: usize,
        context_reserve_bytes: usize,
    ) -> Result<Checkpoint, Error> {
        let total_limit_bytes = managed_limit_bytes
            .checked_add(context_reserve_bytes)
            .ok_or(Error::Overflow)?;
        let context_difference_bytes = self.process_bytes.saturating_sub(managed_live_bytes);
        if managed_live_bytes > managed_limit_bytes
            || self.process_bytes > total_limit_bytes
            || context_difference_bytes > context_reserve_bytes
        {
            return Err(Error::Envelope);
        }
        Ok(Checkpoint {
            observation: self,
            managed_live_bytes,
            context_difference_bytes,
            managed_limit_bytes,
            context_reserve_bytes,
            total_limit_bytes,
        })
    }
}

fn valid_request(uuid: &str, pid: u32) -> bool {
    pid != 0
        && uuid.len() == 40
        && uuid.starts_with("GPU-")
        && uuid.as_bytes()[4..].iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn parse(bytes: &[u8], uuid: &str, pid: u32) -> Result<Observation, Error> {
    if !valid_request(uuid, pid) {
        return Err(Error::InvalidRequest);
    }
    if bytes.len() > OUTPUT_BYTES {
        return Err(Error::OutputLimit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
    let mut found = None;
    let mut count = 0;
    for row in text.lines() {
        count += 1;
        if count > MAX_ROWS {
            return Err(Error::RowLimit);
        }
        let mut fields = row.split(',').map(str::trim);
        let process = fields.next().ok_or(Error::Malformed)?;
        let device = fields.next().ok_or(Error::Malformed)?;
        let memory = fields.next().ok_or(Error::Malformed)?;
        if fields.next().is_some()
            || process.is_empty()
            || !process.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Malformed);
        }
        let process: u32 = process.parse().map_err(|_| Error::Malformed)?;
        if process == pid {
            if !device.eq_ignore_ascii_case(uuid) {
                return Err(Error::WrongDevice);
            }
            if found.is_some() {
                return Err(Error::DuplicateProcess);
            }
            if memory.is_empty() || !memory.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Malformed);
            }
            let mib: usize = memory.parse().map_err(|_| Error::Overflow)?;
            found = Some(mib.checked_mul(MIB).ok_or(Error::Overflow)?);
        }
    }
    Ok(Observation {
        pid,
        process_bytes: found.ok_or(Error::MissingProcess)?,
        rows_examined: count,
    })
}

fn read_bounded(
    reader: &mut impl Read,
    bytes: &mut [u8; OUTPUT_BYTES + 1],
) -> Result<usize, Error> {
    let mut filled = 0;
    loop {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => return Ok(filled),
            Ok(n) => {
                filled += n;
                if filled > OUTPUT_BYTES {
                    return Err(Error::OutputLimit);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Read),
        }
    }
}

// Every returning path waits for the exact child. On panic or early rejection,
// kill then wait before the caller can release its enclosing host reservation.
// Uncertain reaping terminates the guarded worker rather than lending capacity
// while a helper may still be alive. The service guard also owns its cgroup.
struct Running {
    child: Child,
    reaped: bool,
}
impl Running {
    fn wait(&mut self) -> ExitStatus {
        match self.child.wait() {
            Ok(status) => {
                self.reaped = true;
                status
            }
            Err(_) => std::process::abort(),
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            // kill can fail because the child has already exited. Successful
            // wait is the authoritative lifetime boundary in either case.
            let _ = self.child.kill();
            let _ = self.wait();
        }
    }
}

/// Call only after draining GPU work, inside the reserved and guarded worker.
/// This queries all devices so use of a different device by this PID is refused.
/// Command's fixed argv/environment, pipes, helper process and allocator/driver
/// storage remain enclosing admission obligations; the byte array alone is not
/// a full host bound. No shell, inherited environment or output Vec is used.
pub(crate) fn sample(uuid: &str, pid: u32) -> Result<Observation, Error> {
    if !valid_request(uuid, pid) {
        return Err(Error::InvalidRequest);
    }
    let child = Command::new(EXECUTABLE)
        .args(ARGUMENTS)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Spawn)?;
    let mut running = Running {
        child,
        reaped: false,
    };
    let mut pipe = running.child.stdout.take().ok_or(Error::MissingPipe)?;
    let mut bytes = [0; OUTPUT_BYTES + 1];
    let used = read_bounded(&mut pipe, &mut bytes)?;
    drop(pipe);
    let status = running.wait();
    if !status.success() {
        return Err(Error::Exit(status.into_raw()));
    }
    parse(&bytes[..used], uuid, pid)
}
