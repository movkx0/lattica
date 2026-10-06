//! Persistent trusted typed worker over an inherited, bounded local socket.
//!
//! The enclosing runtime enforces the actual device/host assignment. Memory
//! stays reserved through idle periods, GPU teardown and observed process exit.
//! A protocol failure retains the journal reservations for explicit recovery.
//! This is not a remote worker protocol or an active-worker recovery supervisor.

use super::{
    cached::{CompletedJob, Task},
    *,
};
use crate::block_v2::execution::{
    dag::WorkerId,
    journal::{DurableDag, WorkspaceReservation},
    launch::{Token, MAX_REQUEST_BYTES, MAX_TOKEN_BYTES},
    transport::{image_fingerprint, running_image_fingerprint},
    workspace::WorkspaceLease,
};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const DOMAIN: u64 = 0x4c54545053455331;
const MAGIC: &[u8; 8] = b"LTTYIPC1";
const HELLO: u8 = 1;
const READY: u8 = 2;
const JOB: u8 = 3;
const RESULT: u8 = 4;
const STOP: u8 = 5;
const STOPPED: u8 = 6;
const MAX_FRAME: usize = MAX_REQUEST_BYTES + MAX_TOKEN_BYTES + 512;
const TIMEOUT: Duration = Duration::from_secs(600);

#[cfg(test)]
#[path = "worker_typed_process_tests.rs"]
mod tests;

#[path = "worker_typed_process_service.rs"]
mod service;

/// Identity for independently supplied public policy and hardware assignment.
pub fn configuration_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.is_empty() || bytes.len() > 1 << 20 {
        return Err("typed process configuration size".into());
    }
    launch::digest(DOMAIN, bytes)
}

#[derive(Clone)]
pub struct Config {
    registry: TypedRegistry<12>,
    pin: RegistryPin,
    chain: [u8; 32],
    peak: Resources,
    jobs: Resources,
    executable: [u8; 32],
    policy_assignment: [u8; 32],
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: TypedRegistry<12>,
        pin: RegistryPin,
        chain: [u8; 32],
        peak: Resources,
        jobs: Resources,
        executable: [u8; 32],
        policy_assignment: [u8; 32],
    ) -> Result<Self, Error> {
        pin.check_typed(&registry)?;
        peak.validate_capacity()?;
        jobs.validate_request()?;
        if jobs.threads != peak.threads || jobs.vram_bytes != 0 || jobs.scratch_bytes != 0 {
            return Err(
                "typed process job must reserve assigned CPU and host packet memory".into(),
            );
        }
        Ok(Self {
            registry,
            pin,
            chain,
            peak,
            jobs,
            executable,
            policy_assignment,
        })
    }

    fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = MAGIC.to_vec();
        for digest in [
            self.registry.id()?,
            self.pin.profile(),
            self.chain,
            self.executable,
            self.policy_assignment,
        ] {
            bytes.extend(digest);
        }
        for resources in [self.peak, self.jobs] {
            for value in [
                resources.ram_bytes,
                resources.vram_bytes,
                resources.scratch_bytes,
                u64::from(resources.threads),
            ] {
                bytes.extend(value.to_le_bytes());
            }
        }
        Ok(bytes)
    }
}

fn send(socket: &mut UnixStream, kind: u8, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_FRAME {
        return Err("typed process frame exceeds bound".into());
    }
    socket.write_all(&[kind])?;
    socket.write_all(&(bytes.len() as u64).to_le_bytes())?;
    socket.write_all(bytes)?;
    Ok(())
}

fn receive(socket: &mut UnixStream, expected: u8, bound: usize) -> Result<Vec<u8>, Error> {
    let mut header = [0; 9];
    socket.read_exact(&mut header)?;
    let size = u64::from_le_bytes(header[1..].try_into()?);
    if header[0] != expected || size > bound.min(MAX_FRAME) as u64 {
        return Err("typed process frame kind or size".into());
    }
    let mut bytes = vec![0; usize::try_from(size)?];
    socket.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn configure(socket: &UnixStream) -> Result<(), Error> {
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    Ok(())
}

fn accumulate_stats(
    total: CacheStats,
    job: CacheStats,
    completed: u64,
) -> Result<CacheStats, Error> {
    // Packet counters are deltas for this proof; the child's shutdown counters
    // describe the whole session. Never substitute one timing/accounting scope
    // for the other, particularly after the first cache hit.
    if job.setups.checked_add(job.hits) != Some(1) {
        return Err("typed process job cache accounting".into());
    }
    let next = CacheStats {
        setups: total
            .setups
            .checked_add(job.setups)
            .ok_or("typed process setup overflow")?,
        hits: total
            .hits
            .checked_add(job.hits)
            .ok_or("typed process hit overflow")?,
    };
    if next.setups.checked_add(next.hits) != Some(completed) {
        return Err("typed process cache accounting differs from completed jobs".into());
    }
    Ok(next)
}

fn receive_command(socket: &mut UnixStream) -> Result<(u8, Vec<u8>), Error> {
    let mut header = [0; 9];
    socket.read_exact(&mut header)?;
    let size = u64::from_le_bytes(header[1..].try_into()?);
    let bound = match header[0] {
        JOB => MAX_REQUEST_BYTES + MAX_TOKEN_BYTES + 8,
        STOP => 0,
        _ => return Err("typed process command kind".into()),
    };
    if size > bound as u64 {
        return Err("typed process command size".into());
    }
    let mut bytes = vec![0; usize::try_from(size)?];
    socket.read_exact(&mut bytes)?;
    Ok((header[0], bytes))
}

/// Only this object owns the child and its issuing workspace reservation.
pub struct ProcessWorker {
    config: Config,
    reservation: WorkspaceReservation,
    job_worker: WorkerId,
    spec: Vec<u8>,
    child: Option<Child>,
    service: Option<service::OwnedService>,
    socket: Option<UnixStream>,
    pending: Option<(Task, Vec<u8>)>,
    pid: Option<u32>,
    stats: CacheStats,
    completed: u64,
    poisoned: bool,
    exited_cleanly: bool,
}

impl ProcessWorker {
    /// Reserve before creating the child, including every idle cached interval.
    pub fn prepare(
        owner: &mut DurableDag,
        config: Config,
        worker: WorkerId,
        job_worker: WorkerId,
        now_ms: u64,
    ) -> Result<Self, Error> {
        if worker.0 == 0 || job_worker.0 == 0 || worker == job_worker {
            return Err("typed process needs distinct workspace and job worker identities".into());
        }
        let mut spec = config.bytes()?;
        let reservation = owner.reserve_workspace(
            worker,
            Resources {
                threads: 0,
                ..config.peak
            },
            now_ms,
        )?;
        let lease = reservation.lease()?;
        spec.extend(lease.id().session);
        for value in [
            lease.id().epoch,
            lease.id().sequence,
            worker.0,
            job_worker.0,
        ] {
            spec.extend(value.to_le_bytes());
        }
        Ok(Self {
            config,
            reservation,
            job_worker,
            spec,
            child: None,
            service: None,
            socket: None,
            pending: None,
            pid: None,
            stats: CacheStats::default(),
            completed: 0,
            poisoned: false,
            exited_cleanly: false,
        })
    }

    pub fn execution_digest(&self) -> Result<[u8; 32], Error> {
        launch::digest(DOMAIN, &self.spec)
    }
    /// Retain this immutable public session before starting the child.
    pub fn session_bytes(&self) -> &[u8] {
        &self.spec
    }
    pub fn workspace(&self) -> Result<WorkspaceLease, Error> {
        self.reservation.lease()
    }
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
    pub fn stats(&self) -> Result<CacheStats, Error> {
        if self.poisoned {
            return Err("typed process is poisoned".into());
        }
        Ok(self.stats)
    }

    /// The trusted child must use `serve` and must not spawn descendant processes.
    /// Its whole process inherits the enclosing runtime's physical resource caps.
    pub fn start(&mut self, mut command: Command) -> Result<(), Error> {
        if self.poisoned || self.pid.is_some() || self.exited_cleanly {
            return Err("typed process cannot be restarted under the same reservation".into());
        }
        if image_fingerprint(Path::new(command.get_program()))? != self.config.executable {
            return Err("typed process executable changed".into());
        }
        let (mut socket, child_socket) = UnixStream::pair()?;
        configure(&socket)?;
        self.poisoned = true;
        let child = command
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_socket)))
            .spawn()?;
        // Command retains its stdin descriptor so it can be spawned again.
        // Close that parent copy before waiting for the child's handshake;
        // otherwise an early child exit cannot produce socket EOF.
        drop(command);
        self.pid = Some(child.id());
        self.child = Some(child);
        send(&mut socket, HELLO, &self.spec)?;
        let ready = receive(&mut socket, READY, 36)?;
        let mut expected = self.pid.unwrap().to_le_bytes().to_vec();
        expected.extend(self.execution_digest()?);
        if ready != expected {
            return Err("typed process handshake identity".into());
        }
        self.socket = Some(socket);
        self.poisoned = false;
        Ok(())
    }

    pub fn task(&self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<Task, Error> {
        self.stats()?;
        if self.socket.is_none() || self.exited_cleanly {
            return Err("typed process is not running".into());
        }
        let assignment = owner.assignment(lease)?;
        if assignment.resources() != self.config.jobs
            || assignment.job().pin() != self.config.pin
            || lease.worker() != self.job_worker
        {
            return Err("typed process task assignment changed".into());
        }
        let workspace = owner.prepare_workspace_job(&self.reservation, lease, now_ms)?;
        Ok(Task {
            workspace,
            assignment,
        })
    }

    /// Wait for one job; the owner still revokes the launch and CPU-verifies its proof.
    pub fn execute(&mut self, token: &Token, task: Task) -> Result<CompletedJob, Error> {
        self.dispatch(token, task)?;
        self.collect()
    }

    /// Send one job without waiting, retaining its workspace use and request.
    /// Another worker can run concurrently while this reservation remains held.
    pub fn dispatch(&mut self, token: &Token, task: Task) -> Result<(), Error> {
        self.stats()?;
        if task.workspace.lease() != self.reservation.lease()? {
            return Err("typed process task belongs to another workspace".into());
        }
        let request = task.request()?;
        token.check_execution(self.execution_digest()?)?;
        token.check_request(&request)?;
        let token_bytes = token.encode()?;
        let mut packet = (token_bytes.len() as u64).to_le_bytes().to_vec();
        packet.extend(token_bytes);
        packet.extend(&request);
        self.poisoned = true;
        self.pending = Some((task, request));
        let socket = self.socket.as_mut().ok_or("typed process is not running")?;
        send(socket, JOB, &packet)
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Poll only this worker's owned socket. EOF/errors are collected as failures.
    pub fn try_collect(&mut self) -> Result<Option<CompletedJob>, Error> {
        use std::os::fd::AsRawFd;
        if self.pending.is_none() {
            return Ok(None);
        }
        let socket = self.socket.as_ref().ok_or("typed process is not running")?;
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is valid for the duration of this call.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error.into());
        }
        if ready == 0 {
            return Ok(None);
        }
        Ok(Some(self.collect()?))
    }

    fn collect(&mut self) -> Result<CompletedJob, Error> {
        let (task, request) = self
            .pending
            .as_ref()
            .ok_or("typed process has no pending job")?;
        let socket = self.socket.as_mut().ok_or("typed process is not running")?;
        let response = receive(socket, RESULT, packet::MAX_RESULT_BYTES)?;
        let result = packet::decode_result(&task.assignment, request, &response)?;
        let stats = result.stats();
        let next = self
            .completed
            .checked_add(1)
            .ok_or("typed process job count overflow")?;
        let total_stats = accumulate_stats(self.stats, stats, next)?;
        let output = Output {
            lease: task.lease(),
            job: task.assignment.job().id(),
            timings: result.timings(),
            stats,
            bytes: result.into_bytes(),
        };
        let (task, _) = self.pending.take().unwrap();
        self.stats = total_stats;
        self.completed = next;
        self.poisoned = false;
        Ok(CompletedJob {
            task,
            report: Ok(output),
        })
    }

    /// Release only after a clean GPU shutdown receipt AND successful child exit.
    pub fn close(&mut self, owner: &mut DurableDag, now_ms: u64) -> Result<(), Error> {
        owner.check_workspace_reservation(&self.reservation)?;
        self.reservation.require_idle()?;
        self.stats()?;
        if !self.exited_cleanly {
            self.poisoned = true;
            let socket = self
                .socket
                .as_mut()
                .ok_or("typed process has no clean shutdown")?;
            send(socket, STOP, &[])?;
            let receipt = receive(socket, STOPPED, 24)?;
            let expected: Vec<_> = [self.stats.setups, self.stats.hits, self.completed]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect();
            if receipt != expected {
                return Err("typed process shutdown accounting".into());
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let child = self.child.as_mut().ok_or("typed process child missing")?;
                if let Some(status) = child.try_wait()? {
                    if !status.success() {
                        return Err("typed process exited unsuccessfully".into());
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("typed process exit timed out".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            self.child = None;
            if let Some(service) = &self.service {
                service::wait_quiescent(service, deadline)?;
            }
            self.socket = None;
            self.exited_cleanly = true;
            self.poisoned = false;
        }
        owner.release_workspace(&mut self.reservation, now_ms)
    }
}

impl Drop for ProcessWorker {
    fn drop(&mut self) {
        // This is cleanup, never a journal stop/release receipt. An incomplete
        // session remains reserved for recovery even if the exact child exits.
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Run in the trusted child, using independently read policy and assignment.
/// The inherited socket is the only dispatcher; stdout remains a normal log.
pub fn serve(
    mut socket: UnixStream,
    config: Config,
    launches: &Path,
    mut policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    mut shutdown: impl FnMut() -> Result<(), Error>,
) -> Result<u64, Error> {
    configure(&socket)?;
    if running_image_fingerprint()? != config.executable {
        return Err("typed process running image changed".into());
    }
    let prefix = config.bytes()?;
    let spec = receive(&mut socket, HELLO, prefix.len() + 64)?;
    if spec.len() != prefix.len() + 64 || !spec.starts_with(&prefix) {
        return Err("typed process independent configuration mismatch".into());
    }
    let tail = &spec[prefix.len() + 32..];
    let words: Vec<_> = tail
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    if words.iter().any(|v| *v == 0) || words[2] == words[3] {
        return Err("typed process session reservation identity".into());
    }
    let digest = launch::digest(DOMAIN, &spec)?;
    let mut ready = std::process::id().to_le_bytes().to_vec();
    ready.extend(digest);
    let mut worker = TypedWorker::new(config.registry, config.pin, config.peak)?;
    worker.request_resources = config.jobs;
    send(&mut socket, READY, &ready)?;
    let mut completed = 0u64;
    loop {
        let (kind, packet) = receive_command(&mut socket)?;
        if kind == STOP {
            let stats = worker.stats()?;
            worker.drain()?;
            worker.close();
            shutdown()?;
            let receipt: Vec<_> = [stats.setups, stats.hits, completed]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect();
            send(&mut socket, STOPPED, &receipt)?;
            return Ok(completed);
        }
        if packet.len() < 8 {
            return Err("typed process token frame truncated".into());
        }
        let token_len = usize::try_from(u64::from_le_bytes(packet[..8].try_into()?))?;
        if token_len > MAX_TOKEN_BYTES || token_len > packet.len() - 8 {
            return Err("typed process token size".into());
        }
        let token = Token::decode(&packet[8..8 + token_len])?;
        let request = &packet[8 + token_len..];
        token.check_execution(digest)?;
        let gate = WorkerGate::enter(launches, &token, request)?;
        let result = worker.execute_packet(&gate, request, config.chain, &mut policy)?;
        worker.drain()?;
        drop(gate);
        send(&mut socket, RESULT, &result)?;
        completed = completed
            .checked_add(1)
            .ok_or("typed process job count overflow")?;
    }
}
