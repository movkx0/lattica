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
    policy_context::{PolicyContext, MAX_BYTES as MAX_CONTEXT_BYTES},
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
pub(super) const CONFIG_BYTES: usize = MAGIC.len() + 5 * 32 + 2 * 4 * 8 + 2 * 8;
pub(super) const SESSION_BYTES: usize = CONFIG_BYTES + 64;
const HELLO: u8 = 1;
const READY: u8 = 2;
const JOB: u8 = 3;
const RESULT: u8 = 4;
const STOP: u8 = 5;
const STOPPED: u8 = 6;
const CONTEXT: u8 = 7;
const CONTEXT_READY: u8 = 8;
const PING: u8 = 9;
const PONG: u8 = 10;
const RESULT_RETIRING: u8 = 11;
const MAX_FRAME: usize = MAX_REQUEST_BYTES + MAX_TOKEN_BYTES + 512;
const TIMEOUT: Duration = Duration::from_secs(600);

/// An admitted task and its exact launch-binding packet. The packet stays
/// immutable until dispatch consumes it; preparing it grants no launch authority.
pub struct PreparedDispatch {
    task: Task,
    request: launch::PreparedRequest,
}

impl PreparedDispatch {
    pub fn request(&self) -> &[u8] {
        self.request.bytes()
    }

    pub(in crate::block_v2::execution) fn bound_request(&self) -> &launch::PreparedRequest {
        &self.request
    }
}

pub(crate) const CONFIGURATION_IDENTITY_MAX_BYTES: usize = 1 << 20;

#[cfg(test)]
#[path = "worker_typed_process_tests.rs"]
mod tests;

#[path = "worker_typed_process_service.rs"]
mod service;

#[path = "worker_typed_process_storage.rs"]
mod persistent_storage;
pub use persistent_storage::ProcessStorage;

/// Identity for independently supplied public policy and hardware assignment.
pub fn configuration_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.is_empty() || bytes.len() > CONFIGURATION_IDENTITY_MAX_BYTES {
        return Err("typed process configuration size".into());
    }
    launch::digest(DOMAIN, bytes)
}

#[derive(Clone)]
pub struct Config {
    registry: crate::block_v2::typed_recursive::CheckedRegistry,
    pin: RegistryPin,
    chain: [u8; 32],
    peak: Resources,
    jobs: Resources,
    executable: [u8; 32],
    policy_assignment: [u8; 32],
    cache_entries: usize,
    cache_reserve_bytes: u64,
}

impl Config {
    /// A trusted preparation callback must retain the independently admitted
    /// resources and current executable, even when it uses another identity
    /// encoding than the native bootstrap.
    #[cfg(feature = "gpu")]
    pub(crate) fn check_admitted_assignment(
        &self,
        assignment: &serde_json::Value,
    ) -> Result<(), Error> {
        let (peak, jobs) = crate::block_v2::execution::worker_budget::resources(assignment)?;
        let (entries, reserve) =
            crate::block_v2::execution::worker_budget::preprocessing_cache(assignment)?;
        if self.peak != peak
            || self.jobs != jobs
            || self.cache_entries != entries
            || self.cache_reserve_bytes != reserve
            || self.executable != running_image_fingerprint()?
        {
            return Err("prepared public worker differs from admitted assignment/image".into());
        }
        Ok(())
    }

    /// Interpret the existing independently pinned worker assignment. This
    /// builds protocol identity; it does not enforce OS or GPU resources.
    pub fn from_assignment(
        registry: TypedRegistry<12>,
        pin: RegistryPin,
        chain: [u8; 32],
        executable: [u8; 32],
        policy_assignment: [u8; 32],
        assignment: &serde_json::Value,
    ) -> Result<Self, Error> {
        use crate::block_v2::execution::worker_budget;
        let (peak, jobs) = worker_budget::resources(assignment)?;
        let (entries, reserve) = worker_budget::preprocessing_cache(assignment)?;
        Self::new(
            registry,
            pin,
            chain,
            peak,
            jobs,
            executable,
            policy_assignment,
        )?
        .with_preprocessing_cache(entries, reserve)
    }

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
        peak.validate_capacity()?;
        storage::admit_startup(peak.ram_bytes, peak.threads)?;
        let registry = crate::block_v2::typed_recursive::CheckedRegistry::new(registry)?;
        Self::from_checked(
            registry,
            pin,
            chain,
            peak,
            jobs,
            executable,
            policy_assignment,
        )
    }

    pub(crate) fn from_checked_assignment(
        registry: crate::block_v2::typed_recursive::CheckedRegistry,
        pin: RegistryPin,
        chain: [u8; 32],
        executable: [u8; 32],
        policy_assignment: [u8; 32],
        assignment: &serde_json::Value,
    ) -> Result<Self, Error> {
        let (peak, jobs) = crate::block_v2::execution::worker_budget::resources(assignment)?;
        let (entries, reserve_bytes) =
            crate::block_v2::execution::worker_budget::preprocessing_cache(assignment)?;
        Self::from_checked(
            registry,
            pin,
            chain,
            peak,
            jobs,
            executable,
            policy_assignment,
        )?
        .with_preprocessing_cache(entries, reserve_bytes)
    }

    fn from_checked(
        registry: crate::block_v2::typed_recursive::CheckedRegistry,
        pin: RegistryPin,
        chain: [u8; 32],
        peak: Resources,
        jobs: Resources,
        executable: [u8; 32],
        policy_assignment: [u8; 32],
    ) -> Result<Self, Error> {
        pin.check_typed_approved(&registry.as_ref())?;
        peak.validate_capacity()?;
        storage::admit_startup(peak.ram_bytes, peak.threads)?;
        storage::session_memory_bytes(peak.ram_bytes, peak.threads)?;
        jobs.validate_request()?;
        coordinator::admit_budget(jobs.ram_bytes)?;
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
            cache_entries: 1,
            cache_reserve_bytes: 0,
        })
    }

    pub fn with_preprocessing_cache(
        mut self,
        entries: usize,
        reserve_bytes: u64,
    ) -> Result<Self, Error> {
        if entries == 0
            || entries > 12
            || (entries == 1) != (reserve_bytes == 0)
            || crate::block_v2::typed_recursive::storage::active_memory_bytes(
                storage::session_memory_bytes(self.peak.ram_bytes, self.peak.threads)?,
                reserve_bytes,
            )
            .is_err()
        {
            return Err("typed worker preprocessing cache admission".into());
        }
        self.cache_entries = entries;
        self.cache_reserve_bytes = reserve_bytes;
        Ok(self)
    }

    fn descriptor(&self) -> Result<Descriptor, Error> {
        Ok(Descriptor {
            registry_id: self.registry.profile(),
            pin: self.pin,
            chain: self.chain,
            peak: self.peak,
            jobs: self.jobs,
            executable: self.executable,
            policy_assignment: self.policy_assignment,
            cache_entries: self.cache_entries,
            cache_reserve_bytes: self.cache_reserve_bytes,
        })
    }

    fn into_parts(
        self,
    ) -> Result<
        (
            crate::block_v2::typed_recursive::CheckedRegistry,
            Descriptor,
        ),
        Error,
    > {
        let descriptor = self.descriptor()?;
        Ok((self.registry, descriptor))
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> Result<[u8; CONFIG_BYTES], Error> {
        Ok(self.descriptor()?.bytes())
    }
}

/// Validated protocol identity owns no registry or heap storage. The child
/// moves its registry into the typed session; the coordinator retains only
/// this descriptor after preparing its process reservation.
#[derive(Clone, Copy)]
pub(super) struct Descriptor {
    registry_id: [u8; 32],
    pin: RegistryPin,
    chain: [u8; 32],
    peak: Resources,
    jobs: Resources,
    executable: [u8; 32],
    policy_assignment: [u8; 32],
    cache_entries: usize,
    cache_reserve_bytes: u64,
}

impl Descriptor {
    fn bytes(&self) -> [u8; CONFIG_BYTES] {
        let mut bytes = [0; CONFIG_BYTES];
        let mut offset = 0;
        let mut write = |value: &[u8]| {
            bytes[offset..offset + value.len()].copy_from_slice(value);
            offset += value.len();
        };
        write(MAGIC);
        for digest in [
            self.registry_id,
            self.pin.profile(),
            self.chain,
            self.executable,
            self.policy_assignment,
        ] {
            write(&digest);
        }
        for resources in [self.peak, self.jobs] {
            for value in [
                resources.ram_bytes,
                resources.vram_bytes,
                resources.scratch_bytes,
                u64::from(resources.threads),
            ] {
                write(&value.to_le_bytes());
            }
        }
        write(&(self.cache_entries as u64).to_le_bytes());
        write(&self.cache_reserve_bytes.to_le_bytes());
        debug_assert_eq!(offset, CONFIG_BYTES);
        bytes
    }
}

fn send(socket: &mut UnixStream, kind: u8, bytes: &[u8]) -> Result<(), Error> {
    send_parts(socket, kind, &[bytes])
}

fn send_parts(socket: &mut UnixStream, kind: u8, parts: &[&[u8]]) -> Result<(), Error> {
    let size = parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))
        .ok_or("typed process frame size overflow")?;
    if size > MAX_FRAME {
        return Err("typed process frame exceeds bound".into());
    }
    socket.write_all(&[kind])?;
    socket.write_all(&(size as u64).to_le_bytes())?;
    for part in parts {
        socket.write_all(part)?;
    }
    Ok(())
}

fn receive(socket: &mut UnixStream, expected: u8, bound: usize) -> Result<Vec<u8>, Error> {
    let mut header = [0; 9];
    socket.read_exact(&mut header)?;
    let size = u64::from_le_bytes(header[1..].try_into()?);
    if header[0] != expected || size > bound.min(MAX_FRAME) as u64 {
        return Err("typed process frame kind or size".into());
    }
    receive_body(socket, usize::try_from(size)?, bound.min(MAX_FRAME))
}

fn receive_body(socket: &mut UnixStream, size: usize, bound: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = super::packet::storage_vec(size, bound.min(MAX_FRAME))?;
    bytes.resize(size, 0);
    socket.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn receive_result(socket: &mut UnixStream) -> Result<(Vec<u8>, bool), Error> {
    let mut header = [0; 9];
    socket.read_exact(&mut header)?;
    let size = u64::from_le_bytes(header[1..].try_into()?);
    if !matches!(header[0], RESULT | RESULT_RETIRING)
        || size > packet::MAX_RESULT_BYTES.min(MAX_FRAME) as u64
    {
        return Err("typed process result kind or size".into());
    }
    Ok((
        receive_body(socket, usize::try_from(size)?, packet::MAX_RESULT_BYTES)?,
        header[0] == RESULT_RETIRING,
    ))
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
        STOP | PING => 0,
        CONTEXT => MAX_CONTEXT_BYTES,
        _ => return Err("typed process command kind".into()),
    };
    if size > bound as u64 {
        return Err("typed process command size".into());
    }
    let bytes = receive_body(socket, usize::try_from(size)?, bound)?;
    Ok((header[0], bytes))
}

/// Only this object owns the child and its issuing workspace reservation.
pub struct ProcessWorker {
    config: Descriptor,
    reservation: WorkspaceReservation,
    job_worker: WorkerId,
    spec: [u8; SESSION_BYTES],
    child: Option<Child>,
    service: Option<service::OwnedService>,
    socket: Option<UnixStream>,
    pending: Option<(Task, launch::PreparedRequest)>,
    pid: Option<u32>,
    stats: CacheStats,
    completed: u64,
    poisoned: bool,
    exited_cleanly: bool,
    retirement_requested: bool,
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
        let (_, config) = config.into_parts()?;
        let mut spec = [0; SESSION_BYTES];
        spec[..CONFIG_BYTES].copy_from_slice(&config.bytes());
        let reservation = owner.reserve_workspace(
            worker,
            Resources {
                threads: 0,
                ..config.peak
            },
            now_ms,
        )?;
        let lease = reservation.lease()?;
        spec[CONFIG_BYTES..CONFIG_BYTES + 32].copy_from_slice(&lease.id().session);
        for (bytes, value) in spec[CONFIG_BYTES + 32..].chunks_exact_mut(8).zip([
            lease.id().epoch,
            lease.id().sequence,
            worker.0,
            job_worker.0,
        ]) {
            bytes.copy_from_slice(&value.to_le_bytes());
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
            retirement_requested: false,
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
        if self.retirement_requested {
            return Err("typed process requested retirement".into());
        }
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
        let prepared = self.prepare_dispatch(task)?;
        self.dispatch_prepared(token, prepared)
    }

    fn check_dispatch(&self, task: &Task) -> Result<(), Error> {
        self.stats()?;
        if self.retirement_requested {
            return Err("typed process requested retirement".into());
        }
        if task.workspace.lease() != self.reservation.lease()? {
            return Err("typed process task belongs to another workspace".into());
        }
        Ok(())
    }

    /// Prepare once, then let the caller bind a launch token to these bytes.
    /// Ownership prevents the binding packet and dispatched task from diverging.
    pub fn prepare_dispatch(&self, task: Task) -> Result<PreparedDispatch, Error> {
        self.check_dispatch(&task)?;
        let request = launch::PreparedRequest::new(task.request()?)?;
        Ok(PreparedDispatch { task, request })
    }

    /// Consume the exact prepared packet without re-encoding its public proofs.
    /// Process/workspace and token checks still run immediately before sending.
    pub fn dispatch_prepared(
        &mut self,
        token: &Token,
        prepared: PreparedDispatch,
    ) -> Result<(), Error> {
        self.check_dispatch(&prepared.task)?;
        let PreparedDispatch { task, request } = prepared;
        token.check_execution(self.execution_digest()?)?;
        token.check_prepared_request(&request)?;
        let token_bytes = token.encode()?;
        let token_len = (token_bytes.len() as u64).to_le_bytes();
        self.poisoned = true;
        self.pending = Some((task, request));
        let socket = self.socket.as_mut().ok_or("typed process is not running")?;
        send_parts(
            socket,
            JOB,
            &[
                &token_len,
                &token_bytes,
                self.pending.as_ref().unwrap().1.bytes(),
            ],
        )
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    /// The last result remains valid; close the idle worker before replacement.
    pub fn retirement_requested(&self) -> bool {
        self.retirement_requested
    }
    pub fn scheduling_capabilities(
        &self,
    ) -> crate::block_v2::execution::scheduler::WorkerCapabilities {
        crate::block_v2::execution::scheduler::WorkerCapabilities {
            worker: self.job_worker,
            profile: self.config.pin.profile(),
            resources: self.config.jobs,
            resident_mode: None,
            timing_identity: None,
            forecast_retained_mode: false,
            dispatch_deadline_ms: None,
        }
    }

    /// The host approves physical device/driver/kernel/settings fingerprints.
    /// Bind them to this process image and its actual immutable descriptor.
    /// Candidate policies/launch paths belong to protocol fencing, not timing.
    pub fn scheduling_capabilities_with_timing(
        &self,
        identity: crate::block_v2::execution::scheduler::TimingIdentity,
    ) -> Result<crate::block_v2::execution::scheduler::WorkerCapabilities, Error> {
        let mut descriptor = self.config;
        descriptor.policy_assignment = [0; 32];
        let identity = identity.bind_configuration(
            self.config.executable,
            configuration_digest(&descriptor.bytes())?,
        )?;
        Ok(crate::block_v2::execution::scheduler::WorkerCapabilities {
            timing_identity: Some(identity),
            ..self.scheduling_capabilities()
        })
    }

    /// Switch the host-derived public policy without dropping preprocessing or
    /// the GPU context. Only an idle session may change; old launch tokens are
    /// fenced by the new execution digest. An ambiguous reply poisons the
    /// session and leaves its workspace reserved for process reconciliation.
    pub fn replace_context(&mut self, context: &PolicyContext) -> Result<(), Error> {
        self.stats()?;
        self.reservation.require_idle()?;
        if self.pending.is_some() {
            return Err("typed process context change while active".into());
        }
        let packet = context.encode();
        let mut config = self.config;
        config.policy_assignment = configuration_digest(&packet)?;
        let mut spec = self.spec;
        spec[..CONFIG_BYTES].copy_from_slice(&config.bytes());
        let digest = launch::digest(DOMAIN, &spec)?;
        let socket = self.socket.as_mut().ok_or("typed process is not running")?;
        self.poisoned = true;
        send(socket, CONTEXT, &packet)?;
        if receive(socket, CONTEXT_READY, 32)? != digest {
            return Err("typed process context acknowledgement mismatch".into());
        }
        self.config = config;
        self.spec = spec;
        self.poisoned = false;
        Ok(())
    }

    /// Keep an idle, supervised worker alive across transaction cycles. A missing
    /// reply poisons the session; it never releases an outstanding reservation.
    pub fn heartbeat(&mut self) -> Result<(), Error> {
        self.stats()?;
        self.reservation.require_idle()?;
        if self.pending.is_some() {
            return Err("typed process heartbeat while active".into());
        }
        let digest = self.execution_digest()?;
        let socket = self.socket.as_mut().ok_or("typed process is not running")?;
        self.poisoned = true;
        send(socket, PING, &[])?;
        if receive(socket, PONG, 32)? != digest {
            return Err("typed process heartbeat acknowledgement mismatch".into());
        }
        self.poisoned = false;
        Ok(())
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
        let (response, retiring) = receive_result(socket)?;
        let result = packet::decode_result_prepared_owned(&task.assignment, request, response)?;
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
        self.retirement_requested = retiring;
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
    socket: UnixStream,
    config: Config,
    launches: &Path,
    policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    shutdown: impl FnMut() -> Result<(), Error>,
) -> Result<u64, Error> {
    serve_with(
        socket,
        config,
        launches,
        policy,
        shutdown,
        TypedWorker::from_checked,
    )
}

#[cfg(feature = "gpu-cuda")]
pub(crate) fn serve_cuda(
    socket: UnixStream,
    config: Config,
    launches: &Path,
    policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    runtime: crate::cuda_compute::Runtime,
    limits: crate::block_v2::typed_recursive::CudaLimits,
    host_output_bytes: u64,
) -> Result<u64, Error> {
    let worker_runtime = runtime.clone();
    let mut runtime = Some(runtime);
    serve_with(
        socket,
        config,
        launches,
        policy,
        || {
            let snapshot = runtime
                .take()
                .ok_or("CUDA worker already retired")?
                .retire()?;
            eprintln!("typed_cuda_shutdown {}", serde_json::to_string(&snapshot)?);
            Ok(())
        },
        move |registry, pin, resources| {
            TypedWorker::from_checked_cuda(
                registry,
                pin,
                resources,
                &worker_runtime,
                limits,
                host_output_bytes,
            )
        },
    )
}

fn serve_with(
    mut socket: UnixStream,
    config: Config,
    launches: &Path,
    mut policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    mut shutdown: impl FnMut() -> Result<(), Error>,
    construct: impl FnOnce(
        crate::block_v2::typed_recursive::CheckedRegistry,
        RegistryPin,
        Resources,
    ) -> Result<TypedWorker, Error>,
) -> Result<u64, Error> {
    configure(&socket)?;
    if running_image_fingerprint()? != config.executable {
        return Err("typed process running image changed".into());
    }
    let (registry, mut config) = config.into_parts()?;
    let prefix = config.bytes();
    let mut spec: [u8; SESSION_BYTES] = receive(&mut socket, HELLO, SESSION_BYTES)?
        .try_into()
        .map_err(|_| "typed process independent configuration mismatch")?;
    if !spec.starts_with(&prefix) {
        return Err("typed process independent configuration mismatch".into());
    }
    let tail = &spec[CONFIG_BYTES + 32..];
    let words: [u64; 4] =
        std::array::from_fn(|i| u64::from_le_bytes(tail[i * 8..(i + 1) * 8].try_into().unwrap()));
    if words.iter().any(|v| *v == 0) || words[2] == words[3] {
        return Err("typed process session reservation identity".into());
    }
    let mut digest = launch::digest(DOMAIN, &spec)?;
    let mut ready = [0; 36];
    ready[..4].copy_from_slice(&std::process::id().to_le_bytes());
    ready[4..].copy_from_slice(&digest);
    let mut worker = construct(registry, config.pin, config.peak)?;
    worker
        .session
        .as_mut()
        .ok_or("typed worker missing session")?
        .configure_cache(config.cache_entries, config.cache_reserve_bytes)?;
    worker.request_resources = config.jobs;
    #[cfg(target_env = "gnu")]
    crate::spill_alloc::host_backing::report("ready", 0);
    send(&mut socket, READY, &ready)?;
    let mut completed = 0u64;
    let mut retiring = false;
    let mut public_context: Option<PolicyContext> = None;
    loop {
        let (kind, packet) = receive_command(&mut socket)?;
        storage::check_buffers(packet.capacity(), packet::MAX_RESULT_BYTES)?;
        if kind == PING {
            send(&mut socket, PONG, &digest)?;
            continue;
        }
        if kind == CONTEXT {
            let context = PolicyContext::decode(&packet)?;
            worker.drain()?;
            config.policy_assignment = configuration_digest(&packet)?;
            let mut next = spec;
            next[..CONFIG_BYTES].copy_from_slice(&config.bytes());
            digest = launch::digest(DOMAIN, &next)?;
            spec = next;
            public_context = Some(context);
            send(&mut socket, CONTEXT_READY, &digest)?;
            continue;
        }
        if kind == STOP {
            let stats = worker.stats()?;
            worker.drain()?;
            #[cfg(feature = "gpu")]
            let memory = crate::block_v2::gpu_hash::begin_memory_window()?;
            worker.close();
            shutdown()?;
            #[cfg(target_env = "gnu")]
            crate::spill_alloc::host_backing::report("shutdown", completed);
            #[cfg(feature = "gpu")]
            if let Some(memory) = memory {
                eprintln!(
                    "typed_gpu_memory {}",
                    serde_json::json!({
                        "version": 1, "boundary": "shutdown", "completed_jobs": completed,
                        "pid": std::process::id(), "managed": memory.finish()?,
                    })
                );
            }
            let receipt: Vec<_> = [stats.setups, stats.hits, completed]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect();
            send(&mut socket, STOPPED, &receipt)?;
            return Ok(completed);
        }
        if retiring {
            return Err("typed process job after retirement request".into());
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
        #[cfg(target_env = "gnu")]
        crate::spill_alloc::host_backing::report("job_start", completed);
        #[cfg(feature = "gpu")]
        let memory = crate::block_v2::gpu_hash::begin_memory_window()?;
        let result =
            worker.execute_packet(
                &gate,
                request,
                config.chain,
                |artifact| match &public_context {
                    Some(context) => context.policy(artifact),
                    None => policy(artifact),
                },
            )?;
        worker.drain()?;
        #[cfg(target_env = "gnu")]
        crate::spill_alloc::host_backing::report("job_drained", completed);
        #[cfg(feature = "gpu-cuda")]
        if let Some(runtime) = &worker.cuda {
            eprintln!(
                "typed_cuda_memory {}",
                serde_json::to_string(&runtime.snapshot())?
            );
        }
        #[cfg(feature = "gpu")]
        if let Some(memory) = memory {
            eprintln!(
                "typed_gpu_memory {}",
                serde_json::json!({
                    "version": 1, "boundary": "job_drained", "job_index": completed,
                    "pid": std::process::id(), "managed": memory.finish()?,
                })
            );
        }
        drop(gate);
        storage::check_buffers(packet.capacity(), result.capacity())?;
        #[cfg(target_env = "gnu")]
        {
            retiring = !crate::spill_alloc::host_backing::worker_reuse_allowed(
                config.peak.ram_bytes,
                config.cache_reserve_bytes,
            );
        }
        #[cfg(not(target_env = "gnu"))]
        {
            // Without an allocator observation, deliver this job and require
            // physical exit before another process takes its reservation.
            retiring = true;
        }
        send(
            &mut socket,
            if retiring { RESULT_RETIRING } else { RESULT },
            &result,
        )?;
        completed = completed
            .checked_add(1)
            .ok_or("typed process job count overflow")?;
    }
}
