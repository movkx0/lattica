//! Experimental per-lease CPU service supervision; no production activation.
//!
//! Preparation precedes task publication; dispatch intent is durable before the
//! sole launcher is spawned. An unseen launch outcome is quarantined on the same
//! boot, never retried or released because systemd has forgotten its unit.
//! The exclusive caller owns this namespace. Same-UID bypass/mutation is outside
//! the trust model. Stop receipts cover OS work, not CPU verifier drain or proof
//! acceptance. Aggregate journal admission/pruning and physical scratch quotas
//! are still responsibilities of the enclosing bounded runtime.
use super::{
    artifact_store::hex,
    dag::{LaunchBinding, Lease},
    journal::{DurableDag, JournalLimits, PreviousAttempt, SnapshotLog},
    launch::{IdleGate, LaunchStore, Token},
    os_worker::{self, Identity, LiveProcess},
    resources::Resources,
    transport::{absolute_path, image_fingerprint, TaskOwner, WorkerConfig},
};
use crate::block_v2::{commitment, recursive::Error};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
};

const MAGIC: &[u8; 8] = b"LVOSR001";
const BOUND_MAGIC: &[u8; 8] = b"LVOSR002";
const ADMISSION_DOMAIN: u64 = 0x4c4256327a;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Admission {
    path: [u8; 32],
    directory: [u64; 2],
}
fn path_digest(path: &Path) -> Result<[u8; 32], Error> {
    super::launch::digest(ADMISSION_DOMAIN, absolute_path(path)?.as_bytes())
}
const MAX_RECORD_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExitBasis {
    NeverDispatched,
    PriorBoot,
    Observed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    admission: Option<Admission>,
    key: [u8; 32],
    resources: Resources,
    task: PathBuf,
    executable: PathBuf,
    launch_path: PathBuf,
    launch_directory: [u64; 2],
    image: [u8; 32],
    timeout_seconds: u32,
    token: Option<Token>,
    dispatch_boot: Option<[u8; 16]>,
    observed: Option<Identity>,
    cancelled: bool,
    revoked: bool,
    stopped: bool,
}
impl Record {
    fn exit_basis(&self, boot: [u8; 16]) -> Result<ExitBasis, Error> {
        self.validate()?;
        if !self.cancelled || !self.revoked || boot == [0; 16] {
            return Err("stop evidence requires durable cancellation and revocation".into());
        }
        Ok(match self.dispatch_boot {
            None => ExitBasis::NeverDispatched,
            Some(previous) if previous != boot => ExitBasis::PriorBoot,
            Some(_) if self.observed.is_some() => ExitBasis::Observed,
            Some(_) => ExitBasis::Unknown,
        })
    }
    fn unit(&self) -> String {
        format!("lattica-v2-worker-{}.service", hex(&self.key))
    }
    fn validate(&self) -> Result<(), Error> {
        if let Some(a) = &self.admission {
            commitment::digest_from_bytes(&a.path)?;
            if a.directory[1] == 0 {
                return Err("supervisor admission directory".into());
            }
        }
        commitment::digest_from_bytes(&self.key)?;
        commitment::digest_from_bytes(&self.image)?;
        self.resources.validate_request()?;
        if self.resources.vram_bytes != 0
            || self.resources.ram_bytes > 45 << 30
            || self.resources.scratch_bytes > 128 << 30
            || self.resources.threads > 248
            || !(1..=7200).contains(&self.timeout_seconds)
            || self.launch_directory[1] == 0
        {
            return Err("CPU supervisor resource/configuration bound".into());
        }
        for path in [&self.task, &self.executable, &self.launch_path] {
            absolute_path(path)?;
        }
        if self.task == self.launch_path || self.task == self.executable {
            return Err("supervisor path alias".into());
        }
        if let Some(token) = &self.token {
            if token.encode()?.len() != super::launch::MAX_TOKEN_BYTES {
                return Err("supervisor requires an execution-bound token".into());
            }
            if token.key() != self.key || token.resources() != self.resources {
                return Err("supervisor token/lease substitution".into());
            }
        }
        if let Some(boot) = self.dispatch_boot {
            if boot == [0; 16] || self.token.is_none() {
                return Err("invalid dispatch record".into());
            }
        }
        if let Some(identity) = &self.observed {
            identity.validate(&self.unit())?;
            if self.dispatch_boot != Some(identity.boot) {
                return Err("observation boot differs from dispatch".into());
            }
        }
        if (self.revoked && !self.cancelled) || (self.stopped && !self.revoked) {
            return Err("nonmonotonic supervisor stop state".into());
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = if self.admission.is_some() {
            BOUND_MAGIC
        } else {
            MAGIC
        }
        .to_vec();
        out.extend(self.key);
        for value in [
            self.resources.ram_bytes,
            self.resources.vram_bytes,
            self.resources.scratch_bytes,
        ] {
            out.extend(value.to_le_bytes());
        }
        out.extend(self.resources.threads.to_le_bytes());
        out.extend(self.image);
        out.extend(self.timeout_seconds.to_le_bytes());
        for value in self.launch_directory {
            out.extend(value.to_le_bytes());
        }
        for path in [&self.task, &self.executable, &self.launch_path] {
            put_string(&mut out, absolute_path(path)?);
        }
        let token = self
            .token
            .as_ref()
            .map(Token::encode)
            .transpose()?
            .unwrap_or_default();
        out.extend((token.len() as u16).to_le_bytes());
        out.extend(token);
        out.push(u8::from(self.dispatch_boot.is_some()));
        if let Some(boot) = self.dispatch_boot {
            out.extend(boot);
        }
        out.push(u8::from(self.observed.is_some()));
        if let Some(identity) = &self.observed {
            out.extend(identity.boot);
            out.extend(identity.invocation);
            out.extend(identity.pid.to_le_bytes());
            out.extend(identity.start_ticks.to_le_bytes());
            out.extend(identity.device.to_le_bytes());
            out.extend(identity.inode.to_le_bytes());
            put_string(&mut out, &identity.group);
        }
        out.extend([
            u8::from(self.cancelled),
            u8::from(self.revoked),
            u8::from(self.stopped),
        ]);
        if let Some(a) = &self.admission {
            out.extend(a.path);
            for value in a.directory {
                out.extend(value.to_le_bytes());
            }
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err("supervisor record byte bound".into());
        }
        Ok(out)
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("supervisor record byte bound".into());
        }
        let mut r = Reader(bytes);
        let magic = r.array::<8>()?;
        let bound = &magic == BOUND_MAGIC;
        if !bound && &magic != MAGIC {
            return Err("supervisor record version".into());
        }
        let key = r.array()?;
        let resources = Resources {
            ram_bytes: r.u64()?,
            vram_bytes: r.u64()?,
            scratch_bytes: r.u64()?,
            threads: r.u32()?,
        };
        let image = r.array()?;
        let timeout_seconds = r.u32()?;
        let launch_directory = [r.u64()?, r.u64()?];
        let task = PathBuf::from(r.string()?);
        let executable = PathBuf::from(r.string()?);
        let launch_path = PathBuf::from(r.string()?);
        let token_len = u16::from_le_bytes(r.array()?) as usize;
        let token = if token_len == 0 {
            None
        } else {
            Some(Token::decode(r.take(token_len)?)?)
        };
        let dispatch_boot = if r.boolean()? { Some(r.array()?) } else { None };
        let observed = if r.boolean()? {
            Some(Identity {
                boot: r.array()?,
                invocation: r.array()?,
                pid: r.u32()?,
                start_ticks: r.u64()?,
                device: r.u64()?,
                inode: r.u64()?,
                group: r.string()?,
            })
        } else {
            None
        };
        let mut record = Self {
            admission: None,
            key,
            resources,
            task,
            executable,
            launch_path,
            launch_directory,
            image,
            timeout_seconds,
            token,
            dispatch_boot,
            observed,
            cancelled: r.boolean()?,
            revoked: r.boolean()?,
            stopped: r.boolean()?,
        };
        if bound {
            record.admission = Some(Admission {
                path: r.array()?,
                directory: [r.u64()?, r.u64()?],
            });
        }
        if !r.0.is_empty() {
            return Err("supervisor record trailing bytes".into());
        }
        record.validate()?;
        Ok(record)
    }
}
fn put_string(out: &mut Vec<u8>, value: &str) {
    out.extend((value.len() as u32).to_le_bytes());
    out.extend(value.as_bytes());
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err("truncated supervisor record".into());
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into()?)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("supervisor boolean canonicality".into()),
        }
    }
    fn string(&mut self) -> Result<String, Error> {
        let len = self.u32()? as usize;
        if len == 0 || len > 4096 {
            return Err("supervisor string bound".into());
        }
        Ok(std::str::from_utf8(self.take(len)?)?.to_owned())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Prepared,
    Ready,
    DispatchUncertain,
    Observed,
    Cancelled,
    Stopped,
}
pub struct Supervisor {
    log: SnapshotLog,
    record: Record,
    live: Option<LiveProcess>,
}
impl Supervisor {
    /// Call BEFORE creating/issuing the task, AFTER durable scheduler reservation.
    /// Reserve launch capacity before binding preparation, then durably authorize
    /// this exact supervisor directory. Errors retain reservations for recovery.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        path: &Path,
        owner: &mut DurableDag,
        lease: Lease,
        launches: &mut LaunchStore,
        launch_path: &Path,
        task: &Path,
        executable: &Path,
        timeout_seconds: u32,
    ) -> Result<Self, Error> {
        let assignment = owner.assignment(lease)?;
        match std::fs::symlink_metadata(task) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => return Err("supervisor preparation must precede task creation".into()),
        }
        launches.check_directory(launch_path)?;
        let mut record = Record {
            admission: None,
            key: lease.process_key()?,
            resources: assignment.resources(),
            task: task.to_owned(),
            executable: executable.to_owned(),
            launch_path: launch_path.to_owned(),
            launch_directory: launches.directory_identity()?,
            image: image_fingerprint(executable)?,
            timeout_seconds,
            token: None,
            dispatch_boot: None,
            observed: None,
            cancelled: false,
            revoked: false,
            stopped: false,
        };
        record.validate()?;
        let claim = path_digest(path)?;
        launches.reserve_supervisor(owner, lease, claim)?;
        record.admission = Some(Admission {
            path: claim,
            directory: [0; 2],
        });
        let supervisor = Self::create_record(path, record)?;
        #[cfg(test)]
        preparation_crash_boundary("journal");
        let admission = supervisor
            .record
            .admission
            .as_ref()
            .ok_or("missing supervisor admission")?;
        owner.authorize_supervisor(
            lease,
            supervisor.record.launch_directory,
            admission.path,
            admission.directory,
        )?;
        #[cfg(test)]
        preparation_crash_boundary("authorized");
        Ok(supervisor)
    }
    fn create_record(path: &Path, mut record: Record) -> Result<Self, Error> {
        let mut basic = record.clone();
        basic.admission = None;
        basic.validate()?;
        if let Some(a) = &record.admission {
            if a.path != path_digest(path)? {
                return Err("supervisor journal location".into());
            }
        }
        let mut log = SnapshotLog::create(
            path,
            JournalLimits {
                snapshot_bytes: MAX_RECORD_BYTES,
            },
        )?;
        if let Some(a) = &mut record.admission {
            a.directory = log.identity()?;
        }
        log.commit(&record.encode()?)?;
        Ok(Self {
            log,
            record,
            live: None,
        })
    }
    fn open_record(path: &Path, key: [u8; 32], resources: Resources) -> Result<Self, Error> {
        let (mut log, bytes) = SnapshotLog::open(
            path,
            JournalLimits {
                snapshot_bytes: MAX_RECORD_BYTES,
            },
        )?;
        let record = Record::decode(&bytes)?;
        if record.key != key || record.resources != resources {
            return Err("supervisor differs from authoritative lease".into());
        }
        if let Some(a) = &record.admission {
            if a.path != path_digest(path)? || a.directory != log.identity()? {
                return Err("supervisor journal copied/replaced".into());
            }
        }
        log.cleanup_pending()?;
        Ok(Self {
            log,
            record,
            live: None,
        })
    }
    /// The OS receipt is only one prerequisite of the DAG's separate recovery
    /// callback. Old coordinator verification must also be authoritatively drained.
    pub fn recover(path: &Path, attempt: &PreviousAttempt) -> Result<Self, Error> {
        let value = Self::open_record(path, attempt.lease.process_key()?, attempt.resources)?;
        match (
            &value.record.admission,
            attempt.launch_binding,
            attempt.launch_root,
        ) {
            (
                Some(a),
                Some(LaunchBinding::Authorized {
                    path: claim,
                    directory,
                }),
                Some(root),
            ) if claim == a.path
                && directory == a.directory
                && root.store == value.record.launch_directory =>
            {
                ()
            }
            (Some(a), Some(LaunchBinding::Supervised(claim)), Some(root))
                if claim == a.path && root.store == value.record.launch_directory =>
            {
                ()
            }
            (None, None, None) => (), // Historical unbound journal: recovery only.
            _ => return Err("supervisor differs from recovered admission".into()),
        }
        Ok(value)
    }
    pub fn reopen(path: &Path, owner: &DurableDag, lease: Lease) -> Result<Self, Error> {
        let value = Self::open_record(
            path,
            lease.process_key()?,
            owner.assignment(lease)?.resources(),
        )?;
        if let Some(a) = &value.record.admission {
            let current = owner.authorized_supervisor(lease, value.record.launch_directory, a.path);
            if let Ok(binding) = current {
                if binding
                    != (LaunchBinding::Authorized {
                        path: a.path,
                        directory: a.directory,
                    })
                {
                    return Err("supervisor authorization directory differs".into());
                }
            } else {
                owner.check_launch(
                    lease,
                    value.record.launch_directory,
                    LaunchBinding::Supervised(a.path),
                )?;
            }
        } else {
            owner.check_legacy_launch(lease)?;
        }
        Ok(value)
    }
    fn commit(&mut self, record: Record) -> Result<(), Error> {
        self.log.commit(&record.encode()?)?;
        self.record = record;
        Ok(())
    }
    fn check_lease(&self, lease: Lease) -> Result<(), Error> {
        self.log.check_current()?;
        if self.record.key != lease.process_key()? {
            return Err("supervisor lease substitution".into());
        }
        Ok(())
    }
    fn check_launches(&self, launches: &LaunchStore) -> Result<(), Error> {
        self.log.check_current()?;
        launches.check_directory(&self.record.launch_path)?;
        if self.record.admission.is_some() {
            launches.check_reservation(self.record.key)?;
        }
        if launches.directory_identity()? != self.record.launch_directory {
            return Err("supervisor launch directory replaced".into());
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Status, Error> {
        self.log.check_current()?;
        Ok(if self.record.stopped {
            Status::Stopped
        } else if self.record.cancelled {
            Status::Cancelled
        } else if self.record.observed.is_some() {
            Status::Observed
        } else if self.record.dispatch_boot.is_some() {
            Status::DispatchUncertain
        } else if self.record.token.is_some() {
            Status::Ready
        } else {
            Status::Prepared
        })
    }
    pub fn observed_identity(&self) -> Option<&Identity> {
        self.record.observed.as_ref()
    }
    pub fn service_name(&self) -> String {
        self.record.unit()
    }
    /// Create and publish only this admitted supervisor's immutable task.
    /// Partial publication is never retried under the same lease.
    pub fn issue_task(
        &mut self,
        owner: &mut DurableDag,
        lease: Lease,
        launches: &mut LaunchStore,
        config: WorkerConfig,
    ) -> Result<TaskOwner, Error> {
        self.check_lease(lease)?;
        self.check_launches(launches)?;
        let admission = self
            .record
            .admission
            .as_ref()
            .ok_or("legacy supervisor cannot issue/dispatch")?
            .path;
        if self.record.token.is_some() || self.record.cancelled {
            return Err("supervisor task already issued/cancelled".into());
        }
        self.check_admission(owner, lease)?;
        let mut task = TaskOwner::create(&self.record.task)?;
        task.issue_reserved(
            owner,
            launches,
            &self.record.launch_path,
            lease,
            config,
            admission,
        )?;
        self.bind_task(owner, lease, launches, &task)?;
        Ok(task)
    }
    fn check_admission(&self, owner: &DurableDag, lease: Lease) -> Result<(), Error> {
        let a = self
            .record
            .admission
            .as_ref()
            .ok_or("legacy supervisor cannot issue/dispatch")?;
        owner.check_launch(
            lease,
            self.record.launch_directory,
            LaunchBinding::Authorized {
                path: a.path,
                directory: a.directory,
            },
        )
    }

    /// Bind the immutable task after publication. No result is accepted here.
    pub fn bind_task(
        &mut self,
        owner: &DurableDag,
        lease: Lease,
        launches: &LaunchStore,
        task: &TaskOwner,
    ) -> Result<(), Error> {
        self.check_lease(lease)?;
        self.check_launches(launches)?;
        self.check_admission(owner, lease)?;
        if self.record.token.is_some() || self.record.cancelled {
            return Err("supervisor task already bound/cancelled".into());
        }
        let (token, image, timeout) = task.launch_binding(
            &owner.assignment(lease)?,
            &self.record.task,
            &self.record.executable,
            &self.record.launch_path,
        )?;
        if image != self.record.image
            || timeout != self.record.timeout_seconds
            || token.resources() != self.record.resources
        {
            return Err("supervisor immutable execution mismatch".into());
        }
        let mut next = self.record.clone();
        next.token = Some(token);
        self.commit(next)
    }
    /// At most one launcher, even across restarts. A spawn failure never puts
    /// the record back into Ready. Helper exit is not proof of worker exit.
    pub fn dispatch(
        &mut self,
        owner: &DurableDag,
        lease: Lease,
        launches: &LaunchStore,
        task: &TaskOwner,
    ) -> Result<Launcher, Error> {
        self.check_lease(lease)?;
        self.check_launches(launches)?;
        self.check_admission(owner, lease)?;
        let (token, image, timeout) = task.launch_binding(
            &owner.assignment(lease)?,
            &self.record.task,
            &self.record.executable,
            &self.record.launch_path,
        )?;
        if self.record.token.as_ref() != Some(&token)
            || self.record.image != image
            || self.record.timeout_seconds != timeout
        {
            return Err("dispatch task differs from durable binding".into());
        }
        let controller = os_worker::current_controller()?;
        let boot = os_worker::boot_id()?;
        let mut command = self.command(&controller)?;
        self.mark_dispatch(boot)?;
        Ok(Launcher {
            child: command.spawn()?,
        })
    }
    fn mark_dispatch(&mut self, boot: [u8; 16]) -> Result<(), Error> {
        self.log.check_current()?;
        if self.record.token.is_none()
            || self.record.dispatch_boot.is_some()
            || self.record.cancelled
        {
            return Err("dispatch forbidden/repeated".into());
        }
        let mut next = self.record.clone();
        next.dispatch_boot = Some(boot);
        self.commit(next)
    }
    fn command(&self, controller: &str) -> Result<Command, Error> {
        self.record.validate()?;
        let r = self.record.resources;
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args(["--user", "--wait", "--expand-environment=no"])
            .arg(format!("--unit={}", self.record.unit()))
            .args([
                "--slice=lattica-v2-grouped.slice",
                "--property=Type=exec",
                "--property=MemoryAccounting=yes",
                "--property=MemorySwapMax=0",
                "--property=CPUQuotaPeriodSec=100ms",
                "--property=TimeoutStopSec=15",
                "--property=KillMode=control-group",
                "--property=Restart=no",
                "--property=LimitCORE=0",
                "--property=UMask=0077",
            ])
            .arg(format!("--property=MemoryMax={}", r.ram_bytes))
            .arg(format!("--property=CPUQuota={}%", r.threads * 100))
            .arg(format!("--property=TasksMax={}", r.threads + 8))
            .arg(format!(
                "--property=RuntimeMaxSec={}",
                self.record.timeout_seconds + 30
            ))
            .arg(format!("--property=BindsTo={controller}"))
            .arg(format!("--property=After={controller}"))
            .args([
                "--setenv=LATTICA_V2_GPU_HASH=0",
                "--setenv=LATTICA_V2_GPU_PIPELINE=0",
                "--setenv=LATTICA_V2_GPU_RETAIN_TREES=0",
                "--setenv=LATTICA_V2_GPU_RESIDENT_LDE=0",
                "--setenv=LATTICA_V2_GPU_OPENINGS=0",
                "--setenv=LATTICA_V2_QUOTIENT_FUSION=0",
            ])
            .arg("--")
            .arg(&self.record.executable)
            .arg("--task")
            .arg(&self.record.task)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }
    /// Persist an exact live observation. None is deliberately not a receipt.
    pub fn observe(&mut self) -> Result<bool, Error> {
        self.log.check_current()?;
        let Some(boot) = self.record.dispatch_boot else {
            return Err("no durable dispatch to observe".into());
        };
        if boot != os_worker::boot_id()? {
            return Ok(false);
        }
        // Do not race a live worker's temporary hard-link publication window.
        // Kernel capture is authoritative independently of startup-file progress.
        if let Some(live) =
            os_worker::observe(&self.record.unit(), self.record.image, &self.record.task)?
        {
            self.record_observation(live.identity().clone())?;
            self.live = Some(live);
            return Ok(true);
        }
        if let Some(identity) = super::transport::worker_start_identity(
            &self.record.task,
            self.record
                .token
                .as_ref()
                .ok_or("dispatched worker token missing")?,
            self.record.image,
        )? {
            self.record_observation(identity)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn record_observation(&mut self, identity: Identity) -> Result<(), Error> {
        self.log.check_current()?;
        if self.record.stopped {
            return Err("worker observed after stop receipt".into());
        }
        if let Some(previous) = &self.record.observed {
            if *previous != identity {
                return Err("refuse replacement worker invocation".into());
            }
            return Ok(());
        }
        let mut next = self.record.clone();
        next.observed = Some(identity);
        self.commit(next)
    }
    fn cancel(
        &mut self,
        launches: &mut LaunchStore,
        lease: Lease,
    ) -> Result<super::launch::Revocation, Error> {
        self.check_lease(lease)?;
        self.check_launches(launches)?;
        if !self.record.cancelled {
            let mut next = self.record.clone();
            next.cancelled = true;
            self.commit(next)?;
        }
        // Capacity/IO failure preserves reservation. Cancellation alone is NOT
        // proof that the separate durable launch permit has been revoked.
        let revoked = launches.revoke(lease)?;
        if !self.record.revoked {
            let mut next = self.record.clone();
            next.revoked = true;
            self.commit(next)?;
        }
        Ok(revoked)
    }
    /// Revoke first, stop only an observed invocation, then require the lock AND
    /// OS evidence. A task-bound worker startup identity can recover a missed
    /// live observation. Without either identity, a same-boot launch stays fenced.
    pub fn reconcile(
        &mut self,
        launches: &mut LaunchStore,
        lease: Lease,
    ) -> Result<Reconciliation, Error> {
        let revoked = self.cancel(launches, lease)?;
        let boot = os_worker::boot_id()?;
        let mut basis = self.record.exit_basis(boot)?;
        if basis == ExitBasis::Unknown {
            self.observe()?;
            basis = self.record.exit_basis(boot)?;
            if basis == ExitBasis::Unknown {
                return Ok(Reconciliation::Quarantined);
            }
        }
        // A completed/GC'd service may no longer report its invocation. Exact
        // kernel exit evidence needs no successful systemctl stop response.
        if basis == ExitBasis::Observed && !self.observed_quiescent()? {
            os_worker::request_stop(self.record.observed.as_ref().unwrap(), &self.record.unit())?;
        }
        let Some(gate) = launches.try_idle(&revoked)? else {
            return Ok(Reconciliation::Pending);
        };
        if basis == ExitBasis::Observed && !self.observed_quiescent()? {
            return Ok(Reconciliation::Pending);
        }
        // Only never-dispatched, prior-boot, or exact process AND group exit.
        // No elapsed-time or missing-service fallback.
        if !self.record.stopped {
            let mut next = self.record.clone();
            next.stopped = true;
            self.commit(next)?;
        }
        Ok(Reconciliation::Stopped(StopReceipt { lease, _gate: gate }))
    }
    fn observed_quiescent(&self) -> Result<bool, Error> {
        let identity = self
            .record
            .observed
            .as_ref()
            .ok_or("missing exact worker identity")?;
        match &self.live {
            Some(live) if live.identity() == identity => live.quiescent(),
            _ => os_worker::exited(identity, &self.record.unit()),
        }
    }
}
/// Dropping kills/reaps only the owned launcher. It does not acknowledge worker
/// exit, and the persisted dispatch still requires explicit reconciliation.
pub struct Launcher {
    child: Child,
}
impl Launcher {
    pub fn poll(&mut self) -> Result<Option<ExitStatus>, Error> {
        Ok(self.child.try_wait()?)
    }
}
impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
pub enum Reconciliation {
    Pending,
    Quarantined,
    Stopped(StopReceipt),
}
#[must_use = "hold OS receipt through scheduler acknowledgement; verifier drain is separate"]
pub struct StopReceipt {
    lease: Lease,
    _gate: IdleGate,
}
impl StopReceipt {
    pub fn lease(&self) -> Lease {
        self.lease
    }
    pub fn acknowledge(self, owner: &mut DurableDag, now_ms: u64) -> Result<(), Error> {
        owner.worker_stopped(self.lease, now_ms)
    }
}
#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;

#[cfg(test)]
fn preparation_crash_boundary(stage: &str) {
    if std::env::var("LATTICA_V2_PREPARATION_CRASH_STAGE").as_deref() == Ok(stage) {
        std::process::exit(77);
    }
}
