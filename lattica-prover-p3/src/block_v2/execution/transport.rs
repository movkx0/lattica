//! Bounded, immutable local CPU task files. Research only; not a network API.
//!
//! Publication is fail-closed across process interruption. A partial task is
//! never promoted or reused. Neither a result file nor an idle owner lock is
//! evidence of OS termination. The supervisor retains reservations on errors.
//! Same-uid processes, the filesystem and kernel are trusted. Logical file
//! bounds do not implement physical quotas or a global task-retention policy.
use super::{
    artifact_store::{check_file, fd_path, open_directory, safe_file_flags},
    dag::Lease,
    job::RegistryPin,
    journal::DurableDag,
    launch::{self, LaunchStore, Token, MAX_REQUEST_BYTES, MAX_TOKEN_BYTES},
    worker::{packet, Assignment},
};
use crate::block_v2::{
    commitment,
    recursive::{Error, Registry, WrapperConstruction},
};
use p3_field::PrimeField64;
use std::{
    fs::{self, DirBuilder, File, Metadata, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
#[cfg(any(feature = "stream", test))]
use {
    super::launch::WorkerGate,
    super::os_worker::Identity,
    crate::block_v2::{machine::program::Val, profile},
    p3_field::PrimeCharacteristicRing,
};

const MAGIC: &[u8; 8] = b"LVCPUT01";
const SPEC_DOMAIN: u64 = 0x4c42563277;
const IMAGE_CHUNK_DOMAIN: u64 = 0x4c42563278;
const IMAGE_DOMAIN: u64 = 0x4c42563279;
const MAX_SPEC_BYTES: usize = 16 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_IMAGE_BYTES: u64 = 256 * (1 << 20);
const IMAGE_CHUNK_BYTES: usize = 64 * 1024;
const OWNER: &str = ".owner.lock";
const MAX_WORKER_START_BYTES: usize =
    MAX_TOKEN_BYTES + 8 + 16 + 16 + 4 + 8 + 8 + 8 + 4 + MAX_PATH_BYTES;
#[cfg(any(feature = "stream", test))]
const WORKER_START_MAGIC: &[u8; 8] = b"LVWST001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Check,
    Prove,
}

/// Externally chosen local configuration; registry identity is not key approval.
#[derive(Clone)]
pub struct WorkerConfig {
    pub registry: Registry,
    pub pin: RegistryPin,
    pub chain: [u8; 32],
    pub executable: [u8; 32],
    pub timeout_seconds: u32,
    pub mode: Mode,
}
impl WorkerConfig {
    fn validate(&self) -> Result<(), Error> {
        if self.pin.is_typed() {
            return Err("legacy CPU transport rejects typed registry".into());
        }
        RegistryPin::new(&self.registry, self.pin.profile(), self.pin.construction())?;
        commitment::digest_from_bytes(&self.executable)?;
        if !(1..=7200).contains(&self.timeout_seconds) {
            return Err("worker timeout outside research bound".into());
        }
        Ok(())
    }
}

pub(super) struct Spec {
    pub config: WorkerConfig,
    root: [u64; 2],
    pub launch_path: PathBuf,
}
pub(super) fn absolute_path(path: &Path) -> Result<&str, Error> {
    let value = path.to_str().ok_or("worker path UTF8")?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || value.len() > MAX_PATH_BYTES
        || value.bytes().any(|b| b == 0 || b.is_ascii_control())
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("worker path must be absolute and canonical".into());
    }
    Ok(value)
}
impl Spec {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.config.validate()?;
        let path = absolute_path(&self.launch_path)?.as_bytes();
        let mut out = MAGIC.to_vec();
        out.push(match self.config.mode {
            Mode::Check => 0,
            Mode::Prove => 1,
        });
        out.push(match self.config.pin.construction() {
            WrapperConstruction::SingleWallet => 1,
            WrapperConstruction::GroupedPair => 2,
        });
        out.extend(self.config.timeout_seconds.to_le_bytes());
        out.extend(self.config.executable);
        out.extend(self.config.pin.profile());
        out.extend(self.config.chain);
        for value in self.root {
            out.extend(value.to_le_bytes());
        }
        out.extend((self.config.registry.height as u32).to_le_bytes());
        // Exactly three fixed-size caps: no attacker-controlled vector lengths.
        for cap in &self.config.registry.caps {
            for digest in cap {
                for value in digest {
                    out.extend(value.as_canonical_u64().to_le_bytes());
                }
            }
        }
        out.extend((path.len() as u32).to_le_bytes());
        out.extend(path);
        if out.len() > MAX_SPEC_BYTES {
            return Err("worker spec byte bound".into());
        }
        Ok(out)
    }
    #[cfg(any(feature = "stream", test))]
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SPEC_BYTES {
            return Err("worker spec byte bound".into());
        }
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(8)? != MAGIC {
            return Err("worker spec schema".into());
        }
        let mode = match cursor.take(1)?[0] {
            0 => Mode::Check,
            1 => Mode::Prove,
            _ => return Err("worker mode".into()),
        };
        let construction = match cursor.take(1)?[0] {
            1 => WrapperConstruction::SingleWallet,
            2 => WrapperConstruction::GroupedPair,
            _ => return Err("worker construction".into()),
        };
        let timeout_seconds = cursor.u32()?;
        let executable = cursor.array()?;
        let expected_profile = cursor.array()?;
        let chain = cursor.array()?;
        let root = [cursor.u64()?, cursor.u64()?];
        let height = cursor.u32()? as usize;
        if !height.is_power_of_two() || !(8..=1 << 21).contains(&height) {
            return Err("worker registry height".into());
        }
        let mut caps = core::array::from_fn(|_| Vec::with_capacity(1 << profile::CAP_HEIGHT));
        for cap in &mut caps {
            for _ in 0..1 << profile::CAP_HEIGHT {
                let mut digest = [Val::ZERO; 4];
                for value in &mut digest {
                    let word = cursor.u64()?;
                    if word >= commitment::MODULUS {
                        return Err("worker cap canonicality".into());
                    }
                    *value = Val::from_u64(word);
                }
                cap.push(digest);
            }
        }
        let len = cursor.u32()? as usize;
        if len > MAX_PATH_BYTES {
            return Err("worker path byte bound".into());
        }
        let launch_path = PathBuf::from(std::str::from_utf8(cursor.take(len)?)?);
        absolute_path(&launch_path)?;
        if cursor.at != bytes.len() {
            return Err("worker spec trailing bytes".into());
        }
        let registry = Registry { height, caps };
        let pin = RegistryPin::new(&registry, expected_profile, construction)?;
        let config = WorkerConfig {
            registry,
            pin,
            chain,
            executable,
            timeout_seconds,
            mode,
        };
        config.validate()?;
        Ok(Self {
            config,
            root,
            launch_path,
        })
    }
    pub(super) fn digest(&self) -> Result<[u8; 32], Error> {
        launch::digest(SPEC_DOMAIN, &self.encode()?)
    }
}
#[cfg(any(feature = "stream", test))]
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
#[cfg(any(feature = "stream", test))]
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or("worker spec overflow")?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or("worker spec truncated")?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn array(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into()?)
    }
}

fn same_image(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
pub(super) fn fingerprint(mut file: File) -> Result<[u8; 32], Error> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no memory arguments or failure convention.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_IMAGE_BYTES
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || (metadata.uid() != uid && metadata.uid() != 0)
    {
        return Err("worker image type/owner/mode/size".into());
    }
    let mut buffer = vec![0; IMAGE_CHUNK_BYTES];
    let mut root = metadata.len().to_le_bytes().to_vec();
    let mut remaining = metadata.len();
    while remaining != 0 {
        let count = remaining.min(IMAGE_CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        root.extend(launch::digest(IMAGE_CHUNK_DOMAIN, &buffer[..count])?);
        remaining -= count as u64;
    }
    if file.read(&mut [0; 1])? != 0 || !same_image(&metadata, &file.metadata()?) {
        return Err("worker image changed while fingerprinting".into());
    }
    launch::digest(IMAGE_DOMAIN, &root)
}
/// Bounded local image identity, not authentication against malicious same-uid code.
pub fn image_fingerprint(path: &Path) -> Result<[u8; 32], Error> {
    absolute_path(path)?;
    fingerprint(
        OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(path)?,
    )
}
/// Fingerprint the running inode, not a potentially replaced executable pathname.
pub fn running_image_fingerprint() -> Result<[u8; 32], Error> {
    // Intentional kernel-owned proc symlink; all ordinary image paths use NOFOLLOW.
    fingerprint(File::open("/proc/self/exe")?)
}

struct Directory {
    file: File,
    path: PathBuf,
    uid: u32,
    #[cfg(test)]
    fault: Option<PublishFault>,
}
impl Directory {
    fn open(path: &Path) -> Result<Self, Error> {
        absolute_path(path)?;
        let file = open_directory(path)?;
        // SAFETY: geteuid has no memory arguments or failure convention.
        let uid = unsafe { libc::geteuid() };
        let this = Self {
            path: fd_path(&file),
            file,
            uid,
            #[cfg(test)]
            fault: None,
        };
        this.check()?;
        Ok(this)
    }
    fn check(&self) -> Result<(), Error> {
        let m = self.file.metadata()?;
        if m.uid() != self.uid || m.mode() & 0o077 != 0 || m.nlink() == 0 {
            return Err("task directory ownership changed".into());
        }
        Ok(())
    }
    fn identity(&self) -> Result<[u64; 2], Error> {
        let m = self.file.metadata()?;
        Ok([m.dev(), m.ino()])
    }
    fn inventory(&self, allow_stages: bool) -> Result<(), Error> {
        self.check()?;
        let mut count = 0;
        for entry in fs::read_dir(&self.path)? {
            count += 1;
            if count > 10 {
                return Err("task inventory bound".into());
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "task filename UTF8")?;
            if name == "scratch" {
                let m = fs::symlink_metadata(entry.path())?;
                if !m.is_dir() || m.uid() != self.uid || m.mode() & 0o077 != 0 {
                    return Err("task scratch directory".into());
                }
                continue;
            }
            let (base, stage) = match name.strip_prefix(".stage-") {
                Some(base) => (base, true),
                None => (name.as_str(), false),
            };
            let limit = match base {
                OWNER if !stage => 0,
                "spec" => MAX_SPEC_BYTES,
                "request" => MAX_REQUEST_BYTES,
                "token" => MAX_TOKEN_BYTES,
                "result" => packet::MAX_RESULT_BYTES,
                "worker-start" => MAX_WORKER_START_BYTES,
                _ => return Err("unrecognized task entry".into()),
            };
            if stage && !allow_stages {
                return Err("partial task publication".into());
            }
            let m = fs::symlink_metadata(entry.path())?;
            check_file(&m, self.uid, allow_stages)?;
            if m.len() > limit as u64 {
                return Err("task entry byte bound".into());
            }
        }
        Ok(())
    }
    fn read(&self, name: &str, bound: usize) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(self.path.join(name))?;
        let m = file.metadata()?;
        check_file(&m, self.uid, false)?;
        if m.mode() & 0o777 != 0o400 || m.len() == 0 || m.len() > bound as u64 {
            return Err("task payload mode/size".into());
        }
        let mut bytes = Vec::with_capacity(m.len() as usize);
        (&mut file).take(bound as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() != m.len() as usize || !same_image(&m, &file.metadata()?) {
            return Err("task payload changed during read".into());
        }
        Ok(bytes)
    }
    fn publish(&self, name: &str, bytes: &[u8], bound: usize) -> Result<(), Error> {
        self.check()?;
        if bytes.is_empty() || bytes.len() > bound {
            return Err("task publication byte bound".into());
        }
        let stage = self.path.join(format!(".stage-{name}"));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(safe_file_flags())
            .open(&stage)?;
        #[cfg(test)]
        self.inject(PublishFault::StageCreated);
        f.write_all(bytes)?;
        f.set_permissions(Permissions::from_mode(0o400))?;
        f.sync_all()?;
        #[cfg(test)]
        self.inject(PublishFault::StageDurable);
        // hard_link fails if the destination already exists; never overwrite.
        fs::hard_link(&stage, self.path.join(name))?;
        #[cfg(test)]
        self.inject(PublishFault::Linked);
        self.file.sync_all()?;
        #[cfg(test)]
        self.inject(PublishFault::Published);
        fs::remove_file(stage)?;
        #[cfg(test)]
        self.inject(PublishFault::StageRemoved);
        self.file.sync_all()?;
        #[cfg(test)]
        self.inject(PublishFault::Complete);
        Ok(())
    }
}

/// Exclusive coordinator handle. Reopening permits inspection, not task reuse.
pub struct TaskOwner {
    directory: Directory,
    lock: File,
}
impl TaskOwner {
    #[cfg(feature = "stream")]
    pub(super) fn launch_binding(
        &self,
        assignment: &Assignment,
        task_path: &Path,
        image_path: &Path,
        launch_path: &Path,
    ) -> Result<(Token, [u8; 32], u32), Error> {
        self.check()?;
        absolute_path(image_path)?;
        let loaded = WorkerTask::open(task_path)?;
        if loaded.directory.identity()? != self.directory.identity()?
            || loaded.spec.launch_path != launch_path
            || loaded.request != packet::encode_request(assignment)?
            || loaded.token.key() != assignment.lease().process_key()?
            || loaded.token.resources() != assignment.resources()
            || loaded.spec.config.pin != assignment.job().pin()
            || loaded.spec.config.chain != assignment.job().expected().context.chain_id
            || image_fingerprint(image_path)? != loaded.spec.config.executable
        {
            return Err("supervised task/assignment/image binding".into());
        }
        Ok((
            loaded.token,
            loaded.spec.config.executable,
            loaded.spec.config.timeout_seconds,
        ))
    }
    pub fn create(path: &Path) -> Result<Self, Error> {
        absolute_path(path)?;
        DirBuilder::new().mode(0o700).create(path)?;
        let directory = Directory::open(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(safe_file_flags())
            .open(directory.path.join(OWNER))?;
        lock.try_lock()
            .map_err(|e| format!("task owner lock: {e}"))?;
        lock.sync_all()?;
        DirBuilder::new()
            .mode(0o700)
            .create(directory.path.join("scratch"))?;
        open_directory(&directory.path.join("scratch"))?.sync_all()?;
        directory.file.sync_all()?;
        open_directory(path.parent().ok_or("task parent")?)?.sync_all()?;
        Ok(Self { directory, lock })
    }
    pub fn open(path: &Path) -> Result<Self, Error> {
        let directory = Directory::open(path)?;
        directory.inventory(true)?;
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(directory.path.join(OWNER))?;
        check_file(&lock.metadata()?, directory.uid, false)?;
        if lock.metadata()?.len() != 0 {
            return Err("task lock payload".into());
        }
        lock.try_lock()
            .map_err(|e| format!("task owner already active: {e}"))?;
        let owner = Self { directory, lock };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> Result<(), Error> {
        self.directory.check()?;
        let a = self.lock.metadata()?;
        let b = fs::symlink_metadata(self.directory.path.join(OWNER))?;
        check_file(&b, self.directory.uid, false)?;
        if a.dev() != b.dev() || a.ino() != b.ino() || b.len() != 0 {
            return Err("task owner lock replaced".into());
        }
        Ok(())
    }
    /// Spec and request become durable before launch permission; token is last.
    /// Any error after issuance requires revocation/OS reconciliation, not retry.
    pub fn issue(
        &mut self,
        owner: &mut DurableDag,
        launches: &mut LaunchStore,
        launch_path: &Path,
        lease: Lease,
        config: WorkerConfig,
    ) -> Result<Token, Error> {
        self.issue_inner(owner, launches, launch_path, lease, config, None)
    }
    #[cfg(feature = "stream")]
    pub(super) fn issue_reserved(
        &mut self,
        owner: &mut DurableDag,
        launches: &mut LaunchStore,
        launch_path: &Path,
        lease: Lease,
        config: WorkerConfig,
        admission: [u8; 32],
    ) -> Result<Token, Error> {
        self.issue_inner(owner, launches, launch_path, lease, config, Some(admission))
    }
    fn issue_inner(
        &mut self,
        owner: &mut DurableDag,
        launches: &mut LaunchStore,
        launch_path: &Path,
        lease: Lease,
        config: WorkerConfig,
        admission: Option<[u8; 32]>,
    ) -> Result<Token, Error> {
        self.check()?;
        self.directory.inventory(false)?;
        if fs::read_dir(&self.directory.path)?.count() != 2 {
            return Err("task directory already used".into());
        }
        launches.check_directory(launch_path)?;
        let assignment = owner.assignment(lease)?;
        if assignment.job().pin() != config.pin
            || assignment.job().expected().context.chain_id != config.chain
        {
            return Err("task configuration does not match assignment".into());
        }
        let request = packet::encode_request(&assignment)?;
        let spec = Spec {
            config,
            root: self.directory.identity()?,
            launch_path: launch_path.to_owned(),
        };
        let bytes = spec.encode()?;
        let digest = spec.digest()?;
        self.directory.publish("spec", &bytes, MAX_SPEC_BYTES)?;
        self.directory
            .publish("request", &request, MAX_REQUEST_BYTES)?;
        let token = match admission {
            Some(path) => launches.issue_reserved(owner, lease, &request, digest, path)?,
            None => launches.issue_bound(owner, lease, &request, digest)?,
        };
        self.directory
            .publish("token", &token.encode()?, MAX_TOKEN_BYTES)?;
        Ok(token)
    }
    /// Decode only. The owner must independently verify and journal the current
    /// attempt. This call never acknowledges process exit or releases resources.
    pub fn result(&self, assignment: &Assignment) -> Result<packet::UnverifiedResult, Error> {
        self.check()?;
        self.directory.inventory(false)?;
        let original = packet::encode_request(assignment)?;
        if self.directory.read("request", MAX_REQUEST_BYTES)? != original {
            return Err("task request differs from original assignment".into());
        }
        packet::decode_result(
            assignment,
            &original,
            &self.directory.read("result", packet::MAX_RESULT_BYTES)?,
        )
    }
}

#[cfg(any(feature = "stream", test))]
pub(super) struct WorkerTask {
    directory: Directory,
    pub spec: Spec,
    pub token: Token,
    pub request: Vec<u8>,
    pub scratch: File,
}
#[cfg(any(feature = "stream", test))]
impl WorkerTask {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let directory = Directory::open(path)?;
        directory.inventory(false)?;
        let spec = Spec::decode(&directory.read("spec", MAX_SPEC_BYTES)?)?;
        let token = Token::decode(&directory.read("token", MAX_TOKEN_BYTES)?)?;
        token.check_execution(spec.digest()?)?;
        if spec.root != directory.identity()? {
            return Err("task directory identity".into());
        }
        let request = directory.read("request", MAX_REQUEST_BYTES)?;
        token.check_request(&request)?;
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(directory.path.join(OWNER))?;
        check_file(&lock.metadata()?, directory.uid, false)?;
        if lock.metadata()?.len() != 0 {
            return Err("task owner lock payload".into());
        }
        match fs::symlink_metadata(directory.path.join("result")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => return Err("task result already exists".into()),
        }
        let scratch = open_directory(&directory.path.join("scratch"))?;
        let m = scratch.metadata()?;
        if m.uid() != directory.uid || m.mode() & 0o077 != 0 || m.nlink() == 0 {
            return Err("task scratch permissions".into());
        }
        if fs::read_dir(fd_path(&scratch))?.next().is_some() {
            return Err("task scratch not empty".into());
        }
        Ok(Self {
            directory,
            spec,
            token,
            request,
            scratch,
        })
    }
    pub fn publish_result(&self, guard: &WorkerGate, bytes: &[u8]) -> Result<(), Error> {
        if guard.token() != &self.token || self.spec.config.mode != Mode::Prove {
            return Err("task result guard/mode".into());
        }
        self.directory.inventory(false)?;
        self.directory
            .publish("result", bytes, packet::MAX_RESULT_BYTES)
    }

    /// Persist exact process birth before entering the proving gate. This record
    /// is identity evidence only: recovery must still prove kernel/cgroup exit.
    pub(super) fn publish_worker_start(&self, identity: &Identity) -> Result<(), Error> {
        self.directory.inventory(false)?;
        self.directory.publish(
            "worker-start",
            &encode_worker_start(&self.token, identity)?,
            MAX_WORKER_START_BYTES,
        )
    }
}

#[cfg(any(feature = "stream", test))]
fn encode_worker_start(token: &Token, identity: &Identity) -> Result<Vec<u8>, Error> {
    identity.validate(&token.service_name())?;
    let token = token.encode()?;
    if token.len() != MAX_TOKEN_BYTES || identity.group.len() > MAX_PATH_BYTES {
        return Err("worker start requires execution-bound token and bounded group".into());
    }
    let mut bytes = WORKER_START_MAGIC.to_vec();
    bytes.extend(token);
    bytes.extend(identity.boot);
    bytes.extend(identity.invocation);
    bytes.extend(identity.pid.to_le_bytes());
    bytes.extend(identity.start_ticks.to_le_bytes());
    bytes.extend(identity.device.to_le_bytes());
    bytes.extend(identity.inode.to_le_bytes());
    bytes.extend((identity.group.len() as u32).to_le_bytes());
    bytes.extend(identity.group.as_bytes());
    Ok(bytes)
}

#[cfg(any(feature = "stream", test))]
fn decode_worker_start(bytes: &[u8], token: &Token) -> Result<Identity, Error> {
    if bytes.len() > MAX_WORKER_START_BYTES {
        return Err("worker start byte bound".into());
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(8)? != WORKER_START_MAGIC || Token::decode(c.take(MAX_TOKEN_BYTES)?)? != *token {
        return Err("worker start schema/token binding".into());
    }
    let boot = c.take(16)?.try_into()?;
    let invocation = c.take(16)?.try_into()?;
    let pid = c.u32()?;
    let start_ticks = c.u64()?;
    let device = c.u64()?;
    let inode = c.u64()?;
    let len = c.u32()? as usize;
    if len > MAX_PATH_BYTES {
        return Err("worker start group bound".into());
    }
    let group = std::str::from_utf8(c.take(len)?)?.to_owned();
    if c.at != bytes.len() {
        return Err("worker start trailing bytes".into());
    }
    let identity = Identity {
        boot,
        invocation,
        pid,
        start_ticks,
        group,
        device,
        inode,
    };
    identity.validate(&token.service_name())?;
    Ok(identity)
}

/// Missing evidence is only None, never an OS-stop acknowledgement. Read the
/// identity independently of result/scratch publication, which may be interrupted.
#[cfg(feature = "stream")]
pub(super) fn worker_start_identity(
    path: &Path,
    token: &Token,
    image: [u8; 32],
) -> Result<Option<Identity>, Error> {
    let directory = match Directory::open(path) {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let bytes = match directory.read("worker-start", MAX_WORKER_START_BYTES) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let spec = Spec::decode(&directory.read("spec", MAX_SPEC_BYTES)?)?;
    token.check_execution(spec.digest()?)?;
    if spec.root != directory.identity()?
        || spec.config.executable != image
        || Token::decode(&directory.read("token", MAX_TOKEN_BYTES)?)? != *token
    {
        return Err("worker start task/image substitution".into());
    }
    Ok(Some(decode_worker_start(&bytes, token)?))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublishFault {
    StageCreated,
    StageDurable,
    Linked,
    Published,
    StageRemoved,
    Complete,
}
#[cfg(test)]
impl Directory {
    fn inject(&self, stage: PublishFault) {
        if self.fault == Some(stage) {
            std::process::exit(77);
        }
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
