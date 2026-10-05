//! Linux durable CPU-worker launch fencing. Research only.
//!
//! A permit is published only after its lock and immutable intent are durable.
//! Revocation is irreversible and durable before the permit is removed. A late
//! process must acquire the worker lock and recheck revocation before proving.
//! Entry consumes a durable, single-use marker before any work starts. An
//! interrupted entry requires a fresh lease, never replay of the old permit.
//! This is a launch gate, NOT a process supervisor or evidence that an OS process
//! has exited. A runtime must additionally stop/query its exact service/cgroup,
//! drain verification, and enforce the reservation before acknowledging stop.
use super::{
    artifact_store::{check_file, fd_path, hex, open_directory, safe_file_flags},
    dag::{LaunchBinding, Lease},
    journal::DurableDag,
    resources::Resources,
};
use crate::block_v2::{commitment, recursive::Error};
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions, TryLockError},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"LVCPU001";
const BOUND_MAGIC: &[u8; 8] = b"LVCPU002";
const BODY: usize = 116;
const TOKEN_BYTES: usize = BODY + 32;
pub(super) const MAX_TOKEN_BYTES: usize = TOKEN_BYTES + 32;
const OWNER: &str = ".owner.lock";
const INTENT_DOMAIN: u64 = 0x4c42563275;
const REQUEST_DOMAIN: u64 = 0x4c42563276;
pub const MAX_REQUEST_BYTES: usize = 4 * (1 << 20) + 65536;

pub(super) fn digest(domain: u64, bytes: &[u8]) -> Result<[u8; 32], Error> {
    let mut fields = vec![1, bytes.len() as u64];
    for part in bytes.chunks(4) {
        let mut word = [0; 4];
        word[..part.len()].copy_from_slice(part);
        fields.push(u64::from(u32::from_le_bytes(word)));
    }
    Ok(commitment::digest_bytes(commitment::hash_fields(
        domain, &fields,
    )?)?)
}
pub(super) fn request_digest(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("launch request byte bound".into());
    }
    digest(REQUEST_DOMAIN, bytes)
}

/// Local process metadata, not proof authority or a network/consensus encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    key: [u8; 32],
    root: [u64; 2],
    resources: Resources,
    request: [u8; 32],
    execution: Option<[u8; 32]>,
}
impl Token {
    /// Bind an opaque local packet. This does not decode or verify its proofs.
    pub(super) fn check_request(&self, bytes: &[u8]) -> Result<(), Error> {
        self.validate()?;
        if request_digest(bytes)? != self.request {
            return Err("launch request substitution".into());
        }
        Ok(())
    }
    pub fn key(&self) -> [u8; 32] {
        self.key
    }
    pub fn resources(&self) -> Resources {
        self.resources
    }

    #[cfg(feature = "stream")]
    pub(super) fn require_inline(&self) -> Result<(), Error> {
        self.validate()?;
        if self.execution.is_some() {
            return Err("inline cached worker rejects process-bound launch tokens".into());
        }
        Ok(())
    }
    /// Autonomous workers require a bound execution specification. Legacy V1
    /// tokens remain usable only by the existing explicitly guarded inline API.
    pub fn check_execution(&self, digest: [u8; 32]) -> Result<(), Error> {
        self.validate()?;
        if self.execution != Some(digest) {
            return Err("launch execution specification missing or substituted".into());
        }
        Ok(())
    }
    pub fn service_name(&self) -> String {
        format!("lattica-v2-worker-{}.service", hex(&self.key))
    }
    fn validate(&self) -> Result<(), Error> {
        commitment::digest_from_bytes(&self.key)?;
        commitment::digest_from_bytes(&self.request)?;
        if let Some(execution) = self.execution {
            commitment::digest_from_bytes(&execution)?;
        }
        self.resources.validate_capacity()?;
        if self.resources.vram_bytes != 0 {
            return Err("CPU launch reservation has VRAM".into());
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = if self.execution.is_some() {
            BOUND_MAGIC
        } else {
            MAGIC
        }
        .to_vec();
        bytes.extend(self.key);
        for value in self.root {
            bytes.extend(value.to_le_bytes());
        }
        for value in [
            self.resources.ram_bytes,
            self.resources.vram_bytes,
            self.resources.scratch_bytes,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(self.resources.threads.to_le_bytes());
        bytes.extend(self.request);
        if let Some(execution) = self.execution {
            bytes.extend(execution);
        }
        bytes.extend(digest(INTENT_DOMAIN, &bytes)?);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let body = match (bytes.get(..8), bytes.len()) {
            (Some(magic), TOKEN_BYTES) if magic == MAGIC => BODY,
            (Some(magic), MAX_TOKEN_BYTES) if magic == BOUND_MAGIC => BODY + 32,
            _ => return Err("launch token schema/size".into()),
        };
        if bytes[body..] != digest(INTENT_DOMAIN, &bytes[..body])? {
            return Err("launch token schema/size/checksum".into());
        }
        let u64_at = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let token = Self {
            key: bytes[8..40].try_into()?,
            root: [u64_at(40), u64_at(48)],
            resources: Resources {
                ram_bytes: u64_at(56),
                vram_bytes: u64_at(64),
                scratch_bytes: u64_at(72),
                threads: u32::from_le_bytes(bytes[80..84].try_into()?),
            },
            request: bytes[84..116].try_into()?,
            execution: if body == BODY {
                None
            } else {
                Some(bytes[BODY..body].try_into()?)
            },
        };
        token.validate()?;
        Ok(token)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LaunchLimits {
    pub records: usize,
}
impl LaunchLimits {
    fn validate(self) -> Result<(), Error> {
        if !(1..=16384).contains(&self.records) {
            Err("launch record bound".into())
        } else {
            Ok(())
        }
    }
}

struct Directory {
    file: File,
    path: PathBuf,
    uid: u32,
}
impl Directory {
    fn open(path: &Path) -> Result<Self, Error> {
        let file = open_directory(path)?;
        // SAFETY: geteuid has no arguments, memory access or failure convention.
        let uid = unsafe { libc::geteuid() };
        let directory = Self {
            path: fd_path(&file),
            file,
            uid,
        };
        directory.check()?;
        Ok(directory)
    }
    fn check(&self) -> Result<(), Error> {
        let m = self.file.metadata()?;
        if m.uid() != self.uid || m.mode() & 0o077 != 0 || m.nlink() == 0 {
            return Err("launch directory ownership changed".into());
        }
        Ok(())
    }
    fn identity(&self) -> Result<[u64; 2], Error> {
        let m = self.file.metadata()?;
        Ok([m.dev(), m.ino()])
    }
    fn open_file(&self, name: &str) -> Result<File, Error> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(self.path.join(name))?;
        check_file(&f.metadata()?, self.uid, false)?;
        Ok(f)
    }
    fn create_file(&self, name: &str, bytes: &[u8]) -> Result<File, Error> {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(safe_file_flags())
            .open(self.path.join(name))?;
        f.write_all(bytes)?;
        Ok(f)
    }
    fn empty(&self, name: &str) -> Result<File, Error> {
        let f = self.open_file(name)?;
        if f.metadata()?.len() != 0 {
            return Err("launch marker is not empty".into());
        }
        Ok(f)
    }
    fn absent(&self, name: &str) -> Result<bool, Error> {
        match fs::symlink_metadata(self.path.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e.into()),
            Ok(_) => Ok(false),
        }
    }
    fn same_file(&self, name: &str, held: &File) -> Result<(), Error> {
        let a = held.metadata()?;
        let b = fs::symlink_metadata(self.path.join(name))?;
        check_file(&b, self.uid, false)?;
        if a.dev() != b.dev() || a.ino() != b.ino() || a.len() != b.len() {
            return Err("launch lock replaced".into());
        }
        Ok(())
    }
}
fn name(key: [u8; 32], suffix: &str) -> String {
    format!("{}.{}", hex(&key), suffix)
}
fn parse_name(value: &str) -> Result<([u8; 32], &str), Error> {
    let (key, suffix) = value.split_once('.').ok_or("launch filename")?;
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !matches!(
            suffix,
            "worker" | "intent" | "permit" | "revoked" | "started" | "reserved"
        )
    {
        return Err("launch filename".into());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key[2 * i..2 * i + 2], 16)?;
    }
    commitment::digest_from_bytes(&bytes)?;
    Ok((bytes, suffix))
}

/// Single-owner launch inventory. Records/tombstones are preserved, never reused
/// or automatically removed. A later supervisor must add reference-aware pruning.
pub struct LaunchStore {
    directory: Directory,
    owner: File,
    limits: LaunchLimits,
    records: BTreeMap<[u8; 32], u8>,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
    #[cfg(test)]
    crash: bool,
}
impl LaunchStore {
    pub fn create(path: &Path, limits: LaunchLimits) -> Result<Self, Error> {
        limits.validate()?;
        if !path.is_absolute() || path.file_name().is_none() {
            return Err("launch store requires absolute named directory".into());
        }
        let parent = open_directory(path.parent().ok_or("launch parent")?)?;
        let target = fd_path(&parent).join(path.file_name().unwrap());
        DirBuilder::new().mode(0o700).create(&target)?;
        parent.sync_all()?;
        Self::open(&target, limits)
    }
    pub fn open(path: &Path, limits: LaunchLimits) -> Result<Self, Error> {
        limits.validate()?;
        let directory = Directory::open(path)?;
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(safe_file_flags())
            .open(directory.path.join(OWNER))?;
        check_file(&owner.metadata()?, directory.uid, false)?;
        if owner.metadata()?.len() != 0 {
            return Err("launch owner lock is not empty".into());
        }
        owner
            .try_lock()
            .map_err(|e| format!("launch store already owned: {e}"))?;
        directory.file.sync_all()?;
        let mut store = Self {
            directory,
            owner,
            limits,
            records: BTreeMap::new(),
            poisoned: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            crash: false,
        };
        store.refresh()?;
        Ok(store)
    }
    fn live(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err("launch store poisoned; recovery required".into());
        }
        self.directory.check()?;
        self.directory.same_file(OWNER, &self.owner)
    }
    fn refresh(&mut self) -> Result<(), Error> {
        self.live()?;
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(&self.directory.path)? {
            let entry = entry?;
            let value = entry
                .file_name()
                .into_string()
                .map_err(|_| "launch non-UTF8 filename")?;
            if value == OWNER {
                continue;
            }
            let (key, suffix) = parse_name(&value)?;
            let m = fs::symlink_metadata(self.directory.path.join(&value))?;
            check_file(&m, self.directory.uid, false)?;
            if (suffix == "intent" && m.len() > MAX_TOKEN_BYTES as u64)
                || (suffix != "intent" && m.len() != 0)
            {
                return Err("launch file bound".into());
            }
            *records.entry(key).or_insert(0) |= match suffix {
                "worker" => 1,
                "intent" => 2,
                "permit" => 4,
                "revoked" => 8,
                "started" => 16,
                _ => 32,
            };
            if records.len() > self.limits.records {
                return Err("launch inventory record bound".into());
            }
        }
        self.records = records;
        Ok(())
    }
    pub fn record_count(&self) -> Result<usize, Error> {
        self.live()?;
        Ok(self.records.len())
    }

    pub(super) fn check_directory(&self, path: &Path) -> Result<(), Error> {
        self.live()?;
        if Directory::open(path)?.identity()? != self.directory.identity()? {
            return Err("launch path does not name the owned store".into());
        }
        Ok(())
    }

    #[cfg(feature = "stream")]
    pub(super) fn check_reservation(&self, key: [u8; 32]) -> Result<(), Error> {
        self.live()?;
        self.directory.empty(&name(key, "worker"))?;
        self.directory.empty(&name(key, "reserved"))?;
        Ok(())
    }

    #[cfg(feature = "stream")]
    pub(super) fn directory_identity(&self) -> Result<[u64; 2], Error> {
        self.live()?;
        self.directory.identity()
    }

    /// Persist one current durable lease's permission, once. An uncertain error
    /// requires reopen/revoke, not a second issuance or a reused service name.
    /// Request bytes are only hashed here; transport/storage remain runtime work.
    pub fn issue(
        &mut self,
        owner: &mut DurableDag,
        lease: Lease,
        request: &[u8],
    ) -> Result<Token, Error> {
        self.issue_inner(owner, lease, request, None, LaunchBinding::Direct)
    }

    /// Bind executable/configuration identity in addition to the exact packet.
    /// A failure may have published partial records; retain the reservation and
    /// reconcile/revoke the lease before retrying under a fresh attempt.
    pub fn issue_bound(
        &mut self,
        owner: &mut DurableDag,
        lease: Lease,
        request: &[u8],
        execution: [u8; 32],
    ) -> Result<Token, Error> {
        self.issue_inner(
            owner,
            lease,
            request,
            Some(execution),
            LaunchBinding::Direct,
        )
    }

    /// Reserve a registry key while durable DAG state still forbids all worker
    /// execution. A filesystem error poisons both owners until recovery.
    fn reserve_slot(&mut self, owner: &mut DurableDag, lease: Lease) -> Result<(), Error> {
        self.refresh()?;
        owner.check_new_launch(lease, self.directory.identity()?)?;
        let key = lease.process_key()?;
        if self.records.contains_key(&key) {
            return Err("launch admission already reserved/issued".into());
        }
        if self.records.len() >= self.limits.records {
            return Err("launch record admission".into());
        }
        let result = (|| -> Result<(), Error> {
            #[cfg(test)]
            self.inject(Fault::ReservationStarted)?;
            self.directory
                .create_file(&name(key, "worker"), &[])?
                .sync_all()?;
            self.directory.file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::ReservationWorkerDurable)?;
            self.directory
                .create_file(&name(key, "reserved"), &[])?
                .sync_all()?;
            self.directory.file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::ReservationDurable)?;
            self.refresh()
        })();
        if result.is_err() {
            self.poisoned = true;
            owner.poison_launch_admission();
        }
        result
    }

    #[cfg(any(feature = "stream", test))]
    pub(super) fn reserve_supervisor(
        &mut self,
        owner: &mut DurableDag,
        lease: Lease,
        path: [u8; 32],
    ) -> Result<(), Error> {
        LaunchBinding::Preparing(path).validate()?;
        self.reserve_slot(owner, lease)?;
        let result = (|| -> Result<(), Error> {
            owner.bind_launch(
                lease,
                self.directory.identity()?,
                LaunchBinding::Preparing(path),
            )?;
            #[cfg(test)]
            self.inject(Fault::ReservationAdmissionDurable)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            owner.poison_launch_admission();
        }
        result
    }

    pub(super) fn issue_reserved(
        &mut self,
        owner: &mut DurableDag,
        lease: Lease,
        request: &[u8],
        execution: [u8; 32],
        path: [u8; 32],
    ) -> Result<Token, Error> {
        let binding = owner.authorized_supervisor(lease, self.directory.identity()?, path)?;
        self.issue_inner(owner, lease, request, Some(execution), binding)
    }

    /// Recover a V3 attempt which durably never obtained execution permission.
    /// This is not an OS stop receipt and cannot drain an active CPU verifier.
    /// Historical/unobserved authorized attempts never use this shortcut.
    pub fn reconcile_preparation(
        &mut self,
        attempt: &super::journal::PreviousAttempt,
    ) -> Result<PreparationReceipt, Error> {
        self.refresh()?;
        if attempt.verification_active {
            return Err("preparation has active verifier; drain separately".into());
        }
        let pending = match attempt.launch_binding {
            Some(LaunchBinding::Unissued) => false,
            Some(LaunchBinding::Preparing(_)) => true,
            _ => return Err("attempt may have issued execution permission".into()),
        };
        let root = attempt
            .launch_root
            .ok_or("preparation has no pinned journal")?;
        root.validate()?;
        if root.store == [0; 2] {
            if pending {
                return Err("prepared admission has no assigned store".into());
            }
        } else if root.store != self.directory.identity()? {
            return Err("preparation belongs to another launch store".into());
        }
        let key = attempt.lease.process_key()?;
        let prior = self.records.get(&key).copied().unwrap_or(0);
        if prior == 0 {
            if pending {
                return Err("durably reserved launch key is missing".into());
            }
            return Ok(PreparationReceipt {
                lease: attempt.lease,
                _gate: None,
            });
        }
        if prior & !(1 | 8 | 32) != 0 || prior & 1 == 0 {
            return Err("unissued admission contains unexpected launch records".into());
        }
        let revoked = self.revoke(attempt.lease)?;
        let gate = self
            .try_idle(&revoked)?
            .ok_or("preparation gate is still active")?;
        Ok(PreparationReceipt {
            lease: attempt.lease,
            _gate: Some(gate),
        })
    }

    fn issue_inner(
        &mut self,
        owner: &mut DurableDag,
        lease: Lease,
        request: &[u8],
        execution: Option<[u8; 32]>,
        binding: LaunchBinding,
    ) -> Result<Token, Error> {
        self.refresh()?;
        let assignment = owner.assignment(lease)?;
        let token = Token {
            key: lease.process_key()?,
            root: self.directory.identity()?,
            resources: assignment.resources(),
            request: request_digest(request)?,
            execution,
        };
        token.validate()?;
        if binding == LaunchBinding::Direct {
            self.reserve_slot(owner, lease)?;
        } else if self.records.get(&token.key).copied() != Some(1 | 32) {
            return Err("launch lease not fresh or reservation missing".into());
        }
        let result = (|| -> Result<(), Error> {
            owner.bind_launch(lease, self.directory.identity()?, binding)?;
            self.publish_inner(&token, true)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            owner.poison_launch_admission();
        }
        result?;
        Ok(token)
    }

    // All production callers first obtain a current, durably committed assignment.
    // Kept separate so subprocess tests can interrupt exact filesystem boundaries.
    #[cfg(test)]
    fn publish(&mut self, token: &Token) -> Result<(), Error> {
        self.publish_inner(token, false)
    }

    fn publish_inner(&mut self, token: &Token, reserved: bool) -> Result<(), Error> {
        self.refresh()?;
        token.validate()?;
        if token.root != self.directory.identity()? {
            return Err("launch token belongs to another store".into());
        }
        let prior = self.records.get(&token.key).copied().unwrap_or(0);
        if (reserved && prior != (1 | 32)) || (!reserved && prior != 0) {
            return Err("launch lease not fresh or reservation missing".into());
        }
        if prior == 0 && self.records.len() >= self.limits.records {
            return Err("launch record admission".into());
        }
        let bytes = token.encode()?;
        let result = (|| -> Result<(), Error> {
            if !reserved {
                self.directory
                    .create_file(&name(token.key, "worker"), &[])?
                    .sync_all()?;
                self.directory.file.sync_all()?;
            } else {
                self.directory.empty(&name(token.key, "worker"))?;
                self.directory.empty(&name(token.key, "reserved"))?;
            }
            #[cfg(test)]
            self.inject(Fault::WorkerLockDurable)?;
            self.directory
                .create_file(&name(token.key, "intent"), &bytes)?
                .sync_all()?;
            self.directory.file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::IntentDurable)?;
            self.directory
                .create_file(&name(token.key, "permit"), &[])?
                .sync_all()?;
            #[cfg(test)]
            self.inject(Fault::PermitBeforeDirectorySync)?;
            self.directory.file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::PermitDurable)?;
            self.refresh()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Irreversibly fence this lease before stopping/querying its exact OS unit.
    /// Also records a tombstone if no launch was issued before a coordinator crash.
    pub fn revoke(&mut self, lease: Lease) -> Result<Revocation, Error> {
        self.revoke_key(lease.process_key()?)?;
        Ok(Revocation {
            lease,
            root: self.directory.identity()?,
        })
    }

    fn revoke_key(&mut self, key: [u8; 32]) -> Result<(), Error> {
        self.refresh()?;
        commitment::digest_from_bytes(&key)?;
        let prior = self.records.get(&key).copied().unwrap_or(0);
        if prior == 0 && self.records.len() >= self.limits.records {
            return Err("launch revocation record admission".into());
        }
        let result = (|| -> Result<(), Error> {
            if prior & 1 == 0 {
                if prior & (2 | 4 | 16) != 0 {
                    return Err("launch worker lock missing from issued record".into());
                }
                self.directory
                    .create_file(&name(key, "worker"), &[])?
                    .sync_all()?;
                self.directory.file.sync_all()?;
            }
            let marker = name(key, "revoked");
            let file = if self.directory.absent(&marker)? {
                self.directory.create_file(&marker, &[])?
            } else {
                self.directory.empty(&marker)?
            };
            #[cfg(test)]
            self.inject(Fault::RevocationCreated)?;
            file.sync_all()?;
            self.directory.file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::RevocationDurable)?;
            let permit = name(key, "permit");
            if !self.directory.absent(&permit)? {
                self.directory.empty(&permit)?;
                fs::remove_file(self.directory.path.join(permit))?;
            }
            #[cfg(test)]
            self.inject(Fault::PermitRemoved)?;
            self.directory.file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::RevocationComplete)?;
            self.refresh()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// An idle gate is NOT an OS-process-stop acknowledgement. Hold it while the
    /// runtime confirms its unit/cgroup and verification work are stopped. The
    /// durable tombstone continues fencing late starts after this guard is dropped.
    pub fn try_idle(&self, revoked: &Revocation) -> Result<Option<IdleGate>, Error> {
        self.live()?;
        if revoked.root != self.directory.identity()? {
            return Err("revocation belongs to another launch store".into());
        }
        let key = revoked.lease.process_key()?;
        self.directory.empty(&name(key, "revoked"))?;
        if !self.directory.absent(&name(key, "permit"))? {
            return Err("revocation not fully persisted".into());
        }
        let worker = self.directory.empty(&name(key, "worker"))?;
        match worker.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        self.directory.same_file(&name(key, "worker"), &worker)?;
        Ok(Some(IdleGate {
            _worker: worker,
            _directory: self.directory.file.try_clone()?,
        }))
    }
}

pub struct Revocation {
    lease: Lease,
    root: [u64; 2],
}
impl Revocation {
    pub fn lease(&self) -> Lease {
        self.lease
    }
}
#[must_use = "hold the idle gate while confirming process and verifier quiescence"]
pub struct IdleGate {
    _worker: File,
    _directory: File,
}

/// Keep alive throughout all proving work, cleanup and process exit. The worker
/// must not spawn detached descendants that outlive this lock's ownership.
#[must_use = "keep the launch guard alive throughout worker execution"]
pub struct WorkerGate {
    _worker: File,
    _directory: File,
    token: Token,
}
impl WorkerGate {
    pub fn enter(path: &Path, token: &Token, request: &[u8]) -> Result<Self, Error> {
        #[cfg(test)]
        {
            Self::enter_inner(path, token, request, None)
        }
        #[cfg(not(test))]
        {
            Self::enter_inner(path, token, request)
        }
    }
    fn enter_inner(
        path: &Path,
        token: &Token,
        request: &[u8],
        #[cfg(test)] fault: Option<EntryFault>,
    ) -> Result<Self, Error> {
        token.validate()?;
        let directory = Directory::open(path)?;
        if directory.identity()? != token.root {
            return Err("launch directory identity".into());
        }
        let worker = directory.empty(&name(token.key, "worker"))?;
        worker
            .try_lock()
            .map_err(|e| format!("launch worker already active: {e}"))?;
        directory.same_file(&name(token.key, "worker"), &worker)?;
        if !directory.absent(&name(token.key, "started"))? {
            return Err("launch lease already consumed".into());
        }
        if !directory.absent(&name(token.key, "revoked"))? {
            return Err("launch lease revoked".into());
        }
        directory.empty(&name(token.key, "permit"))?;
        let file = directory.open_file(&name(token.key, "intent"))?;
        if file.metadata()?.len() != token.encode()?.len() as u64 {
            return Err("launch intent size".into());
        }
        let mut bytes = Vec::with_capacity(MAX_TOKEN_BYTES);
        file.take(MAX_TOKEN_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if Token::decode(&bytes)? != *token || request_digest(request)? != token.request {
            return Err("launch intent/request binding".into());
        }
        // Exclusive creation under the worker lock makes entry at-most-once.
        // A failed/uncertain sync is never permission to retry this lease.
        let started = directory.create_file(&name(token.key, "started"), &[])?;
        #[cfg(test)]
        if fault == Some(EntryFault::StartedCreated) {
            std::process::exit(77);
        }
        started.sync_all()?;
        directory.file.sync_all()?;
        #[cfg(test)]
        if fault == Some(EntryFault::StartedDurable) {
            std::process::exit(77);
        }
        // Revocation can race request checking; a worker that passed this point
        // still holds the lock, so recovery cannot observe an idle gate until its
        // actual work ends. The supervisor must stop that exact process/service.
        if !directory.absent(&name(token.key, "revoked"))? {
            return Err("launch revoked during admission".into());
        }
        Ok(Self {
            _worker: worker,
            _directory: directory.file,
            token: token.clone(),
        })
    }
    pub fn token(&self) -> &Token {
        &self.token
    }
}

/// Hold any existing launch lock until the recovery epoch commits. No process
/// was authorized; verifier quiescence is independently required.
#[must_use]
pub struct PreparationReceipt {
    lease: Lease,
    _gate: Option<IdleGate>,
}
impl PreparationReceipt {
    pub fn lease(&self) -> Lease {
        self.lease
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    ReservationStarted,
    ReservationAdmissionDurable,
    ReservationWorkerDurable,
    ReservationDurable,
    WorkerLockDurable,
    IntentDurable,
    PermitBeforeDirectorySync,
    PermitDurable,
    RevocationCreated,
    RevocationDurable,
    PermitRemoved,
    RevocationComplete,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryFault {
    StartedCreated,
    StartedDurable,
}
#[cfg(test)]
impl LaunchStore {
    fn inject(&self, stage: Fault) -> Result<(), Error> {
        if self.fault == Some(stage) {
            if self.crash {
                std::process::exit(76);
            }
            return Err("injected launch interruption".into());
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "launch_tests.rs"]
mod tests;
