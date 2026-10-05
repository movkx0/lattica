//! Linux-only immutable public-proof storage for the research execution service.
//!
//! An inventory entry is untrusted bytes, not a completed job. Publication is
//! durable before return, but a journal must still commit the current attempt.
//! Recovery loads always run the original CPU verifier with external bindings.
//! This module neither resumes candidates nor reconciles surviving workers.
//!
//! The directory must be dedicated, private, and on a local filesystem providing
//! exclusive locks, atomic hard links and directory fsync. Linux/procfs is an
//! explicit platform requirement. The operator account and kernel/filesystem are
//! trusted; this is not isolation from a malicious process with the same uid.

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use rand::TryRng;

use super::job::{ArtifactKind, ArtifactRef, Job, RegistryPin, VerifiedNode, VerifiedWallet};
use crate::block_v2::{
    profile::MAX_PROOF_BYTES,
    recursive::{Error, Registry},
};

const LOCK: &str = ".owner.lock";
const PENDING: &str = ".pending-";
const MAX_STORE_BYTES: u64 = 512 * (1 << 20);
const MAX_ENTRIES: usize = 16384;

#[derive(Clone, Copy, Debug)]
pub struct StoreLimits {
    /// Counts logical file lengths conservatively, including both names during
    /// publication even if they share blocks. Filesystem block rounding, metadata
    /// and a future journal need separate accounting in the aggregate scratch cap.
    pub bytes: u64,
    pub entries: usize,
}

impl StoreLimits {
    fn validate(self) -> Result<(), Error> {
        if !(2..=MAX_STORE_BYTES).contains(&self.bytes)
            || !(2..=MAX_ENTRIES).contains(&self.entries)
        {
            return Err("artifact store limit outside research bound".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreUsage {
    pub artifact_bytes: u64,
    pub pending_bytes: u64,
    pub artifacts: usize,
    pub pending_files: usize,
}

struct Inventory {
    artifacts: BTreeMap<String, ArtifactRef>,
    pending: Vec<String>,
    usage: StoreUsage,
}

/// One process owns this store through an exclusive kernel file lock. Not Clone.
/// Quotas are admission checks, not a substitute for filesystem/OS enforcement.
pub struct ArtifactStore {
    directory: File,
    lock: File,
    anchored: PathBuf,
    uid: u32,
    limits: StoreLimits,
    inventory: Inventory,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
    #[cfg(test)]
    crash: bool,
}

impl ArtifactStore {
    /// Job is itself an immutable typed admission contract constructed from
    /// verified wallet tickets; this is not a raw public artifact-write API.
    pub(super) fn put_job_inputs(&mut self, job: &Job, bytes: &[Vec<u8>]) -> Result<(), Error> {
        if bytes.len() != job.wallet_inputs().len() {
            return Err("durable wallet input count".into());
        }
        for (identity, bytes) in job.wallet_inputs().iter().zip(bytes) {
            identity.check_bytes(bytes)?;
        }
        for (identity, bytes) in job.wallet_inputs().iter().zip(bytes) {
            self.put(*identity, bytes)?;
        }
        Ok(())
    }

    /// Called only after a journal has durably committed removal of references.
    /// The scheduler's retention window and outstanding-owner gates precede it.
    pub(super) fn prune_to(&mut self, retained: &[ArtifactRef]) -> Result<usize, Error> {
        self.require_ready()?;
        self.refresh()?;
        self.require_ready()?;
        let mut keep = BTreeMap::new();
        for identity in retained {
            let name = artifact_name(*identity);
            if self.inventory.artifacts.get(&name) != Some(identity) {
                return Err("retained artifact missing or metadata changed".into());
            }
            if keep
                .insert(name, *identity)
                .is_some_and(|old| old != *identity)
            {
                return Err("retained artifact identity conflict".into());
            }
        }
        let remove: Vec<_> = self
            .inventory
            .artifacts
            .keys()
            .filter(|name| !keep.contains_key(*name))
            .cloned()
            .collect();
        let result = (|| -> Result<(), Error> {
            for name in &remove {
                check_file(&self.open_file(name)?.metadata()?, self.uid, false)?;
                fs::remove_file(self.anchored.join(name))?;
            }
            self.directory.sync_all()?;
            self.refresh()?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        Ok(remove.len())
    }

    /// Create one new directory; never repurpose or clear an existing path.
    pub fn create(path: &Path, limits: StoreLimits) -> Result<Self, Error> {
        limits.validate()?;
        if !path.is_absolute() || path.file_name().is_none() {
            return Err("artifact store requires an absolute named directory".into());
        }
        // Anchor creation to the parent descriptor, even if its path is renamed.
        let parent = open_directory(path.parent().ok_or("artifact store parent")?)?;
        let anchored_parent = fd_path(&parent);
        let target = anchored_parent.join(path.file_name().unwrap());
        DirBuilder::new().mode(0o700).create(&target)?;
        parent.sync_all()?;
        Self::open(&target, limits)
    }

    /// Inventory is bounded and untrusted. Pending writes are reported, not
    /// automatically deleted or promoted. Call recover_pending explicitly.
    pub fn open(path: &Path, limits: StoreLimits) -> Result<Self, Error> {
        limits.validate()?;
        let directory = open_directory(path)?;
        // SAFETY: geteuid has no arguments, memory access or failure convention.
        let uid = unsafe { libc::geteuid() };
        let metadata = directory.metadata()?;
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err("artifact directory must be private and owned by the operator".into());
        }
        let anchored = fd_path(&directory);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(safe_file_flags())
            .open(anchored.join(LOCK))?;
        check_file(&lock.metadata()?, uid, false)?;
        if lock.metadata()?.len() != 0 {
            return Err("artifact owner lock must be empty".into());
        }
        lock.try_lock()
            .map_err(|e| format!("artifact store already owned: {e}"))?;
        directory.sync_all()?;
        let mut store = Self {
            directory,
            lock,
            anchored,
            uid,
            limits,
            inventory: Inventory {
                artifacts: BTreeMap::new(),
                pending: Vec::new(),
                usage: StoreUsage::default(),
            },
            poisoned: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            crash: false,
        };
        store.refresh()?;
        Ok(store)
    }

    /// Last successful bounded scan, not physical disk allocation or a live OS
    /// quota. A poisoned object must not be used for further admission.
    pub fn usage(&self) -> StoreUsage {
        self.inventory.usage
    }

    /// Exact descriptors only. This never returns proof-validity authority.
    pub fn inventory(&self) -> Vec<ArtifactRef> {
        self.inventory.artifacts.values().copied().collect()
    }

    pub fn needs_recovery(&self) -> bool {
        self.poisoned || !self.inventory.pending.is_empty()
    }

    /// Delete only recognized interrupted-write names under the held directory
    /// and owner lock. Published artifacts, including orphans, are left intact.
    /// A poisoned live object must first be dropped/reopened to rescan the disk.
    pub fn recover_pending(&mut self) -> Result<usize, Error> {
        self.check_owner()?;
        self.refresh()?;
        let count = self.inventory.pending.len();
        let result = (|| -> Result<(), Error> {
            for name in &self.inventory.pending {
                let file = self.open_file(name)?;
                check_file(&file.metadata()?, self.uid, true)?;
                fs::remove_file(self.anchored.join(name))?;
            }
            self.directory.sync_all()?;
            self.refresh()?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        Ok(count)
    }

    pub fn put_wallet(
        &mut self,
        ticket: VerifiedWallet,
        bytes: &[u8],
    ) -> Result<ArtifactRef, Error> {
        self.put(ticket.artifact(), bytes)
    }

    pub fn put_node(&mut self, ticket: VerifiedNode, bytes: &[u8]) -> Result<ArtifactRef, Error> {
        self.put(ticket.artifact(), bytes)
    }

    pub fn load_wallet(
        &self,
        identity: ArtifactRef,
        pin: RegistryPin,
        registry: &Registry,
        chain: [u8; 32],
    ) -> Result<(VerifiedWallet, Vec<u8>), Error> {
        if identity.kind() != ArtifactKind::Wallet {
            return Err("artifact is not a wallet proof".into());
        }
        let bytes = self.read_exact(identity)?;
        let ticket = VerifiedWallet::verify(pin, registry, chain, &bytes)?;
        if ticket.artifact() != identity {
            return Err("recovered wallet identity".into());
        }
        Ok((ticket, bytes))
    }

    pub fn load_node(
        &self,
        identity: ArtifactRef,
        job: &Job,
        registry: &Registry,
    ) -> Result<(VerifiedNode, Vec<u8>), Error> {
        if identity.kind() != ArtifactKind::Node {
            return Err("artifact is not a recursive node".into());
        }
        let bytes = self.read_exact(identity)?;
        let ticket = VerifiedNode::verify(job, registry, &bytes)?;
        if ticket.artifact() != identity {
            return Err("recovered node identity".into());
        }
        Ok((ticket, bytes))
    }

    fn check_owner(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err("artifact store poisoned; reopen and recover".into());
        }
        let current = fs::symlink_metadata(self.anchored.join(LOCK))?;
        let held = self.lock.metadata()?;
        check_file(&current, self.uid, false)?;
        if current.dev() != held.dev() || current.ino() != held.ino() || current.len() != 0 {
            return Err("artifact owner lock changed".into());
        }
        let directory = self.directory.metadata()?;
        if directory.uid() != self.uid || directory.mode() & 0o077 != 0 || directory.nlink() == 0 {
            return Err("artifact directory ownership changed".into());
        }
        Ok(())
    }

    pub(super) fn require_ready(&self) -> Result<(), Error> {
        self.check_owner()?;
        if !self.inventory.pending.is_empty() {
            return Err("artifact pending-write recovery required".into());
        }
        Ok(())
    }

    fn open_file(&self, name: &str) -> Result<File, Error> {
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(safe_file_flags())
            .open(self.anchored.join(name))?)
    }

    fn refresh(&mut self) -> Result<(), Error> {
        self.check_owner()?;
        let mut inventory = Inventory {
            artifacts: BTreeMap::new(),
            pending: Vec::new(),
            usage: StoreUsage::default(),
        };
        let mut links = Vec::new();
        for entry in fs::read_dir(&self.anchored)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 artifact filename")?;
            if name == LOCK {
                continue;
            }
            if inventory.usage.artifacts + inventory.usage.pending_files >= self.limits.entries {
                return Err("artifact directory entry limit".into());
            }
            let metadata = fs::symlink_metadata(self.anchored.join(&name))?;
            check_file(&metadata, self.uid, true)?;
            if metadata.len() > MAX_PROOF_BYTES as u64 {
                return Err("oversized artifact file".into());
            }
            if is_pending(&name) {
                inventory.usage.pending_files += 1;
                inventory.usage.pending_bytes = inventory
                    .usage
                    .pending_bytes
                    .checked_add(metadata.len())
                    .ok_or("artifact byte overflow")?;
                inventory.pending.push(name);
            } else {
                let identity = parse_name(&name, metadata.len())?;
                inventory.usage.artifacts += 1;
                inventory.usage.artifact_bytes = inventory
                    .usage
                    .artifact_bytes
                    .checked_add(metadata.len())
                    .ok_or("artifact byte overflow")?;
                links.push(metadata.nlink());
                inventory.artifacts.insert(name, identity);
            }
            if inventory
                .usage
                .artifact_bytes
                .checked_add(inventory.usage.pending_bytes)
                .is_none_or(|bytes| bytes > self.limits.bytes)
            {
                return Err("artifact directory byte limit".into());
            }
        }
        // Atomic publication briefly gives the pending and final names one inode.
        // With no pending files, every final name must have exactly one link.
        if inventory.pending.is_empty() && links.iter().any(|n| *n != 1) {
            return Err("artifact has an unexpected hard link".into());
        }
        inventory.pending.sort();
        self.inventory = inventory;
        Ok(())
    }

    pub(super) fn read_exact(&self, identity: ArtifactRef) -> Result<Vec<u8>, Error> {
        self.require_ready()?;
        let name = artifact_name(identity);
        if self.inventory.artifacts.get(&name) != Some(&identity) {
            return Err("artifact unavailable in inventory".into());
        }
        let file = self.open_file(&name)?;
        let metadata = file.metadata()?;
        check_file(&metadata, self.uid, false)?;
        if metadata.len() != u64::from(identity.byte_len()) {
            return Err("artifact file length changed".into());
        }
        let mut bytes = Vec::with_capacity(identity.byte_len() as usize);
        file.take(u64::from(identity.byte_len()) + 1)
            .read_to_end(&mut bytes)?;
        identity.check_bytes(&bytes)?;
        Ok(bytes)
    }

    fn put(&mut self, identity: ArtifactRef, bytes: &[u8]) -> Result<ArtifactRef, Error> {
        self.require_ready()?;
        identity.check_bytes(bytes)?;
        self.refresh()?;
        self.require_ready()?;
        let name = artifact_name(identity);
        if self.inventory.artifacts.contains_key(&name) {
            self.read_exact(identity)?;
            // A previous writer may have died after linking but before fsync.
            self.open_file(&name)?.sync_all()?;
            self.directory.sync_all()?;
            return Ok(identity);
        }
        let extra = (bytes.len() as u64)
            .checked_mul(2)
            .ok_or("artifact publication size overflow")?;
        if self
            .inventory
            .usage
            .artifact_bytes
            .checked_add(extra)
            .is_none_or(|n| n > self.limits.bytes)
            || self
                .inventory
                .usage
                .artifacts
                .checked_add(2)
                .is_none_or(|n| n > self.limits.entries)
        {
            return Err("artifact publication exceeds store admission".into());
        }
        let mut nonce = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| format!("artifact temporary entropy: {e}"))?;
        let pending = format!("{PENDING}{}", hex(&nonce));
        let path = self.anchored.join(&pending);
        let result = (|| -> Result<(), Error> {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(safe_file_flags())
                .open(&path)?;
            file.write_all(bytes)?;
            #[cfg(test)]
            self.inject(Fault::AfterWrite)?;
            file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::AfterFileSync)?;
            // hard_link is atomic and refuses to replace an existing destination.
            fs::hard_link(&path, self.anchored.join(&name))?;
            #[cfg(test)]
            self.inject(Fault::AfterPublish)?;
            self.directory.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::AfterDirectorySync)?;
            fs::remove_file(&path)?;
            #[cfg(test)]
            self.inject(Fault::AfterCleanup)?;
            self.directory.sync_all()?;
            self.refresh()?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        Ok(identity)
    }
}

pub(super) fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

pub(super) fn open_directory(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

pub(super) fn safe_file_flags() -> i32 {
    libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
}

pub(super) fn check_file(
    metadata: &Metadata,
    uid: u32,
    allow_publish_link: bool,
) -> Result<(), Error> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o177 != 0
        || metadata.nlink() == 0
        || metadata.nlink() > if allow_publish_link { 2 } else { 1 }
    {
        return Err("artifact must be a private owned regular file with bounded links".into());
    }
    Ok(())
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn artifact_name(identity: ArtifactRef) -> String {
    let prefix = match identity.kind() {
        ArtifactKind::Wallet => 'w',
        ArtifactKind::Node => 'n',
    };
    format!("{prefix}-{}.proof", hex(&identity.digest_bytes()))
}

pub(super) fn is_pending(name: &str) -> bool {
    name.strip_prefix(PENDING).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn parse_name(name: &str, len: u64) -> Result<ArtifactRef, Error> {
    let kind = match name.as_bytes().first() {
        Some(b'w') => ArtifactKind::Wallet,
        Some(b'n') => ArtifactKind::Node,
        _ => return Err("unknown artifact filename".into()),
    };
    if name.len() != 72 || name.as_bytes()[1] != b'-' || !name.ends_with(".proof") {
        return Err("noncanonical artifact filename".into());
    }
    let digits = &name.as_bytes()[2..66];
    if !digits
        .iter()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return Err("noncanonical artifact digest".into());
    }
    let nibble = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
    let digest = core::array::from_fn(|i| (nibble(digits[2 * i]) << 4) | nibble(digits[2 * i + 1]));
    ArtifactRef::from_descriptor(kind, u32::try_from(len)?, digest)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    AfterWrite,
    AfterFileSync,
    AfterPublish,
    AfterDirectorySync,
    AfterCleanup,
}

#[cfg(test)]
impl ArtifactStore {
    fn inject(&self, stage: Fault) -> Result<(), Error> {
        if self.fault == Some(stage) {
            if self.crash {
                std::process::exit(73);
            }
            Err("injected artifact publication interruption".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "artifact_store_tests.rs"]
mod tests;
