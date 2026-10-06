//! Research-only durable owner of the local DAG and immutable proof store.
//!
//! A bounded snapshot journal atomically replaces its complete current metadata;
//! it is not an append-only audit history. Every mutating API fsyncs a snapshot
//! before returning, including error paths that advance time or reject attempts.
//! Persistence errors make the handle unusable; an error can have an uncertain
//! commit outcome, so recovery must inspect the authoritative on-disk state.
//!
//! Recovery revalidates proof bytes on CPU and never revives old candidates or
//! attempts. The runtime must authoritatively reconcile every recorded unresolved
//! worker/device/verifier before resuming. This module provides that boundary,
//! not an OS worker supervisor, host eligibility checks or production activation.

use rand::TryRng;
use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, Weak},
};

use super::{
    artifact_store::{self, ArtifactStore, StoreUsage},
    dag::{self, AttemptId, CandidateId, Completion, Dag, JobStatus, Lease, Limits, WorkerId},
    job::{ArtifactRef, Job, JobId, RegistryPin, VerifiedNode},
    resources::Resources,
    workspace::{WorkspaceId, WorkspaceLease},
};
use crate::block_v2::{
    commitment,
    recursive::{Error, Registry},
};
pub use dag::snapshot::{PreviousAttempt, PreviousCandidate};

#[path = "journal_workspace.rs"]
mod workspace_guard;
pub use workspace_guard::{WorkspaceReservation, WorkspaceUse};

const STATE: &str = "state";
const LOCK: &str = ".owner.lock";
const MAGIC: &[u8; 8] = b"LVJRN001";
const HEADER: usize = 52;
const HASH_DOMAIN: u64 = 0x4c42563273;
const MAX_PENDING: usize = 16;

#[derive(Clone, Copy, Debug)]
pub struct JournalLimits {
    pub snapshot_bytes: usize,
}
impl JournalLimits {
    fn validate(self) -> Result<(), Error> {
        if !(256..=dag::snapshot::MAX_SNAPSHOT_BYTES).contains(&self.snapshot_bytes) {
            return Err("journal snapshot byte limit".into());
        }
        Ok(())
    }
}

pub(super) struct SnapshotLog {
    directory: File,
    lock: File,
    path: std::path::PathBuf,
    uid: u32,
    limits: JournalLimits,
    generation: u64,
    head: Option<(u64, u64, u64)>,
    pending: Vec<String>,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
    #[cfg(test)]
    crash: bool,
}

impl SnapshotLog {
    pub(super) fn create(path: &Path, limits: JournalLimits) -> Result<Self, Error> {
        limits.validate()?;
        if !path.is_absolute() || path.file_name().is_none() {
            return Err("journal requires an absolute named directory".into());
        }
        let parent = artifact_store::open_directory(path.parent().ok_or("journal parent")?)?;
        let target = artifact_store::fd_path(&parent).join(path.file_name().unwrap());
        DirBuilder::new().mode(0o700).create(&target)?;
        parent.sync_all()?;
        Self::locked(&target, limits)
    }

    fn locked(path: &Path, limits: JournalLimits) -> Result<Self, Error> {
        limits.validate()?;
        let directory = artifact_store::open_directory(path)?;
        // SAFETY: geteuid has no arguments, memory access or failure convention.
        let uid = unsafe { libc::geteuid() };
        let metadata = directory.metadata()?;
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err("journal directory must be private and owned".into());
        }
        let path = artifact_store::fd_path(&directory);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(artifact_store::safe_file_flags())
            .open(path.join(LOCK))?;
        artifact_store::check_file(&lock.metadata()?, uid, false)?;
        if lock.metadata()?.len() != 0 {
            return Err("journal owner lock is not empty".into());
        }
        lock.try_lock()
            .map_err(|e| format!("journal already owned: {e}"))?;
        directory.sync_all()?;
        let mut pending = Vec::new();
        for entry in fs::read_dir(&path)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| "journal non-UTF8 filename")?;
            if name == LOCK {
                continue;
            }
            let metadata = fs::symlink_metadata(path.join(&name))?;
            artifact_store::check_file(&metadata, uid, false)?;
            if metadata.len() > (limits.snapshot_bytes + HEADER) as u64 {
                return Err("journal file exceeds bound".into());
            }
            if name == STATE {
                continue;
            }
            if !artifact_store::is_pending(&name) || pending.len() >= MAX_PENDING {
                return Err("journal unexpected entry or pending count".into());
            }
            pending.push(name);
        }
        pending.sort();
        Ok(Self {
            directory,
            lock,
            path,
            uid,
            limits,
            generation: 0,
            head: None,
            pending,
            poisoned: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            crash: false,
        })
    }

    pub(super) fn open(path: &Path, limits: JournalLimits) -> Result<(Self, Vec<u8>), Error> {
        let mut log = Self::locked(path, limits)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(artifact_store::safe_file_flags())
            .open(log.path.join(STATE))?;
        let metadata = file.metadata()?;
        artifact_store::check_file(&metadata, log.uid, false)?;
        if metadata.len() < HEADER as u64
            || metadata.len() > (limits.snapshot_bytes + HEADER) as u64
        {
            return Err("journal frame length".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((limits.snapshot_bytes + HEADER + 1) as u64)
            .read_to_end(&mut bytes)?;
        let (generation, payload) = decode_frame(&bytes, limits)?;
        log.generation = generation;
        log.head = Some((metadata.dev(), metadata.ino(), metadata.len()));
        log.check_current()?;
        Ok((log, payload.to_vec()))
    }

    pub(super) fn check_current(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err("journal poisoned; recovery required".into());
        }
        let lock = fs::symlink_metadata(self.path.join(LOCK))?;
        let held = self.lock.metadata()?;
        artifact_store::check_file(&lock, self.uid, false)?;
        let directory = self.directory.metadata()?;
        if lock.dev() != held.dev()
            || lock.ino() != held.ino()
            || lock.len() != 0
            || directory.uid() != self.uid
            || directory.mode() & 0o077 != 0
            || directory.nlink() == 0
        {
            return Err("journal owner/directory changed".into());
        }
        match (self.head, fs::symlink_metadata(self.path.join(STATE))) {
            (Some(expected), Ok(metadata)) => {
                artifact_store::check_file(&metadata, self.uid, false)?;
                if expected != (metadata.dev(), metadata.ino(), metadata.len()) {
                    return Err("journal head replaced".into());
                }
            }
            (None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("journal head missing or unexpected".into()),
        }
        Ok(())
    }

    pub(super) fn identity(&self) -> Result<[u64; 2], Error> {
        self.check_current()?;
        let metadata = self.directory.metadata()?;
        Ok([metadata.dev(), metadata.ino()])
    }

    pub(super) fn cleanup_pending(&mut self) -> Result<(), Error> {
        self.check_current()?;
        let result = (|| -> Result<(), Error> {
            for name in &self.pending {
                artifact_store::check_file(
                    &fs::symlink_metadata(self.path.join(name))?,
                    self.uid,
                    false,
                )?;
                fs::remove_file(self.path.join(name))?;
            }
            self.directory.sync_all()?;
            self.pending.clear();
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn commit(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.check_current()?;
        if !self.pending.is_empty() {
            return Err("journal pending cleanup required".into());
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("journal generation exhausted")?;
        let bytes = encode_frame(generation, payload, self.limits)?;
        let mut nonce = [0; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| format!("journal temporary entropy: {e}"))?;
        let pending = self
            .path
            .join(format!(".pending-{}", artifact_store::hex(&nonce)));
        let result = (|| -> Result<(), Error> {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(artifact_store::safe_file_flags())
                .open(&pending)?;
            file.write_all(&bytes)?;
            #[cfg(test)]
            self.inject(Fault::AfterWrite)?;
            file.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::AfterFileSync)?;
            self.check_current()?;
            fs::rename(&pending, self.path.join(STATE))?;
            #[cfg(test)]
            self.inject(Fault::AfterRename)?;
            self.directory.sync_all()?;
            #[cfg(test)]
            self.inject(Fault::AfterDirectorySync)?;
            let metadata = file.metadata()?;
            self.head = Some((metadata.dev(), metadata.ino(), metadata.len()));
            self.generation = generation;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

fn checksum(generation: u64, payload: &[u8]) -> Result<[u8; 32], Error> {
    let mut fields = Vec::with_capacity(4 + payload.len().div_ceil(4));
    fields.extend([
        1,
        u64::from(generation as u32),
        generation >> 32,
        payload.len() as u64,
    ]);
    for part in payload.chunks(4) {
        let mut word = [0; 4];
        word[..part.len()].copy_from_slice(part);
        fields.push(u64::from(u32::from_le_bytes(word)));
    }
    Ok(commitment::digest_bytes(commitment::hash_fields(
        HASH_DOMAIN,
        &fields,
    )?)?)
}
fn encode_frame(generation: u64, payload: &[u8], limits: JournalLimits) -> Result<Vec<u8>, Error> {
    limits.validate()?;
    if generation == 0 || payload.is_empty() || payload.len() > limits.snapshot_bytes {
        return Err("journal payload bound".into());
    }
    let mut out = MAGIC.to_vec();
    out.extend(generation.to_le_bytes());
    out.extend(u32::try_from(payload.len())?.to_le_bytes());
    out.extend(checksum(generation, payload)?);
    out.extend(payload);
    Ok(out)
}
fn decode_frame(bytes: &[u8], limits: JournalLimits) -> Result<(u64, &[u8]), Error> {
    limits.validate()?;
    if bytes.len() < HEADER || &bytes[..8] != MAGIC {
        return Err("journal frame schema".into());
    }
    let generation = u64::from_le_bytes(bytes[8..16].try_into()?);
    let len = u32::from_le_bytes(bytes[16..20].try_into()?) as usize;
    if generation == 0
        || len == 0
        || len > limits.snapshot_bytes
        || len.checked_add(HEADER) != Some(bytes.len())
    {
        return Err("journal frame size/generation".into());
    }
    let payload = &bytes[HEADER..];
    if bytes[20..HEADER] != checksum(generation, payload)? {
        return Err("journal frame checksum".into());
    }
    Ok((generation, payload))
}

pub struct DurableDag {
    core: Dag,
    journal: SnapshotLog,
    store: ArtifactStore,
    poisoned: bool,
    verifiers: BTreeMap<AttemptId, Weak<VerificationOwner>>,
    workspaces: BTreeMap<WorkspaceId, Weak<workspace_guard::Owner>>,
}

/// A duplicate of the journal's locked open-file description. It keeps recovery
/// fenced even if the coordinator handle is dropped while verification runs.
/// This protects trusted local threads, not hostile same-UID file replacement or
/// arbitrary external verifiers. No proof or snapshot encoding changes.
struct VerificationOwner {
    journal: [u64; 2],
    lock: File,
    lease: Lease,
}

#[must_use = "verify or reject the task; abandonment requires rejection/recovery"]
pub struct VerificationTask {
    owner: Arc<VerificationOwner>,
    job: Job,
}

/// Completion owns the same barrier until accepted or explicitly discarded.
#[must_use = "finish the guarded verification or discard it before recovery"]
pub struct VerificationResult {
    owner: Arc<VerificationOwner>,
    result: Option<(VerifiedNode, Vec<u8>)>,
    error: Option<String>,
}

impl VerificationTask {
    pub fn lease(&self) -> Lease {
        self.owner.lease
    }

    /// CPU verification consumes the task. Moving it to a thread transfers the
    /// journal barrier; a panic drops it only after verification unwinds.
    pub fn verify(self, registry: &Registry, bytes: Vec<u8>) -> VerificationResult {
        let (result, error) = match VerifiedNode::verify(&self.job, registry, &bytes) {
            Ok(ticket) => (Some((ticket, bytes)), None),
            Err(error) => (None, Some(error.to_string())),
        };
        VerificationResult {
            owner: self.owner,
            result,
            error,
        }
    }

    pub fn verify_typed(
        self,
        registry: &crate::block_v2::typed_recursive::Registry<12>,
        bytes: Vec<u8>,
    ) -> VerificationResult {
        let (result, error) = match VerifiedNode::verify_typed(&self.job, registry, &bytes) {
            Ok(ticket) => (Some((ticket, bytes)), None),
            Err(error) => (None, Some(error.to_string())),
        };
        VerificationResult {
            owner: self.owner,
            result,
            error,
        }
    }

    /// Explicitly complete without starting CPU verification.
    pub fn reject(self) -> VerificationResult {
        VerificationResult {
            owner: self.owner,
            result: None,
            error: Some("verification not performed".into()),
        }
    }
}

impl VerificationResult {
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// No dispatch API exists while recovery owns these resources. Candidate reports
/// are historical metadata, not current host eligibility or accepted block roots.
pub struct Recovery {
    restored: dag::snapshot::Restored,
    journal: SnapshotLog,
    store: ArtifactStore,
}

impl Recovery {
    /// Generation actually read from the authoritative checkpoint. A durable
    /// recovery admission can be newer if its owner died before committing.
    pub fn previous_epoch(&self) -> u64 {
        self.restored.previous_epoch
    }

    pub fn previous_candidates(&self) -> &[PreviousCandidate] {
        &self.restored.candidates
    }
    pub fn unresolved_attempts(&self) -> &[PreviousAttempt] {
        &self.restored.attempts
    }
    pub fn unresolved_workspaces(&self) -> &[WorkspaceLease] {
        &self.restored.workspaces
    }

    /// Reconciliation must authoritatively stop/drain both proving and verifier
    /// work for each exact old lease; absence must be checked, never inferred from
    /// elapsed time. It must be idempotent if recovery is retried after a failure.
    /// The clock is sampled after reconciliation for the new retention window.
    pub fn resume(
        self,
        reconcile: impl FnMut(&PreviousAttempt) -> Result<(), Error>,
        now: impl FnOnce() -> u64,
    ) -> Result<DurableDag, Error> {
        if !self.restored.workspaces.is_empty() {
            return Err("persistent workspaces require explicit reconciliation".into());
        }
        self.resume_with_workspaces(reconcile, |_| Ok(()), now)
    }

    /// Reconcile all job/verifier work first, then each exact persistent cache
    /// lifetime. Neither a missing service nor an available journal lock is
    /// evidence that arbitrary workspace users have drained.
    pub fn resume_with_workspaces(
        self,
        reconcile: impl FnMut(&PreviousAttempt) -> Result<(), Error>,
        reconcile_workspace: impl FnMut(&WorkspaceLease) -> Result<(), Error>,
        now: impl FnOnce() -> u64,
    ) -> Result<DurableDag, Error> {
        self.resume_initialized(reconcile, reconcile_workspace, now, |_, _| Ok(()))
            .map(|(owner, ())| owner)
    }

    /// The caller must revalidate the native head first. Publish its sealed
    /// candidate in the same checkpoint as the new epoch so an interruption
    /// cannot leave an intermediate checkpoint without candidate provenance.
    pub fn resume_sealed_with_workspaces(
        self,
        reconcile: impl FnMut(&PreviousAttempt) -> Result<(), Error>,
        reconcile_workspace: impl FnMut(&WorkspaceLease) -> Result<(), Error>,
        now: impl FnOnce() -> u64,
        root: JobId,
        eligibility: [u8; 32],
        lifetime_ms: u64,
    ) -> Result<(DurableDag, CandidateId), Error> {
        self.resume_initialized(reconcile, reconcile_workspace, now, |dag, now| {
            let deadline = now
                .checked_add(lifetime_ms)
                .ok_or("candidate deadline overflow")?;
            let candidate = dag.attach(root, eligibility, deadline, now)?;
            dag.seal(candidate, eligibility, now)?;
            Ok(candidate)
        })
    }

    fn resume_initialized<T>(
        mut self,
        mut reconcile: impl FnMut(&PreviousAttempt) -> Result<(), Error>,
        mut reconcile_workspace: impl FnMut(&WorkspaceLease) -> Result<(), Error>,
        now: impl FnOnce() -> u64,
        initialize: impl FnOnce(&mut Dag, u64) -> Result<T, Error>,
    ) -> Result<(DurableDag, T), Error> {
        self.store.require_ready()?;
        self.journal.check_current()?;
        for attempt in &self.restored.attempts {
            reconcile(attempt)?;
        }
        for workspace in &self.restored.workspaces {
            reconcile_workspace(workspace)?;
        }
        let now = now();
        self.restored.dag.rebase_recovered(now)?;
        self.restored
            .dag
            .pin_launch_journal(self.journal.identity()?)?;
        let initialized = initialize(&mut self.restored.dag, now)?;
        self.journal.cleanup_pending()?;
        self.journal.commit(&self.restored.dag.snapshot()?)?;
        Ok((
            DurableDag {
                core: self.restored.dag,
                journal: self.journal,
                store: self.store,
                poisoned: false,
                verifiers: BTreeMap::new(),
                workspaces: BTreeMap::new(),
            },
            initialized,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pruned {
    pub jobs: usize,
    pub artifacts: usize,
}

impl DurableDag {
    pub fn create(
        path: &Path,
        journal_limits: JournalLimits,
        store: ArtifactStore,
        pin: RegistryPin,
        chain: [u8; 32],
        epoch: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        store.require_ready()?;
        let mut core = Dag::new(pin, chain, epoch, limits)?;
        let mut journal = SnapshotLog::create(path, journal_limits)?;
        core.pin_launch_journal(journal.identity()?)?;
        journal.commit(&core.snapshot()?)?;
        Ok(Self {
            core,
            journal,
            store,
            poisoned: false,
            verifiers: BTreeMap::new(),
            workspaces: BTreeMap::new(),
        })
    }

    pub fn recover(
        path: &Path,
        journal_limits: JournalLimits,
        store: ArtifactStore,
        pin: RegistryPin,
        registry: &Registry,
        chain: [u8; 32],
        next_epoch: u64,
        limits: Limits,
    ) -> Result<Recovery, Error> {
        store.require_ready()?;
        let (journal, bytes) = SnapshotLog::open(path, journal_limits)?;
        let restored =
            dag::snapshot::restore(&bytes, pin, registry, chain, next_epoch, limits, &store)?;
        if let Some(root) = restored.dag.launch_root() {
            if root.journal != journal.identity()? {
                return Err("DAG launch admission journal directory replaced".into());
            }
        }
        Ok(Recovery {
            restored,
            journal,
            store,
        })
    }

    /// Registry, chain and wallet policy are trusted host inputs, never taken
    /// from the checkpoint. Every retained proof is independently reverified.
    pub fn recover_typed(
        path: &Path,
        journal_limits: JournalLimits,
        store: ArtifactStore,
        pin: RegistryPin,
        registry: &crate::block_v2::typed_recursive::Registry<12>,
        chain: [u8; 32],
        next_epoch: u64,
        limits: Limits,
        policy: impl FnMut(ArtifactRef) -> Result<crate::block_v2::typed_recursive::Policy, Error>,
    ) -> Result<Recovery, Error> {
        store.require_ready()?;
        let (journal, bytes) = SnapshotLog::open(path, journal_limits)?;
        let restored = dag::snapshot::restore_typed(
            &bytes, pin, registry, chain, next_epoch, limits, &store, policy,
        )?;
        if let Some(root) = restored.dag.launch_root() {
            if root.journal != journal.identity()? {
                return Err("typed DAG launch journal directory replaced".into());
            }
        }
        Ok(Recovery {
            restored,
            journal,
            store,
        })
    }

    fn live(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err("durable execution poisoned; recovery required".into());
        }
        self.store.require_ready()?;
        self.journal.check_current()
    }

    fn persist<T>(&mut self, outcome: Result<T, Error>) -> Result<T, Error> {
        let written = self
            .core
            .snapshot()
            .and_then(|bytes| self.journal.commit(&bytes));
        if let Err(error) = written {
            self.poisoned = true;
            return Err(error);
        }
        outcome
    }

    pub fn generation(&self) -> Result<u64, Error> {
        self.live()?;
        Ok(self.journal.generation)
    }
    pub fn ready(&self) -> Result<Vec<JobId>, Error> {
        self.live()?;
        Ok(self.core.ready())
    }

    /// Export only a durably committed current lease. This does not spawn work.
    pub(super) fn bind_launch(
        &mut self,
        lease: Lease,
        store: [u64; 2],
        binding: dag::LaunchBinding,
    ) -> Result<(), Error> {
        self.live()?;
        let root = dag::LaunchRoot {
            journal: self.journal.identity()?,
            store,
        };
        let outcome = self.core.bind_launch(lease, root, binding);
        self.persist(outcome)
    }
    pub(super) fn check_new_launch(&self, lease: Lease, store: [u64; 2]) -> Result<(), Error> {
        self.live()?;
        self.core.check_new_launch(
            lease,
            dag::LaunchRoot {
                journal: self.journal.identity()?,
                store,
            },
        )
    }

    pub(super) fn poison_launch_admission(&mut self) {
        self.poisoned = true;
    }

    #[cfg(any(feature = "stream", test))]
    pub(super) fn authorize_supervisor(
        &mut self,
        lease: Lease,
        store: [u64; 2],
        path: [u8; 32],
        directory: [u64; 2],
    ) -> Result<(), Error> {
        self.live()?;
        let root = dag::LaunchRoot {
            journal: self.journal.identity()?,
            store,
        };
        let outcome = self.core.authorize_supervisor(lease, root, path, directory);
        self.persist(outcome)
    }

    pub(super) fn authorized_supervisor(
        &self,
        lease: Lease,
        store: [u64; 2],
        path: [u8; 32],
    ) -> Result<dag::LaunchBinding, Error> {
        self.live()?;
        self.core.authorized_supervisor(
            lease,
            dag::LaunchRoot {
                journal: self.journal.identity()?,
                store,
            },
            path,
        )
    }

    #[cfg(feature = "stream")]
    pub(super) fn check_legacy_launch(&self, lease: Lease) -> Result<(), Error> {
        self.live()?;
        self.core.check_legacy_launch(lease)
    }

    #[cfg(feature = "stream")]
    pub(super) fn check_launch(
        &self,
        lease: Lease,
        store: [u64; 2],
        binding: dag::LaunchBinding,
    ) -> Result<(), Error> {
        self.live()?;
        let root = dag::LaunchRoot {
            journal: self.journal.identity()?,
            store,
        };
        self.core.check_launch(lease, root, binding)
    }

    pub fn assignment(&self, lease: Lease) -> Result<super::worker::Assignment, Error> {
        self.live()?;
        self.core.assignment(lease)
    }
    /// Export a durably verified node for recovery. These bytes do not authorize
    /// native application; the caller must still check the current sealed head.
    pub fn verified_node_bytes(&self, job: JobId) -> Result<Option<&[u8]>, Error> {
        self.live()?;
        self.core.verified_node_bytes(job)
    }

    pub fn status(&self, job: JobId) -> Result<JobStatus, Error> {
        self.live()?;
        self.core.status(job)
    }
    pub fn resource_use(&self) -> Result<Resources, Error> {
        self.live()?;
        Ok(self.core.resource_use())
    }
    pub fn store_usage(&self) -> Result<StoreUsage, Error> {
        self.live()?;
        Ok(self.store.usage())
    }
    pub fn pending_stops(&self) -> Result<Vec<Lease>, Error> {
        self.live()?;
        Ok(self.core.pending_stops())
    }
    pub fn leased_job(&self, lease: Lease) -> Result<&Job, Error> {
        self.live()?;
        self.core.leased_job(lease)
    }
    pub fn input_manifest(&self, lease: Lease) -> Result<&[ArtifactRef], Error> {
        self.live()?;
        self.core.input_manifest(lease)
    }
    pub fn input_bytes(&self, lease: Lease, index: usize) -> Result<&[u8], Error> {
        self.live()?;
        self.core.input_bytes(lease, index)
    }

    pub fn admit(&mut self, job: Job, wallets: Vec<Vec<u8>>, now_ms: u64) -> Result<JobId, Error> {
        self.live()?;
        if let Err(error) = self.store.put_job_inputs(&job, &wallets) {
            self.poisoned = self.store.needs_recovery();
            return Err(error);
        }
        let outcome = self.core.admit(job, wallets, now_ms);
        self.persist(outcome)
    }
    pub fn attach(
        &mut self,
        root: JobId,
        eligibility: [u8; 32],
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<CandidateId, Error> {
        self.live()?;
        let outcome = self.core.attach(root, eligibility, deadline_ms, now_ms);
        self.persist(outcome)
    }
    pub fn seal(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        self.live()?;
        let outcome = self.core.seal(candidate, eligibility, now_ms);
        self.persist(outcome)
    }
    pub fn cancel(&mut self, candidate: CandidateId, now_ms: u64) -> Result<(), Error> {
        self.live()?;
        let outcome = self.core.cancel(candidate, now_ms);
        self.persist(outcome)
    }
    pub fn advance(&mut self, now_ms: u64) -> Result<(), Error> {
        self.live()?;
        let outcome = self.core.advance(now_ms);
        self.persist(outcome)
    }
    pub fn lease(
        &mut self,
        job: JobId,
        worker: WorkerId,
        resources: Resources,
        remaining_path_ms: u64,
        lease_ms: u64,
        now_ms: u64,
    ) -> Result<Lease, Error> {
        self.live()?;
        let outcome = self
            .core
            .lease(job, worker, resources, remaining_path_ms, lease_ms, now_ms);
        self.persist(outcome)
    }
    pub fn worker_stopped(&mut self, lease: Lease, now_ms: u64) -> Result<(), Error> {
        self.live()?;
        let outcome = self.core.worker_stopped(lease, now_ms);
        self.persist(outcome)
    }
    /// Legacy/unmanaged boundary. Its caller remains responsible for verifier
    /// drain during cancellation and recovery. Managed CPU work should use the
    /// task below so dropping the coordinator cannot release its journal lock.
    pub fn begin_verification(&mut self, lease: Lease, now_ms: u64) -> Result<Job, Error> {
        self.live()?;
        let outcome = self.core.begin_verification(lease, now_ms);
        self.persist(outcome)
    }

    pub fn begin_guarded_verification(
        &mut self,
        lease: Lease,
        now_ms: u64,
    ) -> Result<VerificationTask, Error> {
        self.live()?;
        if self.verifiers.contains_key(&lease.id()) {
            return Err("verification task already issued".into());
        }
        // Clone before committing verification so FD exhaustion cannot leave a
        // newly issued, unguarded task. dup shares the Linux flock description.
        let owner = Arc::new(VerificationOwner {
            journal: self.journal.identity()?,
            lock: self.journal.lock.try_clone()?,
            lease,
        });
        let job = self.begin_verification(lease, now_ms)?;
        self.verifiers.insert(lease.id(), Arc::downgrade(&owner));
        Ok(VerificationTask { owner, job })
    }

    pub fn finish_guarded_verification(
        &mut self,
        finished: VerificationResult,
        now_ms: u64,
    ) -> Result<Completion, Error> {
        self.live()?;
        let held = self.journal.lock.metadata()?;
        let guarded = finished.owner.lock.metadata()?;
        let lease = finished.owner.lease;
        let issued = self
            .verifiers
            .get(&lease.id())
            .and_then(Weak::upgrade)
            .ok_or("verification result has no live issuing task")?;
        if finished.owner.journal != self.journal.identity()?
            || (held.dev(), held.ino()) != (guarded.dev(), guarded.ino())
            || !Arc::ptr_eq(&issued, &finished.owner)
        {
            return Err("verification result belongs to another owner".into());
        }
        self.verifiers.remove(&lease.id());
        // The task's CPU operation has returned. Keep both lock references until
        // the durable completion (including its failure path) has returned too.
        self.finish_verification(lease, finished.result, now_ms)
    }
    pub fn reject_worker(&mut self, lease: Lease, now_ms: u64) -> Result<(), Error> {
        self.live()?;
        let outcome = self.core.reject_worker(lease, now_ms);
        self.persist(outcome)
    }
    pub fn finish_verification(
        &mut self,
        lease: Lease,
        result: Option<(VerifiedNode, Vec<u8>)>,
        now_ms: u64,
    ) -> Result<Completion, Error> {
        self.live()?;
        if let Some(guard) = self.verifiers.get(&lease.id()) {
            if guard.upgrade().is_some() {
                return Err("guarded verifier/result has not drained".into());
            }
            // A dropped or unwound task permits rejection, never an invented
            // successful result. Recovery still reconciles unmanaged verifiers.
            if result.is_some() {
                return Err("abandoned verification task can only be rejected".into());
            }
            self.verifiers.remove(&lease.id());
        }
        if let Some((ticket, bytes)) = &result {
            if let Err(error) = self.store.put_node(*ticket, bytes) {
                self.poisoned = self.store.needs_recovery();
                return Err(error);
            }
        }
        let outcome = self.core.finish_verification(lease, result, now_ms);
        self.persist(outcome)
    }
    pub fn cache_node(
        &mut self,
        ticket: VerifiedNode,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), Error> {
        self.live()?;
        if let Err(error) = self.store.put_node(ticket, &bytes) {
            self.poisoned = self.store.needs_recovery();
            return Err(error);
        }
        let outcome = self.core.cache_node(ticket, bytes, now_ms);
        self.persist(outcome)
    }
    pub fn candidate_result(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<Option<&[u8]>, Error> {
        self.advance(now_ms)?;
        self.core.candidate_result(candidate, eligibility, now_ms)
    }
    pub fn prune(&mut self, now_ms: u64) -> Result<Pruned, Error> {
        self.live()?;
        let outcome = self.core.prune(now_ms);
        let jobs = self.persist(outcome)?;
        match self.store.prune_to(&self.core.retained_artifacts()) {
            Ok(artifacts) => Ok(Pruned { jobs, artifacts }),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    AfterWrite,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
}
#[cfg(test)]
impl SnapshotLog {
    fn inject(&self, stage: Fault) -> Result<(), Error> {
        if self.fault == Some(stage) {
            if self.crash {
                std::process::exit(74);
            }
            Err("injected journal interruption".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
