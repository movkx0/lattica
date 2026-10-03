//! Bounded local checkpoint metadata. Proof bytes live in the artifact store.
//! This is not a network or consensus encoding. Recovery never revives leases
//! or host eligibility, and conservatively restarts the retention window.

use super::*;
use crate::block_v2::{
    execution::{
        artifact_store::ArtifactStore,
        job::{ArtifactKind, VerifiedWallet},
    },
    recursive::{Registry, WrapperConstruction},
};

pub(crate) const MAX_SNAPSHOT_BYTES: usize = 8 * (1 << 20);
const MAGIC: &[u8; 8] = b"LVDAG001";
const BOUND_MAGIC: &[u8; 8] = b"LVDAG002";
const STAGED_MAGIC: &[u8; 8] = b"LVDAG003";
const WORKSPACE_MAGIC: &[u8; 8] = b"LVDAG004";

#[derive(Clone, Debug)]
pub struct PreviousCandidate {
    pub id: CandidateId,
    pub root: JobId,
    pub eligibility: [u8; 32],
    pub deadline_ms: u64,
    pub sealed: bool,
    pub cancelled: bool,
}

#[derive(Clone, Debug)]
pub struct PreviousAttempt {
    pub lease: Lease,
    pub resources: Resources,
    pub status: AttemptStatus,
    pub worker_stopped: bool,
    pub verification_active: bool,
    pub input_manifest: Vec<ArtifactRef>,
    pub launch_binding: Option<LaunchBinding>,
    pub launch_root: Option<LaunchRoot>,
}

pub(crate) struct Restored {
    pub dag: Dag,
    pub candidates: Vec<PreviousCandidate>,
    pub attempts: Vec<PreviousAttempt>,
    pub workspaces: Vec<WorkspaceLease>,
}

fn byte(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}
fn u32le(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    out.extend(u32::try_from(value)?.to_le_bytes());
    Ok(())
}
fn u64le(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_le_bytes());
}
fn resources(out: &mut Vec<u8>, value: Resources) {
    u64le(out, value.ram_bytes);
    u64le(out, value.vram_bytes);
    u64le(out, value.scratch_bytes);
    out.extend(value.threads.to_le_bytes());
}
fn artifact(out: &mut Vec<u8>, value: ArtifactRef) {
    byte(
        out,
        match value.kind() {
            ArtifactKind::Wallet => 1,
            ArtifactKind::Node => 2,
        },
    );
    out.extend(value.byte_len().to_le_bytes());
    out.extend(value.digest_bytes());
}
fn construction(value: RegistryPin) -> u8 {
    match value.construction() {
        WrapperConstruction::SingleWallet => 1,
        WrapperConstruction::GroupedPair => 2,
    }
}
fn operation(value: Operation) -> u8 {
    match value {
        Operation::Wrap => 1,
        Operation::WrapPair => 2,
        Operation::Empty => 3,
        Operation::Merge => 4,
    }
}
fn attempt_status(value: AttemptStatus) -> Result<u8, Error> {
    Ok(match value {
        AttemptStatus::Leased => 1,
        AttemptStatus::Verifying => 2,
        AttemptStatus::Rejected => 3,
        AttemptStatus::Cancelled => 4,
        AttemptStatus::Expired => 5,
        AttemptStatus::Completed => {
            return Err("checkpoint completed reservation is not released".into())
        }
    })
}

pub(super) fn encode(dag: &Dag) -> Result<Vec<u8>, Error> {
    let base = encode_base(dag)?;
    if dag.workspaces.is_empty() {
        return Ok(base);
    }
    if dag.workspaces.len() > dag.limits.attempts {
        return Err("checkpoint workspace count bound".into());
    }
    let mut out = WORKSPACE_MAGIC.to_vec();
    u32le(&mut out, base.len())?;
    out.extend(base);
    u64le(&mut out, dag.workspace_sequence);
    u32le(&mut out, dag.workspaces.len())?;
    let mut workers: BTreeSet<_> = dag
        .attempts
        .values()
        .filter(|a| !a.released)
        .map(|a| a.lease.worker)
        .collect();
    for (id, lease) in &dag.workspaces {
        lease.resources.validate_request()?;
        if *id != lease.id
            || id.session != dag.session
            || id.epoch != dag.epoch
            || id.sequence == 0
            || id.sequence > dag.workspace_sequence
            || lease.worker.0 == 0
            || !workers.insert(lease.worker)
        {
            return Err("checkpoint workspace identity".into());
        }
        u64le(&mut out, id.sequence);
        u64le(&mut out, lease.worker.0);
        resources(&mut out, lease.resources);
    }
    if out.len() > MAX_SNAPSHOT_BYTES {
        return Err("checkpoint workspace byte bound".into());
    }
    Ok(out)
}

fn encode_base(dag: &Dag) -> Result<Vec<u8>, Error> {
    dag.limits.validate()?;
    let unassigned_store = dag.launch_root.is_some_and(|root| root.store == [0; 2]);
    let staged = unassigned_store
        || dag
            .attempts
            .values()
            .any(|a| !a.released && a.launch_binding.is_some_and(LaunchBinding::is_staged));
    if staged && dag.launch_root.is_none() {
        return Err("staged checkpoint requires pinned journal".into());
    }
    let mut out = if staged {
        STAGED_MAGIC
    } else if dag.launch_root.is_some() {
        BOUND_MAGIC
    } else {
        MAGIC
    }
    .to_vec();
    out.extend(dag.pin.profile());
    byte(&mut out, construction(dag.pin));
    out.extend(dag.chain);
    out.extend(dag.session);
    u64le(&mut out, dag.epoch);
    u64le(&mut out, dag.now_ms);
    u64le(&mut out, dag.candidate_sequence);
    u64le(&mut out, dag.attempt_sequence);
    u32le(&mut out, dag.limits.jobs)?;
    u32le(&mut out, dag.limits.candidates)?;
    u32le(&mut out, dag.limits.attempts)?;
    u64le(&mut out, dag.limits.artifact_bytes as u64);
    u64le(&mut out, dag.limits.recovery_window_ms);
    resources(&mut out, dag.limits.workers);
    let mut jobs: Vec<_> = dag.jobs.values().collect();
    jobs.sort_by_key(|r| (r.job.expected().level, r.job.start(), r.job.id()));
    u32le(&mut out, jobs.len())?;
    let mut logical = 0usize;
    for record in jobs {
        let job = &record.job;
        out.extend(job.id().to_bytes());
        byte(&mut out, operation(job.operation()));
        byte(&mut out, job.start());
        byte(&mut out, job.expected().level);
        byte(&mut out, job.wallet_inputs().len() as u8);
        for identity in job.wallet_inputs() {
            artifact(&mut out, *identity);
            logical = logical
                .checked_add(identity.byte_len() as usize)
                .ok_or("checkpoint artifact overflow")?;
        }
        byte(&mut out, job.dependencies().len() as u8);
        for id in job.dependencies() {
            out.extend(id.to_bytes());
        }
        byte(&mut out, u8::from(record.output.is_some()));
        if let Some((identity, bytes)) = &record.output {
            if bytes.len() != identity.byte_len() as usize {
                return Err("checkpoint output length invariant".into());
            }
            artifact(&mut out, *identity);
            logical = logical
                .checked_add(bytes.len())
                .ok_or("checkpoint artifact overflow")?;
        }
    }
    if logical != dag.stored_bytes {
        return Err("checkpoint stored-byte invariant".into());
    }
    u32le(&mut out, dag.candidates.len())?;
    for (id, c) in &dag.candidates {
        if id.session != dag.session {
            return Err("checkpoint candidate session".into());
        }
        u64le(&mut out, id.sequence);
        out.extend(c.root.to_bytes());
        out.extend(c.eligibility);
        u64le(&mut out, c.deadline_ms);
        byte(&mut out, u8::from(c.sealed));
        byte(&mut out, u8::from(c.cancelled));
    }
    let attempts: Vec<_> = dag.attempts.values().filter(|a| !a.released).collect();
    u32le(&mut out, attempts.len())?;
    let mut used = Resources::default();
    let mut reserved = 0usize;
    for a in attempts {
        if a.lease.id.session != dag.session
            || a.lease.id.epoch != dag.epoch
            || !a.output_reserved
            || a.accepted.is_some()
        {
            return Err("checkpoint attempt invariant".into());
        }
        u64le(&mut out, a.lease.id.sequence);
        out.extend(a.lease.job.to_bytes());
        u64le(&mut out, a.lease.worker.0);
        u64le(&mut out, a.lease.deadline_ms);
        resources(&mut out, a.resources);
        byte(&mut out, attempt_status(a.status)?);
        byte(&mut out, u8::from(a.worker_stopped));
        byte(&mut out, u8::from(a.verification_active));
        byte(&mut out, a.manifest.len() as u8);
        for identity in &a.manifest {
            artifact(&mut out, *identity);
        }
        used = used
            .add(a.resources)
            .ok_or("checkpoint reservation overflow")?;
        reserved = reserved
            .checked_add(MAX_PROOF_BYTES)
            .ok_or("checkpoint output reservation overflow")?;
    }
    if staged {
        byte(&mut out, 1);
    }
    if let Some(root) = dag.launch_root {
        root.validate()?;
        for value in root.journal.into_iter().chain(root.store) {
            u64le(&mut out, value);
        }
    }
    if staged || dag.launch_root.is_some() {
        let bindings: Vec<_> = dag
            .attempts
            .values()
            .filter(|a| !a.released && a.launch_binding.is_some())
            .collect();
        u32le(&mut out, bindings.len())?;
        for a in bindings {
            u64le(&mut out, a.lease.id.sequence);
            let binding = a.launch_binding.unwrap();
            binding.validate()?;
            if unassigned_store && binding != LaunchBinding::Unissued {
                return Err("attempt launch binding without assigned store".into());
            }
            match binding {
                LaunchBinding::Direct => byte(&mut out, 1),
                LaunchBinding::Supervised(path) => {
                    byte(&mut out, 2);
                    out.extend(path);
                }
                LaunchBinding::Unissued => byte(&mut out, 3),
                LaunchBinding::Preparing(path) => {
                    byte(&mut out, 4);
                    out.extend(path);
                }
                LaunchBinding::Authorized { path, directory } => {
                    byte(&mut out, 5);
                    out.extend(path);
                    for value in directory {
                        u64le(&mut out, value);
                    }
                }
            }
        }
    }
    let total = used
        .add(dag.workspace_resources()?)
        .ok_or("checkpoint resource overflow")?;
    if total != dag.used
        || !total.fits(dag.limits.workers)
        || reserved != dag.reserved_output_bytes
        || out.len() > MAX_SNAPSHOT_BYTES
    {
        return Err("checkpoint aggregate invariant or size".into());
    }
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or("checkpoint offset overflow")?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated checkpoint")?
            .try_into()?;
        self.offset = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("noncanonical checkpoint boolean".into()),
        }
    }
    fn u32(&mut self) -> Result<usize, Error> {
        Ok(u32::from_le_bytes(self.take()?) as usize)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn count(&mut self, max: usize) -> Result<usize, Error> {
        let n = self.u32()?;
        if n > max {
            Err("checkpoint count bound".into())
        } else {
            Ok(n)
        }
    }
    fn resources(&mut self) -> Result<Resources, Error> {
        Ok(Resources {
            ram_bytes: self.u64()?,
            vram_bytes: self.u64()?,
            scratch_bytes: self.u64()?,
            threads: u32::from_le_bytes(self.take()?),
        })
    }
    fn job(&mut self) -> Result<JobId, Error> {
        JobId::from_bytes(self.take()?)
    }
    fn artifact(&mut self) -> Result<ArtifactRef, Error> {
        let kind = match self.byte()? {
            1 => ArtifactKind::Wallet,
            2 => ArtifactKind::Node,
            _ => return Err("checkpoint artifact kind".into()),
        };
        let len = u32::from_le_bytes(self.take()?);
        ArtifactRef::from_descriptor(kind, len, self.take()?)
    }
    fn artifacts(&mut self) -> Result<Vec<ArtifactRef>, Error> {
        let n = self.byte()? as usize;
        if n > 2 {
            return Err("checkpoint input count".into());
        }
        (0..n).map(|_| self.artifact()).collect()
    }
}

struct RawJob {
    id: JobId,
    op: Operation,
    start: u8,
    level: u8,
    wallets: Vec<ArtifactRef>,
    dependencies: Vec<JobId>,
    output: Option<ArtifactRef>,
}

pub(crate) fn restore(
    bytes: &[u8],
    pin: RegistryPin,
    registry: &Registry,
    chain: [u8; 32],
    epoch: u64,
    limits: Limits,
    store: &ArtifactStore,
) -> Result<Restored, Error> {
    RegistryPin::new(registry, pin.profile(), pin.construction())?;
    restore_with(
        bytes,
        pin,
        chain,
        epoch,
        limits,
        |identity| store.load_wallet(identity, pin, registry, chain),
        |job, identity| store.load_node(identity, job, registry),
    )
}

// The live caller always uses restore above. Test callbacks can supply tiny
// cfg(test)-only tickets; there is no public switch bypassing CPU revalidation.
pub(crate) fn restore_with(
    bytes: &[u8],
    pin: RegistryPin,
    chain: [u8; 32],
    epoch: u64,
    limits: Limits,
    wallet: impl FnMut(ArtifactRef) -> Result<(VerifiedWallet, Vec<u8>), Error>,
    node: impl FnMut(&Job, ArtifactRef) -> Result<(VerifiedNode, Vec<u8>), Error>,
) -> Result<Restored, Error> {
    limits.validate()?;
    let (base, workspaces) = split_workspaces(bytes, limits)?;
    restore_base_with(base, pin, chain, epoch, limits, workspaces, wallet, node)
}

type RawWorkspace = (u64, WorkerId, Resources);

// Validate the entire outer envelope before the base snapshot can load proofs.
// Nesting LVDAG004 is forbidden; snapshots without workspaces keep old bytes.
fn split_workspaces(bytes: &[u8], limits: Limits) -> Result<(&[u8], Vec<RawWorkspace>), Error> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("checkpoint byte bound".into());
    }
    if !bytes.starts_with(WORKSPACE_MAGIC) {
        return Ok((bytes, Vec::new()));
    }
    let mut r = Reader { bytes, offset: 8 };
    let len = r.count(MAX_SNAPSHOT_BYTES)?;
    let end = r
        .offset
        .checked_add(len)
        .ok_or("workspace base offset overflow")?;
    let base = bytes.get(r.offset..end).ok_or("truncated workspace base")?;
    if ![MAGIC, BOUND_MAGIC, STAGED_MAGIC]
        .iter()
        .any(|magic| base.starts_with(*magic))
    {
        return Err("workspace base snapshot version/nesting".into());
    }
    r.offset = end;
    let sequence = r.u64()?;
    let count = r.count(limits.attempts)?;
    if count == 0 || sequence == 0 {
        return Err("noncanonical empty workspace envelope".into());
    }
    let mut workspaces = Vec::with_capacity(count);
    let mut previous = 0;
    let mut workers = BTreeSet::new();
    let mut used = Resources::default();
    for _ in 0..count {
        let id = r.u64()?;
        let worker = WorkerId(r.u64()?);
        let resources = r.resources()?;
        resources.validate_request()?;
        if id <= previous || id > sequence || worker.0 == 0 || !workers.insert(worker) {
            return Err("checkpoint workspace order/identity".into());
        }
        previous = id;
        used = used
            .add(resources)
            .ok_or("checkpoint workspace reservation sum")?;
        if !used.fits(limits.workers) {
            return Err("checkpoint workspace resource budget".into());
        }
        workspaces.push((id, worker, resources));
    }
    if r.offset != bytes.len() {
        return Err("checkpoint workspace trailing bytes".into());
    }
    Ok((base, workspaces))
}

fn restore_base_with(
    bytes: &[u8],
    pin: RegistryPin,
    chain: [u8; 32],
    epoch: u64,
    limits: Limits,
    raw_workspaces: Vec<RawWorkspace>,
    mut wallet: impl FnMut(ArtifactRef) -> Result<(VerifiedWallet, Vec<u8>), Error>,
    mut node: impl FnMut(&Job, ArtifactRef) -> Result<(VerifiedNode, Vec<u8>), Error>,
) -> Result<Restored, Error> {
    limits.validate()?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("checkpoint byte bound".into());
    }
    let mut r = Reader { bytes, offset: 0 };
    let magic = r.take::<8>()?;
    let bound = &magic == BOUND_MAGIC;
    let staged = &magic == STAGED_MAGIC;
    if (!bound && !staged && &magic != MAGIC)
        || r.take::<32>()? != pin.profile()
        || r.byte()? != construction(pin)
        || r.take::<32>()? != chain
    {
        return Err("checkpoint schema/profile/construction/chain".into());
    }
    let session = r.take::<32>()?;
    let old_epoch = r.u64()?;
    let old_now = r.u64()?;
    let candidate_sequence = r.u64()?;
    let attempt_sequence = r.u64()?;
    let recorded_limits = Limits {
        jobs: r.count(4096)?,
        candidates: r.count(256)?,
        attempts: r.count(16384)?,
        artifact_bytes: usize::try_from(r.u64()?)?,
        recovery_window_ms: r.u64()?,
        workers: r.resources()?,
    };
    if old_epoch == 0 || epoch <= old_epoch || recorded_limits != limits {
        return Err("checkpoint epoch/configuration mismatch".into());
    }
    let workspaces: Vec<_> = raw_workspaces
        .into_iter()
        .map(|(sequence, worker, resources)| WorkspaceLease {
            id: WorkspaceId {
                session,
                epoch: old_epoch,
                sequence,
            },
            worker,
            resources,
        })
        .collect();
    let count = r.count(limits.jobs)?;
    let mut raw: Vec<RawJob> = Vec::with_capacity(count);
    let mut seen = BTreeMap::new();
    let mut logical = 0usize;
    for _ in 0..count {
        let id = r.job()?;
        let op = match r.byte()? {
            1 => Operation::Wrap,
            2 => Operation::WrapPair,
            3 => Operation::Empty,
            4 => Operation::Merge,
            _ => return Err("checkpoint operation".into()),
        };
        let start = r.byte()?;
        let level = r.byte()?;
        if level > DEPTH {
            return Err("checkpoint level".into());
        }
        let wallets = r.artifacts()?;
        if wallets.iter().any(|a| a.kind() != ArtifactKind::Wallet) {
            return Err("checkpoint wallet kind".into());
        }
        let n = r.byte()? as usize;
        if n > 2 {
            return Err("checkpoint dependency count".into());
        }
        let dependencies: Vec<_> = (0..n).map(|_| r.job()).collect::<Result<_, _>>()?;
        if dependencies.iter().any(|id| !seen.contains_key(id)) {
            return Err("checkpoint forward/missing dependency".into());
        }
        if seen.insert(id, raw.len()).is_some() {
            return Err("checkpoint duplicate job".into());
        }
        let output = if r.boolean()? {
            Some(r.artifact()?)
        } else {
            None
        };
        if output.is_some_and(|a| a.kind() != ArtifactKind::Node) {
            return Err("checkpoint node kind".into());
        }
        let shape = match op {
            Operation::Wrap => (1, 0),
            Operation::WrapPair => (2, 0),
            Operation::Empty => (0, 0),
            Operation::Merge => (0, 2),
        };
        if (wallets.len(), dependencies.len()) != shape {
            return Err("checkpoint operation arity".into());
        }
        let width = 1usize << level;
        if start as usize % width != 0 || start as usize + width > (1 << DEPTH) {
            return Err("checkpoint ordered range".into());
        }
        match op {
            Operation::Wrap
                if level != 0 || pin.construction() != WrapperConstruction::SingleWallet =>
            {
                return Err("checkpoint single wrapper geometry".into())
            }
            Operation::WrapPair
                if level != 1 || pin.construction() != WrapperConstruction::GroupedPair =>
            {
                return Err("checkpoint paired wrapper geometry".into())
            }
            Operation::Merge => {
                let left = &raw[seen[&dependencies[0]]];
                let right = &raw[seen[&dependencies[1]]];
                if level == 0
                    || left.level + 1 != level
                    || right.level + 1 != level
                    || left.start != start
                    || right.start as usize != start as usize + width / 2
                {
                    return Err("checkpoint ordered dependency geometry".into());
                }
            }
            _ => {}
        }
        for a in wallets.iter().copied().chain(output) {
            logical = logical
                .checked_add(a.byte_len() as usize)
                .ok_or("checkpoint artifact sum")?;
        }
        if logical > limits.artifact_bytes {
            return Err("checkpoint artifact budget".into());
        }
        raw.push(RawJob {
            id,
            op,
            start,
            level,
            wallets,
            dependencies,
            output,
        });
    }
    let count = r.count(limits.candidates)?;
    let mut candidates = Vec::with_capacity(count);
    let mut candidate_ids = BTreeSet::new();
    for _ in 0..count {
        let sequence = r.u64()?;
        if sequence == 0 || sequence > candidate_sequence || !candidate_ids.insert(sequence) {
            return Err("checkpoint candidate identity".into());
        }
        let root = r.job()?;
        let eligibility = r.take()?;
        let deadline_ms = r.u64()?;
        let sealed = r.boolean()?;
        let cancelled = r.boolean()?;
        if !seen.contains_key(&root) || (!cancelled && deadline_ms <= old_now) {
            return Err("checkpoint candidate root/deadline".into());
        }
        candidates.push(PreviousCandidate {
            id: CandidateId { session, sequence },
            root,
            eligibility,
            deadline_ms,
            sealed,
            cancelled,
        });
    }
    let count = r.count(limits.attempts)?;
    let mut attempts = Vec::with_capacity(count);
    let mut attempt_ids = BTreeSet::new();
    let mut workers: BTreeSet<_> = workspaces.iter().map(|w| w.worker).collect();
    let mut active = BTreeSet::new();
    let mut used = workspaces
        .iter()
        .try_fold(Resources::default(), |used, w| {
            used.add(w.resources)
                .ok_or("checkpoint workspace reservation sum")
        })?;
    for _ in 0..count {
        let sequence = r.u64()?;
        let job = r.job()?;
        let worker = WorkerId(r.u64()?);
        let deadline_ms = r.u64()?;
        let resources = r.resources()?;
        resources.validate_request()?;
        let status = match r.byte()? {
            1 => AttemptStatus::Leased,
            2 => AttemptStatus::Verifying,
            3 => AttemptStatus::Rejected,
            4 => AttemptStatus::Cancelled,
            5 => AttemptStatus::Expired,
            _ => return Err("checkpoint attempt status".into()),
        };
        let worker_stopped = r.boolean()?;
        let verification_active = r.boolean()?;
        let input_manifest = r.artifacts()?;
        if sequence == 0
            || sequence > attempt_sequence
            || !attempt_ids.insert(sequence)
            || worker.0 == 0
            || !workers.insert(worker)
            || deadline_ms == 0
            || !seen.contains_key(&job)
        {
            return Err("checkpoint attempt identity".into());
        }
        if verification_active && !worker_stopped
            || status == AttemptStatus::Verifying && !verification_active
            || matches!(status, AttemptStatus::Leased | AttemptStatus::Rejected)
                && verification_active
            || status.terminal() && worker_stopped && !verification_active
            || !status.terminal() && (deadline_ms <= old_now || !active.insert(job))
            || status == AttemptStatus::Expired && deadline_ms > old_now
        {
            return Err("checkpoint attempt lifecycle".into());
        }
        used = used.add(resources).ok_or("checkpoint reservation sum")?;
        if !used.fits(limits.workers) {
            return Err("checkpoint resource budget".into());
        }
        let lease = Lease {
            id: AttemptId {
                session,
                epoch: old_epoch,
                sequence,
            },
            job,
            worker,
            deadline_ms,
        };
        attempts.push(PreviousAttempt {
            lease,
            resources,
            status,
            worker_stopped,
            verification_active,
            input_manifest,
            launch_binding: None,
            launch_root: None,
        });
    }
    let has_root = if staged { r.boolean()? } else { bound };
    if staged && !has_root {
        return Err("staged checkpoint requires pinned journal".into());
    }
    let launch_root = if has_root {
        let root = LaunchRoot {
            journal: [r.u64()?, r.u64()?],
            store: [r.u64()?, r.u64()?],
        };
        root.validate()?;
        if bound && root.store == [0; 2] {
            return Err("historical bound checkpoint requires assigned store".into());
        }
        Some(root)
    } else {
        None
    };
    if bound || staged {
        let n = r.count(attempts.len())?;
        let indices: BTreeMap<_, _> = attempts
            .iter()
            .enumerate()
            .map(|(i, a)| (a.lease.id.sequence, i))
            .collect();
        let mut previous = 0;
        let mut saw_staged = false;
        for _ in 0..n {
            let sequence = r.u64()?;
            if sequence <= previous {
                return Err("launch admission order/duplicate".into());
            }
            previous = sequence;
            let binding = match r.byte()? {
                1 => LaunchBinding::Direct,
                2 => LaunchBinding::Supervised(r.take()?),
                3 if staged => LaunchBinding::Unissued,
                4 if staged => LaunchBinding::Preparing(r.take()?),
                5 if staged => LaunchBinding::Authorized {
                    path: r.take()?,
                    directory: [r.u64()?, r.u64()?],
                },
                _ => return Err("launch admission role".into()),
            };
            binding.validate()?;
            if launch_root.is_some_and(|root| root.store == [0; 2])
                && binding != LaunchBinding::Unissued
            {
                return Err("attempt launch binding without assigned store".into());
            }
            saw_staged |= binding.is_staged();
            let index = *indices
                .get(&sequence)
                .ok_or("launch admission missing attempt")?;
            attempts[index].launch_binding = Some(binding);
        }
        if staged && !saw_staged && !launch_root.is_some_and(|root| root.store == [0; 2]) {
            return Err("noncanonical staged checkpoint".into());
        }
    }
    for attempt in &mut attempts {
        attempt.launch_root = launch_root;
    }
    if r.offset != bytes.len()
        || logical
            .checked_add(
                count
                    .checked_mul(MAX_PROOF_BYTES)
                    .ok_or("checkpoint output reserve")?,
            )
            .is_none_or(|n| n > limits.artifact_bytes)
    {
        return Err("checkpoint trailing bytes/output budget".into());
    }
    // Validate all metadata before performing expensive CPU proof recovery.
    let mut owned = BTreeSet::new();
    for c in &candidates {
        let root = &raw[seen[&c.root]];
        if root.start != 0 || root.level != DEPTH || root.op == Operation::Empty {
            return Err("checkpoint candidate shape".into());
        }
        if !c.cancelled {
            let mut stack = vec![c.root];
            let mut closure = BTreeSet::new();
            while let Some(id) = stack.pop() {
                if closure.insert(id) {
                    stack.extend(&raw[seen[&id]].dependencies);
                }
            }
            if closure.len() > 127 {
                return Err("checkpoint candidate graph bound".into());
            }
            owned.extend(closure);
        }
    }
    for a in &attempts {
        let job = &raw[seen[&a.lease.job]];
        let mut expected = job.wallets.clone();
        for id in &job.dependencies {
            expected.push(
                raw[seen[id]]
                    .output
                    .ok_or("checkpoint unavailable frozen input")?,
            );
        }
        if a.input_manifest != expected
            || (!a.status.terminal() && (!owned.contains(&a.lease.job) || job.output.is_some()))
        {
            return Err("checkpoint attempt input/candidate binding".into());
        }
    }
    let mut dag = Dag::new(pin, chain, epoch, limits)?;
    dag.launch_root = launch_root;
    for entry in raw {
        let mut tickets = Vec::new();
        let mut wallet_bytes = Vec::new();
        for identity in entry.wallets {
            let (ticket, bytes) = wallet(identity)?;
            if ticket.artifact() != identity {
                return Err("checkpoint wallet ticket binding".into());
            }
            identity.check_bytes(&bytes)?;
            tickets.push(ticket);
            wallet_bytes.push(bytes);
        }
        let job = match entry.op {
            Operation::Wrap => Job::wrap(entry.start, tickets[0])?,
            Operation::WrapPair => Job::wrap_pair(entry.start, tickets[0], tickets[1])?,
            Operation::Empty => Job::empty(pin, chain, entry.start, entry.level)?,
            Operation::Merge => Job::merge(
                &dag.jobs[&entry.dependencies[0]].job,
                &dag.jobs[&entry.dependencies[1]].job,
            )?,
        };
        if job.id() != entry.id || job.start() != entry.start || job.expected().level != entry.level
        {
            return Err("checkpoint derived job mismatch".into());
        }
        dag.admit(job.clone(), wallet_bytes, 0)?;
        if let Some(identity) = entry.output {
            let (ticket, bytes) = node(&job, identity)?;
            if ticket.job() != job.id() || ticket.artifact() != identity {
                return Err("checkpoint node ticket binding".into());
            }
            dag.cache_node(ticket, bytes, 0)?;
        }
    }
    for c in &candidates {
        if dag.jobs[&c.root].job.expected().count == 0 {
            return Err("checkpoint empty candidate".into());
        }
    }
    Ok(Restored {
        dag,
        candidates,
        attempts,
        workspaces,
    })
}
