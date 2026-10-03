//! Bounded in-memory dependency/candidate/attempt state machine.
//!
//! This owns available immutable public artifacts and admission reservations.
//! It does not spawn workers, enforce OS quotas, persist state, check host-chain
//! eligibility, or activate a block profile. A durable service must journal a
//! transition before exposing it and revalidate artifacts after recovery.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use rand::TryRng;

use super::{
    job::{ArtifactRef, Job, JobId, Operation, RegistryPin, VerifiedNode},
    resources::Resources,
    workspace::{WorkspaceId, WorkspaceLease},
};
use crate::block_v2::{commitment::DEPTH, profile::MAX_PROOF_BYTES, recursive::Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidateId {
    session: [u8; 32],
    sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttemptId {
    session: [u8; 32],
    epoch: u64,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkerId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    id: AttemptId,
    job: JobId,
    worker: WorkerId,
    deadline_ms: u64,
}

impl Lease {
    pub fn id(self) -> AttemptId {
        self.id
    }
    pub fn job(self) -> JobId {
        self.job
    }
    pub fn worker(self) -> WorkerId {
        self.worker
    }
    pub fn deadline_ms(self) -> u64 {
        self.deadline_ms
    }

    /// Stable local process name for this exact session/epoch/attempt/job/worker.
    /// Operational metadata only; it neither grants a lease nor verifies a proof.
    pub fn process_key(self) -> Result<[u8; 32], Error> {
        let mut bytes = self.id.session.to_vec();
        bytes.extend(self.id.epoch.to_le_bytes());
        bytes.extend(self.id.sequence.to_le_bytes());
        bytes.extend(self.job.to_bytes());
        bytes.extend(self.worker.0.to_le_bytes());
        bytes.extend(self.deadline_ms.to_le_bytes());
        let mut fields = vec![1];
        fields.extend(
            bytes
                .chunks_exact(4)
                .map(|b| u64::from(u32::from_le_bytes(b.try_into().unwrap()))),
        );
        Ok(crate::block_v2::commitment::digest_bytes(
            crate::block_v2::commitment::hash_fields(0x4c42563274, &fields)?,
        )?)
    }
}

#[cfg(test)]
mod process_key_tests {
    use super::*;
    use crate::block_v2::execution::job::test_support::pin;

    #[test]
    fn process_key_binds_every_lease_identity_field() {
        let job = Job::empty(pin(), [9; 32], 0, 1).unwrap().id();
        let base = Lease {
            id: AttemptId {
                session: [7; 32],
                epoch: 1,
                sequence: 1,
            },
            job,
            worker: WorkerId(1),
            deadline_ms: 100,
        };
        let mut keys = BTreeSet::new();
        keys.insert(base.process_key().unwrap());
        for field in 0..6 {
            let mut changed = base;
            match field {
                0 => changed.id.session[0] ^= 1,
                1 => changed.id.epoch += 1,
                2 => changed.id.sequence += 1,
                3 => changed.job = Job::empty(pin(), [9; 32], 2, 1).unwrap().id(),
                4 => changed.worker = WorkerId(2),
                _ => changed.deadline_ms += 1,
            }
            assert!(keys.insert(changed.process_key().unwrap()));
        }
        assert_eq!(keys.len(), 7);
        assert_eq!(base.process_key().unwrap(), base.process_key().unwrap());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub jobs: usize,
    pub candidates: usize,
    pub attempts: usize,
    pub artifact_bytes: usize,
    pub recovery_window_ms: u64,
    pub workers: Resources,
}

impl Limits {
    fn validate(self) -> Result<(), Error> {
        self.workers.validate_capacity()?;
        if !(1..=4096).contains(&self.jobs)
            || !(1..=256).contains(&self.candidates)
            || !(1..=16384).contains(&self.attempts)
            || !(MAX_PROOF_BYTES..=512 * (1 << 20)).contains(&self.artifact_bytes)
        {
            return Err("execution graph/store limit".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Dormant,
    Waiting,
    Ready,
    Leased,
    Verifying,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStatus {
    Leased,
    Verifying,
    Completed,
    Rejected,
    Cancelled,
    Expired,
}

impl AttemptStatus {
    fn terminal(self) -> bool {
        !matches!(self, Self::Leased | Self::Verifying)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Accepted,
    Duplicate,
    Rejected,
    Fenced,
}

#[derive(Clone)]
struct Record {
    job: Job,
    wallets: Vec<Arc<[u8]>>,
    output: Option<(ArtifactRef, Arc<[u8]>)>,
    candidates: BTreeSet<CandidateId>,
    attempt: Option<AttemptId>,
    last_used_ms: u64,
}

#[derive(Clone)]
struct Candidate {
    root: JobId,
    closure: BTreeSet<JobId>,
    eligibility: [u8; 32],
    deadline_ms: u64,
    sealed: bool,
    cancelled: bool,
    last_used_ms: u64,
}

#[derive(Clone)]
struct Attempt {
    lease: Lease,
    launch_binding: Option<LaunchBinding>,
    manifest: Vec<ArtifactRef>,
    inputs: Vec<Arc<[u8]>>,
    resources: Resources,
    status: AttemptStatus,
    worker_stopped: bool,
    verification_active: bool,
    output_reserved: bool,
    released: bool,
    accepted: Option<ArtifactRef>,
    last_used_ms: u64,
}

/// Single-owner local state. Session nonces fence old handles even when an
/// external leader epoch is accidentally reused. They are never proof RNG seeds.
pub struct Dag {
    pin: RegistryPin,
    chain: [u8; 32],
    limits: Limits,
    session: [u8; 32],
    epoch: u64,
    candidate_sequence: u64,
    attempt_sequence: u64,
    workspace_sequence: u64,
    now_ms: u64,
    jobs: BTreeMap<JobId, Record>,
    candidates: BTreeMap<CandidateId, Candidate>,
    attempts: BTreeMap<AttemptId, Attempt>,
    workspaces: BTreeMap<WorkspaceId, WorkspaceLease>,
    used: Resources,
    stored_bytes: usize,
    reserved_output_bytes: usize,
    launch_root: Option<LaunchRoot>,
}

/// Local filesystem admission identity, not a public proof input or credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchRoot {
    pub(super) journal: [u64; 2],
    pub(super) store: [u64; 2],
}
impl LaunchRoot {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.journal[1] == 0 || (self.store[1] == 0 && self.store != [0; 2]) {
            return Err("launch admission directory identity".into());
        }
        Ok(())
    }
}
/// A lease cannot switch roles or supervisor locations after durable admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchBinding {
    Direct,
    /// Historical V2 binding: issuance may have happened; never infer no dispatch.
    Supervised([u8; 32]),
    /// V3 lease: no worker execution permission has been issued by this runtime.
    Unissued,
    /// Registry capacity is durable; supervisor issuance is still forbidden.
    Preparing([u8; 32]),
    /// Supervisor journal is durable and matches this exact directory identity.
    Authorized {
        path: [u8; 32],
        directory: [u64; 2],
    },
}
impl LaunchBinding {
    pub(super) fn validate(self) -> Result<(), Error> {
        match self {
            Self::Direct | Self::Unissued => (),
            Self::Supervised(path) | Self::Preparing(path) => {
                crate::block_v2::commitment::digest_from_bytes(&path)?;
            }
            Self::Authorized { path, directory } => {
                crate::block_v2::commitment::digest_from_bytes(&path)?;
                if directory[1] == 0 {
                    return Err("supervisor authorization directory".into());
                }
            }
        }
        Ok(())
    }
    pub(super) fn is_staged(self) -> bool {
        matches!(
            self,
            Self::Unissued | Self::Preparing(_) | Self::Authorized { .. }
        )
    }
}

impl Dag {
    #[cfg(target_os = "linux")]
    pub(super) fn snapshot(&self) -> Result<Vec<u8>, Error> {
        snapshot::encode(self)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn rebase_recovered(&mut self, now_ms: u64) -> Result<(), Error> {
        if !self.candidates.is_empty()
            || !self.attempts.is_empty()
            || !self.workspaces.is_empty()
            || self.used != Resources::default()
            || self.reserved_output_bytes != 0
        {
            return Err("execution recovery rebase requires a dormant graph".into());
        }
        self.now_ms = now_ms;
        for record in self.jobs.values_mut() {
            record.last_used_ms = now_ms;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn retained_artifacts(&self) -> Vec<ArtifactRef> {
        self.jobs
            .values()
            .flat_map(|r| {
                r.job
                    .wallet_inputs()
                    .iter()
                    .copied()
                    .chain(r.output.as_ref().map(|(id, _)| *id))
            })
            .collect()
    }

    /// Import an independently CPU-verified cached subtree, never a worker's
    /// unverified claim. The durable owner must publish its bytes before calling.
    #[cfg(target_os = "linux")]
    pub(super) fn cache_node(
        &mut self,
        node: VerifiedNode,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<(), Error> {
        self.advance(now_ms)?;
        node.artifact().check_bytes(&bytes)?;
        let record = self
            .jobs
            .get(&node.job())
            .ok_or("execution unknown cached job")?;
        if let Some((existing, _)) = &record.output {
            if *existing != node.artifact() {
                return Err("execution cached output cannot be replaced".into());
            }
            return Ok(());
        }
        if self
            .attempts
            .values()
            .any(|a| a.lease.job == node.job() && !a.released)
        {
            return Err("execution cached job has a live reservation".into());
        }
        self.store_admission(bytes.len())?;
        self.stored_bytes += bytes.len();
        let record = self.jobs.get_mut(&node.job()).unwrap();
        record.output = Some((node.artifact(), Arc::from(bytes)));
        record.last_used_ms = now_ms;
        Ok(())
    }

    pub fn new(
        pin: RegistryPin,
        chain: [u8; 32],
        leader_epoch: u64,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if leader_epoch == 0 {
            return Err("execution leader epoch must be nonzero".into());
        }
        let mut session = [0; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut session)
            .map_err(|e| format!("execution session entropy: {e}"))?;
        Ok(Self {
            pin,
            chain,
            limits,
            session,
            epoch: leader_epoch,
            candidate_sequence: 0,
            attempt_sequence: 0,
            workspace_sequence: 0,
            now_ms: 0,
            jobs: BTreeMap::new(),
            candidates: BTreeMap::new(),
            attempts: BTreeMap::new(),
            workspaces: BTreeMap::new(),
            used: Resources::default(),
            stored_bytes: 0,
            reserved_output_bytes: 0,
            launch_root: None,
        })
    }

    pub fn resource_use(&self) -> Resources {
        self.used
    }

    /// Reserve a whole persistent workspace lifetime, including idle time.
    /// No job launch, process identity or proof acceptance authority is issued.
    pub fn reserve_workspace(
        &mut self,
        worker: WorkerId,
        resources: Resources,
        now_ms: u64,
    ) -> Result<WorkspaceLease, Error> {
        self.advance(now_ms)?;
        resources.validate_request()?;
        if worker.0 == 0
            || self.workspaces.len() >= self.limits.attempts
            || self.workspaces.values().any(|w| w.worker == worker)
            || self
                .attempts
                .values()
                .any(|a| !a.released && a.lease.worker == worker)
        {
            return Err("execution workspace worker still reserved or history full".into());
        }
        let used = self
            .used
            .add(resources)
            .ok_or("workspace resource overflow")?;
        if !used.fits(self.limits.workers) {
            return Err("execution workspace aggregate admission".into());
        }
        let sequence = self
            .workspace_sequence
            .checked_add(1)
            .ok_or("workspace sequence overflow")?;
        let lease = WorkspaceLease {
            id: WorkspaceId {
                session: self.session,
                epoch: self.epoch,
                sequence,
            },
            worker,
            resources,
        };
        self.workspaces.insert(lease.id, lease);
        self.workspace_sequence = sequence;
        self.used = used;
        Ok(lease)
    }

    /// The caller must have dropped the actual cache and drained all users.
    /// This low-level ledger call neither stops a process nor frees memory.
    pub fn release_workspace(&mut self, lease: WorkspaceLease, now_ms: u64) -> Result<(), Error> {
        self.advance(now_ms)?;
        if self.workspaces.get(&lease.id) != Some(&lease) {
            return Err("execution stale or substituted workspace".into());
        }
        let used = self
            .used
            .subtract(lease.resources)
            .ok_or("workspace resource underflow")?;
        self.workspaces.remove(&lease.id);
        self.used = used;
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "stream"))]
    pub(super) fn check_workspace_job(
        &self,
        workspace: WorkspaceLease,
        lease: Lease,
    ) -> Result<(), Error> {
        self.attempt(lease)?;
        if self.workspaces.get(&workspace.id) != Some(&workspace)
            || lease.id.session != workspace.id.session
            || lease.id.epoch != workspace.id.epoch
            || lease.worker == workspace.worker
        {
            return Err("job does not belong to this persistent workspace owner".into());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn workspace_resources(&self) -> Result<Resources, Error> {
        self.workspaces
            .values()
            .try_fold(Resources::default(), |used, lease| {
                used.add(lease.resources)
                    .ok_or_else(|| "workspace resource overflow".into())
            })
    }
    pub fn stored_bytes(&self) -> usize {
        self.stored_bytes
    }
    pub fn reserved_output_bytes(&self) -> usize {
        self.reserved_output_bytes
    }
    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    /// Append-only dependency admission makes cycles impossible: every child
    /// must already exist, and merge geometry is recomputed from those children.
    /// Equal semantic jobs retain the first exact wallet artifacts, including
    /// while a randomized alternate public proof for the same statement arrives.
    pub fn admit(&mut self, job: Job, wallets: Vec<Vec<u8>>, now_ms: u64) -> Result<JobId, Error> {
        self.advance(now_ms)?;
        if job.pin() != self.pin || job.expected().context.chain_id != self.chain {
            return Err("execution graph profile/chain mismatch".into());
        }
        if wallets.len() != job.wallet_inputs().len() {
            return Err("execution wallet input count".into());
        }
        for (identity, bytes) in job.wallet_inputs().iter().zip(&wallets) {
            identity.check_bytes(bytes)?;
        }
        if let Some(existing) = self.jobs.get(&job.id()) {
            if !existing.job.same_semantics(&job) {
                return Err("execution job identity conflict".into());
            }
            return Ok(job.id());
        }
        if self.jobs.len() >= self.limits.jobs {
            return Err("execution graph full".into());
        }
        if job.operation() == Operation::Merge {
            if job.dependencies().len() != 2 {
                return Err("execution merge dependency count".into());
            }
            let left = &self
                .jobs
                .get(&job.dependencies()[0])
                .ok_or("execution missing left dependency")?
                .job;
            let right = &self
                .jobs
                .get(&job.dependencies()[1])
                .ok_or("execution missing right dependency")?
                .job;
            if !Job::merge(left, right)?.same_semantics(&job) {
                return Err("execution merge derivation mismatch".into());
            }
        } else if !job.dependencies().is_empty() {
            return Err("execution unexpected dependency".into());
        }
        let bytes = wallets
            .iter()
            .try_fold(0usize, |n, b| n.checked_add(b.len()))
            .ok_or("execution store arithmetic")?;
        self.store_admission(bytes)?;
        let id = job.id();
        self.jobs.insert(
            id,
            Record {
                job,
                wallets: wallets.into_iter().map(Arc::from).collect(),
                output: None,
                candidates: BTreeSet::new(),
                attempt: None,
                last_used_ms: now_ms,
            },
        );
        self.stored_bytes += bytes;
        Ok(id)
    }

    fn store_admission(&self, additional: usize) -> Result<(), Error> {
        let total = self
            .stored_bytes
            .checked_add(self.reserved_output_bytes)
            .and_then(|n| n.checked_add(additional));
        if total.is_none_or(|n| n > self.limits.artifact_bytes) {
            return Err("execution artifact store full".into());
        }
        Ok(())
    }

    /// The opaque eligibility stamp must come from host checks. This API does
    /// not decide spend validity. Only a full depth-six, nonempty root is a
    /// candidate; admitting a smaller research subtree never makes it a block.
    pub fn attach(
        &mut self,
        root: JobId,
        eligibility: [u8; 32],
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<CandidateId, Error> {
        self.advance(now_ms)?;
        if self.candidates.len() >= self.limits.candidates || deadline_ms <= now_ms {
            return Err("execution candidate limit/deadline".into());
        }
        let root_job = &self
            .jobs
            .get(&root)
            .ok_or("execution unknown candidate root")?
            .job;
        if root_job.start() != 0
            || root_job.expected().level != DEPTH
            || root_job.expected().count == 0
        {
            return Err("execution candidate requires a complete nonempty tree".into());
        }
        let mut closure = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if closure.insert(id) {
                let job = &self
                    .jobs
                    .get(&id)
                    .ok_or("execution missing dependency")?
                    .job;
                stack.extend(job.dependencies());
                if closure.len() > 127 {
                    return Err("execution candidate tree bound".into());
                }
            }
        }
        let sequence = self
            .candidate_sequence
            .checked_add(1)
            .ok_or("execution candidate sequence exhausted")?;
        let id = CandidateId {
            session: self.session,
            sequence,
        };
        for job in &closure {
            let r = self.jobs.get_mut(job).unwrap();
            r.candidates.insert(id);
            r.last_used_ms = now_ms;
        }
        self.candidates.insert(
            id,
            Candidate {
                root,
                closure,
                eligibility,
                deadline_ms,
                sealed: false,
                cancelled: false,
                last_used_ms: now_ms,
            },
        );
        self.candidate_sequence = sequence;
        Ok(id)
    }

    pub fn seal(
        &mut self,
        id: CandidateId,
        rechecked_eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        self.advance(now_ms)?;
        let c = self
            .candidates
            .get_mut(&id)
            .ok_or("execution unknown candidate")?;
        if c.cancelled || c.eligibility != rechecked_eligibility {
            return Err("execution stale/ineligible candidate".into());
        }
        c.sealed = true;
        c.last_used_ms = now_ms;
        Ok(())
    }

    /// Detach this selection, preserving shared immutable work. Any affected
    /// live attempts remain reserved until their worker/verifier is quiescent.
    pub fn cancel(&mut self, id: CandidateId, now_ms: u64) -> Result<(), Error> {
        self.advance(now_ms)?;
        self.detach(id)?;
        self.fence_unneeded()?;
        Ok(())
    }

    fn detach(&mut self, id: CandidateId) -> Result<(), Error> {
        let c = self
            .candidates
            .get_mut(&id)
            .ok_or("execution unknown candidate")?;
        if !c.cancelled {
            c.cancelled = true;
            c.last_used_ms = self.now_ms;
            for job in &c.closure {
                let r = self.jobs.get_mut(job).unwrap();
                r.candidates.remove(&id);
                r.last_used_ms = self.now_ms;
            }
        }
        Ok(())
    }

    pub fn status(&self, job: JobId) -> Result<JobStatus, Error> {
        let r = self.jobs.get(&job).ok_or("execution unknown job")?;
        if r.output.is_some() {
            return Ok(JobStatus::Completed);
        }
        if let Some(attempt) = r.attempt {
            return Ok(match self.attempts[&attempt].status {
                AttemptStatus::Verifying => JobStatus::Verifying,
                _ => JobStatus::Leased,
            });
        }
        if r.candidates.is_empty() {
            return Ok(JobStatus::Dormant);
        }
        if r.job
            .dependencies()
            .iter()
            .all(|id| self.jobs.get(id).is_some_and(|r| r.output.is_some()))
        {
            Ok(JobStatus::Ready)
        } else {
            Ok(JobStatus::Waiting)
        }
    }

    /// Earliest candidate deadline first; prepared higher-level work is next.
    /// This deterministic order is scheduling policy, never transaction order.
    pub fn ready(&self) -> Vec<JobId> {
        let mut ready: Vec<_> = self
            .jobs
            .iter()
            .filter(|(id, _)| matches!(self.status(**id), Ok(JobStatus::Ready)))
            .map(|(id, r)| {
                (
                    self.deadline(r),
                    std::cmp::Reverse(r.job.expected().level),
                    r.job.start(),
                    *id,
                )
            })
            .collect();
        ready.sort();
        ready.into_iter().map(|(_, _, _, id)| id).collect()
    }

    fn deadline(&self, r: &Record) -> u64 {
        r.candidates
            .iter()
            .filter_map(|id| self.candidates.get(id))
            .map(|c| c.deadline_ms)
            .min()
            .unwrap_or(0)
    }

    /// The caller supplies a measured remaining-path estimate, not just this
    /// job's kernel duration. Passing admission is not a latency guarantee.
    pub fn lease(
        &mut self,
        job: JobId,
        worker: WorkerId,
        resources: Resources,
        remaining_path_ms: u64,
        lease_ms: u64,
        now_ms: u64,
    ) -> Result<Lease, Error> {
        self.advance(now_ms)?;
        resources.validate_request()?;
        if self.status(job)? != JobStatus::Ready || self.attempts.len() >= self.limits.attempts {
            return Err("execution job not ready or attempt history full".into());
        }
        if worker.0 == 0
            || self.workspaces.values().any(|w| w.worker == worker)
            || self
                .attempts
                .values()
                .any(|a| !a.released && a.lease.worker == worker)
        {
            return Err("execution worker is still reserved".into());
        }
        let used = self
            .used
            .add(resources)
            .ok_or("execution resource overflow")?;
        if !used.fits(self.limits.workers) {
            return Err("execution aggregate resource admission".into());
        }
        self.store_admission(MAX_PROOF_BYTES)?;
        let record = &self.jobs[&job];
        let final_deadline = self.deadline(record);
        if remaining_path_ms == 0
            || lease_ms == 0
            || now_ms
                .checked_add(remaining_path_ms)
                .is_none_or(|end| end > final_deadline)
        {
            return Err("execution remaining path misses deadline".into());
        }
        let deadline_ms = now_ms
            .checked_add(lease_ms)
            .ok_or("execution lease overflow")?
            .min(final_deadline);
        let mut manifest = record.job.wallet_inputs().to_vec();
        let mut inputs = record.wallets.clone();
        for id in record.job.dependencies() {
            let (identity, bytes) = self.jobs[id]
                .output
                .as_ref()
                .ok_or("execution unavailable dependency")?;
            manifest.push(*identity);
            inputs.push(bytes.clone());
        }
        let sequence = self
            .attempt_sequence
            .checked_add(1)
            .ok_or("execution attempt sequence exhausted")?;
        let id = AttemptId {
            session: self.session,
            epoch: self.epoch,
            sequence,
        };
        let lease = Lease {
            id,
            job,
            worker,
            deadline_ms,
        };
        self.attempts.insert(
            id,
            Attempt {
                lease,
                launch_binding: Some(LaunchBinding::Unissued),
                manifest,
                inputs,
                resources,
                status: AttemptStatus::Leased,
                worker_stopped: false,
                verification_active: false,
                output_reserved: true,
                released: false,
                accepted: None,
                last_used_ms: now_ms,
            },
        );
        self.jobs.get_mut(&job).unwrap().attempt = Some(id);
        self.used = used;
        self.reserved_output_bytes += MAX_PROOF_BYTES;
        self.attempt_sequence = sequence;
        Ok(lease)
    }

    fn attempt(&self, lease: Lease) -> Result<&Attempt, Error> {
        let a = self
            .attempts
            .get(&lease.id)
            .ok_or("execution stale attempt")?;
        if a.lease != lease || lease.id.session != self.session || lease.id.epoch != self.epoch {
            return Err("execution attempt binding".into());
        }
        Ok(a)
    }

    pub fn attempt_status(&self, lease: Lease) -> Result<AttemptStatus, Error> {
        Ok(self.attempt(lease)?.status)
    }

    /// Inspect the immutable operation associated with a current worker lease.
    pub fn leased_job(&self, lease: Lease) -> Result<&Job, Error> {
        if self.attempt(lease)?.status != AttemptStatus::Leased {
            return Err("execution job requires current worker lease".into());
        }
        Ok(&self.jobs[&lease.job].job)
    }

    pub fn input_manifest(&self, lease: Lease) -> Result<&[ArtifactRef], Error> {
        let a = self.attempt(lease)?;
        if a.status != AttemptStatus::Leased {
            return Err("execution attempt not dispatchable".into());
        }
        Ok(&a.manifest)
    }

    /// Capture one already-admitted lease's immutable public worker inputs.
    /// The runtime must still dispatch at most once and enforce OS reservations.
    pub fn assignment(&self, lease: Lease) -> Result<super::worker::Assignment, Error> {
        let job = self.leased_job(lease)?.clone();
        let dependencies = job
            .dependencies()
            .iter()
            .map(|id| self.jobs[id].job.clone())
            .collect();
        let attempt = self.attempt(lease)?;
        super::worker::Assignment::new(
            lease,
            attempt.resources,
            job,
            dependencies,
            attempt.manifest.clone(),
            attempt.inputs.clone(),
        )
    }

    pub(super) fn check_new_launch(&self, lease: Lease, root: LaunchRoot) -> Result<(), Error> {
        root.validate()?;
        self.leased_job(lease)?;
        if self.attempt(lease)?.launch_binding != Some(LaunchBinding::Unissued)
            || self.launch_root.is_some_and(|existing| {
                existing.journal != root.journal
                    || (existing.store != [0; 2] && existing.store != root.store)
            })
        {
            return Err("launch admission already bound or namespace differs".into());
        }
        Ok(())
    }

    #[cfg(any(feature = "stream", test))]
    pub(super) fn authorize_supervisor(
        &mut self,
        lease: Lease,
        root: LaunchRoot,
        path: [u8; 32],
        directory: [u64; 2],
    ) -> Result<(), Error> {
        self.check_launch(lease, root, LaunchBinding::Preparing(path))?;
        let binding = LaunchBinding::Authorized { path, directory };
        binding.validate()?;
        self.attempts.get_mut(&lease.id).unwrap().launch_binding = Some(binding);
        Ok(())
    }

    pub(super) fn authorized_supervisor(
        &self,
        lease: Lease,
        root: LaunchRoot,
        path: [u8; 32],
    ) -> Result<LaunchBinding, Error> {
        self.leased_job(lease)?;
        match self.attempt(lease)?.launch_binding {
            Some(binding @ LaunchBinding::Authorized { path: expected, .. })
                if self.launch_root == Some(root) && expected == path =>
            {
                Ok(binding)
            }
            _ => Err("supervisor launch is not durably authorized".into()),
        }
    }

    #[cfg(feature = "stream")]
    pub(super) fn check_legacy_launch(&self, lease: Lease) -> Result<(), Error> {
        if self.launch_root.is_some() || self.attempt(lease)?.launch_binding.is_some() {
            return Err("legacy supervisor cannot bypass durable admission".into());
        }
        Ok(())
    }

    pub(super) fn pin_launch_journal(&mut self, journal: [u64; 2]) -> Result<(), Error> {
        if journal[1] == 0 || self.launch_root.is_some_and(|root| root.journal != journal) {
            return Err("DAG admission journal identity mismatch".into());
        }
        if self.launch_root.is_none() {
            self.launch_root = Some(LaunchRoot {
                journal,
                store: [0; 2],
            });
        }
        Ok(())
    }

    pub(super) fn launch_root(&self) -> Option<LaunchRoot> {
        self.launch_root
    }

    pub(super) fn bind_launch(
        &mut self,
        lease: Lease,
        root: LaunchRoot,
        binding: LaunchBinding,
    ) -> Result<(), Error> {
        root.validate()?;
        binding.validate()?;
        self.leased_job(lease)?;
        let attempt = self.attempt(lease)?;
        if self.launch_root.is_some_and(|existing| {
            existing.journal != root.journal
                || (existing.store != [0; 2] && existing.store != root.store)
        }) || attempt
            .launch_binding
            .is_some_and(|existing| existing != LaunchBinding::Unissued && existing != binding)
        {
            return Err("launch admission root/role already bound".into());
        }
        self.launch_root = Some(root);
        self.attempts.get_mut(&lease.id).unwrap().launch_binding = Some(binding);
        Ok(())
    }
    #[cfg(any(feature = "stream", test))]
    pub(super) fn check_launch(
        &self,
        lease: Lease,
        root: LaunchRoot,
        binding: LaunchBinding,
    ) -> Result<(), Error> {
        self.leased_job(lease)?;
        if self.launch_root != Some(root) || self.attempt(lease)?.launch_binding != Some(binding) {
            return Err("launch differs from durable admission".into());
        }
        Ok(())
    }

    pub fn input_bytes(&self, lease: Lease, index: usize) -> Result<&[u8], Error> {
        let a = self.attempt(lease)?;
        if a.status != AttemptStatus::Leased {
            return Err("execution attempt not dispatchable".into());
        }
        Ok(a.inputs.get(index).ok_or("execution input index")?.as_ref())
    }

    /// Call only after authoritative worker termination/event draining. This
    /// does not mean a successful result or release an active verifier's budget.
    pub fn worker_stopped(&mut self, lease: Lease, now_ms: u64) -> Result<(), Error> {
        self.advance(now_ms)?;
        self.attempt(lease)?;
        self.attempts.get_mut(&lease.id).unwrap().worker_stopped = true;
        self.release_if_quiescent(lease.id)
    }

    pub fn begin_verification(&mut self, lease: Lease, now_ms: u64) -> Result<Job, Error> {
        self.advance(now_ms)?;
        let a = self.attempt(lease)?;
        if a.status != AttemptStatus::Leased || !a.worker_stopped {
            return Err("execution verification requires current stopped worker".into());
        }
        let a = self.attempts.get_mut(&lease.id).unwrap();
        a.status = AttemptStatus::Verifying;
        a.verification_active = true;
        Ok(self.jobs[&lease.job].job.clone())
    }

    /// None records a failed CPU verification. A successful ticket must be
    /// produced by VerifiedNode::verify outside this state machine; cancellation
    /// or expiry during that work is checked again before publication.
    pub fn finish_verification(
        &mut self,
        lease: Lease,
        result: Option<(VerifiedNode, Vec<u8>)>,
        now_ms: u64,
    ) -> Result<Completion, Error> {
        self.advance(now_ms)?;
        let a = self.attempt(lease)?;
        if a.status == AttemptStatus::Completed {
            if let Some((node, bytes)) = result {
                if node.job() == lease.job && Some(node.artifact()) == a.accepted {
                    node.artifact().check_bytes(&bytes)?;
                    return Ok(Completion::Duplicate);
                }
            }
            return Err("execution completed result cannot be replaced".into());
        }
        if !a.verification_active {
            return Err("execution no verification in flight".into());
        }
        self.attempts
            .get_mut(&lease.id)
            .unwrap()
            .verification_active = false;
        if self.attempts[&lease.id].status != AttemptStatus::Verifying {
            self.release_if_quiescent(lease.id)?;
            return Ok(Completion::Fenced);
        }
        let Some((node, bytes)) = result else {
            self.terminate(lease.id, AttemptStatus::Rejected)?;
            return Ok(Completion::Rejected);
        };
        if node.job() != lease.job || node.artifact().check_bytes(&bytes).is_err() {
            self.terminate(lease.id, AttemptStatus::Rejected)?;
            return Err("execution result job/artifact mismatch".into());
        }
        let record = self
            .jobs
            .get_mut(&lease.job)
            .ok_or("execution result job missing")?;
        if record.attempt != Some(lease.id)
            || record.candidates.is_empty()
            || record.output.is_some()
        {
            self.terminate(lease.id, AttemptStatus::Cancelled)?;
            return Ok(Completion::Fenced);
        }
        let identity = node.artifact();
        self.stored_bytes += bytes.len();
        record.output = Some((identity, Arc::from(bytes)));
        record.attempt = None;
        record.last_used_ms = now_ms;
        let a = self.attempts.get_mut(&lease.id).unwrap();
        a.status = AttemptStatus::Completed;
        a.accepted = Some(identity);
        a.last_used_ms = now_ms;
        self.release_if_quiescent(lease.id)?;
        Ok(Completion::Accepted)
    }

    /// Explicit worker failure, not a successful CPU result. During CPU
    /// verification use finish_verification(None) so its lifetime is accounted.
    pub fn reject_worker(&mut self, lease: Lease, now_ms: u64) -> Result<(), Error> {
        self.advance(now_ms)?;
        let a = self.attempt(lease)?;
        if a.verification_active {
            return Err("execution verifier still active".into());
        }
        if a.status == AttemptStatus::Completed {
            return Err("execution completed attempt".into());
        }
        if !a.status.terminal() {
            self.terminate(lease.id, AttemptStatus::Rejected)?;
        }
        Ok(())
    }

    fn terminate(&mut self, id: AttemptId, status: AttemptStatus) -> Result<(), Error> {
        let a = self.attempts.get_mut(&id).unwrap();
        if !a.status.terminal() {
            a.status = status;
            a.last_used_ms = self.now_ms;
            let record = self.jobs.get_mut(&a.lease.job).unwrap();
            if record.attempt == Some(id) {
                record.attempt = None;
            }
        }
        self.release_if_quiescent(id)
    }

    fn release_if_quiescent(&mut self, id: AttemptId) -> Result<(), Error> {
        let a = self.attempts.get_mut(&id).unwrap();
        if !a.released && a.status.terminal() && a.worker_stopped && !a.verification_active {
            self.used = self
                .used
                .subtract(a.resources)
                .ok_or("execution resource accounting underflow")?;
            if a.output_reserved {
                self.reserved_output_bytes = self
                    .reserved_output_bytes
                    .checked_sub(MAX_PROOF_BYTES)
                    .ok_or("execution output accounting underflow")?;
                a.output_reserved = false;
            }
            a.inputs.clear();
            a.released = true;
            a.last_used_ms = self.now_ms;
        }
        Ok(())
    }

    fn fence_unneeded(&mut self) -> Result<(), Error> {
        let ids: Vec<_> = self
            .attempts
            .iter()
            .filter(|(_, a)| !a.status.terminal() && self.jobs[&a.lease.job].candidates.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.terminate(id, AttemptStatus::Cancelled)?;
        }
        Ok(())
    }

    /// Advance a trusted monotonic local clock. An external service must call
    /// this on its timer; this library intentionally has no background thread.
    pub fn advance(&mut self, now_ms: u64) -> Result<(), Error> {
        if now_ms < self.now_ms {
            return Err("execution clock moved backwards".into());
        }
        self.now_ms = now_ms;
        let expired: Vec<_> = self
            .candidates
            .iter()
            .filter(|(_, c)| !c.cancelled && c.deadline_ms <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.detach(id)?;
        }
        let expired: Vec<_> = self
            .attempts
            .iter()
            .filter(|(_, a)| !a.status.terminal() && a.lease.deadline_ms <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.terminate(id, AttemptStatus::Expired)?;
        }
        self.fence_unneeded()
    }

    pub fn pending_stops(&self) -> Vec<Lease> {
        self.attempts
            .values()
            .filter(|a| a.status.terminal() && !a.worker_stopped)
            .map(|a| a.lease)
            .collect()
    }

    /// Returned bytes are available only for the exact sealed selection and a
    /// freshly matching host eligibility stamp. Host atomic application remains
    /// outside this API, as do production activation and full64 qualification.
    pub fn candidate_result(
        &mut self,
        id: CandidateId,
        rechecked_eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<Option<&[u8]>, Error> {
        self.advance(now_ms)?;
        let c = self
            .candidates
            .get(&id)
            .ok_or("execution unknown candidate")?;
        if !c.sealed || c.cancelled || c.eligibility != rechecked_eligibility {
            return Err("execution candidate not sealed/current".into());
        }
        Ok(self.jobs[&c.root]
            .output
            .as_ref()
            .map(|(_, bytes)| bytes.as_ref()))
    }

    /// Conservative bounded pruning: no graph storage is released while any
    /// worker/verifier still owns an unreleased reservation. Only detached work
    /// older than the recovery window can be removed. Retained parents keep
    /// their entire dependency closure; removal is one local state transition.
    pub fn prune(&mut self, now_ms: u64) -> Result<usize, Error> {
        self.advance(now_ms)?;
        if self.attempts.values().any(|a| !a.released) {
            return Ok(0);
        }
        let window = self.limits.recovery_window_ms;
        self.candidates
            .retain(|_, c| !c.cancelled || now_ms - c.last_used_ms < window);
        self.attempts
            .retain(|_, a| now_ms - a.last_used_ms < window);
        let removable: Vec<_> = self
            .jobs
            .iter()
            .filter(|(_, r)| r.candidates.is_empty() && now_ms - r.last_used_ms >= window)
            .map(|(id, _)| *id)
            .collect();
        // Do not break a still-retained unreferenced parent's dependency graph.
        let mut keep = BTreeSet::new();
        for (id, r) in &self.jobs {
            if !removable.contains(id) {
                keep.extend(r.job.dependencies().iter().copied());
            }
        }
        let mut stack: Vec<_> = keep.iter().copied().collect();
        while let Some(id) = stack.pop() {
            for child in self.jobs[&id].job.dependencies() {
                if keep.insert(*child) {
                    stack.push(*child);
                }
            }
        }
        let mut count = 0;
        for id in removable {
            if keep.contains(&id) {
                continue;
            }
            let r = self.jobs.remove(&id).unwrap();
            let bytes: usize = r.wallets.iter().map(|b| b.len()).sum::<usize>()
                + r.output.as_ref().map_or(0, |(_, b)| b.len());
            self.stored_bytes = self
                .stored_bytes
                .checked_sub(bytes)
                .ok_or("execution store accounting underflow")?;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(target_os = "linux")]
#[path = "dag_snapshot.rs"]
pub(super) mod snapshot;
