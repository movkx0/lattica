//! Persistent public-proof pool, independent of process launch and transport.
//!
//! A caller supplies independently checked native selections and host policies.
//! This library never creates wallet witnesses, chooses issuance, or applies a
//! chain. Returning a verified root is not a delivered-transaction receipt.

use std::{collections::BTreeMap, time::Instant};

use super::{
    dag::{CandidateId, Completion, JobStatus, Lease, WorkerId},
    job::{Job, JobId, VerifiedNodePayload},
    journal::DurableDag,
    policy_context::PolicyContext,
    scheduler::{CostModel, TimingCalibration, WorkerCapabilities},
    selection::Selection,
};
use crate::block_v2::{
    recursive::Error,
    typed_recursive::{CheckedRegistry, Registry},
};
#[cfg(test)]
use super::job::VerifiedNode;

const MAX_WORKERS: usize = 16;
const MAX_CANDIDATES: usize = 8;
const MAX_JOBS: usize = 4096;
const MAX_FAILURES: usize = 64;
const MAX_FAILURE_CHARS: usize = 2048;
const MAX_SELECTION_JOBS: usize = 2 * crate::block_v2::commitment::CAPACITY - 1;

mod storage;
pub use storage::{PoolBookkeepingStorage, PoolStorage};
mod result_storage;
pub use result_storage::PoolOutputStorage;

// Preserve the first 2,048 Unicode characters without first allocating an
// unbounded error.to_string(). Endpoint-owned formatting work is separate.
fn failure_message(error: &dyn std::fmt::Display) -> String {
    use std::fmt::Write;
    struct Message {
        bytes: String,
        remaining: usize,
    }
    impl Write for Message {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            for ch in value.chars().take(self.remaining) {
                self.bytes.push(ch);
                self.remaining -= 1;
            }
            Ok(())
        }
    }
    let mut message = Message {
        bytes: String::with_capacity(4 * MAX_FAILURE_CHARS),
        remaining: MAX_FAILURE_CHARS,
    };
    write!(message, "{error}").expect("format pool worker failure");
    message.bytes
}

pub mod local;
#[cfg(test)]
mod tests;

/// Transport adapters are installed trusted code. Returned bytes and remote
/// reports are untrusted. Methods may touch only lease/workspace bookkeeping;
/// the coordinator owns proof verification and logical completion.
pub trait WorkerEndpoint {
    /// A completed result can remain valid while the process needs replacement.
    /// Retirement never substitutes for a physical shutdown receipt.
    fn retirement_requested(&self) -> bool {
        false
    }
    fn heartbeat(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn capabilities(&self) -> WorkerCapabilities;
    fn set_context(&mut self, context: &PolicyContext) -> Result<(), Error>;
    fn dispatch(&mut self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<(), Error>;
    fn try_result(
        &mut self,
        owner: &mut DurableDag,
        now_ms: u64,
    ) -> Result<Option<WorkerResult>, Error>;
    /// Must observe physical termination before releasing reservations. A
    /// timeout/error leaves them held; it must not manufacture a stop receipt.
    fn cancel(&mut self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<(), Error>;
    fn close(&mut self, owner: &mut DurableDag, now_ms: u64) -> Result<(), Error>;
}

/// Optional worker-local durations. These diagnostics never authorize a proof,
/// renew a lease, or replace the coordinator's elapsed time in cost admission.
/// The phases exclude coordinator verification/publication and transport waits;
/// they must not be treated as an exclusive breakdown of coordinator wall time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorkerTimings {
    pub input_verification_ms: u64,
    pub proving_ms: u64,
    pub serialization_ms: u64,
}

impl TryFrom<super::worker::Timings> for WorkerTimings {
    type Error = std::num::TryFromIntError;

    fn try_from(value: super::worker::Timings) -> Result<Self, Self::Error> {
        Ok(Self {
            input_verification_ms: value.input_verification_ms.try_into()?,
            proving_ms: value.proving_ms.try_into()?,
            serialization_ms: value.serialization_ms.try_into()?,
        })
    }
}

pub struct WorkerResult {
    pub lease: Lease,
    pub proof: Vec<u8>,
    pub worker_timings: Option<WorkerTimings>,
}

pub struct AcceptedJob {
    pub job: JobId,
    pub worker: WorkerId,
    pub proof_bytes: usize,
    pub elapsed_ms: u64,
    pub worker_timings: Option<WorkerTimings>,
}

struct Active {
    lease: Lease,
    started: Instant,
    capabilities: WorkerCapabilities,
    warm: bool,
}

struct Slot {
    endpoint: Box<dyn WorkerEndpoint>,
    active: Option<Active>,
    closed: bool,
}

struct Candidate {
    jobs: Vec<JobId>,
    context: PolicyContext,
    deadline_ms: u64,
    prefix_only: bool,
}

/// Workers outlive candidates. Keep one coordinator instance for the service
/// lifetime. Native head checks, durable application, and public input admission
/// happen outside this object and remain mandatory at each candidate boundary.
pub struct PoolCoordinator {
    owner: DurableDag,
    registry: CheckedRegistry,
    jobs: BTreeMap<JobId, Job>,
    candidates: BTreeMap<CandidateId, Candidate>,
    slots: Vec<Slot>,
    costs: CostModel,
    failures: Vec<(WorkerId, String)>,
}

impl PoolCoordinator {
    /// Export only this coordinator's CPU-verified, durably accepted live
    /// observations. The caller owns and separately budgets retained records.
    pub fn export_worker_calibration(
        &self,
        worker: WorkerId,
        job: JobId,
        warm: bool,
    ) -> Result<TimingCalibration, Error> {
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.endpoint.capabilities().worker == worker)
            .ok_or("pool unknown calibration worker")?;
        let job = self.jobs.get(&job).ok_or("pool unknown calibration job")?;
        self.costs
            .export_calibration(&slot.endpoint.capabilities(), job, warm)
    }

    /// Timing evidence is supplied/approved by the host, never a worker packet.
    /// Imports only seed scheduling; normal resource, lease, proof and deadline
    /// admission is still mandatory for every job.
    pub fn import_worker_calibration(
        &mut self,
        worker: WorkerId,
        record: &TimingCalibration,
        evidence: [u8; 32],
    ) -> Result<(), Error> {
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.endpoint.capabilities().worker == worker)
            .ok_or("pool unknown calibration worker")?;
        if slot.closed || slot.active.is_some() {
            return Err("pool calibration requires an idle live worker".into());
        }
        self.costs
            .import_calibration(&slot.endpoint.capabilities(), record, evidence)
    }

    pub fn take_failures(&mut self) -> Vec<(WorkerId, String)> {
        std::mem::take(&mut self.failures)
    }

    /// Install a replacement only after the previous endpoint has physically
    /// stopped. The transport factory reserves its workspace against this same
    /// durable owner before it can return an endpoint.
    pub fn replace_worker(
        &mut self,
        worker: WorkerId,
        build: impl FnOnce(&mut DurableDag) -> Result<Box<dyn WorkerEndpoint>, Error>,
    ) -> Result<(), Error> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.endpoint.capabilities().worker == worker)
            .ok_or("pool unknown replacement worker")?;
        if !slot.closed || slot.active.is_some() {
            return Err("pool replacement before physical stop".into());
        }
        let endpoint = build(&mut self.owner)?;
        let cap = endpoint.capabilities();
        cap.resources.validate_request()?;
        if cap.worker != worker || cap.profile != self.registry.profile() {
            return Err("pool replacement identity/profile".into());
        }
        slot.endpoint = endpoint;
        slot.closed = false;
        self.costs.forget_worker(worker);
        Ok(())
    }
    pub fn heartbeat(&mut self) -> Result<(), Error> {
        for slot in &mut self.slots {
            if !slot.closed && slot.active.is_none() {
                slot.endpoint.heartbeat()?;
            }
        }
        Ok(())
    }
    pub fn new(
        owner: DurableDag,
        registry: Registry<12>,
        workers: Vec<Box<dyn WorkerEndpoint>>,
        bootstrap_ms: u64,
    ) -> Result<Self, Error> {
        if workers.is_empty() || workers.len() > MAX_WORKERS {
            return Err("pool worker count".into());
        }
        let registry = CheckedRegistry::new(registry)?;
        let profile = registry.profile();
        let mut ids = std::collections::BTreeSet::new();
        for worker in &workers {
            let cap = worker.capabilities();
            cap.resources.validate_request()?;
            if cap.worker.0 == 0 || cap.profile != profile || !ids.insert(cap.worker) {
                return Err("pool worker identity/registry mismatch".into());
            }
        }
        let mut slots = Vec::with_capacity(workers.len());
        slots.extend(workers.into_iter().map(|endpoint| Slot {
            endpoint,
            active: None,
            closed: false,
        }));
        Ok(Self {
            owner,
            registry,
            jobs: BTreeMap::new(),
            candidates: BTreeMap::new(),
            slots,
            costs: CostModel::new(bootstrap_ms)?,
            failures: Vec::new(),
        })
    }

    pub fn submit(
        &mut self,
        selection: &Selection,
        context: PolicyContext,
        eligibility: [u8; 32],
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<CandidateId, Error> {
        if deadline_ms <= now_ms {
            return Err("pool candidate admission".into());
        }
        let incoming = self.candidate_jobs(selection, &context)?;
        let candidate = selection.attach(&mut self.owner, eligibility, deadline_ms, now_ms)?;
        self.remember_candidate(candidate, incoming, context, deadline_ms, false);
        Ok(candidate)
    }

    /// Dispatch only complete non-root subtrees of an independently checked
    /// unsealed native prefix. Final selection, native eligibility and policies
    /// must be rechecked separately; this candidate cannot be sealed or applied.
    pub fn submit_prefix(
        &mut self,
        selection: &Selection,
        context: PolicyContext,
        eligibility: [u8; 32],
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<CandidateId, Error> {
        if deadline_ms <= now_ms {
            return Err("pool prefix admission".into());
        }
        let incoming = self.prefix_jobs(selection, &context)?;
        let candidate = selection.attach(&mut self.owner, eligibility, deadline_ms, now_ms)?;
        self.remember_candidate(candidate, incoming, context, deadline_ms, true);
        Ok(candidate)
    }

    /// Adopt the exact candidate already sealed by durable recovery. The host
    /// must revalidate its head and wallet policies first. This does not attach
    /// a replacement candidate or extend the durable deadline.
    pub fn adopt_sealed(
        &mut self,
        selection: &Selection,
        context: PolicyContext,
        candidate: CandidateId,
        rechecked_eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        if self.candidates.contains_key(&candidate) {
            return Err("pool candidate already adopted".into());
        }
        let incoming = self.candidate_jobs(selection, &context)?;
        let (root, deadline_ms) =
            self.owner
                .sealed_candidate_binding(candidate, rechecked_eligibility, now_ms)?;
        if root != selection.root().id() {
            return Err("pool sealed candidate selection mismatch".into());
        }
        self.remember_candidate(candidate, incoming, context, deadline_ms, false);
        Ok(())
    }

    /// Adopt a recovered unsealed prefix without adding time or authorizing a
    /// root. Recovery and the caller must preserve the original clock domain.
    pub fn adopt_prefix(
        &mut self,
        selection: &Selection,
        context: PolicyContext,
        candidate: CandidateId,
        rechecked_eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        if self.candidates.contains_key(&candidate) {
            return Err("pool candidate already adopted".into());
        }
        let incoming = self.prefix_jobs(selection, &context)?;
        let (root, deadline_ms) =
            self.owner
                .unsealed_candidate_binding(candidate, rechecked_eligibility, now_ms)?;
        if root != selection.root().id() {
            return Err("pool prefix candidate selection mismatch".into());
        }
        self.remember_candidate(candidate, incoming, context, deadline_ms, true);
        Ok(())
    }

    fn prefix_jobs(
        &self,
        selection: &Selection,
        context: &PolicyContext,
    ) -> Result<Vec<Job>, Error> {
        let mut incoming = self.candidate_jobs(selection, context)?;
        incoming.retain(Job::is_complete_non_root_subtree);
        if incoming.is_empty() {
            return Err("pool prefix has no complete non-root subtree".into());
        }
        Ok(incoming)
    }

    fn candidate_jobs(
        &self,
        selection: &Selection,
        context: &PolicyContext,
    ) -> Result<Vec<Job>, Error> {
        if self.candidates.len() >= MAX_CANDIDATES {
            return Err("pool candidate admission".into());
        }
        self.selection_jobs(selection, context)
    }

    fn selection_jobs(
        &self,
        selection: &Selection,
        context: &PolicyContext,
    ) -> Result<Vec<Job>, Error> {
        let count = selection.jobs().len();
        if count > MAX_SELECTION_JOBS
            || self
                .jobs
                .len()
                .checked_add(count)
                .is_none_or(|n| n > MAX_JOBS)
        {
            return Err("pool job admission".into());
        }
        let mut incoming = Vec::with_capacity(count);
        incoming.extend(selection.jobs().cloned());
        for job in &incoming {
            if job.pin().profile() != self.registry.profile() {
                return Err("pool candidate registry mismatch".into());
            }
            for artifact in job.wallet_inputs() {
                context.policy(*artifact)?;
            }
            if self
                .jobs
                .get(&job.id())
                .is_some_and(|old| !old.same_semantics(job))
            {
                return Err("pool semantic job collision".into());
            }
        }
        Ok(incoming)
    }

    /// A trusted host may seal a verified extension of a complete unsealed
    /// prefix. The same durable candidate and original deadline survive. Native
    /// selection/issuance authority must be rechecked by the caller; this does
    /// not apply a block or authorize a worker-supplied selection.
    pub fn seal_prefix_extension(
        &mut self,
        candidate: CandidateId,
        selection: &Selection,
        context: PolicyContext,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        let previous = self
            .candidates
            .get(&candidate)
            .ok_or("pool unknown prefix")?;
        if !previous.prefix_only
            || context.binding() != previous.context.binding()
            || self.slots.iter().any(|slot| slot.active.is_some())
            || self.slots.iter().all(|slot| slot.closed)
        {
            return Err(
                "pool prefix transition requires its original context and idle live workers".into(),
            );
        }
        let (_, deadline_ms) =
            self.owner
                .unsealed_candidate_binding(candidate, eligibility, now_ms)?;
        if previous.deadline_ms != deadline_ms {
            return Err("pool prefix transition changed its original deadline".into());
        }
        for id in &previous.jobs {
            if self.owner.status(*id)? != JobStatus::Completed {
                return Err("pool prefix transition requires every subtree complete".into());
            }
        }
        // Retain every old wallet policy, including an incomplete odd pair.
        for job in selection.jobs() {
            for artifact in job.wallet_inputs() {
                if let Ok(old) = previous.context.policy(*artifact) {
                    use crate::block_v2::typed_recursive::Policy;
                    let same = match (old, context.policy(*artifact)?) {
                        (Policy::JoinSplit, Policy::JoinSplit) => true,
                        (
                            Policy::Htlc { expected_height: a },
                            Policy::Htlc { expected_height: b },
                        ) => a == b,
                        (
                            Policy::Issuance { authorized_mint: a },
                            Policy::Issuance { authorized_mint: b },
                        ) => a == b,
                        _ => false,
                    };
                    if !same {
                        return Err(
                            "pool prefix transition changed a retained wallet policy".into()
                        );
                    }
                }
            }
        }
        let incoming = self.selection_jobs(selection, &context)?;
        selection.admit(&mut self.owner, now_ms)?;
        self.owner
            .seal_prefix_extension(candidate, selection.root().id(), eligibility, now_ms)?;
        self.remember_candidate(candidate, incoming, context, deadline_ms, false);
        Ok(())
    }

    fn remember_candidate(
        &mut self,
        candidate: CandidateId,
        incoming: Vec<Job>,
        context: PolicyContext,
        deadline_ms: u64,
        prefix_only: bool,
    ) {
        let mut ids = Vec::with_capacity(incoming.len());
        ids.extend(incoming.iter().map(Job::id));
        for job in incoming {
            self.jobs.entry(job.id()).or_insert(job);
        }
        self.candidates.insert(
            candidate,
            Candidate {
                jobs: ids,
                context,
                deadline_ms,
                prefix_only,
            },
        );
    }

    pub fn seal(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        match self.candidates.get(&candidate) {
            None => return Err("pool unknown candidate".into()),
            Some(candidate) if candidate.prefix_only => {
                return Err("pool prefix cannot seal a native candidate".into());
            }
            Some(_) => {}
        }
        self.owner.seal(candidate, eligibility, now_ms)
    }

    pub fn root(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self
            .candidates
            .get(&candidate)
            .is_some_and(|c| c.prefix_only)
        {
            return Err("pool prefix cannot export a candidate root".into());
        }
        let Some(bytes) = self
            .owner
            .candidate_result(candidate, eligibility, now_ms)?
        else {
            return Ok(None);
        };
        if bytes.len() > PoolOutputStorage::ROOT_LIMIT {
            return Err("pool returned root storage limit".into());
        }
        Ok(Some(bytes.to_vec()))
    }

    /// Borrow one durably CPU-verified prefix subtree after rechecking scope,
    /// selection membership, eligibility and the original deadline. The caller
    /// budgets any copy; an untrusted remote result cannot enter through here.
    pub fn prefix_node(
        &mut self,
        candidate: CandidateId,
        job: JobId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<Option<&[u8]>, Error> {
        let record = self
            .candidates
            .get(&candidate)
            .ok_or("pool unknown prefix")?;
        if !record.prefix_only || !record.jobs.contains(&job) {
            return Err("pool prefix node scope or membership".into());
        }
        self.owner
            .unsealed_candidate_binding(candidate, eligibility, now_ms)?;
        self.owner.verified_node_bytes(job)
    }

    /// Visit the entire verified prefix only after every eligible subtree is
    /// complete. No callback runs for a partial prefix. Bytes remain owned by
    /// the durable coordinator; the caller budgets copies and rechecks its
    /// clock before publishing the resulting cache manifest.
    pub fn visit_complete_prefix(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
        mut visit: impl FnMut(&Job, &[u8]) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let record = self
            .candidates
            .get(&candidate)
            .ok_or("pool unknown prefix")?;
        if !record.prefix_only {
            return Err("pool prefix export scope".into());
        }
        self.owner
            .unsealed_candidate_binding(candidate, eligibility, now_ms)?;
        for job in &record.jobs {
            if self.owner.status(*job)? != JobStatus::Completed {
                return Ok(false);
            }
        }
        for id in &record.jobs {
            let job = self.jobs.get(id).ok_or("pool missing prefix job")?;
            let proof = self
                .owner
                .verified_node_bytes(*id)?
                .ok_or("pool missing prefix proof")?;
            visit(job, proof)?;
        }
        Ok(true)
    }

    /// Poll once; the caller controls I/O waiting and its monotonic clock. No
    /// sleep, filesystem path, GPU ordinal, or systemd detail enters scheduling.
    /// If no deadline-admissible placement remains after accepting results,
    /// return those completions first and reconsider placement on the next poll.
    pub fn step(&mut self, now_ms: u64) -> Result<Vec<AcceptedJob>, Error> {
        self.step_before(now_ms, u64::MAX)
    }

    /// An additional host horizon can only shorten scheduling admission. It
    /// never replaces the durable candidate deadline or a worker service window.
    pub fn step_before(
        &mut self,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<Vec<AcceptedJob>, Error> {
        if now_ms >= deadline_ms {
            return Err("pool additional dispatch deadline expired".into());
        }
        let tick = Instant::now();
        let clock = || {
            now_ms
                .checked_add(u64::try_from(tick.elapsed().as_millis())?)
                .ok_or_else(|| -> Error { "pool clock overflow".into() })
        };
        self.owner.advance(now_ms)?;
        self.reconcile_stops(now_ms)?;
        self.retire_idle_workers(clock()?)?;
        if self.slots.iter().all(|s| s.closed) {
            return Err("pool has no surviving workers".into());
        }
        let mut accepted = Vec::with_capacity(self.slots.len());
        for slot in &mut self.slots {
            if slot.closed || slot.active.is_none() {
                continue;
            }
            let result = match slot.endpoint.try_result(&mut self.owner, clock()?) {
                Ok(Some(result)) => result,
                Ok(None) => continue,
                Err(error) => {
                    let lease = slot.active.as_ref().ok_or("pool failed idle worker")?.lease;
                    // An I/O failure is not a stop receipt. Revoke the launch,
                    // observe physical exit, and only then allow another attempt.
                    slot.endpoint.cancel(&mut self.owner, lease, clock()?)?;
                    slot.active = None;
                    slot.closed = true;
                    if self.failures.len() >= MAX_FAILURES {
                        return Err("pool failure report bound".into());
                    }
                    self.failures
                        .push((slot.endpoint.capabilities().worker, failure_message(&error)));
                    continue;
                }
            };
            let active = slot.active.as_ref().ok_or("pool unexpected result")?;
            if result.lease != active.lease {
                return Err("pool substituted worker attempt".into());
            }
            let expected = self.owner.begin_verification(result.lease, clock()?)?;
            let checked =
                VerifiedNodePayload::verify_typed_checked(&expected, &self.registry, result.proof);
            let payload = match checked {
                Ok(payload) => payload,
                Err(error) => {
                    self.owner
                        .finish_verification(result.lease, None, clock()?)?;
                    slot.active = None;
                    return Err(error);
                }
            };
            let proof_bytes = payload.bytes().len();
            if self.owner.finish_verified_node(
                result.lease,
                payload,
                clock()?,
            )? != Completion::Accepted
            {
                slot.active = None;
                return Err("pool fenced completion".into());
            }
            let elapsed_ms = u64::try_from(active.started.elapsed().as_millis())?.max(1);
            self.costs
                .observe(&active.capabilities, &expected, active.warm, elapsed_ms)?;
            accepted.push(AcceptedJob {
                job: expected.id(),
                worker: result.lease.worker(),
                proof_bytes,
                elapsed_ms,
                worker_timings: result.worker_timings,
            });
            slot.active = None;
        }
        loop {
            let mut workers = Vec::with_capacity(self.slots.len());
            workers.extend(
                self.slots
                    .iter()
                    .filter(|s| {
                        !s.closed && s.active.is_none() && !s.endpoint.retirement_requested()
                    })
                    .map(|s| s.endpoint.capabilities()),
            );
            if workers.is_empty() {
                break;
            }
            let mut ready = self.owner.ready()?;
            ready.retain(|id| self.jobs.contains_key(id));
            if ready.is_empty() {
                break;
            }
            let mut deadlines = BTreeMap::new();
            for id in &ready {
                deadlines.insert(*id, self.owner.job_deadline(*id)?.min(deadline_ms));
            }
            let Some(choice) =
                self.costs
                    .select(&self.jobs, &ready, &workers, &deadlines, clock()?)?
            else {
                if self.idle() {
                    // Distinguish an exhausted physical service window from an
                    // impossible candidate path. Relax only a temporary snapshot
                    // to diagnose retirement; never issue a lease from it.
                    let had_windows = workers.iter().any(|w| w.dispatch_deadline_ms.is_some());
                    if had_windows {
                        for worker in &mut workers {
                            worker.dispatch_deadline_ms = None;
                        }
                        if let Some(expired) =
                            self.costs
                                .select(&self.jobs, &ready, &workers, &deadlines, clock()?)?
                        {
                            let slot = self
                                .slots
                                .iter_mut()
                                .find(|s| {
                                    !s.closed && s.endpoint.capabilities().worker == expired.worker
                                })
                                .ok_or("pool worker absent during service retirement")?;
                            if slot.endpoint.capabilities().dispatch_deadline_ms.is_none() {
                                return Err("pool service retirement lost its deadline".into());
                            }
                            slot.endpoint.close(&mut self.owner, clock()?)?;
                            slot.closed = true;
                            continue;
                        }
                    }
                    // These completions are already durable. Deliver their
                    // notifications before reporting an unchanged placement
                    // rejection on the next poll; never dispatch past it.
                    if !accepted.is_empty() {
                        break;
                    }
                    return Err("pool has no deadline-admissible placement".into());
                }
                break;
            };
            let context = &self
                .candidates
                .values()
                .filter(|c| c.jobs.contains(&choice.job))
                .min_by_key(|c| c.deadline_ms)
                .ok_or("pool missing candidate context")?
                .context;
            let slot = self
                .slots
                .iter_mut()
                .find(|s| !s.closed && s.endpoint.capabilities().worker == choice.worker)
                .ok_or("pool worker absent")?;
            slot.endpoint.set_context(context)?;
            let capabilities = slot.endpoint.capabilities();
            let dispatch_now = clock()?;
            let finish = dispatch_now
                .checked_add(choice.service_ms)
                .ok_or("pool service time overflow")?;
            if dispatch_now
                .checked_add(choice.remaining_path_ms)
                .is_none_or(|finish| finish > deadline_ms)
            {
                return Err("pool context negotiation exhausted host deadline".into());
            }
            // Context negotiation may consume the last available service time.
            // Recheck before creating an attempt; a failed shutdown holds the
            // reservation and leaves the slot open for physical reconciliation.
            if capabilities
                .dispatch_deadline_ms
                .is_some_and(|limit| finish > limit)
            {
                slot.endpoint.close(&mut self.owner, dispatch_now)?;
                slot.closed = true;
                continue;
            }
            let lease = self.owner.lease(
                choice.job,
                choice.worker,
                capabilities.resources,
                choice.remaining_path_ms,
                choice.service_ms.saturating_mul(2).clamp(30_000, 600_000),
                clock()?,
            )?;
            // Record ownership before dispatch: an uncertain send is active work,
            // not permission to dispatch the same worker or release its budget.
            slot.active = Some(Active {
                lease,
                started: Instant::now(),
                capabilities,
                warm: choice.warm,
            });
            slot.endpoint.dispatch(&mut self.owner, lease, clock()?)?;
        }
        Ok(accepted)
    }

    fn reconcile_stops(&mut self, now_ms: u64) -> Result<(), Error> {
        let stops = self.owner.pending_stops()?;
        for slot in &mut self.slots {
            let Some(active) = &slot.active else {
                continue;
            };
            if stops.contains(&active.lease) {
                slot.endpoint
                    .cancel(&mut self.owner, active.lease, now_ms)?;
                slot.active = None;
                slot.closed = true;
            }
        }
        Ok(())
    }

    /// Complete cooperative retirement only at idle boundaries. A failed close
    /// leaves the slot unavailable for dispatch and its reservation held.
    pub fn retire_idle_workers(&mut self, now_ms: u64) -> Result<(), Error> {
        for slot in &mut self.slots {
            if !slot.closed
                && slot.active.is_none()
                && (slot.endpoint.retirement_requested()
                    || slot
                        .endpoint
                        .capabilities()
                        .dispatch_deadline_ms
                        .is_some_and(|limit| now_ms >= limit))
            {
                slot.endpoint.close(&mut self.owner, now_ms)?;
                slot.closed = true;
            }
        }
        Ok(())
    }

    /// Release a delivered or cancelled candidate without ending worker sessions.
    /// Keep its DAG artifacts until normal reference/retention pruning permits GC.
    pub fn retire(&mut self, candidate: CandidateId, now_ms: u64) -> Result<(), Error> {
        self.owner.cancel(candidate, now_ms)?;
        self.reconcile_stops(now_ms)?;
        self.candidates
            .remove(&candidate)
            .ok_or("pool unknown candidate")?;
        self.jobs
            .retain(|id, _| self.candidates.values().any(|c| c.jobs.contains(id)));
        self.owner.prune(now_ms)?;
        Ok(())
    }

    pub fn idle(&self) -> bool {
        self.slots.iter().all(|s| s.active.is_none())
    }

    /// All adapters have acknowledged shutdown, so the host may replace them
    /// or save a drained checkpoint. An idle but still reserved worker is open.
    pub fn workers_closed(&self) -> bool {
        self.slots.iter().all(|s| s.closed)
    }

    pub fn close(&mut self, now_ms: u64) -> Result<(), Error> {
        if !self.idle() {
            return Err("pool close requires drained work".into());
        }
        for slot in &mut self.slots {
            if !slot.closed {
                slot.endpoint.close(&mut self.owner, now_ms)?;
                slot.closed = true;
            }
        }
        Ok(())
    }

    pub fn status(&self, job: JobId) -> Result<JobStatus, Error> {
        self.owner.status(job)
    }
}
