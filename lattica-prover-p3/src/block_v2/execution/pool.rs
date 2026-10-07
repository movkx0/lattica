//! Persistent public-proof pool, independent of process launch and transport.
//!
//! A caller supplies independently checked native selections and host policies.
//! This library never creates wallet witnesses, chooses issuance, or applies a
//! chain. Returning a verified root is not a delivered-transaction receipt.

use std::{collections::BTreeMap, time::Instant};

use super::{
    dag::{CandidateId, Completion, JobStatus, Lease, WorkerId},
    job::{Job, JobId, VerifiedNode},
    journal::DurableDag,
    policy_context::PolicyContext,
    scheduler::{CostModel, WorkerCapabilities},
    selection::Selection,
};
use crate::block_v2::{recursive::Error, typed_recursive::Registry};

pub mod local;
#[cfg(test)]
mod tests;

/// Transport adapters are installed trusted code. Returned bytes and remote
/// reports are untrusted. Methods may touch only lease/workspace bookkeeping;
/// the coordinator owns proof verification and logical completion.
pub trait WorkerEndpoint {
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

pub struct WorkerResult {
    pub lease: Lease,
    pub proof: Vec<u8>,
}

pub struct AcceptedJob {
    pub job: JobId,
    pub worker: WorkerId,
    pub proof_bytes: usize,
    pub elapsed_ms: u64,
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
}

/// Workers outlive candidates. Keep one coordinator instance for the service
/// lifetime. Native head checks, durable application, and public input admission
/// happen outside this object and remain mandatory at each candidate boundary.
pub struct PoolCoordinator {
    owner: DurableDag,
    registry: Registry<12>,
    jobs: BTreeMap<JobId, Job>,
    candidates: BTreeMap<CandidateId, Candidate>,
    slots: Vec<Slot>,
    costs: CostModel,
    failures: Vec<(WorkerId, String)>,
}

impl PoolCoordinator {
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
        if cap.worker != worker || cap.profile != self.registry.id()? {
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
        if workers.is_empty() || workers.len() > 16 {
            return Err("pool worker count".into());
        }
        let profile = registry.id()?;
        let mut ids = std::collections::BTreeSet::new();
        for worker in &workers {
            let cap = worker.capabilities();
            cap.resources.validate_request()?;
            if cap.worker.0 == 0 || cap.profile != profile || !ids.insert(cap.worker) {
                return Err("pool worker identity/registry mismatch".into());
            }
        }
        Ok(Self {
            owner,
            registry,
            jobs: BTreeMap::new(),
            candidates: BTreeMap::new(),
            slots: workers
                .into_iter()
                .map(|endpoint| Slot {
                    endpoint,
                    active: None,
                    closed: false,
                })
                .collect(),
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
        if self.candidates.len() >= 8 || deadline_ms <= now_ms {
            return Err("pool candidate admission".into());
        }
        let incoming: Vec<_> = selection.jobs().cloned().collect();
        if self
            .jobs
            .len()
            .checked_add(incoming.len())
            .is_none_or(|n| n > 4096)
        {
            return Err("pool job admission".into());
        }
        for job in &incoming {
            if job.pin().profile() != self.registry.id()? {
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
        let candidate = selection.attach(&mut self.owner, eligibility, deadline_ms, now_ms)?;
        let ids = incoming.iter().map(Job::id).collect();
        for job in incoming {
            self.jobs.entry(job.id()).or_insert(job);
        }
        self.candidates.insert(
            candidate,
            Candidate {
                jobs: ids,
                context,
                deadline_ms,
            },
        );
        Ok(candidate)
    }

    pub fn seal(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<(), Error> {
        if !self.candidates.contains_key(&candidate) {
            return Err("pool unknown candidate".into());
        }
        self.owner.seal(candidate, eligibility, now_ms)
    }

    pub fn root(
        &mut self,
        candidate: CandidateId,
        eligibility: [u8; 32],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .owner
            .candidate_result(candidate, eligibility, now_ms)?
            .map(<[u8]>::to_vec))
    }

    /// Poll once; the caller controls I/O waiting and its monotonic clock. No
    /// sleep, filesystem path, GPU ordinal, or systemd detail enters scheduling.
    pub fn step(&mut self, now_ms: u64) -> Result<Vec<AcceptedJob>, Error> {
        let tick = Instant::now();
        let clock = || {
            now_ms
                .checked_add(u64::try_from(tick.elapsed().as_millis())?)
                .ok_or_else(|| -> Error { "pool clock overflow".into() })
        };
        self.owner.advance(now_ms)?;
        self.reconcile_stops(now_ms)?;
        if self.slots.iter().all(|s| s.closed) {
            return Err("pool has no surviving workers".into());
        }
        let mut accepted = Vec::new();
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
                    if self.failures.len() >= 64 {
                        return Err("pool failure report bound".into());
                    }
                    self.failures.push((
                        slot.endpoint.capabilities().worker,
                        error.to_string().chars().take(2048).collect(),
                    ));
                    continue;
                }
            };
            let active = slot.active.as_ref().ok_or("pool unexpected result")?;
            if result.lease != active.lease {
                return Err("pool substituted worker attempt".into());
            }
            let expected = self.owner.begin_verification(result.lease, clock()?)?;
            let checked = VerifiedNode::verify_typed(&expected, &self.registry, &result.proof);
            let ticket = match checked {
                Ok(ticket) => ticket,
                Err(error) => {
                    self.owner
                        .finish_verification(result.lease, None, clock()?)?;
                    slot.active = None;
                    return Err(error);
                }
            };
            let proof_bytes = result.proof.len();
            if self.owner.finish_verification(
                result.lease,
                Some((ticket, result.proof)),
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
            });
            slot.active = None;
        }
        loop {
            let workers: Vec<_> = self
                .slots
                .iter()
                .filter(|s| !s.closed && s.active.is_none())
                .map(|s| s.endpoint.capabilities())
                .collect();
            if workers.is_empty() {
                break;
            }
            let ready: Vec<_> = self
                .owner
                .ready()?
                .into_iter()
                .filter(|id| self.jobs.contains_key(id))
                .collect();
            if ready.is_empty() {
                break;
            }
            let deadlines = ready
                .iter()
                .map(|id| Ok((*id, self.owner.job_deadline(*id)?)))
                .collect::<Result<BTreeMap<_, _>, Error>>()?;
            let Some(choice) =
                self.costs
                    .select(&self.jobs, &ready, &workers, &deadlines, clock()?)?
            else {
                if self.idle() {
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
