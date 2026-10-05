//! Serial inline CPU proving with one persistently budgeted preprocessing cache.
//!
//! The enclosing runtime must enforce the combined cgroup/device/scratch bounds.
//! This is not a daemon, remote-worker protocol or automatic crash reconciler.
//! Only completed public proofs are accepted; no wallet witness API is exposed.

use super::*;
use crate::block_v2::execution::{
    dag::WorkerId,
    journal::{DurableDag, WorkspaceReservation, WorkspaceUse},
    launch::WorkerGate,
    workspace::WorkspaceLease,
};

/// The entire prover peak, not just currently resident preprocessing. Retained
/// memory and mapped scratch remain covered while the allocator is unarmed/idle.
pub const WORKSPACE_RESOURCES: Resources = Resources {
    ram_bytes: 44 << 30,
    vram_bytes: 0,
    scratch_bytes: 120 << 30,
    threads: 8,
};

/// Additional per-job public inputs/result delivery and owner verification.
/// With the workspace this is 45 GiB RAM/128 GiB scratch, leaving 3 GiB host RAM
/// within the existing 48 GiB aggregate gate. These are reservations, not quotas.
pub const JOB_RESOURCES: Resources = Resources {
    ram_bytes: 1 << 30,
    vram_bytes: 0,
    scratch_bytes: 8 << 30,
    threads: 1,
};

#[must_use = "execute or discard the task; it retains a local workspace user"]
pub struct Task {
    assignment: Assignment,
    workspace: WorkspaceUse,
}

impl Task {
    pub fn lease(&self) -> Lease {
        self.assignment.lease()
    }
    pub fn request(&self) -> Result<Vec<u8>, Error> {
        packet::encode_request(&self.assignment)
    }
}

/// Returned only after the synchronous CPU producer and its launch guard have
/// drained. It is not a proof-validity ticket and does not release the cache.
#[must_use = "acknowledge local job quiescence before verifying its output"]
pub struct CompletedJob {
    task: Task,
    report: Result<Output, String>,
}

impl CompletedJob {
    pub fn lease(&self) -> Lease {
        self.task.lease()
    }

    pub fn acknowledge(self, owner: &mut DurableDag, now_ms: u64) -> Result<Output, Error> {
        owner.acknowledge_workspace_job(&self.task.workspace, self.task.lease(), now_ms)?;
        self.report.map_err(Into::into)
    }
}

pub struct CachedCpuWorker {
    // Data is dropped before its reservation, including on unwind/abandonment.
    session: Option<ConstructionSession>,
    reservation: WorkspaceReservation,
    worker: CpuWorker,
}

impl CachedCpuWorker {
    pub fn new(
        owner: &mut DurableDag,
        registry: Registry,
        pin: RegistryPin,
        worker: WorkerId,
        now_ms: u64,
    ) -> Result<Self, Error> {
        let reference = CpuWorker::new(registry.clone(), pin)?;
        let session = ConstructionSession::new(pin.construction(), registry, pin.profile())?;
        // ConstructionSession::new does not allocate/register preprocessing.
        // Reserve before its first proving call can allocate persistent data.
        let reservation = owner.reserve_workspace(worker, WORKSPACE_RESOURCES, now_ms)?;
        Ok(Self {
            session: Some(session),
            reservation,
            worker: reference,
        })
    }

    pub fn workspace(&self) -> Result<WorkspaceLease, Error> {
        self.reservation.lease()
    }

    pub fn stats(&self) -> Result<CacheStats, Error> {
        Ok(self
            .session
            .as_ref()
            .ok_or("cached worker closed or unwound")?
            .stats())
    }

    pub fn task(&self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<Task, Error> {
        require_cpu_backend()?;
        self.stats()?;
        let workspace = owner.prepare_workspace_job(&self.reservation, lease, now_ms)?;
        let assignment = owner.assignment(lease)?;
        if assignment.resources() != JOB_RESOURCES || assignment.job().pin() != self.worker.pin {
            return Err("cached CPU task budget or registry mismatch".into());
        }
        Ok(Task {
            assignment,
            workspace,
        })
    }

    /// Both task and gate are consumed: the same entered gate cannot be reused
    /// for a second cached call. An execution-bound autonomous-process token
    /// cannot be repurposed as this separate inline lifetime.
    pub fn execute(&mut self, gate: WorkerGate, task: Task) -> Result<CompletedJob, Error> {
        require_cpu_backend()?;
        self.stats()?;
        if task.workspace.lease() != self.reservation.lease()? {
            return Err("cached task belongs to another workspace".into());
        }
        gate.token().require_inline()?;
        let packet = task.request()?;
        self.worker.check_assignment_gate(
            &gate,
            &packet,
            task.assignment.job.expected().context.chain_id,
        )?;
        let started = Instant::now();
        let report = match self.worker.prepare(&task.assignment) {
            Ok(inputs) => {
                let input_verification_ms = started.elapsed().as_millis();
                self.prove(inputs, &task.assignment, input_verification_ms)
            }
            Err(error) => Err(error),
        };
        // No asynchronous device work is permitted by require_cpu_backend.
        // A returned error still represents a drained local call. A panic
        // returns no receipt; unwinding drops the taken session and poisons
        // further proving by leaving self.session empty.
        drop(gate);
        Ok(CompletedJob {
            task,
            report: report.map_err(|error| error.to_string()),
        })
    }

    fn prove(
        &mut self,
        inputs: Inputs,
        assignment: &Assignment,
        input_verification_ms: u128,
    ) -> Result<Output, Error> {
        require_cpu_backend()?;
        let mut session = self
            .session
            .take()
            .ok_or("cached worker closed or unwound")?;
        let before = session.stats();
        let _spill = crate::spill_alloc::SpillScope::arm();
        let started = Instant::now();
        let result = (|| {
            // ProverSession keeps exact immutable-program/registered-cap
            // equality and creates fresh salts/hiding randomness per prove.
            let proof = prove_inputs(&mut session, inputs, assignment.job.expected())?;
            let proving_ms = started.elapsed().as_millis();
            if proof.public
                != programs::statement(
                    assignment.job.expected(),
                    assignment.job.operation().proof_mode(),
                )
            {
                return Err("cached worker generated unexpected statement".into());
            }
            let serialized = Instant::now();
            let bytes = codec::encode_node(&proof)?;
            let after = session.stats();
            Ok(Output {
                lease: assignment.lease(),
                job: assignment.job.id(),
                bytes,
                timings: Timings {
                    input_verification_ms,
                    proving_ms,
                    serialization_ms: serialized.elapsed().as_millis(),
                },
                stats: CacheStats {
                    setups: after.setups - before.setups,
                    hits: after.hits - before.hits,
                },
            })
        })();
        if result.is_err() {
            session.clear();
        }
        self.session = Some(session);
        result
    }

    pub fn close(&mut self, owner: &mut DurableDag, now_ms: u64) -> Result<(), Error> {
        owner.check_workspace_reservation(&self.reservation)?;
        self.reservation.require_idle()?;
        if let Some(mut session) = self.session.take() {
            session.clear();
        }
        // Cache data is already gone before the durable reservation releases.
        owner.release_workspace(&mut self.reservation, now_ms)
    }
}

#[cfg(test)]
#[path = "worker_cached_tests.rs"]
mod tests;
