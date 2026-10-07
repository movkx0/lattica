//! Inline typed execution with a persistent, separately reserved workspace.
//! The enclosing runtime enforces the supplied device/host assignment. This is
//! not an OS process supervisor; no receipt here claims process termination.

use super::*;
use crate::block_v2::execution::{
    dag::WorkerId,
    journal::{DurableDag, WorkspaceReservation, WorkspaceUse},
    workspace::WorkspaceLease,
};

pub struct Task {
    pub(super) workspace: WorkspaceUse,
    pub(super) assignment: Assignment,
}

#[cfg(test)]
#[path = "worker_typed_cached_tests.rs"]
mod tests;

impl Task {
    pub fn lease(&self) -> Lease {
        self.assignment.lease()
    }
    pub fn request(&self) -> Result<Vec<u8>, Error> {
        packet::encode_request(&self.assignment)
    }
}

pub struct CompletedJob {
    pub(super) task: Task,
    pub(super) report: Result<Output, String>,
}

impl CompletedJob {
    pub fn lease(&self) -> Lease {
        self.task.lease()
    }
    /// Releases only this job's reservation. The workspace remains owned and
    /// the untrusted proof still requires independent owner-side verification.
    pub fn reconcile(self, owner: &mut DurableDag, now_ms: u64) -> Result<Output, Error> {
        owner.acknowledge_workspace_job(&self.task.workspace, self.task.lease(), now_ms)?;
        self.report.map_err(Into::into)
    }
}

pub struct CachedTypedWorker {
    worker: Option<TypedWorker>,
    reservation: WorkspaceReservation,
    peak: Resources,
    job_resources: Resources,
    job_worker: WorkerId,
}

impl CachedTypedWorker {
    /// `peak` comes from the assigned worker's hardware admission. RAM, VRAM
    /// (managed allocations), and scratch stay reserved while idle. The outer
    /// device admission separately retains its driver/context allowance.
    /// `job_resources` reserves active CPU threads and host-owned packet/audit
    /// memory. The enclosing host plan supplies that separate memory allowance.
    pub fn new(
        owner: &mut DurableDag,
        registry: TypedRegistry<12>,
        pin: RegistryPin,
        worker_id: WorkerId,
        job_worker: WorkerId,
        peak: Resources,
        job_resources: Resources,
        now_ms: u64,
    ) -> Result<Self, Error> {
        peak.validate_capacity()?;
        job_resources.validate_request()?;
        if job_worker.0 == 0 || job_worker == worker_id {
            return Err("typed workspace requires a distinct assigned job worker".into());
        }
        if job_resources.threads != peak.threads
            || job_resources.vram_bytes != 0
            || job_resources.scratch_bytes != 0
        {
            return Err(
                "typed workspace job must reserve assigned CPU and host packet memory".into(),
            );
        }
        let mut worker = TypedWorker::new(registry, pin, peak)?;
        worker.request_resources = job_resources;
        let resident = Resources { threads: 0, ..peak };
        let reservation = owner.reserve_workspace(worker_id, resident, now_ms)?;
        Ok(Self {
            worker: Some(worker),
            reservation,
            peak,
            job_resources,
            job_worker,
        })
    }

    pub fn workspace(&self) -> Result<WorkspaceLease, Error> {
        self.reservation.lease()
    }
    pub fn stats(&self) -> Result<CacheStats, Error> {
        self.worker
            .as_ref()
            .ok_or("typed workspace is closed or poisoned")?
            .stats()
    }

    pub fn task(&self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<Task, Error> {
        self.stats()?;
        let workspace = owner.prepare_workspace_job(&self.reservation, lease, now_ms)?;
        let assignment = owner.assignment(lease)?;
        let worker = self.worker.as_ref().ok_or("typed workspace is closed")?;
        if assignment.resources() != self.job_resources
            || assignment.job().pin() != worker.pin
            || lease.worker() != self.job_worker
        {
            return Err("typed workspace task resource or registry mismatch".into());
        }
        Ok(Task {
            workspace,
            assignment,
        })
    }

    pub fn execute(
        &mut self,
        gate: WorkerGate,
        task: Task,
        policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    ) -> Result<CompletedJob, Error> {
        self.stats()?;
        if task.workspace.lease() != self.reservation.lease()? {
            return Err("typed task belongs to another workspace".into());
        }
        gate.token().require_inline()?;
        let request = task.request()?;
        let mut worker = self
            .worker
            .take()
            .ok_or("typed workspace is closed or poisoned")?;
        let report = worker
            .execute_packet(
                &gate,
                &request,
                task.assignment.job().expected().context.chain_id,
                policy,
            )
            .and_then(|bytes| {
                let decoded = packet::decode_result(&task.assignment, &request, &bytes)?;
                Ok(Output {
                    lease: task.lease(),
                    job: task.assignment.job().id(),
                    timings: decoded.timings(),
                    stats: decoded.stats(),
                    bytes: decoded.into_bytes(),
                })
            });
        // A failed GPU fence produces no completion receipt. The journal's
        // workspace and attempt reservations remain held for reconciliation.
        worker.drain()?;
        if worker.stats().is_ok() {
            self.worker = Some(worker);
        }
        drop(gate);
        Ok(CompletedJob {
            task,
            report: report.map_err(|error| error.to_string()),
        })
    }

    pub fn close(&mut self, owner: &mut DurableDag, now_ms: u64) -> Result<(), Error> {
        owner.check_workspace_reservation(&self.reservation)?;
        self.reservation.require_idle()?;
        self.worker = None;
        if self.peak.vram_bytes == 0 {
            require_cpu_backend()?;
        } else {
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            crate::block_v2::gpu_hash::shutdown()?;
            #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
            return Err("typed GPU workspace requires GPU teardown".into());
        }
        owner.release_workspace(&mut self.reservation, now_ms)
    }

    /// Drop preprocessing while retaining the entire workspace reservation.
    /// This allows the runner to capture final GPU counters before teardown.
    pub fn clear_cache(&mut self, owner: &DurableDag) -> Result<(), Error> {
        owner.check_workspace_reservation(&self.reservation)?;
        self.reservation.require_idle()?;
        self.worker = None;
        Ok(())
    }
}
