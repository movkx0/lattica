//! Local supervised-process adapter. Paths and OS/device lifetime enforcement
//! stay here; the coordinator only sees semantic jobs, leases, and proof bytes.
use super::*;
use crate::block_v2::execution::{launch::LaunchStore, worker::typed::process::ProcessWorker};
use std::sync::{Arc, Mutex};

pub struct LocalProcessEndpoint {
    worker: ProcessWorker,
    launches: Arc<Mutex<LaunchStore>>,
    capabilities: WorkerCapabilities,
    context: Option<Vec<u8>>,
    active: Option<Lease>,
}

impl LocalProcessEndpoint {
    pub fn new(worker: ProcessWorker, launches: Arc<Mutex<LaunchStore>>) -> Result<Self, Error> {
        if worker.service_identity().is_none() {
            return Err("pool requires an observed supervised local process".into());
        }
        let capabilities = worker.scheduling_capabilities();
        Ok(Self {
            worker,
            launches,
            capabilities,
            context: None,
            active: None,
        })
    }
}

impl WorkerEndpoint for LocalProcessEndpoint {
    fn heartbeat(&mut self) -> Result<(), Error> {
        self.worker.heartbeat()
    }
    fn capabilities(&self) -> WorkerCapabilities {
        self.capabilities.clone()
    }

    fn set_context(&mut self, context: &PolicyContext) -> Result<(), Error> {
        if self.active.is_some() {
            return Err("pool local worker is active".into());
        }
        let bytes = context.encode();
        if self.context.as_ref() != Some(&bytes) {
            self.worker.replace_context(context)?;
            self.context = Some(bytes);
        }
        Ok(())
    }

    fn dispatch(&mut self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<(), Error> {
        if self.active.is_some()
            || self.context.is_none()
            || lease.worker() != self.capabilities.worker
        {
            return Err("pool local dispatch state/worker".into());
        }
        self.active = Some(lease);
        let task = self.worker.task(owner, lease, now_ms)?;
        let request = task.request()?;
        let token = self
            .launches
            .lock()
            .map_err(|_| "pool launch store poisoned")?
            .issue_bound(owner, lease, &request, self.worker.execution_digest()?)?;
        self.worker.dispatch(&token, task)
    }

    fn try_result(
        &mut self,
        owner: &mut DurableDag,
        now_ms: u64,
    ) -> Result<Option<WorkerResult>, Error> {
        let Some(completed) = self.worker.try_collect()? else {
            return Ok(None);
        };
        let lease = completed.lease();
        if self.active != Some(lease) {
            return Err("pool local result attempt mismatch".into());
        }
        let mut launches = self
            .launches
            .lock()
            .map_err(|_| "pool launch store poisoned")?;
        let revoked = launches.revoke(lease)?;
        let _idle = launches
            .try_idle(&revoked)?
            .ok_or("pool local launch still active")?;
        let mode = owner.leased_job(lease)?.operation().proof_mode();
        let output = completed.reconcile(owner, now_ms)?;
        self.capabilities.resident_mode = Some(mode);
        self.active = None;
        Ok(Some(WorkerResult {
            lease,
            proof: output.into_bytes(),
        }))
    }

    fn cancel(&mut self, owner: &mut DurableDag, lease: Lease, now_ms: u64) -> Result<(), Error> {
        if self.active != Some(lease) {
            return Err("pool local cancellation attempt mismatch".into());
        }
        let mut launches = self
            .launches
            .lock()
            .map_err(|_| "pool launch store poisoned")?;
        let started = Instant::now();
        self.worker
            .stop_failed_supervised(owner, &mut launches, lease, || {
                now_ms.saturating_add(
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                )
            })?;
        self.active = None;
        Ok(())
    }

    fn close(&mut self, owner: &mut DurableDag, now_ms: u64) -> Result<(), Error> {
        if self.active.is_some() {
            return Err("pool local close while active".into());
        }
        self.worker.close(owner, now_ms)
    }
}
