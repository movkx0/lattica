//! Local supervised-process adapter. Paths and OS/device lifetime enforcement
//! stay here; the coordinator only sees semantic jobs, leases, and proof bytes.
use super::*;
use crate::block_v2::execution::{launch::LaunchStore, worker::typed::process::ProcessWorker};
use std::sync::{Arc, Mutex};

#[path = "local_storage.rs"]
mod storage;
pub use storage::LocalPoolStorage;

pub struct LocalProcessEndpoint {
    worker: ProcessWorker,
    launches: Arc<Mutex<LaunchStore>>,
    capabilities: WorkerCapabilities,
    context: Option<Vec<u8>>,
    active: Option<Lease>,
}

impl LocalProcessEndpoint {
    pub fn new(worker: ProcessWorker, launches: Arc<Mutex<LaunchStore>>) -> Result<Self, Error> {
        worker.persistent_storage_bytes()?;
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

    /// Install host-approved qualification before any candidate is dispatched.
    /// The caller must check the physical device/driver and complete settings;
    /// the adapter independently binds the process executable and descriptor.
    pub fn with_timing_identity(
        mut self,
        identity: super::super::scheduler::TimingIdentity,
    ) -> Result<Self, Error> {
        if self.context.is_some()
            || self.active.is_some()
            || self.capabilities.timing_identity.is_some()
        {
            return Err("pool local timing qualification already installed or active".into());
        }
        let deadline = self.capabilities.dispatch_deadline_ms;
        self.capabilities = self.worker.scheduling_capabilities_with_timing(identity)?;
        self.capabilities.dispatch_deadline_ms = deadline;
        Ok(self)
    }

    /// Explicitly forecast same-mode preprocessing retention for this qualified
    /// process. Typed process configurations retain at least their last mode;
    /// the timing identity already binds the actual cache configuration.
    /// Retirement, mode changes and process replacement still invalidate the
    /// assumed continuation. This grants no lease or process-lifetime extension.
    pub fn with_retention_forecast(mut self) -> Result<Self, Error> {
        if self.context.is_some()
            || self.active.is_some()
            || self.capabilities.timing_identity.is_none()
            || self.capabilities.forecast_retained_mode
            || self.worker.retirement_requested()
        {
            return Err("pool local retention forecast requires idle qualified process".into());
        }
        self.capabilities.forecast_retained_mode = true;
        Ok(self)
    }

    /// The host derives this cutoff from the observed service lifetime and
    /// reserves teardown time separately. Never accept a remote self-reported
    /// extension or change it after dispatch has begun. OS limits remain final.
    pub fn with_dispatch_deadline(mut self, deadline_ms: u64) -> Result<Self, Error> {
        if deadline_ms == 0
            || self.context.is_some()
            || self.active.is_some()
            || self.capabilities.dispatch_deadline_ms.is_some()
            || self.worker.retirement_requested()
        {
            return Err("pool dispatch deadline requires an idle unconfigured process".into());
        }
        self.capabilities.dispatch_deadline_ms = Some(deadline_ms);
        Ok(self)
    }
}

impl WorkerEndpoint for LocalProcessEndpoint {
    fn retirement_requested(&self) -> bool {
        self.worker.retirement_requested()
    }
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
        let prepared = self.worker.prepare_dispatch(task)?;
        let token = self
            .launches
            .lock()
            .map_err(|_| "pool launch store poisoned")?
            .issue_prepared_bound(
                owner,
                lease,
                prepared.bound_request(),
                self.worker.execution_digest()?,
            )?;
        self.worker.dispatch_prepared(&token, prepared)
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
        // The packet format already bounds each duration to u64. Keep the
        // conversion checked so unavailable diagnostics cannot fail a proof.
        let worker_timings = WorkerTimings::try_from(output.timings()).ok();
        self.capabilities.resident_mode = Some(mode);
        self.active = None;
        Ok(Some(WorkerResult {
            lease,
            proof: output.into_bytes(),
            worker_timings,
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
