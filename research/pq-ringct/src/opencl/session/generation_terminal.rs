//! Consumes the actual ordinary Session and returns only fixed observations.
//! No JSON, copied completion count or caller-provided retirement flag can
//! create the sealed successful-shutdown owner returned here.
use super::*;
use crate::execution::generation_terminal::{GenerationError, NativeGenerationCompletion};

#[derive(Clone, Copy, serde::Serialize)]
pub(crate) struct NativeSessionRecord {
    pub(crate) allocations: u64,
    pub(crate) commits: u64,
    pub(crate) managed_peak_bytes: usize,
    pub(crate) uploaded_bytes: u64,
    pub(crate) downloaded_bytes: u64,
    pub(crate) queue_drained: bool,
    pub(crate) context_closed: bool,
    pub(crate) managed_live_bytes: usize,
    pub(crate) host_tree_live_bytes: usize,
}

/// Even an observation/completion refusal may have a successful cleanup. This
/// nonclone object records that actual consumed Session result. Callers release
/// runtime originals only after this object exists and all context data dies.
pub(crate) struct RetiredGenerationSession {
    record: Result<NativeSessionRecord, GenerationError>,
}
impl RetiredGenerationSession {
    pub(crate) fn record(&self) -> Result<NativeSessionRecord, GenerationError> { self.record }
}

impl Session {
    pub(crate) fn retire_native_generation(mut self, completion: Option<&NativeGenerationCompletion>)
        -> Result<RetiredGenerationSession, GenerationError>
    {
        let observed = (|| {
            if self.closed || self.runtime_lifetime.is_some()
                || !self.workflow_transition.legacy_open()
                || crate::host_memory_profile::HostMemoryProfile::from_worker_bytes(self.limits.host_bytes).is_err() || self.limits.device_bytes != 8 << 30
                || self.context_bytes != 4 << 30
            { return Err(GenerationError::Authority); }
            gpu_hash::drain().map_err(|_| GenerationError::Drain)?;
            let snapshot = gpu_hash::report("owned native generation retirement")
                .ok_or(GenerationError::Observation)?;
            if snapshot.managed_peak_bytes > 8 << 30 || snapshot.commits != 0
                || snapshot.lde_commits != 0 || snapshot.opening_calls != 0
                || snapshot.device_matrices != 0
                || completion.is_some_and(|c| c.totals().spends == 0 || snapshot.allocations == 0)
            { return Err(GenerationError::Completion); }
            Ok(NativeSessionRecord { allocations: snapshot.allocations, commits: snapshot.commits,
                managed_peak_bytes: snapshot.managed_peak_bytes, uploaded_bytes: snapshot.uploaded_bytes,
                downloaded_bytes: snapshot.downloaded_bytes, queue_drained: true, context_closed: true,
                // Set only after close succeeds below. The maintained shutdown
                // checks both actual managed accounting and host-tree liveness.
                managed_live_bytes: 0, host_tree_live_bytes: 0 })
        })();
        // Never short-circuit cleanup on validation failure. An unsuccessful
        // actual shutdown returns no retirement owner and preserves quota.
        self.close().map_err(|_| GenerationError::Shutdown)?;
        if gpu_hash::report("owned native generation retired check").is_some() {
            return Err(GenerationError::Shutdown);
        }
        Ok(RetiredGenerationSession { record: observed })
    }
}
