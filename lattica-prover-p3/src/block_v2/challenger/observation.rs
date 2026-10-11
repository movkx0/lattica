use super::*;
use crate::proving::{Backend as ProvingBackend, Run, Stage};

pub(crate) struct Observation<'a> {
    run: &'a Run,
    session: DeviceSession,
    before: super::super::gpu_hash::device::SessionStats,
    stages: &'static [Stage],
}
impl CandidateChallenger {
    pub(crate) fn observe_execution<'a>(
        &self,
        run: &'a Run,
    ) -> Result<Option<Observation<'a>>, String> {
        self.observe_stages(run, &[Stage::Transcript, Stage::Grinding, Stage::Scalar])
    }

    /// FRI samples challenges and query indices but performs no PCS scalar
    /// preparation. Keep its receipts scoped to the operations it executes.
    pub(crate) fn observe_fri<'a>(&self, run: &'a Run) -> Result<Option<Observation<'a>>, String> {
        self.observe_stages(run, &[Stage::Transcript, Stage::Grinding])
    }

    fn observe_stages<'a>(
        &self,
        run: &'a Run,
        stages: &'static [Stage],
    ) -> Result<Option<Observation<'a>>, String> {
        let Backend::Gpu(gpu) = &self.inner else {
            return Ok(None);
        };
        for &stage in stages {
            run.check_device_stage(stage, ProvingBackend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        let session = gpu.session();
        let before = session
            .try_stats()
            .ok_or("GPU transcript statistics poisoned")?;
        Ok(Some(Observation {
            run,
            session,
            before,
            stages,
        }))
    }
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        let Some(after) = self.session.try_stats() else {
            return;
        };
        let pairs = [
            (
                Stage::Transcript,
                after.transcript_observations
                    + after.transcript_samples
                    + after.transcript_snapshots,
                self.before.transcript_observations
                    + self.before.transcript_samples
                    + self.before.transcript_snapshots,
                after.transcript_device_ns,
                self.before.transcript_device_ns,
            ),
            (
                Stage::Grinding,
                after.grinding_calls,
                self.before.grinding_calls,
                after.grinding_device_ns,
                self.before.grinding_device_ns,
            ),
            (
                Stage::Scalar,
                after.scalar_calls,
                self.before.scalar_calls,
                after.scalar_device_ns,
                self.before.scalar_device_ns,
            ),
        ];
        for (stage, calls, old_calls, ns, old_ns) in pairs {
            if !self.stages.contains(&stage) {
                continue;
            }
            if let (Some(calls), Some(ns)) = (calls.checked_sub(old_calls), ns.checked_sub(old_ns))
            {
                let _ = self
                    .run
                    .observe_device(stage, ProvingBackend::OpenCl, calls, ns);
            }
        }
    }
}
