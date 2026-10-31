//! Prefix work is reported separately from fresh registrations and proof work.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct IdentityPreprocessingTotals {
    pub(crate) batches: u64,
    pub(crate) programs: u64,
    pub(crate) elapsed_ns: u128,
    pub(crate) analysis_ns: u128,
    pub(crate) hash_wall_ns: u128,
    pub(crate) hash_device_ns: u128,
    pub(crate) fields: u64,
    pub(crate) uploaded_bytes: u64,
    pub(crate) downloaded_bytes: u64,
    pub(crate) reserved_host_peak_bytes: u64,
    pub(crate) reserved_managed_peak_bytes: u64,
}
impl IdentityPreprocessingTotals {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(feature = "identity-batch-experiment")]
impl IdentityPreprocessingTotals {
    fn add(self, next: Self) -> Result<Self> {
        macro_rules! sum {
            ($field:ident) => {
                self.$field
                    .checked_add(next.$field)
                    .ok_or(ObservationError::Overflow)?
            };
        }
        Ok(Self {
            batches: sum!(batches),
            programs: sum!(programs),
            elapsed_ns: sum!(elapsed_ns),
            analysis_ns: sum!(analysis_ns),
            hash_wall_ns: sum!(hash_wall_ns),
            hash_device_ns: sum!(hash_device_ns),
            fields: sum!(fields),
            uploaded_bytes: sum!(uploaded_bytes),
            downloaded_bytes: sum!(downloaded_bytes),
            reserved_host_peak_bytes: self
                .reserved_host_peak_bytes
                .max(next.reserved_host_peak_bytes),
            reserved_managed_peak_bytes: self
                .reserved_managed_peak_bytes
                .max(next.reserved_managed_peak_bytes),
        })
    }
}

#[cfg(feature = "identity-batch-experiment")]
impl ProvingContext {
    pub(in crate::execution) fn record_owned_identity_batch(
        &self,
        batch: &lattica_prover_p3::block_v2::machine::backend::identity_batch::IdentityBatchReport,
    ) -> Result<IdentityPreprocessingTotals> {
        use lattica_prover_p3::proving::{Backend, Stage};
        let report = &batch.preprocessing;
        if self.policy() != Policy::GpuRequired
            || report.policy != Policy::GpuRequired
            || batch.schema != "identity-prefix-batch-v1"
            || !(1..=16).contains(&batch.streams)
            || report.entry_point != "block_v2_identity_prefix_batch"
            || report.capabilities.profile() != Profile::BlockV2Cubic
            || report.capabilities.scope() != CoverageScope::Operation
            || !report.succeeded
            || !report.stage_coverage_complete
            || report.completion_rejected
            || report.observation_errors != 0
            || report.observations.len() != 1
            || !report.components.is_empty()
            || batch.device_ns == 0
            || batch.fields == 0
        {
            return Err(ObservationError::Report);
        }
        let stage = &report.observations[0];
        if stage.stage != Stage::Preprocessing
            || stage.backend != Backend::OpenCl
            || stage.completed_calls == 0
            || stage.device_calls != stage.completed_calls
            || stage.calls != stage.completed_calls
        {
            return Err(ObservationError::Report);
        }
        let measured = IdentityPreprocessingTotals {
            batches: 1,
            programs: batch.streams as u64,
            elapsed_ns: report.elapsed_ns,
            analysis_ns: batch.analysis_ns,
            hash_wall_ns: batch.hash_wall_ns,
            hash_device_ns: batch.device_ns,
            fields: batch.fields,
            uploaded_bytes: batch.uploaded_bytes,
            downloaded_bytes: batch.downloaded_bytes,
            reserved_host_peak_bytes: batch.footprint.host_bytes,
            reserved_managed_peak_bytes: batch.footprint.managed_bytes,
        };
        self.owned_workflow_observations.update(|mut totals| {
            totals.identity_preprocessing = totals.identity_preprocessing.add(measured)?;
            super::super::report_transport::emit(b"owned_identity_report ", report)
                .map_err(|_| ObservationError::Write)?;
            Ok(totals)
        })?;
        Ok(measured)
    }
}
