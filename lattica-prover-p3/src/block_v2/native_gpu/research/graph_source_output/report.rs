//! Validate the real fixed native Run report without constructing a replacement.
use super::{Error, Result, ENTRY_POINT};
use crate::proving::{Backend, CoverageScope, Policy, Profile, Report, Stage};

fn required(stage: Stage) -> bool {
    Stage::ARITHMETIC.contains(&stage) && stage != Stage::Lookup
}

pub(super) fn validate(report: &Report) -> Result<()> {
    if report.schema != "lattica-proving-stages-v1"
        || report.entry_point != ENTRY_POINT
        || report.policy != Policy::GpuRequired
        || report.capabilities.profile() != Profile::BlockV2Cubic
        || report.capabilities.max_log_fri_arity() != 1
        || report.capabilities.scope() != CoverageScope::ProofRequest
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || !report.components.is_empty()
    {
        return Err(Error::Report);
    }
    let expected = Stage::ARITHMETIC.into_iter().filter(|&s| required(s));
    if report.capabilities.stages().len() != expected.clone().count() {
        return Err(Error::Report);
    }
    for stage in expected {
        if report
            .capabilities
            .stages()
            .iter()
            .filter(|cap| cap.stage == stage && cap.backend == Backend::OpenCl)
            .count()
            != 1
            || report
                .observations
                .iter()
                .filter(|observed| observed.stage == stage)
                .count()
                != 1
            || !report.observations.iter().any(|observed| {
                observed.stage == stage
                    && observed.backend == Backend::OpenCl
                    && observed.calls == observed.completed_calls
                    && observed.completed_calls > 0
                    && observed.device_calls > 0
                    && observed.device_calls <= observed.completed_calls
            })
        {
            return Err(Error::Report);
        }
    }
    if report
        .observations
        .iter()
        .filter(|observed| observed.stage == Stage::Serialization)
        .count()
        > 1
        || report.observations.iter().any(|observed| {
            observed.calls == 0
                || observed.calls != observed.completed_calls
                || (observed.stage == Stage::Serialization
                    && (observed.backend != Backend::Cpu || observed.device_calls != 0))
                || (observed.stage != Stage::Serialization && !required(observed.stage))
        })
    {
        return Err(Error::Report);
    }
    Ok(())
}
