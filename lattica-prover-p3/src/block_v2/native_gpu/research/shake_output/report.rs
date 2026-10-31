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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::{Capabilities, Observation};

    fn fixture() -> Report {
        let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, false);
        let observations = Stage::ARITHMETIC
            .into_iter()
            .filter(|&s| required(s))
            .map(|stage| {
                capabilities.set(stage, Backend::OpenCl);
                Observation {
                    stage,
                    backend: Backend::OpenCl,
                    calls: 1,
                    completed_calls: 1,
                    device_calls: 1,
                    inclusive_ns: 1,
                    device_ns: 1,
                }
            })
            .collect();
        Report {
            schema: "lattica-proving-stages-v1",
            entry_point: ENTRY_POINT,
            policy: Policy::GpuRequired,
            capabilities,
            elapsed_ns: 1,
            succeeded: true,
            stage_coverage_complete: true,
            completion_rejected: false,
            observation_errors: 0,
            observations,
            components: Vec::new(),
        }
    }

    #[test]
    fn completed_native_report_requires_each_actual_device_stage() {
        let valid = fixture();
        validate(&valid).unwrap();
        for index in 0..valid.observations.len() {
            for mutation in 0..5 {
                let mut invalid = fixture();
                match mutation {
                    0 => invalid.observations[index].completed_calls = 0,
                    1 => invalid.observations[index].device_calls = 0,
                    2 => invalid.observations[index].backend = Backend::Cpu,
                    3 => {
                        invalid.observations.remove(index);
                    }
                    _ => invalid
                        .observations
                        .push(invalid.observations[index].clone()),
                }
                assert_eq!(validate(&invalid), Err(Error::Report));
            }
        }
    }

    #[test]
    fn wrong_entry_policy_scope_and_failure_are_not_fresh_native_receipts() {
        for mutation in 0..7 {
            let mut invalid = fixture();
            match mutation {
                0 => invalid.entry_point = "block_v2_registered_program",
                1 => invalid.policy = Policy::CpuRequired,
                2 => invalid.succeeded = false,
                3 => invalid.stage_coverage_complete = false,
                4 => invalid.completion_rejected = true,
                5 => invalid.observation_errors = 1,
                _ => {
                    invalid.capabilities =
                        invalid.capabilities.scoped(CoverageScope::Operation, &[])
                }
            }
            assert_eq!(validate(&invalid), Err(Error::Report));
        }
    }
}
