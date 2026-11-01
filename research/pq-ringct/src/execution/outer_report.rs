//! Exact GPU outer receipts, shared by the owned full-workflow driver.
//! These checks authenticate execution reporting only; they issue no proof,
//! memory reservation, runtime, or transaction acceptance authority.
use lattica_prover_p3::proving::{Backend, CoverageScope, Observation, Policy, Profile,
    Report, Stage, StageCapability};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { Report, Order, Write }

/// Report payloads plus this module's forwarding and streaming frames.
/// The caller separately charges its concrete scope, operation and result
/// owners. This census allocates nothing and grants no dispatch authority.
pub(crate) fn required_host_bytes() -> Result<u64, Error> {
    use core::mem::size_of;
    let mut total = lattica_prover_p3::proving::FixedProofReportStorage::fixed()
        .map_err(|_| Error::Report)?.required_host_bytes().checked_mul(2).ok_or(Error::Report)?;
    for bytes in [
        8 * size_of::<Sequence>(), 8 * size_of::<ReportView<'static>>(),
        8 * size_of::<Result<(), Error>>(), 8 * size_of::<Result<State, Error>>(),
        8 * size_of::<CoverageScope>(), 8 * size_of::<&Report>(),
        super::report_transport::required_host_bytes(),
        4 * size_of::<Result<(u128, u128), Error>>(),
        4 * size_of::<core::fmt::Arguments<'static>>(),
    ] {
        total = total.checked_add(bytes).ok_or(Error::Report)?;
    }
    u64::try_from(total).map_err(|_| Error::Report)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State { Setup, Identity, Proof, Complete, Poisoned }

/// Bounded inline record of exactly one fresh setup followed by one proof.
/// An invalid receipt or publication failure permanently closes this sequence.
pub(crate) struct Sequence {
    state: State,
    setup_ns: Option<u128>,
    proving_ns: Option<u128>,
}
impl Sequence {
    pub(crate) fn new() -> Self {
        Self { state: State::Setup, setup_ns: None, proving_ns: None }
    }

    fn begin(&mut self, scope: CoverageScope) -> Result<State, Error> {
        let previous = core::mem::replace(&mut self.state, State::Poisoned);
        match (previous, scope) {
            (State::Setup, CoverageScope::Preprocessing) => Ok(State::Identity),
            (State::Identity, CoverageScope::Operation) => Ok(State::Proof),
            (State::Proof, CoverageScope::RegisteredProof) => Ok(State::Complete),
            _ => Err(Error::Order),
        }
    }

    pub(crate) fn record(&mut self, report: &Report, scope: CoverageScope) -> Result<(), Error> {
        let next = self.begin(scope)?;
        validate_report(report, scope)?;
        // The fixed transport holds one stderr lock and latches raw write
        // failures without constructing boxed I/O or serializer diagnostics.
        // Only this genuine, validated report is published. A partial record
        // leaves the sequence poisoned and can never be retried.
        super::report_transport::emit(b"proving_stage_report ", report)
            .map_err(|_| Error::Write)?;
        match next {
            State::Identity => self.setup_ns = Some(report.elapsed_ns),
            State::Proof => {},
            State::Complete => self.proving_ns = Some(report.elapsed_ns),
            _ => unreachable!("validated receipt transition"),
        }
        self.state = next;
        Ok(())
    }

    pub(crate) fn timings(&self) -> Result<(u128, u128), Error> {
        if self.state != State::Complete { return Err(Error::Order); }
        match (self.setup_ns, self.proving_ns) {
            (Some(setup), Some(proof)) => Ok((setup, proof)),
            _ => Err(Error::Order),
        }
    }
}

fn required(scope: CoverageScope, stage: Stage) -> bool {
    match scope {
        CoverageScope::Preprocessing => matches!(
            stage,
            Stage::Preprocessing | Stage::Randomness | Stage::Transform | Stage::Commitment
        ),
        CoverageScope::RegisteredProof => {
            Stage::ARITHMETIC.contains(&stage) && stage != Stage::PublicValues
        }
        _ => false,
    }
}

// A borrowed view of the real returned report. It cannot be converted into a
// Run, capability, proof or admission; keeping it private allows mutation tests
// without widening core Capabilities construction or its visibility.
struct ReportView<'a> {
    schema: &'a str,
    entry_point: &'a str,
    policy: Policy,
    profile: Profile,
    max_log_fri_arity: u8,
    scope: CoverageScope,
    stages: &'a [StageCapability],
    succeeded: bool,
    stage_coverage_complete: bool,
    completion_rejected: bool,
    observation_errors: u64,
    observations: &'a [Observation],
    component_count: usize,
}

pub(crate) fn validate_report(report: &Report, scope: CoverageScope) -> Result<(), Error> {
    validate_view(
        ReportView {
            schema: report.schema,
            entry_point: report.entry_point,
            policy: report.policy,
            profile: report.capabilities.profile(),
            max_log_fri_arity: report.capabilities.max_log_fri_arity(),
            scope: report.capabilities.scope(),
            stages: report.capabilities.stages(),
            succeeded: report.succeeded,
            stage_coverage_complete: report.stage_coverage_complete,
            completion_rejected: report.completion_rejected,
            observation_errors: report.observation_errors,
            observations: &report.observations,
            component_count: report.components.len(),
        },
        scope,
    )
}

fn validate_view(report: ReportView<'_>, scope: CoverageScope) -> Result<(), Error> {
    if scope == CoverageScope::Operation {
        if report.schema != "lattica-proving-stages-v1" || report.entry_point != "block_v2_cpu_identity"
            || report.policy != Policy::CpuRequired || report.profile != Profile::BlockV2Cubic
            || report.max_log_fri_arity != 1 || report.scope != CoverageScope::Operation
            || !report.succeeded || !report.stage_coverage_complete || report.completion_rejected
            || report.observation_errors != 0 || report.component_count != 0 || report.stages.len() != 1
            || report.observations.len() != 1 { return Err(Error::Report); }
        let stage = &report.stages[0]; let observation = &report.observations[0];
        if stage.stage != Stage::Preprocessing || stage.backend != Backend::Cpu
            || observation.stage != Stage::Preprocessing || observation.backend != Backend::Cpu
            || observation.calls != 1 || observation.completed_calls != 1 || observation.device_calls != 0 || observation.device_ns != 0 {
            return Err(Error::Report);
        }
        return Ok(());
    }
    let entry = match scope {
        CoverageScope::Preprocessing => "block_v2_preprocessing",
        CoverageScope::RegisteredProof => "block_v2_registered_program",
        _ => return Err(Error::Report),
    };
    if report.schema != "lattica-proving-stages-v1"
        || report.entry_point != entry
        || report.policy != Policy::GpuRequired
        || report.profile != Profile::BlockV2Cubic
        || report.max_log_fri_arity != 1
        || report.scope != scope
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || report.component_count != 0
    {
        return Err(Error::Report);
    }
    let expected = Stage::ARITHMETIC
        .into_iter()
        .filter(|&stage| required(scope, stage));
    if report.stages.len() != expected.clone().count() {
        return Err(Error::Report);
    }
    for stage in expected {
        if report
            .stages
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
                || (observed.stage != Stage::Serialization && !required(scope, observed.stage))
        })
    {
        return Err(Error::Report);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
