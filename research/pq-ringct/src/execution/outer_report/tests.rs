//! Synthetic receipts exercise rejection; no dispatch authority.
use super::*;

#[test]
fn missing_or_reordered_receipts_cannot_complete_or_retry() {
    let mut sequence = Sequence::new();
    assert_eq!(sequence.timings(), Err(Error::Order));
    assert_eq!(sequence.begin(CoverageScope::RegisteredProof), Err(Error::Order));
    assert_eq!(sequence.begin(CoverageScope::Preprocessing), Err(Error::Order));
    assert_eq!(sequence.timings(), Err(Error::Order));

    // Entering validation/publication is terminal until the genuine report
    // has both validated and been published. A partial failure cannot retry.
    let mut partial = Sequence::new();
    assert_eq!(partial.begin(CoverageScope::Preprocessing), Ok(State::Identity));
    assert_eq!(partial.timings(), Err(Error::Order));
    assert_eq!(partial.begin(CoverageScope::RegisteredProof), Err(Error::Order));
}

fn observation(stage: Stage, backend: Backend) -> Observation {
    Observation {
        stage,
        backend,
        calls: 1,
        completed_calls: 1,
        device_calls: u64::from(backend == Backend::OpenCl),
        inclusive_ns: 1,
        device_ns: 1,
    }
}

struct Fixture {
    schema: &'static str,
    entry_point: &'static str,
    policy: Policy,
    profile: Profile,
    max_log_fri_arity: u8,
    scope: CoverageScope,
    capabilities: Vec<StageCapability>,
    succeeded: bool,
    stage_coverage_complete: bool,
    completion_rejected: bool,
    observation_errors: u64,
    observations: Vec<Observation>,
    component_count: usize,
}

fn check(fixture: &Fixture, scope: CoverageScope) -> Result<(), Error> {
    validate_view(
        ReportView {
            schema: fixture.schema,
            entry_point: fixture.entry_point,
            policy: fixture.policy,
            profile: fixture.profile,
            max_log_fri_arity: fixture.max_log_fri_arity,
            scope: fixture.scope,
            stages: &fixture.capabilities,
            succeeded: fixture.succeeded,
            stage_coverage_complete: fixture.stage_coverage_complete,
            completion_rejected: fixture.completion_rejected,
            observation_errors: fixture.observation_errors,
            observations: &fixture.observations,
            component_count: fixture.component_count,
        },
        scope,
    )
}

fn report(scope: CoverageScope) -> Fixture {
    let stages: Vec<_> = Stage::ARITHMETIC
        .into_iter()
        .filter(|&stage| required(scope, stage))
        .collect();
    Fixture {
        schema: "lattica-proving-stages-v1",
        entry_point: match scope {
            CoverageScope::Preprocessing => "block_v2_preprocessing",
            CoverageScope::RegisteredProof => "block_v2_registered_program",
            _ => panic!("fixed outer scope"),
        },
        policy: Policy::GpuRequired,
        profile: Profile::BlockV2Cubic,
        max_log_fri_arity: 1,
        scope,
        capabilities: stages
            .iter()
            .map(|&stage| StageCapability {
                stage,
                backend: Backend::OpenCl,
            })
            .collect(),
        succeeded: true,
        stage_coverage_complete: true,
        completion_rejected: false,
        observation_errors: 0,
        observations: stages
            .into_iter()
            .map(|stage| observation(stage, Backend::OpenCl))
            .collect(),
        component_count: 0,
    }
}

#[test]
fn setup_and_proof_reports_require_their_exact_closed_scope() {
    for scope in [CoverageScope::Preprocessing, CoverageScope::RegisteredProof] {
        let complete = report(scope);
        check(&complete, scope).unwrap();
        assert!(check(&complete, CoverageScope::Operation).is_err());
        let other = if scope == CoverageScope::Preprocessing {
            CoverageScope::RegisteredProof
        } else {
            CoverageScope::Preprocessing
        };
        assert!(check(&complete, other).is_err());
        let mutations: [fn(&mut Fixture); 11] = [
            |r: &mut Fixture| r.entry_point = "wrong entry",
            |r: &mut Fixture| r.schema = "wrong schema",
            |r: &mut Fixture| r.policy = Policy::Compatible,
            |r: &mut Fixture| r.succeeded = false,
            |r: &mut Fixture| r.stage_coverage_complete = false,
            |r: &mut Fixture| r.completion_rejected = true,
            |r: &mut Fixture| r.observation_errors = 1,
            |r: &mut Fixture| r.profile = Profile::LegacyQuadratic,
            |r: &mut Fixture| r.max_log_fri_arity = 4,
            |r: &mut Fixture| r.scope = CoverageScope::ProofRequest,
            |r: &mut Fixture| r.component_count = 1,
        ];
        for mutate in mutations {
            let mut changed = report(scope);
            mutate(&mut changed);
            assert_eq!(check(&changed, scope), Err(Error::Report));
        }
    }
}

#[test]
fn every_required_receipt_rejects_missing_duplicate_cpu_and_incomplete_execution() {
    for scope in [CoverageScope::Preprocessing, CoverageScope::RegisteredProof] {
        for index in 0..report(scope).observations.len() {
            for mutation in 0..8 {
                let mut changed = report(scope);
                match mutation {
                    0 => {
                        changed.observations.remove(index);
                    }
                    1 => changed.observations.push(observation(
                        changed.observations[index].stage,
                        Backend::OpenCl,
                    )),
                    2 => changed.observations[index].backend = Backend::Cpu,
                    3 => changed.observations[index].calls = 2,
                    4 => changed.observations[index].completed_calls = 0,
                    5 => changed.observations[index].device_calls = 0,
                    6 => changed.observations[index].device_calls = 2,
                    7 => changed.capabilities[index].backend = Backend::Mixed,
                    _ => unreachable!(),
                }
                assert_eq!(
                    check(&changed, scope),
                    Err(Error::Report),
                    "index={index} mutation={mutation}"
                );
            }
        }
    }
}

#[test]
fn only_one_completed_cpu_serialization_observation_is_optional() {
    for scope in [CoverageScope::Preprocessing, CoverageScope::RegisteredProof] {
        let mut complete = report(scope);
        complete
            .observations
            .push(observation(Stage::Serialization, Backend::Cpu));
        check(&complete, scope).unwrap();
        for mutation in 0..5 {
            let mut changed = report(scope);
            let mut extra = observation(Stage::Serialization, Backend::Cpu);
            match mutation {
                0 => extra.backend = Backend::OpenCl,
                1 => extra.device_calls = 1,
                2 => extra.completed_calls = 0,
                3 => extra.stage = Stage::UpstreamProver,
                4 => changed
                    .observations
                    .push(observation(Stage::Serialization, Backend::Cpu)),
                _ => unreachable!(),
            }
            changed.observations.push(extra);
            assert_eq!(check(&changed, scope), Err(Error::Report));
        }
    }
}
