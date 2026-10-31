//! Synthetic reports test rejection only; they never authorize dispatch.
use super::*;
use lattica_prover_p3::proving::{Observation, StageCapability};

#[test]
fn exact_original_tree_overlap_preserves_worker_and_native_partitions() {
    let worker = 32u64 << 30;
    let tree = 8u64 << 30;
    for callers in [1u64 << 20, 2 << 30, 10 << 30] {
        let startup_without_trees = 96u64 << 20;
        let old_remaining = worker - callers - startup_without_trees;
        let old_native = (old_remaining - tree).min(24 << 30);
        let new_remaining = old_remaining - tree;
        let native = native_after_original_tree_claim(new_remaining, tree, tree).unwrap();
        assert_eq!(native, old_native);
        let inclusive_backend = native + tree;
        let backend_claim = inclusive_backend - tree;
        let old_total = callers + startup_without_trees + inclusive_backend;
        let new_total = callers + (startup_without_trees + tree) + backend_claim;
        assert_eq!(new_total, old_total);
        assert!(new_total <= worker && native <= 24 << 30);
    }
    for (remaining, captured, claimed) in [
        (1, tree, 0),
        (1, tree, tree - 1),
        (1, tree - 1, tree),
        (0, tree, tree),
        (u64::MAX, tree, tree),
    ] {
        assert!(native_after_original_tree_claim(remaining, captured, claimed).is_err());
    }
}

#[test]
fn additive_ocl_claim_refuses_before_startup_and_survives_owner_moves() {
    use crate::execution::retained_resources::WorkerAllowance;
    let required = FixedOuterOclStorage::fixed().unwrap().required_host_bytes() as u64;
    let short = Ledger::new(WorkerAllowance {
        host: required - 1,
        device: 8 << 30,
    });
    assert!(matches!(
        reserve_ocl_wrappers(&short),
        Err(Error::Admission(_))
    ));
    assert_eq!(short.snapshot().current, Bytes::ZERO);
    let exact = Ledger::new(WorkerAllowance {
        host: required,
        device: 0,
    });
    let token = reserve_ocl_wrappers(&exact).unwrap();
    assert!(token.belongs_to(&exact));
    assert!(!token.belongs_to(&short));
    assert_eq!(
        exact.snapshot().current,
        Bytes {
            host: required,
            device: 0
        }
    );
    assert!(matches!(
        reserve_ocl_wrappers(&exact),
        Err(Error::Admission(_))
    ));
    fn failed_phase(token: Reservation, ledger: &Ledger, required: u64) -> Result<(), Error> {
        assert!(token.belongs_to(ledger));
        assert_eq!(ledger.snapshot().current.host, required);
        Err(Error::Proof)
    }
    assert_eq!(failed_phase(token, &exact, required), Err(Error::Proof));
    assert_eq!(exact.snapshot().current, Bytes::ZERO);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let token = reserve_ocl_wrappers(&exact).unwrap();
        assert!(token.belongs_to(&exact));
        panic!("injected failure under original outer wrapper claim");
    }));
    assert!(result.is_err());
    assert_eq!(exact.snapshot().current, Bytes::ZERO);
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

mod qualification;
