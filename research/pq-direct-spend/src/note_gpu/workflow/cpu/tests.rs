use super::*;
use p3_air::{
    symbolic::{get_symbolic_constraints, AirLayout},
    BaseAir,
};

#[test]
fn cpu_census_and_symbolic_geometry_match_the_fixed_original_air() {
    let plan = CpuPlan::new().unwrap();
    assert!(plan.operation_bytes < 24 << 30);
    assert!(plan.total_bytes < WORKER_HOST_BYTES);
    assert!(plan.trace_bytes >= 740_960);
    assert!(plan.transforms_bytes > 125 << 20);
    assert_eq!(plan.encoded_output_bytes, MAX_PROOF_BYTES);
    let session = DecodeSession::new(WORKER_HOST_BYTES).unwrap();
    let charge = session.reserve_for_producer(plan.symbolic_bytes).unwrap();
    let air = verification::air::VerifierAir;
    let constraints = get_symbolic_constraints::<Val, _>(&air, AirLayout::from_air(&air));
    assert_eq!(air.width(), 19);
    assert_eq!(air.num_periodic_columns(), 33);
    assert_eq!(constraints.len(), 81);
    assert_eq!(
        constraints.iter().map(|c| c.degree_multiple()).max(),
        Some(8)
    );
    drop(constraints);
    drop(charge);
    assert_eq!(session.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn cpu_complete_continuation_is_atomic_and_survives_session_retirement() {
    let context = Context([109; 32]);
    let plan = CpuPlan::new().unwrap();
    let fixture_bytes = FixturePlan::new().unwrap().required_host_bytes;
    let required = LEDGER_BYTES + fixture_bytes + plan.total_bytes;
    let short = DecodeSession::new(required - 1).unwrap();
    let fixtures = short.research_fixtures(context).unwrap();
    let baseline = short.snapshot();
    assert!(matches!(
        CpuPrepared::reserve(&short, fixtures.get(FixtureId::ALL[0]), context),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(
        short.snapshot().live_reserved_bytes,
        baseline.live_reserved_bytes
    );
    assert_eq!(
        short.snapshot().admitted_attempts,
        baseline.admitted_attempts
    );
    drop(fixtures);
    assert_eq!(short.snapshot().live_reserved_bytes, LEDGER_BYTES);

    let exact = DecodeSession::new(required).unwrap();
    let fixtures = exact.research_fixtures(context).unwrap();
    let prepared = CpuPrepared::reserve(&exact, fixtures.get(FixtureId::ALL[0]), context).unwrap();
    let marker = exact.reserve_for_producer(0).unwrap();
    assert_eq!(marker.snapshot().live_reserved_bytes, required);
    drop(exact);
    let moved = Some(prepared);
    assert_eq!(marker.snapshot().live_reserved_bytes, required);
    drop(moved);
    assert_eq!(
        marker.snapshot().live_reserved_bytes,
        LEDGER_BYTES + fixture_bytes
    );
    drop(fixtures);
    assert_eq!(marker.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn cpu_preparation_rejects_context_mismatch_without_leaking_admission() {
    let session = DecodeSession::new(WORKER_HOST_BYTES).unwrap();
    let fixtures = session.research_fixtures(Context([109; 32])).unwrap();
    let before = session.snapshot().live_reserved_bytes;
    assert!(matches!(
        CpuPrepared::reserve(
            &session,
            fixtures.get(FixtureId::ALL[0]),
            Context([110; 32])
        ),
        Err(Error::Context)
    ));
    assert_eq!(session.snapshot().live_reserved_bytes, before);
}
