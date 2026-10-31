use super::*;

#[test]
fn report_refuses_short_preclaim_and_reserves_the_closed_observation_keyspace() {
    let resources = NoteReportResources::new().unwrap();
    let policy = WorkerPolicyAbsent::capture().unwrap();
    assert!(NoteRun::new(resources.required_host_bytes - 1, &policy).is_err());
    let note = NoteRun::new(resources.required_host_bytes, &policy).unwrap();
    assert_eq!(note.run.entry_point, ENTRY);
    assert_eq!(note.run.request.policy, Policy::GpuRequired);
    assert!(note.run.request.emit_report);
    assert!(note.run.parent.is_none());
    let state = note.run.state.lock().unwrap();
    assert_eq!(state.observations.capacity(), OBSERVATIONS);
    assert_eq!(state.components.capacity(), 0);
    drop(state);
    // Empty synthetic work is deliberately not a successful proof receipt.
    assert!(note.finish(true).is_err());
}

#[test]
fn maximal_fixed_report_fits_the_publication_census() {
    let resources = NoteReportResources::new().unwrap();
    let policy = WorkerPolicyAbsent::capture().unwrap();
    let note = NoteRun::new(resources.required_host_bytes, &policy).unwrap();
    let stages = [
        Stage::PublicValues,
        Stage::WitnessTrace,
        Stage::Preprocessing,
        Stage::Lookup,
        Stage::Transform,
        Stage::Quotient,
        Stage::Randomness,
        Stage::Hiding,
        Stage::Commitment,
        Stage::Opening,
        Stage::FriFold,
        Stage::FriQuery,
        Stage::FinalPolynomial,
        Stage::Scalar,
        Stage::Transcript,
        Stage::Grinding,
        Stage::UpstreamProver,
        Stage::ConstraintAudit,
        Stage::Serialization,
    ];
    let backends = [
        Backend::Cpu,
        Backend::OpenCl,
        Backend::Metal,
        Backend::Cuda,
        Backend::Mixed,
        Backend::Unknown,
    ];
    let mut observations = Vec::with_capacity(OBSERVATIONS);
    for (index, stage) in stages.into_iter().enumerate() {
        assert_eq!(stage_slot(stage), index);
        for (index, backend) in backends.into_iter().enumerate() {
            assert_eq!(backend_slot(backend), index);
            observations.push(Observation {
                stage,
                backend,
                calls: u64::MAX,
                completed_calls: u64::MAX,
                device_calls: u64::MAX,
                inclusive_ns: u128::MAX,
                device_ns: u128::MAX,
            });
        }
    }
    let report = Report {
        schema: "lattica-proving-stages-v1",
        entry_point: ENTRY,
        policy: Policy::GpuRequired,
        capabilities: note.run.capabilities.clone(),
        elapsed_ns: u128::MAX,
        succeeded: false,
        stage_coverage_complete: false,
        completion_rejected: false,
        observation_errors: u64::MAX,
        observations,
        components: Vec::new(),
    };
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(encoded.len() <= resources.maximum_json_bytes);
    assert!(encoded.capacity() * 3 <= resources.publication_overlap_bytes);
    assert!(
        !report.succeeded,
        "synthetic maximum is memory evidence only"
    );
}

#[cfg(feature = "stream")]
#[test]
fn report_construction_and_failure_publication_fit_reserved_payload() {
    use crate::spill_alloc::allocation_requests::measure;
    let (resources, census) = measure(NoteReportResources::new);
    let resources = resources.unwrap();
    assert_eq!(census.calls, 0);
    let policy = WorkerPolicyAbsent::capture().unwrap();
    let ((), allocated) = measure(|| {
        let note = NoteRun::new(resources.required_host_bytes, &policy).unwrap();
        assert!(note.finish(true).is_err());
    });
    assert!(!allocated.overflow);
    assert!(allocated.bytes <= resources.required_host_bytes);
}
