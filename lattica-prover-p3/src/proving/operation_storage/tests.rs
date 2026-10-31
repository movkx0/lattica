use super::*;

const STAGE_KEYS: [Stage; STAGES] = [
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
const BACKEND_KEYS: [Backend; BACKENDS] = [
    Backend::Cpu,
    Backend::OpenCl,
    Backend::Metal,
    Backend::Cuda,
    Backend::Mixed,
    Backend::Unknown,
];

fn raw_run() -> Run {
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, false, false)
        .scoped(CoverageScope::Operation, &[Stage::WitnessTrace]);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    Run::new(
        "pq_graph_witness_preparation",
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        capabilities,
    )
    .unwrap()
}

fn populate(run: &Run, maximal: bool) {
    let mut state = run.state.lock().unwrap();
    for stage in STAGE_KEYS {
        for backend in BACKEND_KEYS {
            state.observations.push(Observation {
                stage,
                backend,
                calls: if maximal { u64::MAX } else { 1 },
                completed_calls: if maximal { u64::MAX } else { 0 },
                device_calls: if maximal { u64::MAX } else { 0 },
                inclusive_ns: u128::MAX,
                device_ns: u128::MAX,
            });
        }
    }
    state.observation_errors = u64::MAX;
}

#[test]
fn closed_raw_report_and_original_error_text_fit_the_source_census() {
    let resources = RawPreparationReportStorage::new().unwrap();
    for (index, stage) in STAGE_KEYS.into_iter().enumerate() {
        assert_eq!(stage_slot(stage), index);
        for (index, backend) in BACKEND_KEYS.into_iter().enumerate() {
            assert_eq!(backend_slot(backend), index);
            assert!(format!("{:?}", StageCapability { stage, backend }).len() < 128);
        }
    }
    let run = raw_run();
    populate(&run, true);
    // Failure report deliberately contains every key, including rejected
    // backends. This fixture is memory evidence, not successful GPU execution.
    let mut report = run.finish(false).unwrap();
    report.elapsed_ns = u128::MAX;
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.len() <= resources.maximum_json_bytes);
    assert!(json.capacity() * 3 <= resources.publication_overlap_bytes);
    drop(json);
    drop(report);

    let run = raw_run();
    populate(&run, false);
    let error = run.finish(true).unwrap_err();
    let text = error.to_string();
    assert!(text.len() <= resources.maximum_error_bytes);
    assert!(text.capacity() * 3 <= resources.error_format_overlap_bytes);
    assert!(matches!(error, Error::IncompleteCoverage { .. }));
    // Unsupported admission may contain the whole initial inventory; test its
    // formatting independently of the one-stage raw request.
    let error = Error::Unsupported {
        policy: Policy::GpuRequired,
        gaps: STAGE_KEYS[..INVENTORY]
            .iter()
            .map(|&stage| StageCapability {
                stage,
                backend: Backend::Unknown,
            })
            .collect(),
    };
    assert!(error.to_string().len() <= resources.maximum_error_bytes);
}

#[cfg(all(feature = "stream", not(debug_assertions)))]
#[test]
fn raw_report_lifecycle_requested_allocations_fit_before_entry() {
    use crate::spill_alloc::allocation_requests::measure;
    let (resources, census) = measure(RawPreparationReportStorage::new);
    let resources = resources.unwrap();
    assert_eq!(census.calls, 0);
    for success in [false, true] {
        let (_, census) = measure(|| {
            let run = raw_run();
            populate(&run, false);
            match run.finish(success) {
                Ok(report) => {
                    drop(serde_json::to_string(&report).unwrap());
                    drop(report);
                }
                Err(error) => {
                    drop(error.to_string());
                    drop(error);
                }
            }
        });
        assert!(
            !census.overflow && census.bytes <= resources.required_host_bytes,
            "{census:?}"
        );
    }
}
