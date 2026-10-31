use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use lattica_prover_p3::proving::{Capabilities, ComponentObservation};

const ALL_STAGES: [Stage; STAGES] = [
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
const ALL_BACKENDS: [Backend; BACKENDS] = [
    Backend::Cpu,
    Backend::OpenCl,
    Backend::Metal,
    Backend::Cuda,
    Backend::Mixed,
    Backend::Unknown,
];
const IDS: [&str; COMPONENTS] = [
    "c00", "c01", "c02", "c03", "c04", "c05", "c06", "c07", "c08", "c09", "c10", "c11", "c12",
    "c13", "c14", "c15",
];

fn identity(kind: PhaseKind) -> PhaseIdentity {
    PhaseIdentity {
        kind,
        ordinal: 7,
        first_segment: 8,
        segment_count: 1,
        profile: [29; 32],
    }
}
fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: PhaseReportOwner::requirements().total().unwrap().host,
        device: 0,
    })
}
fn owner(ledger: &Ledger, kind: PhaseKind) -> PhaseReportOwner {
    let token = ledger
        .admit_phase(PhaseReportOwner::requirements())
        .unwrap();
    PhaseReportOwner::from_reservation(token, ledger, identity(kind))
        .unwrap_or_else(|_| panic!("exact report reservation"))
}
fn report() -> Report {
    Report {
        schema: "lattica-proving-stages-v1",
        entry_point: "bounded_\"\\\n_é",
        policy: Policy::GpuRequired,
        capabilities: Capabilities::cpu(Profile::BlockV2Cubic, true, true),
        elapsed_ns: 123456789,
        succeeded: true,
        stage_coverage_complete: false,
        completion_rejected: false,
        observation_errors: 3,
        observations: ALL_STAGES
            .into_iter()
            .flat_map(|stage| {
                ALL_BACKENDS.into_iter().map(move |backend| Observation {
                    stage,
                    backend,
                    calls: u64::MAX,
                    completed_calls: 17,
                    device_calls: 9,
                    inclusive_ns: 123456,
                    device_ns: 99999,
                })
            })
            .collect(),
        components: IDS
            .into_iter()
            .map(|id| ComponentObservation {
                id,
                scope: CoverageScope::RegistryCompilation,
                started: true,
                cached: true,
                succeeded: false,
                stage_coverage_complete: false,
            })
            .collect(),
    }
}

#[test]
fn exact_receipts_survive_source_destruction_and_encode_without_recharging() {
    let ledger = ledger();
    let mut owned = owner(&ledger, PhaseKind::RegisteredWrapper);
    let source = report();
    let expected = serde_json::to_value(&source).unwrap();
    owned.record_proving(&source).unwrap();
    owned.record_proving(&source).unwrap();
    assert_eq!(owned.record_proving(&source), Err(Error::ReportSlotsFull));
    drop(source);
    let before = ledger.snapshot();
    let encoded: serde_json::Value = serde_json::from_slice(owned.encode().unwrap()).unwrap();
    assert_eq!(encoded["proving_reports"][0], expected);
    assert_eq!(encoded["proving_reports"][1], expected);
    assert_eq!(encoded["dispatch_authorized"], false);
    assert_eq!(encoded["source_transients_admitted"], false);
    assert_eq!(ledger.snapshot(), before);
    assert!(owned.belongs_to(&ledger));
    drop(owned);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn wrong_ledger_category_size_and_identity_return_the_original_token() {
    let first = ledger();
    let second = ledger();
    let token = first.admit_phase(PhaseReportOwner::requirements()).unwrap();
    let before = first.snapshot();
    let (error, token) =
        PhaseReportOwner::from_reservation(token, &second, identity(PhaseKind::NativeChild))
            .err()
            .unwrap();
    assert_eq!(error, Error::WrongLedger);
    assert!(token.belongs_to(&first));
    assert_eq!(first.snapshot(), before);
    let mut invalid = identity(PhaseKind::NativeChild);
    invalid.segment_count = 2;
    let (error, token) = PhaseReportOwner::from_reservation(token, &first, invalid)
        .err()
        .unwrap();
    assert_eq!(error, Error::InvalidIdentity);
    invalid = identity(PhaseKind::WrapperCompilation);
    invalid.first_segment = u64::MAX;
    let (error, token) = PhaseReportOwner::from_reservation(token, &first, invalid)
        .err()
        .unwrap();
    assert_eq!(error, Error::InvalidIdentity);
    assert_eq!(first.snapshot(), before);
    drop(token);
    let bytes = PhaseReportOwner::requirements().total().unwrap();
    for request in [
        Requirements::single(Category::NativeProof, bytes),
        Requirements::single(
            Category::Report,
            Bytes {
                host: bytes.host - 1,
                device: 0,
            },
        ),
    ] {
        let token = first.admit_phase(request).unwrap();
        let (error, returned) = PhaseReportOwner::from_reservation(
            token,
            &first,
            identity(PhaseKind::RegisteredWrapper),
        )
        .err()
        .unwrap();
        assert_eq!(error, Error::WrongReservation);
        assert_eq!(returned.requirements(), request);
        drop(returned);
    }
    assert_eq!(first.snapshot().current, Bytes::ZERO);
}

#[test]
fn source_refusals_are_transactional_and_phase_slot_counts_are_closed() {
    let ledger = ledger();
    let mut owned = owner(&ledger, PhaseKind::NativeChild);
    let mut source = report();
    source.observations.push(source.observations[0].clone());
    assert_eq!(owned.record_proving(&source), Err(Error::InventoryTooLarge));
    source.observations.pop();
    source.observations[1] = source.observations[0].clone();
    assert_eq!(
        owned.record_proving(&source),
        Err(Error::DuplicateObservation)
    );
    source = report();
    source.components[1].id = source.components[0].id;
    assert_eq!(
        owned.record_proving(&source),
        Err(Error::DuplicateComponent)
    );
    source = report();
    source.entry_point = "012345678901234567890123456789012345678901234567890123456789012345678";
    assert_eq!(owned.record_proving(&source), Err(Error::LabelTooLong));
    let empty: serde_json::Value = serde_json::from_slice(owned.encode().unwrap()).unwrap();
    assert!(empty["proving_reports"].as_array().unwrap().is_empty());
    owned.record_proving(&report()).unwrap();
    assert_eq!(owned.record_proving(&report()), Err(Error::ReportSlotsFull));
    drop(owned);
    let mut compiler = owner(&ledger, PhaseKind::WrapperCompilation);
    assert_eq!(
        compiler.record_proving(&report()),
        Err(Error::ReportSlotsFull)
    );
    compiler
        .record_failure(FailureStage::Admission, "fixed row refusal")
        .unwrap();
    assert_eq!(
        compiler.record_failure(FailureStage::Compilation, "replacement"),
        Err(Error::FailureAlreadyRecorded)
    );
    let encoded: serde_json::Value = serde_json::from_slice(compiler.encode().unwrap()).unwrap();
    assert_eq!(encoded["failure"]["message"], "fixed row refusal");
}

#[test]
fn utf8_failure_prefix_and_escaped_worst_case_fit_the_fixed_buffer() {
    let ledger = ledger();
    let mut owned = owner(&ledger, PhaseKind::RegisteredWrapper);
    let message = format!("{}é{}", "x".repeat(2047), "z".repeat(99));
    owned
        .record_failure(FailureStage::Proving, &message)
        .unwrap();
    let encoded: serde_json::Value = serde_json::from_slice(owned.encode().unwrap()).unwrap();
    assert_eq!(encoded["failure"]["message"].as_str().unwrap().len(), 2047);
    assert_eq!(encoded["failure"]["original_bytes"], message.len());
    assert_eq!(encoded["failure"]["truncated"], true);
    drop(owned);

    let mut owned = owner(&ledger, PhaseKind::RegisteredWrapper);
    let mut source = report();
    source.elapsed_ns = u128::MAX;
    source.observation_errors = u64::MAX;
    for observation in &mut source.observations {
        observation.calls = u64::MAX;
        observation.completed_calls = u64::MAX;
        observation.device_calls = u64::MAX;
        observation.inclusive_ns = u128::MAX;
        observation.device_ns = u128::MAX;
    }
    owned.record_proving(&source).unwrap();
    owned.record_proving(&source).unwrap();
    // Exercise every fixed slot and maximal escaping independently of the
    // closed upstream constructors' smaller capability inventories/labels.
    for snapshot in owned.payload.reports.iter_mut().flatten() {
        snapshot.schema = Text::exact(&"\0".repeat(LABEL_BYTES)).unwrap();
        snapshot.entry_point = snapshot.schema;
        snapshot.capabilities = std::array::from_fn(|i| {
            Some(StageCapability {
                stage: ALL_STAGES[i],
                backend: Backend::Unknown,
            })
        });
        for component in snapshot.components.iter_mut().flatten() {
            component.id = snapshot.schema;
        }
    }
    owned
        .record_failure(FailureStage::QueueDrain, &"\0".repeat(FAILURE_BYTES))
        .unwrap();
    let encoded = owned.encode().unwrap();
    assert!(encoded.len() <= ENCODED_BYTES);
    let parsed: serde_json::Value = serde_json::from_slice(encoded).unwrap();
    assert_eq!(parsed["proving_reports"].as_array().unwrap().len(), 2);
    assert_eq!(
        parsed["failure"]["message"].as_str().unwrap().len(),
        FAILURE_BYTES
    );
    assert!(std::str::from_utf8(encoded)
        .unwrap()
        .contains("340282366920938463463374607431768211455"));
}

#[test]
fn encoding_overflow_is_fixed_and_does_not_expose_partial_data() {
    let mut output = Encoding {
        bytes: vec![0; 1],
        used: 0,
    };
    assert_eq!(output.string("x"), Err(Error::EncodingOverflow));
    assert_eq!(output.bytes.len(), 1);
    assert_eq!(output.decimal(u128::MAX), Err(Error::EncodingOverflow));
}
