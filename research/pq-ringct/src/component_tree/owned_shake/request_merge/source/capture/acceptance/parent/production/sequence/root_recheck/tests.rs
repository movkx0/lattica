//! Pure source/header/classifier/quota checks, never real proof mutations.
use super::*;
use crate::execution::retained_resources::WorkerAllowance;

fn source_spec() -> Spec {
    Spec {
        contract: Contract::shake(
            [98; 32],
            7,
            crate::shake_air::Descriptor {
                input_len: 16_416,
                output_len: 137,
            },
        )
        .unwrap(),
        first: 0,
        count: 122,
        level: 3,
    }
}

#[test]
fn fixed_root_header_matches_maintained_source_header_without_proof_credit() {
    let spec = source_spec();
    let context = EndpointContext {
        context: [99; 32],
        statement: [Val::from_u64(19); 4],
        input: [Val::from_u64(23); 4],
        output: [Val::from_u64(29); 4],
    };
    let fixed = source_header(&spec, &context).unwrap();
    let maintained = crate::component_tree::header(&spec, &context).unwrap();
    assert_eq!(fixed.as_slice(), &maintained[..HEADER]);
    assert_eq!(maintained.len(), PUBLICS);
    let mut wrong = spec.clone();
    wrong.first = 1;
    assert!(source_header(&wrong, &context).is_err());
    wrong = spec.clone();
    wrong.count = 121;
    assert!(source_header(&wrong, &context).is_err());
    wrong = spec;
    wrong.level = 2;
    assert!(source_header(&wrong, &context).is_err());
}

#[test]
fn root_recheck_claim_covers_all_heights_and_exact_byte_boundary() {
    let cpu = CpuEnvelope::source().unwrap();
    assert_eq!(cpu.heights, 18);
    let required = requirements(cpu).unwrap();
    let total = required.total().unwrap();
    assert_eq!(total.device, 0);
    assert_eq!(
        required.get(Category::IndependentVerifier).host,
        (cpu.bytes + RegisteredVerifier::classified_call_extra_bytes()) as u64
    );
    assert!(required.get(Category::PhaseScratch).host > 64 << 10);
    for (host, fits) in [(total.host, true), (total.host - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let original = ledger.admit_phase(required);
        assert_eq!(original.is_ok(), fits);
        drop(original);
        let after = ledger.snapshot();
        assert_eq!(after.current, Bytes::ZERO);
        assert!(after.categories.iter().all(|c| c.current == Bytes::ZERO));
    }
}

#[test]
fn classified_outcome_filter_is_metadata_only_and_refuses_infrastructure_errors() {
    use RegisteredVerificationFailure as Failure;
    assert!(require_relation_rejection(Ok(())).is_err());
    for error in [
        Failure::Admission("synthetic classifier test".into()),
        Failure::Configuration("synthetic classifier test".into()),
        Failure::Allocation("synthetic classifier test".into()),
    ] {
        assert!(require_relation_rejection(Err(error)).is_err());
    }
    assert!(require_relation_rejection(Err(Failure::RelationRejected(
        "synthetic classifier test; not proof evidence".into(),
    )))
    .is_ok());
}
