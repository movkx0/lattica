//! Synthetic restoration/header/timing fixtures only; no proof or GPU credit.
use super::*;

struct FixedOpening {
    word: Option<Challenge>,
}
impl mutation::OpeningOwner for FixedOpening {
    fn opening_mut(&mut self) -> Option<&mut Challenge> {
        self.word.as_mut()
    }
}

#[test]
fn opening_guard_refuses_absent_slot_without_mutation() {
    let mut fixture = FixedOpening { word: None };
    assert!(OpeningMutation::new(&mut fixture).is_err());
    assert!(fixture.word.is_none());
}

#[test]
fn opening_guard_restores_before_each_typed_outcome_is_classified() {
    use RegisteredVerificationFailure as Failure;
    for outcome in [
        Ok(()),
        Err(Failure::RelationRejected("synthetic only".into())),
        Err(Failure::Admission("synthetic only".into())),
        Err(Failure::Configuration("synthetic only".into())),
        Err(Failure::Allocation("synthetic only".into())),
    ] {
        let expects_rejection = matches!(&outcome, Err(Failure::RelationRejected(_)));
        let original = Challenge::from_u64(31);
        let mut fixture = FixedOpening { word: Some(original) };
        let guard = OpeningMutation::new(&mut fixture).unwrap();
        assert_eq!(guard.original(), original);
        assert_eq!(guard.proof().word, Some(original + Challenge::ONE));
        drop(guard);
        assert_eq!(fixture.word, Some(original));
        assert_eq!(require_relation_rejection(outcome).is_ok(), expects_rejection);
    }
}

#[test]
fn opening_guard_restores_on_synthetic_unwind_without_gpu_cleanup_credit() {
    let original = Challenge::from_u64(37);
    let mut fixture = FixedOpening { word: Some(original) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = OpeningMutation::new(&mut fixture).unwrap();
        assert_eq!(guard.proof().word, Some(original + Challenge::ONE));
        panic!("synthetic verifier unwind, no GPU/runtime owner");
    }));
    assert!(result.is_err());
    assert_eq!(fixture.word, Some(original));
}


fn source_spec() -> Spec {
    Spec {
        contract: crate::component_tree::Contract::shake(
            [98; 32], 7,
            crate::shake_air::Descriptor { input_len: 16_416, output_len: 137 },
        ).unwrap(),
        first: 0, count: 32, level: 0,
    }
}

#[test]
fn leaf0_header_matches_maintained_source_and_refuses_sibling_or_parent_geometry() {
    let spec = source_spec();
    let context = EndpointContext {
        context: [99; 32], statement: [Val::from_u64(19); 4],
        input: [Val::from_u64(23); 4], output: [Val::from_u64(29); 4],
    };
    let fixed = source_header(&spec, &context).unwrap();
    let maintained = crate::component_tree::header(&spec, &context).unwrap();
    assert_eq!(fixed.as_slice(), &maintained[..HEADER]);
    assert_eq!(maintained.len(), PUBLICS);
    for (first, count, level) in [(32, 32, 0), (0, 64, 1), (0, 122, 3), (0, 31, 0)] {
        let mut wrong = spec.clone();
        wrong.first = first; wrong.count = count; wrong.level = level;
        assert!(source_header(&wrong, &context).is_err());
    }
    let mut wrong = spec.clone();
    wrong.contract.total = 121;
    assert!(source_header(&wrong, &context).is_err());
    let mut other_context = context;
    other_context.context[0] ^= 1;
    assert_ne!(source_header(&spec, &other_context).unwrap(), fixed);
}

fn synthetic_measurements() -> InteriorOpeningMeasurements {
    InteriorOpeningMeasurements {
        cpu_heights: 18, positive_checks: 2, opening_probes: 1,
        positive_verification_ns: 7, mutation_verification_ns: 5, elapsed_ns: 13,
        retained_output_restored: true, parent0_child_consumed: false,
    }
}

#[test]
fn interior_measurement_scope_refuses_missing_checks_restoration_and_timing_overflow() {
    assert!(check_measurements(&synthetic_measurements()).is_ok());
    for changed in 0..7 {
        let mut m = synthetic_measurements();
        match changed {
            0 => m.cpu_heights = 17,
            1 => m.positive_checks = 1,
            2 => m.opening_probes = 0,
            3 => m.retained_output_restored = false,
            4 => m.elapsed_ns = 11,
            5 => m.positive_verification_ns = u128::MAX,
            6 => m.mutation_verification_ns = 0,
            _ => unreachable!(),
        }
        assert!(check_measurements(&m).is_err());
    }
}
