//! Authored qualification only; not executed while the benchmark is frozen.
use super::*;
use p3_field::PrimeCharacteristicRing;

fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 1 << 20,
        max_wires: 1024,
        max_input_values: 32,
    }
}

#[test]
fn invalid_limits_fail_before_any_program_construction() {
    for bad in [
        ConstructionLimits { max_requested_program_bytes: 0, ..limits() },
        ConstructionLimits { max_wires: MAX_WIRES + 1, ..limits() },
        ConstructionLimits { max_wires: 0, max_input_values: 0, ..limits() },
        ConstructionLimits { max_wires: 1, max_input_values: 1, ..limits() },
    ] {
        assert!(matches!(
            ProgramBuilder::new_with_construction_limits(1, bad),
            Err(ExecutionError::TooLarge)
        ));
    }
}

#[test]
fn first_operation_respects_requested_byte_limit_and_failure_is_sticky() {
    let mut builder = ProgramBuilder::new_with_construction_limits(
        0,
        ConstructionLimits { max_requested_program_bytes: 1, ..limits() },
    ).unwrap();
    let _ = builder.input();
    let first = builder.construction_counters();
    assert!(first.resource_failed);
    assert_eq!(first.operations, 0);
    assert!(first.requested_bytes_peak <= 1);
    let _ = builder.constant(Val::ONE);
    assert_eq!(builder.construction_counters(), first);
    assert!(matches!(builder.finish(None), Err(ExecutionError::TooLarge)));
}

#[test]
fn proof_input_collection_respects_the_separate_value_bound() {
    let mut builder = ProgramBuilder::new_with_construction_limits(
        1,
        ConstructionLimits { max_input_values: 1, ..limits() },
    ).unwrap();
    let mut inputs = ProofInputs::default();
    assert!(inputs.bases(&mut builder, &[Val::ONE, Val::ONE]).is_err());
    assert!(inputs.values.is_empty());
    assert_eq!(inputs.values.capacity(), 0);
    assert_eq!(builder.construction_counters().witnesses, 0);
    assert!(matches!(builder.finish(None), Err(ExecutionError::TooLarge)));
}

fn example(mut builder: ProgramBuilder) -> Program {
    let left = builder.input();
    let right = builder.input();
    let two = builder.constant(Val::from_u64(2));
    let sum = builder.add(left, right);
    let product = builder.mul(sum, two);
    let public = builder.public(0).unwrap();
    builder.assert_equal(public, product);
    builder.finish(None).unwrap()
}

fn manifest(program: &Program) -> Vec<u64> {
    let mut result = Vec::new();
    program.emit_manifest(&mut |word| {
        result.push(word);
        Ok(())
    }).unwrap();
    result
}

#[test]
fn admitted_limits_preserve_exact_program_manifest_and_input_order() {
    let unbounded = example(ProgramBuilder::new(1).unwrap());
    let bounded = example(ProgramBuilder::new_with_construction_limits(1, limits()).unwrap());
    assert_eq!(manifest(&bounded), manifest(&unbounded));
    assert_eq!(bounded.public_values(), unbounded.public_values());
    assert_eq!(bounded.witness_values(), unbounded.witness_values());
    assert_eq!(bounded.wire_count(), unbounded.wire_count());
    assert_eq!(bounded.height(), unbounded.height());
}
