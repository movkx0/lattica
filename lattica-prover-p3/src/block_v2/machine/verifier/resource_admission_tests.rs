//! Authored only during the benchmark freeze; no runtime qualification yet.
use super::*;
use crate::block_v2::machine::program::{ConstructionLimits, ExecutionError};
use p3_field::PrimeCharacteristicRing;

fn limits() -> ConstructionLimits {
    ConstructionLimits { max_requested_program_bytes: 1 << 20, max_wires: 1024, max_input_values: 1 }
}

#[test]
fn only_explicit_too_large_becomes_resource_admission() {
    assert_eq!(
        CompileError::from_builder_admission(ExecutionError::TooLarge, "bounded fixture"),
        CompileError::ResourceAdmission("bounded fixture"),
    );
    for error in [
        ExecutionError::InvalidWire, ExecutionError::PublicInputCount,
        ExecutionError::WitnessCount, ExecutionError::Unsatisfied,
        ExecutionError::InvalidHeight, ExecutionError::NonCanonicalField,
        ExecutionError::ProvingPolicy, ExecutionError::GpuFailure,
        ExecutionError::CompilerBackend,
    ] {
        assert_eq!(
            CompileError::from_builder_admission(error, "bounded fixture"),
            CompileError::Shape("bounded fixture"),
        );
    }
}

#[test]
fn input_value_limit_returns_typed_admission_before_allocating() {
    let mut b = ProgramBuilder::new_with_construction_limits(0, limits()).unwrap();
    let mut inputs = ProofInputs::default();
    assert!(matches!(
        inputs.bases(&mut b, &[Val::ONE, Val::ONE]),
        Err(CompileError::ResourceAdmission("proof input storage allowance")),
    ));
    assert!(inputs.values.is_empty());
    assert_eq!(inputs.values.capacity(), 0);
    assert_eq!(b.resource_failure(), Some(ExecutionError::TooLarge));
    assert_eq!(b.construction_counters().witnesses, 0);
    assert!(matches!(b.finish(None), Err(ExecutionError::TooLarge)));
}

#[test]
fn program_byte_refusal_propagates_through_proof_inputs_and_stays_sticky() {
    let mut b = ProgramBuilder::new_with_construction_limits(
        0, ConstructionLimits { max_requested_program_bytes: 1, ..limits() },
    ).unwrap();
    let mut inputs = ProofInputs::default();
    assert!(matches!(
        inputs.bases(&mut b, &[Val::ONE]),
        Err(CompileError::ResourceAdmission("proof input storage allowance")),
    ));
    let before = b.construction_counters();
    assert!(before.resource_failed);
    assert!(inputs.values.is_empty());
    assert_eq!(inputs.values.capacity(), 0);
    assert!(matches!(
        inputs.bases(&mut b, &[Val::ONE]),
        Err(CompileError::ResourceAdmission(_)),
    ));
    assert_eq!(b.construction_counters(), before);
    assert!(matches!(b.finish(None), Err(ExecutionError::TooLarge)));
}
