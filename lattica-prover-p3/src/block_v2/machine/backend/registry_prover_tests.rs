use super::*;
use crate::block_v2::machine::{analysis::AdmissionError, ProgramBuilder};
use crate::proving::{Request, Run};

const BUDGET: u64 = 1 << 30;

fn air(constant: u64) -> MachineAir {
    let mut builder = ProgramBuilder::new(1).unwrap();
    let input = builder.input();
    let constant = builder.constant(Val::from_u64(constant));
    let sum = builder.add(input, constant);
    let public = builder.public(0).unwrap();
    builder.assert_equal(sum, public);
    MachineAir::new(builder.finish(Some(16)).unwrap())
}

fn setup() -> Run {
    Run::new(
        "registry_bound_setup_test",
        Request::compatible(),
        profile::preprocessing_capabilities(),
    )
    .unwrap()
}

#[test]
fn registry_bound_proof_preserves_the_standalone_key_and_independent_verifier() {
    let original =
        RegisteredProgram::new_with_request(air(7), BUDGET, Request::compatible()).unwrap();
    let identity = original.id();
    let bound = RegistryProgram::new_in_run(
        air(7),
        BUDGET,
        setup(),
        original.preprocessing_cap().roots(),
    )
    .unwrap();
    assert_eq!(bound.preprocessing_cap(), original.preprocessing_cap());
    assert_eq!(bound.air().program(), original.air().program());
    let run = Run::new(
        "registry_bound_proof_test",
        Request::compatible(),
        profile::registered_proof_capabilities(),
    )
    .unwrap();
    let proof = bound
        .prove_in_run(&[Val::from_u64(10)], &[Val::from_u64(3)], run)
        .unwrap();
    let verifier = original.verifier();
    verifier.verify(&proof, &[Val::from_u64(10)]).unwrap();
    assert!(verifier.verify(&proof, &[Val::from_u64(11)]).is_err());
    assert_eq!(original.id(), identity);
}

#[test]
fn registry_bound_setup_rejects_substituted_programs_and_commitments() {
    let original =
        RegisteredProgram::new_with_request(air(7), BUDGET, Request::compatible()).unwrap();
    let expected = original.preprocessing_cap().roots();
    assert_eq!(
        RegistryProgram::new_in_run(air(8), BUDGET, setup(), expected).err(),
        Some(AdmissionError::RegistryCommitmentMismatch)
    );
    let mut altered = expected.to_vec();
    altered[0][0] += Val::ONE;
    for cap in [altered.as_slice(), &[]] {
        assert_eq!(
            RegistryProgram::new_in_run(air(7), BUDGET, setup(), cap).err(),
            Some(AdmissionError::RegistryCommitmentMismatch)
        );
    }
}
