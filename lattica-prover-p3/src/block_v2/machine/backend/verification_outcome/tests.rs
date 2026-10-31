use super::*;
use crate::block_v2::machine::verifier::template;
use p3_symmetric::MerkleCap;

fn fixture() -> (RegisteredVerifier, BatchProof<Config>, [Val; 1]) {
    let height = 64usize;
    let roots = 1 << (height.ilog2() as usize + 1 + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT);
    let verifier = RegisteredVerifier::from_trusted_cap(
        1,
        height,
        MerkleCap::new(vec![[Val::ZERO; 4]; roots]),
    )
    .unwrap();
    let proof = template::batch(&verifier.air).unwrap();
    (verifier, proof, [Val::ZERO])
}

#[test]
fn injected_infrastructure_failures_never_classify_as_relation_rejection() {
    let (verifier, proof, public) = fixture();
    for fault in [Fault::Admission, Fault::Configuration, Fault::Allocation] {
        let result = verifier.verify_classified_inner(&proof, &public, fault);
        assert!(matches!(
            (fault, result),
            (
                Fault::Admission,
                Err(RegisteredVerificationFailure::Admission(_))
            ) | (
                Fault::Configuration,
                Err(RegisteredVerificationFailure::Configuration(_))
            ) | (
                Fault::Allocation,
                Err(RegisteredVerificationFailure::Allocation(_))
            )
        ));
    }
}

#[test]
fn structural_refusal_does_not_earn_mutation_credit() {
    let (verifier, mut proof, public) = fixture();
    assert!(matches!(
        verifier.verify_classified(&proof, &[]),
        Err(RegisteredVerificationFailure::Admission(_))
    ));
    proof.degree_bits[0] += 1;
    assert!(matches!(
        verifier.verify_classified(&proof, &public),
        Err(RegisteredVerificationFailure::Admission(_))
    ));
    proof.degree_bits[0] -= 1;
    let terminal = proof.lookup_terminals.pop().unwrap();
    assert!(matches!(
        verifier.verify_classified(&proof, &public),
        Err(RegisteredVerificationFailure::Admission(_))
    ));
    proof.lookup_terminals.push(terminal);
    proof.opened_values.instances.clear();
    assert!(matches!(
        verifier.verify_classified(&proof, &public),
        Err(RegisteredVerificationFailure::Admission(_))
    ));
}

#[test]
fn trusted_geometry_failure_in_envelope_is_not_relation_rejection() {
    let (mut verifier, proof, public) = fixture();
    verifier.common.lookups.clear();
    assert!(matches!(
        verifier.verify_classified(&proof, &public),
        Err(RegisteredVerificationFailure::Admission(_))
    ));
}

#[test]
fn actual_numerical_rejection_has_the_legacy_diagnostic() {
    // This shape-admitted template is deliberately not a valid proof. Its
    // numerical rejection exercises the actual upstream verifier, no injected
    // outcome and no acceptance owner or GPU work.
    let (verifier, proof, public) = fixture();
    let classified = verifier.verify_classified(&proof, &public);
    let Err(RegisteredVerificationFailure::RelationRejected(message)) = classified else {
        panic!("template did not reach numerical rejection: {classified:?}");
    };
    assert_eq!(verifier.verify(&proof, &public).unwrap_err(), message);
    assert!(message.len() <= verification_call::DIAGNOSTIC_BYTES);
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[test]
fn real_proof_acceptance_and_mutations_match_legacy_verification() {
    use crate::block_v2::machine::ProgramBuilder;
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public_wire = builder.public(0).unwrap();
    let input = builder.input();
    builder.assert_equal(public_wire, input);
    let registered =
        RegisteredProgram::new(MachineAir::new(builder.finish(Some(64)).unwrap())).unwrap();
    let public = [Val::from_u64(17)];
    let mut proof = registered.prove(&public, &public).unwrap();
    let verifier = registered.verifier();
    drop(registered);
    assert_eq!(verifier.verify_classified(&proof, &public), Ok(()));
    verifier.verify(&proof, &public).unwrap();
    let changed = [public[0] + Val::ONE];
    assert!(matches!(
        verifier.verify_classified(&proof, &changed),
        Err(RegisteredVerificationFailure::RelationRejected(_))
    ));
    assert!(verifier.verify(&proof, &changed).is_err());
    let original = proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0];
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += profile::Challenge::ONE;
    assert!(matches!(
        verifier.verify_classified(&proof, &public),
        Err(RegisteredVerificationFailure::RelationRejected(_))
    ));
    assert!(verifier.verify(&proof, &public).is_err());
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] = original;
    assert_eq!(verifier.verify_classified(&proof, &public), Ok(()));
    verifier.verify(&proof, &public).unwrap();
}
