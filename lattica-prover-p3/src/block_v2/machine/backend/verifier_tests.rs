use super::*;
use crate::block_v2::machine::symbolic::verifier::Limits;
use p3_symmetric::MerkleCap;

fn cap() -> p3_batch_stark::Commitment<Config> {
    MerkleCap::new(vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT])
}

#[test]
fn bounded_verifier_metadata_matches_the_upstream_reference() {
    for (publics, height) in [(0, 8), (1, 32), (33, 64), (64, 2048)] {
        let verifier = RegisteredVerifier::from_trusted_cap(publics, height, cap()).unwrap();
        let reference = common_from_cap(&verifier.air, cap()).unwrap();
        let expected = reference.preprocessed.as_ref().unwrap();
        let actual = verifier.common.preprocessed.as_ref().unwrap();
        assert_eq!(actual.commitment.roots(), expected.commitment.roots());
        assert_eq!(actual.matrix_to_instance, expected.matrix_to_instance);
        let meta = actual.instances[0].as_ref().unwrap();
        let expected = expected.instances[0].as_ref().unwrap();
        assert_eq!(
            (meta.matrix_index, meta.width, meta.degree_bits),
            (expected.matrix_index, expected.width, expected.degree_bits)
        );
        assert_eq!(
            format!("{:?}", verifier.common.lookups),
            format!("{:?}", reference.lookups)
        );
    }
}

#[test]
fn cap_and_geometry_reject_before_graph_preparation() {
    let limits = Limits {
        recording: 0,
        ..Limits::default()
    };
    assert!(matches!(
        RegisteredVerifier::with_metadata_limits(
            1,
            8,
            MerkleCap::new(vec![[Val::ZERO; 4]]),
            limits
        ),
        Err(ExecutionError::InvalidHeight)
    ));
    for height in [0, 1, 7, 9, (1 << 24) + 1] {
        assert!(matches!(
            RegisteredVerifier::with_metadata_limits(1, height, cap(), limits),
            Err(ExecutionError::InvalidHeight)
        ));
    }
    assert!(matches!(
        RegisteredVerifier::with_metadata_limits(65, 8, cap(), limits),
        Err(ExecutionError::TooLarge)
    ));
}

#[test]
fn bounded_verifier_propagates_invalid_and_insufficient_limits() {
    assert!(matches!(
        RegisteredVerifier::with_metadata_limits(
            1,
            8,
            cap(),
            Limits {
                recording: usize::MAX,
                ..Limits::default()
            }
        ),
        Err(ExecutionError::TooLarge)
    ));
    for limits in [
        Limits {
            recording: 0,
            ..Limits::default()
        },
        Limits {
            normalization: 0,
            ..Limits::default()
        },
        Limits {
            packing: 0,
            ..Limits::default()
        },
        Limits {
            retained: 0,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            RegisteredVerifier::with_metadata_limits(1, 8, cap(), limits),
            Err(ExecutionError::CompilerBackend)
        ));
    }
    assert!(RegisteredVerifier::from_trusted_cap(1, 8, cap()).is_ok());
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[test]
fn bounded_and_reference_verifiers_accept_proof_and_reject_tampering() {
    let mut builder = super::super::ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    builder.assert_equal(public, input);
    let registered =
        RegisteredProgram::new(MachineAir::new(builder.finish(Some(8)).unwrap())).unwrap();
    let public = [Val::from_u64(17)];
    let mut proof = registered.prove(&public, &public).unwrap();
    let verifier = RegisteredVerifier::from_trusted_cap(
        1,
        8,
        registered
            .data
            .common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment
            .clone(),
    )
    .unwrap();
    let reference = common_from_cap(
        &verifier.air,
        registered
            .data
            .common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment
            .clone(),
    )
    .unwrap();
    drop(registered);
    verifier.verify(&proof, &public).unwrap();
    verify_registered(
        &verifier.air,
        &reference,
        verifier.quotient_chunks,
        &proof,
        &public,
    )
    .unwrap();
    let wrong = [public[0] + Val::ONE];
    assert!(verifier.verify(&proof, &wrong).is_err());
    assert!(verify_registered(
        &verifier.air,
        &reference,
        verifier.quotient_chunks,
        &proof,
        &wrong
    )
    .is_err());
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += profile::Challenge::ONE;
    assert!(verifier.verify(&proof, &public).is_err());
    assert!(verify_registered(
        &verifier.air,
        &reference,
        verifier.quotient_chunks,
        &proof,
        &public
    )
    .is_err());
}
