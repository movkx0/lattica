use super::*;

#[test]
fn mutation_credit_requires_numerical_rejection_regardless_of_diagnostic_text() {
    assert_eq!(require_relation_rejection(Ok(())), Err(Error::Verification));
    for failure in [
        RegisteredVerificationFailure::Admission("proof rejected".into()),
        RegisteredVerificationFailure::Configuration("proof rejected".into()),
        RegisteredVerificationFailure::Allocation("proof rejected".into()),
    ] {
        assert_eq!(
            require_relation_rejection(Err(failure)),
            Err(Error::Verification)
        );
    }
    assert_eq!(
        require_relation_rejection(Err(RegisteredVerificationFailure::RelationRejected(
            "public input allocation failed".into(),
        ))),
        Ok(())
    );
    // These are classifier inputs, not proof/retirement/accepted-output evidence.
    assert!(
        mutation_caller_host_bytes().unwrap()
            > RegisteredVerifier::classified_call_extra_bytes() as u64
                + 8 * core::mem::size_of::<[Val; HEADER + 8]>() as u64
    );
}
