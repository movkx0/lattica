//! One conservative decision shared by child and outer mutation qualification.
//! Diagnostic strings are never acceptance or classification inputs.
use lattica_prover_p3::block_v2::machine::backend::{
    RegisteredVerificationFailure, RegisteredVerifier,
};
use std::mem::size_of;

pub(crate) fn require_rejection(
    outcome: Result<(), RegisteredVerificationFailure>,
) -> Result<(), &'static str> {
    match outcome {
        Err(RegisteredVerificationFailure::RelationRejected(_)) => Ok(()),
        Ok(()) => Err("mutated proof or public input accepted"),
        Err(RegisteredVerificationFailure::Admission(_)) => {
            Err("mutation verifier admission failed")
        }
        Err(RegisteredVerificationFailure::Configuration(_)) => {
            Err("mutation verifier configuration failed")
        }
        Err(RegisteredVerificationFailure::Allocation(_)) => {
            Err("mutation verifier public input allocation failed")
        }
    }
}

pub(crate) const fn caller_bytes() -> usize {
    // The shared classifier consumes and drops the core diagnostic before a
    // child/outer terminal failure is constructed. Existing caller Error and
    // catch_unwind results remain charged by their original type census.
    RegisteredVerifier::classified_call_extra_bytes()
        + 4 * size_of::<RegisteredVerificationFailure>()
        + 4 * size_of::<Result<(), RegisteredVerificationFailure>>()
        + 4 * size_of::<Result<(), &'static str>>()
        + 4 * size_of::<String>()
        + 4 * size_of::<&'static str>()
        + 4 * size_of::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_numerical_relation_rejection_earns_mutation_credit() {
        assert!(require_rejection(Ok(())).is_err());
        assert!(
            require_rejection(Err(RegisteredVerificationFailure::RelationRejected(
                "native verifier public input allocation failed".into(),
            )))
            .is_ok()
        );
        // Misleading diagnostics cannot override the typed stage.
        for failure in [
            RegisteredVerificationFailure::Admission("proof rejected".into()),
            RegisteredVerificationFailure::Configuration("proof rejected".into()),
            RegisteredVerificationFailure::Allocation("proof rejected".into()),
        ] {
            assert!(require_rejection(Err(failure)).is_err());
        }
    }
}
