//! Research qualification needs to distinguish numerical proof rejection from
//! infrastructure failure. The legacy verifier entry and its diagnostics stay
//! unchanged; this opt-in path follows the same checks in the same order.
use super::*;
use core::mem::size_of;

/// An unsuccessful standalone verification, classified by the operation that
/// failed, never by diagnostic text. Only `RelationRejected` certifies that the
/// numerical verifier ran and rejected the candidate proof/public statement.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisteredVerificationFailure {
    /// Returned by the unchanged upstream numerical `verify_batch` call only.
    RelationRejected(String),
    /// Lifecycle, public/degree/lookup shape, structural envelope, or call
    /// storage refusal. Structural rejection deliberately earns no mutation
    /// credit, including envelope failures involving trusted geometry.
    Admission(String),
    /// Constructing the verifier configuration failed before verification.
    Configuration(String),
    /// The fallible public-input copy failed before numerical verification.
    Allocation(String),
}

// Private, per-call fault injection. Production constructs only None. Tests
// select a failure stage, never a success result, arbitrary callback or pointer.
// Faults join the same map_err as the corresponding real fallible operation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Admission,
    Configuration,
    Allocation,
}

impl RegisteredVerifier {
    /// Qualify a research negative probe without crediting resource/configuration
    /// failure as proof rejection. Panics remain panics, not typed rejection.
    /// The caller must catch them as terminal failure if its lifecycle does so.
    pub fn verify_classified(
        &self,
        proof: &BatchProof<Config>,
        public: &[Val],
    ) -> Result<(), RegisteredVerificationFailure> {
        self.verify_classified_inner(proof, public, Fault::None)
    }

    /// Additive caller-side storage for this entry's typed-result transport,
    /// private fault selector, forwarding/census frames and bounded diagnostic.
    /// Existing native lifecycle/call reservation and enclosing caller storage
    /// remain required. This grants no memory admission or execution authority.
    /// Sequential probes may share the charge; simultaneous probes may not.
    pub const fn classified_call_extra_bytes() -> usize {
        8 * size_of::<RegisteredVerificationFailure>()
            + 8 * size_of::<Result<(), RegisteredVerificationFailure>>()
            + 4 * size_of::<String>()
            + 4 * size_of::<Result<(), String>>()
            + 4 * size_of::<Result<(), &'static str>>()
            + 4 * size_of::<Fault>()
            + 8 * size_of::<&RegisteredVerifier>()
            + 8 * size_of::<&BatchProof<Config>>()
            + 8 * size_of::<&[Val]>()
            + 8 * size_of::<usize>()
            + 8 * size_of::<bool>()
            // Additive even though native call storage already includes the
            // sole bounded returned diagnostic. No diagnostic clones occur.
            + verification_call::DIAGNOSTIC_BYTES
    }

    fn verify_classified_inner(
        &self,
        proof: &BatchProof<Config>,
        public: &[Val],
        fault: Fault,
    ) -> Result<(), RegisteredVerificationFailure> {
        use RegisteredVerificationFailure as Failure;
        #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
        self.admit_storage(verification_lifetimes::LIMIT_BYTES)
            .map_err(Failure::Admission)?;
        if public.len() != self.air.program().public_values() {
            return Err(Failure::Admission("public input count".into()));
        }
        if proof.degree_bits != [self.air.program().height().ilog2() as usize + 1] {
            return Err(Failure::Admission("unregistered degree".into()));
        }
        if proof.lookup_terminals.len() != 1
            || !proof.lookup_terminals[0]
                .as_ref()
                .is_some_and(|t| t.0 == profile::Challenge::ZERO)
        {
            return Err(Failure::Admission(
                "single-table lookup terminal must be zero".into(),
            ));
        }
        verification_envelope::check(&self.air, &self.common, self.quotient_chunks, proof)
            .map_err(|error| Failure::Admission(error.to_owned()))?;
        let admission = if fault == Fault::Admission {
            Err("injected native verifier call admission failure")
        } else {
            #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
            {
                verification_call::Plan::new(&self.air, &self.common, self.quotient_chunks, proof)
                    .and_then(verification_call::Plan::admit)
            }
            #[cfg(not(all(not(debug_assertions), target_arch = "x86_64")))]
            {
                Ok(())
            }
        };
        admission.map_err(|error| Failure::Admission(error.to_owned()))?;
        let config = if fault == Fault::Configuration {
            Err("injected native verifier configuration failure")
        } else {
            profile::verification::make_config()
        }
        .map_err(|error| Failure::Configuration(error.to_owned()))?;
        let public = if fault == Fault::Allocation {
            Err("injected native verifier public input allocation failure")
        } else {
            verification_call::copy_public(public)
        }
        .map_err(|error| Failure::Allocation(error.to_owned()))?;
        verify_batch(
            &config,
            core::slice::from_ref(&self.air),
            proof,
            &[public],
            &self.common,
        )
        .map_err(|error| Failure::RelationRejected(verification_call::error(&error)))
    }
}

#[cfg(test)]
mod tests;
