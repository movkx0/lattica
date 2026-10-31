//! Typed mutation-check forwarding. This adds no acceptance predicate.
use super::{BatchProof, Config, NodeKey, NodeProof, RegisteredVerifier, Val};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::backend::RegisteredVerificationFailure;

impl NodeKey {
    /// Preserve the core distinction between a numerical relation rejection and
    /// admission, configuration, or allocation failure.
    pub(crate) fn verify_classified(
        &self,
        proof: &NodeProof,
    ) -> Result<(), RegisteredVerificationFailure> {
        self.verifier.verify_classified(&proof.proof, &proof.public)
    }

    /// Additive to the existing legacy verification bound: the complete core
    /// classified call plus this forwarding frame. The caller must separately
    /// charge its probe storage, result, and caller/helper frames before work.
    /// The multiplier includes argument, return, and move overlap; there is no
    /// heap clone or new verifier owner in this forwarding layer.
    pub(crate) const fn classified_call_extra_bytes() -> usize {
        RegisteredVerifier::classified_call_extra_bytes()
            + 4 * (size_of::<&Self>()
                + size_of::<&NodeProof>()
                + size_of::<&RegisteredVerifier>()
                + size_of::<&BatchProof<Config>>()
                + size_of::<&Vec<Val>>()
                + size_of::<&[Val]>()
                + size_of::<Result<(), RegisteredVerificationFailure>>()
                + size_of::<usize>())
    }
}
