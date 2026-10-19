//! Single-use handoff of the exact node verified during worker preparation.
//! No approval is serialized, cached by artifact ID, or attached to mutable data.
use super::*;

/// Owns the complete verified statement/proof and the immutable registry's
/// content identity. Private fields and no Clone/mutable access prevent a caller
/// from substituting data after verification. Moving this value retains the
/// existing proof backing; the enclosing worker retains its decode allowance.
pub(crate) struct VerifiedNodeInput {
    node: NodeProof,
    profile: [u8; 32],
}

impl VerifiedNodeInput {
    pub(crate) fn verify(
        registry: &CheckedRegistryRef<'_>,
        node: NodeProof,
        expected: &[Val; PUBLIC_VALUES],
    ) -> Result<Self, Error> {
        registry.verify(&node, expected)?;
        Ok(Self {
            node,
            profile: registry.profile(),
        })
    }

    fn check_session(&self, session: &Session<12>) -> Result<(), Error> {
        // Both identities were derived from the complete immutable registry,
        // including its height and all caps. Approval never comes from a packet.
        if self.profile != session.expected_profile {
            return Err("verified typed input belongs to another registry".into());
        }
        Ok(())
    }
}

impl Session<12> {
    pub(crate) fn merge_verified(
        &mut self,
        left: VerifiedNodeInput,
        right: VerifiedNodeInput,
    ) -> Result<NodeProof, Error> {
        left.check_session(self)?;
        right.check_session(self)?;
        self.backend.clone().request("block_v2_typed_merge", |run| {
            self.merge_proof(run, &left.node, &right.node)
        })
    }

    pub(crate) fn finalize_verified(
        &mut self,
        child: VerifiedNodeInput,
    ) -> Result<NodeProof, Error> {
        child.check_session(self)?;
        self.backend
            .clone()
            .request("block_v2_typed_finalize", |run| {
                self.finalize_proof(run, typed_pairs::FINALIZE, &child.node)
            })
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
