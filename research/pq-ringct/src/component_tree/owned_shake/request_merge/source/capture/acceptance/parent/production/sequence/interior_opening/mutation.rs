//! Shape-preserving one-word mutation; no mutable proof borrow escapes.
use super::*;

// Private, statically dispatched, and implemented for the actual BatchProof.
// Tests use a fixed fixture solely to exercise returned-error/unwind cleanup.
pub(super) trait OpeningOwner {
    fn opening_mut(&mut self) -> Option<&mut Challenge>;
}

impl OpeningOwner for BatchProof<Config> {
    fn opening_mut(&mut self) -> Option<&mut Challenge> {
        if self.opened_values.instances.len() != 1 {
            return None;
        }
        self.opened_values.instances[0].permutation_local.first_mut()
    }
}

pub(super) struct OpeningMutation<'a, T: OpeningOwner> {
    proof: &'a mut T,
    original: Challenge,
}

impl<'a, T: OpeningOwner> OpeningMutation<'a, T> {
    pub(super) fn new(proof: &'a mut T) -> InteriorResult<Self> {
        let slot = proof.opening_mut().ok_or(ParentCompileError::Source)?;
        let original = *slot;
        *slot += Challenge::ONE;
        Ok(Self { proof, original })
    }

    pub(super) fn proof(&self) -> &T {
        self.proof
    }

    pub(super) fn original(&self) -> Challenge {
        self.original
    }
}

impl<T: OpeningOwner> Drop for OpeningMutation<'_, T> {
    fn drop(&mut self) {
        // Constructor validated the slot. Only a shared T borrow is exposed,
        // so the actual BatchProof's Vec shape cannot change while we exist.
        *self.proof.opening_mut().expect("private Leaf0 opening shape") = self.original;
    }
}
