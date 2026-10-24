//! Resource-only observations of already-owned outer nodes.
//! These methods neither validate proofs nor admit their earlier allocation.
use super::{ExecutionError, NodeKey, NodeProof, RegisteredVerifier, Val};
use core::mem::{align_of, size_of};
use lattica_prover_p3::block_v2::machine::backend::retained_proof_capacity_bytes;

type CapacityResult = std::result::Result<usize, ExecutionError>;

fn public_backing_bytes(capacity: usize) -> CapacityResult {
    capacity
        .checked_mul(size_of::<Val>())
        .ok_or(ExecutionError::TooLarge)
}

fn key_reservation_bytes(cap_capacity: usize, verifier_bytes: usize) -> CapacityResult {
    let cap_bytes = cap_capacity
        .checked_mul(size_of::<[Val; 4]>())
        .ok_or(ExecutionError::TooLarge)?;
    // Match the execution metadata cache's documented Arc control/padding
    // allowance. This is not an exact allocator or unique-ownership measure.
    let arc_allowance = size_of::<usize>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(align_of::<RegisteredVerifier>()))
        .ok_or(ExecutionError::TooLarge)?;
    cap_bytes
        .checked_add(verifier_bytes)
        .and_then(|bytes| bytes.checked_add(arc_allowance))
        .ok_or(ExecutionError::TooLarge)
}

impl NodeProof {
    /// Requested public/proof Vec backing, including spare nested capacity.
    /// Overflow or a total above `max_bytes` returns only `TooLarge`.
    ///
    /// The enclosing NodeProof/header storage, allocator overhead and other
    /// live owners are separate. This does not inspect field values, allocate,
    /// clone, verify a proof, or retroactively admit its decoding/allocation.
    pub fn retained_backing_bytes(
        &self,
        max_bytes: usize,
    ) -> std::result::Result<usize, ExecutionError> {
        let public_bytes = public_backing_bytes(self.public.capacity())?;
        let remaining = max_bytes
            .checked_sub(public_bytes)
            .ok_or(ExecutionError::TooLarge)?;
        let proof_bytes = retained_proof_capacity_bytes(&self.proof, remaining)?;
        public_bytes
            .checked_add(proof_bytes)
            .ok_or(ExecutionError::TooLarge)
    }
}

impl NodeKey {
    /// Reservation for this key's copied cap and immutable verifier metadata.
    /// Includes the existing metadata census and a caller Arc envelope allowance.
    /// Overflow returns only `TooLarge`; callers separately admit the result.
    ///
    /// The inline NodeKey value, allocator overhead, and verification/proving
    /// scratch are separate. Each call charges the complete shared verifier;
    /// summing keys or execution-cache entries can conservatively double-count
    /// an Arc. This is not unique ownership, exact allocator bytes, or RSS.
    /// No proof data or witness values are read, cloned, or validated.
    pub fn retained_reservation_bytes(&self) -> std::result::Result<usize, ExecutionError> {
        key_reservation_bytes(self.cap.capacity(), self.verifier.cached_metadata_bytes())
    }
}

#[cfg(test)]
mod tests;
