//! Portable resource accounting for already-owned concrete BatchProof storage.
//! Kept separate from numerical verification and target-specific scratch plans.
use super::{BatchProof, Config, ExecutionError, Val};

struct Backing {
    bytes: usize,
    limit: usize,
}
impl Backing {
    fn new(limit: usize) -> Self {
        Self { bytes: 0, limit }
    }
    fn capacity<T>(&mut self, capacity: usize) -> Result<(), ExecutionError> {
        self.bytes = self
            .bytes
            .checked_add(
                capacity
                    .checked_mul(core::mem::size_of::<T>())
                    .ok_or(ExecutionError::TooLarge)?,
            )
            .ok_or(ExecutionError::TooLarge)?;
        if self.bytes > self.limit {
            return Err(ExecutionError::TooLarge);
        }
        Ok(())
    }
    fn vector<T>(&mut self, value: &Vec<T>) -> Result<(), ExecutionError> {
        self.capacity::<T>(value.capacity())
    }
    fn cap(&mut self, cap: &p3_batch_stark::Commitment<Config>) -> Result<(), ExecutionError> {
        self.capacity::<[Val; 4]>(cap.root_capacity())
    }
    fn rows<T>(&mut self, rows: &Vec<Vec<T>>) -> Result<(), ExecutionError> {
        self.vector(rows)?;
        for row in rows {
            self.vector(row)?;
        }
        Ok(())
    }
    fn optional<T>(&mut self, value: &Option<Vec<T>>) -> Result<(), ExecutionError> {
        if let Some(value) = value {
            self.vector(value)?;
        }
        Ok(())
    }
    fn authentication(
        &mut self,
        (salts, path): &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    ) -> Result<(), ExecutionError> {
        self.rows(salts)?;
        self.vector(path)
    }
    fn opening(&mut self, proof: &p3_batch_stark::PcsProof<Config>) -> Result<(), ExecutionError> {
        let (hiding, fri) = proof;
        self.vector(hiding)?;
        for matrices in hiding {
            self.vector(matrices)?;
            for points in matrices {
                self.rows(points)?;
            }
        }
        self.vector(&fri.commit_phase_commits)?;
        for cap in &fri.commit_phase_commits {
            self.cap(cap)?;
        }
        self.vector(&fri.commit_pow_witnesses)?;
        self.vector(&fri.final_poly)?;
        self.vector(&fri.query_proofs)?;
        for query in &fri.query_proofs {
            self.vector(&query.input_proof)?;
            for opening in &query.input_proof {
                self.rows(&opening.opened_values)?;
                self.authentication(&opening.opening_proof)?;
            }
            self.vector(&query.commit_phase_openings)?;
            for layer in &query.commit_phase_openings {
                self.vector(&layer.sibling_values)?;
                self.authentication(&layer.opening_proof)?;
            }
        }
        Ok(())
    }
}

/// Count the requested backing capacity of an already-owned proof, bounded by
/// `max_bytes`. Overflow or excess capacity returns only `ExecutionError::TooLarge`.
/// This does not inspect field values, verify a proof, allocate or clone data.
///
/// Inline proof/Vec headers outside the backing buffers, allocator overhead,
/// prior allocation peaks, and verifier/proving scratch are excluded. This is
/// an observation of current retained backing, not admission of prior decoding
/// or a bound on process RSS. Even an invalid proof shape may be counted.
///
/// Walk only initialized entries. Each outer capacity is admitted before its
/// children, so even before the envelope this traversal has bounded work and
/// makes no allocation. The structural envelope is still required separately.
/// Each Vec backing buffer is charged once, including spare capacity; inline
/// Vec headers in outer buffers are charged by the outer element size.
pub fn retained_proof_capacity_bytes(
    proof: &BatchProof<Config>,
    max_bytes: usize,
) -> Result<usize, ExecutionError> {
    let mut heap = Backing::new(max_bytes);
    heap.cap(&proof.commitments.main)?;
    heap.cap(&proof.commitments.quotient_chunks)?;
    for cap in [&proof.commitments.permutation, &proof.commitments.random]
        .into_iter()
        .flatten()
    {
        heap.cap(cap)?;
    }
    heap.vector(&proof.degree_bits)?;
    heap.vector(&proof.lookup_terminals)?;
    heap.vector(&proof.opened_values.instances)?;
    for instance in &proof.opened_values.instances {
        let base = &instance.base_opened_values;
        heap.vector(&base.trace_local)?;
        heap.optional(&base.trace_next)?;
        heap.optional(&base.preprocessed_local)?;
        heap.optional(&base.preprocessed_next)?;
        heap.optional(&base.random)?;
        heap.rows(&base.quotient_chunks)?;
        heap.vector(&instance.permutation_local)?;
        heap.vector(&instance.permutation_next)?;
    }
    heap.opening(&proof.opening_proof)?;
    Ok(heap.bytes)
}

/// Same retained-backing accounting for a native uni-STARK proof. Inline
/// owners/public arrays and prior allocation peaks are charged by the caller.
pub fn retained_native_proof_capacity_bytes(
    proof: &p3_uni_stark::Proof<Config>,
    max_bytes: usize,
) -> Result<usize, ExecutionError> {
    let mut heap = Backing::new(max_bytes);
    heap.cap(&proof.commitments.trace)?;
    heap.cap(&proof.commitments.quotient_chunks)?;
    if let Some(cap) = &proof.commitments.random {
        heap.cap(cap)?;
    }
    let base = &proof.opened_values;
    heap.vector(&base.trace_local)?;
    heap.optional(&base.trace_next)?;
    heap.optional(&base.preprocessed_local)?;
    heap.optional(&base.preprocessed_next)?;
    heap.optional(&base.random)?;
    heap.rows(&base.quotient_chunks)?;
    heap.opening(&proof.opening_proof)?;
    Ok(heap.bytes)
}

#[cfg(test)]
mod tests;
