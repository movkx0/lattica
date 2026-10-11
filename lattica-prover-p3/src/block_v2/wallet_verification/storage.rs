//! Count each owned Vec backing once, including spare capacity. Envelope
//! checks run first, so both traversal and allocation requests remain bounded.
use super::{Val, WalletProof, PROOF_BACKING_LIMIT};

#[derive(Default)]
pub(super) struct Backing(usize);
impl Backing {
    pub(super) fn capacity<T>(&mut self, capacity: usize) -> Result<(), &'static str> {
        let bytes = capacity
            .checked_mul(core::mem::size_of::<T>())
            .ok_or("wallet proof backing overflow")?;
        self.0 = self
            .0
            .checked_add(bytes)
            .ok_or("wallet proof backing overflow")?;
        if self.0 > PROOF_BACKING_LIMIT {
            return Err("wallet proof backing allowance");
        }
        Ok(())
    }
    fn vector<T>(&mut self, values: &Vec<T>) -> Result<(), &'static str> {
        self.capacity::<T>(values.capacity())
    }
    fn rows<T>(&mut self, rows: &Vec<Vec<T>>) -> Result<(), &'static str> {
        self.vector(rows)?;
        for row in rows {
            self.vector(row)?;
        }
        Ok(())
    }
    fn optional<T>(&mut self, values: &Option<Vec<T>>) -> Result<(), &'static str> {
        if let Some(values) = values {
            self.vector(values)?;
        }
        Ok(())
    }
    fn cap(&mut self, cap: &p3_symmetric::MerkleCap<Val, [Val; 4]>) -> Result<(), &'static str> {
        self.capacity::<[Val; 4]>(cap.root_capacity())
    }
    fn authentication(
        &mut self,
        proof: &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    ) -> Result<(), &'static str> {
        self.rows(&proof.0)?;
        self.vector(&proof.1)
    }
}

pub(super) fn proof_bytes(wallet: &WalletProof) -> Result<usize, &'static str> {
    let mut heap = Backing::default();
    heap.vector(&wallet.public)?;
    let proof = &wallet.proof;
    heap.cap(&proof.commitments.trace)?;
    heap.cap(&proof.commitments.quotient_chunks)?;
    if let Some(cap) = &proof.commitments.random {
        heap.cap(cap)?;
    }
    let values = &proof.opened_values;
    heap.vector(&values.trace_local)?;
    heap.optional(&values.trace_next)?;
    heap.optional(&values.preprocessed_local)?;
    heap.optional(&values.preprocessed_next)?;
    heap.optional(&values.random)?;
    heap.rows(&values.quotient_chunks)?;
    let (hiding, fri) = &proof.opening_proof;
    heap.vector(hiding)?;
    for matrices in hiding {
        heap.vector(matrices)?;
        for points in matrices {
            heap.rows(points)?;
        }
    }
    heap.vector(&fri.commit_phase_commits)?;
    for cap in &fri.commit_phase_commits {
        heap.cap(cap)?;
    }
    heap.vector(&fri.commit_pow_witnesses)?;
    heap.vector(&fri.final_poly)?;
    heap.vector(&fri.query_proofs)?;
    for query in &fri.query_proofs {
        heap.vector(&query.input_proof)?;
        for opening in &query.input_proof {
            heap.rows(&opening.opened_values)?;
            heap.authentication(&opening.opening_proof)?;
        }
        heap.vector(&query.commit_phase_openings)?;
        for opening in &query.commit_phase_openings {
            heap.vector(&opening.sibling_values)?;
            heap.authentication(&opening.opening_proof)?;
        }
    }
    Ok(heap.0)
}
