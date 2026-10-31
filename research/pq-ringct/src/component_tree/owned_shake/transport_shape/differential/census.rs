//! Actual returned Vec/cap capacities, independent of the layout algebra.
use super::*;

impl Backing {
    fn add(&mut self, length: usize, capacity: usize, element: usize) -> R<()> {
        require(length == capacity)?;
        let bytes = product(capacity, element)?;
        self.bytes = sum(self.bytes, bytes)?;
        self.allocations = sum(self.allocations, usize::from(bytes != 0))?;
        self.max_vector = self.max_vector.max(length);
        Ok(())
    }
    fn vector<T>(&mut self, values: &Vec<T>) -> R<()> {
        self.add(values.len(), values.capacity(), size_of::<T>())
    }
    fn cap(&mut self, cap: &Cap) -> R<()> {
        self.add(cap.num_roots(), cap.root_capacity(), size_of::<[Val; 4]>())
    }
    fn optional<T>(&mut self, values: &Option<Vec<T>>) -> R<()> {
        if let Some(values) = values { self.vector(values)?; }
        Ok(())
    }
    fn authentication(&mut self, proof: &(Vec<Vec<Val>>, Vec<[Val; 4]>)) -> R<()> {
        self.vector(&proof.0)?;
        for salts in &proof.0 { self.vector(salts)?; }
        self.vector(&proof.1)
    }
}

pub(super) fn proof(proof: &Proof) -> R<Backing> {
    let Proof { commitments, opened_values, opening_proof, lookup_terminals, degree_bits } = proof;
    let mut result = Backing::default();
    result.cap(&commitments.main)?;
    if let Some(cap) = &commitments.permutation { result.cap(cap)?; }
    result.cap(&commitments.quotient_chunks)?;
    if let Some(cap) = &commitments.random { result.cap(cap)?; }
    result.vector(&opened_values.instances)?;
    for values in &opened_values.instances {
        let base = &values.base_opened_values;
        result.vector(&base.trace_local)?;
        result.optional(&base.trace_next)?;
        result.optional(&base.preprocessed_local)?;
        result.optional(&base.preprocessed_next)?;
        result.vector(&base.quotient_chunks)?;
        for chunk in &base.quotient_chunks { result.vector(chunk)?; }
        result.optional(&base.random)?;
        result.vector(&values.permutation_local)?;
        result.vector(&values.permutation_next)?;
    }
    result.vector(&opening_proof.0)?;
    for round in &opening_proof.0 {
        result.vector(round)?;
        for matrix in round {
            result.vector(matrix)?;
            for point in matrix { result.vector(point)?; }
        }
    }
    let fri = &opening_proof.1;
    result.vector(&fri.commit_phase_commits)?;
    for cap in &fri.commit_phase_commits { result.cap(cap)?; }
    result.vector(&fri.commit_pow_witnesses)?;
    result.vector(&fri.query_proofs)?;
    for query in &fri.query_proofs {
        result.vector(&query.input_proof)?;
        for input in &query.input_proof {
            result.vector(&input.opened_values)?;
            for values in &input.opened_values { result.vector(values)?; }
            result.authentication(&input.opening_proof)?;
        }
        result.vector(&query.commit_phase_openings)?;
        for step in &query.commit_phase_openings {
            result.vector(&step.sibling_values)?;
            result.authentication(&step.opening_proof)?;
        }
    }
    result.vector(&fri.final_poly)?;
    result.vector(lookup_terminals)?;
    result.vector(degree_bits)?;
    Ok(result)
}
