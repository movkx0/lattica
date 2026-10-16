use super::{Error, PcsField, Proof, ProvingConfig, Val};
use core::mem::size_of;
use p3_symmetric::MerkleCap;

/// Charge each outer buffer before visiting initialized children, bounding the
/// traversal by the allowance. Inline headers belong to the outer element size;
/// spare capacity at every owned level counts even when its length is zero.
pub(super) struct Backing {
    bytes: usize,
    limit: usize,
}

impl Backing {
    pub(super) fn new(limit: usize) -> Self {
        Self { bytes: 0, limit }
    }
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    fn capacity<T>(&mut self, capacity: usize) -> Result<(), Error> {
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .ok_or(Error::HostLimit)?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|n| *n <= self.limit)
            .ok_or(Error::HostLimit)?;
        Ok(())
    }
    pub(super) fn vector<T>(&mut self, value: &Vec<T>) -> Result<(), Error> {
        self.capacity::<T>(value.capacity())
    }
    fn cap(&mut self, cap: &MerkleCap<Val, [Val; 4]>) -> Result<(), Error> {
        self.capacity::<[Val; 4]>(cap.root_capacity())
    }
    fn rows<T>(&mut self, rows: &Vec<Vec<T>>) -> Result<(), Error> {
        self.vector(rows)?;
        for row in rows {
            self.vector(row)?;
        }
        Ok(())
    }
    fn optional<T>(&mut self, value: &Option<Vec<T>>) -> Result<(), Error> {
        if let Some(value) = value {
            self.vector(value)?;
        }
        Ok(())
    }
    fn authentication(
        &mut self,
        (salts, path): &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    ) -> Result<(), Error> {
        self.rows(salts)?;
        self.vector(path)
    }

    pub(super) fn proof<E: PcsField>(
        &mut self,
        proof: &Proof<ProvingConfig<E>>,
    ) -> Result<(), Error> {
        self.cap(&proof.commitments.trace)?;
        self.cap(&proof.commitments.quotient_chunks)?;
        if let Some(cap) = &proof.commitments.random {
            self.cap(cap)?;
        }
        let values = &proof.opened_values;
        self.vector(&values.trace_local)?;
        self.optional(&values.trace_next)?;
        self.optional(&values.preprocessed_local)?;
        self.optional(&values.preprocessed_next)?;
        self.optional(&values.random)?;
        self.rows(&values.quotient_chunks)?;
        let (hiding, fri) = &proof.opening_proof;
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

    #[cfg(test)]
    pub(super) fn overflow_checks() {
        let mut backing = Self::new(usize::MAX);
        assert_eq!(backing.capacity::<Val>(usize::MAX), Err(Error::HostLimit));
        backing.capacity::<u8>(usize::MAX).unwrap();
        assert_eq!(backing.capacity::<u8>(1), Err(Error::HostLimit));
    }
}
