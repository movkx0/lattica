use super::super::{profile, verification_scratch, BatchProof, Config, MachineAir, Val};
use super::DIAGNOSTIC_BYTES;

pub(in super::super) const PROOF_LIMIT_BYTES: usize = 64 << 20;
pub(in super::super) const TEMPORARY_LIMIT_BYTES: usize = 64 << 20;
const ERROR: &str = "native verifier call storage exceeds allowance";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct Plan {
    pub(in super::super) proof_backing_bytes: usize,
    pub(in super::super) numerical_bytes: usize,
    pub(in super::super) configuration_bytes: usize,
    pub(in super::super) public_copy_bytes: usize,
    pub(in super::super) diagnostic_bytes: usize,
    pub(in super::super) temporary_requested_bytes: usize,
}

fn add(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_add(b).ok_or(ERROR)
}
fn bytes<T>(capacity: usize) -> Result<usize, &'static str> {
    capacity.checked_mul(core::mem::size_of::<T>()).ok_or(ERROR)
}

#[derive(Default)]
struct Backing(usize);
impl Backing {
    fn capacity<T>(&mut self, capacity: usize) -> Result<(), &'static str> {
        self.0 = add(self.0, bytes::<T>(capacity)?)?;
        if self.0 > PROOF_LIMIT_BYTES {
            return Err(ERROR);
        }
        Ok(())
    }
    fn vector<T>(&mut self, value: &Vec<T>) -> Result<(), &'static str> {
        self.capacity::<T>(value.capacity())
    }
    fn cap(&mut self, cap: &p3_batch_stark::Commitment<Config>) -> Result<(), &'static str> {
        self.capacity::<[Val; 4]>(cap.root_capacity())
    }
    fn rows<T>(&mut self, rows: &Vec<Vec<T>>) -> Result<(), &'static str> {
        self.vector(rows)?;
        for row in rows {
            self.vector(row)?;
        }
        Ok(())
    }
    fn optional<T>(&mut self, value: &Option<Vec<T>>) -> Result<(), &'static str> {
        if let Some(value) = value {
            self.vector(value)?;
        }
        Ok(())
    }
    fn authentication(
        &mut self,
        (salts, path): &(Vec<Vec<Val>>, Vec<[Val; 4]>),
    ) -> Result<(), &'static str> {
        self.rows(salts)?;
        self.vector(path)
    }
}

/// Walk only initialized entries. Each outer capacity is admitted before its
/// children, so even before the envelope this traversal has bounded work and
/// makes no allocation. The structural envelope is still required separately.
/// Each Vec backing buffer is charged once, including spare capacity; inline
/// Vec headers in outer buffers are charged by the outer element size.
pub(in super::super) fn proof_bytes(proof: &BatchProof<Config>) -> Result<usize, &'static str> {
    let mut heap = Backing::default();
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
        for layer in &query.commit_phase_openings {
            heap.vector(&layer.sibling_values)?;
            heap.authentication(&layer.opening_proof)?;
        }
    }
    Ok(heap.0)
}

impl Plan {
    /// Caller must first check public length, degree/terminal and shape.
    pub(in super::super) fn new(
        air: &MachineAir,
        common: &p3_batch_stark::CommonData<Config>,
        quotient_chunks: usize,
        proof: &BatchProof<Config>,
    ) -> Result<Self, &'static str> {
        let proof_backing_bytes = proof_bytes(proof)?;
        let numerical = verification_scratch::Plan::new(air, common, quotient_chunks)?;
        numerical.admit(verification_scratch::LIMIT_BYTES)?;
        let configuration_bytes = profile::verification::requested_bytes();
        let public_copy_bytes = bytes::<Val>(air.program().public_values())?;
        let temporary_requested_bytes = add(
            add(numerical.requested_bytes, configuration_bytes)?,
            add(public_copy_bytes, DIAGNOSTIC_BYTES)?,
        )?;
        Ok(Self {
            proof_backing_bytes,
            numerical_bytes: numerical.requested_bytes,
            configuration_bytes,
            public_copy_bytes,
            diagnostic_bytes: DIAGNOSTIC_BYTES,
            temporary_requested_bytes,
        })
    }

    pub(in super::super) fn admit(self) -> Result<(), &'static str> {
        if self.proof_backing_bytes > PROOF_LIMIT_BYTES
            || self.temporary_requested_bytes > TEMPORARY_LIMIT_BYTES
        {
            return Err(ERROR);
        }
        Ok(())
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    #[test]
    fn capacity_and_temporary_limits_reject_overflow_and_accept_exact_boundary() {
        assert!(add(usize::MAX, 1).is_err());
        assert!(bytes::<Val>(usize::MAX).is_err());
        let mut heap = Backing::default();
        heap.capacity::<u8>(PROOF_LIMIT_BYTES).unwrap();
        assert!(heap.capacity::<u8>(1).is_err());
        let mut plan = Plan {
            proof_backing_bytes: PROOF_LIMIT_BYTES,
            numerical_bytes: 0,
            configuration_bytes: 0,
            public_copy_bytes: 0,
            diagnostic_bytes: 0,
            temporary_requested_bytes: TEMPORARY_LIMIT_BYTES,
        };
        plan.admit().unwrap();
        plan.temporary_requested_bytes += 1;
        assert!(plan.admit().is_err());
        plan.temporary_requested_bytes -= 1;
        plan.proof_backing_bytes += 1;
        assert!(plan.admit().is_err());
    }
}
