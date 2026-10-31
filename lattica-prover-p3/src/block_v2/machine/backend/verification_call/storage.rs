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

/// Same release-x86_64 verifier admission and error as before. The portable
/// helper only counts backing capacities; it never validates a proof.
pub(in super::super) fn proof_bytes(proof: &BatchProof<Config>) -> Result<usize, &'static str> {
    super::super::retained_proof_capacity_bytes(proof, PROOF_LIMIT_BYTES)
        .map_err(|_| ERROR)
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
