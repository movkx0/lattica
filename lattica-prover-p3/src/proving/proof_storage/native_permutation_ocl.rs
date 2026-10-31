//! Additive OCL wrappers for the fixed serial native permutation producer.
//! This arithmetic is not a runtime, token or proof-dispatch capability.
use super::super::Error;
use super::outer_ocl::FixedOuterOclStorage;
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedNativePermutationOclStorage {
    required_host_bytes: usize,
}

impl FixedNativePermutationOclStorage {
    /// Native permutation arithmetic uses the same ordinary quotient/NTT/opening/FRI kernels
    /// and single specialized quotient Program as the cubic outer schedule.
    /// research_arithmetic_trace launches three Permutation kernels serially:
    /// Permutation has nine arguments, Poseidon columns has
    /// eight, and public has three. All fit the
    /// separately audited sixteen-argument/two-live-pair source inventory.
    /// Each launch's builder/kernel is destroyed before its event is read;
    /// the next kernel does not coexist with a prior builder/kernel.
    ///
    /// Reusing that pure allocation inventory confers none of the outer
    /// dispatch authority. This distinct native census must have its own
    /// original token before startup, retained through exact runtime cleanup.
    /// Trace/source/public buffers, native configuration/preparation and every
    /// PCS payload are additive. Driver/compiler storage stays in the existing
    /// 4 GiB context reserve. No startup or backend overlap is subtracted.
    pub fn fixed() -> Result<Self, Error> {
        let common = FixedOuterOclStorage::fixed()?.required_host_bytes();
        let required_host_bytes = common
            // The common inventory already includes its own inline owner.
            // Keep both values charged rather than take a move/alias credit.
            .checked_add(size_of::<Self>())
            .ok_or(Error::ComponentRejected)?;
        Ok(Self {
            required_host_bytes,
        })
    }

    pub fn required_host_bytes(self) -> usize {
        self.required_host_bytes
    }
}
