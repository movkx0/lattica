//! Additive OCL wrappers for the fixed serial native transcript producer.
//! This arithmetic is not a runtime, token or proof-dispatch capability.
use super::super::Error;
use super::outer_ocl::FixedOuterOclStorage;
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedNativeTranscriptOclStorage {
    required_host_bytes: usize,
}

impl FixedNativeTranscriptOclStorage {
    /// Native transcript sampling uses the same ordinary quotient/NTT/opening/FRI kernels
    /// and single specialized quotient Program as the cubic outer schedule.
    /// pq_sampling_trace launches five transcript kernels serially. The chain has
    /// five explicit arguments plus four constants; hints has three; Poseidon
    /// has three plus four constants; bundle has two plus four constants;
    /// public has two. All fit the
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
