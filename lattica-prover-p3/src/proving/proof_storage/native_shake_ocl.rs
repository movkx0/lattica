//! Additive OCL wrappers for the fixed singleton/batch native SHAKE producer.
//! This arithmetic is not a runtime, token or proof-dispatch capability.
use super::super::Error;
use super::outer_ocl::FixedOuterOclStorage;
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedNativeShakeOclStorage {
    required_host_bytes: usize,
}

impl FixedNativeShakeOclStorage {
    /// Native SHAKE uses the same ordinary quotient/NTT/opening/FRI kernels
    /// and single specialized quotient Program as the cubic outer schedule.
    /// Its additional crypto_trace launches have nine supplied arguments;
    /// public canonicalization has three. Both fit the separately audited
    /// sixteen-argument/two-live-pair source inventory. Kernel temporaries
    /// retire in each launch statement; EventBatch retains Events, not Kernels.
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

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;

    #[test]
    fn native_wrapper_inventory_is_pure_and_additive_to_its_source_basis() {
        let (native, requests) = crate::spill_alloc::allocation_requests::measure(|| {
            FixedNativeShakeOclStorage::fixed().unwrap()
        });
        assert_eq!(
            (requests.calls, requests.bytes, requests.overflow),
            (0, 0, false)
        );
        assert_eq!(
            native.required_host_bytes(),
            FixedOuterOclStorage::fixed().unwrap().required_host_bytes()
                + size_of::<FixedNativeShakeOclStorage>()
        );
    }

    #[test]
    fn actual_native_trace_builders_stay_within_shared_argument_inventory() {
        let source = include_str!("../../block_v2/gpu_hash/engine/device/pq_crypto.rs");
        let trace = source
            .split(".kernel_builder(name)")
            .nth(1)
            .unwrap()
            .split(".global_work_size(work)")
            .next()
            .unwrap();
        let rows = source
            .split(".kernel_builder(\"pq_crypto_poseidon_rows\")")
            .nth(1)
            .unwrap()
            .split(".global_work_size(plan.rows * plan.pose_count)")
            .next()
            .unwrap();
        let public = source
            .split(".kernel_builder(\"pq_crypto_public_values\")")
            .nth(1)
            .unwrap()
            .split(".global_work_size(plan.specs[1].columns())")
            .next()
            .unwrap();
        assert_eq!(trace.matches(".arg(").count(), 9);
        assert_eq!(rows.matches(".arg(").count(), 9);
        assert_eq!(public.matches(".arg(").count(), 3);
        assert!(!source.contains(".arg_named(") && !source.contains("KernelCache"));
    }
}
