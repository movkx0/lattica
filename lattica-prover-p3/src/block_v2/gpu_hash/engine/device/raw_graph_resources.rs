//! Data-wrapper storage for one sequential fixed MatRiCT raw operation.
//! The graph constructor composes this into its real preceding reservation.
//! Runtime, kernel builders, reports/errors and driver storage are separate.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]
use super::*;
use crate::block_v2::gpu_hash::cache_metadata::arc_bytes;
use core::mem::size_of;

#[derive(Clone, Copy, Debug)]
pub struct RawGraphOperationStorage {
    allocation_owner_bytes: usize,
    planner_bytes: usize,
    inline_bytes: usize,
    requested_bytes: usize,
}
impl RawGraphOperationStorage {
    /// The largest raw arithmetic/crypto call has four secret buffers. Graph
    /// operations serialize on the context and scrub/fence before returning.
    /// Raw result Vec backing is charged by the exact caller's schedule.
    pub fn fixed() -> Result<Self, &'static str> {
        let allocation_owner_bytes = 4usize
            .checked_mul(size_of::<random::SecretAllocation>() + arc_bytes::<Allocation>())
            .ok_or("raw graph allocation owner overflow")?;
        // Arithmetic collects four MatrixSpecs; MemoryPlan::new allocates one
        // four-entry Vec. SecretAllocation::new uses allocation directly and
        // does not recursively construct another MemoryPlan. The crypto/node
        // paths use smaller or inline spec arrays. Three covers growth overlap.
        let planner_bytes = 3usize
            .checked_mul(4 * (size_of::<MatrixSpec>() + size_of::<usize>()))
            .ok_or("raw graph planner overflow")?;
        let inline_bytes = size_of::<MemoryPlan>()
            + size_of::<crate::block_v2::native_gpu::operations_arithmetic::ArithmeticOperationSpec>()
            + size_of::<[MatrixSpec; 4]>()
            + size_of::<[usize; 4]>()
            + size_of::<[u64; 5]>()
            + 3 * size_of::<Vec<u64>>()
            + size_of::<Allocation>() // the value before Arc::new moves it
            + size_of::<event_batch::EventBatch<'static>>()
            + 2 * size_of::<compute::Event>()
            + 2 * size_of::<super::super::QueueFence>()
            + pq_raw_crypto::graph_payload_inline_bytes()
            + size_of::<Self>()
            + super::preparation_storage::HOST_BYTES
            + crate::block_v2::native_gpu::RawCommitmentBatchStorage::HOST_BYTES;
        let requested_bytes = allocation_owner_bytes
            .checked_add(planner_bytes)
            .and_then(|bytes| bytes.checked_add(inline_bytes))
            .ok_or("raw graph wrapper sum overflow")?;
        Ok(Self {
            allocation_owner_bytes,
            planner_bytes,
            inline_bytes,
            requested_bytes,
        })
    }

    pub fn requested_bytes(self) -> usize {
        self.requested_bytes
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;

    #[test]
    fn raw_secret_wrapper_bound_covers_the_original_arc_requests() {
        let (_owners, measured) = measure(|| {
            core::array::from_fn::<_, 4, _>(|_| Arc::new(MaybeUninit::<Allocation>::uninit()))
        });
        let plan = RawGraphOperationStorage::fixed().unwrap();
        assert!(!measured.overflow);
        assert_eq!(measured.calls, 4);
        assert_eq!(
            plan.allocation_owner_bytes,
            measured.bytes + 4 * size_of::<random::SecretAllocation>(),
        );
    }

    #[test]
    fn raw_wrapper_plan_allocates_nothing_and_charges_its_actual_fields() {
        let (plan, measured) = measure(|| RawGraphOperationStorage::fixed().unwrap());
        assert_eq!(
            (measured.calls, measured.bytes, measured.overflow),
            (0, 0, false)
        );
        assert_eq!(
            plan.requested_bytes,
            plan.allocation_owner_bytes + plan.planner_bytes + plan.inline_bytes
        );
    }

    #[test]
    fn fixed_raw_arithmetic_metadata_matches_the_constructor_bound() {
        use crate::block_v2::native_gpu::operations_arithmetic::ArithmeticOperationSpec as Spec;
        let ntt = Spec::ntt(
            167_770_241,
            1,
            &[[0, 128, 1, 1]; 768],
            &core::array::from_fn::<_, 64, _>(|i| i as u64),
        )
        .unwrap();
        let mul = Spec::mul(167_770_241, 1, &[[1, 0]; 1024]).unwrap();
        let aut = Spec::automorphism(&core::array::from_fn::<_, 256, _>(|i| i as u64), &[1; 256])
            .unwrap();
        for spec in [ntt, mul, aut] {
            assert!(spec.metadata.capacity() <= 2 * 3140);
            assert!(spec.input_words <= 512);
            assert!(spec.output_words <= 256);
            assert!(spec.work_items <= 256);
            assert!(spec.staging_bytes().unwrap() <= 3_060_528);
            let device =
                8 * (spec.input_words + spec.metadata.len() + spec.output_words + spec.work_items);
            assert!(device <= 1_844_280);
        }
    }
}
