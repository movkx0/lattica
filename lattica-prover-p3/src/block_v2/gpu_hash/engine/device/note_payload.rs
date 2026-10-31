//! Source-owned Rust wrappers for the fixed note's pre-opening operations.
//! The enclosing reservation must precede construction and outlive all these
//! owners. This census neither allocates device storage nor grants admission.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use super::*;
use crate::block_v2::gpu_hash::{cache_metadata::arc_bytes, engine::lde_execute::note_storage};
use core::mem::size_of;

// One periodic transform, at most one main-prefix transform, and two inputs
// per quotient coset. Sixteen cosets conservatively covers the fixed sixteen
// chunk profile (the current normalized graph actually uses eight cosets).
pub(crate) const TRANSFORMS: usize = 2 + 2 * 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Resources {
    ordinary_matrix_owner_bytes: usize,
    direct_allocation_owner_bytes: usize,
    private_sample_owner_bytes: usize,
    planner_backing_bytes: usize,
    inline_owner_bytes: usize,
    requested_payload_bytes: usize,
}

impl Resources {
    pub(crate) fn new() -> Result<Self, &'static str> {
        // Count across phases rather than recycle an earlier phase's wrapper.
        // Wallet trace/public/three scratch; periodic output/input/metadata;
        // projected main prefix; every transform output+scratch; full and
        // per-coset quotient results. Captured PCS outputs belong to C012.
        let ordinary_matrices = 5 + 3 + 1 + 2 * TRANSFORMS + 2;
        let ordinary_matrix_owner_bytes =
            ordinary_matrices * (size_of::<DeviceMatrix>() + matrix_host_backing(false));
        // Three constant/parameter allocations per transform, quotient code
        // plus five evaluator scratch allocations, and trace normalization /
        // quotient parameters / randomization parameters (one of each).
        // These Allocation owners are inline, not extra Arc allocations.
        let direct_allocations = 3 * TRANSFORMS + 6 + 3;
        let direct_allocation_owner_bytes = direct_allocations * size_of::<Allocation>();
        // Four retained hiding/randomization draws plus one active rejection
        // operation's output/raw/count/offset/total. Replays draw sequentially.
        // Each sample conservatively includes both its inline SecretAllocation
        // and a possible into_matrix scrub Arc; no alias credit is taken.
        let private_sample_owner_bytes = 9
            * (size_of::<RandomWords>()
                + size_of::<DeviceMatrix>()
                + arc_bytes::<Allocation>()
                + arc_bytes::<random::SecretAllocation>());
        // The largest request has five wallet specs. The deepest planning
        // chain is partition scalar-plan + result-plan + transform-plan;
        // allow one further inner allocation-plan without borrowing storage.
        // Runtime lde/scalar execution has its own plan plus allocate's plan.
        let planner_backing_bytes = 4 * note_storage::vector_backing::<usize>(5)?;
        let inline_owner_bytes = size_of::<Self>()
            + 4 * size_of::<MemoryPlan>()
            + size_of::<WalletTrace>()
            + size_of::<crate::gpu_wallet::Plan>()
            + size_of::<crate::gpu_wallet::InputWords>()
            + size_of::<PreparedQuotient>()
            + size_of::<quotient::PartitionStorage>()
            + 2 * size_of::<crate::gpu_random::Plan>()
            + size_of::<crate::gpu_random::FieldStoragePlan>()
            + 3 * size_of::<CommitInputStorage>();
        let requested_payload_bytes = [
            ordinary_matrix_owner_bytes,
            direct_allocation_owner_bytes,
            private_sample_owner_bytes,
            planner_backing_bytes,
            inline_owner_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |a, b| a.checked_add(b))
        .ok_or("note preopening wrapper census overflow")?;
        Ok(Self {
            ordinary_matrix_owner_bytes,
            direct_allocation_owner_bytes,
            private_sample_owner_bytes,
            planner_backing_bytes,
            inline_owner_bytes,
            requested_payload_bytes,
        })
    }

    pub(crate) fn requested_payload_bytes(self) -> usize {
        self.requested_payload_bytes
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;

    #[test]
    fn sample_wrapper_charge_covers_actual_arc_requests_without_alias_credit() {
        let (_owners, request) = measure(|| {
            std::array::from_fn::<_, 9, _>(|_| {
                (
                    Arc::new(MaybeUninit::<Allocation>::uninit()),
                    Arc::new(MaybeUninit::<random::SecretAllocation>::uninit()),
                )
            })
        });
        let report = Resources::new().unwrap();
        assert_eq!(request.calls, 18);
        assert!(!request.overflow);
        assert_eq!(
            report.private_sample_owner_bytes,
            request.bytes + 9 * (size_of::<RandomWords>() + size_of::<DeviceMatrix>())
        );
    }

    #[test]
    fn preopening_wrapper_census_allocates_nothing() {
        let (report, request) = measure(|| Resources::new().unwrap());
        assert_eq!(
            (request.calls, request.bytes, request.overflow),
            (0, 0, false)
        );
        assert!(report.requested_payload_bytes() > report.private_sample_owner_bytes);
    }
}
