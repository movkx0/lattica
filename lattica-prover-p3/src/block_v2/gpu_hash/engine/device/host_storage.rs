//! Shared session ownership retained by a synchronous opening call.
use super::*;
use crate::block_v2::challenger::{resources, storage::Plan};
use crate::block_v2::gpu_hash::cache_metadata::arc_bytes;
mod quota;
pub(crate) use quota::{HostQuota, HostScope};

pub(super) fn new_quota() -> Arc<HostQuota> {
    Arc::new(HostQuota::new(resources::HOST_BYTES))
}

fn session_bytes() -> usize {
    // Session owns only inline counters/mutexes and its context Arc. The
    // context allocation and accounting Arc belong to the engine envelope.
    core::mem::size_of::<DeviceSession>() + arc_bytes::<Session>() + arc_bytes::<HostQuota>()
}

impl DeviceSession {
    pub(crate) fn reserve_transcript_host(&self, plan: Plan) -> Result<HostScope, String> {
        plan.admit(resources::HOST_BYTES)?;
        self.session.transcript_host.reserve(plan.bytes)
    }

    pub(crate) fn check_transcript_host(
        &self,
        scope: &mut HostScope,
        plan: Plan,
    ) -> Result<(), String> {
        scope.check(&self.session.transcript_host, plan.bytes)
    }

    pub(crate) fn transcript_state_host_backing() -> Result<usize, String> {
        super::transcript::state_host_backing()
    }

    #[cfg(test)]
    pub(crate) fn transcript_host_reserved_bytes(&self) -> usize {
        self.session.transcript_host.live()
    }

    /// Three temporary allocation owners cover transcript grinding or scalar
    /// input/output. Retained state is charged separately; opaque library and
    /// driver allocations are outside this Rust backing calculation.
    pub(crate) fn transient_host_backing() -> usize {
        core::mem::size_of::<HostScope>()
            + core::mem::size_of::<MemoryPlan>()
            + 2 * core::mem::size_of::<usize>()
            + 3 * (arc_bytes::<Allocation>()
                + core::mem::size_of::<DeviceMatrix>()
                    .max(core::mem::size_of::<super::random::SecretAllocation>()))
    }

    pub(crate) fn opening_host_reservation(&self) -> Result<(usize, usize), String> {
        self.with_engine(|engine| {
            Ok((
                super::super::host_storage::opening_reservation(engine)?,
                session_bytes(),
            ))
        })
    }
}

#[cfg(all(test, feature = "stream"))]
#[test]
fn opening_session_backing_matches_allocator_requests() {
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;
    let (_session, allocation) =
        measure(|| (Arc::new(MaybeUninit::<Session>::uninit()), new_quota()));
    let (bytes, census) = measure(session_bytes);
    assert_eq!(
        bytes,
        allocation.bytes + core::mem::size_of::<DeviceSession>()
    );
    assert_eq!(allocation.calls, 2);
    assert_eq!(census.calls, 0);
    assert!(!allocation.overflow && !census.overflow);
    eprintln!(
        "opening_session_census planned_bytes={} independent_bytes={} allocation_free=true",
        bytes,
        allocation.bytes + core::mem::size_of::<DeviceSession>()
    );
}

#[cfg(all(test, feature = "stream"))]
#[test]
fn transient_allocation_wrapper_layout_matches_allocator_requests() {
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;
    let (_owners, allocation) = measure(|| {
        (
            std::array::from_fn::<_, 3, _>(|_| Arc::new(MaybeUninit::<Allocation>::uninit())),
            Vec::<usize>::with_capacity(2),
        )
    });
    let independent = allocation.bytes
        + core::mem::size_of::<HostScope>()
        + core::mem::size_of::<MemoryPlan>()
        + 3 * core::mem::size_of::<DeviceMatrix>()
            .max(core::mem::size_of::<super::random::SecretAllocation>());
    let (bytes, census) = measure(DeviceSession::transient_host_backing);
    assert_eq!(bytes, independent);
    assert_eq!(allocation.calls, 4);
    assert_eq!(census.calls, 0);
    assert!(!allocation.overflow && !census.overflow);
    eprintln!("transcript_temporary_wrappers planned_bytes={bytes} independent_bytes={independent} allocation_free=true");
}
