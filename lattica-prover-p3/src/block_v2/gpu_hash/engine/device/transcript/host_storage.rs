//! Retained transcript family storage, without reading duplex state. The owned
//! opening/FRI call is synchronous and does not snapshot the challenger. This
//! counts current live states. The separate session host quota owns each state
//! through cleanup and bounds future state growth and concurrent operation
//! scratch within the opening partition's fixed envelope.
use super::*;
use crate::block_v2::gpu_hash::cache_metadata::{add, arc_bytes, capacity};

pub(super) fn family_bytes(states: usize) -> Result<usize, String> {
    if states == 0 {
        return Err("opening transcript has no live state".into());
    }
    // Each state is stored inline in a CandidateChallenger and owns one
    // allocation Arc through its inline SecretAllocation. Shared failure and
    // live-state counters are counted once; include the proof-attempt guard.
    let states_bytes = add(
        capacity::<crate::block_v2::challenger::CandidateChallenger>(states)?,
        states
            .checked_mul(arc_bytes::<Allocation>())
            .ok_or("transcript storage overflow")?,
    )?;
    add(
        states_bytes,
        arc_bytes::<AtomicUsize>()
            + arc_bytes::<Mutex<bool>>()
            + core::mem::size_of::<TranscriptAttempt>(),
    )
}

impl DeviceTranscript {
    pub(crate) fn opening_host_backing(&self) -> Result<(usize, usize), String> {
        let states = self.slot.live.load(Ordering::Acquire);
        if states > self.slot.limit {
            return Err("opening transcript exceeds live-state limit".into());
        }
        Ok((family_bytes(states)?, states))
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;
    use core::mem::MaybeUninit;

    #[test]
    fn opening_transcript_family_matches_allocator_requests() {
        let (_owners, allocated) = measure(|| {
            (
                Arc::new(MaybeUninit::<Allocation>::uninit()),
                Arc::new(MaybeUninit::<Allocation>::uninit()),
                Arc::new(AtomicUsize::new(2)),
                Arc::new(Mutex::new(false)),
            )
        });
        let (bytes, census) = measure(|| family_bytes(2).unwrap());
        assert_eq!(
            bytes,
            allocated.bytes
                + 2 * core::mem::size_of::<crate::block_v2::challenger::CandidateChallenger>()
                + core::mem::size_of::<TranscriptAttempt>()
        );
        assert_eq!(allocated.calls, 4);
        assert_eq!(census.calls, 0);
        assert!(!allocated.overflow && !census.overflow);
        eprintln!("opening_transcript_family_census states=2 planned_bytes={} independent_bytes={} allocation_free=true",
            bytes, allocated.bytes
                + 2 * core::mem::size_of::<crate::block_v2::challenger::CandidateChallenger>()
                + core::mem::size_of::<TranscriptAttempt>());
        assert!(family_bytes(0).is_err());
        assert!(family_bytes(usize::MAX).is_err());
    }

    #[test]
    fn opening_transcript_census_tracks_shared_state_slots() {
        let root = StateSlot::new(2).unwrap();
        let one = family_bytes(root.live.load(Ordering::Acquire)).unwrap();
        let clone = root.acquire().unwrap();
        let two = family_bytes(root.live.load(Ordering::Acquire)).unwrap();
        assert_eq!(
            two - one,
            core::mem::size_of::<crate::block_v2::challenger::CandidateChallenger>()
                + arc_bytes::<Allocation>()
        );
        assert!(root.acquire().is_err());
        drop(clone);
        assert_eq!(
            family_bytes(root.live.load(Ordering::Acquire)).unwrap(),
            one
        );
    }
}
