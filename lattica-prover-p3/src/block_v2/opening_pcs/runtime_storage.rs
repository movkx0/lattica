//! The retained engine, session and GPU transcript coexist with opening/FRI.
//! This composes their host backing with the commitment partition; it is not a
//! whole-proof reservation or an allowance for opaque driver allocations.
//! The fixed scratch allowance is a session-wide quota: new transcript states
//! and concurrent scalar/transcript operations hold charges against it. The
//! current-state census is additional conservative retained backing. Escaped
//! outputs still require ownership in their enclosing phase or caller.
use super::{super::gpu_hash::device::DeviceSession, Challenger};

#[derive(Debug)]
pub(super) struct Partition {
    engine_bytes: usize,
    session_bytes: usize,
    transcript_bytes: usize,
    transcript_states: usize,
    retained_bytes: usize,
    scratch_bytes: usize,
    charged_bytes: usize,
    pub opening_allowance: usize,
    allowance: usize,
}

impl Partition {
    fn from_backing(
        engine_bytes: usize,
        session_bytes: usize,
        transcript_bytes: usize,
        transcript_states: usize,
        scratch_bytes: usize,
        allowance: usize,
    ) -> Result<Self, String> {
        let retained_bytes = engine_bytes
            .checked_add(session_bytes)
            .and_then(|bytes| bytes.checked_add(transcript_bytes))
            .ok_or("opening runtime storage overflow")?;
        let charged_bytes = retained_bytes
            .checked_add(scratch_bytes)
            .ok_or("opening runtime scratch overflow")?;
        let opening_allowance = allowance
            .checked_sub(charged_bytes)
            .filter(|bytes| *bytes > 0)
            .ok_or("retained runtime exceeds opening allowance")?;
        Ok(Self {
            engine_bytes,
            session_bytes,
            transcript_bytes,
            transcript_states,
            retained_bytes,
            scratch_bytes,
            charged_bytes,
            opening_allowance,
            allowance,
        })
    }

    pub(super) fn new(
        session: &DeviceSession,
        challenger: &Challenger,
        allowance: usize,
    ) -> Result<Option<Self>, String> {
        let Some((transcript_bytes, transcript_states)) =
            challenger.opening_host_backing(session)?
        else {
            return Ok(None);
        };
        let (engine_bytes, session_bytes) = session.opening_host_reservation()?;
        Self::from_backing(
            engine_bytes,
            session_bytes,
            transcript_bytes,
            transcript_states,
            super::super::challenger::storage::reservation()?,
            allowance,
        )
        .map(Some)
    }

    pub(super) fn report(&self) {
        eprintln!("bounded_opening_runtime_partition engine_bytes={} session_bytes={} transcript_bytes={} transcript_states={} retained_bytes={} scratch_bytes={} charged_bytes={} opening_allowance_bytes={} allowance_bytes={} whole_proof=false",
            self.engine_bytes, self.session_bytes, self.transcript_bytes, self.transcript_states,
            self.retained_bytes, self.scratch_bytes, self.charged_bytes, self.opening_allowance, self.allowance);
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;

    #[test]
    fn runtime_partition_reserves_each_owner_without_allocating() {
        let (plan, census) = measure(|| Partition::from_backing(128, 32, 17, 2, 11, 256).unwrap());
        assert_eq!(plan.retained_bytes, 177);
        assert_eq!(plan.scratch_bytes, 11);
        assert_eq!(plan.charged_bytes, 188);
        assert_eq!(plan.opening_allowance, 68);
        assert_eq!(
            plan.retained_bytes + plan.scratch_bytes + plan.opening_allowance,
            plan.allowance
        );
        assert_eq!(census.calls, 0);
        assert!(!census.overflow);
    }

    #[test]
    fn runtime_partition_rejects_exhausted_and_overflowed_allowances() {
        for allowance in [0, 187, 188] {
            assert!(Partition::from_backing(128, 32, 17, 2, 11, allowance).is_err());
        }
        assert_eq!(
            Partition::from_backing(128, 32, 17, 2, 11, 189)
                .unwrap()
                .opening_allowance,
            1
        );
        assert!(Partition::from_backing(usize::MAX, 1, 0, 1, 0, usize::MAX).is_err());
        assert!(Partition::from_backing(0, usize::MAX, 1, 1, 0, usize::MAX).is_err());
        assert!(Partition::from_backing(1, 0, 0, 1, usize::MAX, usize::MAX).is_err());
    }
}
