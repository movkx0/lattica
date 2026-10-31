//! The decoder, producer and verifier use the same opaque core ledger/token.
//! These aliases add no wrapper or allocation to the established owner census.
pub use lattica_prover_p3::note_research_quota::QuotaSnapshot;
pub(super) use lattica_prover_p3::note_research_quota::{Quota, Reservation, LEDGER_BYTES};

impl From<lattica_prover_p3::note_research_quota::ResourceLimit> for super::Error {
    fn from(_: lattica_prover_p3::note_research_quota::ResourceLimit) -> Self {
        Self::ResourceLimit
    }
}
