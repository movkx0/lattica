//! Bounded terminal observations after every original case owner has dropped.
//! The private ledger handle cannot admit, split, release, or dispatch work.
use super::{FreshGenerationBatch, FreshGenerationError, Result};
use crate::execution::retained_resources::{Bytes, Ledger, Snapshot};

pub(crate) struct FreshLedgerObservation {
    ledger: Ledger,
}

impl FreshLedgerObservation {
    pub(crate) fn snapshot(&self) -> Snapshot { self.ledger.snapshot() }

    /// Only numerical observations cross the final report boundary. A leaked
    /// or still-live original prevents publication of a completed case time.
    pub(crate) fn confirm_empty(&self) -> Result<Snapshot> {
        let snapshot = self.snapshot();
        if snapshot.current != Bytes::ZERO {
            return Err(FreshGenerationError::Resource("fresh workflow originals remain after terminal teardown"));
        }
        Ok(snapshot)
    }
}

impl<const N: usize> FreshGenerationBatch<N> {
    /// Capture while the case and its fixed cache/report backing are live.
    /// Sharing counters creates no new allowance and exposes no ledger API.
    pub(crate) fn ledger_observation(&self) -> FreshLedgerObservation {
        FreshLedgerObservation { ledger: self.ledger.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::{Category, WorkerAllowance};

    #[test]
    fn terminal_observation_requires_all_host_and_device_originals_to_drop() {
        for bytes in [Bytes { host: 1, device: 0 }, Bytes { host: 0, device: 1 }] {
            let ledger = Ledger::new(WorkerAllowance { host: 8, device: 8 });
            let observation = FreshLedgerObservation { ledger: ledger.clone() };
            let original = ledger.reserve(Category::Report, bytes).unwrap();
            assert!(observation.confirm_empty().is_err());
            assert_eq!(observation.snapshot().current, bytes);
            drop(original);
            let terminal = observation.confirm_empty().unwrap();
            assert_eq!(terminal.current, Bytes::ZERO);
            assert_eq!(terminal.peak, bytes);
        }
    }
}
