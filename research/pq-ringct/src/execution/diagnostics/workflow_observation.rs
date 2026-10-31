//! Allocation-free borrowed snapshot of actual source-context counters.
use super::*;
use crate::execution::owned_workflow_observation::{ObservationError, SourcePreparationSnapshot};

impl Diagnostics {
    pub(in crate::execution) fn source_observation_host_bytes() -> Result<usize, ObservationError> {
        use core::mem::size_of;
        [size_of::<std::cell::Ref<'static, State>>(), size_of::<&WitnessPreparationTotals>(),
            size_of::<SourcePreparationSnapshot>(), size_of::<Result<SourcePreparationSnapshot, ObservationError>>(),
            size_of::<Result<u64, core::num::TryFromIntError>>(), size_of::<[u64; 4]>(),
        ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
            .and_then(|bytes| bytes.checked_mul(8)).ok_or(ObservationError::Overflow)
    }

    pub(in crate::execution) fn source_preparation_snapshot(&self, session_id: u64)
        -> Result<SourcePreparationSnapshot, ObservationError>
    {
        if self.session_id != session_id || self.policy != Policy::GpuRequired {
            return Err(ObservationError::Context);
        }
        let state = self.state.try_borrow().map_err(|_| ObservationError::Busy)?;
        let preparation = &state.witness_preparation;
        if !preparation.seconds.is_finite() || preparation.seconds < 0.0 {
            return Err(ObservationError::Report);
        }
        Ok(SourcePreparationSnapshot { session_id,
            calls: preparation.calls, succeeded: preparation.succeeded,
            complete_reports: preparation.reports, seconds: preparation.seconds,
            witness_completed_calls: preparation.witness.completed_calls,
            witness_device_calls: preparation.witness.device_calls,
            witness_device_ns: preparation.witness.device_ns,
            native_cpu_calls: state.native_calls, native_cpu_succeeded: state.native_succeeded,
            failure_events: u64::try_from(state.failures.len()).map_err(|_| ObservationError::Overflow)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_snapshot_reads_independent_actual_counters_and_session() {
        let diagnostics = Diagnostics::new(37, Policy::GpuRequired, Value::Null);
        {
            let mut state = diagnostics.state.borrow_mut();
            state.witness_preparation.calls = 3;
            state.witness_preparation.succeeded = 2;
            state.witness_preparation.reports = 1;
            state.witness_preparation.seconds = 0.5;
            state.witness_preparation.witness.completed_calls = 9;
            state.witness_preparation.witness.device_calls = 7;
            state.witness_preparation.witness.device_ns = 11;
            state.native_calls = 4;
            state.native_succeeded = 3;
        }
        let snapshot = diagnostics.source_preparation_snapshot(37).unwrap();
        assert_eq!((snapshot.calls, snapshot.succeeded, snapshot.complete_reports), (3, 2, 1));
        assert_eq!((snapshot.witness_completed_calls, snapshot.witness_device_calls), (9, 7));
        assert_eq!(snapshot.witness_device_ns, 11);
        assert_eq!((snapshot.native_cpu_calls, snapshot.native_cpu_succeeded), (4, 3));
        assert_eq!(diagnostics.source_preparation_snapshot(38), Err(ObservationError::Context));
    }

    #[test]
    fn source_snapshot_rejects_busy_or_nonfinite_observations() {
        let diagnostics = Diagnostics::new(37, Policy::GpuRequired, Value::Null);
        let mut state = diagnostics.state.borrow_mut();
        assert_eq!(diagnostics.source_preparation_snapshot(37), Err(ObservationError::Busy));
        state.witness_preparation.seconds = f64::NAN;
        drop(state);
        assert_eq!(diagnostics.source_preparation_snapshot(37), Err(ObservationError::Report));
    }
}
