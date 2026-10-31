//! Native-only completion from the actual context-owned diagnostic state.
use super::*;
use crate::execution::generation_terminal::GenerationError;

#[derive(Clone, Copy, serde::Serialize)]
pub(crate) struct NativeGenerationTotals {
    pub(crate) spends: u64,
    pub(crate) seconds: f64,
    pub(crate) managed_peak_bytes: usize,
    pub(crate) witness_completed_calls: u64,
    pub(crate) witness_device_calls: u64,
    pub(crate) witness_device_ns: u128,
}

/// No constructor, Clone or numerical attachment API. Only the real diagnostic
/// owner can issue this value; it does not itself certify Session shutdown.
pub(crate) struct NativeGenerationCompletion {
    session_id: u64,
    totals: NativeGenerationTotals,
}
impl NativeGenerationCompletion {
    pub(crate) fn session_id(&self) -> u64 { self.session_id }
    pub(crate) fn totals(&self) -> NativeGenerationTotals { self.totals }
}

impl Diagnostics {
    pub(in crate::execution) fn native_generation_completion(&self, session_id: u64,
        expected: usize) -> Result<NativeGenerationCompletion, GenerationError>
    {
        let state = self.state.try_borrow().map_err(|_| GenerationError::Busy)?;
        if self.session_id != session_id || self.policy != Policy::GpuRequired
            || !matches!(expected, 3 | 4) || state.directory.is_some()
            || state.artifact_attempted || !state.failures.is_empty()
            || state.stark_work_attempted
            || state.prove_calls != 0 || state.prove_succeeded != 0
            || state.prove_active_rows != 0 || state.prove_padded_rows != 0
            || state.verify_calls != 0 || state.verify_succeeded != 0
            || state.native_calls != 0 || state.native_succeeded != 0
            || state.native_gpu.calls != 0 || state.native_gpu.succeeded != 0
            || state.native_gpu.reports != 0
            || state.native_gpu.stages.iter().any(|s|
                s.completed_calls != 0 || s.device_calls != 0 || s.device_ns != 0)
            || state.witness_preparation.calls != 0 || state.witness_preparation.succeeded != 0
            || state.witness_preparation.reports != 0
            || state.native_spend.calls != expected as u64
            || state.native_spend.succeeded != expected as u64
            || state.native_spend.reports != expected as u64
            || !state.native_spend.seconds.is_finite() || state.native_spend.seconds <= 0.0
            || state.native_spend.peak_managed_bytes == 0
            || state.native_spend.peak_managed_bytes > 8 << 30
            || state.native_spend.witness.completed_calls < expected as u64
            || state.native_spend.witness.device_calls < expected as u64
            || state.native_spend.witness.device_calls > state.native_spend.witness.completed_calls
        { return Err(GenerationError::Completion); }
        Ok(NativeGenerationCompletion { session_id, totals: NativeGenerationTotals {
            spends: state.native_spend.reports,
            seconds: state.native_spend.seconds,
            managed_peak_bytes: state.native_spend.peak_managed_bytes,
            witness_completed_calls: state.native_spend.witness.completed_calls,
            witness_device_calls: state.native_spend.witness.device_calls,
            witness_device_ns: state.native_spend.witness.device_ns,
        } })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Diagnostics {
        let diagnostics = Diagnostics::new(9, Policy::GpuRequired, Value::Null);
        {
            let mut state = diagnostics.state.borrow_mut();
            state.native_spend.calls = 3;
            state.native_spend.succeeded = 3;
            state.native_spend.reports = 3;
            state.native_spend.seconds = 1.0;
            state.native_spend.peak_managed_bytes = 1024;
            state.native_spend.witness.completed_calls = 3;
            state.native_spend.witness.device_calls = 3;
        }
        diagnostics
    }
    #[test]
    fn completion_rejects_failed_extra_spend_and_other_work() {
        let diagnostics = valid();
        assert_eq!(diagnostics.native_generation_completion(9, 3).unwrap().totals().spends, 3);
        diagnostics.state.borrow_mut().native_spend.calls = 4;
        assert!(diagnostics.native_generation_completion(9, 3).is_err());
        let diagnostics = valid();
        diagnostics.state.borrow_mut().stark_work_attempted = true;
        assert!(diagnostics.native_generation_completion(9, 3).is_err());
        let diagnostics = valid();
        diagnostics.state.borrow_mut().witness_preparation.calls = 1;
        assert!(diagnostics.native_generation_completion(9, 3).is_err());
    }
    #[test]
    fn completion_binds_actual_session_and_exact_success_count() {
        let diagnostics = valid();
        assert!(diagnostics.native_generation_completion(8, 3).is_err());
        assert!(diagnostics.native_generation_completion(9, 4).is_err());
        assert!(diagnostics.native_generation_completion(9, 0).is_err());
        diagnostics.state.borrow_mut().native_spend.witness.completed_calls = 2;
        assert!(diagnostics.native_generation_completion(9, 3).is_err());
    }
}
