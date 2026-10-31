//! Fixed failure-event inventory for the owned full-workflow call surface.
//! No failed proof is serialized here: a configured artifact directory is
//! refused, and the external runner captures terminal failures separately.
use super::{Diagnostics, MAX_ERROR_CHARS, MAX_EVENTS};
use crate::execution::workflow_footprint::{
    add, cloned_identity_json_bytes, growing, identity_json_bytes, mul, object_keys,
};
use core::mem::size_of;
use lattica_prover_p3::{block_v2::profile, gpu_device::Identity, proving::Policy};
use serde_json::Value;

type Error = &'static str;
mod generation;
const EVENT_KEYS: [&str; 8] = [
    "stage", "identity", "session_id", "policy", "device", "error", "returned_proof", "retry_attempted",
];
const IDENTITY_KEYS: [&str; 2] = ["program_identity_sha3_256", "canonical_manifest_sha3_256"];
// Superset of every maintained registration, cap mismatch, drain, admission and
// native admission identity. Alternative shapes are intentionally additive.
const DETAIL_KEYS: [&str; 11] = [
    "program_identity_sha3_256", "canonical_manifest_sha3_256", "registered_program_id",
    "preprocessing_cap", "expected_preprocessing_cap", "next_program", "prepared_program",
    "program_height", "maximum_rows", "entry", "rows",
];
const STAGES: [&str; 12] = [
    "registration_cap_mismatch", "prove", "verify", "registration_drain", "release_drain",
    "registration_admission", "native_cpu", "registration", "registered_callback", "native_gpu",
    "native_gpu_admission", "native_spend",
];
const NATIVE_ENTRIES: [&str; 10] = [
    "pq_aes_lane_native", "pq_shake_segment_native", "pq_shake_wide_native", "pq_aes_wide_native",
    "matrict_affine_gpu", "matrict_ntt_gpu", "matrict_mul_gpu", "matrict_g_bound_gpu",
    "matrict_permutation_gpu", "matrict_linear_map_gpu",
];

fn longest(values: &[&str]) -> usize {
    values.iter().map(|value| value.len()).max().unwrap_or(0)
}

fn cap_bytes() -> Result<usize, Error> {
    if profile::CAP_HEIGHT != 6 {
        return Err("workflow diagnostic cap inventory changed");
    }
    let roots = 1usize.checked_shl(profile::CAP_HEIGHT as u32)
        .ok_or("workflow diagnostic cap height overflow")?;
    // Temporary canonical rows, the outer JSON array and four scalar Values
    // for every cap row. Both actual JSON cloning and Vec growth are covered.
    add(growing::<[u64; 4]>(roots)?,
        add(growing::<Value>(roots)?, mul(roots, growing::<Value>(4)?)?)?)
}

fn event_bytes(identity: &Identity) -> Result<usize, Error> {
    let mut bytes = object_keys(&EVENT_KEYS)?;
    bytes = add(bytes, growing::<u8>(longest(&STAGES))?)?;
    bytes = add(bytes, growing::<u8>("gpu_required".len())?)?;
    bytes = add(bytes, cloned_identity_json_bytes(identity)?)?;
    // The bound is in Unicode scalar values; four UTF-8 bytes per scalar are
    // required. Counting only MAX_ERROR_CHARS bytes would be unsound.
    bytes = add(bytes, growing::<u8>(mul(MAX_ERROR_CHARS, 4)?)?)?;
    bytes = add(bytes, object_keys(&DETAIL_KEYS)?)?;
    bytes = add(bytes, object_keys(&IDENTITY_KEYS)?)?;
    bytes = add(bytes, mul(4, growing::<u8>(64)?)?)?;
    bytes = add(bytes, mul(2, cap_bytes()?)?)?;
    bytes = add(bytes, growing::<Value>(4)?)?;
    add(bytes, growing::<u8>(longest(&NATIVE_ENTRIES))?)
}

impl Diagnostics {
    pub(in crate::execution) fn workflow_enclosing_bytes(
        &self,
        identity: &Identity,
        session_id: u64,
        policy: Policy,
    ) -> Result<usize, Error> {
        let state = self.state.try_borrow().map_err(|_| "workflow diagnostics busy")?;
        if self.session_id != session_id || self.policy != policy || policy != Policy::GpuRequired
            || state.directory.is_some() || state.artifact_attempted || !state.failures.is_empty()
            || state.failures.capacity() != 0 || state.stark_work_attempted
            || state.prove_calls != 0 || state.prove_succeeded != 0 || state.prove_seconds != 0.0
            || state.prove_active_rows != 0 || state.prove_padded_rows != 0
            || state.verify_calls != 0 || state.verify_succeeded != 0 || state.verify_seconds != 0.0
            || state.native_calls != 0 || state.native_succeeded != 0 || state.native_seconds != 0.0
            || state.native_gpu.calls != 0 || state.native_gpu.succeeded != 0
            || state.native_gpu.seconds != 0.0 || state.native_gpu.reports != 0
            || state.native_gpu.stages.iter().any(|stage|
                stage.completed_calls != 0 || stage.device_calls != 0 || stage.device_ns != 0)
            || state.witness_preparation.calls != 0 || state.witness_preparation.succeeded != 0
            || state.witness_preparation.seconds != 0.0 || state.witness_preparation.reports != 0
            || state.witness_preparation.witness.completed_calls != 0
            || state.witness_preparation.witness.device_calls != 0
            || state.witness_preparation.witness.device_ns != 0
            || state.native_spend.calls != 0 || state.native_spend.succeeded != 0
            || state.native_spend.seconds != 0.0 || state.native_spend.reports != 0
            || state.native_spend.peak_managed_bytes != 0
            || state.native_spend.witness.completed_calls != 0
            || state.native_spend.witness.device_calls != 0
            || state.native_spend.witness.device_ns != 0
        {
            return Err("workflow enclosing census requires pristine artifact-free diagnostics");
        }
        // Rc's two counters plus the owned Diagnostics allocation. The Rc
        // handle and all State headers are already inline in these owners.
        let mut bytes = add(size_of::<Self>(), mul(2, size_of::<usize>())?)?;
        bytes = add(bytes, identity_json_bytes(&self.device, identity)?)?;
        // Event construction can clone its identity argument while the original
        // lives, and begins before the oldest retained event is removed. Two
        // copies of 33 complete event bounds cover that peak, as well as one
        // report's clone of all 32 retained events. The report's own outer JSON
        // and output serialization remain the caller's phase responsibility.
        bytes = add(bytes, mul(mul(add(MAX_EVENTS, 1)?, 2)?, event_bytes(identity)?)?)?;
        add(bytes, growing::<Value>(add(MAX_EVENTS, 1)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity { opencl_index: 0, uuid: None, name: "NVIDIA GeForce RTX 5080".into(),
            pci: None, global_bytes: 16 << 30, max_allocation_bytes: 8 << 30, driver: "test".into() }
    }

    #[test]
    fn diagnostic_census_rejects_work_and_failure_artifacts() {
        let identity = identity();
        let diagnostics = Diagnostics::new(7, Policy::GpuRequired, serde_json::to_value(&identity).unwrap());
        assert!(diagnostics.workflow_enclosing_bytes(&identity, 7, Policy::GpuRequired).is_ok());
        diagnostics.state.borrow_mut().directory = Some("/tmp".into());
        assert!(diagnostics.workflow_enclosing_bytes(&identity, 7, Policy::GpuRequired).is_err());
        diagnostics.state.borrow_mut().directory = None;
        diagnostics.state.borrow_mut().witness_preparation.calls = 1;
        assert!(diagnostics.workflow_enclosing_bytes(&identity, 7, Policy::GpuRequired).is_err());
    }

    #[test]
    fn diagnostic_census_binds_session_policy_and_both_cap_arrays() {
        let identity = identity();
        let diagnostics = Diagnostics::new(7, Policy::GpuRequired, serde_json::to_value(&identity).unwrap());
        assert!(diagnostics.workflow_enclosing_bytes(&identity, 8, Policy::GpuRequired).is_err());
        assert!(diagnostics.workflow_enclosing_bytes(&identity, 7, Policy::CpuRequired).is_err());
        let events = event_bytes(&identity).unwrap();
        assert!(events > 2 * cap_bytes().unwrap() + MAX_ERROR_CHARS * 4);
        assert!(diagnostics.workflow_enclosing_bytes(&identity, 7, Policy::GpuRequired).unwrap()
            > 2 * (MAX_EVENTS + 1) * events);
    }
}
