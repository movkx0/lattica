use super::*;
use crate::block_v2::gpu_hash::engine::{
    lde_plan::LdeRetention, lde_readback::ReadbackLayout, Limits, CONSTANT_BYTES,
};

struct Fixed<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Fixed<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap()
    }
}
impl<const N: usize> fmt::Write for Fixed<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
fn plan(inputs: &[InputShape], retention: LdeRetention, layout: ReadbackLayout) -> LdeCommitPlan {
    let limits = Limits::default();
    LdeCommitPlan::new_with_retention(
        inputs,
        6,
        limits,
        4 << 30,
        1,
        CONSTANT_BYTES + limits.staging_bytes + 1024 + 2048,
        0,
        24 << 30,
        retention,
        layout,
    )
    .unwrap()
}
fn report<'a>(inputs: &'a [InputShape], plan: &'a LdeCommitPlan) -> LdePlanReport<'a> {
    LdePlanReport {
        inputs,
        plan,
        managed_cap_bytes: 8 << 30,
        max_allocation_bytes: 4 << 30,
        live_without_transform_bytes: CONSTANT_BYTES + Limits::default().staging_bytes,
        replaced_hash_workspace_bytes: 0,
        owned_output_bytes: 1024,
        replay_workspace_bytes: 2048,
        host_budget_bytes: 24 << 30,
    }
}

// Exact original commit_inputs_inner telemetry expression, kept only as the
// reference oracle. Its Value/maps/Strings are deliberately outside measurement.
fn legacy_value(report: &LdePlanReport<'_>) -> serde_json::Value {
    let plan = report.plan;
    serde_json::json!({
        "schema": "lattica-lde-plan-v1",
        "managed_cap_bytes": report.managed_cap_bytes,
        "max_allocation_bytes": report.max_allocation_bytes,
        "inputs": report.inputs.iter().map(|s| serde_json::json!({
            "rows": s.height, "columns": s.width, "added_bits": s.added_bits,
        })).collect::<Vec<_>>(),
        "output_rows": plan.output_height(),
        "live_without_transform_bytes": report.live_without_transform_bytes,
        "replaced_hash_workspace_bytes": report.replaced_hash_workspace_bytes,
        "owned_output_bytes": report.owned_output_bytes,
        "replay_workspace_bytes": report.replay_workspace_bytes,
        "hash_workspace_bytes": plan.hash_workspace_bytes,
        "retained_tree_bytes": plan.retained_tree_bytes,
        "retained_tree_storage": plan.tree_storage_mode,
        "retained_tree_device_bytes_after_commit": plan.retained_tree_device_bytes,
        "retained_tree_host_charge_bytes": plan.retained_tree_host_bytes,
        "sponge_state_bytes": plan.sponge_state_bytes,
        "twiddle_bytes": plan.twiddle_bytes,
        "query_reserve_bytes": plan.query_reserve_bytes,
        "fixed_bytes": plan.predicted_managed_peak_bytes - 2 * plan.transform_buffer_bytes,
        "columns_per_tile": plan.columns_per_tile(),
        "transform_buffer_bytes": plan.transform_buffer_bytes,
        "predicted_managed_peak_bytes": plan.predicted_managed_peak_bytes,
        "predicted_host_peak_bytes": plan.predicted_host_peak_bytes,
        "host_output_payload_bytes": plan.host_output_bytes,
        "host_output_backing_bytes": plan.host_output_backing_bytes,
        "host_reorder_payload_bytes": plan.host_reorder_workspace_bytes,
        "host_reorder_backing_bytes": plan.host_reorder_backing_bytes,
        "host_budget_bytes": report.host_budget_bytes,
    })
}

#[test]
fn borrowed_telemetry_matches_exact_legacy_json_for_note_commitment_shapes() {
    // Main trace, 16 quotient chunks and random codewords: distinct shapes
    // expose swapped fields and input flattening mistakes in the serializer.
    for (count, width) in [(1, 23), (16, 6), (1, 6)] {
        let inputs = vec![
            InputShape {
                height: 1 << 12,
                width,
                added_bits: 5
            };
            count
        ];
        let plan = plan(&inputs, LdeRetention::DeviceOnly, ReadbackLayout::Banded);
        let report = report(&inputs, &plan);
        let expected = legacy_value(&report);
        let mut output = Fixed::<4096>::new();
        report.write_to(&mut output).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(output.as_str()).unwrap(),
            expected
        );
        assert_eq!(output.as_str(), expected.to_string());
        assert_eq!(report.to_string(), output.as_str());
        assert_eq!(expected.as_object().unwrap().len(), 27);
        for entry in expected["inputs"].as_array().unwrap() {
            assert_eq!(entry.as_object().unwrap().len(), 3);
        }
    }
}

#[test]
fn retained_tree_storage_and_charges_match_current_schema_for_both_modes() {
    let inputs = [InputShape {
        height: 256,
        width: 3,
        added_bits: 4,
    }];
    let mut plan = plan(&inputs, LdeRetention::DeviceOnly, ReadbackLayout::Banded);
    // Distinct values test field mapping; these are report fixtures, not a claim
    // that this altered plan admits a device allocation or host-backed tree.
    plan.retained_tree_bytes = 789;
    plan.retained_tree_device_bytes = 123;
    plan.retained_tree_host_bytes = 456;
    for mode in [
        RetainedTreeStorageMode::Device,
        RetainedTreeStorageMode::HostBacking,
    ] {
        plan.tree_storage_mode = mode;
        let report = report(&inputs, &plan);
        let mut output = Fixed::<4096>::new();
        report.write_to(&mut output).unwrap();
        let expected = legacy_value(&report);
        assert_eq!(output.as_str(), expected.to_string());
        assert_eq!(expected["retained_tree_device_bytes_after_commit"], 123);
        assert_eq!(expected["retained_tree_host_charge_bytes"], 456);
        assert_eq!(
            expected["retained_tree_storage"],
            serde_json::to_value(mode).unwrap()
        );
    }
}

#[test]
fn host_retention_and_large_unsigned_values_keep_the_same_field_meanings() {
    let inputs = [InputShape {
        height: 1 << 8,
        width: 3,
        added_bits: 4,
    }];
    let plan = plan(&inputs, LdeRetention::HostPrefix(2), ReadbackLayout::Banded);
    let mut report = report(&inputs, &plan);
    report.replaced_hash_workspace_bytes = usize::MAX;
    report.owned_output_bytes = usize::MAX - 1;
    report.replay_workspace_bytes = usize::MAX - 2;
    report.host_budget_bytes = usize::MAX - 3;
    let mut output = Fixed::<4096>::new();
    report.write_to(&mut output).unwrap();
    assert_eq!(output.as_str(), legacy_value(&report).to_string());
    assert!(plan.host_output_backing_bytes > 0);
}

#[test]
fn invalid_fixed_term_refuses_before_writing_and_writer_failure_is_not_retried() {
    let inputs = [InputShape {
        height: 256,
        width: 3,
        added_bits: 4,
    }];
    let mut plan = plan(&inputs, LdeRetention::DeviceOnly, ReadbackLayout::Banded);
    struct Reject {
        calls: usize,
    }
    impl fmt::Write for Reject {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            self.calls += 1;
            Err(fmt::Error)
        }
    }
    let mut reject = Reject { calls: 0 };
    assert!(report(&inputs, &plan).write_to(&mut reject).is_err());
    assert_eq!(reject.calls, 1);
    plan.predicted_managed_peak_bytes = 0;
    let mut reject = Reject { calls: 0 };
    assert!(report(&inputs, &plan).write_to(&mut reject).is_err());
    assert_eq!(reject.calls, 0);
}

#[cfg(feature = "stream")]
#[test]
fn borrowed_serialization_and_fixed_writer_failure_make_no_heap_requests() {
    use fmt::Write;
    let inputs = [InputShape {
        height: 1 << 12,
        width: 6,
        added_bits: 5,
    }; 16];
    let plan = plan(&inputs, LdeRetention::DeviceOnly, ReadbackLayout::Banded);
    let report = report(&inputs, &plan);
    let mut output = Fixed::<4096>::new();
    let (result, requests) =
        crate::spill_alloc::allocation_requests::measure(|| write!(output, "{report}"));
    result.unwrap();
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
    assert!(!requests.overflow);
    let mut short = Fixed::<1>::new();
    let (result, requests) =
        crate::spill_alloc::allocation_requests::measure(|| report.write_to(&mut short));
    assert!(result.is_err());
    assert_eq!(requests.calls, 0);
    assert_eq!(requests.bytes, 0);
    assert!(!requests.overflow);
}
