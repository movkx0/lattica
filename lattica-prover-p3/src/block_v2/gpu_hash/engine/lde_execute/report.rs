//! Borrowed serialization of the existing admission telemetry. This constructs
//! no JSON Value, map, key String, input collection or detached output String.
//! It reports the current plan; it grants no memory or dispatch authority.
use super::{InputShape, LdeCommitPlan};
use crate::block_v2::gpu_hash::engine::RetainedTreeStorageMode;
use core::fmt;

#[cfg(test)]
mod tests;

pub(super) struct LdePlanReport<'a> {
    pub(super) inputs: &'a [InputShape],
    pub(super) plan: &'a LdeCommitPlan,
    pub(super) managed_cap_bytes: usize,
    pub(super) max_allocation_bytes: usize,
    pub(super) live_without_transform_bytes: usize,
    pub(super) replaced_hash_workspace_bytes: usize,
    pub(super) owned_output_bytes: usize,
    pub(super) replay_workspace_bytes: usize,
    pub(super) host_budget_bytes: usize,
}

impl LdePlanReport<'_> {
    /// A formatter borrows every input for the full write. Errors propagate
    /// directly as the fixed fmt::Error, without allocating an error wrapper.
    /// Sink buffering and already-existing plan storage belong to the caller.
    pub(super) fn write_to(&self, output: &mut impl fmt::Write) -> fmt::Result {
        let plan = self.plan;
        // The admitted planner already establishes this invariant. Refuse a
        // malformed future caller before any output, rather than underflow.
        let fixed = plan
            .transform_buffer_bytes
            .checked_mul(2)
            .and_then(|buffers| plan.predicted_managed_peak_bytes.checked_sub(buffers))
            .ok_or(fmt::Error)?;

        // Preserve the pinned serde_json Map's lexical key order as well as all
        // 27 field meanings. All strings are static JSON syntax/schema literals
        // or the exhaustive storage enum mapping below. Numeric values and
        // input rows are borrowed from the existing plan.
        write!(output, "{{\"columns_per_tile\":{}", plan.columns_per_tile())?;
        number(output, "fixed_bytes", fixed)?;
        number(output, "hash_workspace_bytes", plan.hash_workspace_bytes)?;
        number(output, "host_budget_bytes", self.host_budget_bytes)?;
        number(
            output,
            "host_output_backing_bytes",
            plan.host_output_backing_bytes,
        )?;
        number(output, "host_output_payload_bytes", plan.host_output_bytes)?;
        number(
            output,
            "host_reorder_backing_bytes",
            plan.host_reorder_backing_bytes,
        )?;
        number(
            output,
            "host_reorder_payload_bytes",
            plan.host_reorder_workspace_bytes,
        )?;
        output.write_str(",\"inputs\":[")?;
        for (index, input) in self.inputs.iter().enumerate() {
            if index != 0 {
                output.write_char(',')?;
            }
            write!(
                output,
                "{{\"added_bits\":{},\"columns\":{},\"rows\":{}}}",
                input.added_bits, input.width, input.height
            )?;
        }
        output.write_char(']')?;
        number(
            output,
            "live_without_transform_bytes",
            self.live_without_transform_bytes,
        )?;
        number(output, "managed_cap_bytes", self.managed_cap_bytes)?;
        number(output, "max_allocation_bytes", self.max_allocation_bytes)?;
        number(output, "output_rows", plan.output_height())?;
        number(output, "owned_output_bytes", self.owned_output_bytes)?;
        number(
            output,
            "predicted_host_peak_bytes",
            plan.predicted_host_peak_bytes,
        )?;
        number(
            output,
            "predicted_managed_peak_bytes",
            plan.predicted_managed_peak_bytes,
        )?;
        number(output, "query_reserve_bytes", plan.query_reserve_bytes)?;
        number(
            output,
            "replaced_hash_workspace_bytes",
            self.replaced_hash_workspace_bytes,
        )?;
        number(
            output,
            "replay_workspace_bytes",
            self.replay_workspace_bytes,
        )?;
        number(output, "retained_tree_bytes", plan.retained_tree_bytes)?;
        number(
            output,
            "retained_tree_device_bytes_after_commit",
            plan.retained_tree_device_bytes,
        )?;
        number(
            output,
            "retained_tree_host_charge_bytes",
            plan.retained_tree_host_bytes,
        )?;
        let storage = match plan.tree_storage_mode {
            RetainedTreeStorageMode::Device => "device",
            RetainedTreeStorageMode::HostBacking => "host_backing",
        };
        write!(output, ",\"retained_tree_storage\":\"{storage}\"")?;
        output.write_str(",\"schema\":\"lattica-lde-plan-v1\"")?;
        number(output, "sponge_state_bytes", plan.sponge_state_bytes)?;
        number(
            output,
            "transform_buffer_bytes",
            plan.transform_buffer_bytes,
        )?;
        number(output, "twiddle_bytes", plan.twiddle_bytes)?;
        output.write_char('}')
    }
}

// Called only with the static field identifiers above; no dynamic string needs
// JSON escaping or temporary storage. Integer formatting is core fmt.
fn number(output: &mut impl fmt::Write, name: &'static str, value: usize) -> fmt::Result {
    write!(output, ",\"{name}\":{value}")
}
impl fmt::Display for LdePlanReport<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(output)
    }
}
