# Borrowed LDE admission telemetry

This candidate has no parent module or call-site hook yet. The coordinator owns
those edits. LdePlanReport borrows the existing LdeCommitPlan and InputShape
slice, plus seven scalar context values. It emits the same 27 outer JSON fields
and three numeric fields per input as commit_inputs_inner's existing json!
expression. The schema remains lattica-lde-plan-v1. Field order matches the
pinned serde_json Map's lexical ordering, including added_bits/columns/rows.

Runtime values are unsigned integers plus the retained-tree storage enum. Its
exhaustive mapping preserves serde's device/host_backing strings. JSON field
names and the schema are static literals, so core fmt writes them directly without dynamic escaping,
maps, key Strings, input collection or an intermediate output String. Both the
Display implementation and write_to use the same borrowed formatter. Writer
failures return fmt::Error immediately; no error boxing, retry or diagnostic
String occurs. The derived fixed-bytes invariant is checked before output.

Only this formatter's storage is closed. The existing plan, shape and capture
Vecs, writer/stderr buffers, output artifacts, caller errors, engine and all
driver/stack/allocator storage remain their existing owners. The formatter
does not create a reservation, change phase arithmetic, or report GPU work.

Suggested root-owned replacement, after adding mod report in lde_execute.rs:

```rust
eprintln!(
    "bounded_gpu_lde_plan {}",
    report::LdePlanReport {
        inputs: &shapes,
        plan: &plan,
        managed_cap_bytes: self.limits.managed_bytes,
        max_allocation_bytes: self.max_alloc,
        live_without_transform_bytes: live,
        replaced_hash_workspace_bytes: old_workspace,
        owned_output_bytes: device_bytes,
        replay_workspace_bytes: replay_bytes,
        host_budget_bytes: host_budget,
    }
);
```

Five focused tests are authored, not executed: exact legacy JSON equivalence
for main/16-quotient/random note shapes; host-prefix output and large integer
semantics; both retained-tree storage modes and their distinct device/host
charges; failure before output for malformed fixed terms and immediate writer
error propagation; and feature-stream zero Rust allocation requests for both
successful formatting and writer failure. Reference Value construction, plan
construction and test String parsing remain outside the allocation observation.
The coordinator must compile and run these tests under the pinned feature set
before adopting the hook. No cryptographic or workflow speedup claim is made.

B019 used a stale worktree preimage with 24 outer fields. B020 supersedes that
rejected snapshot using the current integration source, preserving the newer
retained_tree_storage, retained_tree_device_bytes_after_commit and
retained_tree_host_charge_bytes fields. B019 remains immutable review evidence.
