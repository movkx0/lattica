# Portable benchmark record, version 1

The importer uses Python's standard library and works without Linux, cgroups,
systemd, CUDA or OpenCL. Supply a JSON object with the fields below. The Apple
effort can populate it with its own measured solver, verification and resource
data. No Apple benchmark result is claimed by the initial dataset.

This is a structural example with unknown measurements, **not a measured run**:

```json
{
  "schema_version": 1,
  "run_id": "apple-silicon-unique-run-id",
  "label": "Describe the measured workload",
  "kind": "solving",
  "status": "unknown",
  "track": "apple-silicon",
  "platform": {
    "os": "macos",
    "architecture": "aarch64",
    "backend": "record the actual backend",
    "memory_model": "unified",
    "unified_memory_bytes": null,
    "cpu": null,
    "gpu": null
  },
  "revision": {
    "git_commit": null,
    "dirty": null,
    "binary_sha256": null,
    "profile_sha256": null
  },
  "measurement_scope": "recursive_aggregation",
  "workload": {
    "user_transactions": null,
    "issuance_transactions": null,
    "fixture_reuse": null,
    "count_evidence": null,
    "description": "State what the timed job includes and excludes"
  },
  "timing": {
    "elapsed_seconds": null,
    "recursive_seconds": null,
    "started_utc": null
  },
  "verification": {
    "cpu_audited": null,
    "root_bytes": null,
    "root_sha256": null
  },
  "configuration": {},
  "stages": [],
  "proofs": [],
  "measurements": {
    "tables": [],
    "timeline_events": 0,
    "resource_samples": 0
  },
  "sources": [],
  "limitations": [],
  "campaign_ids": [],
  "milestones": ["P0"]
}
```

## Field rules

| Field | Meaning |
|---|---|
| `run_id` | Immutable identifier, 1–128 ASCII letters/digits, `_`, `.` or `-`; first character alphanumeric. Use a distinct ID for each actual run. |
| `kind` | `solving`, `registration`, `component`, `diagnostic` or `summary`. |
| `status` | Prefer `succeeded`, `failed`, `incomplete` or `unknown`. Legacy `completed` means completion was recorded but independent audit was not established. |
| `track` | Project development track, such as `apple-silicon` or `linux-opencl`. |
| `platform` | Recorded hardware/backend identity. Preserve device UUID/PCI identity where available; GPU ordering is not identity. Record unified memory once. |
| `revision` | Actual measured source revision, dirty state, build/profile hashes and compiler flags when available. Do not substitute the report-generation revision. |
| `measurement_scope` | State the measured boundary. Initial historical scope is `recursive_aggregation`. Use a separate explicit scope for wallet proving, component work or canonical chain acceptance. |
| `workload.user_transactions` | Explicit nonnegative integer count. Requires a nonempty public `count_evidence` reference. Do not infer it from proof count. |
| `workload.issuance_transactions` | Separate payout/issuance count; excluded from useful-user rate. |
| `workload.fixture_reuse` | Whether fixture inputs repeat. Repeated fixture processing is not unique delivered-chain throughput. |
| `timing.*_seconds` | Finite nonnegative durations or null. Whole job and recursive command remain separate. |
| `verification.cpu_audited` | Boolean or null. A successful throughput numerator requires true. Keep verification details in additional metadata as needed. |
| `configuration` | Configured threads, admission policy, managed memory, driver/context allowance, host/spill reservations and other settings. These are budgets, not observations. |
| `sources` | Objects with `path`, `sha256` and `bytes`. Paths document provenance; portable rendering never opens them. Do not reference private material. |
| `limitations` | Plain-language missing data, clock limits, drops, interrupted work and measurement exclusions. |

Known controller adapters retain original measured metadata in `retained_metadata`
and `controller_metadata`. Public measurement extensions are allowed. Fields
named `private_key`, `secret_key`, `seed_phrase`, `mnemonic`, `proof_payload` or
`wallet_material` are rejected. Producers must exclude private data and proof
payloads from all other fields too.

## Stages and proofs

Stages may include `name`, `status`, `wall_seconds`, `started_utc`, `started_ns`
and `finished_ns`. Preserve the clock domain. Do not fabricate stage boundaries
from cumulative phase counters.

Proof entries may include `artifact`, `elapsed_seconds`, `setups`, `cache_hits`,
`resumed`, `source`, `source_line` and recorded dependencies. The HTML shows
durations/order; it does not infer dependency timing from artifact names.

## Measurement tables

Each table has `kind`, `source`, `clock`, `columns`, `dictionaries` and `rows`:

```json
{
  "kind": "host_timeline_interval",
  "source": "public-measurement-log",
  "clock": "host_monotonic_relative",
  "columns": ["thread", "name", "start_ns", "end_ns"],
  "dictionaries": {"name": ["proving"]},
  "rows": [[0, 0, "10000000000000001", "10000000000000123"]]
}
```

Every row has one cell per column. For a dictionary column, a non-null cell is
an integer index into that column's dictionary. Mixed-type columns remain
unencoded. Numeric strings are retained literally.

Nanosecond timestamps and integers outside JavaScript's exact integer range
(`±(2^53−1)`) are decimal strings. Do not round them through a floating-point
encoder. NaN and infinity are invalid. Null means unavailable, not zero.

Recognized interactive kinds are `host_timeline_interval`,
`gpu_timeline_interval` and `resource_samples`. Other kinds remain accessible as
profiling tables. Interval tables use `start_ns`/`end_ns`, optional `thread` or
`queue`, and optional `_checkpoint`. Device and host clock domains remain
separate. Resource tables retain original unit-bearing field names and capture
order. Cgroup counters and per-process GPU samples are preserved independently.

## Comparison windows

The catalog retains windows with `run_ids`, `elapsed_seconds` and source
provenance. Aggregate rates divide successful CPU-audited user-input counts by
the sum of measured wall windows, not the sum of concurrent job durations.
Duplicate references inside a window are counted once. Reusing a run in multiple
windows is rejected because the overlap is ambiguous. Failed windows may have
no completed runs and still contribute elapsed time.

Comparison windows require a common measurement scope. The exporter does not
invent windows from individual timestamps or compare unrelated workload scopes.
Portable single-run import currently adds individual records; a future portable
campaign format can add explicit arrival/recovery and chain-acceptance windows.
