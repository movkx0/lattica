Persistent local pool and delivered-throughput campaigns

This is opt-in research tooling for the current native test chain. Production
parameters remain 64 inputs, depth 6, 720-second cadence, and a 2 MiB root. The
600-second cold full-64 and 180-second complete post-seal gates are unchanged.
No rate or speedup is implied by the implementation or a small smoke run.

Build matching CPU and GPU profiles. The native host feature selects wide lanes;
mixing a narrow GPU binary with a host CPU binary is correctly rejected.

  CARGO_TARGET_DIR=target/pool-host cargo build --release --no-default-features \
    --features block-v2-host,stream --lib --bin block-v2-paired-probe
  CARGO_TARGET_DIR=target/pool-gpu cargo build --release --no-default-features \
    --features block-v2-host,stream,gpu --bin block-v2-paired-probe
  python3 scripts/build-block-v2-host.py \
    --rust-staticlib target/pool-host/release/liblattica_prover_p3.a \
    --output target/pool-native-bridge

Use a registry fixture previously qualified for this exact profile/geometry.
Keep frozen binaries, keys, logs, and old failed runs. Changed binaries, cache
settings, geometry, or resource assignments need fresh context qualification.
The default resource planner retains conservative bootstrap context allowances
when no matching calibration is supplied; it never shrinks margins to fit.

Copy block-v2-multi-gpu-direct-readback-workload.json into a new workload file.
Add a pool_allocation object, naming the actual two UUIDs:

  "pool_allocation": {
    "wallet_threads": 4, "wallet_bytes": 2147483648,
    "coordinator_threads": 2, "coordinator_bytes": 1073741824,
    "weights": {"GPU-<laptop-uuid>": 1, "GPU-<desktop-uuid>": 1}
  }

Weights control per-GPU CPU/RAM allocation after wallet/coordinator reservations.
They are tuning inputs, not assumed speed ratios. Every worker must still pass
the full phase memory model. OS/controller headroom and tmpfs charging remain.
The separate controller has a reserved core and a 4 GiB cap. Adjust workload
reservations to actual bounded participants, never by bypassing GPU admission.
The independent CPU audit uses the wallet reservation after wallet jobs drain.

Create a campaign input JSON using absolute paths:

  {
    "schema_version": 1,
    "library": "/absolute/pool-native-bridge/liblattica_host_bridge.so",
    "registry_fixture": "/absolute/qualified-native-fixture",
    "cpu_binary": "/absolute/pool-host/release/block-v2-paired-probe",
    "gpu_binary": "/absolute/pool-gpu/release/block-v2-paired-probe",
    "workload": "/absolute/pool-workload.json",
    "gpu_uuids": ["GPU-<laptop-uuid>", "GPU-<desktop-uuid>"],
    "scratch": "/tmp",
    "count": 4, "max_roots": 2, "min_roots": 2,
    "min_duration_seconds": 0, "max_wall_seconds": 7200,
    "candidate_timeout_seconds": 3600, "cycle_seconds": 0,
    "mode": "exploratory", "arrival_mode": "saturated",
    "wallet": {"participants": 4, "threads": 4, "ram_bytes": 2147483648}
  }

  python3 scripts/block-v2-pool-campaign.py init --config campaign-input.json \
    --output target/pool-chain-NEW
  python3 scripts/block-v2-pool-campaign.py run \
    --config target/pool-chain-NEW/campaign-config.json --output target/pool-run-NEW

Initialization pins a new funded synthetic genesis and explicit issuance grants.
It uses the versioned sustained fixture (up to 16,384 slots; extended research
HTLC deadlines). Legacy delivery fixtures, production funds, and emission rules
are untouched. A fresh campaign requires its own empty journal. The generated
workload contains three user transaction kinds and one issuance input per four
inputs. Wallet workers hold private witnesses/RNG only within their processes.

The measurement starts before wallet proving and GPU service startup. Its event
journal counts a transaction only after independent CPU root audit, native body
validation, and a durable commit receipt recheck. Issuance, failures, duplicates,
backlog, reversals, and application latency are separate accounting fields.
The existing campaign analyzer supports reversal/reapplication events; this
workload producer aborts on an unexpected head change and does not invent them.
Warm aggregation-only intervals must not be reported as delivered transactions.

For fixed-rate arrivals use arrival_mode="fixed_rate" and arrival_interval_ms.
The interval applies to all four input kinds. 11250 ms corresponds to four user
requests/minute for this 3:1 user/issuance mix. Submitted events continue while
proving runs; queueing and backlog remain in the evidence. The pacing interval
defaults to 720 seconds. Zero pacing is an explicitly exploratory saturation
measurement, not a consensus cadence change.

For qualification require min_duration_seconds >= 86400, min_roots >= 150,
cycle_seconds = 720, sufficient max_roots/funding, and a max_wall_seconds bound
longer than both requirements. At 720 seconds, 150 roots takes about 30 hours.
Set mode="qualifying" and supply qualification={contract,resource_plan,evidence}
paths accepted by block-v2-throughput-pilot.py. Existing blocked gates block this
mode. Exploratory failures never qualify timing or sustained throughput. A new
pool/resource geometry still needs its own valid evidence; changing a mode flag
cannot establish correctness or speed. No production option is auto-promoted.

Use the same resource_assignment and workload contract for matched comparisons.
Retain five complete pairs in alternating control/candidate, candidate/control
order. block-v2-pool-research.py compare accepts a JSON manifest with pairs:
{order:[...],match_id:"...",control:"relative-summary.json",candidate:"..."}.
Promotion needs positive median delivered-rate improvement, four improved pairs,
and no correctness, resource, or deadline failures. Missing runs cannot be filled
with aggregation estimates. A comparison report never activates production.

Captured run IDs, boot identity and non-overlapping monotonic intervals must
confirm the declared alternating order. Duplicate runs or pairs are rejected.
Campaign summaries pin the binaries, native adapter, workload and Python sources.

Optional caches remain off (or single-entry) until individually qualified:

  "preprocessing_cache": {"entries": 2, "reserve_bytes": <calibrated extra RAM>}
  "geometry": { ...existing fields..., "lde_workspace_bytes": <bounded bytes>,
                "gpu_fri_fold": false }

Preprocessing is keyed by exact program/registry within one session, uses LRU
eviction, and subtracts the declared idle-cache reserve from active proving RAM.
This reserve must be measured for the selected entry count. Hard cgroup/GPU caps
remain authoritative. Only immutable public preprocessing is cached; each proof
gets fresh randomness. GPU LDE scratch reuse is capped at one quarter of managed
VRAM, remains charged while idle, and scrubs attempt buffers before retention.
Set geometry.gpu_fri_fold=true to opt into tiled OpenCL arity-two Goldilocks
cubic FRI folding. The planner charges an extra MiB of host transfer workspace;
device buffers remain charged to the aggregate GPU limit. Transcript sampling,
commitment order, proof encoding and CPU verification remain unchanged. The
selected kernel fails closed on errors and is not supported by Metal yet.
CPU quotient polynomial evaluation and other FRI operations are still present.
Kernel equivalence and valid roots alone do not establish a throughput gain.

Validation retained in docs/evidence/block-v2-persistent-pool-2026-10-06.json:
two four-input candidates used the same two worker processes, eight fresh
recursive proofs, independent CPU root audits, and two durable native commits.
Both GPU FRI and LDE workspace kernels have differential CPU checks on both
devices. This small exploratory run does not qualify a delivered transaction
rate, full-64 latency, cache promotion, or sustained service. Earlier failed
attempts are retained with their failure reasons.

Architecture and local protocol

execution/pool.rs owns candidate DAGs, deadlines, verification and logical jobs.
WorkerEndpoint separates that logic from execution/pool/local.rs and its existing
supervised processes, launch fencing, workspace reservations and physical-stop
receipts. No path, systemd unit or GPU ordinal enters the scheduler. Costs use
bounded rolling p95 samples by worker, profile, mode, level, thread assignment
and warm/cold state. Bootstrap costs are explicitly unmeasured. Replacement
workers discard old estimates. A failed transport is physically reconciled
before another worker can retry its lease.

The opt-in fleet plan field pool_requests names a private local directory. Its
trusted controller atomically publishes 000000.json, 000001.json, etc. Each has
schema_version=1, absolute fixture and expected paths, the verified native_host
binding, and deadline_ms relative to the service clock. pool-ready.json supplies
the ready clock offset. Results are published atomically under candidate-NNNNNN.
A result is proof availability only; the native controller remains the authority
for application. A .cancel file fences a stale candidate. A stop file drains an
idle service. Idle heartbeats preserve the 600-second IPC timeout across cycles.
The service admits at most 256 requests per bounded lifetime. Completed roots
are synced before unreferenced intermediate DAG data is pruned.

Native session-v2 holds a verified native Chain and applies only an exact new
history suffix. Changed history, reorg, restart, or failed mutation rebuilds from
durable records. Published state and cached summaries are never proof authority.
The durable store still reads/hashes public history artifacts; this is not yet a
streaming history loader. Wallet participant processes cache verification within
their batch. Interrupted campaigns retain evidence and require explicit physical
reconciliation; automatic pool reconstruction/resume is not implemented here.

Remote workers need an authenticated/versioned transport and observed resource
lifetime semantics before activation. Only public proof jobs may cross it.
The current implementation opens no LAN listener.

  python3 scripts/block-v2-pool-research.py profile --capacity 512 \
    --cycle-seconds 180 --issuance-inputs 4

This emits a separate proposal identity, boundary counts, capacity arithmetic and
required security/host checks. It does not enable 512-input proving. A new
registry, complete-tree security analysis, Rust/Zig vectors, anchor/HTLC/reorg
behavior and full lifecycle qualifications remain prerequisites for that work.
