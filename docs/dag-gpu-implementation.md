# Execution DAG and GPU proving implementation plan

> **IMPLEMENTATION DIRECTION SELECTED / NOT IMPLEMENTED — 2026-10-01.**
> Make an execution DAG the coordinator's work model and prioritize a GPU
> pipeline that retains intermediate data on the device. This specifies new
> implementation work; it does not report completed functionality or activate
> a proof profile. [Block-proving v2](block-proving-v2.md) retains authority over
> the construction, aggregate resource limits and release gates.

## 1. Decision and implementation priority

The immediate performance work is **GPU transforms through commitments with
shared device buffers**, followed by quotient evaluation, opening reductions
and FRI folding. Build a small local execution DAG harness alongside this work
so that the same verified jobs can later run on multiple devices and hosts.
A complete remote CPU pool is not a prerequisite for GPU development.

Use two execution layers:

1. **Proof DAG:** public-proof wrapping, approved grouped wrapping, empty
   subtrees and ordered merges. The scheduler tracks verified dependencies,
   candidate versions, resource reservations and deadlines.
2. **Worker GPU pipeline:** the arithmetic, commitments and reductions inside
   each proof. Keep compatible large intermediates local to the assigned device;
   respect every transcript challenge and data dependency.

The host retains its ordered transaction body, Merkle commitment, PoW policy and
one accepted final aggregate proof. A DAG ledger would need a separate consensus
decision. Wallet witnesses remain local to wallets; workers receive public
proofs and statements. Host nullifier/conflict checks and atomic state application
remain required even when proof jobs run concurrently.

This document controls implementation sequencing for the
[distributed service](distributed-proving.md) and
[throughput plan](high-throughput-proving-plan.md). The latter's 512/4,096-capacity,
three-minute profiles remain separately gated research proposals. The current
candidate is still 64 total transactions; no 128-transaction result is established.

## 2. Existing integration points

| Existing source | Implementation use |
|---|---|
| [recursive.rs](../lattica-prover-p3/src/block_v2/recursive.rs) | Adapt `ProverSession` and `ConstructionSession` into bounded worker operations; use `Registry::verify` with externally expected statements at result acceptance |
| [commitment.rs](../lattica-prover-p3/src/block_v2/commitment.rs) and [Zig commitment](../src/block_v2.zig) | Construct and check ordered subtree statements, levels, counts, context and padding |
| [profile.rs](../lattica-prover-p3/src/block_v2/profile.rs) | Preserve candidate cubic-extension arithmetic, parameters and CPU verification configuration; explicit research backend selection |
| [gpu_hash.rs](../lattica-prover-p3/src/block_v2/gpu_hash.rs) | Extend commitments beyond host `RowMajorMatrix` inputs while preserving CPU verification and proof encoding |
| [gpu_hash/engine.rs](../lattica-prover-p3/src/block_v2/gpu_hash/engine.rs) | Reuse bounded allocation, retained-tree, event and cleanup mechanisms; evolve ownership safely for multiple devices |
| [normalization_workspace.rs](../lattica-prover-p3/src/block_v2/normalization_workspace.rs) and [quotient_pcs.rs](../lattica-prover-p3/src/block_v2/quotient_pcs.rs) | Identify host materialization, layout conversions and quotient interfaces to replace in the candidate proving path |
| [gpu.rs](../lattica-prover-p3/src/gpu.rs) | Reuse validated base-field arithmetic/transform ideas after candidate-specific tests; the legacy quadratic PCS is not the cubic candidate backend |
| [perf.rs](../lattica-prover-p3/src/block_v2/perf.rs) and [accounting controller](../lattica-prover-p3/scripts/block-v2-accounting.py) | Extend phase, byte, resource and failure measurements without changing preserved experiment inputs |

Current GPU acceleration covers salted hashing and Merkle compression. Polynomial
arithmetic remains CPU work. The current engine has a mutex and a per-user process
lease; selecting a device does not implement concurrent multiple-GPU execution.
The [GPU guide](gpu-acceleration.md) and [bounded engine record](bounded-execution-engine.md)
describe implemented behavior and dated evidence.

Suggested **new research modules**, whose names are proposals rather than existing
files or exported APIs:

| Proposed location under `lattica-prover-p3/src/` | Responsibility |
|---|---|
| `block_v2/execution/job.rs` | Logical job identity, statements, artifacts, resource contracts and attempts |
| `block_v2/execution/dag.rs` | Validated dependencies, ready sets, invalidation and candidate sealing |
| `block_v2/execution/scheduler.rs` | Placement, deadline estimates, locality and resource admission |
| `block_v2/execution/journal.rs` | Durable transitions, completion fencing and recovery |
| `block_v2/execution/worker.rs` | CPU/GPU adapters around registered recursive operations |
| `block_v2/gpu_pipeline/{buffer,transform,quotient,opening,fri}.rs` | Device storage, candidate arithmetic and explicit pipeline dependencies |
| `bin/block_v2_worker.rs` and `bin/block_v2_pool.rs` | Local harness first, then authenticated experimental worker/pool transport |

Keep these outside the default production ABI. No new runtime switch, command,
wire tag or ABI symbol is allocated by this document.

## 3. Proof DAG contract

### Logical nodes and identity

Admit `Wrap`, registered `WrapPair`, supported `Empty` and `Merge` nodes.
`SolveSubtree` is a scheduling assignment that owns a contiguous subgraph of
those operations and exports its root; it does not introduce a new circuit.
Keep circuit grouping distinct from the number of transactions placed locally.

Extend the [job contract](distributed-proving.md#4-job-and-artifact-contract)
with the following logical fields. Define a bounded canonical service encoding
and rejection vectors before exposing it over a network.

| Record | Required fields and checks |
|---|---|
| Semantic job | Schema, operation, approved profile/construction, registry digest, ordered range/level, context, expected statement and ordered dependency identities |
| Input manifest | Exact public artifact digests, decoded lengths, approved formats and pinned statement bindings; no raw wallet witness |
| Candidate attachment | Candidate/selection epoch, eligibility snapshot, root destination and deadline; several eligible candidates may reference one immutable job |
| Attempt | Logical job ID, attempt ID, leader fencing epoch, assigned worker/device, resource reservation and bounded lease |
| Result | Job/attempt binding, proof digest/length, claimed statement and observational resource/timing data |

Derive logical job IDs with domain-separated cryptographic hashing over canonical
semantic fields. Keep randomized proof-byte digests separate from semantic reuse
keys. Freeze exact child artifact digests when an attempt starts; a second valid
proof for the same statement must not silently replace an in-flight input.
Candidate and lease bindings are coordinator checks, not automatically authenticated
by the recursive proof's public statement.

On graph admission, validate:

- Acyclicity, permitted operation/level transitions and bounded node/edge counts.
- Ordered contiguous child ranges, counts, context and registry compatibility.
- Current profile capacity and supported empty/grouped/padding constructions.
- Exact state eligibility and conflict policy for the candidate transaction body.
- Admission limits before allocating dependency tables or fetching large objects.

Hash tables hold exact operational indexes. A durable journal backs authoritative
transitions. Bloom filters may advertise artifact inventories, but cannot mark
dependencies ready or establish spend validity.

### Readiness and completion

Use a state machine with `waiting -> ready -> leased -> verifying -> completed`,
plus explicit expired, rejected and cancelled attempts. A waiting node becomes
ready only when every required dependency has a verified, available artifact.
There is no barrier requiring unrelated nodes at the same level to finish.

The following is behavioral pseudocode, not an existing API:

```text
on_result(attempt, proof):
    check active attempt, leader epoch, bounded encoding and exact input manifest
    recompute expected statement from pinned ordered inputs
    verify proof with approved CPU registry and expected statement
    make the verified artifact durable under the declared recovery policy
    atomically complete the still-current attempt and update dependency readiness
    enqueue newly ready parents whose resource/deadline conditions permit execution
```

Recheck the attempt fence and candidate attachments in the commit transaction:
expiry or cancellation may occur while verification runs. Duplicate completion
must not decrement dependencies or issue credit twice. Late results can enter
a verified semantic cache under policy without reopening a cancelled candidate.
An orphaned artifact after a crash is recoverable garbage, not a completed job.

Within a worker-owned subtree, intermediate stages can remain local. The service
verifies every exported result; recursive verification enforces the internal
chain. Do not require a coordinator upload of every inner proof. Local durable
checkpoints should be completed subtree proofs, with their cost included in the
transfer budget. Inputs must remain recoverable if that worker disappears.

### Reuse and incremental finalization

Start eligible subtrees as public wallet proofs arrive. Candidate selection fixes
canonical order; arrival order and hash-map iteration do not define consensus
order. Reuse only when profile, registry, context, expected statement and inputs
match, and recheck current host eligibility before inclusion.

When selection changes, detach the affected candidate and invalidate its dependent
ancestors; preserve immutable jobs still referenced by other eligible candidates.
Release buffers/artifacts only after all dependents and the recovery window permit
it. At sealing, freeze the exact candidate and include late issuance, padding,
remaining merges, final CPU verification and body availability in the deadline.
Treat cold aggregation and work remaining after sealing as separate metrics.

## 4. GPU pipeline contract

### First implementation slice

Implement **candidate-compatible transforms feeding the existing commitment
engine through retained device buffers**. Benchmark a complete recursive proof,
including setup, transfers, assembly and CPU verification. A standalone fast
transform that downloads its full output for immediate re-upload is insufficient
evidence of the intended pipeline benefit.

The candidate PCS currently exposes host matrix materialization and host-backed
prover data. Replacing only the DFT type will not remove those transfers. Add a
narrow candidate proving adapter for resident commitments and opening access;
preserve CPU verifier types and serialized proof semantics. Document any required
upstream PCS adapter/fork and compare it against the unchanged reference path.

Extend in this order, re-profiling after each slice:

1. Base-field transforms, coset operations and commitment consumption.
2. Cubic-profile quotient evaluation/randomization and quotient commitments.
3. Polynomial opening reductions using already resident matrices.
4. Large FRI folds/commitments; measure when small rounds are cheaper on CPU.

### Device storage and transcript boundaries

An opaque `DeviceMatrixLease` should carry device/context generation, element
type and extension basis, dimensions, row order/strides, allocated byte count,
owner/attempt, readiness event and lifetime references. It is a local handle,
never a wire object. A consumer must reject incompatible device, layout, shape,
profile or expired ownership before accessing it.

Plan buffers across the producer and all consumers. Keep an intermediate on the
device until its last permitted use, or use an explicit bounded readback/eviction
plan. Any access needed for final openings must have retained data or a tested
recomputation path. Recompute with the same per-attempt committed data and masks;
fresh masks midway through a proof would change its commitments.

The GPU operation graph must reproduce the reference prover's transcript order.
Commitment caps go to the CPU challenger; challenge-dependent work starts only
after the required commitment absorption and challenge derivation. Subsequent
FRI rounds have their own dependencies. Do not precompute using guessed
challenges, alter absorption order or treat all GPU stages as independent.
The CPU remains responsible for canonical proof assembly and independent result
verification. Small transcript exchanges need not move whole matrices.

Use exact Goldilocks and candidate cubic-extension arithmetic, matching roots,
cosets, basis, reduction rules and canonical encoding at required boundaries.
Floating-point approximations are not valid substitutes. Preserve query count,
blowup, hiding codewords, salts and all other approved parameters.

Draw fresh full-entropy randomness for every proof attempt, with the independence
requirements of the reference prover. Cache only immutable public preprocessing.
Never cache proof RNG state, masks or salts for reuse across jobs. Deterministic
same-seed comparisons belong only in isolated equivalence tests.

### Tiling and memory admission

Full retention is not assumed to fit a gaming GPU. The existing geometry model
has a 12.25 GiB main LDE and about 55.5 GiB for all modeled LDEs, salts and trees
before additional workspaces. See the [retention model](evidence/block-v2-retention-model-2026-10-01.json).
These are modeled storage totals, not measured simultaneous VRAM peaks.

Tile independent columns or use validated staged transforms; arbitrary row
chunking can violate transform dependencies. Account for transitions between
column-oriented transforms and row-oriented hashing, and test partial tiles.
Retain compatible tiles across consumers where dependency/commitment order
allows it. Compare retention, explicit spilling and recomputation end to end.

Before admitting a stage, reserve all live device buffers, retained trees,
staging, temporary transforms and driver headroom. Also reserve host RAM, CPU
threads, pinned memory, disk and file descriptors. Free memory reported by a
driver is an observation, not a concurrency lock. Managed-byte accounting and
sampled physical VRAM are distinct measurements.

For the first pipeline experiment, keep one GPU worker and the existing exclusive
engine ownership. For subsequent multiple-GPU work, implement service-owned
per-device leases keyed by stable physical identity and host-wide admission.
Keep isolated engines/processes initially. Two devices do not pool VRAM, and
splitting a single proof across devices requires a separate measured design.

On cancellation or device error, stop admission, fence result publication and
drain outstanding events before releasing buffers. If a safe drain cannot be
established, terminate the isolated worker and quarantine/reset its device as
appropriate. Requeue a fresh attempt under explicit policy; record any qualified
CPU retry separately. Never hide a backend failure by changing security settings.

## 5. Scheduling by capability and critical path

Qualify each backend/profile/device/driver combination against the CPU verifier.
Use self-reported hardware only as a starting hint. Maintain measured completion
distributions by operation, dimensions, subtree size and resource allocation.
Requalify after relevant backend/driver changes.

First filter by correctness qualification, eligible inputs and resources. Estimate
queue delay, missing-input transfer, compute, verification and retry margin. Rank
deadline-feasible placements by remaining dependent work, data locality and
measured energy/cost. Reserve dependable capacity for late issuance and final
merges; use aging or fair queues so urgent work cannot starve all earlier jobs.

Strong compute with a slow uplink can receive larger local subtrees. Intermittent
workers need shorter assignments and retry slack. Choose subtree size from the
deadline and observed failure rate as well as transfer savings. GPU availability
does not remove a job's host-memory requirement. Avoid one job per CPU core;
each prover already uses internal parallelism.

Within one host, launch independent jobs on distinct qualified GPUs only when
their combined CPU/RAM/I/O budgets fit. Benchmark one versus two workers before
assuming scaling. A shared coordinator/verifier/store can become the bottleneck;
bound its queues and include its resources in fleet reports.

The [public worker protocol](distributed-proving.md) carries immutable manifests,
leases and proofs, not device buffers or working matrices. Verification and
credit are idempotent per logical job under published pool rules. Proof jobs
remain separate from PoW shares and from any future trustless payment mechanism.

## 6. Work packages and dependency order

GPU work begins after the short baseline step and runs alongside the minimal
local DAG implementation. Remote transport and broad heterogeneous scale-out
follow a qualified local pipeline; they do not gate its development.

| Milestone | Deliverable | Required exit evidence |
|---|---|---|
| G0: baseline and interfaces | Pin workload/profile, CPU and current GPU controls; define job IDs, device handles, metrics and budgets | Repeatable full-strength controls, known expected statements, separate phase/transfer/resource counters |
| G1a: local proof DAG | Bounded local ready queue, journal, subtree ownership, completion fencing, CPU reference adapter | Correct roots under shuffled completion, cancellation/restart and duplicate results; no unsupported capacity or grouping |
| G1b: first GPU pipeline, primary performance work | Candidate transform-to-commitment buffer reuse and exact arithmetic/layout tests | Full recursive proof accepted by unchanged CPU verifier; bounded memory and measured end-to-end benefit against current retained-hash control |
| G2: extend and qualify GPU execution | Quotient/opening/FRI slices, per-device ownership, host admission and measured capability classes | Repeated full-strength proofs, resource/error cleanup and one/two-device contention results; each added vendor qualified separately |
| G3: distributed DAG pool | Authenticated leases, direct artifact retrieval, durable failover, locality-aware subtree placement | Two/four-host correctness and failure recovery, measured cross-worker transfer reduction and scaling with fixed reliability policy |
| G4: full-block and cadence research | Current 64-transaction/full-type qualification, then explicitly reviewed larger profiles | Existing A3/resource/security gates and separately specified new cadence gates; real host state application and activation review |

G1a and G1b may proceed in parallel after G0. Keep the local harness small enough
to support the GPU experiment without waiting for internet transport, payment
infrastructure or a general-purpose DAG framework. The throughput plan's staffing
and effort windows are estimates; passing these evidence gates determines progress.

## 7. Tests and acceptance measurements

### Correctness and failure tests

- CPU/GPU arithmetic and same-seed test-fixture commitment/opening equivalence:
  cubic basis, roots/cosets, bit order, noncanonical inputs at applicable boundaries,
  salts, matrix ordering, partial tiles and every admitted dimension.
- Exact full-size public preprocessing caps against independently pinned values;
  fresh randomized recursive proofs accepted by the unchanged CPU auditor.
- DAG rejection for cycles, illegal levels, wrong ordered ranges/count/context,
  missing inputs, unsupported grouping and mixed registry/profile artifacts.
- Duplicate, stale, late and reordered completions; cancellation during GPU work
  and verification; crashes between artifact persistence and completion commit;
  coordinator restart and candidate reorg/invalidation.
- Allocation failures, retained-buffer pressure, device loss, event/drain errors,
  per-device isolation and aggregate host admission. No released buffer may be
  reused while a kernel or DMA operation can still access it.
- Fresh CPU root replay after required inner-artifact and shared-fixture pruning,
  together with malformed-proof and statement mutation rejection. Preserve
  existing experiment consumers and their pruning/replay obligations.

### Performance gates

Use the same public workload, approved parameters, inputs, fixed resource class
and declared cache state for matched comparisons. Start with the existing small
registered constructions; progressing to a larger graph needs its own fixtures,
closure and profile qualification. A 128-job queue is not a 128-transaction block.

For the first pipeline slice, run at least five alternating matched pairs against
the current retained-hash backend, and report the CPU reference separately.
An initial engineering target is **at least 20% lower median complete recursive
aggregation time at the same resource budget**, with every failure and observed
finalization regression reported and investigated. This is a proposed decision
target, not a measured or promised gain. Kernel-only improvements do not pass.
Five pairs are not production p95/p99 qualification.

Report:

- Wallet-proof-ready to verified-root latency, queue delay, cold setup, and
  selection-seal to host-ready root/body latency as separate quantities.
- Device kernel time, host preparation, physical transfer event time, API enqueue
  time and waits; do not sum nested or overlapping spans into elapsed time.
- Host-to-device/device-to-host bytes per accepted proof, WAN proof bytes,
  replication/retry traffic, RAM/VRAM/scratch peaks and disk traffic separately.
- CPU thread/concurrency sweeps, sustained DRAM bandwidth/stalls where counters
  are available, actual PCIe link and temperature/power behavior. High RAM use
  alone does not establish a bandwidth bottleneck.
- Accepted user transactions, wall energy/cost, fleet resources and failed or
  deferred work. GPU model names and aggregate FLOPs do not establish capacity.

The original aggregate workstation gate remains 48 GiB RAM, 12 GiB VRAM and
128 GiB scratch, with ten-minute cold and three-minute complete finalization
targets for the existing 64-transaction candidate. Fleet experiments must report
their larger total resources separately. The proposed three-minute transaction
cadence has a separate 60-second finalization research target in the throughput
plan. Neither is established by a small local GPU speedup.

For G3/G4, retain the throughput plan's matched reliability policy, at least 80%
intermediate-transfer reduction target, 70% two/four-host scale-out efficiency
target, and at least 24 hours plus 100 root cycles of arrival-driven qualification
(run until both duration conditions hold). Full transaction types, late issuance,
padding, cold starts, host state/reorg behavior and bounded faults remain required.

## 8. First implementation handoff

1. Pin a fresh, isolated copy of an existing public research fixture and its
   approved registry/expected statement. Preserve active benchmark directories.
2. Add the local DAG contract/tests and per-attempt accounting around existing
   recursive APIs; establish serial and shuffled-completion controls.
3. Prototype one candidate transform feeding a resident commitment input, then
   exercise a complete recursive proof and unchanged CPU verification.
4. Compare full proof time and all transfer/resource counters under the same
   budget. Use the result to choose the next quotient/opening/FRI slice.
5. Add per-device concurrency and remote subtree placement only after their
   ownership, correctness and resource prerequisites pass.

Keep the CPU reference available throughout. Qualifying a GPU research backend
does not change the default production build, historical verifier, capacity,
consensus cadence or activation status. Promote each explicitly after its own
review and measured acceptance gates.
