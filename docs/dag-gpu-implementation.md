# Execution DAG and GPU proving implementation plan

> **RESEARCH IMPLEMENTATION PARTIAL / FULL GPU PLAN — updated 2026-10-10.**
> The research path on `main` qualifies all 16 proving arithmetic stages on
> OpenCL, including full-size recursive jobs through a persistent native worker.
> Complete scheduler lifetime profiles and broader workload qualification remain
> open. [Section 9](#9-plan-for-all-proving-arithmetic-on-the-gpu) records the
> source review at `e9e35067fc3b419a54d790a71663071455f203f1` and the remaining plan.
> Sections 1–8 retain the original design and sequencing, rather than a current
> completion ledger. [Block-proving v2](block-proving-v2.md) retains authority over
> construction, aggregate resource limits and release gates. This plan activates
> no proof profile.

The latest checkpoint is [§9.93, native numerical verifier scratch](#993-native-numerical-verifier-scratch-2026-10-10).
Registered single-machine verification on release x86_64 now checks a
source-derived cumulative allocation-request bound against a **64 MiB component
ceiling** before configuration construction or numerical work. Both CPU layouts
pass allocation and proof conformance; full-size GPU proofs preserve the
registry and all 16 OpenCL proving arithmetic stages. Configuration, caller-owned
storage, complete scheduler lifetimes and sustained throughput remain open.

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

At the original October 1 design baseline, GPU acceleration covered salted hashing
and Merkle compression. The October 6 implementation also has bounded GPU
transforms, quotient commitments, opening reductions, optional OpenCL FRI folding
and persistent workers on multiple devices. October 7 adds optional OpenCL cubic
quotient evaluation and an opt-in GPU lookup-to-commitment path. Host opening matrices
and other CPU proving arithmetic remain.
See section 9 for current source locations and limits.
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

The 2026-10-04 development pilot uses the current workstation's adaptive host,
per-device VRAM, CPU and scratch budgets. The earlier 48 GiB RAM / 12 GiB VRAM /
128 GiB scratch envelope is retained as historical evidence. Keep the existing
64-transaction, 600-second cold and 180-second complete post-seal targets, depth
six and 2 MiB root limit. New geometries require admission and qualification on
each selected GPU UUID. See the machine-readable
[qualification contract](../lattica-prover-p3/scripts/block-v2-throughput-contract.json).

The immediate campaign is a two-hour development pilot with four participants,
504 scheduled user requests and mixed transaction types. It starts only after
full-count, mixed-recursion, durable-host and recovery gates pass. The proposed
three-minute cadence and its separate 60-second finalization target remain a
later research project.

For G3/G4, retain the throughput plan's matched reliability policy, at least 80%
intermediate-transfer reduction target, 70% two/four-host scale-out efficiency
target, and at least 24 hours plus 150 root cycles of arrival-driven qualification
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

## 9. Plan for all proving arithmetic on the GPU

### 9.1 Scope and completion definition

The target is GPU execution of proof-generation arithmetic for wallet proofs and
recursive block proofs: preprocessing, witness-to-trace construction, lookup
arguments, transforms, quotient evaluation, hiding, commitments, openings, FRI,
transcript permutations and proof-of-work grinding. Small FRI rounds count too.
Public-value arithmetic used to construct a proof belongs in this inventory.

The CPU continues to parse inputs, compile static program metadata, obtain fresh
OS entropy, schedule work, move bytes, serialize the established proof format and
independently verify/apply results. Verification stays outside the GPU prover.
The target is all proving arithmetic on GPU, not zero CPU use by the application.

Support both maintained proof families without merging their profiles: legacy
wallet/batch proofs use the quadratic Goldilocks extension and production FRI
arity up to 16; block-v2 wallet and recursive proofs use the cubic extension and
binary FRI. Preserve circuits, field polynomials, lookup order, query counts,
blowup, salts, transcripts, encodings and verifier behavior. Inventory standalone
research proving entry points too. Every supported proving entry point must honor
the required-GPU policy before coverage is complete. Explicitly invoked CPU
reference implementations and test oracles remain available for comparison.

Add an explicit `GpuRequired` policy alongside the CPU reference and existing
hybrid research policy. Reject unsupported proof families, missing operations or
insufficient memory before starting a job. Under `GpuRequired`, CPU arithmetic
fallback is an error, including for small FRI rounds. Record the backend of every
proving stage and identify CPU verification separately.

All-GPU computation and full device residency are separate properties. On a
16 GB GPU, bounded host/NVMe storage may be needed to stream unchanged bytes
between device passes. Arithmetic still runs on GPU. Report these transfers and
storage costs; do not call that configuration fully resident. Unified memory
also requires a working-set budget and synchronization, and still contends with
CPU verification for physical memory and bandwidth.

### 9.2 Findings from the current source

| Stage or entry point | What exists | Remaining work |
|---|---|---|
| Wallet C-ABI | [`lib.rs`](../lattica-prover-p3/src/lib.rs), `joinsplit_air::prove_to_bytes` and `htlc_air::prove_to_bytes` reach CPU `config::proof_to_bytes`; compiling `gpu` merely makes other GPU APIs available | Route actual maintained wallet/batch and C-ABI proving calls through explicit backend selection |
| Block-v2 wallet proofs | [`leaf.rs`](../lattica-prover-p3/src/block_v2/leaf.rs) and [`typed_leaf.rs`](../lattica-prover-p3/src/block_v2/typed_leaf.rs) build traces on CPU and use `profile::make_config`; recursive proving switches do not select a full GPU wallet prover | Cover join-split, HTLC and issuance with their existing contexts, authorization checks and encodings |
| Recursive traces/preprocessing | The explicitly selected path in [`machine/backend.rs`](../lattica-prover-p3/src/block_v2/machine/backend.rs) now constructs device traces and preprocessing through [`machine/gpu_backend.rs`](../lattica-prover-p3/src/block_v2/machine/gpu_backend.rs), with unchanged registered identity and CPU verification (§9.20); default callers still use `MachineAir::trace` | Qualify complete worker workloads and port wallet/batch/public-value arithmetic; registry hashing still uses CPU; public salts have an opt-in GPU path (§9.25) |
| LDE/commitments | [`engine/lde_execute.rs`](../lattica-prover-p3/src/block_v2/gpu_hash/engine/lde_execute.rs) performs GPU transforms, retained-tree commitments, and owned degree-prefix captures; the opt-in device-only PCS mode skips host polynomial allocation/readback/reorder (§9.17), with registered GPU randomness and salts (§9.25) | Extend profile/backend coverage and qualify complete-workload memory and throughput |
| Lookup/quotient | The opt-in owned OpenCL route in [`gpu_quotient_prover::prove_batch`](../lattica-prover-p3/src/block_v2/gpu_quotient_prover/mod.rs) recovers trace rows, generates lookup witnesses, commits permutation traces and evaluates/commits quotients on GPU (§9.12) | Support periodic inputs and legacy profiles; qualify complete-workload memory and throughput |
| Legacy quotient | [`quotient_gpu.rs`](../lattica-prover-p3/src/quotient_gpu.rs) has a quadratic GPU evaluator; the normal GPU-hiding API still uses upstream CPU `prove` | Reuse its expression machinery, remove marshalling and add the distinct cubic/lookup batch-STARK adapter |
| Openings | [`opening_pcs/owned.rs`](../lattica-prover-p3/src/block_v2/opening_pcs/owned.rs) selects GPU cosets, inversion, barycentric evaluation and reduction in real proofs, with a direct device FRI handoff (§9.15) and device-only polynomial storage (§9.17) | Port other profiles/backends and qualify full-size residency |
| FRI/queries | [`opening_pcs/owned_fri.rs`](../lattica-prover-p3/src/block_v2/opening_pcs/owned_fri.rs) keeps binary cubic layers, commitments, folds and input mixing on GPU and gathers final proof rows; initial PCS queries use owned prefixes and can omit all host polynomial storage (§9.17); registered GPU transcripts and batched query-index sampling compose with complete proofs (§9.29) | Support wallet arities and other backends; finish actual stage reporting and full-size qualification |
| Transcript/grinding/scalars | [`challenger.rs`](../lattica-prover-p3/src/block_v2/challenger.rs) preserves the CPU default and selects device-owned absorption, sampling, grinding and derived scalar arithmetic in registered owned proofs (§9.28–9.29), with bounded snapshots, actual stage reports and worker reservations; the root wallet/legacy challenger remains unchanged | Extend maintained proving-route and backend coverage; audit remaining setup and public-value arithmetic |
| Hiding randomness | The registered `LATTICA_V2_GPU_RANDOMNESS=1` path selects all four private streams and public preprocessing salts, with failure retirement, GPU event reporting and additive worker reservations (§9.25); the default remains CPU randomness | Qualify full-size memory and throughput; extend backend and proof-family coverage |
| Backend/pool | OpenCL and Metal share parts of the bounded engine; [`pool.rs`](../lattica-prover-p3/src/block_v2/execution/pool.rs) provides persistent transport-independent endpoints | Metal rejects the current GPU FRI fold switch; qualify complete operation coverage per backend/device/driver |

This review covers Linux `main` and the uncommitted October 7 implementation
checkpoint below. Six modules referenced by the Apple
reports remain on the Mac and are absent here. Preserve them through the
[local Mac source checkpoint](../lattica-prover-p3/scripts/apple-current-benchmark-README.txt)
before reconciling overlapping Metal work. The reports alone do not establish
the committed Metal backend's capabilities.

The [retained 64-input capacity run](evidence/block-v2-vram16-capacity-qualification-2026-10-06-r1.json)
offers a priority signal: 63 fresh recursive proofs, retained wallet proofs and
2,112.426 seconds of owner elapsed time on the 16 GB RTX 5080 Laptop GPU. This is
an earlier single-GPU capacity workload, not a fresh-wallet throughput baseline
or a measurement of the final persistent-pool commit.

| Recorded span | Total seconds |
|---|---:|
| Native batch proving | 1,518.699 |
| Quotient polynomial evaluation | 478.944 |
| Preprocessing setup | 245.827 |
| FRI prover | 262.173 |
| FRI query phase, contained within FRI | 188.723 |
| Execution trace construction | 15.475 |

These are inclusive spans, some nested; do not sum them as independent costs or
interpret them as device-exclusive timings. Opening-reduction counters alone
record 151.594 GiB uploaded and 11.813 GiB downloaded, with 2.345 seconds of kernel
time versus 63.567 seconds of wrapper wall time. This supports prioritizing
quotient evaluation and data reuse over another standalone fold kernel. It does
not establish an expected speedup. Fresh measurements on the selected current
binary remain the first implementation gate.

### 9.3 Architecture

Use two prover adapters over a shared device runtime: wallet/uni-STARK and
registered block-v2/batch-STARK. Reuse the bounded engine, allocation accounting,
event fences, retained Merkle trees and validated kernels. Share base-field
primitives while keeping quadratic/cubic extension and profile parameters
explicit. Do not make `Pcs::EvaluationsOnDomain` pretend a GPU buffer is a host
matrix: introduce a narrow device-prover interface and retain the CPU PCS/verifier
as the reference. Keep adaptations to pinned Plonky3 0.6.1 narrow, with upstream
source/license provenance and conformance checks when dependencies change.

Evolve the planned `block_v2/gpu_pipeline` surface, extracting primitives for the
wallet adapter as needed:

- `DeviceSession`: device/backend identity, queue, immutable program cache,
  per-attempt allocations, fresh RNG state, cancellation and telemetry.
- `DeviceMatrix`/`DeviceVector`: allocation handle, field representation,
  dimensions/stride, domain/coset, bit order, valid extent and readiness event.
  Handles remain local to a device session and never enter distributed packets.
- `PreparedProgram`: registry/AIR/profile identity, constant buffers, constraint
  schedule, preprocessed commitment and per-phase memory plan. Cache only public
  immutable work; witness, salts and hiding data belong to individual attempts.
- Device operations for trace generation, lookup scans/inversion, NTT/LDE,
  constraints/quotients, commitments, interpolation/reductions, FRI, transcript,
  grinding and sparse query extraction.

Keep large intermediates on GPU across stages. Follow the reference transcript:
commitments precede lookup challenges; permutation commitments/terminals precede
quotient alpha; quotient commitments precede opening points; opened evaluations
precede the reduction challenge; each FRI commitment/grinding witness precedes
its next challenge. A device graph does not parallelize these dependencies.
Early milestones may exchange caps/challenges with the host; the strict final
path performs transcript arithmetic on GPU and returns proof payloads for host
serialization.

Admission uses peak simultaneous live allocations: preprocessing, retained trees,
trace/quotient tiles, opening/FRI vectors, query storage, staging and driver
headroom. Respect maximum single allocation and total device limits. Plan column
tiling for transforms, row tiles with required next-row access for quotients, and
bounded reconstruction/storage for late queries. Host spill is storage-only.
Apple/AMD unified-memory machines need shared physical-memory accounting;
discrete GPUs need separate host-RAM and per-device VRAM budgets. Two GPUs do not
provide one combined VRAM allocation.

### 9.4 Implementation sequence

Each milestone produces a complete CPU-verifiable proof before the next removes
more host work. Partial milestones remain labeled hybrid. Define OpenCL/Metal
contracts from the start; Linux measurements can proceed while the Mac checkpoint
and native Metal qualification are pending.

1. **Freeze coverage and measure the current pipeline.** Inventory maintained
   legacy wallet/batch, block-v2 wallet, wrap/pair, padding, merge and finalization
   entry points. Add a stage ledger with CPU arithmetic/fallback counters,
   transfer bytes, cold/warm setup and whole-proof times; separate verification
   and host application. Pin source, dependencies, binary, driver, registry,
   workload and cache policy. Exit: reproducible controls and an entry-point
   coverage matrix that catches CPU proving behind a GPU request.

2. **Introduce device intermediates and bounded memory plans.** Return device views
   from transform/commitment stages and pass them to later operations. Make any
   CPU reference readback explicit in telemetry. Reuse allocation/fence machinery
   instead of adding another unbounded pool. Describe supported fields, profiles,
   FRI arities, operations and memory limits in worker capabilities. Exit: a full
   hybrid proof with device transform/commitment reuse, correct caps/openings,
   tested allocation failures and measured transfer savings.

3. **Move lookup and quotient arithmetic onto GPU.** Compile bounded AIR expression
   programs and specialize stable registered programs where useful. Port
   selectors, periodic columns, lookup challenge combinations, batch inversion,
   exclusive prefix sums and LogUp terminals. Evaluate base/extension constraints
   in reference order, including local/next-row/preprocessed/lookup columns.
   Split quotient chunks and commit without host marshalling. Reuse legacy
   expression machinery while preserving its distinct field/profile. Bound
   register/scratch pressure and compare interpreter versus specialized kernels.
   Exit: reference arithmetic checks, unchanged preprocessing caps and fresh
   full-strength proofs accepted by unchanged CPU verifiers for both families.

4. **Complete device openings, FRI and queries.** Move denominator generation,
   inversion, barycentric evaluation and opening reductions to resident buffers.
   Keep FRI layers on GPU through folds, commitments, input mixing and final IDFT.
   Support binary block-v2 FRI and the actual arity sequence up to 16 for legacy
   wallet proofs. Batch query reconstruction/gathers and authentication paths;
   retain or reconstruct exact committed values and salts. Remove the per-round
   host-vector boundary and CPU fold fallback from the required-GPU policy.
   Exit: only bounded transcript exchanges and final proof material leave the
   device, apart from declared storage-only spill.

5. **Move witness, trace and preprocessing arithmetic onto GPU.** Build local
   join-split/HTLC/issuance/batch traces and proof public values on device. For
   recursive programs, compile `Program::operations` dependencies into a reusable
   schedule: execute independent wire operations in waves/batches, then populate
   the existing AIR rows. Preserve dependencies and unsatisfied-witness errors;
   neither assume independent rows nor change circuit packing/registry identity.
   Generate deterministic preprocessed columns/commitments on GPU and cache them
   by full program/profile identity. Exit: cold and warm proofs need no host
   trace/preprocessing field arithmetic. This milestone can develop after 2
   alongside quotient/opening work; its measured priority is currently lower.

6. **Close the remaining proving arithmetic.** Add device transcript absorption,
   squeezing, challenge conversion/rejection sampling and FRI grinding with exact
   reference state transitions. Keep tiny FRI operations on GPU in strict mode.
   Obtain independent per-proof entropy on the host, then expand the reference
   ChaCha20 streams, field samples, salts and hiding columns on device. Preserve
   draw order for deterministic conformance fixtures; never reuse seed/counter
   ranges across proofs or retry attempts. Keep deterministic seeds test-only
   and scrub private device/staging storage on completion or cancellation.
   Exit: zero CPU proving-arithmetic/fallback events, transcript/randomness
   conformance and independent verification of fresh randomized proofs.

7. **Connect real entry points, the pool and both backends.** Carry explicit backend
   policy through Rust wallet APIs, existing C-ABI wrappers and node integration
   without changing verifier ABI or accepted formats. Cover block-v2 wallet and
   recursive APIs independently. Qualify the complete operation set on NVIDIA
   OpenCL, AMD OpenCL and native Apple Metal; reject unsupported stages instead
   of using CPU. Reconcile pending Mac source where it overlaps these modules.
   Extend `WorkerEndpoint`/`WorkerCapabilities` and scheduler cost classes with
   immutable backend/kernel/profile qualification identities. Start with one
   admitted proof per GPU, retain public preprocessing between jobs, and place
   ready subtrees according to memory and measured finish times. Workers exchange
   verified public proof artifacts, never raw device handles or wallet secrets.
   Wallet GPU proving runs locally inside the wallet's trust boundary. LAN
   transport and cross-GPU NTT sharding are separate extensions, not prerequisites.

8. **Qualify delivered throughput and promote explicitly.** Validate small
   full-strength fixtures and every proof type, then 8/16/32/64-input jobs within
   admitted budgets. Measure cold/warm behavior, one versus multiple workers and
   mixed arrivals on each supported device class. Preserve unsuccessful runs.
   A full GPU path can be slower for small proofs; measure that outcome instead
   of disguising a hybrid path as all GPU. Promote only after the gates below.

The dependency chain is 1 → 2 → 3 → 4 → 6 → 7 → 8; milestone 5 depends on 2 and
must finish before 7 can claim complete coverage. Backend conformance and fault
tests accompany every milestone. Start with milestones 1–3 as the first tranche;
the existing pool does not need to be replaced to execute this plan.

### 9.5 Validation and acceptance

- **Arithmetic/layout:** differential CPU/GPU vectors for Goldilocks boundary
  values, quadratic/cubic arithmetic, inversion, NTT bit order/cosets, Poseidon2,
  salts, lookup terminals, quotient chunks, openings and all supported FRI arities.
  Cover tile boundaries and partial tiles. Compare canonical field, commitment
  and transcript semantics; do not demand identical bytes from independently
  randomized proofs. Identical seeds belong only in controlled conformance tests,
  accounting for internal noncanonical field representations.
- **Full proofs:** every supported entry point must produce fresh hiding proofs
  accepted by unchanged CPU verifiers and trusted registries. Test malformed
  proof, public-input, registry, query and context mutations; independently replay
  roots after existing pruning steps. Preserve proof parameters, identities,
  default capacity and consensus cadence.
- **Coverage:** strict mode fails on any missing device operation. Counters show
  zero CPU proving arithmetic, including wallet traces, lookups, tiny FRI rounds,
  randomness expansion and transcript/grinding. CPU audits are separate. GPU
  utilization alone does not demonstrate complete coverage.
- **Lifecycle/resources:** test admission rejection, cache/scratch bounds, event
  dependencies, cancellation during kernels/transfers, failed drains, worker
  restart, stale results and retry fencing. Physical stop remains required before
  releasing reservations/retrying elsewhere. Reserve host CPU/RAM for wallet
  input handling, coordinator and independent audits.
- **Performance:** run five alternating matched pairs against the current hybrid
  implementation using identical fresh workloads, hardware, budgets and declared
  cache state. Keep a separate CPU control. Require positive median delivered-user
  transaction gain and improvement in at least four pairs, without correctness,
  resource or deadline regressions. The original 20% lower proof-latency goal is
  an engineering target, not a promise. Count durably applied user transactions
  separately from issuance, retries and reused proofs.
- **Sustained gate:** follow the [pool qualification contract](../lattica-prover-p3/scripts/block_v2_pool_qualification.py)
  and [recorded promotion gates](evidence/block-v2-persistent-pool-2026-10-06.json):
  at least **24 hours AND 150 completed roots**, full-64 cold completion within
  600 seconds, complete post-seal-through-application within 180 seconds, depth
  six and root size at most 2 MiB. The two-root pool smoke and earlier capacity
  run do not satisfy these gates. This plan enables neither 512-input circuits
  nor a change to the 720-second cycle.

The main risks are memory residency on 16 GB devices, serial dependencies in
recursive witness generation, register/scratch pressure in constraint evaluation,
vendor differences in exact-integer throughput, and transcript/randomness
compatibility with pinned Plonky3. Resolve these with staged prototypes and
measurements. This review alone supports no transaction-per-hour or speedup claim.

### 9.6 Implementation checkpoint — 2026-10-07

Policy admission, partial stage reporting, an experimental device-buffer
handoff and optional OpenCL cubic quotient evaluation are implemented. **No
complete proving path is all-GPU, and the main PCS still returns host matrices.**
Milestones 1 and 2 remain in progress, with part of milestone 3 now available;
the fresh delivered-throughput baseline is still outstanding.

[`proving.rs`](../lattica-prover-p3/src/proving.rs) defines explicit requests:

| Setting | Behavior |
|---|---|
| `LATTICA_PROVING_POLICY=compatible` | Default; preserve the selected CPU/hybrid path |
| `LATTICA_PROVING_POLICY=cpu-required` | Reject selected GPU, mixed or unknown arithmetic |
| `LATTICA_PROVING_POLICY=gpu-required` | Reject every current complete prover at admission; no silent CPU fallback |
| `LATTICA_PROVING_REPORT=1` | Emit bounded `proving_stage_report` JSON on instrumented entry points |

Admission covers legacy wallet/batch byte APIs, all five legacy proving C-ABI
functions, block-v2 join-split/HTLC/issuance APIs, and registered-program setup and
proving. Standalone legacy prove-and-verify helpers and the generic GPU quotient
research adapter also check policy. Explicit wallet `*_with_request` APIs and
`RegisteredProgram::{new_with_request,prove_with_request}` accept an independent
CPU reference request without rereading process policy. Verification does not
consult proving policy. C-ABI rejection preserves its existing error code.

Reports use schema `lattica-proving-stages-v1` and record stage/backend, attempted
and completed calls, and inclusive wall times. Initial timers cover public-value
and trace construction, preprocessing, the upstream prover envelope, CPU
lookup/quotient work in the candidate adapter, and legacy serialization. Opaque
upstream calls or mixed/unknown work make coverage explicitly incomplete. These
are not yet complete arithmetic audits; nested/concurrent times are not additive.
Reports contain no witnesses, public inputs or randomness. Transfer counters
remain separate device/engine observations. Systemd controller, supervisor,
wallet and worker launches forward policy/report settings; controller intents
and worker budgets retain them for recovery.

[`gpu_hash::device`](../lattica-prover-p3/src/block_v2/gpu_hash/engine/device.rs)
provides proof-session ownership, checked domain/layout/extension metadata,
device matrices, live-allocation plans and explicit bounded transfers. Buffers
share engine accounting, fences and the context lease. Cross-session use is
rejected; live matrices or commitments prevent shutdown. The experimental chain
is a device cubic vector → binary FRI fold → salted Merkle commitment → next
fold. It exchanges device handles between operations. Only caps and requested
authentication paths leave the device during commitment. Compile-time FRI roots
are checked against the pinned CPU field; callers still supply salts/challenges.

The main prover does not yet use this chain. Metal folding rejects explicitly;
neither Metal nor AMD has been qualified for the new operations. CPU checks and
bounded NVIDIA OpenCL tests cover admission, buffer accounting, fold results,
commitment caps, paths and ownership. Production wallet/registered-program proofs
still verify on CPU, and the existing hybrid quotient pipeline preserves reference
proof bytes. The [checkpoint evidence](evidence/gpu-proving-foundation-2026-10-07.json)
pins the tested binary, source archive and GPU identity. These checks establish
correctness, not a throughput improvement.

The cubic block-v2 quotient evaluator compiles the pinned AIR and LogUp
constraints into a bounded program. OpenCL evaluates selectors, alpha powers,
base and cubic extension constraints, and division by the trace vanishing
polynomial. Constraint ordering follows Plonky3's global interleaved emission
order. Current/next main, preprocessed and permutation rows, all public values,
lookup challenges and terminals are supported. Periodic columns reject
explicitly. Scratch registers reuse expression lifetimes; row tiles respect
live allocations, aggregate/device allocation limits and host output bounds.

Select this research path with `LATTICA_V2_GPU_QUOTIENT_EVAL=1`, in addition to
GPU hashing, retained trees, resident LDEs, quotient fusion and
`LATTICA_V2_GPU_QUOTIENT_LDE=1`. It defaults off, rejects invalid values and
unsupported backends, and never silently falls back to CPU. Pool workload
geometry accepts `gpu_quotient_eval: true`; worker budgets retain the selection
and reserve additional host memory for program compilation and tiled transfers.
`gpu-required` still rejects this hybrid prover.

Bounded NVIDIA checks passed exact arithmetic comparisons on nonzero matrices,
three trace/quotient geometries, zero/one/nontrivial alpha, interleaved constraint
types, next-row accesses and multiple tiles. Invalid overlapping domains reject.
Full proof bytes match the CPU reference; the unchanged CPU verifier accepts
both the test proof and a registered-program proof with 64 public slots, and
rejects changed public statements. These establish correctness, not delivered
throughput. [Quotient evaluation evidence](evidence/gpu-quotient-evaluation-2026-10-07.json)
pins the release binary, source, runner, bounded services and successful checks.
Across three synthetic runs with 4,096 quotient rows and nontrivial alpha, median
CPU and GPU-adapter times were 19.587 ms and 19.557 ms, respectively. The adapter
was slower on 8- and 32-row inputs. These stage measurements include program
compilation and transfers, but are not transaction-throughput measurements.
They prioritize device data reuse and prepared-program reuse before any speedup
claim. The evaluator still packs host matrices and returns host quotient
values; lookup witness generation, trace construction, transcript and other
proving arithmetic remain on CPU. AMD OpenCL and Apple Metal are unqualified.

The subsequent owned-input integration is recorded in §9.8. A matched
workload baseline and GPU lookup witness generation (challenge combinations,
inversion, prefix sums and terminals) remain outstanding, followed by the
remaining stages and qualification gates in §9.4.

### 9.7 Owned transform → quotient → commitment checkpoint — 2026-10-07

This records the device API milestone. The subsequent integration into real
proofs is recorded in §9.8 below.

The experimental device interface now connects three arithmetic stages without
intermediate matrix readback. This route has not yet replaced the host-backed
PCS interfaces in the main prover; it is not a complete GPU proof path.

- `DeviceSession::lde` interpolates a device matrix on its input coset and
  evaluates it on an equal or larger coset. It uses the existing bounded tiled
  NTT, preserves the input, and handles natural and bit-reversed storage. Base,
  quadratic and cubic columns share the base-field transform. Normalization
  and coset scaling execute on GPU; only pinned root constants are uploaded.
- `prepare_quotient` uploads a compiled static AIR program once. The prepared
  code retains its device context and can be reused across fresh proof
  sessions. It contains no witnesses, sampled challenges or salts. Private
  matrices still reject use by a different proof session.
- `quotient_cubic` gathers local/next rows from device main, preprocessed and
  cubic permutation matrices, reuses the existing quotient evaluator, and
  returns an owned cubic device vector. Parameters are uploaded per call; the
  GPU validates the disjoint coset and returns an eight-byte status. The result
  can feed `DeviceSession::commit` directly, with only caps and requested paths
  returned to the host.

All live inputs, prepared code, output matrices, transform scratch and quotient
tiles count against the existing engine allocator. Planning precedes enqueue,
per-allocation limits remain enforced, and queue fences retain temporary
buffers on failure. Prepared code and matrices prevent context shutdown until
they are released. Unsupported Metal operations reject explicitly; AMD remains
unqualified.

GPU conformance covers 20 transform combinations across cosets, physical row
orders, matrix widths and extension degrees, including one-row transforms and
multiple NTT groups. The connected test reuses prepared code across fresh
sessions, changes proof parameters, compares CPU quotient vectors, caps and
paths, and crosses quotient tile boundaries. It asserts no intermediate matrix
uploads/downloads, rejects overlapping cosets and foreign-session matrices, and
checks allocation recovery after failures. Existing host-adapter arithmetic
and complete proof-byte equivalence checks also pass with the shared kernel.

The [owned quotient checkpoint evidence](evidence/gpu-owned-quotient-2026-10-07.json)
pins a release binary, matching source archive, runner and all five bounded GPU
checks, plus eight unit checks and both CPU/GPU streaming builds. In the test
fixture each quotient call uploads 800 parameter bytes and downloads the
eight-byte status; static code is uploaded once. These are transfer and
correctness observations, not a transaction-throughput qualification.

Integration still requires explicit ownership for public preprocessing and
attempt-private main/permutation data in the real proving adapter. Quotient
chunk splitting, hiding and PCS opening consumers must accept device buffers;
adding another host `Matrix` facade would restore the boundary this interface
removes. Keep these changes tied to unchanged CPU verification and the real
proof DAG before making any transaction-throughput claim.

### 9.8 Owned quotient inputs in real proofs — 2026-10-07

This checkpoint records the initial contiguous-input integration. The subsequent
bounded coset implementation is recorded in §9.9.

The registered block-v2 prover now has an opt-in route from GPU trace commitments
through GPU quotient evaluation, using owned device inputs. Set
`LATTICA_V2_GPU_QUOTIENT_RESIDENT=1` together with GPU hashing, retained trees,
resident PCS, quotient fusion, GPU quotient LDE and GPU quotient evaluation.
The flag defaults off. It accepts only ASCII `0` or `1`, records the selection
immutably, and rejects missing dependencies or unsupported backends without
CPU fallback. `gpu-required` still rejects the complete hybrid prover.

The resident PCS captures degree-sized, bit-reversed prefixes while commitment
transform tiles are live. Deterministic public preprocessing owns immutable GPU
allocations that fresh proof sessions may import within the same GPU context.
Main and permutation captures remain private to their proof attempt. Projection
strips hiding columns and interprets permutation coefficient columns as cubic
extension elements; GPU transforms expand prefixes to the quotient domain.
The quotient evaluator consumes these buffers before any host
`get_evaluations_on_domain` calls. Private captures are released after quotient
evaluation. Public allocations live as long as the registered prover data.

This integration removes quotient **input** matrix readback and re-upload from
that stage. Existing host copies are still produced for PCS openings. Quotient
**output** is explicitly read back for CPU chunk splitting and the existing
hiding PCS boundary. Static AIR code is prepared per proof in this adapter;
caching it across registered proofs remains future work. Program/challenge
uploads, transform root uploads and an eight-byte domain-status download remain
explicit. Trace construction, LogUp witness generation, transcript/randomness,
opening interpolation and other proving arithmetic remain on CPU.

Admission now includes captured prefixes and contiguous expanded inputs, with
both aggregate and single-allocation checks before execution. Pool workload
geometry can request `gpu_quotient_resident: true` only alongside
`gpu_quotient_eval: true`; worker assignments pin the mode and reservation.
The existing full workload has 524,288 prefix rows, 4,194,304 quotient rows and
200 preprocessing columns. Its expanded preprocessing matrix alone needs
6,710,886,400 bytes, exceeding the laptop GPU's 4,174,331,904-byte allocation
limit. That workload is rejected. It needs a bounded input strategy before this
route can be qualified at full size; increasing the memory budget cannot remove
the hardware's single-allocation limit.

[Integration evidence](evidence/gpu-owned-prover-2026-10-07.json) records the
source archive, release binary, bounded native checks and earlier failed runs.
Full and compact proofs preserve reference proof bytes and pass the unchanged
CPU verifier, including rejection of altered public statements. Three fresh
registered proofs share public preprocessing while private device allocations
return to baseline after each proof. Dropping the registered prover releases
public buffers; the independent verifier still works after GPU shutdown.
Default-path regressions cover the previous quotient adapter, compact proofs,
commitment randomness and tiled LDEs. Resource tests and CPU/GPU streaming builds
also pass. These are correctness/lifecycle checks on NVIDIA OpenCL, not delivered
transaction-throughput measurements. AMD and Metal remain unqualified.

Next, make large input consumption bounded without restoring host arithmetic,
then keep quotient chunk processing on the device and port lookup witness
generation. Continue openings/FRI, trace generation, transcript/randomness,
entry-point coverage and the performance/qualification gates in §9.4–§9.5.

### 9.9 Bounded coset quotient evaluation — 2026-10-07

This checkpoint records bounded quotient evaluation. The later removal of its
output readback and host chunk/hiding arithmetic is recorded in §9.10.

The owned-input route now evaluates the quotient domain as at most 256 smaller
cosets. Each pass expands inputs only to the largest retained prefix height,
evaluates constraints, then interleaves its natural-order cubic results into the
full device output. Multiplication by the trace generator stays inside each
component coset, so next-row constraints preserve the reference semantics.
The AIR, transcript order, hiding parameters, commitments and verifier stay
unchanged. Public domain partition descriptors are still constructed on CPU;
interpolation, quotient arithmetic and output assembly run on GPU.

`DeviceSession::quotient_cubic_partitioned` reuses the prepared AIR program across
all cosets in a proof. An unchanged prefix can be aliased within its proof
session; other cosets use the owned transform operation. Temporary evaluated
inputs are released after each coset. No intermediate matrix leaves the GPU.
The adapter still reads back the final cubic quotient for CPU chunk handling,
and still produces host PCS copies for openings. Parameter and transform-root
uploads are counted explicitly; domain validation returns eight bytes per coset.
Repeated interpolation and queue synchronization may cost time, so this is a
memory/correctness improvement without a throughput claim.

[Bounded quotient evidence](evidence/gpu-partitioned-quotient-2026-10-07.json)
records CPU quotient/cap/path comparisons for four geometries, including nonzero
constraints, alpha zero and nontrivial alpha, public inputs, extension arithmetic,
and local/next-row accesses. Under a 12 MiB device-engine budget, the old full
expansion is rejected while the partitioned 1,024-prefix-row / 4,096-quotient-row
case succeeds. Full and compact proof bytes remain identical to the reference;
public preprocessing reuse and private allocation cleanup still pass. Release
regressions also cover the earlier unpartitioned device API and default paths.

For the existing full workload, the largest new input allocation is
838,860,800 bytes instead of 6,710,886,400 bytes. Pool reservations now account for
captured prefixes, projected prefixes, one coset's inputs, transform scratch,
public preprocessing cache entries, the full cubic output and a temporary cubic
coset. The conservative extra reservation is 5,460,983,808 bytes; combined with
the existing 4 GiB phase allowance it exceeds the 7 GiB managed budget in the
16 GiB resource test assignment. The profile remains rejected on aggregate
memory, and no full-size native proof is qualified by these tests. Measure
simultaneously live allocations and refine phase reservations before a large
run; preserve existing budgets and admission checks.

The next arithmetic boundary is quotient chunk splitting and hiding commitment
input. Keep that output on device, then port lookup witness generation and
continue the remaining sequence in §9.4. A matched end-to-end throughput baseline,
complete stage accounting, AMD/Metal conformance and sustained pool qualification
remain open.

### 9.10 GPU quotient chunks and hiding commitments — 2026-10-07

The opt-in owned quotient route now carries its cubic output directly into
chunk processing and hiding commitments. It no longer reads the quotient vector
back to CPU, flattens/splits it into host matrices, or uploads those matrices
again. The existing `LATTICA_V2_GPU_QUOTIENT_RESIDENT=1` selection controls this
route; default behavior and strict-policy rejection of the hybrid prover remain
unchanged.

The shared LDE/commitment executor now accepts an explicit device quotient input,
separate from its host matrix input. A GPU kernel gathers each chunk's three
coefficient columns and its hiding columns into the existing transform tiles.
GPU kernels also compute transform normalization, coset scaling and balanced
hiding coefficients before the forward transform and joint salted commitment.
For a complete uniform coset partition, all reference normalized vanishing
weights equal `-1/chunks`; the final mask is therefore the negative sum of the
independent masks. The device input contract admits only that canonical
partition, with the existing cubic profile and 2–16 chunks. CPU reference tests
check the weight identity independently.

Random samples are still drawn on CPU, in the exact reference order: all random
columns in chunk/row/column order, then all independent masks. GPU code computes
the constrained final mask. Neither private randomness nor input buffers become
shared preprocessing. Shapes, ownership, host output bounds, aggregate GPU
memory and each auxiliary allocation are checked before RNG draws. The executor
replans under the engine lock and fences kernels before buffers can be released.
Pool reservations now also cover random-column samples, independent mask samples
and hiding parameters, including cases where these are wider than trace inputs.

[Quotient commitment evidence](evidence/gpu-owned-quotient-commit-2026-10-07.json)
records complete proof-byte equality, unchanged CPU verification, preprocessing
reuse and private allocation cleanup. Direct checks compare all LDE entries,
commitment caps, opened values and paths for 2/4/16 chunks, shifts 7 and 11, and
chunk heights through 8,192 rows. Invalid chunks, foreign proof sessions and
mismatched domains are rejected without advancing hiding or salt RNG streams.
Default host-input commitment and admission regressions remain part of the
release checks, alongside CPU/GPU streaming builds and resource tests.

The 1,024-row proof fixture now records zero quotient-vector readback and zero
quotient-matrix upload into commitment. It still uploads 86,528 bytes of random
samples for its 16 hiding chunks. This is a transfer/correctness observation,
not a transaction-throughput result. PCS LDE readback remains for host openings;
public domain descriptors, AIR compilation, witness/trace generation, lookup
witnesses, random expansion and transcript work still use CPU. Only NVIDIA
OpenCL has been tested; Metal rejects this path and AMD remains unqualified.
The conservative full-size pool profile still fails aggregate admission.

Next, move LogUp witness generation onto GPU: compile its tuple/multiplicity
expressions, combine lookup challenges, invert denominators, compute prefix sums
and terminals, and feed the resulting permutation trace into GPU commitments.
Continue the remaining stages and complete-workload gates in §9.4–§9.5.

### 9.11 GPU LogUp witness arithmetic — 2026-10-07

This records the arithmetic-only checkpoint. The subsequent real-prover
integration is documented in §9.12.

An experimental OpenCL device API now generates the cubic block-v2 LogUp
permutation trace and terminal. It is **not connected to real proving yet**;
registered proofs still call the CPU lookup generator. This is progress within
milestone 3, not a completed all-GPU proving path or a throughput result.

`LookupProgram` compiles the pinned Plonky3 0.6.1 tuple and multiplicity
expressions into bounded scalar stores, reusing the quotient expression compiler
and register allocator. It validates contiguous lookup slots, matching
multiplicities, expression windows and resource bounds. Current/next main and
preprocessed columns, public values, first/last/transition selectors, empty
tuples and nonempty lookups with zero tuples are supported. Periodic and
permutation inputs reject explicitly. AIRs without lookups must skip the API.

`DeviceSession::lookup_permutation` consumes original, unblinded subgroup traces
in natural or bit-reversed order. Kernels perform cubic Horner combinations,
128-lane product-tree inversion, fraction generation and a hierarchical prefix
scan. Column zero is the exclusive accumulator; the terminal includes every row.
Zero multiplicity substitutes denominator one. An active zero denominator sets
failure status, drains pending commands and rejects the result. Tiles contain
at most 1,024 rows; full output, scan levels, parameters and scratch are checked
against aggregate and per-allocation limits. Private buffers remain owned by one
proof attempt; immutable prepared programs can be reused in the same GPU context.
Only an eight-byte status and the 24-byte terminal leave the device on success.
Session counters record prepared programs, completed generations and device time.

[Lookup conformance evidence](evidence/gpu-lookup-2026-10-07.json) pins the source
archive, release binary, bounded runner and retained unsuccessful runs. **58 Rust
tests and 29 Python resource tests passed**, along with CPU and GPU streaming
builds. Lookup checks compare every entry and terminal with the reference for
1–32,768 rows, all four input row-order combinations, multiple tiles and three
scan levels. They cover boundary field values, shared expressions, selectors,
next-row wraparound, signed/zero multiplicities, empty tuple cases, active-zero
rejection, prepared reuse, private ownership and allocation recovery. These
fixtures upload original traces for comparison; they do not establish an
integrated device lookup pipeline. Existing full/compact proof-byte, CPU
verification, registered preprocessing reuse and default-path regressions pass
with their existing CPU lookup generation. Only NVIDIA OpenCL is tested; Metal
rejects the operation and AMD remains unqualified.

The next integration checkpoint is concrete:

1. Recover original trace rows on GPU from captured degree prefixes: transform
   the 2N-row hiding domain to the subgroup, gather even rows and strip hiding
   columns. Reuse public preprocessing through its existing context ownership;
   retain private main data only within its proof attempt.
2. Extend `CommitSource` to accept the device permutation trace. Fill original
   values and hiding rows/columns on GPU using samples drawn in the exact
   reference order. Capture the permutation prefix for quotient consumption.
3. Add an immutable opt-in lookup selection requiring the owned OpenCL quotient
   route. Reject missing capabilities or memory before work, include the new
   simultaneous allocations in pool reservations, and record the actual lookup
   backend in stage reports. Keep debug CPU audits explicit.
4. Require complete full/compact proof-byte equality, unchanged CPU verification,
   fresh registered proofs, preprocessing reuse, cleanup/error tests and default
   regressions before claiming lookup integration. Then continue milestones
   4–8, including legacy profiles, native backends and measured transactions/hour.

### 9.12 GPU lookup integration and permutation commitments — 2026-10-07

The real registered block-v2 prover now has an opt-in GPU lookup path. Set
`LATTICA_V2_GPU_LOOKUP=1` alongside the owned OpenCL quotient route and its
existing dependencies. Selection is immutable, accepts only ASCII `0` or `1`,
and defaults off. Missing capabilities, unsupported layouts and allocation
failures reject without CPU fallback. Complete proving remains hybrid, so
`gpu-required` still rejects the full prover.

Before main commitment randomness is consumed, the adapter compiles and admits
lookup expression programs. After challenges are sampled it imports the captured
main/preprocessing prefixes into the proof session, projects the AIR columns,
transforms the doubled hiding domain back to the subgroup and selects even rows.
The original trace values never leave the GPU at this boundary. Public
preprocessing remains reusable across sessions; recovered rows and lookup output
remain private to the proof attempt.

The generated cubic permutation trace feeds a new device commitment input.
Hiding samples are still drawn on CPU, in the existing matrix/row/column order.
GPU kernels interleave original values, random columns and random rows, then
normalize and scale inverse-transform coefficients before the existing LDE and
Merkle commitment. The commitment captures an owned permutation prefix for the
GPU quotient stage. There is no permutation trace readback or re-upload in the
release route. Host PCS LDE matrices still exist for openings. Debug builds make
the constraint-audit readback explicit; these audits are separate from proving.

Pool assignments now pin `gpu_lookup` and require owned quotient evaluation.
Reservations include recovered traces, projection/transform buffers, permutation
output, scan levels, hiding samples and bounded expression scratch. One hiding
sample vector is materialized on the host at a time. Expression tiles are capped
at 64 MiB as well as the existing engine and per-allocation limits. For the
preserved full workload, the conservative extra managed reservation remains
5,460,983,808 bytes and the maximum individual allocation 838,860,800 bytes;
lookup sample staging adds 132,120,576 host bytes. Combining this reservation
with the existing 4 GiB phase allowance still exceeds the managed GPU budget.
This checkpoint does not qualify a full-size workload.

[Integration evidence](evidence/gpu-lookup-integration-2026-10-07.json) pins the
release binary, matching source archive and bounded runner. **62 Rust tests and
30 Python resource tests passed**, plus CPU and GPU streaming builds. Full and
compact proofs preserve reference proof bytes and pass the unchanged CPU
verifier. Three fresh registered proofs reuse public preprocessing and release
private allocations; verification also works after GPU teardown. Direct tests
compare every LDE entry, caps, openings and paths, recover original rows through
8,192 rows, and verify that rejected inputs do not disturb hiding or salt streams.
The earlier lookup arithmetic tests and default proving paths remain covered.

The full-proof fixture has 64 original rows, 16 lookups and 93 tuples. Its lookup
call returns 32 control bytes and no matrix; permutation commitment uploads
30,208 bytes of hiding samples and no permutation matrix. The registered stage
ledger records a completed OpenCL lookup call and still reports incomplete
coverage. These observations establish correctness and data flow, not a
transactions-per-hour improvement. Only NVIDIA OpenCL is tested; AMD remains
unqualified and Metal rejects this path.

Next, complete device opening evaluation and FRI/query consumers, retaining the
existing cubic profile and proof format. Continue witness/preprocessing,
transcript/randomness, legacy/API/backend coverage and complete-workload
qualification in §9.4–§9.5. Measure actual simultaneous allocations before
relaxing any pool reservations.

### 9.13 Device opening evaluation and FRI-input arithmetic — 2026-10-07

An experimental device API now performs the opening arithmetic from degree
prefixes through reduced FRI input vectors. **At this checkpoint, real proving did
not select this API; §9.14 records its integration.** The previous opening adapter generates denominators and claimed
values on CPU, then returns GPU-reduced vectors to the host FRI prover. This is
progress within milestone 4; complete proving remains hybrid.

`DeviceSession::evaluate_opening` accepts a session-owned, bit-reversed base-field
coset prefix and bounded cubic opening points. GPU kernels compute point
inverses, barycentric scaling, coset denominators, batch inversions and tiled
column sums. Claimed values stay on device until an explicit bounded
`opening_values` read supplies the transcript. Zero points and malformed shapes
reject before dispatch; a point on the prefix coset drains commands and fails.

After the transcript supplies alpha, `OpeningAccumulator` maintains reference
matrix/point/column ordering and per-height alpha offsets. GPU kernels form
powers and compressed claims, compress each degree prefix, expand only its cubic
combination through the existing device LDE, and accumulate opening quotients.
The finished vector is a device-owned bit-reversed cubic subgroup vector, ready
for FRI. A failed append consumes the accumulator, so partially written output
cannot be reused. A point on the expanded coset fails even when it was not on
the smaller prefix coset. No implicit host matrix readback or CPU fallback exists.

Plans cover retained values/points, interpolation partials, denominator tiles,
compressed vectors, full transform output/scratch, alpha metadata and status.
Every allocation and aggregate peak is checked against engine limits. Evaluation
tiles contain at most 4,096 rows, reduction tiles at most 65,536, and temporary
tiles at most 64 MiB. The API preserves the current 4,096-column, 32-point and
binary cubic profile bounds; Metal rejects it. Claimed-value readback is explicit
proof/transcript material, separate from intermediate matrix transfer counters.

[Opening arithmetic evidence](evidence/gpu-owned-openings-2026-10-07.json) pins the
release binary, source archive and bounded native runner. **65 Rust tests and
30 Python resource tests passed**, along with CPU and GPU streaming builds.
Claimed values match direct CPU polynomial evaluation; every reduced vector
entry matches direct reference opening arithmetic. Cases span 1–8,192 prefix
rows and 16–131,072 FRI rows, two cosets, multiple matrix widths, up to 32 points,
repeated points, zero/nontrivial alpha and Goldilocks boundary values. Tests
cover tile boundaries, private ownership, explicit readback allowances,
denominator failures and allocation recovery. The resulting vectors feed the
existing cubic fold operation without upload or download. This is a device
handoff check, not a complete resident FRI proof.

Each evaluation uploads only its points and returns an eight-byte status before
claimed values are explicitly requested. Each accumulator uploads a 24-byte
alpha; each append returns an eight-byte status. Transform-root uploads remain
visible. No intermediate matrix leaves the device in this API. Existing complete
proof, verifier and lifetime regressions pass using their previous opening path.
Only NVIDIA OpenCL is tested; these are correctness observations, not measured
transactions-per-hour improvements.

The next integration must extend commitment ownership, not add another host
prefix upload. Capture quotient and random-codeword prefixes; quotient hiding
doubles its degree, so capturing only the original quotient chunk height is
insufficient. Keep private main/permutation prefixes through opening rather than
releasing them after quotient evaluation. Preserve transcript observation order,
add simultaneous-memory admission, and require full/compact proof-byte and
verifier checks. Then connect device FRI commitments, input mixing, final
coefficients and queries, continuing the remaining gates in §9.4–§9.5.

### 9.14 GPU opening integration — 2026-10-07

Real block-v2 proofs now have an opt-in GPU opening evaluator and reducer. Select
`LATTICA_V2_GPU_OPENING_EVAL=1` together with `LATTICA_V2_GPU_OPENINGS=1` and
the owned OpenCL quotient route. Selection is recorded before work and cannot
change during a process. The default adapter remains available. **Complete
proving is still hybrid**, and `gpu-required` continues to reject it.

Main and permutation degree prefixes now survive quotient evaluation when this
mode is selected. Quotient commitments capture **twice the original chunk
height** to include hiding masks; random-codeword commitments capture their
existing degree without another hiding step. Capture admission counts those
buffers before random/salt draws and rechecks under the engine lock. Private
prefixes stay bound to their proof session; public preprocessing can be imported
by fresh sessions. All private allocations drop with the attempt.

The opening adapter imports these commitment buffers without uploading host
prefixes. GPU kernels evaluate the claimed values, which are observed in the
unchanged round/matrix/point order. Alpha is sampled afterwards. Device
accumulators preserve the original per-height exponent order. One height is
reduced at a time, then explicitly downloaded for the existing FRI prover.
Commitments still produce host PCS data for its remaining interfaces. Removing
both host boundaries belongs to the next FRI/query milestone.

Pool assignments pin `gpu_opening_eval`. Reservations cover retained trace,
quotient and random prefixes, claimed values, the accumulator, compressed
prefixes, transform output/scratch and the explicit host FRI boundary. The
preserved full workload adds 404,426,752 host bytes for opening; its conservative
managed reservation remains 5,460,983,808 bytes because the quotient phase still
dominates. Adding the existing phase allowance still fails GPU memory admission.
No full-size workload or transactions-per-hour improvement is qualified.

[Integration evidence](evidence/gpu-opening-integration-2026-10-07.json) pins
the binary, source archive, runner and logs. **74 Rust test cases and 32 Python
resource tests passed**, plus CPU and GPU streaming checks. Full and compact
proofs preserve exact reference bytes and pass unchanged CPU verification with
GPU lookup both off and on. Tests compare every captured quotient/random
prefix entry to its full reference LDE, preserve RNG streams across clones and
rejected admissions, and reuse public preprocessing for three fresh proofs
while restoring private-allocation baselines. Earlier arithmetic and default
proving regressions remain covered.

The 64-row proof fixture opens 20 matrices, reads 12,648 bytes of claimed values
and explicitly downloads 49,152 FRI-vector bytes. Opening itself uploads or
downloads no degree prefix. These are transfer/correctness observations, not
throughput measurements. Only the RTX 5080 Laptop OpenCL backend was tested;
AMD is unqualified and Metal rejects the new operations.

At this checkpoint the next step was to replace the FRI host-vector consumer
(implemented for binary block-v2 in §9.15) with device commitments, folds,
input mixing, final coefficients and query assembly. Preserve transcript order,
salts and proof bytes while accounting for complete layer lifetimes. Then
continue witness/preprocessing construction, transcript/random expansion,
legacy and wallet/API coverage, AMD/Metal conformance and full-size memory and
throughput qualification in §9.4–§9.5. Keep strict GPU-only admission closed
until all required proving stages are covered.

### 9.15 Resident binary FRI integration — 2026-10-07

`LATTICA_V2_GPU_FRI_RESIDENT=1` now connects the owned opening outputs directly
to a device FRI consumer. It requires owned OpenCL opening evaluation and is
immutable after initialization. This separate switch controls every binary
fold in the resident path, independent of the older `LATTICA_V2_GPU_FRI_FOLD`
adapter switch. Default paths and the proof parameters remain unchanged.
**This completes the binary block-v2 FRI arithmetic path, not all proving.**

Opening reduction retains its finished vectors on GPU. Each FRI round pairs
adjacent cubic elements through an immutable view, commits those values and
four salt columns on GPU, observes the cap, and samples beta in upstream order.
Folding and `beta²` input mixing allocate new device outputs, preserving all
committed layers. The fixed profile has a one-coefficient final polynomial;
its inverse transform is the identity, so only that 24-byte coefficient is
read for transcript observation. No FRI input or layer vector is downloaded.

Query indices are sampled in reference order. Device gathers return the two
queried cubic values and four salts for each layer; retained Merkle trees
supply the authentication paths. Only final proof material is assembled on
the host. Initial PCS queries still use the existing host-backed/compact
reconstruction interface. Transcript/grinding and random expansion remain
on CPU. Larger final polynomials, nonbinary wallet arities, AMD and Metal
are outside this checkpoint.

A local extension-MMCS adapter preserves Plonky3's exact flattening, proof
encoding, verification and cloning behavior while exposing its original salt
stream to the device committer. No alternate or replayed RNG stream is added.
Salt staging and the complete commitment peak are admitted before salt draws,
including any transform cache still live during upload. Execution replans
under the engine lock. Immutable layers, salts and trees remain bound to one
proof session and are released after query assembly.

Pool assignments pin `gpu_fri_resident` and reserve concurrent opening outputs,
geometrically decreasing FRI layers, salts, trees and fold/mix/commit scratch.
CPU salt staging has a separate 1 GiB bound. The preserved full workload adds
269,484,032 host bytes for this path; the existing conservative phase model is
retained. Its extra managed reservation remains 5,460,983,808 bytes and still
fails admission when combined with the existing phase allowance. No full-size
throughput claim or relaxation of aggregate limits follows from these tests.

[Resident FRI evidence](evidence/gpu-resident-fri-2026-10-07.json) pins the final
binary, source archive, runner and logs in `gpu-resident-fri-20261007/run-02`.
**81 Rust test cases and 33 Python resource tests passed**, plus CPU and GPU
streaming checks. Full/compact proofs preserve exact reference bytes with
GPU lookup both off and on. Serialized proofs also decode and verify through
the original Plonky3 CPU PCS and extension adapter. Three fresh registered
proofs reuse preprocessing, restore private allocation baselines and verify
after GPU teardown. Default proving regressions remain covered.

Independent FRI checks span input heights `[16]`, `[32, 16]`,
`[2048, 128, 16]` and `[65536, 4096, 256]`. Proof bytes and the next transcript
challenge match the upstream algorithm. Exact transfer counts account only
for salt uploads, query indices, caps, query values/salts, authentication paths
and the final coefficient. Foreign owners, invalid query bounds, insufficient
host staging and aggregate GPU admission failures reject; failed admission
does not advance the salt stream. The extension adapter also matches the
upstream adapter across mixed matrix heights and repeated commitments.

The 64-row proof fixture runs seven device folds. Its opening FRI-vector
readback drops from 49,152 bytes to zero. Layer query values/salts and the final
coefficient total 71,704 bytes; caps and paths are separate final-proof
transfers. These measurements demonstrate data flow and correctness on the
RTX 5080 Laptop OpenCL backend, not transactions-per-hour improvement.

At this checkpoint the next step was initial PCS storage/query integration.
§9.16 removes the query dependency; redundant host LDE production remains.
Continue GPU witness/preprocessing construction, transcript/grinding/random
expansion, legacy wallet/API and backend coverage, and complete-workload
qualification. Strict `gpu-required` admission remains closed until the
whole required stage inventory and verification gates are satisfied.


### 9.16 Owned initial PCS query reconstruction — 2026-10-07

The selected resident binary FRI route now reconstructs initial PCS query
rows from the existing device-owned degree prefixes. It no longer reads
host LDE matrices or invokes the legacy compact-prefix uploader/cache.
`LATTICA_V2_GPU_FRI_RESIDENT=1` selects this path with its existing required
opening/quotient modes. The older query-gather switch continues to control
its existing adapter; the owned route always gathers on device.
**Complete proving remains hybrid, and redundant host LDE production still
exists at commitment time.**

`OwnedInputs` records committed dimensions independently of host matrices.
Owned opening evaluation and query assembly consume that metadata, import
public preprocessing or alias private prefixes within the correct session,
and reject missing ownership instead of falling back. Query reconstruction
interpolates and expands one column tile at a time using two reusable
buffers. Normalization runs on GPU; immutable root constants and indices
are the only uploads. Gathered rows are returned in caller order, including
duplicates. Host assembly adds existing salt rows and authentication paths
from the retained GPU tree. The salt stream and proof encoding are unchanged.

The query API admits 1–256 indices, at most 4,096 base-field columns and
committed domains through 2^25 rows. Plans include both transform buffers,
root/parameter/index buffers, the gathered tile, host result and staging.
It prefers at most 64 MiB of GPU scratch; domains requiring more for a single
column use that explicitly bounded minimum. Aggregate and individual
allocation limits still apply, commands drain before release, and inputs
remain immutable. Metal rejects the new operation.

Pool reservations include simultaneous retained FRI layers and query scratch,
plus bounded host proof assembly. The preserved full workload adds
31,129,600 host bytes for initial PCS queries. Total selected extra host
reservation is 1,105,596,416 bytes. The conservative extra managed reservation
remains 5,460,983,808 bytes and the largest allocation 838,860,800 bytes;
quotient work still dominates. The full workload remains unqualified under
the existing aggregate memory admission. This change establishes no
transactions-per-hour improvement.

[Owned query evidence](evidence/gpu-owned-pcs-queries-2026-10-07.json) pins the
release binary, all 223 source files, source archive, bounded runner and
logs in `gpu-owned-pcs-queries-20261007/run-02`. **85 Rust test cases and
34 Python resource tests passed**, plus CPU and GPU streaming builds.
Native primitive checks cover 1–8,192 prefix rows, 1–131,072 committed rows,
three cosets, boundary field values, repeated/unsorted queries and tiles
that require multiple passes. Exact transfer counts include only immutable
roots/indices uploaded and queried values downloaded. Admission/owner
failures preserve inputs and allocations; every native check drains to
zero managed bytes and releases its lease.

Full/compact commitment-oracle tests remove host LDE containers before
querying, compare exact CPU rows/salts/paths and check the subsequent salt
stream. Complete proofs also remove main/permutation host LDEs after
quotient evaluation: GPU opening evaluation and queries still preserve
reference bytes with GPU lookup off/on and verify with the original CPU
PCS and extension adapter. Three fresh registered proofs reuse public
preprocessing, restore private allocation baselines and verify after GPU
teardown. Default/earlier paths retain regression coverage.

The 64-row fixture reconstructs 20 matrices in 20 tiles and downloads
483,328 initial PCS query-value bytes, with **zero prefix upload or readback
during queries**. Its query host plan is 6,578,176 bytes. Salts, caps and
paths are separate proof material; commitment-time host LDE copies still
exist. The existing FRI layer-query/final-coefficient total remains 71,704
bytes. These are correctness/data-flow measurements on NVIDIA OpenCL;
AMD/Metal and transaction throughput remain unqualified. Run-01 is retained:
its arithmetic test passed, but its integration fixture used a one-row
input unsupported by the existing commitment executor. Run-02 corrects
that fixture and strengthens the full-proof storage-removal checks.

The storage change planned here, now completed in §9.17, was to:

1. Introduce an explicit retention type distinguishing a host prefix from
   device-only output in the LDE planner/executor. The device-only branch
   must skip host allocation, readback and reorder, rather than discard data
   after downloading it. Keep existing host planner entry points compatible.
2. Add a real device PCS representation containing committed geometry,
   owned prefixes, salts and retained trees. Its host matrix accessor must
   reject access. Owned openings and the query adapter above already have
   the interfaces needed to consume it.
3. Admit the selected route before random or salt draws, require the owned
   quotient/lookup/opening/FRI consumers, and preserve explicit debug audits.
   Keep CPU reference proving configured independently of process-global
   device-only selection for byte-equivalence tests.
4. Measure zero commitment LDE readback and preserve complete proof bytes,
   original CPU verification, preprocessing reuse and cleanup. Recompute
   simultaneous memory requirements before changing pool limits.
5. Keep CPU-sampled salt storage explicit until random expansion is ported.
   `PublicMatrix` is only deterministic preprocessing: do not use it to share
   salts, hiding masks or witness buffers across private sessions.

Then continue witness/preprocessing construction, transcript/grinding/random
expansion, nonbinary and legacy wallet/API support, AMD/Metal conformance,
and complete-workload memory/throughput qualification in §9.4–§9.5. Strict
GPU-only admission remains closed.

### 9.17 Device-only PCS storage — 2026-10-07

`LATTICA_V2_GPU_PCS_DEVICE_ONLY=1` now removes commitment-time host LDE
matrices and prefixes from the selected binary cubic OpenCL prover. It
requires owned GPU lookup, quotient and opening evaluation, resident FRI,
and the existing resident commitment backend. Private proving also checks
that its opening consumer was selected before drawing randomness. Public
preprocessing can be constructed first and imported by later proof sessions.
**This is device-only polynomial storage, not complete GPU proving: salts,
random expansion, witness construction and transcript work remain on CPU.**

The LDE planner/executor distinguishes `HostPrefix(bits)` from `DeviceOnly`.
The latter skips `HostReadback` allocation, transfer, decoding and reorder;
it does not download and then discard matrices. Its host polynomial output
plan is zero, while device allocation limits and capture reservations remain
enforced. `ProverData::DeviceOnly` contains independent committed dimensions,
owned prefixes, the original host salts and a retained GPU tree. Generic
matrix access and legacy query interfaces reject it. The selected PCS also
rejects host quotient construction/commitment, domain evaluation and CPU
opening entry points instead of delegating to the upstream host prover.

The existing salt and hiding streams are unchanged. Remaining CPU staging
is separately admitted before draws: a conservative two input-sized buffers,
salt storage and pending auxiliary allocations must fit the caller's host
allowance. Invalid masks now reject before commitment salt draws as well as
inside the executor. Missing capture, wrong geometry, insufficient host
staging and GPU admission failures preserve subsequent CPU-reference
commitments and queried salts. Public preprocessing retains its own lifetime;
private matrices retain their original proof-session ownership. Salts and
hiding material are never promoted to `PublicMatrix`.

[Device-only PCS evidence](evidence/gpu-device-pcs-2026-10-07.json) records
**55 bounded checks: 93 Rust test cases**, plus **36 Python resource tests**
and successful CPU/GPU streaming builds. All 225 current source files,
archive contents, the release binary, runner and logs were hash-verified in
`gpu-device-pcs-20261007/run-01`. All 39 native checks ran serially on the
RTX 5080 Laptop GPU with 3 GiB RAM, zero swap, four CPU cores and a 180-second
limit per check; each drained to zero managed bytes and released its lease.

The commitment oracle covers 2, 32 and 4,096 source rows, multi-matrix and
multi-tile widths, both prior retention choices and public/private ownership.
Commitments download exactly their cap bytes. Queried values, salts and paths
match the CPU implementation, including duplicates and unsorted indices.
Host access rejects explicitly. Complete full/compact proofs match an
independently configured CPU reference byte-for-byte and verify through the
original upstream CPU PCS/extension adapter. Three fresh registered proofs
under each full/compact selection reuse preprocessing, restore private
allocation baselines and verify after GPU shutdown. Existing host-backed
proving, randomness, lookup, opening and FRI regressions also pass.

The 64-row fixture performs five device-only LDE commitments including
preprocessing, with **zero host LDE output/readback or reorder**. For the
four private commitments, the same-binary host-backed control reads back
4,456,448 bytes, and its compact control reads back 980,992 bytes; device-only
selection reads back zero in both cases. Final proof transfers remain:
12,648 claimed-value bytes, 483,328 initial PCS query-value bytes, and 71,704
FRI query/final-coefficient bytes, plus caps, paths and scalar control checks.
Opening/FRI vectors and initial query prefixes stay on GPU. These are small
fixture correctness and data-flow measurements, not throughput results.

Pool assignments validate and pin the new flag and all prerequisite
consumers. Reservations remain conservative: the preserved full workload
still adds 5,460,983,808 managed bytes, has an 838,860,800-byte largest
allocation and adds 1,105,596,416 host bytes. It remains rejected when these
reservations are combined with the existing phase allowance. Removing host
LDE copies alone does not qualify full-size GPU memory or justify increasing
worker concurrency.

Continue the remaining §9.4 sequence:

1. Compile recursive wire dependencies into a reusable bounded execution
   schedule; construct witness and deterministic preprocessing columns on
   GPU without changing AIR packing or registry identity. Compare wire/row
   values and preprocessing caps, then connect device traces to hiding and
   commitment without a host trace round trip. Cover wallet/batch trace and
   public-value arithmetic separately.
2. Port exact ChaCha20 expansion, field sampling, salts/hiding columns,
   transcript state transitions and grinding. Preserve fresh per-proof
   entropy, draw order, cancellation cleanup and CPU-reference challenges;
   final proof bytes and declared storage spill remain legitimate transfers.
3. Complete periodic inputs, legacy quadratic/nonbinary/final-polynomial
   support and actual wallet/C-ABI entry points. Reconcile the pending Mac
   source through its local commit, then qualify AMD OpenCL and Apple Metal.
4. Recompute simultaneous phase memory, qualify complete workloads and
   sustained delivered transactions per hour across pool workers, and only
   then consider strict GPU admission or higher concurrency.

`gpu-required` remains closed; no full-GPU or transaction-throughput claim
follows from this checkpoint. The implementation is still uncommitted on
`main`.

### 9.18 GPU witness and preprocessing primitives — 2026-10-07

Recursive execution now has bounded GPU primitives for every existing SSA
operation and for construction of the unchanged witness and deterministic
preprocessing columns. **These primitives are validated but are not yet
connected to registered proving.** `RegisteredProgram::prove_with_request`
still calls CPU `MachineAir::trace`; key generation still obtains CPU
`preprocessed_trace`. There is no new selection flag or resource-profile
change, and strict `gpu-required` admission remains closed.

`WitnessProgram` compiles immutable instruction, row and port metadata
into dependency waves. It explicitly includes `Bit` and `SelectHint`
execution inputs: their omission from `Op::reads()` is intentional for
AIR lookup semantics, but would be incorrect for execution scheduling.
Compilation validates definitions, hint geometry, dimensions and bounded
host metadata without evaluating private fields or creating dense host
preprocessing. A context-bound `PreparedWitness` uploads this public
metadata once and can serve fresh private proof sessions.

GPU kernels evaluate inputs, constants, scalar arithmetic and assertions,
inversion, selection, cubic multiplication/inversion, Poseidon and both
hints. Row kernels reproduce all packed columns and Poseidon checkpoints.
Successful execution returns a natural-order base-field `DeviceMatrix`;
only private/public inputs are uploaded and one eight-byte status is
downloaded. Deterministic preprocessing construction performs no transfers.
Private input, wire and status scratch is zero-filled and drained before
its reservations are released. Metal rejects these primitives explicitly.

[Witness evidence](evidence/gpu-witness-2026-10-07.json) records **63 passing
bounded checks and 103 Rust cases**, including 43 native checks on the
selected RTX 5080 Laptop GPU. Each check used 3 GiB RAM, zero swap, four
CPU cores and a 180-second limit; every native check released its lease
with zero managed bytes remaining. The wide-layout suite contributes
98 cases; the original eight-lane layout adds five. CPU/GPU streaming
builds passed. The 36 resource-test results are reused from §9.17, with
unchanged script hashes verified; those tests were not rerun here.
All 230 source files, archive contents, both binaries, runners and logs
were hash-verified in `gpu-witness-20261007/run-01` and `narrow-02`.

Conformance covers empty and public-only programs, all opcodes, large
field values, high-bit hints, computed selection tables, dependent hash
chains, partial packed rows and 33/64 public values. Six program shapes
per layout run in three fresh sessions and match CPU trace/preprocessing
values exactly. Each evaluation has zero metadata reupload, trace upload
or trace readback, and exactly eight status bytes. Invalid assertions,
inverses and hints match CPU `Unsatisfied`; count, canonicality, host
allowance, device geometry and ownership failures preserve allocation
baselines and reusable public state. Existing complete-proof commitment,
lookup, quotient, opening and FRI regressions also pass.

The first narrow build omitted `block-v2`, so its filter selected zero
tests and the runner rejected it. That attempt is preserved under
`run-01/narrow`; `narrow-02` corrects the feature set. No native arithmetic
ran in the failed attempt.

The next integration steps are to accept base-field device traces in
hiding commitments, introduce a real device-trace batch-prover interface,
and build deterministic preprocessing commitments/CommonData directly
from GPU columns. Public preprocessing must use an explicit trusted
interface; private traces, masks and salts must retain private ownership.
Preserve random draw order and admission before draws. Add immutable
selection, accurate capability/stage reporting and simultaneous memory
reservations before enabling the path in workers. Then continue the
wallet/public-value, randomness/transcript, portability and workload
qualification sequence in §9.17. This checkpoint establishes correctness
and data flow, not transaction throughput or a completed all-GPU prover.

The direct batch-prover handoff is now validated in §9.19. Registered
entry-point selection and worker resource admission follow in §9.20.

### 9.19 GPU witness-to-proof handoff — 2026-10-07

The adapted batch prover now accepts an explicit device main trace and
produces complete proofs from GPU-generated witness and preprocessing
columns. **This is an internal, validated proving interface; existing
`RegisteredProgram` callers still select CPU trace construction.** No
worker flag, resource profile or `gpu-required` admission has changed.
Random expansion, salts, transcript updates and grinding still use CPU
arithmetic. The work remains uncommitted on `main`.

`ProvingInstance::from_device` transfers ownership of a real device matrix
into the prover. It validates the AIR width, field, row order, domain and
session before commitment randomness; the selected route requires one
AIR and owned GPU lookup/quotient consumers. The main commitment consumes
the original trace, so its allocation can end before downstream stages
recover rows from retained prefixes. CPU callers use an explicit host
input variant. No placeholder host matrix is constructed.

The hiding commitment executor now accepts base-field main traces as
well as cubic lookup traces. Separate entry points enforce those field
contracts. Both preserve the reference row/column random draw order and
admit simultaneous inputs, samples, captures and transform buffers before
draws. `PreprocessingTrace` has a separate provenance: only immutable
compiled program metadata can produce it. A GPU kernel interleaves its
rows with zeros, and only those deterministic committed prefixes become
reusable public state. Private traces, masks and salt storage keep their
existing ownership. No hiding samples are drawn for preprocessing.

`machine::gpu_backend::prepare` compiles the actual execution program,
constructs its device preprocessing and builds the same single-table
`CommonData` used by trusted-cap verification. It does not call CPU
`preprocessed_trace`. Its prepared witness metadata can be reused across
fresh proof sessions. Debug builds explicitly download admitted main
traces and run the original CPU constraint and lookup audits; release
device proving does not make that host trace copy.

[Handoff evidence](evidence/gpu-witness-handoff-2026-10-07.json) records
**119 passing Rust cases across 79 bounded checks**, including 57 native
checks. The wide release build contributes 105 cases, the original
eight-lane release build 12, and debug proof/audit checks two. All ran with
the existing 3 GiB RAM, zero-swap, four-core and 180-second limits. Every
native check released its lease with zero managed bytes remaining.
CPU/GPU streaming builds passed. All 233 source files, archive contents,
three binaries, runners and logs were hash-verified in
`gpu-witness-handoff-20261007/run-01`. The unchanged 36 resource-test
results are reused from §9.17, not rerun or counted as new tests.

The main commitment oracle covers 1–8,192 original rows, widths that
cross column-tile boundaries and repeated commitments. CPU matrices,
caps, paths, salts and recovered original rows match. Wrong domains,
field layouts, row order, empty inputs and foreign sessions reject;
subsequent commitments preserve CPU hiding/salt streams. Deterministic
preprocessing imports into fresh sessions, while private commitments
reject foreign ownership.

Full and compact 64-row device-only proofs match independent CPU
reference bytes and verify through the original upstream CPU
PCS/extension adapter. A second fixture exercises every opcode, dependent
hashes and hints, cubic inverses and 33 public values in three fresh
sessions per storage selection and layout. Each proof matches CPU bytes,
restores the private allocation baseline, and verifies after GPU shutdown.
Debug versions of both fixtures also pass their CPU constraint audits.
The earlier commitment, lookup, quotient, opening, FRI, registered CPU
and registered GPU regressions remain passing.

In the 64-row wide fixture, witness execution uploads 16 input bytes and
downloads one eight-byte status. Program metadata is not reuploaded;
the trace and preprocessing matrices have zero upload/readback, and
device-only commitment LDE readback remains zero. The main hiding samples
still upload 52,224 bytes. The all-opcode fixture uploads 272 input bytes
and reads eight status bytes per proof; its nine dependency waves cover
eight wide-layout rows or 16 original-layout rows. Debug audits explicitly
read an additional 6,016 main-trace bytes in the wide fixture. These are
correctness/data-flow measurements, not throughput results.

The next activation work is concrete:

1. Bind the prepared witness and preprocessing state to `RegisteredProgram`
   under immutable, explicit selection. Create its proving configuration
   and private session before witness execution, and use the device-input
   adapter above. Preserve the registered identity and CPU verifier.
2. Report the actual witness/preprocessing backends and reject unsupported
   device configurations before private work. Keep debug CPU audits
   explicit. Remaining CPU stages still prevent strict GPU-only admission.
3. Extend worker manifests and phase reservations for compiled metadata,
   source-program storage, private inputs/wires/traces, preprocessing and
   overlapping commitments. Include largest allocations and host staging;
   keep full-size admission closed until the aggregate model fits.
4. Continue wallet/batch/public-value arithmetic, exact random expansion,
   transcript/grinding, legacy and nonbinary coverage, then AMD/Metal and
   sustained complete-workload qualification from §9.17. The internal
   handoff alone does not justify higher pool concurrency or a transaction
   throughput claim.

### 9.20 Registered GPU witness selection and worker reservations — 2026-10-07

`RegisteredProgram` can now construct recursive witness and preprocessing
columns on GPU and pass the device trace directly into complete proving.
Select `LATTICA_V2_GPU_WITNESS=1` through the explicit research initializer.
The flag defaults off, is immutable after initialization, and requires OpenCL
hashing, resident LDE, quotient fusion, owned GPU quotient/lookup/openings,
resident binary FRI and device-only PCS. Raw environment variables alone do
not activate the library's research modes. **This remains a hybrid prover:**
random expansion, salts, transcript/grinding and wallet/public-value
arithmetic still use CPU. `gpu-required` remains rejected.

Registration retains reusable public witness metadata and GPU preprocessing.
The registered identity and preprocessing cap match independent upstream CPU
setup. Each proof creates fresh entropy, configuration and a private device
session before witness construction. Input counts reject before uploads;
invalid witnesses return the existing `Unsatisfied` error and release private
scratch. The prepared program survives those failures and subsequent fresh
sessions. Stage reports identify witness execution as OpenCL and preprocessing
as Mixed, with incomplete all-GPU coverage recorded explicitly.

Workers now assign `gpu_witness`, `witness_bounds` and `witness_reservation`.
Rust and Python use matching checked arithmetic for source-program vector
capacities, compiled public metadata, private inputs/wires/traces,
preprocessing, hiding samples and debug readback. Public program cache entries
increase both host and device reservations. These costs are **additive** to
existing quotient, commitment, opening/FRI and simultaneous phase allowances;
they do not reduce an existing reservation or increase concurrency. The
launcher pins selection from the assignment, overriding inherited settings.
The Rust initializer checks assignment consistency before freezing witness
selection or creating the GPU context; registration checks actual program bounds before
uploading metadata. No existing workload profile was enabled or relaxed.

[Registered-witness evidence](evidence/gpu-witness-registered-2026-10-07.json)
records **64 passing Rust cases across 27 bounded checks**, including
**19 native GPU checks**, plus **40 passing Python resource tests**. Wide
release contributes 38 Rust cases, the original eight-lane release 24, and
debug two. Rust checks used 3 GiB RAM, zero swap, four CPU cores and a
180-second limit; every native check used the selected RTX 5080 Laptop GPU
and released its lease with zero managed bytes remaining. CPU-only and GPU
streaming builds passed. All 235 source files, source archive contents,
three binaries, runners and logs were hash-verified in
`gpu-witness-registered-20261007/run-01`.

Full and compact registration tests each produce three fresh proofs in both
layouts and in the debug build. The original upstream CPU PCS verifies the
serialized proofs after GPU shutdown and rejects changed public values.
Policy, input-count and worker-assignment failures reject without new GPU
uploads or allocations. Invalid witness execution restores the private
allocation baseline. Regressions retain exact CPU proof-byte comparisons for
the internal device-input adapter, every-opcode fresh-session reuse, and both
CPU/default and CPU-trace/GPU-PCS registered paths. Debug proofs pass explicit
CPU constraint/lookup audits. The broader §9.19 checks remain dated evidence;
they are not counted as rerun here.

The 64-row wide fixture has 64 public and 64 private inputs. Its two witness
waves upload 1,024 input bytes, download eight status bytes and perform no
metadata reupload or release trace upload/readback. Host commitment LDE
output/reorder remains zero. Debug audits separately read 48,128 main-trace
bytes per proof. The additional witness reservation is 206,024 managed bytes
and 1,407,392 host bytes; it is not the complete proof's memory requirement.
The initial Python golden expectation omitted the eight-byte status; the
test expectation was corrected and its failed log is preserved. No native
check failed in this checkpoint.

The remaining implementation sequence is:

1. Add session-owned GPU ChaCha20 expansion, exact field sampling and
   salt/hiding storage. Preserve independent fresh per-proof streams,
   reference draw/clone order and admission before draws. Compare streams,
   rejection-sampling edges, commitment caps and complete proof bytes;
   scrub private storage on completion, cancellation and failure.
2. Move transcript state, challenge conversion and grinding into the device
   session. Express commitment/challenge dependencies explicitly and retain
   reference state transitions, tiny FRI rounds and query indices. CPU
   entropy acquisition, scheduling, serialization and independent
   verification remain outside proving arithmetic.
3. Port wallet/batch trace and proof-public-value arithmetic, periodic
   columns, the legacy quadratic extension, nonbinary FRI and general final
   polynomials. Connect the actual maintained Rust and C-ABI entry points
   through the same explicit policy while preserving each proof family.
4. Reconcile the pending Apple source through its next local Mac commit,
   then implement/qualify the remaining Metal and AMD OpenCL operations.
   Record capabilities by backend, device, driver and proof profile;
   unsupported combinations must reject before private proving work.
5. Qualify full-size simultaneous memory and bounded storage-only spill,
   cancellation/retry behavior and sustained delivered transactions per
   hour across persistent workers. Cache only immutable public setup and
   schedule admitted complete proofs per GPU. Enable strict GPU admission
   only when every required stage has measured device coverage.

The implementation remains uncommitted on `main`. Registered witness
selection completes this integration step; it does not establish full GPU
proving, a qualified full-size worker campaign or a throughput improvement.

### 9.21 GPU random streams and hiding-buffer handoff — 2026-10-07

The device runtime now expands ChaCha20 streams and samples canonical
Goldilocks fields on GPU. Generated samples pass directly into main-trace,
cubic lookup and quotient hiding commitments, where matrices, caps, salts
and authentication paths match the CPU reference. **These are internal
interfaces; registered proofs still select CPU random expansion.** No new
runtime flag, worker reservation or workload profile was enabled. Salts,
the standalone randomization polynomial, transcript and grinding still
follow their existing host paths.

`DeviceRandom` consumes the source `ChaCha20Rng` and imports its abstract
seed, stream identifier and u32-word position without host expansion. Its
clone shares a serialized cursor rather than replaying it. The kernel uses
the original 64-bit block-counter/64-bit stream layout of `rand_chacha`
0.10.0. Sampling matches `p3-goldilocks` 0.6.1: reject each noncanonical
64-bit candidate, preserve candidate order and draw again. A GPU count,
exclusive-offset and scatter pass compacts accepted samples; no field
reduction substitutes for rejection. Host work consists of counters,
allocation, command submission and an eight-byte batch status.

Each call admits its complete output and scratch before draws. Output is
bounded to 2^28 field words; candidate batches contain at most 2^20 words
and compaction tiles contain 256. The stream rejects counter wrap and
more than 1,024 additional rejected candidates. Any failure after execution
starts makes every shared handle unusable, requiring a fresh attempt.
Admission failures leave the cursor untouched. Device keys, candidates,
counters and generated sample buffers are scrubbed and drained before
their reservations are released; explicit host seed-upload staging is also
cleared. The opaque `RandomWords` type enforces session ownership and
cannot be promoted to public preprocessing. Metal rejects these operations
explicitly.

`prepare_trace_commit_with_random` and
`prepare_quotient_commit_with_random` consume these buffers while retaining
their cleanup ownership. Existing host-sample interfaces still work. The
new handoff performs no sample upload or readback; the commitment oracle
tests separately use the existing host LDE output and bounded readback
interfaces to compare results. This is not an assertion that a complete
proof now avoids every host random-data boundary.

[Random-stream evidence](evidence/gpu-random-2026-10-07.json) records
**28 passing Rust cases across 27 bounded checks**, including **22 native
GPU checks**. Wide release contributes 17 cases, the original eight-lane
release seven, and debug four. Each Rust check used 3 GiB RAM, zero swap,
four CPU cores and a 180-second limit. Every native check ran on the
selected RTX 5080 Laptop GPU, drained to zero managed bytes and released
its lease. CPU-only and GPU streaming builds passed. All 239 source files,
source archive contents, three binaries, runners and logs were
hash-verified in `gpu-random-20261007/run-01`. The unchanged 40 Python
resource-test results from §9.20 are explicitly reused with script/log
hash verification; they were not rerun or counted as new tests.

Conformance covers 63 seed/stream/position combinations with five successive
draws alternating shared handles. Tests include all-zero, all-one and
incrementing seeds, odd positions, ChaCha block/buffer boundaries, 32-bit
block-counter carry and near exhaustion. A separate 1,048,833-field case
crosses the batch boundary: one 32-byte seed upload and 16 bytes of status
readback precede the explicit test-oracle readback. Forced rejection tests
cover `p-1`, `p`, `p+1`, `u64::MAX`, zero and one, partial tiles and entirely
rejected tiles. Shared-stream commitments exercise 1–8,192 trace rows,
base/cubic columns and 2/4/16 quotient chunks. Wrong dimensions/ownership,
allocation rejection, injected execution failure and explicit scrubbing
all pass. Existing full/compact proof-byte, CPU-verification and registered
debug-audit regressions also pass with their existing CPU random streams.

The next integration must complete all consumers of each stream together:

1. Give the standalone randomization polynomial an owned GPU matrix/LDE
   interface. It shares the witness-hiding stream, so routing only trace
   samples to GPU would leave later draws out of sync.
2. Retain GPU-generated salts through LDE commitments, FRI and final query
   gathers. Deterministic public preprocessing salts need a separate
   trusted ownership path so reusable setup does not promote private
   random material.
3. Preserve the MMCS's construction-time RNG snapshot semantics and its
   active shared-stream semantics. Keep witness, quotient and salt streams
   independent, with fresh entropy for every proof attempt.
4. Add immutable selection, accurate stage reporting and simultaneous
   worker reservations, including sampling scratch, before activating the
   complete path. Require exact controlled CPU proof bytes, fresh proof
   verification, cancellation/failure cleanup and unchanged profile
   identities in both layouts.

Then continue transcript/grinding, wallet and legacy-profile coverage,
backend portability and full-size throughput qualification from §9.20.
This checkpoint remains uncommitted on `main` and does not establish an
all-GPU prover or a transaction-throughput improvement.

### 9.22 GPU randomization polynomials and retained salts — 2026-10-07

GPU-generated field samples can now remain in private device matrices for the
standalone randomization polynomial and commitment salts. Natural-order
evaluations feed the existing LDE executor through an inverse NTT, GPU
normalization/coset scaling and forward transform. The input polynomial is
already random, so this path neither interleaves trace rows nor appends hiding
columns. Its retained prefixes, commitments and final query proofs match the
CPU path, including non-unit source cosets and multiple matrices.

Trace, cubic lookup, quotient and randomization commitments can consume salt
column bands directly from GPU storage. Device-only prover data now retains
either the existing host salts or private device salts. The device variant
requires four base-field columns, matching committed height, bit-reversed row
order, unit shift and the owning proof session. Binary cubic FRI also accepts
device salts. Final proof assembly gathers only the queried salt rows; no full
salt matrix is downloaded. Existing host-salt proof paths remain supported.

Generated matrices share a cleanup guard across private aliases. Dropping the
original handle preserves its aliases; dropping the last alias scrubs and drains
the allocation before releasing its reservation. Direct promotion to public
preprocessing rejects, and the new salted trace interface rejects reusable
preprocessing inputs. **Trusted GPU salts for public preprocessing remain a
separate, unfinished integration step.** Existing sampling bounds still apply:
at most 2^28 output fields per request, with matrix geometry limited to 2^25 rows
and 4,096 columns. Evaluation commitments currently require 2..2^25 natural-order
base-field rows and the registered profile's blowup.

These interfaces eliminate private sample uploads and host polynomial output
for the covered handoffs. Existing LDE setup still uploads public forward and
inverse NTT root tables: 16 times log2(committed height) bytes. Public caps also
return to the host. A zero host polynomial-output allowance is valid for
device-only commitments; final query assembly has its own checked host allowance.
GPU random generation retains the seed/status boundaries recorded in §9.21.

[Random-storage evidence](evidence/gpu-random-storage-2026-10-07.json) records
**34 passing Rust cases across 32 bounded checks**, including **28 native GPU
checks**. Wide release contributes 22 cases, original eight-lane release eight,
and debug four. All checks use the existing 3 GiB, zero-swap, four-core and
180-second service bounds. Every native check ran on the selected RTX 5080
Laptop GPU and released its lease with zero managed bytes remaining. CPU-only
and GPU streaming builds pass. All 242 source files, archive contents, three
binaries, runners and logs are hash-verified in
`gpu-random-storage-20261007/run-02`. The unchanged 40 Python resource-test
results from §9.20 are reused with script/log hash verification, not rerun or
counted as new tests.

Conformance covers retained prefix words, caps, queried values/salts and
authentication paths; base/cubic traces at heights 1/8/256/8,192 alternate with
two randomization polynomials through shared stream handles. Separate cases
cover evaluation widths through 65, cosets 1/7/11/p-1, 2/4/16 quotient chunks,
binary FRI layers down to a single committed row, allocation rejection,
malformed salt geometry, foreign sessions and private preprocessing rejection.
Existing full/compact registered proofs, host-salt queries, fresh-session reuse
and debug CPU audits still pass. Two initial test expectations were corrected:
one counted public NTT constants as private uploads; the other expected a zero
host polynomial-output allowance to reject. Their original binary, source
archive and failed logs remain in `run-01`; neither was an arithmetic mismatch.

**Registered proofs still select CPU random generation.** Before activating GPU
randomness, finish trusted public preprocessing salts, preserve MMCS
construction-time RNG snapshots and wire every consumer of each active stream
together. Then add immutable runtime selection, actual stage reporting,
simultaneous worker memory reservations and fresh complete-proof conformance.
GPU transcript/grinding, wallet/batch/public-value arithmetic, remaining proof
profiles, maintained entry points, AMD/Metal coverage and sustained full-size
pool throughput qualification remain in the sequence from §9.20. These changes
remain uncommitted on `main`; this checkpoint establishes neither complete GPU
proving nor a transaction-throughput improvement.

### 9.23 Trusted public GPU salts and RNG snapshots — 2026-10-07

The device runtime now distinguishes construction snapshots from active stream
clones. `DeviceRandom::snapshot` copies the current position into an independent
cursor while sharing the immutable device key. It performs no key readback,
upload or device allocation. Ordinary `Clone` continues to share the active
cursor. The key is scrubbed only after its final owner is dropped; a failed
stream cannot create a new snapshot. These primitives support the remaining
private MMCS stream integration without changing its selection yet.

Public preprocessing now has a separate salt type and an internal path through
complete device key generation. Only a stream constructed with the fixed public
zero seed can produce `PublicSalts`; arbitrary private samples cannot become
reusable public salt storage. Public salts retain their cleanup guard and GPU
context, and can be imported into fresh proof sessions in that context. Imported
aliases cannot cross private session boundaries or be recast as preprocessing
traces. Both the salts and polynomial prefixes survive the original setup
session, and only queried salt rows are gathered for the proof.

The preprocessing configuration factory records this public purpose explicitly.
Supplying the same zero bytes to a private constructor does not grant the public
capability. The internal `with_gpu_preprocessing_salts` selector requires trusted
device-only setup and its GPU consumers, and must run before configuration
cloning or work. Its configuration rejects private proving and host preprocessing
inputs; only compiler-owned preprocessing traces enter the public salt path.
Active PCS clones share the complete public salt stream and advance it together.

Batch salt generation is serialized across shared handles. Admission checks all
retained salt outputs, pending trace parameters and sampling scratch before
drawing. Commitment planning also includes the complete salt storage alongside
the retained prefixes and LDE workspace. These are preflight snapshots, not
worker reservations; execution rechecks allocations. A failed partial batch or
commitment failure after draws retires the shared stream. Public batches are
bounded to 256 matrices with four columns and a power-of-two height of 1..2^25.

[Public-salt evidence](evidence/gpu-public-salts-2026-10-07.json) records **49
passing Rust cases across 34 bounded checks**, including **29 native GPU checks**.
Wide release contributes 36 cases, original eight-lane release eight, and debug
five. Each check used 3 GiB RAM, zero swap, four CPU cores and a 180-second
limit. All native checks used the selected RTX 5080 Laptop GPU and released
its lease with zero managed bytes remaining. CPU-only and GPU streaming builds
pass. All 243 source files, archive contents, three binaries, runners and logs
are hash-verified in `gpu-public-salts-20261007/run-01`. The unchanged 40 Python
resource-test results from §9.20 are reused with script/log hash verification;
they were not rerun or counted as new tests. No native check failed.

Snapshots match CPU streams at ordinary, odd-word and 32-bit block-counter carry
positions, including after earlier draws and after the original handles are
dropped. Public sample batches match the fixed CPU stream and preserve storage
through fresh-session imports. Selection, shape and memory rejection checks
preserve the next reference draws. Two successive preprocessing commits through
shared PCS handles produce the corresponding distinct CPU keys and query proofs.
Full and compact public-salt cases each produce three fresh all-opcode proofs in
both layouts and in debug: exact CPU proof bytes match, the original CPU PCS
verifies after GPU shutdown, and changed public values reject. Existing private
salt paths, registered witness proofs, host-salt queries and FRI regressions pass.

**Registered proving still selects CPU randomness, including public salts.**
The next step is to connect private input/FRI salt streams, witness
hiding/randomization and quotient masks under one immutable GPU randomness
selection, using the required construction snapshots and shared active streams.
Add actual stage reporting, simultaneous worker memory reservations and fresh
registered complete-proof conformance before activating that selection. The
transcript/grinding, remaining proof families, backend coverage and full-size
pool qualification work from §9.20 remains. This checkpoint is uncommitted on
`main` and does not establish complete GPU proving or improved transaction
throughput.

### 9.24 Private GPU randomness in complete proofs — 2026-10-07

The internal resident PCS can now select GPU randomness for all four private
protocol streams together: input commitment salts, FRI salts, witness
hiding/randomization, and quotient samples/masks. `ProofRng` preserves explicit
construction snapshots separately from shared active cursors. Selection imports
four stream states with 128 seed-upload bytes, must precede PCS cloning or proof
work, and requires the owned device consumers and independent quotient stream.
Identical selection does not reseed. Selected streams reject CPU expansion;
there is no fallback to host randomness. Trusted public preprocessing salts use
the separate setup configuration from §9.23, which cannot prove private inputs.

Base main traces, cubic lookup traces, standalone randomization polynomials,
quotient random columns/masks, input salts, and FRI salts now consume their
private samples directly on the device. Complete-proof logs identify each of
these consumers and report zero sample upload/readback. CPU/default proving
remains compatible, and no environment switch or registered runtime activation
was added in this checkpoint. The transcript and challenge generation still
run on the CPU.

All four streams share a failure state. Stage guards retire that state if work
fails after admission, and an enclosing guard now covers the entire owned
`prove_batch` call. This includes failures between stages, after an earlier
stage has successfully consumed randomness. A failed full proof requires a
fresh configuration; active clones and construction snapshots cannot resume
its streams. A regression removes backing preprocessing data while retaining
valid metadata: the main commitment draws hiding samples and salts, lookup
execution then aborts, and both the original configuration and its active clone
reject further commitments without drawing. Direct stage admission failures
before draws remain retryable outside a full proof attempt.

Admission accounts for retained sample outputs, pending buffers, salts, and
commitment workspace before draws. A random preflight accepts at most 512
requests; private salt batches retain the 256-matrix, four-column, 1..2^25-row
bounds. These checks are snapshots, not simultaneous worker reservations.
Execution rechecks allocations, and final owners scrub private storage and
release it. Registered worker reservations are unchanged.

[Private-randomness evidence](evidence/gpu-random-integrated-2026-10-07.json)
records **72 passing Rust cases across 44 bounded checks**, including **36
native GPU checks**. Wide release contributes 40 cases, eight-lane release 24,
and debug eight. Every check uses 3 GiB RAM, zero swap, four CPU cores and a
180-second limit. All native checks used the selected RTX 5080 Laptop GPU and
released its lease with zero managed bytes remaining. CPU-only and GPU
streaming builds pass. All 245 source files, archive members, three binaries,
runners, and logs are hash-verified in
`gpu-random-integrated-20261007/run-02`. The earlier passing wide run before
whole-proof retirement remains in `run-01` and is not counted here. The
unchanged 40 Python resource cases are reused from §9.20 with script and log
hash verification, not rerun or counted as new tests.

Each full/compact complete-proof case produces three fresh all-opcode proofs
with exact CPU proof bytes and reusable public preprocessing keys, in both
layouts and debug. The upstream CPU PCS verifies after GPU shutdown and rejects
changed public values. All four private streams are imported once per proof
and make GPU draws. Logs confirm three calls each for base hiding, cubic hiding,
quotient randomness, and randomization, plus 12 FRI salt calls in wide/debug or
15 in the taller eight-lane fixture. Debug cases retain three explicit main
trace readbacks for CPU constraint audits. Active-clone, admission, failure,
public-salt, registered-witness, CPU-default, query, FRI, and PCS checks pass.

**Registered proving still selects CPU randomness.** The next step is immutable
registered selection with actual stage reporting and simultaneous worker
memory reservations, followed by fresh registered complete-proof conformance.
Then continue with GPU transcript/challenge conversion/grinding; wallet,
batch and public-value arithmetic and the remaining proof profiles; maintained
Rust/C-ABI entry points; AMD/Metal qualification and the pending local Mac
source commit; and full-size memory, cancellation/retry and sustained delivered
transactions/hour across the worker pool. These changes remain uncommitted on
`main`. This checkpoint establishes neither complete GPU proving nor a measured
transaction-throughput improvement.

### 9.25 Registered GPU randomness and worker admission — 2026-10-07

`LATTICA_V2_GPU_RANDOMNESS=1` now selects private GPU randomness and trusted
public preprocessing salts in registered execution proving. It requires the
owned device-only OpenCL witness/PCS path from §9.20, including independent
quotient fusion, lookup, openings, and resident FRI. The selector accepts only
ASCII `0` or `1`, defaults to CPU randomness, and rejects unsupported
combinations. All GPU protocol switches are recorded together in one immutable
selection, so a failed reinitialization cannot partially change the mode.

The registered configuration factories activate the four private streams, or
the separate public setup stream, before cloning or proof work. Each private
attempt receives fresh entropy. Public salts preserve the CPU preprocessing
cap and registry identity and remain reusable across fresh proof sessions.
The failure retirement from §9.24 continues to cover the whole private proof;
there is no CPU fallback after GPU randomness is selected.

Worker profiles select `geometry.gpu_randomness` explicitly. The resource
planner derives `randomness_bounds` and `randomness_reservation`, and the
launcher writes the assigned environment value even if the parent environment
requests a different mode. Rust checks the assignment at mode selection,
before registration/key imports and activation, and against actual proof
dimensions before main hiding and salt draws. Invalid assignments reject before
device uploads; valid assigned configurations complete registered proofs.

The new reservation is additional to existing phase, owned PCS and witness
reservations. It includes retained main/lookup/randomization/quotient salts,
binary FRI salt layers, all cached public salts, simultaneous sample outputs,
sampling scratch, five stream keys and 1 MiB of host overhead. No existing
host reservation is reduced. Peak single-allocation checks remain separate
from aggregate managed-memory checks. This model assumes one active proof
attempt per assignment and supports up to 12 cached public programs. Bounds
are at most 2^20 base rows, 4096 columns per matrix, 2^25 salt rows, 2^28 words
per sample request, and 2/4/8/16 quotient chunks. Worker accounting remains
distinct from device preflight snapshots and execution-time allocation checks.

Rust and Python share checked fixtures for these calculations. A 16-row fixture
adds 398,824 managed bytes, a 16,448-byte largest allocation and 1 MiB of host
memory. A 16,384-row fixture with 12 cached programs adds 584,253,672 managed
bytes and a 16 MiB largest allocation. These are admission calculations, not
measurements of a full-size workload. Tests reject aggregate oversubscription,
malformed bounds, insufficient reservations, inherited mode changes, and proof
dimensions that exceed the assignment, including excessive quotient chunk
height despite a smaller total quotient.

The proving report now distinguishes `randomness` from `hiding`. The selected
capabilities identify both as OpenCL, and randomness observations use completed
sampler requests and actual GPU event time. `device_ns` is separate from
inclusive host wall time; an opaque whole-proof timer is never reported as
sampler time. Observation guards also report samples completed before a later
proof abort. Reports still identify the CPU transcript/grinding and other
mixed stages, and continue to report incomplete stage coverage. `GpuRequired`
does not admit the complete prover yet.

[Registered-randomness evidence](evidence/gpu-random-registered-2026-10-07.json)
records **101 passing Rust cases across 60 bounded checks**, including **48
native GPU checks**, plus **44 rerun Python resource cases**. Wide release
contributes 56 Rust cases, eight-lane release 31, and debug 14. Every check uses
3 GiB RAM, zero swap, four CPU cores and a 180-second limit. All native runs
used the selected RTX 5080 Laptop GPU and released its lease with zero managed
bytes remaining. CPU-only and GPU streaming builds pass. All 246 source files,
archive members, three binaries, runners and logs are hash-verified in
`gpu-random-registered-20261007/run-02`; the initial wide run remains preserved
in `run-01` and is not counted here.

Full/compact registered cases each produce three fresh proofs in both layouts
and debug, retain CPU registry identity, verify with the upstream CPU PCS after
GPU shutdown, and reject changed public values. Each case reports one public
salt sampling call and 31 private sampling calls per proof; the verifier
matches reported counts and device times to the actual kernel logs. Debug
cases retain explicit CPU main-trace audits. Existing internal all-opcode
proofs still match exact CPU proof bytes. The post-main abort cases report
their two completed sampler calls and retire both active clones. CPU randomness,
worker admission, query, FRI, and nine enabled policy/reporting unit cases pass;
the latter suite's production-strength CPU wallet proof remains explicitly
ignored and is not counted.

The next implementation step is GPU transcript state, challenge conversion and
grinding. Wallet/batch/public-value and registry arithmetic, remaining proof
profiles, maintained Rust/C-ABI entry points, AMD/Metal qualification, the
pending local Mac source commit, and full-size cancellation/retry and sustained
delivered transactions/hour remain. This checkpoint is uncommitted on `main`
and does not establish complete GPU proving or a throughput improvement.

### 9.26 GPU transcript and grinding primitives — 2026-10-07

The bounded OpenCL engine now has device-owned Poseidon2 transcript state in
`gpu_hash/engine/device/transcript.rs` and `transcript_kernels.rs`. These are
internal primitives; complete and registered proofs still select the CPU
challenger. The public `config::Challenger` alias, proof encoding, verifier,
protocol parameters and registered capability reports are unchanged.

The kernels reproduce the pinned `p3-challenger 0.6.1` width-eight, rate-four
duplex: overwrite absorption, capacity length tags, zero padding only for
nonempty absorption, and reverse output sampling. State stays in an 18-word
(144-byte) device allocation. Observe/sample calls accept at most 4,096 fields;
only public input words, canonical challenges and masked query indices cross
the host boundary. On the tested 64-bit host, sampling accepts 0..63 bits.
Zero-bit sampling consumes a field; zero-bit grinding leaves the transcript
unchanged.

Nonzero grinding evaluates candidates in parallel, reduces to the smallest
valid witness, rechecks it and advances the real transcript on GPU. It supports
up to 20 bits, including the maintained 16-bit profile, and searches at most
2^26 candidates in batches of 65,536. Candidate, reduction and status scratch
total 526,352 bytes; each batch returns a 16-byte witness/status record. Budget
exhaustion explicitly fails the attempt. There is no CPU arithmetic fallback.
CPU grinding can select a different valid witness under parallel scheduling;
deterministic comparisons therefore use a single-thread upstream CPU oracle.

Snapshots copy device state independently and share failure retirement. An
execution error or unwind prevents further use of every related snapshot;
separately created transcripts remain usable. Admission failures before
execution leave the state available. Allocation checks include simultaneous
scratch and the largest single allocation. Private storage is scrubbed on
drop, and queue fences cover host transfers and temporary allocations.
Session counters record completed observations, samples, grinding batches,
public readback bytes and GPU event times.

[Transcript evidence](evidence/gpu-transcript-2026-10-07.json) records **48
passing Rust cases across 31 bounded checks**, including **27 native GPU
checks**. Wide release contributes 30 cases; eight-lane release and debug each
contribute nine. Native checks run serially on the selected RTX 5080 Laptop GPU
with 3 GiB RAM, zero swap, four CPU cores and a 180-second limit per check.
Every native check releases the lease with zero managed bytes. CPU-only and
GPU streaming builds pass. The 246 source files, source archive, three test
binaries, runners and logs are hash-verified in
`gpu-transcript-20261007/run-01`.

The new checks cover empty/full/partial absorption, length tags, base,
quadratic and cubic samples, query bit masks, independent snapshots, admission,
execution failure, unwind, cleanup and bounded search exhaustion. Grinding
matches the deterministic CPU witness, passes upstream `check_witness`, and
produces identical subsequent challenges. Uneven small batches test reduction
and continuation. Existing full/compact registered randomness proofs pass in
both layouts and debug; wide internal exact-proof, randomness failure, query,
FRI and PCS regressions also pass. Resource scripts were unchanged and their
Python tests were not rerun for this checkpoint.

The next integration sequence is:

1. Introduce a block-v2 challenger adapter with CPU and device implementations,
   retaining the public root challenger used by wallets and legacy callers.
   Start device state before the first transcript observation and route
   `BatchTranscript`, PCS openings and resident FRI through the same instance.
   Couple transcript retirement to the complete proof attempt, including
   failures outside transcript operations.
2. Establish full and compact owned-proof conformance with fixed randomness and
   a single-thread CPU transcript oracle. Check exact proof bytes, unchanged
   registry identity and upstream CPU verification after GPU shutdown, including
   rejection of altered public values. Keep unsupported profiles explicit.
3. Add immutable registered transcript selection to the existing `GpuSelection`,
   actual transcript/grinding stage observations and additive worker reservations
   for live transcript snapshots, challenge outputs and grinding scratch.
   Validate assignment bounds before activation and rerun registered complete
   proofs in both layouts and debug before reporting GPU stage coverage.

Wallet/batch/public-value and registry arithmetic, remaining proof profiles,
maintained Rust/C-ABI entry points, AMD/Metal qualification, the pending local
Mac source commit, and full-size cancellation/retry and sustained delivered
transactions/hour remain. This checkpoint is uncommitted on `main` and does
not establish complete GPU proving or a throughput improvement.

### 9.27 GPU transcripts in complete owned proofs — 2026-10-07

Block-v2 now has a `CandidateChallenger` adapter in `challenger.rs`. Its CPU
default delegates the upstream observation, sampling and grinding traits. Its
explicit device implementation starts before the first batch metadata binding
and retains GPU state through main/preprocessing commitments, lookup challenges,
quotient/randomization commitments, claimed openings and resident FRI. The root
`config::Challenger` used by wallets and legacy callers is unchanged, as are
the maintained C-ABI source, protocol parameters and proof encoding.

The internal `CandidatePcs::gpu_challenger()` constructor binds the challenger
to the proof's existing device session. It requires private GPU randomness and
the owned OpenCL witness/PCS consumers. It rejects public setup and host PCS
configurations. The prover rejects a challenger from another proof session
before any private draws or proof uploads. This checkpoint adds no registered
runtime switch: registered factories continue to select CPU transcripts.

Observations use bounded 4,096-word staging, with chunk boundaries preserving
pending sponge inputs. Extension coefficients are sampled together on GPU and
assembled into their existing Rust representation. Resident FRI samples all
128 query indices in one GPU call. Its log records the actual transcript
backend. Independent device snapshots preserve upstream clone semantics while
sharing failure retirement.

Whole-proof guards now cover transcript state as well as all four private
random streams. A failure after main commitment retires related transcript and
RNG clones, including failures outside transcript operations. The randomness
guard starts before the initial challenger snapshot, so failure to initialize
that snapshot also retires the random group. Trait operations fail explicitly
without CPU fallback, including admission failures after an earlier observation
chunk. Separately constructed attempts remain usable.

[Integrated-transcript evidence](evidence/gpu-transcript-integrated-2026-10-07.json)
records **81 passing Rust cases across 50 bounded checks**, including **41 native
GPU checks**. Wide release contributes 49 cases; eight-lane release and debug
each contribute 16. Full and compact cases each prove three statements in fresh
sessions in every build variant: **18 complete GPU-transcript proofs** match
exact single-thread CPU proof bytes. Public preprocessing keys remain reusable.
The original upstream CPU PCS and root challenger verify the serialized proofs
after GPU shutdown and reject changed public values. Debug retains explicit
CPU trace audits.

The matrix also covers CPU trait and pending-state compatibility, GPU adapter
clones and retirement, foreign-session admission, failed initial snapshots,
post-main proof aborts, transcript primitives, and existing registered
randomness, CPU, opening/query, FRI and PCS paths. The nine enabled proving
policy/reporting tests pass; the production-strength CPU wallet proof remains
explicitly ignored. CPU-only and GPU streaming builds pass. Resource scripts
were unchanged and their Python tests were not rerun.

Every native check ran serially on the selected RTX 5080 Laptop GPU with 3 GiB
RAM, zero swap, four CPU cores and a 180-second per-check limit, and released
its lease with zero managed bytes. All 248 source/configuration files, archive
members, three test binaries, runners and logs are hash-verified in
`gpu-transcript-integrated-20261007/run-02`. The initial CPU comparison in
`run-01` used parallel grinding on one side; the corrected comparison uses the
same single-thread oracle on both sides. That initial result and six GPU pilot
checks remain preserved and are excluded from the final totals.

The next work is to remove remaining derived scalar arithmetic from the owned
prover, including lookup bus-prefix derivation in upstream
`BatchTranscript::sample_perm_challenges` and domain next-point multiplication
when constructing opening points. Then add immutable registered transcript
selection, actual transcript/grinding stage observations and additive worker
reservations for live snapshots, sample buffers and grinding scratch, with
registered full/compact conformance before activation.

Wallet/batch/public-value and registry arithmetic, remaining proof profiles,
maintained Rust/C-ABI proving routes, AMD/Metal qualification, the pending local
Mac source commit, and full-size memory, cancellation/retry and sustained
delivered transactions/hour remain. This checkpoint is uncommitted on `main`.
It establishes neither all proving arithmetic on GPU nor a throughput gain.

### 9.28 GPU scalar arithmetic and owned domain metadata — 2026-10-07

The owned OpenCL prover now derives lookup bus prefixes, disjoint quotient
domains, coset partition shifts and next-row opening points on GPU. The audit
found that upstream `TwoAdicMultiplicativeCoset::new` computes a shift inverse,
even when its caller only needs a size and shift. Selected GPU-transcript
proofs now carry a checked `DomainSpec` through main, permutation,
randomization and quotient operations. Constructing this descriptor performs
no field arithmetic. CPU proving retains the upstream domain implementation;
an owned domain cannot be converted implicitly into a CPU proving domain.

Lookup bus assignment remains host metadata work: traversal order, shared
global names, distinct local buses and maximum tuple width match upstream.
The GPU samples alpha followed by beta and derives
`prefix[i] = alpha + (i + 1) * beta^width` in the cubic field. Empty lookup
batches consume no samples. Next-row points are computed once per instance
and reused for main, preprocessing and permutation openings. Owned quotient
assembly carries chunk counts instead of constructing unused chunk domains.
The live domain split in partitioned quotient evaluation now uses GPU shifts;
the similarly named split in `device/quotient_commit.rs` was test-only.

Scalar calls validate canonical fields and dimensions, reserve simultaneous
input/output allocations under the device session, fence transfers and record
actual device time and public bytes. Bounds are 4,096 lookup/scalar outputs,
256 partition cosets and domain logarithms 0 through 32; later polynomial
operations retain their narrower supported geometries. Failures in selected
transcript scalar derivations retire related challengers. Whole-proof guards
continue to retire transcript and private RNG families after failures elsewhere.
There is no CPU fallback for these device operations.

[Scalar evidence](evidence/gpu-scalars-2026-10-07.json) records **102 passing Rust
cases across 71 bounded checks**, including **56 native GPU checks**. Wide
release contributes 56 cases; eight-lane release and debug each contribute 23.
Eighteen complete full/compact proofs match exact single-thread CPU bytes and
verify with the original upstream CPU PCS and root challenger after GPU
shutdown. Altered public values reject and public preprocessing keys remain
reusable. Debug retains its explicit CPU trace audits. In the small single-AIR
proof fixture, scalar work uses four GPU calls, uploads 112 public bytes and
returns 120 public bytes; these are conformance measurements, not throughput
results or general proof-size estimates.

Additional coverage includes zero and near-modulus extension values, message
widths through `u32::MAX`, 4,096 bus prefixes, all supported domain logarithms,
shared/local bus mappings, empty batches, subsequent transcript-state equality,
failed admission and retirement after scalar execution. Partitioned quotient
caps and paths match CPU at four geometries under 12 MiB managed memory. Its
transfer assertions account for the added public scalars. The first eight-lane
run exposed a fixture assumption: its fixed unsplit expansion fit the narrower
AIR budget. The corrected fixture derives a rejecting expansion from the
actual preprocessing width. `run-01` preserves that failure and its passing
checks; final totals include only `gpu-scalars-20261007/run-02`.

CPU-only and GPU streaming builds pass, as do registered CPU/randomness paths
and the nine enabled proving policy/reporting tests. The production-strength
CPU wallet proof remains explicitly ignored. All native checks ran serially
on the selected RTX 5080 Laptop GPU with 3 GiB RAM, zero swap, four CPU cores
and a 180-second limit, releasing every lease with zero managed bytes. The
evidence verifier checks 253 source/configuration files and archive members,
three binaries, runners and logs. Resource scripts did not change and their
Python tests were not rerun. Root `config.rs` and `lib.rs` match the preceding
checkpoint; registered transcript selection remains CPU.

The remaining implementation sequence is:

1. Add immutable registered transcript selection, requiring the existing owned
   witness/PCS and private GPU randomness path. Report actual transcript,
   grinding and derived arithmetic execution. Add worker reservations for live
   snapshots, sample buffers, scalar scratch and grinding scratch alongside
   retained polynomials; reject assignments before activation or private draws.
   Revalidate registered full/compact proofs in both AIR layouts and debug.
2. Audit and migrate the remaining setup, registry and public-value arithmetic,
   wallet/batch witnesses, maintained Rust/C-ABI proving routes, and unsupported
   periodic, legacy, nonbinary and general-final-polynomial profiles. Keep
   strict GPU admission explicit for each supported combination.
3. Qualify AMD and Metal implementations and integrate the pending local Mac
   source commit. Preserve per-attempt device ownership and failure retirement
   when extending the pool/worker interface across devices and hosts.
4. Validate full-size simultaneous memory, cancellation and fresh-attempt retry,
   then measure sustained delivered transactions/hour across the pool with
   CPU verification and realistic input, output and scheduling costs included.

This checkpoint remains uncommitted on `main`. It does not establish all-GPU
proving across the codebase, AMD/Metal compatibility or a throughput gain.

### 9.29 Registered GPU transcripts, reporting and worker reservations — 2026-10-07

Registered proving now accepts explicit `LATTICA_V2_GPU_TRANSCRIPT=1`. Selection
is immutable after initialization and requires registered private GPU randomness,
GPU witnesses and the owned OpenCL PCS consumers. Private proof configurations
create a GPU challenger in their existing device session. CPU transcripts remain
the default. Public preprocessing and independent verification retain their CPU
challengers, and registry identities and the original proof encoding are unchanged.
The root wallet/legacy configuration and maintained C-ABI source are unchanged.

`challenger/resources.rs` defines fixed bounds shared with the primitive kernels.
Registered transcript families admit at most **two live device states**, covering
the configuration state and its proving snapshot. An additional snapshot rejects
before copying or changing device counters. Dropping a state scrubs and frees its
secret allocation before returning the slot. A fallible primitive admission
failure preserves existing states; the infallible challenger adapter retires its
family after a failed clone. Fresh attempts remain independent. Internal oracle
constructors retain their existing managed-memory limit for tests that need more
snapshots.

Worker planning adds **723,272 managed bytes**, a **524,288-byte maximum
allocation**, and **1,048,576 host bytes**. This covers two 18-word states, bounded
observation/sample buffers, scalar scratch and grinding scratch. Limits remain
4,096 transcript words/scalar outputs, 256 partition cosets, batches of 65,536
grinding candidates, at most 20 grinding bits and 2^26 candidates per operation.
Reservations add to the existing owned quotient, witness and randomness totals;
there are no overlap credits. Rust and Python reject changed flags, bounds,
reservations, aggregate shortfalls and integer overflow. Selection checks run
before engine activation; registration and each proof recheck the assignment
before creating their device state. The shared launcher explicitly sets the
assigned transcript flag, including zero, so inherited settings cannot enable it.

Stage reports now include `Scalar`. Selected registered proofs advertise OpenCL
for transcript, grinding and scalar arithmetic. Their observations contain actual
completed calls and device-event nanoseconds, including work completed before a
later failure. Empty intervals produce no entries; device timings are not copied
into wall-time fields. The transcript observation interval starts after the
initial configuration snapshot and does not include state creation or that first
copy. Existing mixed/CPU stages and the upstream proving envelope still prevent
strict GPU admission and complete stage coverage.

[Registered-transcript evidence](evidence/gpu-transcript-registered-2026-10-07.json)
records **84 passing Rust cases across 55 bounded checks**, including **45 native
GPU checks**, plus **135 passing Python cases** across resource planning, controller,
supervisor and typed worker suites. Wide release contributes 54 Rust cases;
eight-lane release and debug each contribute 15. CPU-only and GPU streaming builds
pass. The nine enabled proving-policy tests pass; the production-strength CPU
wallet test remains explicitly ignored.

The matrix verifies **18 registered GPU-transcript proofs** across full/compact
storage and the three builds. Registry identity and preprocessing caps match the
CPU reference; reusable public keys work with fresh private sessions. Serialized
proofs verify with the original upstream CPU PCS and root challenger after GPU
shutdown, and changed public values reject. A further **18 deterministic owned
proofs** match exact single-thread CPU bytes. Debug retains explicit CPU trace
audits. CPU-default registered paths, GPU witness/randomness paths with CPU
transcripts, failure retirement, reporting and worker rejection also pass.

All native checks ran serially on the selected RTX 5080 Laptop GPU under 3 GiB
RAM, zero swap, four CPU cores and a 180-second per-check limit, releasing every
lease with zero managed bytes. Source, scripts, configuration, archive members,
three binaries and logs are hash-verified in
`gpu-transcript-registered-20261007/run-01`. These are bounded correctness and
admission checks, not transaction-throughput measurements.

The next implementation sequence is:

1. **Close the supported registered route.** Audit `machine/gpu_backend.rs`
   preprocessing domain construction and `machine/backend.rs::program_identity`.
   Carry metadata-only domains through setup and add device domain-separated
   hashing with exactly the existing `commitment::hash_fields` semantics.
   Migrate proving-side statement/root construction in `recursive.rs` while
   retaining independent CPU verification. Instrument transforms, commitments,
   openings, FRI and queries individually. Enable strict GPU admission only
   after every required arithmetic stage has evidence and fallback rejection.
2. **Cover wallet and batch proving.** Port join-split, HTLC and issuance public
   values and witnesses in `leaf.rs`, `typed_leaf.rs` and the maintained AIR
   modules. Connect maintained Rust and C-ABI proving calls to explicit backend
   selection. Qualify quadratic legacy arithmetic, periodic inputs, nonbinary
   FRI and general final-polynomial profiles separately; preserve their protocol
   parameters and encodings.
3. **Qualify hardware and distributed execution.** Complete AMD and Metal
   operation coverage, integrate the pending local Mac source commit, and retain
   per-attempt device ownership in the pool/worker interface. Transfer bounded
   jobs and proof artifacts between hosts; device handles remain worker-local.
4. **Measure complete workloads.** Validate full-size simultaneous memory,
   streaming/recomputation where needed, cancellation and fresh-attempt retries.
   Measure sustained delivered transactions/hour with CPU verification, input
   preparation, transfers and scheduling included, on each target device and
   across the pool.

The checkpoint remains uncommitted on `main`. All proving arithmetic across the
codebase, strict GPU-only registered admission, AMD/Metal compatibility and a
throughput improvement are not yet established.

### 9.30 GPU setup domains and registered identity hashing — 2026-10-07

Registered GPU witness setup now computes its program identity on GPU. The
canonical manifest still binds the program, AIR/lookup constraints, protocol
parameters and deterministic preprocessing cap in exactly the existing order.
`machine/backend.rs` separates that metadata encoding from the selected hash.
CPU registration and independent verification retain their reference paths.
No new environment switch is needed: this is part of the already selected GPU
witness setup, with correspondingly updated worker reservations.

The new `device/public_hash.rs` implements the protocol's
`commitment::hash_fields`, which differs from the Fiat–Shamir transcript. It starts
with `[domain, total_length, 0, 0]`, applies Poseidon2 to successive four-word
chunks, and pads only the final partial chunk. Empty input performs no
permutations. Canonical domain, length and every field are checked before any
device allocation or upload. Intermediate chaining state remains on device across
4,096-word transfers; only the final 32-byte digest returns to the host.

The hash uses a fixed **32,800-byte managed workspace** and a **32,768-byte largest
allocation**. Witness worker reservations add these bounds and **65,536 host
bytes** without reducing existing metadata, compiler, cache or proving allowances.
The host still assembles the same public manifest as before; this change does not
make that metadata encoding a streaming host operation. An injected failure after
a GPU batch discards its local hash state; a fresh call remains independent.
There is no CPU arithmetic fallback. Per-batch device timings and completion
counts feed actual preprocessing/public-value observations.

GPU preprocessing now passes `DomainSpec` directly into
`commit_preprocessing_device`. This removes the upstream natural-domain
constructor and its hidden CPU shift inversion from this setup path. Domain
size/shift and session checks still precede commitment work. Public salts,
preprocessing caps, proof encoding and the root wallet/legacy challenger remain
unchanged. Capability/report coverage stays conservative; this checkpoint does
not enable strict GPU-only admission.

[Setup evidence](evidence/gpu-setup-2026-10-07.json) records **76 passing Rust cases
across 51 bounded checks**, including **41 native GPU checks**, and **135 passing
Python cases**. Wide release contributes 50 Rust cases; eight-lane release and
debug each contribute 13. CPU-only and GPU streaming builds pass. Native checks
ran serially on the selected RTX 5080 Laptop GPU with 3 GiB RAM, zero swap, four
CPU cores and 180 seconds per check; every lease released with zero managed
bytes. Source, configuration, scripts, archive members, binaries and logs are
hash-verified in `gpu-setup-20261007/run-01`.

Hash conformance covers domain/field boundaries, empty messages, final padding,
4,096-word chunk boundaries and messages through 65,537 fields. A further
131,073-field message is larger than the test's 1 MiB managed-memory allowance
but hashes with the same bounded scratch. Tests check exact CPU digests, transfer
counts, permutations, admission before upload, maximum-allocation rejection,
failure cleanup and actual reports. The initial Rust build needed a `usize`
annotation in the new boundary fixture; final counts include only the corrected
build and passing matrix.

**Forty-two registered proofs** use the new setup hash across GPU witness,
randomness and transcript selections. They preserve CPU registry identities and
preprocessing caps, reuse public keys, verify serialized proofs with the original
upstream CPU PCS/root challenger after GPU shutdown, and reject changed public
values. This includes 18 registered GPU-transcript proofs across both storage
modes and all three builds. An additional **18 owned GPU-transcript proofs**
retain exact single-thread CPU bytes. Debug retains explicit CPU trace audits;
CPU registration, public-salt and preprocessing-handoff regressions also pass.

In the wide-layout registered fixture, the 56,048-field identity manifest uses
14 GPU batches, uploads 448,384 public bytes and downloads 32 bytes. This verifies
the data flow and accounting. It does not demonstrate a speedup; serial identity
hashing and transfers must be included in later cold-setup measurements.

Next, apply the public hash to proving-side statement/leaf/empty/merge
construction in `recursive.rs` and wallet flows. Pass an explicit proving
backend so verification and host acceptance never switch implicitly. Then finish
individual transform/commitment/opening/FRI/query observations and strict
admission, followed by the wallet/batch/C-ABI, backend and complete-workload gates
listed in §9.29. Full-size host/device memory, cancellation/retry and sustained
delivered transactions/hour remain unqualified. This checkpoint is uncommitted
on `main`; the overall all-GPU proving goal remains incomplete.

### 9.31 GPU statement derivation in recursive sessions — 2026-10-07

Proving-side statement hashing now uses the selected registered witness backend.
This includes statement digests, leaves, canonical empty subtrees, merges and
finalizer padding in both `recursive.rs` and `typed_recursive.rs`, including
grouped and typed pair wrappers. The private `prove` guards also validate empty
roots through this backend; replacing only the outer constructors would have
left this hidden CPU hash in the proving path.

`commitment.rs` shares its field encodings and structural validation through
fallible hash callbacks. Its public CPU APIs retain their signatures, domains,
known-answer roots and validation rules. `statements.rs` owns a scoped derivation
with one immutable backend selection. The complete recursive proving policy and
assigned witness resources are checked before hashing. GPU failures propagate;
there is no CPU fallback. The public device session is released before private
proving, and the scratch fits the public-hash reservation added in §9.30. No new
runtime switch or worker-packet field is needed.

Proving contexts reuse the profile pin authenticated when the session was
constructed. CPU wallet/child verification, registry approval and exported host
summary helpers remain independent. Metadata decoding is separate from canonical
empty-root validation, so host acceptance never changes backend implicitly.
Device handles remain local to the worker; only ordinary summaries and proofs
cross this interface.

Actual completed GPU hash batches and device-event time appear as `PublicValues`
observations. Failed derivations retain observations for work already completed.
The capability inventory remains `Mixed` for this stage: compiler-side registry
fingerprints still use CPU hashing. Reports do not claim complete stage coverage,
and strict GPU-only proving admission still rejects this unfinished route.

[Statement evidence](evidence/gpu-statements-2026-10-07.json) records **75 passing
Rust cases across 42 bounded checks**, including **29 native GPU checks**, and
**135 passing Python cases**. Wide release contributes 37 cases; narrow release
and wide debug contribute 18 each. Two additional CPU session checks cover
preprocessing reuse, fresh hiding randomness and the typed empty/merge reference
path. CPU-only and GPU-enabled streaming builds pass.

**Thirty-two recursive empty proofs** exercise the public untyped, five-key,
six-key and twelve-key session APIs. All four use full and compact storage in
wide release, and full storage in narrow release and debug. At height 2048, each
session proves levels zero and five, reusing its preprocessing key. Serialized
proofs verify after GPU shutdown. Altered in-range public counts are rejected
even when the expected statement matches the altered artifact, exercising proof
verification rather than only the API's expected-statement comparison. Eighteen
additional registered GPU proofs cover witness/transcript regressions.

Hash conformance covers all three transaction kinds, ordered roots at counts
1, 2, 3, 17, 63 and 64, every empty level, partial-pair padding and finalizer
derivation. Invalid context, metadata, padding and dense-prefix combinations
reject. Callback and derivation failures propagate, subsequent derivations stay
independent, and invalid worker assignments reject before allocation or upload.
These are not full-size wrapped-wallet, merged or finalized root proofs.

Native checks ran serially on the selected RTX 5080 Laptop GPU under 3 GiB RAM,
zero swap, four CPU cores and a 180-second per-check limit. Recursive integration
uses a 1 GiB GPU managed-memory limit. Every lease releases with zero managed
bytes. The final matrix, binaries, logs and **402 source/configuration/script
files** are hash-verified in `gpu-statements-20261007/run-02`. The earlier
`run-01` passed but predates the strengthened public-value tamper checks; it is
retained separately. No transactions/hour improvement is inferred.

### 9.32 GPU compiler registry fingerprints — 2026-10-07

The AIR fingerprint embedded in compiler registry prefixes now uses the selected
registered witness backend. Both recursive proving-session APIs and all five
registration entry points use this path: untyped single/grouped wrappers and the
typed five-, six- and twelve-key registries. Wrapper, pair, empty, merge,
finalizer and registration-template compilers accept a private prepared prefix
and verify its height and key count before use. Metadata construction and
symbolic constraint encoding remain on the host; their field ordering and
domain encodings are unchanged.

The prefix is computed through an explicit fallible hash callback inside the
scoped `statements::compile` operation. Policy and worker resource admission
precede metadata and device work. Backend selection is immutable for the
operation, failures propagate, and the public device session is released before
private proving. Prefixes are neither cached nor serialized. Public CPU compiler
and geometry APIs, profile approval and independent CPU verification retain
their reference paths. No new runtime switch, worker-packet field or memory
reservation is needed: this work reuses the 32,800-byte public-hash scratch.

`block_v2_registry_compilation` reports actual completed GPU hash batches and
event time under `Preprocessing`. A failure after hashing retains observations
for completed work. These reports do not claim complete compiler arithmetic or
stage coverage. `PublicValues` remains conservatively `Mixed`, and strict
GPU-only admission continues to reject this route.

[Registry evidence](evidence/gpu-registry-2026-10-07.json) records **90 passing
Rust cases across 51 bounded checks**, including **35 native GPU checks**, and
**135 passing Python cases**. Wide release contributes 42 cases; narrow release
and wide debug contribute 23 each, plus two CPU session regressions. CPU-only
and GPU-enabled streaming builds pass. Exact compiled programs and witness
vectors match CPU references for registry sizes 3, 5, 6 and 12 at heights 64,
2048 and 4096. Interpreter checks preserve the CPU profile binding. Tests also
cover mismatched prefix geometry, invalid key counts, injected failures and
rejection before device allocation or upload.

The matrix retains **32 recursive empty GPU proofs** and **18 additional
registered GPU proofs**, with independent CPU verification after GPU shutdown.
It checks **47 successful GPU registry-compilation reports**: two per recursive
session check and all five registration entry points in each build configuration.
Registration preprocessing caps match CPU-compiled reference programs. These
registration checks use empty programs; compiler branch rejection tests also
exercise wrapper, pair and finalizer forwarding. They do not establish full-size
wrapped-wallet, merged or finalized proof qualification.

Native checks ran serially on the selected RTX 5080 Laptop GPU under 3 GiB RAM,
zero swap, four CPU cores and a 180-second per-check limit. Registration and
recursive integration use a 1 GiB GPU managed-memory limit. Every native check
releases its lease with zero managed bytes. The final matrix, binaries, logs,
runners and source archive are recorded in `gpu-registry-20261007/run-01`, with
**403 source/configuration/script files and 77 artifacts** hash-verified. The
initial debug fixture compile error was corrected before this matrix; its log
is retained at `/tmp/lattica-gpu-registry-debug-initial.log`. No transactions/hour
improvement is inferred.

### 9.33 GPU public compiler constant helpers — 2026-10-07

Explicit public constant helpers now use the selected compilation backend.
`machine/compiler_constants.rs` covers Lagrange selector denominators, subgroup
inverses, periodic-column interpolation, and quotient coset shifts and
normalization inverses. Prepared registry prefixes borrow this backend for one
compilation. Wrappers, ordered pairs, empties, merges, both finalizers and their
registration templates forward it through the inner uni/batch verifier
compilers. Public CPU compiler APIs retain their reference behavior. Device
errors propagate through `CompileError::Backend` without a CPU fallback.

Pinned subgroup powers now come directly from the Goldilocks root table.
Negative one and one half use fixed field constants. Tests compare the exact
emitted subgroup programs against the previous exponentiation construction for
every valid bit length for subgroups through order 2^32. These substitutions
preserve the instruction layout and avoid runtime arithmetic for fixed values.

The GPU interpolation implementation uses a direct quadratic algorithm with
2,048-value input and output tiles. It admits power-of-two periods through
65,536, streams each input tile through the coefficient accumulators, and
downloads the public coefficients needed by the compiler. Its two device
buffers total at most 32,768 bytes; extra host staging is at most 16,384 bytes.
The returned coefficient vector replaces the same-size CPU compiler vector.
All helper kernels fit the existing public-hash scratch envelope, so no worker
reservation, packet field or runtime switch is added. Selector ranges admit at
most 64 values, quotient layouts at most 32 chunks, and logarithmic subgroup
sizes at most 32. Unsupported geometry rejects before GPU allocation or upload.

An initial bounded wallet-compilation probe exposed that a single 2,048-value
interpolation buffer was too small for maintained wallet columns. Tiling fixes
that limit. The final checks compare the maximum admitted period and every
JoinSplit/HTLC AIR periodic column against an independent CPU inverse DFT. The
initial rejected probe remains in
`/tmp/lattica-compiler-constants-extended-probe-wallet.log`; it is not counted as
successful wallet-program or proof qualification.

[Compiler evidence](evidence/gpu-compiler-2026-10-07.json) records **108 passing
Rust cases across 63 bounded checks**, including **44 native GPU checks**, and
**135 passing Python cases**. Wide release contributes 48 cases; narrow release
and wide debug contribute 29 each, plus two CPU session regressions. CPU-only
and GPU-enabled streaming builds pass. Native conformance covers selector
boundary values, interpolation, quotient normalization, scratch admission and
observations retained after an injected failure. A small real periodic AIR
proof produces the same complete verifier program and witness on CPU and GPU;
CPU interpretation accepts it and rejects an altered witness.

Eighteen complete merge/finalizer program comparisons cover all four registry
sizes and both finalizers across the three build configurations. These use
shape templates and establish compiler equality, not validity of those template
proofs. The matrix retains **32 recursive empty GPU proofs** and **18 additional
registered GPU proofs**, with independent CPU verification after GPU shutdown.
There are **65 successful registry-compilation reports** with actual GPU
preprocessing event time. Completed kernels remain recorded when later compiler
work fails; reports continue to mark stage coverage incomplete.

The native matrix ran serially on the selected RTX 5080 Laptop GPU under 3 GiB
RAM, zero swap, four CPU cores and a 180-second per-check limit. Every native
check releases its lease with zero managed bytes. The source archive, binaries,
logs and runners are in `gpu-compiler-20261007/run-01`: **406
source/configuration/script files and 89 artifacts** are hash-verified. These
checks do not qualify full-size wallet/pair/merge/finalizer proving or a
transactions/hour improvement.

At this checkpoint compiler arithmetic was still incomplete. `ProgramBuilder` performed CPU constant
folding of known base and cubic expressions in `machine/program.rs`, including
addition, multiplication and inversion. Symbolic AIR construction also needs an
arithmetic audit and explicit backend treatment. `PublicValues` and
`Preprocessing` remain conservatively `Mixed`, and strict GPU-only admission
continues to reject the unfinished route.

### 9.34 GPU compiler constant folding — 2026-10-07

The registered recursive compilers now send known base-field addition,
multiplication and inversion, plus cubic-extension multiplication and inversion,
to the selected backend. `ProgramBuilder` keeps its public CPU API as an alias
of `ScopedProgramBuilder<'static>`; selected compilers borrow a backend only for
the lifetime of compilation. Generic circuit, Merkle, transcript and verifier
helpers accept the scoped builder. Finished programs and worker packets contain
no backend references, device handles or fold caches.

The device path uses the protocol's cubic field `F[X]/(X^3 - X - 1)` and preserves
constant interning, instruction order, base-scaling shortcuts and zero-inverse
runtime instructions. Each fold uses six input words and four result words:
**80 managed bytes**. A **64-entry cache, bounded to 8 KiB of host memory**, stores
successful public results, including noninvertibility. Full canonical keys
prevent collisions from returning an unrelated result. Replacement keeps the
cache bounded; CPU builders allocate no cache. The cache and transient folding
or periodic-interpolation scratch fit the existing public-hash reservation.

The first backend failure is latched. Subsequent folds perform no arithmetic or
cache lookup, and `finish` rejects the builder before constructing a program.
The shared compiler finish helper preserves the original backend cause. Actual
completed GPU kernels report preprocessing event time; cache hits add no kernel
calls. Completed observations survive a later compilation failure. The Metal
path explicitly reports unsupported folding, with no CPU fallback.

Validation in [the evidence manifest](evidence/gpu-folding-2026-10-07.json) covers
**150 Rust cases in 84 bounded checks, including 50 native GPU checks**, and
**135 Python cases**. This comprises 62 wide release cases, 43 narrow release
cases, 43 wide debug cases and two CPU session regressions. CPU-only and
GPU-enabled streaming library builds pass. New tests cover native-field edge
values, exact CPU/GPU programs, zero inversion, cache hits and collisions,
failure latching, original-cause propagation and rejection before allocation or
upload. The existing circuit, transcript and Merkle helper tests also pass.

The matrix retains 18 exact merge/finalizer program comparisons, three real
periodic uni-verifier checks with altered-witness rejection, 32 recursive empty
GPU proofs and 18 additional registered GPU proofs independently CPU-verified
after GPU shutdown. All 65 successful registry-compilation reports contain GPU
preprocessing observations and continue to mark stage coverage incomplete.

Native checks run serially on the selected RTX 5080 Laptop GPU with 3 GiB RAM,
zero swap, a four-core CPU quota and a 180-second per-check limit. Every native
check releases its lease with zero managed bytes. The source archive, binaries,
logs and runners in `gpu-folding-20261007/run-01` pin **409 source/configuration/script
files and 110 artifacts**, all hash-verified. These checks establish bounded
correctness and compatibility; they do not establish a transactions/hour gain,
full wallet/pair program qualification or AMD/Metal support.

The remaining implementation sequence is:

1. **Finish the supported registered route.** Audit symbolic AIR construction and the
   remaining compiler/setup callers for field arithmetic, preserving identical
   compiled programs and independent CPU registry approval. The pinned
   `p3-air 0.6.1` still folds constants in `SymbolicExpr::sym_add`, `sym_sub`,
   `sym_neg` and `sym_mul`; these run during the symbolic constraint collection
   used by registry analysis and both inner-proof verifiers.
   Record actual transform, commitment,
   opening, FRI and query operations individually; enable strict GPU admission
   only when every required stage is covered and CPU fallback is rejected.
2. **Cover wallet, batch and maintained entry points.** Port witness and public
   value arithmetic in `leaf.rs`, `typed_leaf.rs` and the join-split/HTLC/batch
   AIRs. Connect Rust and C-ABI proving calls to explicit backend selection.
   Qualify legacy quadratic extensions, periodic inputs, nonbinary FRI and
   general final polynomials without changing protocol parameters or encodings.
3. **Qualify hardware and worker execution.** Match operation coverage on AMD
   and Metal; integrate the pending Mac source through its local commit. Keep
   per-attempt device ownership and bounded resource admission in the existing
   pool/worker model. Remote jobs transport inputs and proof artifacts, never
   device handles. Qualify cancellation, cleanup and fresh-attempt retries.
4. **Validate complete workloads.** Measure simultaneous host/device memory at
   full size and add streaming or recomputation where necessary. Benchmark
   sustained delivered transactions/hour, including preparation, transfers,
   scheduling and independent CPU verification, on each target and across the
   pool. Correctness, GPU-only coverage and throughput are separate gates.

This checkpoint remains uncommitted on `main`. The overall all-GPU proving goal,
AMD/Metal qualification and sustained pool throughput remain unfinished.

### 9.35 GPU symbolic AIR compilation — 2026-10-07

Selected registry compilation and recursive inner verifiers now record symbolic
AIR expressions without native symbolic field operators, then normalize them
through the explicit compiler arithmetic backend. This covers registry geometry
and fingerprints, batch and uni verifier constraints, lookup collection/packing,
and the geometry used to construct merge/finalizer registration templates. The
public CPU compiler APIs retain the pinned native symbolic implementation as an
independent reference. Dependencies, proof encodings and protocol parameters are
unchanged.

The local recording builder preserves base/extension constraint emission order,
public/periodic/permutation variable layouts and interactions. Its fallible
normalizer uses GPU folding for base-representable constant addition,
subtraction, negation and multiplication, while retaining the pinned treatment
of nonbase cubic constants. It preserves `p3-air 0.6.1` simplification order and
**input Arc sharing**, because the registry fingerprint encodes DAG identity.
Structural interning would change that identity. Lookup packing reproduces
`p3-lookup 0.6.1` bus order, greedy degree limits, column assignment and saturating
count weights using integer metadata. Normalized constraints contain no backend
references or device state.

All recorded constraint and interaction roots are checked before folding, with
limits of **131,072 nodes and depth 512**. A shared node is revisited when reached
along a longer path; shallow traversal cannot conceal an excessive depth.
Normalized degree sums reject overflow, and quotient chunk metadata uses an
overflow-safe bit calculation. The Rust and Python worker models both reserve an
additional **64 MiB of transient host memory** for graph storage, retained lookup
expressions, memo tables and traversal. Recording still evaluates trusted
internal AIR implementations; these checks do not sandbox arbitrary remote AIR
code or bound an arbitrary AIR's construction before it returns. Existing
service memory limits remain necessary. No worker packet carries a compiler
backend or device handle.

Validation in [the evidence manifest](evidence/gpu-symbolic-2026-10-07.json)
records **174 Rust cases in 102 bounded checks, including 62 native
GPU checks**, plus **135 Python cases**. There are 74 wide release cases,
49 narrow release cases, 49 wide debug cases and two CPU session
regressions. CPU-only and GPU-enabled streaming library builds pass. Exact
fingerprints, constraint degrees, lookup layouts, geometry/security metadata and
registration templates match the CPU reference at machine heights 8, 64 and
2,048. Synthetic AIRs cover shared expressions, zero/one simplifications, double
negation, cubic constants, interleaved constraints and local/global lookup buses.
The actual JoinSplit and HTLC symbolic constraints also match the CPU reference.

Admission checks cover excess roots, deep shared paths, degree overflow and
policy rejection without GPU allocation, upload or CPU fallback. A later
injected failure preserves completed GPU preprocessing observations. The
existing template regression confirms that zero-filled proof-shaped objects
remain invalid proofs. The matrix retains 18 merge/finalizer program comparisons,
three real periodic-verifier checks with tamper rejection, 32 recursive empty GPU
proofs and 18 other registered GPU proofs independently verified on CPU after
GPU shutdown. The worker-admission regression adds one more registered GPU proof
verified independently on CPU. All 65 successful registry-compilation reports
continue to mark stage coverage incomplete.

Checks run serially on the selected RTX 5080 Laptop GPU in services limited to
3 GiB RAM, zero swap, four CPU cores and 180 seconds per check. Every native check
releases its lease with zero managed bytes. The source archive, binaries, logs
and runners in `gpu-symbolic-20261007/run-03` pin **415 source, configuration and
script files and 200 artifacts**, all hash-verified. These checks establish
bounded correctness and compatibility; they do not establish a transactions/hour
improvement or complete wallet/pair program and proof qualification.

The retained `run-01` stopped at a registered-proof fixture whose historical
64 MiB host allowance omitted the new reservation. Admission rejected it. A
follow-up allocation assertion exposed lazy device setup ahead of that guard,
so registered and direct setup now check the host reservation before constructing
PCS/device-session state. The corrected fixtures allow 64 MiB plus the reservation,
and explicitly test rejection of the old budget without allocation or upload.
The first version of that new rejection test compared a shortened diagnostic;
`run-02` retained that test failure, and the assertion now matches the error
category and compiler/staging marker. Six additional native regressions cover
affected worker admission, witness reuse, complete proofs, handoff and
failure/session isolation. `run-03` is the passing matrix; the artifact count
includes both earlier runs' preserved evidence.

The next implementation steps are:

1. Move remaining selected proving setup and quotient symbolic collection onto
   explicit backends. Native symbolic builders still occur in
   `machine/backend.rs` and `gpu_quotient_prover/mod.rs`. Preserve independent CPU
   verification and exact approved program identities.
2. Record individual transform, commitment, opening, FRI and query operations.
   Enable strict GPU admission only after every required stage has measured
   coverage and CPU fallback is rejected.
3. Complete wallet/batch Rust and C-ABI proving routes, then qualify AMD/Metal,
   full-size simultaneous memory, cancellation/retry and sustained delivered
   transactions/hour across the pool. The pending Apple source still needs its
   local Mac checkpoint commit; no SSH retrieval is authorized.

This checkpoint remains uncommitted on `main`. Full GPU proving, hardware
qualification and sustained pool throughput remain unfinished.

### 9.36 GPU symbolic setup and quotient compilation — 2026-10-08

Registered GPU witness setup now reuses explicitly GPU-normalized constraints
for geometry/security analysis, packed lookup metadata and program identity.
The initial worker and compiler host-budget checks still precede PCS/session
creation. Bounded symbolic arithmetic then supplies the exact geometry used by
the compact/full RAM guard before allocating preprocessing matrices. The CPU
analysis, key generation, identity and verification paths remain independent
references; approved identities and proof bytes are unchanged in the checks.

The pinned lookup library's private container is constructed by replaying
already-normalized interaction expressions through its public API. Replay
clones expression nodes and records tuples; it does not evaluate the original
AIR or perform field arithmetic. Upstream lookup packing is reused without a
dependency patch, unsafe conversion or serialized backend handle.

Selected GPU quotient paths now normalize each AIR once per proof through an
explicit device session. Quotient-degree inference and constraint-count checks
use that result, and lowering emits the same immutable instructions as the CPU
oracle. Invalid degree/count hints and unsupported/oversized input layouts
reject without CPU fallback. The host-input experimental route creates an
explicit compiler session even when there is no owned PCS session. Its batch
support remains available; device-owned main traces and owned quotient
commitment still require one AIR.

Compilation proceeds sequentially across AIRs and drops each symbolic graph
after lowering. Only instructions and small metadata remain for the proof,
with a **16 MiB aggregate IR cache limit** that counts vector capacity and Arc
storage. The shared transient compiler allowance is now **192 MiB**: the
previous 64 MiB symbolic allowance plus 128 MiB for lowering and bounded cache
storage. Rust and Python reserve this once per worker, not once per cached
registered program. Historical 64/128 MiB setup budgets and insufficient new
budgets reject before device allocation/upload. This is a conservative
reservation, not a measured working-set or throughput claim.

Evidence: [checkpoint manifest](evidence/gpu-setup-quotient-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-setup-quotient-20261008/run-01`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 79 cases / 47 checks / 32 native |
| Narrow release Rust | 54 cases / 31 checks / 18 native |
| Wide debug Rust | 54 cases / 31 checks / 18 native |
| CPU session regressions | 2 cases |
| Total Rust | 189 cases / 111 bounded checks / 68 native |
| Python resource/controller/worker checks | 135 cases |

The matrix covers CPU/GPU instruction equality, base-only and extension AIRs,
lookup constraints, hiding/non-hiding degree inference, invalid hints, layout
and cache admission, nonzero quotient evaluations across domain/tile sizes,
registered identities, full/compact proof bytes, worker admission and fresh
session/failure isolation. It includes 32 recursive empty GPU proofs, 19 other
registered GPU proofs and 65 successful GPU registry compilations. Eighteen
of the latter 19 proofs were independently CPU-verified after GPU shutdown;
the worker-admission proof was verified with the runtime initialized.

Three additional two-AIR host-input quotient proofs match the upstream proof
bytes and CPU verification, using the existing batch commitment adapter.
These fixtures verify while the GPU runtime remains initialized. The owned
single-AIR commitment restriction is unchanged. CPU-only and GPU streaming
builds, formatting, whitespace checks and all source/archive/artifact hashes
pass. The evidence checker validates 417 source/config/script files and
141 artifacts for the passing matrix.

The five smoke attempts remain intact. They exposed an input-layout admission
ordering regression and an assumed owned session in the host-input path; both
are fixed and covered. The multi-AIR fixture now selects the supported batch
commitment adapter. The final wide runner also stopped after a passing Rust
check because it expected an optional JSON report suppressed by
`Request::compatible()`. Its original runner/logs remain preserved; a corrected
resume runner completed only the unrecorded checks.

Next, connect operation-level measurements for transforms, commitments,
openings, FRI and queries, and enable strict GPU admission only after complete
stage coverage and fallback rejection are demonstrated. Full wallet/batch
Rust and C-ABI proving, AMD/Metal qualification, realistic simultaneous memory,
cancellation/retry and sustained delivered transactions/hour remain open.
The pending Apple source still needs its local Mac checkpoint commit.
This checkpoint remains uncommitted on `main`; the overall GPU proving goal
is active.

### 9.37 GPU execution receipts and stage coverage — 2026-10-08

Proof reports now separate wall-clock envelopes from completed device operations.
The additive `device_calls` field counts operations recorded by a device executor;
`measure` only contributes wall time and cannot satisfy GPU coverage on its own.
`observation_errors` records lost or invalid observations, and any such error
prevents a complete-coverage claim. Counter overflow retains the earlier receipts
and invalidates coverage instead of wrapping or panicking.

Each explicit `DeviceSession` now owns arithmetic counters for preprocessing,
witness generation, transforms, lookups, quotient evaluation, hiding, commitments,
openings, FRI folding, query gathering and final-polynomial extraction. Scoped
observers attach deltas to the current `Run`; no ambient run or backend is stored
in matrices, immutable programs or worker messages. Observers claim exclusive
stage scopes, reject overlapping claims, release them on unwind and preserve work
completed before a later proof failure. Independent sessions cannot contribute
operations to one another's reports. Reusing a session reports only the new scope's
deltas.

Direct kernels record completed event intervals. Existing engine NTT and Merkle
hash counters are sampled while the engine is exclusively borrowed and attributed
to the owning session. Query reconstruction includes its nested NTT work; opening
reductions inherit transform observations through the owned LDE path. Sponge time
is already included in leaf hashing and is not added twice. Failed aggregate
operations retain elapsed device time without claiming a completed operation.
These counts describe executor operations or aggregate transform/hash work, **not
individual kernel launches**; device nanoseconds exclude wall and transfer time.

The final constant polynomial has a separate extraction operation and stage. It
checks the final FRI geometry, gathers exactly one cubic coefficient and downloads
24 bytes. Wrong geometry, overflowed blowup and foreign-session inputs reject
before allocating or launching work. Registered setup, witness generation and the
owned prover install observers around their corresponding explicit sessions.
Compiler, randomness, scalar, transcript and grinding observations remain in their
existing dedicated scopes.

Evidence: [checkpoint manifest](evidence/gpu-coverage-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-coverage-20261008/run-01`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 84 cases / 49 checks / 33 native |
| Narrow release Rust | 56 cases / 33 checks / 19 native |
| Wide debug Rust | 56 cases / 33 checks / 19 native |
| CPU session regressions | 2 cases |
| Total Rust | 198 cases / 117 bounded checks / 71 native |
| Python resource/controller/worker checks | 135 cases |

The matrix includes 32 recursive empty GPU proofs, 19 other registered GPU proofs,
65 successful GPU registry compilations and three host-input two-AIR quotient
proof comparisons. Eighteen of the 19 registered proofs are independently verified
on CPU after GPU shutdown; the worker-admission proof is verified with the runtime
initialized. The two-AIR fixtures use the existing batch commitment adapter and
verify while the runtime remains initialized. Owned main and quotient commitment
remain single-AIR.

45 successful proof reports contain positive completed device calls and device
time for all 15 selected arithmetic stages, including exactly one final-polynomial
extraction. Six rejected-assignment reports preserve the witness work completed
before rejection. All observed real reports have zero observation errors and
continue to report incomplete stage coverage. The evidence checker validates
418 source/configuration/script hashes and 143 artifact hashes, including the
source archive, binaries, runners and logs.

New tests cover wall-only coverage rejection, observation loss and overflow,
session isolation, overlapping scopes, unwind cleanup, failure receipt retention
and final-polynomial extraction/admission. Full/compact storage, wide/narrow lanes,
CPU-only and GPU streaming builds, formatting and whitespace checks pass.
All native checks ran serially on the RTX 5080 Laptop GPU in services limited to
3 GiB RAM, zero swap, four CPUs and 180 seconds; successful shutdown reports zero
managed live bytes and a released lease. These are bounded correctness checks,
not throughput measurements.

**Strict GPU admission remains disabled.** Positive receipts show that selected
operations ran on GPU; they do not prove the absence of host arithmetic. The
public-value/preprocessing capability inventory stays mixed and the outer prover
still has an opaque mixed envelope, so real proof reports continue to mark stage
coverage incomplete. Host-input, non-captured and experimental paths can have
partial receipts. The next step is to compose whole-request coverage, replace the
remaining coarse envelopes and enforce rejection of CPU fallback before enabling
strict admission. Wallet/batch Rust and C ABI routes, AMD/Metal, full-size concurrent
memory and sustained pool transactions/hour remain open. Pending Apple source
still needs its authorized local Mac checkpoint commit; no SSH was attempted.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.38 Checked GPU completion and explicit CPU audits — 2026-10-08

`Run::finish` now returns `Result<Report, Error>`. An admitted `gpu-required`
request cannot finish successfully unless every declared stage has a completed
device receipt and there are no observation errors, unfinished calls or
unaccounted operations. Unlisted stages and backend mismatches also invalidate
coverage. Wall timers alone remain insufficient. Rejection returns
`IncompleteCoverage` with the missing/unaccounted inventory and error count;
when reporting is enabled, exactly one report records `succeeded=false` and the
new additive `completion_rejected=true` field.

All in-repository production callers handle completion before releasing their
output: registered setup/proofs, statement/registry operations, wallet and batch
proof APIs, leaf/typed-leaf encoders, and standalone proving helpers. Fallible APIs
propagate rejection through their existing policy errors; legacy infallible
helpers retain their panic-on-policy-error contract. Existing C ABI admission and
unwind guards remain in place. CPU-compatible requests still return their outputs
with incomplete reports where appropriate. An already-failed operation preserves
its original failure rather than acquiring a secondary completion error. Host
serialization remains permitted after GPU arithmetic.

Debug batch proving now records its CPU trace readback, constraint evaluation and
lookup-balance checks under `constraint_audit`. Each audit passes through the
policy guard before executing. These observations have CPU wall time and zero
device calls/time, and cannot satisfy the arithmetic inventory. The audits retain
their prior behavior; this change makes them visible and rejects them under a
GPU-required request. Release builds contain no such debug observations.

Evidence: [checkpoint manifest](evidence/gpu-completion-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-completion-20261008/run-01`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 88 cases / 50 checks / 34 native |
| Narrow release Rust | 57 cases / 34 checks / 20 native |
| Wide debug Rust | 57 cases / 34 checks / 20 native |
| CPU session regressions | 2 cases |
| Total Rust | 204 cases / 120 bounded checks / 74 native |
| Python resource/controller/worker checks | 135 cases |

The new native completion test runs three attempts against one explicit session:
a completed GPU fold with no attached receipt, a fold with a deliberately lost
observation, and a correctly observed fold. The first two withhold their outputs;
all three release their temporary buffers back to the measured baseline. The
successful attempt receives only its own receipt, despite earlier session work.
Across the three build profiles, six completion reports show rejection and three
show a successfully accounted **isolated FRI operation**. These fixtures admit a
one-stage inventory; they do not qualify any full GPU-required prover.

Unit regressions cover missing/partial receipts, unlisted work, interrupted calls,
observation loss/overflow, CPU/opaque fallback rejection, host serialization and
preserving prior failures. The existing complete-proof matrix still includes 32
recursive empty GPU proofs, 19 other registered GPU proofs, 65 successful GPU
registry compilations and three two-AIR host-input quotient proof comparisons.
Eighteen registered proofs are CPU-verified after GPU shutdown; the worker
admission proof and two-AIR fixtures verify while the runtime is initialized.

All 45 fully selected GPU proof reports retain positive device receipts for the
15 selected stages. Eleven debug proof reports additionally expose their CPU
constraint audits; release reports have no such entries. Six rejected-assignment
reports still retain completed GPU witness work. The verifier checks
418 source/configuration/script hashes and 146 artifact hashes, including
binaries, source archive, runners and logs.

CPU-only and GPU streaming builds, changed-file formatting, whitespace and the
source/archive/artifact checks pass. All native tests run serially on the permitted
RTX 5080 Laptop GPU in services bounded to 3 GiB RAM, zero swap, four CPUs and
180 seconds, and report clean shutdown. These remain correctness and admission
checks, not throughput measurements.

**Strict GPU admission remains disabled.** This checkpoint enforces completion
once a path is admitted; it does not turn partial backend support into a supported
GPU-only prover. Whole-request coverage still needs to compose statement and
registry work, cached preprocessing provenance and the owned proof pipeline.
The mixed capability inventory and opaque outer prover envelope remain, and debug
CPU audits now form an explicit additional gap. Wallet/batch Rust and C ABI proving,
AMD/Metal qualification, full-size simultaneous memory, retry/cancellation and
sustained pool transactions/hour remain open. Pending Apple source still requires
its authorized local Mac checkpoint commit; no SSH was attempted.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.39 Explicit GPU coverage scopes and registered proofs — 2026-10-08

Release registered-program proving now supports `gpu-required` with all owned
OpenCL stages selected. The contract starts from supplied circuit/public inputs:
preprocessing and proof generation have distinct scopes, and a successful proof
must contain completed device receipts for all 15 declared arithmetic stages.
This qualifies the registered API; whole recursive requests still reject strict
GPU admission until their component coverage and provenance are composed.

`Capabilities` now serializes `scope`: `proof_request`, `statement`,
`registry_compilation`, `preprocessing`, `registered_proof`, or `operation`.
Statement derivation covers public values, registry compilation covers its public
compiler arithmetic, and preprocessing covers construction, randomness, transforms
and commitments. The registered-proof scope excludes public values, which are
supplied inputs. A complete component report cannot stand in for a complete
request. Typed and untyped recursive proving entry points enforce the conservative
whole-request inventory before beginning component work.

The device-owned registered path no longer uses an opaque `UpstreamProver` wall
clock as its execution envelope. Its actual operations feed checked completion;
missing or mismatched receipts withhold the proof. Cached GPU preprocessing must
match the selected witness backend, and missing provenance is rejected before
allocation or upload. Host-input and CPU paths keep their existing accounting and
do not acquire GPU-only coverage through this change. Debug registered proofs
explicitly declare CPU constraint audits, so GPU-required admission rejects them
before private witness work.

The source audit found a remaining CPU inversion in shared LDE root preparation.
Forward and inverse roots now use the same immutable constants as owned
transforms. A unit test checks both tables against independent field operations
for all 33 Goldilocks domains, bits 0 through 32. Host-input inverse/scaling code
remains separate; the registered device path uses owned inputs and rejects host
PCS or quotient callbacks.

Validation also caught an overstatement in preprocessing capabilities: public
salt generation follows the randomness switch. With that switch disabled, the
scope now retains CPU randomness and GPU-required setup rejects before device
work. Two preserved earlier runs record this report-validation failure and an
outdated registry test assertion; neither is counted as final passing evidence.

Evidence: [checkpoint manifest](evidence/gpu-scopes-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-scopes-20261008/run-03`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 92 cases / 53 checks / 36 native |
| Narrow release Rust | 60 cases / 37 checks / 22 native |
| Wide debug Rust | 60 cases / 37 checks / 22 native |
| CPU session regressions | 2 cases |
| Total Rust | 214 cases / 129 bounded checks / 80 native |
| Python resource/controller/worker checks | 135 cases |

The release full/compact fixtures produce 12 GPU-required registered proofs,
all CPU-verified after GPU shutdown, and six GPU-required preprocessing reports across release/debug.
Two debug full/compact fixtures complete public GPU setup, then reject strict
registered admission before private work. Sixteen typed/untyped recursive fixtures reject whole-request
GPU admission without allocating or uploading component work, then successfully
exercise compatible proofs.

The broader matrix retains 32 recursive empty proofs, 31 other registered GPU
proofs, 65 registry compilations and three two-AIR host-input quotient comparisons.
Thirty of the other registered proofs are CPU-verified after shutdown; one worker
admission proof is verified while its runtime remains initialized. Fifty-seven
proof reports have positive receipts across all 15 selected arithmetic stages.
Ten rejected witness assignments retain completed device receipts. The six strict
completion rejections and three successful isolated FRI operations remain
separate from the newly qualified registered proofs. Eleven debug compatible
proof reports explicitly record CPU audits; their complete registered scope does
not mean GPU-only execution.

All 418 archived source hashes match the final tree; 13 Rust files changed since
§9.38. Release wide/narrow builds, debug wide build, CPU-only and GPU-only feature
checks pass. Native tests run serially on the RTX 5080 Laptop UUID ending `ee6b`,
driver `615.71.09`, in services bounded by 3 GiB RAM, no swap, four CPU equivalents
and 180 seconds. Every native fixture reports zero live managed GPU bytes and a
released device lease at shutdown. Artifact hashes and command limits are checked
by the archived evidence verifier.

Remaining work is whole-request receipt composition and fallback rejection across
recursive orchestration, legacy wallet/batch proving, owned multi-AIR support,
production-size resource qualification, and sustained pool throughput. CPU
orchestration, input acquisition, serialization and independent verification are
outside the registered arithmetic contract. AMD/Metal remain unqualified, and
pending Apple source still requires the authorized local Mac checkpoint commit.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.40 Recursive request receipt composition — 2026-10-08

Typed and untyped recursive proving now compose component execution into a
`proof_request` report. Release requests with all owned OpenCL stages selected
can use `gpu-required`; the return boundary requires coverage of all 16 proving
arithmetic stages and every named component. Native qualification here covers
empty recursive proofs under three-, five-, six- and twelve-key registries,
including cold setup and cached preprocessing. The same explicit request plumbing
covers wrap, pair, merge and finalizer entry points; their full-size end-to-end
GPU-required proof workloads remain unqualified.

Each request declares five single-use slots before work: statement derivation,
registry compilation, statement validation, preprocessing, and registered proof.
A completed stage in one component cannot cover an omitted component with the
same stage. Child runs inherit the request policy and attach through explicit
handles, with no thread-local collector. Their actual receipts are merged under
bounded synchronization; failures and unwinding retain completed work even when
optional JSON emission is disabled. Duplicate slots, wrong scopes, foreign
inventories, counter overflow and outstanding children prevent strict completion.
A late child cannot reopen a finished parent.

`RegisteredProgram` retains immutable preprocessing coverage alongside its public
setup data. A cache hit records this provenance separately and adds no device
calls or time. CPU or incomplete cached setup cannot qualify a GPU-required
request. A cold request records its new preprocessing execution normally. The
existing registered witness/session checks still enforce the selected device
backend before private work; cached witnesses and private RNG state are never
retained by this receipt mechanism.

The report schema adds `components`; `IncompleteCoverage` now also identifies
missing components. Root observations are sums of child observations, not extra
GPU execution. Telemetry consumers must select the appropriate scope instead of
summing root and child reports. CPU parsing, static metadata, input/result
verification, serialization and host acceptance remain outside proving arithmetic.
Request elapsed time includes this host orchestration and verification.

Evidence: [checkpoint manifest](evidence/gpu-request-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-request-20261008/run-01`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 100 cases / 54 checks / 36 native |
| Narrow release Rust | 68 cases / 38 checks / 22 native |
| Wide debug Rust | 68 cases / 38 checks / 22 native |
| CPU session regressions | 2 cases |
| Total Rust | 238 cases / 132 bounded checks / 80 native |
| Python resource/controller/worker checks | 135 cases |

The recursive matrix produces 24 GPU-required release requests and eight debug
compatible requests, with all encoded outputs CPU-verified after GPU shutdown.
Sixteen requests use fresh setup and sixteen reuse its provenance; exact report
comparisons confirm that cached setup contributes no replayed events. All 32
request reports complete their five slots and their declared arithmetic inventory.
Debug requests include explicit CPU constraint audits, and four negative fixtures
reject GPU-required whole-request admission before component work begins.

Eight composition regressions per profile exercise omitted components despite
overlapping stage coverage, explicit cache reuse, failed/unwound children,
duplicate or mismatched components, concurrent completion, overflow, late
completion, and CPU/incomplete cached setup. The broader matrix retains 31 other registered GPU proofs, including 12
independent GPU-required proofs,
65 GPU registry compilations, three two-AIR host-input quotient comparisons,
six strict completion rejections and three isolated accepted FRI operations.
Fifty-seven registered proof reports retain positive receipts in all 15 supplied-
input stages, including 11 debug reports that also declare CPU constraint audits.

All 420 archived source hashes and the recorded artifact hashes verify. Ten Rust
files changed since §9.39, including two new composition modules. Wide/narrow
release, wide debug, CPU-only and GPU-only feature builds pass; formatting and
whitespace checks pass. Native tests remain serial, on the RTX 5080 Laptop UUID
ending `ee6b`, driver `615.71.09`, with 3 GiB RAM, no swap, four CPU equivalents
and 180-second service limits. Every native fixture releases its lease and all
managed GPU allocations at shutdown.

The broader all-proving goal remains open: legacy wallet/batch arithmetic, owned
multi-AIR commitment, full-size wrap/merge/finalizer qualification, production
resource limits, sustained multi-worker throughput and AMD/Metal qualification
are unfinished. Pending Apple source still requires the authorized local Mac
checkpoint commit; no SSH was attempted.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.41 GPU join-split witness generation and explicit host-prover bridge — 2026-10-08

Join-split witness and public-value arithmetic now has an owned OpenCL path.
`DeviceSession::joinsplit_witness` accepts the raw witness and returns opaque
device matrices for the 4,096 × 19 trace and 26 public values. The kernels compute
ownership hashes, both note-commitment permutations, 32-level Merkle paths,
nullifiers, per-round Poseidon2 rows, persistent columns, position accumulators,
52-bit range columns and the global balance accumulator. The CPU AIR supplies
the layout constants; the AIR constraints, public-value order and proof format
are unchanged.

Generation uploads 3,136 bytes of raw input and public geometry and reads back
only an eight-byte validation status. Trace and public values stay on the device
until an explicit readback. Two witness kernels and one public-value kernel each
record a completed device event directly into the operation's report. A
GPU-required operation can qualify these two stages; it does not qualify the
whole wallet proof. Invalid witnesses retain their completed receipts in failed
reports, and event-observation failures prevent successful completion.

The opt-in `block_v2::leaf::prove_joinsplit_with_gpu_witness` API exercises this
path through the existing single-AIR prover and unchanged CPU verifier. It
requires an initialized bounded OpenCL engine and an explicit host allowance.
The bridge reads back 622,592 trace bytes and 208 public-value bytes and reserves
1,245,600 host bytes for both raw and decoded buffers. This allowance does not
cover downstream CPU prover memory. Reports identify the two GPU stages and an
opaque mixed upstream prover; whole-proof coverage remains incomplete. Both
`cpu-required` and `gpu-required` whole-proof policies reject the mixed route
before private work. The existing CPU leaf API remains available.

Admission also rejects insufficient host staging, wrong profiles, nonzero mint
at the leaf boundary, and any `LATTICA_V2_WORKER_BUDGET` assignment before private
allocation/upload. Public recursive worker assignments do not authorize private
wallet jobs or this host prover allocation. The complete device allocation plan
covers both outputs, inputs, geometry and status; readback checks aggregate host
allowance and session ownership. Host input staging and device scratch are
scrubbed on exit, including error paths. Private witnesses and derived traces are
not cached. Metal explicitly rejects wallet witness generation.

Evidence: [checkpoint manifest](evidence/gpu-wallet-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-wallet-20261008/run-02`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 106 cases / 58 checks / 38 native |
| Narrow release Rust | 71 cases / 41 checks / 24 native |
| Wide debug Rust | 70 cases / 40 checks / 23 native |
| CPU session regressions | 2 cases |
| Total Rust | 249 cases / 141 bounded checks / 85 native |
| Python resource/controller/worker checks | 135 cases |

Nine conformance runs compare every trace cell and public value with the CPU
reference: a standard spend, boundary values/raw keys/high Merkle positions, and
issuance arithmetic. Issuance is a witness-engine fixture only; the leaf bridge
still rejects it. Fifteen invalid witness attempts cover input/output assets,
anchors, balance and range while retaining all three GPU receipts. Tests also
check exact transfers, aggregate readback limits and cross-session rejection.
Four fresh wallet proofs through the new API verify after GPU shutdown; proof
bytes differ with fresh hiding, and modified fee/context or truncated encoding
reject. Three existing CPU leaf cases validate the shared proof/encoding tail.

The regression matrix retains 24 GPU-required recursive empty requests and eight
debug-compatible requests, cold/cached setup, and independent registered proving
checks. All 423 archived source hashes and recorded artifact hashes verify.
Seven Rust files changed since §9.40, including three new wallet modules.
Wide/narrow release, wide debug, CPU-only and GPU-only feature builds pass.
Native checks run serially on the RTX 5080 Laptop UUID ending `ee6b`, driver
`615.71.09`, with 3 GiB RAM, no swap, four CPU equivalents and 180-second service
limits. Every native fixture releases its device lease and managed allocations.
The preliminary `run-01` is preserved: its CPU leaf tests passed, but the harness
misclassified a legacy report. The final run fixes that classification and adds
the session-ownership and worker-admission controls.

Next is a device-owned single-AIR prover consuming these matrices without full
trace readback. HTLC witness generation, legacy wallet/batch integration, private
wallet worker admission, owned multi-AIR commitment and full-size recursive
qualification remain open. These checks establish correctness on the selected
NVIDIA device; they make no AMD/Metal or sustained throughput claim. Pending
Apple source still requires its authorized local Mac checkpoint commit.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.42 Owned single-AIR wallet proving and periodic quotients — 2026-10-08

The opt-in `block_v2::leaf::prove_joinsplit_on_gpu` API now proves the existing
cubic join-split wallet leaf without reading its private trace back into a host
prover. It consumes the owned witness from §9.41 in the same PCS session, then
uses GPU main/quotient commitments, hiding/randomness, transcript and grinding,
opening evaluation, FRI folding, final polynomial and query reconstruction.
Release GPU-required requests require positive completed device receipts for all
15 applicable arithmetic stages. This AIR has no lookup argument; the inventory
and execution observer omit that stage instead of claiming a fictitious lookup.

The single-AIR proof assembly follows p3-uni-stark 0.6.1's exact transcript order
and existing proof fields. The source attribution and upstream hash are recorded
in `gpu_quotient_prover/uni.rs`. Wallet encoding and the independent CPU verifier
remain unchanged. Generation reads an eight-byte validation status; the owned
handoff reads only the 208-byte public statement. The 622,592-byte private trace
stays on GPU through the release proving path. Claimed values, queried rows,
authentication paths and final proof coefficients are explicit proof output.

Wallet AIRs use 33 periodic columns, which the previous owned quotient path did
not support. The new single-AIR lowering treats their polynomials as uncommitted
auxiliary inputs to quotient evaluation. Host code copies and canonically
encodes the static AIR tables; interpolation and evaluation on the quotient
coset execute on GPU. The public AIR still declares zero preprocessed columns,
and no extra commitment or opening enters its transcript. The internal lowered
layout rejects committed preprocessing or lookup arguments and cannot alias a
preprocessed symbolic variable to a periodic input. Public periodic tables are
expanded/uploaded per attempt in this version; public setup caching remains a
possible optimization. No private witness or trace is cached.

The API requires the complete initialized owned OpenCL PCS, GPU randomness and
GPU transcript selections. Policy, profile, issuance, compiler host allowance
and public-worker assignment checks precede private work. Existing public
recursive worker assignments still do not authorize private wallet jobs.
Debug builds preserve an explicit CPU constraint audit, including its trace
readback, and reject GPU-required admission before private work. Compatible
debug reports retain that CPU observation alongside the GPU stages.

Evidence: [checkpoint manifest](evidence/gpu-uni-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-uni-20261008/run-02`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 109 cases / 61 checks / 40 native |
| Narrow release Rust | 74 cases / 44 checks / 26 native |
| Wide debug Rust | 73 cases / 43 checks / 25 native |
| CPU session regressions | 2 cases |
| Total Rust | 258 cases / 150 bounded checks / 91 native |
| Python resource/controller/worker checks | 135 cases |

Eight fresh GPU-required release wallet proofs and four compatible debug wallet
proofs verify after GPU shutdown, across wide/narrow builds and full/compact PCS
storage. Each pair has different proof bytes with fresh hiding; changed fees,
contexts and truncated encodings reject. All release reports complete the 15
GPU stages without a CPU proving observation. Four debug reports additionally
declare their CPU audit. Six invalid wallet requests retain the three completed
witness/public kernels and return no proof. Admission tests confirm rejected
policies, profiles, issuance and public-worker assignments allocate/upload no
private work. A compiler regression checks periodic lowering and conflicting
preprocessing/lookup layouts. The previous wallet trace/bridge and recursive
request regression matrices remain passing.

Native checks run serially on the RTX 5080 Laptop UUID ending `ee6b`, driver
`615.71.09`, with 3 GiB RAM, no swap, four CPU equivalents and 180-second service
limits. Owned wallet fixtures use a 1 GiB managed GPU allowance. A preserved
256 MiB pilot reached quotient commitment and returned `GpuFailure`, retaining
earlier receipts and releasing its lease/allocations; successful full-storage
logs include allocation plans above 256 MiB. This allowance is a correctness
test setting, not a calibrated production memory/throughput recommendation.
Every native fixture releases all managed GPU bytes and its device lease.

All 425 archived source hashes and recorded artifact hashes verify. Seven Rust
files changed since §9.41, including the new single-AIR prover and its tests.
Wide/narrow release, wide debug, CPU-only and GPU-only feature builds, formatting
and whitespace checks pass. Pilot logs are preserved, including an initial
incomplete test initialization. The first wide validator incorrectly expected
registry reports and CPU-RNG commitment labels from passing wallet proofs; its
manifest/log are preserved, and the corrected validator reran that check.
That run passed all runtime cases, but the evidence audit found the invalid-wallet
control disabled report output. Final `run-02` enables that control report and
rebuilds/revalidates every profile so failed-request receipts are checked directly.

The broader goal remains open: legacy quadratic wallet/batch integration, HTLC
witness/proving, private wallet worker transport/admission, owned multi-AIR
commitment, full-size recursive qualification, production resource calibration,
sustained pool throughput and AMD/Metal qualification. Host metadata, entropy
acquisition, orchestration, serialization and independent verification remain
outside proving arithmetic. Pending Apple source still requires the authorized
local Mac checkpoint commit; no SSH was attempted.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.43 Owned HTLC witness generation and typed GPU proving — 2026-10-08

The opt-in `block_v2::typed_leaf::prove_htlc_on_gpu` API now generates the HTLC
witness/public statement and completes the cubic single-AIR proof on the owned
OpenCL path. It preserves the existing typed HTLC encoding, context binding,
transcript and independent CPU verifier. Release GPU-required requests enforce
completed device receipts for all 15 applicable arithmetic stages. The HTLC AIR
has no lookup argument. Its 43 periodic columns use the GPU interpolation and
quotient evaluation introduced in §9.42.

Three kernels produce the 4096-row, 36-column trace and 31 public values. They
cover plain and HTLC note commitments, claim ownership, the four-permutation
HTLC owner chain, membership paths, mode-independent HTLC nullifiers, range and
balance columns, timeout inequalities and the nonzero-hashlock witness. The
shared wallet runner retains memory planning, private staging/scratch scrubbing,
session ownership checks and event receipts for both join-split and HTLC work.
It uploads 397 raw input words and 41 geometry words (3504 bytes), then reads an
eight-byte validation status. The proving handoff reads only the 248-byte public
statement; the private trace stays on the device in release.

The kernel validates assets, anchors, balance, ranges, input note type/mode,
claiming party, redeem/refund timeout boundaries, nonzero and shared redeemed
hashlocks, and zero mint. Output note types retain the existing AIR semantics.
SHA-256 preimage acceptance remains an external host check, and callers still
provide an independently expected block height to verification. Proving this
AIR does not replace either acceptance requirement.

Policy, profile, mint, host allowance and public-worker assignment admission
precede private allocation/upload. Public recursive worker assignments still
do not authorize private wallet jobs. Debug builds explicitly audit constraints
on CPU, reading 1,179,648 trace bytes per proof, and reject GPU-required admission
before private work. Compatible debug reports include that CPU observation.

Evidence: [checkpoint manifest](evidence/gpu-htlc-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-htlc-20261008/run-01`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 113 cases / 65 checks / 43 native |
| Narrow release Rust | 78 cases / 48 checks / 29 native |
| Wide debug Rust | 77 cases / 47 checks / 28 native |
| CPU session regressions | 2 cases |
| Total Rust | 270 cases / 162 bounded checks / 100 native |
| Python resource/controller/worker checks | 135 cases |

Across the three profiles, 18 valid fixtures compare every GPU trace cell and
public value against the CPU implementation. They include plain, redeem,
refund, maximum range boundaries, raw field-key boundaries and two redeemed
inputs. All 42 invalid engine witnesses retain three completed kernel receipts.
Six invalid complete requests likewise preserve their witness/public receipts
and return no proof.

Sixteen GPU-required release HTLC proofs and eight compatible debug HTLC proofs
verify after GPU shutdown, across full/compact PCS storage and wide/narrow
release plus wide debug builds. Each storage/profile fixture includes a redeem,
a fresh repeat redeem, a refund and a two-HTLC-input redeem. Fresh hiding changes
proof bytes; redeem/refund retain the same first HTLC nullifier. Modified
nullifier, hashlock, height, fee, context, independently expected height and
truncated encodings reject. Existing owned join-split, mixed bridge, registered
and recursive request regressions remain passing.

Native checks run serially on the RTX 5080 Laptop UUID ending `ee6b`, driver
`615.71.09`, under 3 GiB RAM, no swap, four CPU equivalents and 180-second service
limits. Complete HTLC fixtures use a 1 GiB managed GPU allowance. Every native
fixture releases its managed allocations and device lease. These are correctness
and coverage checks; production memory and transactions per hour remain
unqualified. AMD and Metal were not tested.

All 428 archived source hashes and recorded artifact hashes verify. Nine Rust
files changed since §9.42, including three new HTLC modules. Wide/narrow release,
wide debug, CPU-only and GPU-only builds, formatting and whitespace checks pass.
The first build found a test-only variable shadowing error; its log is preserved.
After scoping that binding, all three pilot runtime checks passed without kernel
changes. The complete regression matrix uses a separate artifact directory and
preserves the §9.42 evidence.

Remaining work includes legacy quadratic wallet/batch integration, private
wallet worker transport/admission, owned multi-AIR commitments, full-size
recursive qualification, production resource calibration, sustained pool
throughput and AMD/Metal qualification. Host metadata, entropy acquisition,
orchestration, serialization, independent verification and external preimage
acceptance remain outside proving arithmetic. Pending Apple source still needs
its authorized local Mac checkpoint commit; no SSH was attempted.

This checkpoint remains uncommitted on `main`; the overall GPU proving goal is active.

### 9.44 Owned issuance proving and candidate wallet entrypoint routing — 2026-10-08

The maintained candidate join-split, HTLC and issuance `*_with_request` APIs now
select the owned prover when the complete OpenCL PCS, quotient, randomness and
transcript path has been explicitly initialized. Their `*_research` wrappers
carry the environment-derived request through the same selection. Compatible
and GPU-required requests use that owned path; its admission still rejects
CPU-required requests and GPU-required debug proving. Other selections retain
their existing policy checks. Merely compiling GPU support does not select it.
The legacy quadratic Rust/C ABI routes and all proof encodings remain unchanged.

`block_v2::typed_leaf::prove_issuance_on_gpu` adds the missing owned typed
issuance path. It reuses GPU join-split witness/public generation and the owned
single-AIR prover with the existing issuance AIR/context and encoding. The
nonzero, in-range authorized mint must match the witness before private work;
the GPU-produced public mint is checked against that authorization again before
proving. External host policy still determines mint authority and issuance
count. The proof API does not grant either permission. Ordinary join-split and
HTLC routes continue to reject issuance, and public recursive worker assignments
do not authorize these private wallet jobs.

Backend selection persists after engine shutdown. A new resident-engine guard
rejects selected-but-retired wallet requests with `GpuFailure` before the
infallible profile constructor can run. Strict and compatible requests both
return without reinitializing the GPU or falling through to CPU proving.

Evidence: [checkpoint manifest](evidence/gpu-issuance-2026-10-08.json) and
`lattica-prover-p3/benchmark-results/gpu-issuance-20261008/run-01`.

| Validation | Passing cases/checks |
| --- | ---: |
| Wide release Rust | 120 cases / 69 checks / 46 native |
| Narrow release Rust | 81 cases / 51 checks / 32 native |
| Wide debug Rust | 80 cases / 50 checks / 31 native |
| CPU session regressions | 2 cases |
| Total Rust | 283 cases / 172 bounded checks / 109 native |
| Python resource/controller/worker checks | 135 cases |

Across full/compact storage and the three profiles, 42 additional candidate
wallet proofs independently verify after GPU shutdown: 18 issuance, 12 join-split
and 12 HTLC proofs. Of these, 28 release proofs require all 15 applicable GPU
arithmetic receipts and 14 compatible debug proofs additionally declare CPU
constraint audits. All six maintained request/research entrypoints are exercised,
along with direct GPU issuance. Nine issuance fixtures compare every GPU trace
cell/public value with the CPU at mint amounts 1, 17 and `2^52 - 1`. Six unbalanced
issuance requests return no proof and retain three completed witness/public
kernel receipts. Existing join-split, HTLC, registered and recursive regressions
remain passing; four CPU typed-wallet tests also preserve the unselected path.

Fresh repeats produce different proof bytes. Wrong authorized amounts, changed
nullifiers/output commitments/fees/mint/transaction binding, relabeled chain
contexts, truncation and issuance/join-split kind substitution reject. Admission
checks cover policy, profile, zero/mismatched/out-of-range authorization, issuance
through spend/HTLC routes and public-worker assignments without private
allocation/upload. Private traces stay on GPU in release; handoff reads 208
public bytes for join-split/issuance or 248 for HTLC. Debug audits explicitly read
622,592 or 1,179,648 private trace bytes respectively. HTLC preimage acceptance
and independently expected block height remain external requirements.

Native tests run serially on the RTX 5080 Laptop UUID ending `ee6b`, driver
`615.71.09`, in 3 GiB zero-swap services with four CPU equivalents and a 180-second
runtime limit. Complete wallet fixtures use a 1 GiB managed GPU allowance. Every
native fixture releases its allocations and device lease. Wide/narrow release,
wide debug, CPU-only and GPU-only builds, formatting and whitespace checks pass.
All 429 archived source hashes and artifact hashes verify; three Rust files
changed since §9.43, including the new native entrypoint/issuance tests.

The preserved first pilot generated seven proofs but failed a fixture assumption
that shutdown clears selection. That exposed the need for the live-engine guard;
the corrected pilot CPU-verifies all seven proofs and checks retired requests.
Two wide validator records initially confused a proof-type count with a Rust
test count. Their original manifest/runner are preserved; metadata was corrected
against unchanged hashed test logs, and the final audit independently reparses
every result. Earlier checkpoint evidence remains unchanged.

The broader goal remains active: legacy quadratic wallet/batch and C ABI GPU
integration, owned multi-AIR commitments, full-size recursive qualification,
private wallet worker admission, resource calibration, sustained transactions
per hour and AMD/Metal qualification remain unfinished. These correctness checks
do not establish throughput. Pending Apple source still needs its authorized
local Mac checkpoint commit; no SSH was attempted. Changes remain uncommitted
on `main`.


### 9.45 Generalized GPU FRI and final-polynomial interpolation — 2026-10-08

The owned FRI driver now shares an implementation for the pinned quadratic
extension (`u² = 7`) and the existing cubic extension. It supports fold arities
2, 4, 8 and 16, follows Plonky3's schedule without skipping the next input height,
and binds each actual arity into the transcript. Grouped commitment leaves are
immutable views of session-owned GPU matrices. Query siblings and cumulative
index shifts follow the selected arities. The maintained candidate prover keeps
its existing stricter binary/cubic admission and specialized binary kernels;
no pinned protocol parameters or proof encodings changed.

Larger folds and their beta-powered input mixing execute on GPU. A constant
final polynomial reads only its first value. Nonconstant final polynomials use
GPU reordering, inverse NTT and normalization, then read only the final
coefficients. The host supplies immutable inverse roots (`8 * log_final_len`
bytes), not private layer values. Ownership, extension basis, challenge encoding,
domain geometry and output allowances are checked before the corresponding
operation. The research driver bounds input log height at 25, maximum log arity
at 4 and final-polynomial log length at 16.

Standalone FRI reports use `operation` scope with explicit randomness,
commitment, fold, query, final-polynomial, transcript and grinding observers.
Nonconstant final polynomials also require a transform receipt. They do not
claim a PCS scalar stage that the component never executes. Every required
stage must have actual GPU calls and positive event time before strict
completion can release the result. These component checks also run under
`gpu-required` in debug; full STARK debug proofs retain their explicit CPU
constraint audits and existing policy admission.

Validation uses the selected RTX 5080 Laptop GPU only, under the existing serial
3 GiB RAM / zero-swap / four-CPU / 180-second service limits. Complete wallet
regressions retain their 1 GiB managed GPU allowance. All five build checks pass:
wide and narrow release, wide debug, CPU-only library and GPU-only library.
The final run passes **295 Rust cases across 184 bounded checks, including 121
native checks**, plus **135 Python worker/controller/resource cases**.

- Device arithmetic matches upstream CPU folds and mixing for both extensions,
  all supported arities, input log heights 1, 4, 5, 9 and 14, and zero, one,
  nontrivial and large-coefficient challenges. Final-polynomial comparisons
  cover log lengths 0, 1, 3, 7 and 12. Transfer checks distinguish immutable
  parameter uploads from final-coefficient readback.
- **36 generalized FRI component proofs** CPU-verify after GPU shutdown: 18
  quadratic and 18 cubic, including 12 with nonconstant final polynomials.
  Each extension/build combination covers `(input log height, max log arity,
  final log length)` of `(10,1,0)`, `(10,2,0)`, `(10,3,0)`, `(10,4,0)`,
  `(12,4,3)` and `(16,4,8)`.
- Proof bytes match the upstream prover using the same independently checked
  proof-of-work witnesses. Upstream's parallel CPU grinder may select a
  different valid nonce, so the reference checks and replays GPU witnesses
  before comparison. The unchanged CPU verifier subsequently rejects modified
  final coefficients, FRI siblings and claimed openings.
- Existing resident FRI, candidate issuance/join-split/HTLC, recursive,
  strict-completion, worker-admission and resource checks remain in the matrix.
  Historical query-prefix transfer telemetry is retained, with an
  extension-aware final-coefficient byte count.

These are FRI component proofs from public CPU-generated reduced-input
fixtures. Their input-matrix openings come from the independent CPU fixture
outside the GPU operation. They do **not** qualify an end-to-end legacy
quadratic STARK/PCS GPU prover. Larger cubic arities and nonconstant final
polynomials are isolated research configurations, not changes to the maintained
candidate protocol.

Evidence: [generalized FRI validation](evidence/gpu-general-fri-2026-10-08.json).
The final artifacts are in
`lattica-prover-p3/benchmark-results/gpu-general-fri-20261008/run-02`.
All 433 source hashes and the source archive are checked, with an exact
12-file diff from §9.44. Earlier build/pilot failures and the first qualification
run remain preserved. They exposed an OpenCL address-space mismatch, differing
valid CPU/GPU PoW nonces, a missing inverse-transform receipt, and dropped
query-transfer telemetry. A separate pool temporarily held the laptop GPU;
it was left running and qualification resumed after its lease was released.
The §9.42–§9.44 artifact hashes were rechecked without modifying those records.

Next is legacy quadratic witness/quotient/opening and whole-STARK/PCS integration.
Private wallet worker transport/admission, batch and C ABI integration, owned
multi-AIR commitments, full-size recursive qualification, resource calibration,
sustained transaction throughput and AMD/Metal qualification remain unfinished.
Host entropy acquisition, metadata, orchestration, serialization, independent
verification and external mint/HTLC acceptance remain host responsibilities.
Pending Apple source still requires its authorized local Mac checkpoint commit;
no SSH was attempted. This checkpoint remains uncommitted on `main`, and the
overall GPU proving goal remains active.

### 9.46 Quadratic/cubic owned PCS openings and GPU input queries — 2026-10-08

The owned opening driver now evaluates and reduces retained GPU prefixes for
both the pinned quadratic extension (`u² = 7`) and the existing cubic extension.
It passes the resulting device vectors directly to generalized FRI and produces
all initial input-matrix query openings from the retained GPU commitments.
This closes the CPU input-opening boundary in the §9.45 component fixtures.
The maintained candidate path continues to use its existing cubic parameters;
no protocol parameters, transcript rules or proof encodings changed.

Device openings and accumulators carry their extension explicitly. Compact
challenge/value buffers use two or three coefficients as appropriate. The new
quadratic kernels include a 128-lane product-tree batch inverse; existing cubic
kernels remain in use. Point encoding, extension degree, session ownership,
output allowance and allocation limits are checked at the device boundary.
Cross-extension append rejects and retires the consumed accumulator before any
kernel work. Denominator-zero failures on both the initial and expanded cosets
release their allocations. Opening evaluation reads back claimed values and
control status; prefixes and reduced FRI vectors stay on GPU.

The standalone `gpu_owned_extension_pcs` operation requires exactly nine stages:
randomness, transform, commitment, opening, FRI fold, FRI query, final polynomial,
transcript and grinding. Separate opening/FRI observers avoid counting the same
device event twice. Each required stage must have positive device calls and
event time, with no observation errors, before strict completion releases the
result. These component checks use `gpu-required` in release and debug. Whole
STARK debug proofs retain their explicit CPU constraint audits.

Qualification used only the NVIDIA RTX 5080 Laptop GPU
`GPU-9ccf62bc-bc19-a667-4803-d3bce901ee6b`, driver `615.71.09`. Every native
service ran serially with a 3 GiB host memory cap, no swap, four CPU cores, a
180-second runtime limit and control-group cleanup. Complete wallet regressions
retain their 1 GiB managed GPU allowance.

| Build | Rust cases | Bounded checks | Native checks |
| --- | ---: | ---: | ---: |
| Wide release | 133 | 80 | 56 |
| Narrow release | 94 | 62 | 42 |
| Wide debug | 93 | 61 | 41 |
| CPU session checks | 2 | 2 | 0 |
| Total | 322 | 205 | 139 |

All **135 Python cases** also pass. The matrix includes:

- **36 complete owned PCS opening proofs**, 18 quadratic and 18 cubic, verified
  with the upstream CPU PCS after GPU shutdown. Both full and compact storage
  run in all three build profiles, including compact direct/parallel readback.
  Each combination covers three sets of commitment rounds with mixed widths,
  multiple matrices, multiple input heights and repeated opening points.
- Exact claimed-value and proof-byte comparisons against upstream
  `TwoAdicFriPcs`. The CPU reference independently validates and replays GPU
  proof-of-work witnesses, since parallel CPU grinding can find a different
  valid nonce. Modified claimed values and input query openings fail verification.
- Independent CPU Horner evaluation and reduction formulas for both fields,
  log heights through 13, 1–32 points, multiple shifts, Goldilocks boundary
  values, zero/nontrivial alpha, tile limits and allocation recovery. Foreign
  sessions, mismatched extensions/decoders, malformed challenges and insufficient
  output allowances reject.
- Zero prefix upload/readback and zero reduced-FRI-vector readback in every
  combined PCS fixture. Input queries are produced by the GPU operation; no
  CPU input proof is attached afterward.
- The 36 generalized FRI component proofs from §9.45 and existing candidate
  wallet, recursive, strict-completion, worker-admission and resource regressions.

Evidence: [owned PCS validation](evidence/gpu-quadratic-opening-2026-10-08.json).
Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-quadratic-opening-20261008/run-01`.
All 436 source hashes and the source archive verify, with an exact 14-file diff
from §9.45. The first test build needed a missing trait import and a borrowed
coefficient slice.
The first two PCS pilots rejected fixture initialization that did not satisfy
resident MMCS admission. The corrected third pilot passes all seven checks;
production admission guards were preserved. Earlier build/pilot logs remain
archived, and all §9.42–§9.45 artifact hashes were rechecked unchanged.

This qualifies the owned two-adic PCS opening component. Its public base
evaluations and opening points are test inputs supplied outside the operation.
The complete legacy quadratic hiding PCS/STARK adapter, witness/quotient
integration and scalar next-point handling remain unfinished. The next step is
quadratic quotient evaluation, followed by generic resident/hiding PCS
configuration and legacy wallet whole-proof checks. GPU base-field witness
builders already used by the candidate wallet path may be reusable.

Private wallet worker transport/admission, batch and C ABI integration, owned
multi-AIR commitments, full-size recursive workloads, sustained throughput,
resource calibration and AMD/Metal qualification remain open. No transaction
throughput claim follows from these correctness fixtures. Pending Apple source
still requires its authorized local Mac checkpoint commit. Work remains
uncommitted on `main`, and the overall GPU proving goal remains active.

### 9.47 Quadratic/cubic GPU quotients, hiding commitments and scalar points — 2026-10-08

Owned quotient evaluation now supports the pinned quadratic extension (`u² = 7`)
alongside the existing cubic extension. Compiled programs carry their extension;
row/parameter offsets, alpha weights, register scratch and output allocations
use its actual degree. A shared OpenCL evaluator is instantiated for each field,
preserving global constraint order, selectors and division by the trace
vanishing polynomial. Cubic compatibility entry points reject a program for
another extension.

Both direct evaluation and bounded coset partition/interleave keep input
matrices and quotient values on GPU. The generic owned adapter checks the
program/challenge pairing before preparing work. Partitioned evaluation also
checks owners, layouts and canonical parameters before expansion. Domain
descriptors, immutable transform roots and validation status remain host-visible;
these are distinct from witness/quotient matrix transfers.

Quotient hiding commitments now derive their value-column count from the
extension. Quadratic commitments use two value columns plus the existing four
random codewords; cubic commitments retain three plus four. The hiding masks,
salt order, cap height, proof encoding and protocol parameters are unchanged.
The GPU randomness path generates and consumes both masks and salts without
sample uploads or readback. Scalar next-row derivation also accepts compact
quadratic values, including through the challenger adapter, without absorbing
additional transcript data.

Qualification used only the RTX 5080 Laptop GPU
`GPU-9ccf62bc-bc19-a667-4803-d3bce901ee6b`, driver `615.71.09`. Native services ran
serially with 3 GiB host memory, no swap, four CPU cores, a 180-second limit and
control-group cleanup. Complete wallet regressions retain their 1 GiB managed
GPU allowance.

| Build | Rust cases | Bounded checks | Native checks |
| --- | ---: | ---: | ---: |
| Wide release | 151 | 91 | 64 |
| Narrow release | 112 | 73 | 50 |
| Wide debug | 111 | 72 | 49 |
| CPU session checks | 2 | 2 | 0 |
| Total | 376 | 238 | 163 |

All **135 Python cases** pass, as do CPU-only and GPU-only library checks,
changed-file formatting and whitespace checks. The matrix includes:

- **96 quotient arithmetic/commitment comparisons**, 48 per field, plus
  **12 generic owned-adapter comparisons**. Every field/build combination
  covers `(trace log height, quotient log height, shift)` of `(0,3,7)`,
  `(3,6,11)`, `(5,9,7)` and `(10,13,11)`, in direct and partitioned modes with
  zero and nonzero alpha. Mixed base/extension constraints exercise local/next
  main, preprocessing and permutation rows, public values, challenges,
  terminals, constants, all selectors and global folding order. Independent
  CPU field formulas check every output value. In the 96 pipeline cases, GPU
  commitments consume the quotient before value readback, and their caps/query
  paths match CPU results. The 12 additional adapter cases read final values
  for comparison without adding another commitment.
- **48 hiding-commitment comparisons**, 24 per field, across full/compact storage
  and all three builds. An independent upstream CPU `HidingFriPcs` uses matching
  deterministic test streams. All caps and GPU-owned query openings match;
  the CPU MMCS verifies each query. Smaller fixtures also compare every retained
  prefix value. Shapes cover `(chunk height, chunk count, shift)` of `(8,2,7)`,
  `(32,4,11)`, `(64,16,7)` and `(8192,2,11)`. Invalid owners, domains and
  partitions reject before advancing the hiding/salt streams.
- Compact next-point checks at every domain log size from **0 through 32**,
  zero and field-boundary values, invalid encodings and empty challenger
  requests. CPU/GPU challenger comparisons confirm subsequent transcript
  samples are unchanged. Planner checks cover the two-coefficient allocation
  boundary and compiler row/parameter/constant encodings.
- The existing **36 owned PCS opening proofs**, **36 generalized FRI proofs**,
  candidate wallet, recursive, worker-admission and strict-completion
  regressions. Their CPU verification after GPU shutdown and receipt checks
  remain in the matrix. Debug whole-STARK proofs retain their explicit CPU
  constraint audits.

Evidence: [quadratic/cubic quotient validation](evidence/gpu-quadratic-quotient-2026-10-08.json).
Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-quadratic-quotient-20261008/run-01`.
All 438 source hashes, 289 final artifact hashes and 45 preliminary artifact
hashes verify, with an exact 17-file diff from §9.46. All 1,271 archived artifact
hashes from §9.42–§9.46 also verify unchanged.

Early builds exposed API-name and generic test-bound mistakes. The hiding
fixtures then exposed three obsolete assumptions: a resident PCS could serve
as a CPU oracle under device-only policy, opening consumers could be omitted
before GPU randomness, and the result would contain host-retained matrices.
The fixtures now use the upstream CPU oracle, explicit owned consumers and the
device-only query comparator. Production admission guards were preserved.
The fifth pilot passes the affected hiding checks, quadratic PCS checks and
candidate wallet regressions; the final matrix qualifies the complete source.

These are component checks starting from public test matrices. They do not yet
qualify complete legacy quadratic STARK proofs. Next is generic resident/hiding
PCS and opening configuration, then legacy wallet witness integration and
whole-proof CPU verification. Quadratic lookup generation where required,
legacy batch/C ABI delivery, private wallet worker admission, owned multi-AIR
commitments and full-size recursive workloads remain unfinished.

No sustained transaction-throughput, resource calibration or AMD/Metal
qualification follows from these correctness checks. Pending Apple source
still requires its authorized local Mac checkpoint commit. Changes remain
uncommitted on `main`, and the overall GPU proving goal remains active.

### 9.48 Generic resident hiding PCS for quadratic and cubic profiles — 2026-10-08

`CandidatePcs<E>` and its resident hiding state now support both pinned fields,
with the cubic candidate as the default. Reference PCS types, opening values,
randomization widths and extension-trace commitment geometry use the selected
field. A sealed field interface pins quadratic FRI to 96 queries and maximum
arity 16, while retaining the candidate's 128-query binary admission. The
legacy `config.rs` protocol definitions and proof encoding remain unchanged.

Owned quadratic openings use the generalized GPU FRI prover; cubic openings
retain their existing strict binary implementation. GPU trace masking now
accepts quadratic coefficient layouts as well as base and cubic traces.
Quotient commitments reject a buffer from the wrong field before drawing masks
or salts. Constructor checks also reject a zero or greater-than-32-GiB host
output allowance before backend admission. Existing equal-height resident
batch admission remains in place.

The explicitly selected quadratic host-opening path delegates full LDE
matrices to upstream PCS while sharing the active FRI salt stream. It rejects
compact prefixes before attempting the full-matrix interface. Device-only
proving retains its owned-consumer requirements and cannot select this host
path. Active PCS clones continue to share their attempt and randomness streams.

Qualification used only RTX 5080 Laptop GPU
`GPU-9ccf62bc-bc19-a667-4803-d3bce901ee6b`, driver `615.71.09`. Native checks ran
serially with a 3 GiB host cap, zero swap, four CPU workers and a 180-second
service limit. Complete wallet regressions retained a 1 GiB managed GPU
allowance. CPU-only and GPU-only library builds also passed.

| Build | Rust cases | Bounded checks | Native checks |
| --- | ---: | ---: | ---: |
| Wide release | 159 | 99 | 70 |
| Narrow release | 120 | 81 | 56 |
| Wide debug | 119 | 80 | 55 |
| CPU session checks | 2 | 2 | 0 |
| **Total** | **400** | **262** | **181** |

The new validation covers **36 complete hiding PCS proofs**, 18 quadratic and
18 cubic, across full/compact selections and three build profiles. Each case
commits a randomization polynomial, base traces and flattened extension traces.
Three geometries exercise single/multiple matrices, equal-height batches,
different heights across rounds, and successive commitments through active
clones. All input caps, opened values, hidden values, exact upstream proof bytes
and subsequent transcript samples match. GPU PoW witnesses are independently
checked on CPU before replay for deterministic byte comparison. After GPU
shutdown, the CPU verifier accepts each proof and rejects altered claimed
values and input query rows.

Every GPU PCS case requires complete receipts for nine operation stages,
including in debug. Prefixes and reduced FRI vectors have zero uploads/readbacks;
hiding masks and salts are generated on GPU. The input matrices are public
fixtures uploaded before the observed opening operation. Six additional
explicit host-mode PCS proofs check repeated opening stream continuity and
CPU verification after shutdown; three compact-host checks verify rejection.
These compatibility checks are separate from GPU stage coverage.

Existing quotient, owned-opening, generalized FRI, candidate wallet, recursive,
session, worker-admission and completion regressions remain in the matrix.
Debug complete-STARK regressions retain their explicit CPU constraint audits.
No Python source changed; this checkpoint does not rerun or add to the previous
Python test count.

Evidence: [resident hiding PCS validation](evidence/gpu-resident-generic-2026-10-08.json).
Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-resident-generic-20261008/run-01`.
All 441 current source hashes match the archive, with
an exact 11-file diff from §9.47.
The 305 final artifact hashes,
47 preliminary artifact hashes and
1,605 prior checkpoint artifact hashes verify. Early fixture and admission
corrections are retained in the pilot records. One evidence-checker label was
corrected by revalidating the successful original proof log without repeating
the native run; its original record is preserved.

These are PCS proofs, not complete legacy quadratic wallet STARK proofs. Next
is the generic single-AIR GPU prover and legacy wallet configuration/witness
integration, followed by complete legacy proof verification after GPU shutdown.
Quadratic lookup generation where required, legacy batch/C ABI delivery,
private wallet worker admission, owned multi-AIR commitments and full-size
recursive workloads remain unfinished. Sustained throughput, resource
calibration and AMD/Metal qualification remain open. Pending Apple source
still requires its authorized local Mac checkpoint commit. Changes remain
uncommitted on `main`, and the overall GPU proving goal remains active.

### 9.49 Legacy quadratic wallet proving and native ABI delivery on GPU — 2026-10-08

The existing legacy join-split and HTLC Rust APIs and four single-wallet C ABI
entrypoints now use the complete owned GPU path when it is explicitly selected.
GPU-generated private traces stay on the device through quotient evaluation,
hiding commitments, opening and FRI. GPU-produced public values also feed the
native ABI, avoiding CPU public-input recomputation. The unchanged CPU verifiers
accept the resulting `postcard(Proof<config::MyConfig>)` bytes after GPU shutdown.
Default CPU selection and the existing proof/public-input wire formats remain.
The native checks first initialize the resident backend through the existing
Rust API in the same process. An exported native GPU initialization/lifecycle API
is still needed for standalone C callers; this checkpoint does not add one.

The single-AIR prover and configuration factory now support both sealed PCS
fields. Legacy quadratic proving retains 96 FRI queries and maximum log arity 4;
the cubic candidate profile keeps its existing parameters. A base-only symbolic
conversion preserves constraint order and rejects extension expressions or
extension indices before changing fields. Legacy mint semantics, including the
maximum allowed mint, remain intact; the candidate zero-mint rule is not applied.

The native entrypoints `lattica_joinsplit_prove`, `lattica_htlc_prove` and their
`_demo` variants share GPU-aware admission and contain proving panics. Admission
rejects CPU-required requests, unsupported private worker assignments and
insufficient host budgets before proving. Invalid policies and malformed host
budgets leave native output buffers and lengths untouched. Retired engines reject
without CPU fallback. Batch and recursive ABI routing are unchanged.

Qualification produced **72 complete legacy wallet proofs**: 48 through Rust and
24 through the C ABI, covering full and compact storage in wide release, narrow
release and wide debug builds. The **48 release proofs require GPU completion**;
the 24 debug proofs explicitly retain CPU constraint audits. Proof serialization
and host orchestration remain CPU work. Both AIRs have no lookup argument.

Fixtures cover ordinary join-split spends, fresh repeated witnesses, mint 17 and
maximum mint, plus HTLC ordinary spend, redeem and refund. All proofs verify
through unchanged CPU APIs after GPU shutdown. Wrong public inputs, trailing
proof bytes and altered query rows reject. Each proof transfers only public
values at the witness handoff: 208 bytes for join-split and 248 bytes for HTLC,
with no private full-trace handoff. Hiding samples and query prefixes stay on GPU.

All **415 Rust test executions**, **274 bounded checks** and **193
native checks** pass. The matrix retains candidate-wallet, quadratic/cubic PCS,
quotient, generalized FRI, recursive-session, worker-admission and completion
regressions. CPU-only and GPU-only library builds also pass. Native checks use
only the authorized RTX 5080 Laptop GPU and bounded serial services; complete
wallet checks retain the 1 GiB managed GPU allowance.

The evidence includes 443 source hashes, the exact 11-file source delta from
§9.48, archived binaries/logs/runners and verification that prior checkpoint
artifacts remain unchanged. Two result-checker corrections were applied by
revalidating successful saved logs without native re-execution: explicit CPU
serialization/actual storage flags, and the prior hiding-PCS log-label fix.
Both original records and the relevant runners are preserved.

Evidence: [`gpu-legacy-wallet-2026-10-08.json`](evidence/gpu-legacy-wallet-2026-10-08.json).
Reproducible local artifacts:
`lattica-prover-p3/benchmark-results/gpu-legacy-wallet-20261008/run-01`.
Work remains uncommitted on `main`.

The overall GPU proving goal remains open. Next work includes legacy batches,
private wallet worker admission, quadratic lookup generation where required,
native GPU initialization/lifecycle, owned multi-AIR commitments and full-size
recursive workloads. These correctness
fixtures establish no sustained transaction-throughput or AMD/Metal result.
Resource calibration and the authorized local Mac source checkpoint also remain
outstanding; no SSH retrieval was attempted.

### 9.50 Legacy batch proving, GPU periodic setup and 32-chunk quotients — 2026-10-08

Legacy join-split and HTLC batch proving now use the complete owned GPU path
when selected, through both Rust and the two native batch proving entrypoints.
The existing CPU verifiers and proof/root wire formats are unchanged. Raw wallet
inputs enter the GPU; private traces, padding, statement folds and the batch root
remain there through proving. Only the four-field public root (32 bytes) crosses
the witness handoff before proof/root serialization.

Batch assembly uses the AIR's own staged-column and ordered chunk layout. The
GPU generates each wallet trace and reuses one GPU-generated canonical dummy
trace for padding. It copies the tile columns, evaluates the Poseidon statement
and root chains, and supplies the final permutation output as the public root.
The complete assembly peak includes the destination, root, layout and one wallet
generator before any witness is uploaded. Trace comparisons now cover counts
**0, 1, 3, 4 and 64** for both AIRs, including the maximum protocol tile count.

Periodic setup now uploads compact static columns and expands their repetitions
on the GPU before GPU interpolation and coset evaluation. This removes host
table expansion and gives preprocessing an actual device receipt. Mixed period
lengths, canonical field limits, empty/invalid lengths and aggregate host staging
limits are checked. Expanded tables are neither uploaded nor read back in the
proving path; the CPU encodes only static source columns and metadata.

HTLC batches require **32 quotient chunks**. Two old commitment/storage guards
incorrectly tied chunk count to the 16x LDE blowup; they now share the compiler's
existing 32-chunk bound. The 2 GiB per-chunk and 32 GiB aggregate quotient heap
limits remain. The FRI parameters, LDE blowup, legacy security floor and maximum
batch size are unchanged. Independent quadratic/cubic commitment checks now
include 32 chunks, preserving CPU matrices/caps/openings and random-stream order.

Qualification produced **72 complete batch proofs**: 48 through Rust and 24
through the C ABI, across both storage modes and three build profiles. All verify
with the unchanged CPU APIs after GPU shutdown. The **48 release proofs require
GPU completion**; the 24 debug proofs retain explicit CPU constraint audits.
Proof fixtures include empty Rust batches, one transaction and three transactions
padded to four, with repeated batches producing fresh hiding. Join-split minting
semantics and HTLC's zero-mint rule remain intact. Wrong roots, trailing bytes,
damaged proofs, invalid balances, unsupported private workers, invalid counts,
malformed policies/budgets and retired engines are covered.

All **433 Rust test executions**, **292 bounded checks** and **208
native checks** pass, alongside CPU-only and GPU-only library builds. The matrix
retains 72 legacy single-wallet proofs, candidate-wallet and recursive-session
regressions, 36 GPU hiding PCS proofs, and 60 quotient commitment comparisons.
Thirty batch trace/root comparisons include 64-tile assembly. Work stays on the
authorized RTX 5080 Laptop GPU, in serial services with 3 GiB host memory, zero
swap, four CPU threads and a 180-second limit. Complete wallet and batch checks
retain the **1 GiB managed GPU allowance**.

The evidence archives 448 current source inputs and the exact 22-file delta from
§9.49. Earlier pilots and both failed qualification attempts remain intact. The
first exposed a stale assumption that 32 chunks were invalid; the second exposed
a counter still expecting four cases after the 32-chunk fixture added a fifth.
The rejection fixture now uses 64, and the count derives from the fixture array.
The final matrix uses fresh matching source and binaries. Previous checkpoint
artifacts remain unchanged.

Evidence: [`gpu-legacy-batch-2026-10-08.json`](evidence/gpu-legacy-batch-2026-10-08.json).
Reproducible local artifacts:
`lattica-prover-p3/benchmark-results/gpu-legacy-batch-20261008/run-03`.
Work remains uncommitted on `main`.

Complete proof fixtures reach four padded tiles; **complete 64-tile proofs and
sustained throughput/capacity remain unqualified**, despite the verified 64-tile
trace assembly. Remaining work includes standalone native GPU initialization,
private worker admission, tree/recursive native delivery, quadratic lookup
generation where required, owned multi-AIR commitments and larger recursion.
AMD/Metal qualification and the authorized local Mac source checkpoint are also
outstanding. No SSH retrieval was attempted.

### 9.51 Native GPU lifecycle and standalone C delivery — 2026-10-09

Native callers can now initialize, drain and shut down the complete legacy GPU
prover without a Rust startup shim. The public header exposes three process-local
functions, all returning `int32_t`: `lattica_gpu_initialize_from_env`,
`lattica_gpu_drain` and `lattica_gpu_shutdown`. Status **0** means success, **1**
means rejection and **2** means the build lacks the required `block-v2,gpu`
features. Unsupported builds retain all three symbols and do not initialize GPU
state. Existing proving entrypoints, proof encodings, public values and CPU
verifiers are unchanged.

Startup requires an explicit GPU UUID, a positive managed GPU byte allowance,
the complete owned-path switches, a valid proving policy and sufficient host
output allowance. Environment policy values use hyphens (`gpu-required`,
`cpu-required`); report JSON uses underscores. Private worker assignments reject
before initialization. Resident settings are checked together before any new
immutable setting is recorded. Startup configures quotient evaluation, the GPU
engine and resident commitments, then admits the complete legacy wallet path.

Lifecycle calls are serialized and catch panics inside the lifecycle lock so
later recovery remains possible. Failed or panicking startup retires only an
engine it created; a borrowed live engine survives. A live engine records its
UUID and OpenCL index selectors and rejects changed selectors before selecting
another device or allocating. Drain requires a live engine. Shutdown rejects
retained device sessions or commitments, is idempotent after cleanup, and keeps
GPU selection active so later proving rejects until reinitialization.

Each of six native lifecycle checks exercises **11 rejected initializations**,
**two startup rollbacks**, **two borrowed-engine preservation cases**, and **two
changed-device rejections**, plus retained-session protection and reinitialization.
Panic-boundary unit checks pass in all three GPU build profiles. Separate CPU-only
unit checks cover panic recovery and unavailable exports.

The standalone `tests/gpu_lifecycle.c` caller links the Rust static library and
uses only the public C header. Each process initializes twice, proves a join-split
demo, an HTLC demo and both three-record batch fixtures, then drains and shuts
down. It CPU-verifies all four proofs after shutdown, checks that rejected retired
proving preserves caller buffers, reinitializes and proves the join-split demo
again. Repeated public inputs match and proof bytes are fresh; the fifth proof
also CPU-verifies after shutdown.

The standalone matrix produces **30 complete C proofs** across wide release,
narrow release and wide debug, in full and compact storage. **20 release proofs
require GPU completion**; the ten debug proofs record CPU constraint audits.
Witness handoffs contain public values only, with no private trace readback.
Trace and quotient hiding samples remain on GPU. CPU-only and GPU-only builds
return unavailable for all lifecycle exports, and the header passes C++17 syntax
checking.

The retained regression matrix passes **442 Rust executions in 301 bounded
checks**, including **214 native GPU checks**. It includes 72 legacy single-wallet
proofs, 72 legacy batch proofs and the previous quotient, PCS, FRI, candidate
wallet, recursive-session and admission checks. The 30 standalone C proofs are
additional. A separate compatibility run passes eight checks, including two
CPU-only Rust cases; these are not folded into the 442-case regression count.

The user confirmed that the current host now uses the **desktop NVIDIA GeForce
RTX 5080**, UUID `GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`, driver 615.71.09.
Final qualification explicitly selects that device. Historical laptop runs are
preserved separately. Builds and tests remain serial, with **3 GiB host memory,
zero swap, four CPU threads, 180-second per-service limits and no core dumps**.
Complete wallet and native proof checks retain the **1 GiB managed GPU allowance**.

Evidence archives **453 source inputs** and the **11-file change/inventory delta**
from §9.50, including the newly inventoried C header and fixture. Earlier pilots,
the superseded laptop wide-release run, the unexecuted failed device-snapshot
attempt and the compatibility run remain intact. Source archives, exact binaries,
test commands and logs are hashed; all recorded artifacts from §9.42–§9.50 are
rechecked. The final runner also treats lifecycle-marker and C++ header validation
failures as qualification failures.

Evidence: [`gpu-native-lifecycle-2026-10-09.json`](evidence/gpu-native-lifecycle-2026-10-09.json).
Reproducible local artifacts:
`lattica-prover-p3/benchmark-results/gpu-native-lifecycle-20261009/run-03`.
Work remains uncommitted on `main`.

Application/Zig startup wiring remains separate from these native exports.
Complete batch proofs remain qualified only through four padded tiles; complete
64-tile proofs and sustained transaction throughput still need qualification.
Private worker admission, tree/recursive native delivery, quadratic lookups where
required, owned multi-AIR commitments and full-size recursion remain open. Host
orchestration and serialization remain CPU work. Multi-GPU scaling, AMD/Metal
qualification and the authorized local Mac source checkpoint are outstanding.
No SSH retrieval was attempted.

### 9.52 Zig GPU startup, wallet CLI and real node delivery — 2026-10-09

Zig applications now share `prover_runtime.Gpu.initialize`, `drain` and `shutdown`
through the public native lifecycle ABI. Startup requires `gpu-required` and
installs all four real wallet/batch proving and verifying registrations only
after successful native initialization. Rejected startup installs nothing.
Rejected drain/shutdown leaves the live registrations available for cleanup and
retry. Successful shutdown clears all four proving registrations while retaining
the CPU verifiers for serialized proofs. The application owns this process
lifecycle: configure once, initialize before admitting work, then join all proof
work before draining and shutting down from one control thread.

`zig build -Dgpu-prover=true -Doptimize=ReleaseSafe` now builds a wallet CLI whose
transfer demo uses the real native GPU prover. `-Dprover-library=PATH` can select
an already built static library. The default CLI remains a mock demonstration,
but rejects strict proving policies instead of satisfying them with mocks.
Exchange scanning, key generation and hashing benchmarks initialize no GPU.
The existing real node executable automatically uses GPU startup when the
environment requests `gpu-required`.

The integration script selects the standalone C GPU lifecycle harness and real
node GPU path under that policy; compatible/CPU-required runs retain real CPU
integration. It builds the matching Rust features offline unless
`LATTICA_PROVER_LIBRARY` supplies a prebuilt library.
`LATTICA_INTEGRATION_OUT` selects a durable output directory. Qualification uses
the exact five Rust static libraries archived at §9.51; **no Rust proving source
changed**. The script's Cargo build arguments match those already qualified
feature sets; this checkpoint exercises its prebuilt-library path.

Zig FFI tests run as a standalone process with inherited stdio and checked exit
status, and install `bin/lattica-ffi-tests` under the selected prefix. The first
server-mode pilot reached its 180-second limit while the child waited on stdin;
the standalone runner passes. The original timeout, source and command remain
preserved. FFI tests prove through the native API, shut down through the shared
Zig runtime, check that all four proving registrations are gone, then verify and
reject altered public inputs through the unchanged CPU interface.

Final qualification passes **43 bounded checks**, **404 Zig test executions**
and **64 GPU-required proofs**. The Zig count consists of 116 unit cases in each
of Debug and ReleaseSafe, four 35-case GPU FFI runs and one 32-case CPU FFI run.
The GPU matrix covers wide and narrow Rust release libraries, full and compact
storage, the CLI, FFI tests, real node and integration script. Its proofs comprise
18 join-split, 30 HTLC and eight batches for each AIR. Each successful report
contains receipts for all **15 arithmetic stages on OpenCL**; only serialization
has a CPU observation. There are 960 GPU stage observations and 64 serialization
observations, with no private trace handoff.

Real node checks retain transaction-root agreement, proof verification, ghost
output/tamper rejection, double-spend rejection, HTLC locking and refund timing,
and one-proof-per-block application. Twelve startup rejections cover a strict
request in a mock build, missing/incorrect policy, invalid UUID, zero budget,
private worker assignment, missing GPU stage, unsupported CPU-only/GPU-only
libraries and a debug Rust library whose CPU audits cannot meet strict policy.
Both GPU storage modes and the CPU mode of the integration script pass.

The first qualification's CPU FFI process passed all 32 cases, but its validator
incorrectly expected 35. CPU builds omit three unused GPU-runtime test cases.
The corrected record preserves that attempt, reuses 39 passing checks only after
matching source/library/manifest/log hashes, reruns CPU FFI, and completes the
three script checks. Original commands retain their `run-01` provenance; the
consolidated `run-02` record identifies every reused check.

Evidence archives 27 application/script/fixture inputs, references all 453
unchanged Rust checkpoint inputs, hashes 21 application/test artifacts and the
five Rust libraries, and rechecks previous checkpoint artifacts. All native
builds and tests remain serial on the authorized desktop RTX 5080, with 3 GiB
host memory, zero swap, four CPU threads, 180-second service limits and 1 GiB
managed GPU memory for complete proving.

Evidence: [`gpu-zig-startup-2026-10-09.json`](evidence/gpu-zig-startup-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-zig-startup-20261009/run-02`.
Work remains uncommitted on `main`.

Private worker admission, tree/recursive native delivery, quadratic lookups where
needed, owned multi-AIR commitments and full-size recursion remain open. Complete
batch proofs remain qualified only through four padded tiles. Host orchestration,
serialization and independent verification stay on CPU. Sustained throughput,
multi-GPU scaling, AMD/Metal qualification and the authorized local Mac source
checkpoint remain outstanding. No SSH retrieval was attempted.

### 9.53 Wallet-owned local GPU worker admission — 2026-10-09

**Implemented and qualified on the desktop RTX 5080; work remains uncommitted.**
Private wallet proving now has a separate local resource assignment,
`LATTICA_WALLET_WORKER_BUDGET`, with schema `lattica-wallet-local-gpu-v1`.
Wallet witnesses remain in the wallet application. The assignment contains only
the service name, GPU UUID and resource limits. The public recursive pool's
`LATTICA_V2_WORKER_BUDGET` continues to reject private wallet input, including
coexistence with the new assignment.

Admission validates a bounded, owner-only regular JSON file with a closed
schema; GPU-required policy; matching device, host-output, managed/context GPU
and thread budgets; actual Rayon pool size; and actual Linux cgroup v2 service
membership, finite memory/CPU limits, zero swap and disabled core dumps. Native
startup prepares admission before GPU creation and commits the assignment only
after successful initialization. The file's device/inode, path, parsed resource
assignment and cgroup identity remain pinned across GPU shutdown. An ordinary
unassigned native startup is pinned too. Resource changes require a new process.

The common proving admission now rejects policy downgrades for assigned workers,
including explicit Rust requests and CPU ABI selection after environment changes.
Every assigned proof run revalidates its resource assignment. The owned legacy
wallet/batch path and candidate JoinSplit, HTLC and issuance path share these
checks; the mixed GPU-witness/CPU-prover bridge remains unavailable to assigned
workers. Failed startup preserves a borrowed engine and can still drain or shut
down. Process VRAM checkpoints also run for the local wallet assignment.

`scripts/run-wallet-gpu-worker.py` starts a wallet application in a dedicated
`lattica-wallet-*.service`, creates the owner-only assignment, configures the
complete full/compact GPU path and waits for termination. Its reference limits
are 3 GiB host RAM, zero swap, four CPU threads, 1 GiB managed GPU memory, a
4 GiB context allowance, a 1 GiB host-output allowance and 180 seconds. The
launcher retains only its public assignment metadata. It introduces no private
queue, transport or public-pool witness artifact.

Qualification freshly passed **50 checks**, including **25 Rust test executions**
and **31 GPU-required proofs** in the wide-lane release build. Of these proofs,
17 run under local wallet assignments: six candidate Rust proofs, ten legacy
single/batch proofs through the launcher and one real Zig wallet CLI proof.
Fourteen unassigned candidate proofs provide regression coverage. Every complete
proof has 15 OpenCL arithmetic observations; serialization and independent
verification remain on CPU. Both full and compact storage pass, including CPU
verification after GPU shutdown.

Twenty-eight fresh processes reject invalid schemas, missing/duplicate/unknown
fields, invalid budgets, wrong services/devices, cgroup limit mismatches,
permissive/executable files, symlinks, directories, FIFOs and public-worker
coexistence. Runtime tests also reject policy/environment changes, file edits,
removal and inode substitution, preserving output canaries and live engines.
They check 390 rejected native proving calls and pin persistence across shutdown.
The Rust test verifies that rejected private requests add no allocations or
uploads, and that a mismatched actual Rayon pool rejects despite matching
environment settings. CPU-only, CPU block-v2 and GPU-only library checks pass.

The evidence includes 55 process-VRAM checkpoints, with a largest observed
process allocation of 1,197,473,792 bytes under the 5 GiB combined allowance.
These checkpoints are observations, not a continuous peak measurement. The
record archives 341 source/configuration inputs and verifies 91 artifacts.
The initial pilot passed. The first qualification was stopped because Cargo ran
outside the crate directory, omitting its compiler configuration. The next
attempt correctly rejected incomplete compact-storage settings. Both attempts
remain preserved; the corrected final run freshly executes all 50 checks.

Evidence: [`gpu-wallet-worker-2026-10-09.json`](evidence/gpu-wallet-worker-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-wallet-worker-20261009/run-03`.
Launch instructions: [wallet-owned local GPU workers](gpu-acceleration.md#wallet-owned-local-gpu-workers-linuxopencl).

Tree/recursive native delivery, quadratic lookups where required, owned multi-AIR
commitments and full-size recursion remain open. Legacy batches remain qualified
only through four padded tiles. Sustained throughput, multi-GPU scaling,
AMD/Metal qualification and the authorized local Mac source checkpoint still
need separate work. No SSH retrieval was attempted.

### 9.54 Legacy tree GPU delivery — 2026-10-09

**Implemented and qualified on the desktop RTX 5080; work remains uncommitted.**
The existing `LJSTREE1` compatibility container now uses GPU arithmetic for its
leaf proofs and transaction root when GPU proving is selected. Its bytes and
CPU verifier remain unchanged. This container retains every leaf proof; it
does not perform recursive aggregation or activate a new consensus profile.

Leaf proofs reuse the owned legacy wallet prover. The root operation uploads
only public statements and constructs canonical dummy padding on GPU using the
existing batch AIR geometry. It reads back 32 public root bytes and an 8-byte
validity status, with zero trace readback. Each leaf has a complete
`proof_request` receipt with 15 GPU arithmetic observations. Root receipts have
`scope: operation` and cover only `witness_trace` and `public_values`; they are
not additional proofs.

Native admission checks GPU selection and resource limits before parsing
private witnesses. The output allowance is bounded by the smaller of 512 MiB
and the header plus the maximum leaf-record size multiplied by the count.
The existing 1,024-leaf limit remains. Container assembly rejects overflow
before extending the output buffer. Wallet-owned worker assignments retain
their pinned identity and GPU-required policy; the public recursive pool
continues rejecting private wallet input.

Zig startup installs a separate tree proving backend, and shutdown clears it.
Tree verification registration remains explicit: initializing the GPU prover
does not enable acceptance of tree containers. The FFI test verifies complete
GPU containers with the existing CPU verifier after GPU shutdown. The wallet
demo also correctly identifies its real GPU proving backend.

Qualification passed **42 checks**, including **24 Rust test executions**,
**188 Zig test executions**, **2,167 complete GPU proofs** and **3 CPU
compatibility proofs**. It produced **14 complete GPU tree containers** and
**16 root-operation receipts**. Root differential checks cover 18 counts per
storage mode through 1,024, including padding boundaries. Complete C containers
cover counts 1, 3, 4, 33 and 1,024 in both full and compact storage. A distinct
statement Rust fixture rejects leaf reordering; C tests reject altered counts,
roots, public values and truncation. Budget/policy rejection, worker mutation,
wallet/batch, candidate wallet, real Zig wallet and node regressions pass.
CPU-only, CPU block-v2 and GPU-only library checks also pass.

| Storage | Leaves | Container bytes | GPU tree construction | Controller, including CPU verification and tamper checks |
|---|---:|---:|---:|---:|
| Full | 1,024 | 469,385,575 | 151.838 s | 170.145 s |
| Compact | 1,024 | 469,378,332 | 151.557 s | 169.801 s |

Both maximum-count runs report a 1.1 GiB host memory peak and zero swap. All
native builds and tests run serially with 3 GiB host RAM, four CPU threads,
zero swap and 180-second service limits. Complete proofs use a 1 GiB managed
GPU allowance. The evidence records 6,557 process-VRAM checkpoints, with a
largest observed process allocation of 1,197,473,792 bytes and managed
allocation of 1,033,897,088 bytes. These observations are not a continuous peak
measurement. All **346 source/configuration hashes and 81 artifact hashes**
were revalidated before finalizing the evidence.

These are synthetic conformance runs, not sustained transactions/hour or chain
capacity measurements. The large C fixtures repeat canonical dummy witnesses;
their leaves are not independent valid ledger payments. This tree result does
not extend legacy batch qualification beyond four padded tiles.

The initial compilation failure referenced a nonexistent session allocation
field; the corrected test uses actual engine counters and session statistics.
The first root pilot found the expected 32 public bytes plus 8 validity bytes,
correcting an overly narrow readback assertion. Both attempts are preserved,
alongside the passing corrected Rust and native pilots and the fresh final run.

Evidence: [`gpu-legacy-tree-2026-10-09.json`](evidence/gpu-legacy-tree-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-legacy-tree-20261009/run-01`.

Public recursive native delivery, quadratic lookups where required, owned
multi-AIR commitments and full-size recursion remain open. Host orchestration,
serialization and independent CPU verification remain intentional. Sustained
throughput, multi-GPU scaling, AMD/Metal qualification and the authorized local
Mac source checkpoint need separate qualification. No SSH retrieval was attempted.

### 9.55 Quadratic GPU lookups and shared opening inversion — 2026-10-09

**Implemented and qualified on the desktop RTX 5080; work remains uncommitted.**
Device-owned LogUp generation now supports both the legacy quadratic field
`X^2 - 7` and the candidate cubic field `X^3 - X - 1`. The lookup API infers
the extension degree from the challenge arrays and rejects unsupported degrees
before allocation or transfer. Its memory plan accounts for the selected
degree in challenge parameters, inversion tiles, scan levels, output and terminal.

Expression evaluation, denominator construction, bounded batch inversion,
fraction columns and prefix scans remain on GPU. Successful quadratic lookup
generation reads back only its 16-byte terminal and 8-byte status; the cubic
path retains its 24-byte terminal and 8-byte status. Active zero denominators
reject after reading the status. No intermediate matrix is downloaded during
generation. CPU comparisons explicitly read results afterward for testing.

Opening reduction now uses the same degree-aware batch-inversion kernel for
both fields, removing the duplicate quadratic inversion kernel. Existing proof
formats, registry identities and CPU verifiers remain unchanged. This adds a
lookup primitive; it does not activate a new quadratic AIR or profile. The
current legacy wallet AIRs have no lookup argument to enable.

The fresh qualification passed **11 checks**, including **8 Rust test
executions** and **68 CPU/GPU lookup comparisons**. Each field covers 1, 2, 64,
128, 256, 1,024, 2,048 and 32,768 rows with all four combinations of natural and
bit-reversed main/preprocessed rows, plus zero multiplicities and lookups with
no tuples. Tests also cover next-row windows, selectors, public values, signed
multiplicities, shared expressions, active zero denominators, unsupported
degrees, malformed/noncanonical challenges, foreign sessions and buffer release.

Full and compact regressions produce **6 registered cubic GPU proofs** and
**6 complete quadratic wallet GPU proofs in 2 tree containers**. All verify
with unchanged CPU verification after GPU shutdown, and altered public values
reject. Registered-proof receipts cover 15 GPU arithmetic stages but exclude
public statement construction; they are counted separately from complete
`proof_request` receipts. Two preprocessing receipts and two tree-root operation
receipts are also separate. The receipt checker accounts for registered stages'
enclosing orchestration measurements alongside their actual GPU events.

All builds and tests ran serially with 3 GiB host RAM, zero swap, four CPU
threads and 180-second service limits. Differential tests use a 64 MiB managed
GPU allowance; complete proof regressions use 1 GiB. The largest planned lookup
allocation totals in these differential fixtures were 4,348,312 bytes for
quadratic and 5,710,304 bytes for cubic. Twenty process-VRAM checkpoints from
assigned tree proofs observed at most 478,150,656 process bytes; this is not a
continuous peak measurement. CPU-only, CPU block-v2 and GPU-only compilation,
changed-file formatting and whitespace checks pass. Evidence revalidates
346 source/configuration inputs and 16 archived artifacts.

The first attempt passed both lookup differential suites but caught a missing
degree argument in the opening caller. After correcting the shared caller, the
next attempt passed its native tests but exposed an overly strict controller
assumption that every enclosing GPU-stage measurement was itself a device event.
The corrected controller freshly passed all 11 checks with the same corrected
source and binary. Both earlier attempts remain preserved.

Evidence: [`gpu-quadratic-lookup-2026-10-09.json`](evidence/gpu-quadratic-lookup-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-quadratic-lookup-20261009/run-03`.

Public recursive native delivery, owned multi-AIR commitments and full-size
recursion remain open, followed by sustained throughput and multi-GPU scaling.
AMD/Metal qualification and the authorized local Mac source checkpoint remain
separate work. This component qualification does not change consensus activation
or establish transactions per hour.


### 9.56 Owned multi-AIR GPU batches (2026-10-09)

Owned-input proving now accepts several AIR instances in one batch. Their main
traces, lookup matrices, quotient evaluations and commitment inputs stay on the
GPU. Quotient commitments preserve AIR/chunk order and enforce each AIR's
existing chunk limit plus a **256-matrix aggregate admission bound**. The
aggregate check precedes main commitment randomness. The retained commitment
engine also applies the batch limit; its original single-input adapter keeps
its existing storage checks.

The machine backend now prepares multiple public witness programs and commits
their GPU-generated preprocessing traces together. Verifier metadata preserves
the original instance order. Witness and randomness admission include combined
live storage; a collection of individually admissible AIRs can no longer pass
an undersized assignment. Existing worker schemas and per-AIR validation remain
in force. Unsupported geometry, empty batches and foreign sessions reject before
commitment draws.

**Equal padded AIR heights are required.** Testing exposed the resident
commitment engine's existing equal-output-height restriction. Setup now rejects
unequal heights before GPU work. Callers may explicitly pad compatible public
programs before setup, which changes their preprocessing keys and degree
metadata. Supporting mixed heights without padding still needs GPU tree
injection, per-matrix salt ordering and owned-query changes.

The fresh qualification passed **17 checks and 18 Rust test executions**.
Sixteen complete three-AIR batch proofs, covering three distinct programs,
two instance orders and two witness sets in full/compact storage, exactly match
seeded CPU proof bytes. All verify with the unchanged CPU verifier after GPU
shutdown; modified and reordered public statements reject. Each AIR uses
64 trace rows and the batch commits 48 quotient matrices. Eight batches use GPU
randomness and transcripts and pass GPU-required registered-proof coverage for
all 15 arithmetic stages. The other eight exercise CPU randomness/transcript
compatibility. Six singleton GPU regressions bring the total to **14
GPU-required registered-proof receipts**, with **6 separate preprocessing
receipts**. Registered-proof scope excludes public statement derivation.

Four additional quotient-commitment comparisons cover **50 partitions** in
AIR order, variable per-AIR chunk counts, CPU/device RNGs, both storage modes,
foreign ownership and invalid geometry. Their explicit matrix reads are test
audits. Complete batch proofs retain zero host LDE output/reordering and restore
the baseline live device matrices after each proof. The quadratic/cubic lookup
regressions add 68 comparisons, and quadratic single-AIR quotient regressions
add 10 comparisons. CPU-only, CPU block-v2 and GPU-only compilation
also pass.

All native checks ran serially under 3 GiB host RAM, zero swap, four CPU threads
and 180-second limits. Complete proofs use a 1 GiB managed GPU allowance on the
desktop RTX 5080. Source/archive verification covers **347
inputs and 20 artifacts**. Earlier attempts are preserved,
including fixture/receipt corrections and GPU lease conflicts. The final
controller passively waits for other lease holders.

Evidence: [`gpu-multi-air-2026-10-09.json`](evidence/gpu-multi-air-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-multi-air-20261009/run-12`.

These are joint AIR proofs with the upstream shared global-lookup semantics.
MachineAir uses a named global wire bus; independently scheduled transactions
need separate proofs or explicitly designed and verified bus isolation.
This is an internal proving capability; it adds no public worker packet or
consensus profile. Mixed-height commitments, public recursive native delivery,
full-size recursion and sustained multi-GPU throughput remain open. The
synthetic tests do not establish transactions per hour or qualify AMD/Metal.

### 9.57 Shared public GPU worker admission (2026-10-09)

The Linux public-worker resource checks now live in
`block_v2::execution::gpu_admission::Admission`, shared by the grouped and
typed GPU command-line runtimes and available to a future native runtime.
This removes the probe-only implementation as a prerequisite for native
public-worker startup. It does not add a native proof entrypoint or qualify
recursive proving at full size.

`Admission::from_env` reads the existing worker assignment with a 1 MiB
limit and checks the current process's actual cgroup-v2 identity, worker and
fleet memory limits, zero-swap limits, CPU quota, effective CPU set, Rayon
configuration, selected GPU UUID, GPU/context/host allowances and scratch
filesystem. It also preserves the assigned readback layout and rejects a
private wallet assignment. Its fields are private; production callers cannot
substitute observations from another process. The original assignment stays
available for existing workload checks and identity construction.

All checks complete before `initialize_rayon` creates the global pool. The
typed CLI performs its workload, FRI and workspace checks against that same
assignment snapshot before starting threads. The earlier implementation
started Rayon before checking GPU/spill configuration and scratch identity.
The shared parser also rejects non-finite or zero CPU quotas, malformed
quota records, overlapping CPU ranges and extra range delimiters. It compares
CPU ranges against the bounded assignment without expanding large ranges.
Already initialized Rayon pools still reject; admission creates no GPU
context, approves no registry and changes no proof parameters or formats.

The enclosing runtime must continue to hold the assignment, environment,
cgroup and scratch allocation fixed throughout the worker lifetime. This
check does not reserve resources or replace the existing worker ledger,
launch gate, registry/profile/executable pins or public policy binding. Native
public recursive delivery must reuse those contracts and the existing typed
Unix service. Private wallet startup remains separate.

The final qualification passes **9 checks and 17 top-level Rust tests**:
eight admission cases, one isolated native rejection case and eight CPU
worker-IPC regressions. All four affected GPU CLIs compile, as do the
CPU block-v2 and GPU-only libraries. Changed-file formatting and whitespace
checks pass. Source/archive verification covers **349 inputs**. Native checks
run serially with 3 GiB host RAM, zero swap, four CPU threads and 180-second
limits; no GPU work is submitted.

The native check confirms rejection under an uncapped parent cgroup and
then successfully initializes Rayon, demonstrating that rejection did not
start the global pool. It also checks rejection of a private wallet
assignment. Accepted assignments use controlled resource observations;
this checkpoint does not qualify a live accepted GPU worker. Existing fleet
limits remain untouched. An earlier attempt passed the GPU-build admission
tests but ran CPU-only IPC fixtures in that GPU build; their runtime guard
rejected as designed. The preserved final attempt uses the CPU-only fixture
configuration.

Evidence and validation results are recorded in
[`gpu-worker-admission-2026-10-09.json`](evidence/gpu-worker-admission-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-worker-admission-20261009/run-02`.
No GPU arithmetic or throughput qualification is claimed for this startup
change. Full-size wrap/merge/finalizer proofs, native public delivery,
mixed-height commitments, AMD/Metal and sustained multi-GPU throughput remain
open.

### 9.58 Native public GPU worker startup (2026-10-09)

The new C entrypoint `lattica_gpu_public_worker_initialize_from_env` and Zig
`prover_runtime.PublicGpuWorker` initialize the complete owned OpenCL backend
for an explicitly assigned public recursive worker. They require a fresh
Linux process, a release library built with `block-v2`, `gpu` and `stream`,
`gpu-required`, all owned GPU switches and the existing public worker budget.
Private wallet assignments, an active engine and an existing global Rayon
pool reject. This route installs no wallet callbacks or verifiers and grants
no registry approval. A public worker that has initialized Rayon must be
replaced by a fresh process before another startup attempt.

Wallet and public startup now share the owned-path environment checks,
quotient/backend selection and cleanup guard. Rejection or unwinding releases
a newly created engine while preserving a borrowed engine. The existing
wallet API continues to reject public worker assignments. The public route
also checks complete recursive-request capabilities after initialization;
partial GPU selection and debug CPU constraint auditing cannot qualify it.
The existing C drain/shutdown calls serve both routes.

Resource admission now permits independently capped fleet slices named
`lattica-v2-multi-*.slice`, as well as the original
`lattica-v2-multi.slice`. The actual parent must still exactly match the
assignment and enforce its finite memory and zero-swap limits. This allows
isolated native worker fleets without modifying a shared fleet's limits;
it introduces no new resource schema or worker packet.

Qualification prepares the Empty preprocessing key in a separate CPU process,
then starts the native public GPU route and produces **two complete 2,048-row
recursive empty proofs**, at levels zero and five. Both pass unchanged CPU
verification after GPU shutdown, and altered public statements reject. The
first proof sets up preprocessing and the second reuses it. The twelve-slot
fixture contains the valid Empty key and zero placeholders for the eleven
unused modes; it is not approval of a full recursive registry.

Both complete `block_v2_typed_empty` receipts cover **all 16 arithmetic stages**
with `gpu_required`, OpenCL observations, positive completed device calls and
no observation errors. Eleven successful receipts comprise those two whole
requests, two registered proofs, one preprocessing execution, two registry
compilations and four statement derivations. The warm request explicitly
records cached preprocessing. Receipt checks distinguish enclosing
orchestration measurements from completed GPU events.

An independently linked C program and a native Zig test exercise successful
public initialization, private-wallet rejection, repeated-start rejection,
drain/shutdown and the fresh-process requirement after shutdown. The existing
wallet lifecycle regression still covers admission, error/panic cleanup and
retained-session shutdown rejection. CPU builds explicitly return the
unavailable status. Across the final runs, **15 top-level Rust tests**, the C
lifecycle program, and **four Zig tests** pass. GPU CLI, CPU block-v2 and
GPU-only compilation, changed-file formatting and whitespace checks pass.

Native builds and tests ran serially with 3 GiB worker memory, zero swap,
four CPU threads and 180-second limits. Public GPU checks used 1 GiB managed
GPU memory on the desktop RTX 5080 and isolated 4 GiB, zero-swap fleet slices.
Both slices were stopped, their temporary properties removed, and their
inactive state independently verified. The existing shared fleet was not
reconfigured. The complete-proof service reported a 265.3 MiB host memory
peak; this single fixture is not resource calibration or a throughput result.

The first controller attempt used the wrong query-layout name and passed a
file where the existing environment encoder expects a directory; those were
corrected before GPU startup. Independent Zig linking also required the
Linux unwinding library and LLVM linker for this host's GCC unwind metadata.
All attempts remain preserved. Final source/archive verification covers
**354 source/configuration inputs**.

Evidence: [`gpu-native-public-startup-2026-10-09.json`](evidence/gpu-native-public-startup-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-native-public-20261009/run-02`
and `run-05` in the same directory.

This delivers native public backend startup, not a C/Zig public proof service.
Native delivery must still connect the existing typed Unix service, pinned
registry/profile/executable, host policy context and launch gate. Full-size
wrap/pair/merge/finalizer proving, mixed-height commitments, AMD/Metal and
sustained multi-GPU throughput remain open. No transactions/hour claim follows
from these empty-proof fixtures.

## 9.59 Native public GPU worker service (2026-10-09)

`lattica_gpu_public_worker_serve` and Zig
`prover_runtime.servePublicGpuWorker` now connect native callers to the existing
typed public-worker service. One blocking call performs fresh-process admission,
GPU initialization, HELLO/JOB/CONTEXT/PING/STOP handling and teardown. The caller
supplies a connected Unix stream and an independently trusted bootstrap, without
calling initialization first. The descriptor is duplicated and remains owned by
the caller. Success writes the completed-job count only after clean STOP and GPU
shutdown; failures return a zero count and attempt cleanup. The process must
exit after return so its supervisor can reconcile reservations.

The bounded, versioned local `execution::native_worker::Bootstrap` binds the
registry, profile, chain, executable fingerprint, launch directory and existing
public policy context. Coordinator and worker independently derive their initial
protocol identity from this bootstrap and the complete resource assignment.
`Config::from_assignment` and `worker_budget` share the typed CLI's existing
resource/cache interpretation. CLI configuration identity and worker packet
encodings remain unchanged. `Prepared` separates admission from initialization,
allowing bootstrap/configuration rejection before creating GPU resources.

The service reuses `ProcessWorker`, `TypedWorker`, `WorkerGate`, durable launch
tokens and owner-side CPU verification. Its lifecycle lock spans the service;
internal teardown calls Rust directly to avoid recursively locking the C API.
This local bootstrap provides no remote authentication or registry approval.
The API installs no wallet callbacks or verifier, transports no private wallet
witnesses or device handles, and changes no consensus activation or proof format.

Qualification uses the archived CPU-prepared Empty key with its exact
`block-v2-wide-lanes,gpu,stream` release build. A separately linked C executable
serves **two complete 2,048-row Empty jobs**, at levels one and five, through a
supervised persistent worker. Each result passes unchanged CPU verification in
the coordinator before durable acceptance; altered public statements reject.
An idle policy-context update changes the session identity while preserving
preprocessing: one setup and one cache hit. Clean STOP retires the GPU, preserves
the caller's descriptor, and releases the workspace only after observing the
exact worker process and cgroup exit.

Four further C processes exercise a wrong executable pin, a different independent
configuration, peer disconnect and malformed job framing. All reject with zero
completed output and retire the GPU; their journal reservations remain charged.
The bootstrap, resource/cache, descriptor and FFI boundary tests also pass, as do
the existing CPU-only process regressions and unavailable-backend checks.
Overall: **19 top-level Rust tests**, **one independently linked Zig test**, and
**five C worker processes**. CPU library, GPU CLI, formatting and whitespace
checks pass. The earlier narrow build correctly rejected the archived wide
registry before GPU startup; all three preliminary attempts remain preserved.

Both whole-request receipts cover **all 16 arithmetic stages on OpenCL**, with
completed device calls and no observation errors. Eleven receipts cover two
whole requests, two registered proofs, one preprocessing execution, two registry
compilations and four statement derivations. The audit distinguishes enclosing
orchestration measurements from device events. Source/archive and artifact
verification covers **360 source/configuration inputs and 78 final artifacts**.

Builds and native tests ran serially with 3 GiB memory, zero swap, four CPU
threads and 180-second limits. GPU workers used the desktop RTX 5080, 1 GiB
managed GPU memory and an isolated 4 GiB zero-swap fleet. The 4 GiB GPU context
reservation remains conservative, not a measured peak. The fleet was stopped,
its temporary limits removed, and its inactive state independently verified.

Evidence: [`gpu-native-public-service-2026-10-09.json`](evidence/gpu-native-public-service-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-native-service-20261009/run-04`
and `checkpoint/` in the same directory.

The twelve-slot fixture registers only Empty; the eleven other caps are zero
placeholders. Its synthetic candidate anchor exists only to schedule the Empty
jobs and is never sent to, proved by or accepted from the native worker. This
qualifies the local native service, not a complete recursive registry or
transaction throughput. Full-size wrap/pair/merge/finalizer proving, mixed-height
commitments, AMD/Metal and sustained multi-GPU throughput remain open. The
overall all-GPU proving goal remains active and incomplete.

## 9.60 Full-size recursive geometry and admission (2026-10-09)

The next qualification now uses the archived, transaction-bearing twelve-key
paired fixture at **262,144 rows**. All 78 archived fixture hashes were checked
before copying the required public wallet proofs, body, height and registry
keys. These are real research keys, with no placeholder caps. The fixture remains
separate from production registry approval.

Twelve bounded CPU tests independently verify the JoinSplit, HTLC and issuance
templates, compile each registered mode, pad its program to the registered
height, and derive the exact witness/compiler resource bounds. Rust and Python
reservation calculations agree for every mode. The release build, all twelve
tests, changed-file formatting and whitespace checks pass. Source/archive and
artifact audits cover **361 source inputs and 60 artifacts**.

The complete allocation model exposes two limits that the 2,048-row service
fixtures did not exercise:

| Registered mode | Additive managed GPU bound | Witness/source/compiler host bound |
| --- | ---: | ---: |
| JoinSplit pair (1) | 11.82 GiB | 2.41 GiB |
| Empty (2) | 11.59 GiB | 1.20 GiB |
| Merge (3) | 11.97 GiB | 3.23 GiB |
| HTLC pair (7) | 11.85 GiB | 2.49 GiB |
| Finalizer (12) | 11.78 GiB | 2.22 GiB |

These are conservative simultaneous-allocation bounds, not measured peaks. The
managed total includes owned quotient/opening storage, witness resources,
randomness and transcript storage; context headroom and a device safety margin
are additional. Retained random salts and sampling contribute **6,268,453,096
bytes**, and owned quotient/opening storage contributes **5,410,652,160 bytes**.
The merge witness bound is **3,468,002,940 bytes**, exceeding the enforced 3 GiB
host allowance. A successful geometry compilation does not demonstrate that its
later overlapping proving allocations fit.

The desktop GPU availability snapshot recorded **12,491,685,888 bytes free**.
The JoinSplit pair's **12,696,026,960-byte** managed model already exceeds that
space before context overhead. No full-size GPU proof was launched, no admission
bound was weakened, and no other GPU application was stopped. The compiled
`full_size_pair_gpu_proof_matches_archived_registry` test is ready to exercise
two actual public wallet proofs and verify its result against the archived keys
after GPU shutdown once the allocation plan fits.

The next implementation target is retained salt storage. `DeviceRandom` already
supports a device-key snapshot with an independent cursor; ordinary clones share
the active cursor. Salt replay can preserve the existing ChaCha20/rejection
stream while generating one matrix at a time for commitment and queried rows.
It must preserve atomic snapshot/advancement, failure poisoning, scrubbing,
session ownership and query-only disclosure. Generation inside a commitment
must avoid recursively locking the engine. Both commitment peak storage and
later retention must fall before the Rust/Python admission models can be reduced.
Merge source/compiler staging also needs reduction to fit the existing host cap.

Evidence: [`gpu-full-size-admission-2026-10-09.json`](evidence/gpu-full-size-admission-2026-10-09.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-full-size-20261009/run-01`.
This checkpoint qualifies full-size geometry and identifies admission limits;
it completes **zero full-size GPU proofs** and makes no throughput or capacity
claim. Full paired/merge/finalizer closure and the overall GPU goal remain open.

## 9.61 Private GPU salt replay (2026-10-10)

Private main, lookup, randomization and quotient commitments now retain
session-owned replay records instead of complete salt matrices. Preparation
holds the active random cursor across the whole batch, samples each matrix
with the existing ChaCha20/rejection implementation, records its exact start
and end positions, and scrubs its output before sampling the next matrix.
Records share the existing device key. They cannot be serialized or promoted
to public preprocessing, and remain local to their proof worker and session.

Commitment hashing regenerates one matrix inside the already-held engine;
query gathering does the same through its owning session and downloads only
queried rows. Replay uses a local cursor, never locks the active cursor, and
checks the original ending position. Execution failures and position
mismatches poison the record. Output and key storage retain their existing
scrub-on-drop owners. Public preprocessing and FRI salts remain resident.
This version deliberately performs an initial sampling pass to establish
rejection boundaries, so reduced memory does not establish higher throughput.

Both commitment admission and Rust/Python worker reservations include a
temporary salt output plus sampler scratch. The full-size randomness bound
falls from **6,268,453,096 to 1,436,614,888 bytes**, saving **4.5 GiB** for
each of the twelve archived modes. Other reservation components, proof
formats, parameters and registry identities are unchanged. These remain
conservative static bounds rather than measured full-proof peaks.

| Registered mode | Revised additive managed GPU bound | With 4 GiB context reserve and 1 GiB guard |
| --- | ---: | ---: |
| JoinSplit pair (1) | 7,864,188,752 bytes | 13,232,897,872 bytes |
| Empty (2) | 7,614,455,408 bytes | 12,983,164,528 bytes |
| Merge (3) | 8,018,533,184 bytes | 13,387,242,304 bytes |
| HTLC pair (7) | 7,887,822,464 bytes | 13,256,531,584 bytes |
| Finalizer (12) | 7,816,442,960 bytes | 13,185,152,080 bytes |

Qualification on the desktop RTX 5080 covers:

- Exact CPU ChaCha20 field values at positions 0, 15 and a large counter;
  unchanged subsequent draws; repeated replay after the original handle
  advances or drops; replay while the active cursor is held.
- Wrong-session rejection, injected execution failure, consumed-position
  mismatch, output/key scrubbing, and refusal to shut down with live records.
- Nine 8 MiB salt matrices under a 64 MiB managed cap. The former retained
  allocation fails admission; replay peaks at **17,892,184 managed bytes**
  and retains only the shared **32-byte key**, above engine baseline. No
  sample upload/readback occurs during preparation; status words remain.
- CPU-equal commitment caps, queried salts and authentication paths;
  quadratic and cubic owned PCS proofs verify after GPU shutdown.
- Two complete 2,048-row Empty proofs at levels 0 and 5 through native public
  startup, with one preprocessing setup and one cache hit. Both verify on
  CPU after shutdown and reject altered statements. All **16 arithmetic
  stages** report OpenCL; all **11 receipts** succeed.

The checks comprise **21 distinct Rust tests**, **49 Python tests**, the CPU
library build, formatting, whitespace and source/artifact audits. GPU work
was serial under existing leases, with 3 GiB host caps, zero swap and four
CPU threads. An initial PCS test invocation omitted the required lookup
selection and rejected before GPU initialization; both tests passed after
correcting that invocation. The finalized attempts remain preserved.

The availability snapshot had **12,549,357,568 bytes free**, still below the
full-size pair assignment including context and guard. No full-size GPU
proof was launched and no other GPU application was stopped. The merge host
bound remains **3,468,002,940 bytes**, above the 3 GiB worker cap. Further
storage/context qualification and reduced merge compiler staging are needed
before running the prepared full-size pair test, then actual merge and
finalizer proofs. The small Empty fixture has only one populated registry
key. Full-size completion, transactions/hour, AMD/Metal and sustained
multi-GPU throughput remain unqualified; the overall GPU goal is open.

Evidence: [`gpu-salt-replay-2026-10-10.json`](evidence/gpu-salt-replay-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-salt-replay-20261010`.

## 9.62 FRI salt replay and a verified full-size paired GPU proof (2026-10-10)

The desktop RTX 5080 now completes a **262,144-row JoinSplit pair proof for
two transactions** against the unchanged archived **12-key registry**,
with no placeholder keys. All **16 arithmetic stages** report completed
OpenCL work, and all six receipts succeed. After dropping the proving
session, native shutdown releases every managed allocation and the lease.
The CPU verifier accepts the proof and rejects the altered statement;
the GPU context remains absent throughout verification. The encoded proof
is **1,683,948 bytes**. This qualifies one full-size paired mode; the overall
GPU proving goal remains open.

The implementation extends private salt replay to FRI. Each FRI commitment
consumes its original GPU sample, then scrubs the sample and retains its
session-owned replay recipe for queries. It adds no separate preparation
pass for that commitment and preserves the exact rejection stream, caps,
queried salts and authentication paths. Public preprocessing salts remain
resident. The full-size randomness component falls another **512 MiB**,
from **1,436,614,888 to 899,743,976 bytes**. Replay records remain local to
their worker and device session; they are not distributed job payloads.

Witness compilation and admission now use the same metadata layout based
on actual instructions and ports. Padding height no longer charges the
compiler for nonexistent occupied rows. Metadata encoding is unchanged.
For the pair, the resulting host witness reservation is **2,187,350,608
bytes**; the merge reservation is **3,209,260,380 bytes**, narrowly below
the 3 GiB worker cap before other host components.

Full-size testing exposed two production issues hidden by Empty proofs:

- A nonempty summary requires no commitment hash, so its statement scope
  recorded no public-value work. A fixed-size GPU kernel now validates
  context limbs, mode, level, count and canonical root words and reports
  its completed event. The CPU path records its own metadata validation.
  Canonical empty-root authentication still uses the selected hash backend.
- Registration applied the host LDE payload guard to device preprocessing.
  It now selects that guard from the actual preprocessing branch. The
  owned device branch retains its source/compiler/staging admission,
  assigned worker checks, per-operation device plans and allocator cap.
  CPU preprocessing retains its full or compact host payload guard.

The full-size test also initializes the native worker before CPU wallet
verification can initialize Rayon, and checks context absence after
shutdown. The selected-backend flag intentionally persists for the process.

The successful cold run takes **88.25 seconds** end to end. Its receipts
record **70.94 seconds** of preprocessing and **16.03 seconds** of registered
proving. GPU program-identity hashing accounts for about **69.20 seconds**
of preprocessing. These measurements include one setup and no cache hit;
they do not establish sustained transactions/hour.

The measured managed GPU peak is **9,113,690,096 bytes (8.49 GiB)** under a
**9,663,676,416-byte (9 GiB)** cap. The service reports **1.5G host memory**
and **zero swap**, with a 3 GiB host cap and four CPU threads. The earlier
**7,128,387,872-byte** sum of owned-quotient, witness, randomness and
transcript reservations excludes base commitment/LDE temporaries. It is
**not a complete lifetime bound**. The final controller labels it as a
component sum and relies on enforced allocation limits and per-operation
plans for this bounded qualification. A complete phase profile is still
required before scheduler capacity or concurrent throughput qualification.

Validation includes 18 replay/sampler/PCS component tests, nine summary
and public-hash tests, CPU host rejection, three device admission/registry/
worker tests, the twelve full-size geometries, nine resource/small-proof
tests, 49 Python tests and the CPU-only library check. The small proof test
produces two complete Empty proofs. The final admission regression admits
device preprocessing below the host LDE payload bound and rejects a host
allowance one byte too small before upload. Formatting and whitespace
checks pass. The audit verifies **366 current source files**, **10 source
archives** and **179 artifacts**. Failed attempts and their controllers are
preserved, including the corrected regression fixture and shutdown assertion.
No proof services or GPU leases remain; the parent systemd slices are empty.

Next work is the complete scheduler lifetime model, actual full-size merge
and finalizer proofs, other paired modes, cache reuse and sustained pool
throughput. AMD and Metal remain unqualified. Proof formats, parameters,
registry identities and consensus activation are unchanged.

Evidence: [`gpu-fri-replay-2026-10-10.json`](evidence/gpu-fri-replay-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-fri-replay-20261010`.

## 9.63 Full-size Empty, merge and finalizer proofs (2026-10-10)

The full-size recursive path now extends the verified two-transaction pair
from §9.62 through a merge and a finalizer. All proofs use the unchanged
**262,144-row, twelve-key archived registry**, with no placeholder keys.
Each proof reports all **16 arithmetic stages on OpenCL** and six successful
receipts. After native GPU shutdown, the encoded proof is decoded and
verified on CPU; an altered statement is rejected. The GPU context is
absent both before and after that verification.

The Empty proof represents a canonical level-1 zero-count subtree. The
merge combines the previously verified level-1 transaction pair on the
left with that Empty proof on the right, producing a level-2 node with
two transactions. The finalizer pads this verified merge to depth 6.
Expected statements are derived independently from the original pinned
wallets 0 and 4 and CPU commitment helpers. Controllers verify input hashes
and copy each dependency into the new run; earlier artifacts remain intact.

| Mode | Cold wall time | Managed GPU peak | Reported host peak | Output |
| --- | ---: | ---: | ---: | --- |
| Empty (2) | 18.03 s | 9,304,785,024 bytes (8.67 GiB) | 301.7M | Count 0, level 1 |
| Merge (3) | 124.73 s | 9,337,593,216 bytes (8.70 GiB) | 2.1G | Count 2, level 2 |
| Finalizer (12) | 71.54 s | 9,614,729,664 bytes (8.95 GiB) | 1.2G | Count 2, level 6 |

Every run stays within its **9 GiB managed GPU** and **3 GiB host** caps,
with zero swap, four CPU threads and a 180-second service limit. Each
encoded proof is **1,683,948 bytes**. The runs are serial on the authorized
desktop RTX 5080 and each performs one setup with no cache hit. They are
cold correctness qualifications, not sustained transaction throughput.

The LDE planner chooses the widest power-of-two column tile that fits the
assigned memory remaining after fixed allocations. Its two transform
buffers therefore consume spare budget, making the observed peak dependent
on the assigned cap. This explains why even the simpler Empty proof can
peak above the pair. Component reservation sums and observed peaks are
different quantities; a complete scheduler phase profile must account for
this adaptive workspace and simultaneous retained data.

Only the GPU-gated full-size test module changed after §9.62. The audit
checks **366 source files**, **three source archives**, **40 new artifacts**
and the **179 parent artifacts**. Formatting and whitespace checks pass.
All three proof services terminate, their leaf slices are inactive and
empty, and no GPU lease remains. The remaining parent slices contain no
processes.

The demonstrated merge has an Empty right child. Full-size merges with two
nonempty children, other paired transaction kinds, larger blocks, cache
reuse and sustained throughput still need qualification. Complete scheduler
lifetime profiles and AMD/Metal qualification also remain open. The overall
GPU goal is active; proof formats, parameters, registry identities and
consensus activation are unchanged.

Evidence: [`gpu-full-size-recursion-2026-10-10.json`](evidence/gpu-full-size-recursion-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-full-size-recursion-20261010`.

## 9.64 Audited LDE plans and 7 GiB recursive proving (2026-10-10)

Full-size finalization and the pair-plus-Empty merge now also complete
under a **7 GiB managed GPU cap**, with the same 3 GiB host cap, zero swap,
four CPU threads, 4 GiB context reserve and 1 GiB free-memory guard.
All 16 proving arithmetic stages report OpenCL. Serialized proofs verify
on CPU after GPU shutdown, altered statements are rejected, and the GPU
context remains absent during verification. The registry, inputs and
262,144-row geometry are pinned to the preceding checkpoints.

| Qualification | Managed cap | Measured managed peak | Cold wall time | Reported host peak |
| --- | ---: | ---: | ---: | ---: |
| Finalizer reference | 9 GiB | 9,614,729,664 bytes (8.95 GiB) | 71.52 s | 1.2G |
| Finalizer with lower cap | 7 GiB | 7,467,246,016 bytes (6.95 GiB) | 71.55 s | 1.2G |
| Merge with lower cap | 7 GiB | 7,397,673,760 bytes (6.89 GiB) | 124.80 s | 2.1G |

The only production change is versioned `bounded_gpu_lde_plan` telemetry.
It records the operative plan's observed live allocations, replaced hash
workspace, owned outputs, salt replay scratch, hash/sponge/tree/query
allowances, transform tile and predicted peak. This is an admission
snapshot, not a completed arithmetic receipt. The existing allocator and
per-operation admission continue to enforce the assigned cap.

An independent Python audit checks all **15 recorded plans** from the
three proofs. It reconstructs fixed storage, checks the sum of fixed bytes
and both transform buffers, verifies whole-column geometry and confirms
the selected power-of-two tile against both total and single-allocation
limits. The finalizer's five fixed terms are identical at both caps.
Reducing the cap changes its tile widths from **32/32/32/4/4** columns to
**16/16/16/4/4**, lowering the measured peak by exactly **2 GiB**. The merge
uses **16/16/8/4/2** columns at 7 GiB. Recorded one-column minima are only
snapshot bounds; successful complete proofs additionally qualify the
other phases at this cap for these inputs.

This does not establish higher throughput: each measurement is one cold
proof with one setup and no cache hits. It also does not supply a complete
scheduler lifetime profile. The current Python `extra_host_reserve` still
totals **4,316,931,420 bytes** for the merge by combining witness compiler
and manifest storage with lookup random staging, opening FRI-vector
readback and CPU FRI salt staging. Several terms describe host transfers
absent from the fully owned GPU path; others belong to different lifetimes.
Those paths must be traced before changing admission. In particular,
`lookup_random_host_reserve` also supplies a sample-size term to the GPU
reservation, so simply zeroing it would incorrectly shrink that reservation.

Formatting and whitespace checks pass. The audit verifies **366 source
files**, **three source archives**, **47 new artifacts**, **40 parent
artifacts** and **179 ancestor artifacts**. All three services are terminal,
their leaf slices are empty, and no GPU lease remains. The host lifetime
model, a complete scheduler profile, broader transaction/merge cases,
cache reuse, sustained pool throughput and AMD/Metal remain open.

Evidence: [`gpu-lde-phase-plans-2026-10-10.json`](evidence/gpu-lde-phase-plans-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-lde-phase-plans-20261010`.

## 9.65 GPU witness host retention and transfer accounting (2026-10-10)

The GPU witness cache now releases its host instruction, row and port words
after the upload fence completes. `PreparedWitness` retains only dimensions
and a compact launch schedule, alongside the existing device allocation and
context ownership check. The full-size merge uploads **621,708,376 bytes**
but retains only **63,152 bytes** of host schedule; the finalizer uploads
**311,642,160 bytes** and retains the same schedule size. GPU conformance
checks prove the source `Arc` expires before subsequent preprocessing and
witness execution, including reuse across fresh sessions and error recovery.

Rust and Python admission now reserve source storage and a conservative
schedule bound for every cache entry. Setup compiler/manifest storage plus
staging and incoming source/input storage are separate lifetimes: reserve
their maximum, while retaining the full cache throughout. The schedule
bound uses the compiler allowance minus uploaded metadata; worker coverage
checks that difference as well as both original bounds, so increasing the
declared metadata cannot silently reduce the admitted host schedule. Full
trace debug readbacks and the symbolic compiler allowance remain covered.

Host transfer accounting now follows the selected storage and RNG paths:

- Lookup sample geometry has its own helper. Device RNG removes the host
  sample matrix while preserving the identically sized GPU allocation.
- Resident FRI consumes opening vectors on GPU; raw and converted claims
  still have a host allowance. The nonresident path keeps vector readback.
- Device RNG removes host FRI salt staging. Query output and metadata stay
  reserved, and the host RNG path keeps its actual salt staging.

For the full-size merge, these absent host transfers account for
**803,209,216 bytes (766 MiB)**. With the released witness upload and the
explicit incoming-source lifetime, its witness host bound changes from
**3,209,260,380** to **2,610,980,304 bytes**. The complete
`extra_host_reserve` component sum changes from **4,316,931,420** to
**2,915,442,128 bytes**. Device reservations are unchanged for all twelve
archived mode profiles. This is a component accounting correction, not a
complete scheduler workload profile: phase heap, driver, spill and adaptive
GPU allocations must still be qualified through scheduler admission.

| Full-size proof | Cold wall time | Managed GPU peak | Reported host peak before → after |
| --- | ---: | ---: | ---: |
| Pair-plus-Empty merge | 124.84 s | 7,397,673,760 bytes | 2.1G → 1.8G |
| Finalizer | 71.62 s | 7,467,246,016 bytes | 1.2G → 1G |

Both runs use the authorized desktop RTX 5080, **7 GiB managed GPU** and
**3 GiB host** caps, zero swap, four CPU threads and the 180-second limit.
All **16 arithmetic stages report OpenCL** and all six receipts per proof
succeed. The 1,683,948-byte serialized proofs verify on CPU after GPU
shutdown and reject altered statements. All ten recorded LDE plans have
the same fixed terms and tile selections as §9.64; measured GPU peaks are
also unchanged. Reported host peaks are rounded cgroup measurements.
Single cold runs establish correctness and memory behavior, not higher
sustained transaction throughput.

Validation passes **52 Python scheduler tests**, **10 native component
cases**, both full-size proofs and the offline `block-v2,stream` CPU build
check. The evidence audit verifies **366 sources**, **three source archives**
and **49 artifacts**, with hashes for the controllers, logs, binaries and
inputs. Formatting and whitespace checks pass. All native services have
terminated, GPU leases are released, and the ten remaining parent slices
are empty. No commit or push was made.

The overall GPU goal remains active. Next work is the complete scheduler
lifetime profile and real scheduler/worker qualification, followed by
full-size cache reuse, two nonempty merge children, broader transaction
kinds, larger blocks, sustained pool throughput and AMD/Metal qualification.
Proof formats, parameters, registry identities and activation are unchanged.

Evidence: [`gpu-witness-host-retention-2026-10-10.json`](evidence/gpu-witness-host-retention-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-witness-host-retention-20261010`.

## 9.66 Full-size cached native worker (2026-10-10)

The persistent native worker now has qualification with all twelve actual
archived registry keys at height 262,144. The coordinator CPU-verifies the
archived wallets and imports verified pair, Empty and merge dependencies into
the durable DAG. It submits two distinct finalizer jobs: the pair itself and
its pair-plus-Empty merge. Their dependencies differ, while their independently
derived terminal statements are equal.

Both jobs execute through the independently linked C service,
`lattica_gpu_public_worker_serve`, supervised `ProcessWorker`, authenticated
`LaunchStore` tokens, framed IPC and durable reconciliation. Each reports all
16 proving arithmetic stages on OpenCL. The coordinator independently
CPU-verifies both results, rejects altered COUNT statements, and re-verifies
the saved results after the worker exits. Distinct proof bytes and cache
counters establish that both jobs execute, with one setup and one cache hit.

| Full-size worker measurement | Result |
| --- | ---: |
| Cold finalizer | 73.0845 s |
| Warm finalizer | 18.2675 s |
| Whole full-size qualification check | 96.0399 s |
| Each proof | 1,683,948 bytes |
| Worker cgroup memory peak | 1,302,663,168 bytes (1.2132 GiB) |
| Worker telemetry samples | 186 |
| Swap / OOM events | 0 / 0 |

The service limits are 7 GiB of managed GPU memory, 3 GiB of host memory,
four CPU threads and 180 seconds, within a 4 GiB aggregate host slice. Host
telemetry checks the exact observed cgroup identity against the recorded
device and inode. No actual aggregate managed-GPU peak is exported by this
C service; the claim is the enforced cap plus nine audited operative LDE
plans. Cold tiles are 16/16/16/4/4 columns and warm tiles are 16/16/4/4,
with a maximum predicted snapshot peak of 7,467,248,064 bytes. These snapshots
do not constitute a complete scheduler lifetime model.

Only the GPU-gated native worker test module changes from §9.65; production
proving code is unchanged. The research executable and static library builds,
four native worker unit cases, one FFI pointer case, the existing small
two-proof C-service regression, the full-size two-proof case and CPU-only
compatibility check pass. The first build exposed a missing test import;
it was corrected before the successful build, and both logs are retained.
There are seven native test cases, four GPU proofs and 22 successful stage
receipts. Each two-job service uploads witness metadata once and reports one
preprocessing setup.

The evidence pins 366 sources, one source archive and 104 root artifacts;
the finalized audit verifies 94 run artifacts and 49 parent artifacts.
Formatting and whitespace checks pass. Cleanup records no running Lattica
services or held GPU leases, with twelve empty parent slices. Executed
controllers and finalized artifact directories remain immutable.

This establishes full-size native delivery and warm-cache reuse for these
finalizers, not sustained transactions per hour or complete block production.
GPU-owned scheduler lifetime profiles and admission, full-size merges of two
nonempty children, other transaction kinds, larger blocks, sustained pool
throughput, multi-GPU saturation and AMD/Metal qualification remain open.
Proof formats, parameters, registry identities and consensus activation are
unchanged.

Evidence: [`gpu-full-size-cached-worker-2026-10-10.json`](evidence/gpu-full-size-cached-worker-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-full-size-cached-worker-20261010`.

## 9.67 Native worker GPU memory accounting (2026-10-10)

The shared GPU allocator now supports one measurement window per serial
worker job. Each window includes allocations already live at entry and
updates its peak on every successful reservation, so short-lived buffers
are counted even if they are gone before the job finishes. Lifetime peaks
remain cumulative. Overlapping windows reject, and dropping an unfinished
window clears only its measurement state; it cannot release allocation
leases or erase lifetime counters.

The typed process worker, shared by the CLI and native C service, emits
structured `typed_gpu_memory` records after each existing job drain and
after shutdown. The shutdown window retains only the accounting Arc, so
it can observe the final zero without retaining any device resources.
Records contain the service PID, job index or completed-job count, start
and end usage, window and lifetime peaks, new allocation counts, largest
new allocation, retained trees, device matrices and enforced limits.
These diagnostic records do not change the framed worker protocol and
confer no proof acceptance, admission or worker-termination authority.

The independently linked C service repeats the small two-Empty regression
and the full-size two-finalizer case from §9.66. Both use the 7 GiB managed
GPU cap, 3 GiB service host limit, four CPU threads and 180-second service
limit within a 4 GiB aggregate slice. The full-size case retains all twelve
archived keys at height 262,144, CPU-verifies both outputs, rejects changed
statements and re-verifies saved outputs after worker exit. All four GPU
proofs report all 16 proving arithmetic stages on OpenCL.

| Full-size native worker measurement | Result |
| --- | ---: |
| Cold job time / managed allocation peak | 71.7995 s / 7,467,246,016 bytes |
| Warm job time / managed allocation peak | 17.3605 s / 7,467,247,040 bytes |
| Managed bytes retained between jobs | 2,022,919,936 bytes (1.8840 GiB) |
| Retained preprocessing tree | 536,870,880 bytes |
| Retained device matrices | 3 / 1,418,938,416 bytes |
| Largest new allocation in either job | 1,073,741,824 bytes |
| Managed bytes after shutdown | 0 |
| Worker cgroup host peak | 1,302,798,336 bytes (1.2133 GiB) |
| Swap / OOM events | 0 / 0 |

The small fixture independently demonstrates that a warm window does not
inherit the cold peak: its peaks are 333,441,768 and 224,462,152 bytes,
while its lifetime peak remains 333,441,768. Both fixtures check the report
PID against the observed service identity, continuity from one job's end
to the next job's start, cap compliance, retained cache charges and full
release after shutdown. Four malformed/bootstrap/disconnect cases also
clean up without a successful job/shutdown measurement report or premature
release of coordinator reservations.

Three pure allocator tests cover retained baselines and transient peaks,
overlapping/aborted windows, and rejected/overflowing reservations. Together
with four native worker unit cases, one FFI case and three service cases,
eleven native cases pass. Research executable/static-library builds and
CPU-only compatibility pass. The first build attempt was blocked by the
sandbox's user-bus restriction before compilation; the authorized capped
retry passed, and both logs are retained.

The finalized audit checks 367 pinned sources, one source archive, 128 run
artifacts, 104 parent artifacts, 22 successful stage receipts and nine
operative LDE plans. It retains 181 exact-cgroup host telemetry samples.
Evidence pins 138 root artifacts and the audit output separately. Formatting
and whitespace pass. Cleanup confirms no running Lattica services or held
GPU leases and fourteen empty parent slices.

The approximately 1.884 GiB idle cache must stay reserved between jobs.
These managed reservation counters exclude driver/context VRAM and host
memory; they are not whole-device physical memory measurements. They close
the native-service measurement gap from §9.66, not the scheduler lifetime
model. Adaptive LDE admission must reserve its enforced managed cap or
impose an actual tile limit, rather than treating a measured peak or a
conservative fixed-allocation snapshot as a universal upper bound.
GPU-owned scheduler profiles, broader full-size proof cases, sustained pool
throughput, multi-GPU saturation and AMD/Metal qualification remain open.
Proof formats, parameters, registry identities and activation are unchanged.

Evidence: [`gpu-worker-memory-windows-2026-10-10.json`](evidence/gpu-worker-memory-windows-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-worker-memory-windows-20261010`.

## 9.68 Worker GPU allocation limits (2026-10-10)

The scheduler review found that the public worker's
`gpu.max_allocation_bytes` was used in resource planning but did not constrain
the shared engine. The §9.67 assignment allowed 1,073,741,824 bytes per buffer,
while its runtime reported the hardware maximum of 4,175,986,688 bytes. Those
measured jobs happened to allocate no buffer larger than 1 GiB. A larger
adaptive transform could nevertheless have exceeded the assigned limit.

The engine now reads the public assignment through a bounded 1 MiB reader
before acquiring its device lease or creating a context, then uses the
minimum of the assigned and hardware maxima in every shared-engine plan and
managed buffer allocation. An existing engine binds that assignment: changing
or removing the limit rejects reinitialization, while restoring the original
assignment permits reuse. Public startup admission also rejects missing,
zero, negative and noninteger limits before initializing Rayon or the GPU.
Paths without a public-worker assignment retain their hardware limit and
aggregate managed cap. No new environment switch or worker protocol is added.

A real GPU conformance case enforces an 8 MiB per-buffer allowance within
64 MiB of managed memory. It selects 16-column transform tiles with 8 MiB
buffers, rejects an allocation eight bytes over the limit before charging
any reservation, and accepts/releases an allocation exactly at the limit.
Changing or removing the assignment cannot widen the live engine's limit;
an undersized initial allowance rejects without installing an engine.
Pure tests cover the hardware/assignment minimum, invalid fields and the
bounded assignment reader.

Both small C-service Empty jobs and both full-size finalizers pass with the
assigned **1 GiB per-allocation cap** enforced. All native memory reports
and all nine operative full-size LDE plans now report that cap. The
full-size managed peaks remain 7,467,246,016 and 7,467,247,040 bytes under
the unchanged 7 GiB aggregate limit. Cache retention remains 2,022,919,936
bytes between jobs and falls to zero on shutdown. The twelve-key registry,
262,144-row height, 3 GiB service host limit and 4 GiB aggregate host slice
are unchanged.

The two full-size jobs take 72.1841 and 17.3595 seconds. Their coordinator
independently CPU-verifies both proofs, rejects changed statements and
re-verifies the outputs after worker exit. All four GPU proofs, including
the small regression, report all 16 proving arithmetic stages on OpenCL.
These timings remain qualification results for two finalizers of the same
terminal statement, not sustained transaction throughput.

Twenty-four native cases pass, including nine startup-admission cases,
allocator/window tests, the 8 MiB GPU case, the C-service regressions and
four malformed/bootstrap/disconnect cleanup scenarios. Research executable
and static-library builds, CPU-only compatibility, formatting and whitespace
checks pass. The first build exposed a misplaced engine field and incorrect
test references to the LDE planner API; both were corrected before the
successful second build, and both logs are preserved.

The audit verifies 368 pinned sources, one source archive, 134 run artifacts,
138 parent artifacts, 22 successful stage receipts and nine LDE plans.
Evidence pins 144 root artifacts plus the audit output separately. Exact
worker-cgroup telemetry has 182 samples, a 1,304,842,240-byte host peak
(1.2152 GiB), zero swap and zero OOM events. Cleanup confirms no running
Lattica services or held GPU leases and sixteen empty parent slices.

This closes an enforcement gap needed for reliable scheduler admission.
Complete host/compiler and GPU lifetime profiles, explicit trace versus
committed-column geometry, broader full-size proof cases, sustained pool
throughput, multi-GPU saturation and AMD/Metal qualification remain open.
Proof formats, parameters, registry identities and activation are unchanged.

Evidence: [`gpu-worker-allocation-limit-2026-10-10.json`](evidence/gpu-worker-allocation-limit-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-worker-allocation-limit-20261010`.

## 9.69 Raw trace and committed-column geometry (2026-10-10)

The scheduler now distinguishes raw witness columns from the wider matrices
committed by the hiding PCS. GPU witness profiles must provide
`geometry.main_trace_columns` and
`geometry.permutation_trace_columns_upper_bound`. The latter counts flattened
base-field columns, including the lookup accumulator. The existing
`main_columns` and `permutation_columns_upper_bound` remain committed widths:
each nonempty private trace adds four hiding columns; an empty lookup stays
zero. Preprocessing has no hiding columns. Missing, partial, noninteger or
inconsistent explicit geometry rejects before an assignment is produced.

Witness allocation bounds cover raw geometry and can be conservative. RNG
assignments preserve those larger witness allowances without treating them as
the actual committed width. Opening claims and retained-prefix/quotient
reservations use committed columns; lookup sample allocations use raw
columns. Legacy profiles without GPU witnesses keep their previous
conservative accounting, including existing query slack.

The archived full-size profile used 94 main columns in both witness bounds
and commitment geometry, although native LDE plans commit 98. Its main
capture was undercounted by **16 MiB**. A new qualification profile specifies
94 raw / 98 committed main columns, 51 raw / 55 committed permutation columns
and 200 preprocessing columns. The owned quotient/prefix reservation rises
from **5,410,652,160 to 5,460,983,808 bytes** (48 MiB across the three prefix
sets). Witness reservations are unchanged. The RNG lookup bound becomes 51;
its reservation size is unchanged because other allocations dominate.
Old artifact profiles and controllers remain intact.

All **169 Python cases** across seven scheduler/controller suites pass,
including ambiguous-geometry rejection, conservative witness bounds, empty
lookups and legacy compatibility. Native sources are unchanged, so this run
reuses the exact §9.68 Rust executable and linked C service, with their build
and CPU-compatibility provenance pinned. The public C worker accepts the
corrected assignment and proves both full-size finalizers. All 16 proving
arithmetic stages per request run on OpenCL; the coordinator independently
CPU-verifies both outputs, rejects altered statements and verifies the
outputs again after worker exit. All nine LDE plans match the corrected
commitment widths and captured byte counts.

The jobs take **72.5750 / 17.3250 seconds** with unchanged 7 GiB managed GPU,
1 GiB per-allocation, 3 GiB worker host and 4 GiB aggregate host limits.
Managed peaks remain 7,467,246,016 / 7,467,247,040 bytes; the 2,022,919,936-byte
idle cache falls to zero at shutdown. There are 183 host telemetry samples,
a 1,310,605,312-byte worker peak, zero swap and zero OOM events. Cleanup finds
no running services or GPU leases and eighteen empty parent slices.

The final audit verifies 368 source hashes, one archive, 75 run artifacts,
the prior checkpoint's 144 artifacts, eleven stage receipts and the geometry
of all nine LDE plans. The initial audit included its still-open stdout log
in its root pins; the final audit runs without that redirection and all its
pins verify. Both records are retained.

This closes the width-accounting ambiguity, not the complete scheduler
lifetime model. The corrected qualification profile still has no phases
and is rejected by ordinary fleet admission. Adaptive transforms must
reserve their enforced aggregate cap unless a runtime tile constraint is
introduced; compiler/source/cache host lifetimes still need a complete
profile. Broader proof cases, sustained pool throughput, multiple GPUs and
AMD/Metal qualification remain open. These two finalizer timings are not a
transaction-throughput measurement. Proof formats, parameters, registry
identities and activation are unchanged.

Evidence: [`gpu-worker-trace-geometry-2026-10-10.json`](evidence/gpu-worker-trace-geometry-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-worker-trace-geometry-20261010`.

## 9.70 Program packing host lifetimes (2026-10-10)

Tracing host lifetimes found two unnecessary allocations before GPU witness
setup. `ProgramBuilder::finish` retained its construction interning tables
and constant-folding cache while it cloned operations into AIR rows and
allocated reference arrays. Geometric vector growth also gave each full
23-lane ALU row 32 operation slots, while the outer row vector could retain
spare capacity and temporarily coexist with its old allocation during growth.

The builder now moves out its immutable source operations and explicitly
drops the construction tables before allocating packed rows. A metadata-only
pass counts public, hash, ALU and cubic rows and rejects an invalid height
before those allocations. The outer row vector and each full or partial row
request their final sizes. Original source operations are moved without
copying. Row flush order, the trailing ALU-before-cubic order, hint routing,
reference counts and all field arithmetic remain unchanged.

For the same full-size finalizer, actual retained program source falls from
**571,816,240 to 506,224,936 bytes**, a **65,591,304-byte (62.6 MiB)** reduction.
Metadata, compiler scratch, wire/input counts and trace geometry are
unchanged. The worker's observed host peak falls from **1,310,605,312 to
1,107,386,368 bytes**, or **15.5%**, in this matched qualification. This is a
measurement for this fixture; the existing conservative witness assignment
and the 3 GiB worker / 4 GiB aggregate host limits remain unchanged.

All **20 native cases** pass: five packing cases in each of the standard and
wide lane configurations, two metadata compiler cases, five witness-resource
cases, two GPU witness conformance cases and the full-size C-service case.
Tests cover empty/public-only programs, full/partial row capacities,
interleaved row order, hint routing and malformed programs. GPU conformance
compares witness and preprocessing values against the CPU reference across
program shapes and fresh sessions, and checks bounded failure/reuse.

The C service produces both full-size finalizers using the unchanged
twelve-key registry. All 16 arithmetic stages per proof request execute on
OpenCL. Independent CPU verification accepts both outputs, rejects altered
statements and re-verifies after worker exit. The jobs take
**71.9180 / 18.5507 seconds**. These remain two finalizers of the same terminal
statement through distinct verified dependencies, not sustained transaction
throughput measurements.

GPU memory behavior is unchanged: peaks of 7,467,246,016 / 7,467,247,040 bytes
under the 7 GiB managed cap, a 1 GiB maximum allocation, 2,022,919,936 bytes
retained between jobs and zero managed bytes after shutdown. There are 184
host telemetry samples, zero swap and zero OOM events. Cleanup confirms no
running services or held GPU leases and twenty empty parent slices.

Research executable, static-library and CPU test builds pass offline under
the established 3 GiB / four-CPU / 180-second service limits. The first build
caught an incorrect `bit` call in the new tests; it was corrected to the
existing `bit_hint` API, and both logs are retained. Formatting, whitespace
and the artifact audit pass. Build commands and both native feature sets
are recorded with the artifacts.

This simplifies the packing lifetime and reduces retained source storage.
Construction map growth and reallocations **before** `finish` still need an
explicit bound, alongside the remaining host/compiler lifetimes. The
qualification profile still has no phases and ordinary fleet planning
rejects it. Adaptive GPU phases must reserve their enforced aggregate cap
unless runtime tile constraints are added. No scheduler allowance has been
reduced from measured peaks. Broader proof cases, sustained pool throughput,
multiple GPUs and AMD/Metal qualification remain open. Proof formats,
parameters, registry identities and activation are unchanged.

Evidence: [`gpu-program-packing-2026-10-10.json`](evidence/gpu-program-packing-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-program-packing-20261010`.

## 9.71 Bounded program construction (2026-10-10)

The packing change in §9.70 released construction tables before row
allocation. The preceding construction phase now also has an enforced
allowance. Assigned device builders reuse `witness_bounds.program_host_bytes`
for both construction and packing. They read and validate the existing
bounded worker assignment; there are no new assignment fields or environment
switches. CPU and unassigned builders retain their existing unassigned mode.

Interning maps and sets now use explicitly sized slot vectors with randomized
hashes, full-key equality and bounded occupancy. They only serve lookup and
insertion, so table order does not affect operation order or program identity.
One shared counter covers every table, operation buffers and retained hint
vectors. Growth admits the complete replacement buffer while the old buffer
remains charged, moves entries, then releases the old charge. Overflow or
quota failure latches rejection before that allocation; subsequent builder
operations and proof-input value collection stop growing.

After dropping construction tables, packing admits source operations, source
and cloned hints, exact row storage, reference/definition arrays and bounded
temporaries against the same allowance. Assigned wire and input counts are
also enforced. `finish` returns an error for a failed builder, with a
`bounded_program_construction` diagnostic identifying the phase, allowance
and admitted peak. These counters describe requested builder storage, not
physical RSS or all compiler allocations.

All **35 native cases** pass: twelve construction/packing cases in each of
the wide and standard lane configurations, two metadata compiler cases,
five witness-resource cases, two GPU witness conformance cases, a native
construction rejection case and the full-size C-worker finalizer case.
Boundary tests cover colliding keys, replacement, shared table allowances,
simultaneous old/new table and operation buffers, exact-cap and one-byte-short
admission, hints/packing, latched failure, wire/input limits and overflow.

The native rejection case sends a valid leased Empty request with a
**one-byte** construction allowance and a recomputed witness reservation.
It rejects with **zero admitted builder bytes**, before witness setup or
LDE planning, completes no job, retires the GPU and preserves the descriptor.
Scheduler reservations remain held after the failure. The test's candidate
anchor is metadata only; synthetic wallet proofs never enter the worker.

Both full-size construction passes report **508,066,244 bytes** against the
unchanged **571,816,240-byte** allowance. Retained program source remains
**506,224,936 bytes**; metadata, compiler bounds, wire/input counts and trace
geometry match §9.70. The C service produces two independently CPU-verified
proofs under the original twelve-key registry, rejects altered statements,
and verifies the outputs again after exit. All **16 arithmetic stages per
proof request** complete on OpenCL. Cold/warm jobs take **71.8611 / 17.4176
seconds**. They finalize the same terminal statement through distinct
verified dependencies and do not measure sustained transaction throughput.

The observed worker host peak is **1,099,972,608 bytes** across **181 samples**,
with zero swap and zero OOM events. Managed GPU peaks are
7,467,246,016 / 7,467,247,040 bytes, with 2,022,919,936 bytes retained between
jobs and zero after shutdown. The enforced limits remain 7 GiB managed GPU,
1 GiB per allocation, 3 GiB worker host and 4 GiB aggregate host. Cleanup
finds no running workers or held GPU leases and twenty-one empty parent
slices. No allowance has been reduced from these measurements.

Research executable, static library and standard-lane CPU builds pass
offline under the established four-CPU, zero-swap, 180-second service caps.
The initial unit fixture inferred the wrong integer slot type. Two native
fixture attempts stopped before worker launch because of a shallow candidate
and a process-owned task API used by the raw socket harness. All were
corrected; their logs, executed controllers and source archives are retained
unchanged. The successful audit verifies **371 source files**, **89 run
artifacts**, the preceding checkpoint's **87 artifacts**, and all nine native
LDE plans. Evidence pins **217 artifacts** across this checkpoint, including
failed attempts. Formatting and whitespace checks pass.

Remaining host work includes caller-owned proof data, temporary wire arrays,
fixed folding/symbolic scratch, cached programs and allocator/driver overhead
under complete enclosing lifetime reservations. Hint entry vectors are
allocated by callers before adoption, so this cap does not retroactively
bound their allocation. `Bounds::for_program` still describes retained source
storage; future profile generation must also allow the enforced construction
and packing requirement. This is not a complete host/compiler lifetime model.

The qualification profile still has no phases and ordinary fleet planning
rejects it. Adaptive GPU phases must reserve their enforced aggregate cap
unless runtime tile constraints are introduced. Broader proof cases, sustained
pool throughput, multiple GPUs and AMD/Metal qualification remain open.
Proof formats, parameters, registry identities and activation are unchanged.

Evidence: [`gpu-program-construction-2026-10-10.json`](evidence/gpu-program-construction-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-program-construction-20261010`.

## 9.72 Compiler lifetime accounting (2026-10-10)

Program admission now preserves the construction requirement introduced in
§9.71. A completed `Program` retains its peak requested builder storage,
including packing and scoped scratch, across cloning and padding. Equality
continues to compare operations, rows, references, public/witness counts and
height. Canonical manifest encoding excludes this admission metadata, so a
different construction history cannot change a program's identity or prevent
an otherwise valid cache hit.

`Bounds::for_program` supplies the larger of this construction requirement
and current retained source capacity in `program_host_bytes`. Profiles
derived from those bounds now include construction storage. Current capacity
is still checked independently, including when it exceeds recorded history.
The requirement describes the recorded compiler path; a different path that
produces an equal program can need a larger allowance, and runtime admission
still rejects excess growth.

The Merkle compiler also brings its temporary storage into the shared
allowance. Leaf hashing streams each row and salt through the existing
padding-free sponge instead of building a concatenated vector. Cap reduction
uses one fixed, admitted digest buffer and overwrites consumed pairs in
place. Hint entry callbacks run only after their exact storage is admitted.
The callback is invoked a fixed number of times, independent of iterator
size hints. Scoped scratch remains charged while operation buffers grow and
is released after either success or an ordinary error. Caller-owned cap,
row and proof inputs retain their separate lifetimes.

All **48 native cases** pass: sixteen construction/packing cases and two
Merkle cases in each lane configuration, two metadata compiler cases, six
witness-resource cases, two GPU witness conformance cases, the native
construction rejection case and the full-size C-worker case. New boundaries
cover rejected callbacks, scratch overlapping operation growth, release on
error, exact-cap reconstruction, identity-preserving provenance and current
retained capacity exceeding construction history. Native Merkle comparisons
cover cap heights **0, 1, 3, 6 and 7**, five leaf indices at each height, altered
rows and partial sponge blocks.

Both full-size constructions report **508,066,252 bytes**, and their resource
bounds now carry that same requirement. The assigned allowance stays at
**571,816,240 bytes**. Metadata/compiler bounds, raw/committed trace geometry,
wire/input counts, the twelve-key registry and proof encoding remain
unchanged. Both proofs complete all **16 arithmetic stages on OpenCL** and
pass independent CPU verification, altered-statement rejection and
verification after worker exit. Cold/warm jobs take **71.9828 / 18.4093
seconds**. They finalize the same terminal statement through distinct
verified dependencies; sustained transaction throughput remains unmeasured.

Worker host peak is **1,101,590,528 bytes** across **184 samples**, with zero
swap and zero OOM events. GPU peaks remain 7,467,246,016 / 7,467,247,040 bytes,
with 2,022,919,936 retained between jobs and zero after shutdown. Limits stay
at 7 GiB managed GPU, 1 GiB per allocation, 3 GiB worker host and 4 GiB
aggregate host. Cleanup confirms no running workers or held leases and
twenty-three empty parent slices. No allowance was reduced from observations.

Research, static-library and CPU builds pass offline under the existing
four-CPU, zero-swap, 180-second service caps. The audit verifies **371 source
files**, five before-source copies against §9.71, **91 run artifacts**, all
**217 parent artifacts** and nine LDE plans. Evidence pins **108 artifacts**
for this checkpoint. Formatting and whitespace checks pass.

Remaining compiler work includes manifest encoding and vector growth:
`Program::manifest_fields` clones row operations, and
`program_identity_fields_prepared` extends another manifest vector with its
result. Their overlapping storage needs an explicit allocation layout.
Caller-owned proof data, remaining wire arrays, fixed folding/symbolic
scratch, caches and driver/allocator overhead also need complete enclosing
lifetime reservations. These counters bound requested builder storage and
do not establish a complete host-memory model.

Ordinary fleet planning still rejects the phase-less qualification profile.
Adaptive GPU phases must reserve their enforced aggregate cap unless runtime
tile constraints are introduced. Broader proof cases, sustained pool
throughput, multiple GPUs and AMD/Metal qualification remain open. Proof
parameters, registry identities and activation are unchanged.

Evidence: [`gpu-compiler-lifetimes-2026-10-10.json`](evidence/gpu-compiler-lifetimes-2026-10-10.json).
Artifacts: `lattica-prover-p3/benchmark-results/gpu-compiler-lifetimes-20261010`.


## 9.73 Bounded manifest streaming (2026-10-10)

GPU program registration now hashes the canonical identity without building
complete program and identity vectors. `Program::emit_manifest` borrows rows
and hint storage, emits operation addresses from fixed stack arrays, and
stops immediately on consumer failure. The existing CPU collection API
retains the same field order and uses a counted, exact-capacity output.

The device public hash accepts a replayable field producer. Its first pass
validates the domain, every field and the total length before device
allocation or upload. Its second pass feeds **4,096-word / 32 KiB** host
scratch into the existing GPU sponge, checking the count and canonical form
again. Empty input, partial final batches and the original length binding
remain unchanged. Short or long replays, noncanonical values, producer
errors and ignored sink failures return no digest. Completed device batches
remain reported on failure; scoped device buffers are drained and released.
The identity producer borrows immutable program, fingerprint and commitment
data across both passes. This API checks replay length and canonical form;
it does not compare two same-length canonical streams for equal contents.

The GPU fingerprint encoder separately admits explicit fixed-capacity
pointer tables, node fields and root arrays before allocating them. Its
**32 MiB** allowance is contained within the existing **192 MiB** symbolic
compiler reserve. Combined node, root and layout counts each have a
**131,072** limit, and traversal has a **512** depth limit. It preserves
child-first node numbering, pointer-based DAG sharing and constraint order.
It drops the pointer tables before appending roots/layout, and uses fixed
coefficient arrays instead of per-node vectors. The CPU fingerprint encoder
provides an independent compatibility reference.

All **63 native cases** pass: eighteen program/construction cases, two
Merkle cases and two fingerprint cases in each lane configuration; two
metadata cases, six witness-resource cases, two public-hash unit cases,
five GPU public-hash cases, two GPU witness cases, the native construction
rejection case and the full-size worker case. Compatibility checks cover
every program row and operation family, hints, public banks, shared symbolic
subexpressions and reordered constraints. Rejection cases exercise exact
host allowance boundaries, node/root/layout/depth limits, malformed stream
replays, policy rejection before source evaluation and device cleanup after
partially completed work.

The full-size identity emits **13,263,913 fields** through **3,239 batches**,
with **106,111,304 bytes uploaded** and **32 bytes downloaded**, matching
§9.72 exactly. The retained fingerprint buffer requests **5,249,768 bytes**.
There is no full identity vector in this GPU path. Both proofs retain the
original twelve-key registry and unchanged proof encoding, report all
**16 arithmetic stages on OpenCL**, and pass independent CPU verification,
altered-statement rejection and verification after worker exit. Cold/warm
jobs take **72.4365 / 17.4309 seconds**. These finalizers prove the same
terminal statement through distinct verified dependencies; these timings
do not establish sustained transactions per hour or a throughput gain.

Construction bounds remain **508,066,252 bytes** against the unchanged
**571,816,240-byte** assignment. Worker host peak is **1,101,000,704 bytes**
over **183 samples**, with zero swap/OOM. Managed GPU peaks are
**7,467,246,016 / 7,467,247,040 bytes**, with **2,022,919,936 bytes** retained
while idle and zero after shutdown. Limits remain **3 GiB worker host /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB individual allocation**.
Cleanup finds no workers or held GPU leases and **25 empty parent slices**.
Observed peaks do not reduce scheduler reservations.

Evidence is pinned in
[`gpu-manifest-lifetimes-2026-10-10.json`](evidence/gpu-manifest-lifetimes-2026-10-10.json).
The successful artifact directory is
`lattica-prover-p3/benchmark-results/gpu-manifest-lifetimes-20261010/run-01`.
The audit verifies **375 source files**, **97 run artifacts** and **108
parent artifacts**; the checkpoint pins **117 root artifacts**, including
before-source copies, controllers, builds, source archive, worker binaries,
proofs, logs, telemetry, CPU compatibility checks and cleanup.

The full GPU/pool goal remains incomplete. Caller-owned proof inputs,
remaining compiler temporaries, other symbolic/folding scratch, cached
programs and allocator/driver overhead still need complete enclosing
lifetime reservations. Scheduler phases, broader full-size workloads,
sustained throughput, multiple GPUs and AMD/Metal qualification remain
open. This checkpoint changes no proof profile or activation.


## 9.74 Expression memo lifetimes (2026-10-10)

The base and extension memo tables used to lower symbolic constraints now
share the program builder's construction allowance. They use its explicit
slot-vector accounting, randomized hashing and full-key equality. Growth
admits the old and new arrays simultaneously before allocation; memo hits
and replacements do not allocate. A quota failure latches builder rejection
and prevents further lowering, including reuse of an already cached result.

`Lowerer` owns both tables while exclusively borrowing the builder. On
scope exit it frees their backing arrays and releases the exact admitted
capacities, including ordinary error and unwind paths. The recorded
construction peak survives release and continues into the completed
program's resource bounds. Other evaluation vectors and caller-owned
symbolic/proof data retain their separate lifetimes.

Four new tests in each lane configuration cover simultaneous table growth
at an exact quota boundary, retained entries after rejection, scope release
on success/error/unwind, and latched failure on cached lookups. A frozen
copy of the previous lowerer compares operation order, wire identifiers,
program equality, canonical manifests and evaluated values for all base
and extension variable families, arithmetic expressions and shared DAGs.
All **60 relevant native cases** pass: twenty-two program/construction and
two Merkle cases per lane configuration, two metadata cases, six resource
cases, two GPU witness cases, native construction rejection and the full-size
worker case. The unchanged fingerprint/public-hash primitives retain §9.73's
qualification; this checkpoint does not recount those tests as newly run.

Both full-size compilations report releases of **655,360 base-memo bytes**
and **81,920 extension-memo bytes** before packing. The audit verifies each
release against its live counter and checks both release pairs precede their
packed constructions. The pre-packing construction peak is **499,427,392
bytes**; the final requirement remains **508,066,252 bytes**, below the
unchanged **571,816,240-byte** assignment. Program/registry identities and
proof encoding are unchanged. Both proofs complete all **16 arithmetic
stages on OpenCL**, pass independent CPU verification and altered-statement
rejection, and verify again after worker exit.

Cold/warm jobs take **73.9639 / 17.3971 seconds**. These jobs finalize the
same terminal statement through distinct verified dependencies and do not
measure sustained transactions per hour. Worker host peak is **1,101,426,688
bytes** over **186 samples**, with zero swap/OOM. Managed GPU peaks remain
**7,467,246,016 / 7,467,247,040 bytes**; idle storage is **2,022,919,936 bytes**
and shutdown storage is zero. The existing **3 GiB worker / 4 GiB aggregate
host / 7 GiB managed GPU / 1 GiB allocation** caps remain unchanged.
Cleanup confirms no workers or GPU leases and **27 empty parent slices**.

[`gpu-expression-lifetimes-2026-10-10.json`](evidence/gpu-expression-lifetimes-2026-10-10.json)
pins this checkpoint. The successful artifact directory is
`lattica-prover-p3/benchmark-results/gpu-expression-lifetimes-20261010/run-01`.
The audit verifies **377 sources**, **91 run artifacts** and **117 parent
artifacts**; the evidence pins **108 root artifacts**. Research executable,
static library, native service and standard-lane compatibility checks pass
under the established serial, offline, zero-swap limits.

The goal remains incomplete. Retained proof-input values, temporary wire
vectors, other symbolic/folding scratch, caller-owned decoded proofs,
cache overlaps and allocator/driver overhead still need complete enclosing
lifetime bounds. Scheduler phases, broader workloads, sustained pool
throughput, multiple GPUs and AMD/Metal qualification remain open. This
checkpoint changes no activation or proof profile.

## 9.75 Proof input lifetimes (2026-10-10)

`ProofInputs` now checks each requested group against the builder's input
and wire limits before allocating its returned wire array or invoking
input callbacks. Checked arithmetic rejects overflow; a latched builder
failure stops collection and drops partial output. Existing production
callers propagate the fallible base/extension collectors. Scalar input
helpers retain their fixed-size APIs, without growing retained value
storage after construction rejection.

Retained field values use explicit, fallible growth clipped to the input
limit. Each old or new backing array is within that limit, bounding their
simultaneous requested storage by twice the declared value count. This
storage belongs to the existing input staging reservation, separately
from the program construction allowance. The bound does not cover later
wire-vector clones/appends or caller-owned decoded proofs.

Five new tests in each lane configuration cover small/exact boundaries,
whole-group rejection before callbacks or builder mutation, exhausted
construction quotas, excessive existing capacity and arithmetic overflow.
A frozen previous collector checks input order, wire IDs, program equality,
canonical manifests and evaluated values. All **70 relevant native cases**
pass: twenty-seven program/construction/input and two Merkle cases per
lane configuration, two metadata cases, six resource cases, two GPU witness
cases, native construction rejection and the full-size worker case.

Both full-size compilations collect **211,083 values** with exactly
**211,083 capacity values / 1,688,664 bytes**. Each performs **17 growth
allocations**; the largest overlap is **2,737,240 bytes** for the old
131,072-value and new 211,083-value arrays. The audit derives the input
limit from the unchanged 211,106-value assignment minus 23 public values
and checks every growth transition. Both proofs preserve the registry,
complete all **16 arithmetic stages on OpenCL**, pass independent CPU
verification and altered-statement rejection, and verify after worker exit.

Cold/warm jobs take **72.8500 / 17.7219 seconds**. They finalize the same
terminal statement through distinct verified dependencies and do not
measure sustained transactions per hour. Worker host peak is
**1,102,733,312 bytes** over **184 samples**, with zero swap/OOM. Managed
GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**; idle storage is
**2,022,919,936 bytes** and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup confirms no workers or GPU leases and **29 empty parent
slices**.

[`gpu-input-lifetimes-2026-10-10.json`](evidence/gpu-input-lifetimes-2026-10-10.json)
pins **379 sources** and **114 root artifacts**. The audit also verifies
**91 run artifacts** and **108 parent artifacts**. The successful run is
`lattica-prover-p3/benchmark-results/gpu-input-lifetimes-20261010/run-01`.
Research executable, static library, native service and standard-lane
checks pass under the established serial, offline, zero-swap limits.

The goal remains incomplete. Temporary wire vectors and nested headers,
other symbolic/folding scratch, decoded caller proofs, cache overlaps and
allocator/driver overhead still need complete enclosing lifetime bounds.
Scheduler phases, broader workloads, sustained pool throughput, multiple
GPUs and AMD/Metal qualification remain open. This checkpoint changes no
activation, proof format, parameters or registry identity.

## 9.76 PCS compiler scratch (2026-10-10)

The uni/batch verifier compilers now lend opening values and commitments
to PCS verification. They no longer clone those wire buffers or allocate
nested round/matrix/point descriptor vectors. Random codeword additions
occupy a fixed suffix table, so adding randomness does not grow or copy
the borrowed openings. Transcript absorption and opening reductions visit
the original values followed by their random suffixes in the same order.

The supported compiler geometry is checked before use: at most **5 rounds,
32 matrices per round, 2 points per matrix**, and a domain logarithm
including blowup of at most **32**. These bounds cover the existing batch
and uni compiler shapes. Invalid counts and overflowing domain inputs
return errors. The random suffix table occupies **30 KiB** on this 64-bit
host; this is its fixed data capacity, not a complete stack/RSS estimate.
Fixed arrays also replace cap/beta/row headers, per-query `BTreeMap`
reductions, salt/sibling vectors and six-wire FRI rows. Cap and query-row
payloads still use the fallible, bounded proof-input collectors from §9.75.
The MMCS helper accepts borrowed rows without changing their hash order.

Three new tests per lane configuration compare against a frozen previous
PCS compiler and reject oversized descriptors/authentication scratch and
domain overflow. Reference comparisons cover mixed heights, repeated-height
reductions, preprocessing, one/two points and the maximum matrix count,
with identical input values and canonical manifests. Existing real uni,
wallet and batch proof tests also pass their tampering checks.

All **82 relevant native cases** pass: **47** in the research build and
**35** standard-lane compatibility cases. Both full-size finalizers preserve
the original registry, complete all **16 arithmetic stages on OpenCL**, pass
independent CPU verification and altered-statement rejection, and verify
after worker exit. The construction requirement remains **508,066,252
bytes**, within the unchanged **571,816,240-byte** assignment.

Cold/warm jobs take **71.7660 / 17.4054 seconds**. They finalize the same
terminal statement through distinct verified dependencies; these timings
do not measure sustained transactions per hour. Worker host peak is
**1,099,874,304 bytes** over **181 samples**, with zero swap/OOM. Managed GPU
peaks remain **7,467,246,016 / 7,467,247,040 bytes**; idle storage is
**2,022,919,936 bytes** and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup confirms no workers or GPU leases and **31 empty parent
slices**.

[`gpu-pcs-scratch-2026-10-10.json`](evidence/gpu-pcs-scratch-2026-10-10.json)
pins **381 source files** and **135 root artifacts**. Its successful run is
`lattica-prover-p3/benchmark-results/gpu-pcs-scratch-20261010/run-02`.
The audit verifies **97 successful-run artifacts** and **114 parent
artifacts**. Run 01 is preserved: its tests passed, but its controller
expected one uni test instead of two and stopped before GPU qualification.
The revised controller and run are separate artifacts. Research executable,
static library, native C service and CPU compatibility checks pass under
the established serial, offline, zero-swap limits.

The goal remains incomplete. Evaluation and ordered-constraint vectors,
other symbolic/folding scratch, decoded caller proofs, cache overlaps and
allocator/driver overhead still need complete enclosing lifetime bounds.
Scheduler phases, broader workloads, sustained pool throughput, multiple
GPUs and AMD/Metal qualification remain open. This checkpoint changes no
activation, proof format, parameters or registry identity.

## 9.77 Evaluation lifetimes (2026-10-10)

The registered uni/batch compilers now borrow input and public values
during expression lowering. Repeated zero rows and lookup challenge
patterns use checked views of fixed arrays, and terminal values stay in
a fixed array. They no longer allocate those repeated/copied vectors.
Views preserve the original index order and reject out-of-range access;
pattern lengths use checked multiplication.

Periodic and recomposed permutation results occupy one scoped array.
The batch compiler's ordered constraint table occupies a nested scoped
array. Both reserve their exact backing capacity against the same
construction allowance as operations and expression memo tables before
allocation. Callbacks borrow fixed slices. Scope exit frees the backing
storage before releasing its reservation, including ordinary errors and
unwind, while retaining the construction peak. A latched quota failure
blocks further callbacks, including zero-length requests.

Quotient vanishing values now use fixed scratch for the supported maximum
of **32 chunks**. Constraint emission checks counts, duplicate indexes,
out-of-range indexes and missing slots before accepting the compiled
result. The allocating `periodic_values` CPU compatibility helper still
returns caller-owned results; registered compilers use the slice helper.
Public periodic-column sources and constant-helper buffers keep separate
enclosing lifetimes.

Four new scratch tests per lane configuration cover simultaneous nested
reservations, exact quota boundaries, success/error/unwind release and
reuse, overflow, latched rejection, and coexistence with operation/memo
storage. Two additional cases per configuration cover repeated/borrowed
indexing and invalid periodic/quotient geometry. The frozen lowerer retains
its independent owned-vector representation, and canonical program/input
comparisons plus real uni/wallet/batch proof tampering checks pass.

All **94 relevant native cases** pass: **53** in the research build and
**41** standard-lane compatibility cases. Both full-size compilations
release **13,664 bytes** of ordered constraints and **816 bytes** of
evaluation storage after the expression memo releases and before packing.
The audit verifies the release order and live-counter transitions in
both windows. Pre-packing peak remains **499,427,392 bytes**; the final
construction requirement remains **508,066,252 bytes**, within the
unchanged **571,816,240-byte** assignment.

Both full-size finalizers preserve the original registry, complete all
**16 arithmetic stages on OpenCL**, pass independent CPU verification and
altered-statement rejection, and verify after worker exit. Cold/warm jobs
take **73.0221 / 17.4033 seconds**. They finalize the same terminal statement
through distinct verified dependencies and do not measure sustained
transactions per hour. Worker host peak is **1,103,405,056 bytes** over
**184 samples**, with zero swap/OOM. Managed GPU peaks remain
**7,467,246,016 / 7,467,247,040 bytes**; idle storage is **2,022,919,936 bytes**
and shutdown storage is zero. The **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation** caps remain unchanged. Cleanup
confirms no workers or GPU leases and **33 empty parent slices**.

[`gpu-evaluation-lifetimes-2026-10-10.json`](evidence/gpu-evaluation-lifetimes-2026-10-10.json)
pins **384 source files** and **123 root artifacts**. The audit verifies
**99 run artifacts** and **135 parent artifacts**. Its successful run is
`lattica-prover-p3/benchmark-results/gpu-evaluation-lifetimes-20261010/run-01`.
Research executable, static library, native C service and CPU checks pass
under the established serial, offline, zero-swap limits.

The goal remains incomplete. Public constant/periodic source buffers,
remaining symbolic graph/normalization storage, decoded caller proofs,
cache overlaps and allocator/driver overhead still need complete enclosing
lifetime bounds. Scheduler phases, broader workloads, sustained pool
throughput, multiple GPUs and AMD/Metal qualification remain open. This
checkpoint changes no activation, proof format, parameters or registry
identity and does not qualify ordinary pool admission without a lifetime
profile.

## 9.78 Symbolic recording (2026-10-10)

The symbolic AIR recorder now admits its own requested storage before
allocation. A **64 MiB cumulative quota**, within the existing **192 MiB**
symbolic allowance, covers expression child Arcs, layout arrays and their
shared headers, constraint roots and indexes, recorded interactions and
bus-name strings. Discarded intermediates and both old and new growth
arrays retain their admission; freeing an intermediate does not replenish
the quota. Initial arrays and local-interaction output arrays use exact,
fallible allocation. Growing vectors have explicit bounded capacities.
Main, preprocessed and permutation row windows share their backing arrays,
so requesting another main or permutation window does not copy its rows.

Raw expression wrappers carry depth metadata without changing the recorded
tree or its sharing. Base constants have depth zero; the pinned extension
representation wraps base constants and therefore starts at depth one.
Depth **512** is enforced before allocating child Arcs. Excess depth or
storage latches a recording failure and subsequent operators return an
allocation-free placeholder. The recording scope rejects that result before
normalization or backend arithmetic can use it. Builder initialization is
fallible, and partial vector growth also leaves a persistent builder failure.
Thread-local scope state is restored on success, error and unwind; nested
recording is rejected. Existing post-recording graph admission remains in
place for raw trees constructed outside a scope.

Ten new tests per lane configuration cover exact and undersized quotas,
skipped initialization callbacks, cumulative discarded/growth storage,
depth boundaries including lifted base leaves, shared row windows,
malformed layouts and bus names, local-output capacity, scope restoration,
thread isolation, nesting and partial root growth. The existing geometry
tests now also discard an over-deep intermediate before attempting a later
constraint, exercising single-AIR, batch and lookup entrypoints. GPU checks
confirm rejection without allocation, upload or arithmetic observations.
Pinned CPU/GPU DAG fingerprints, degrees and lookup packing remain equal.

All **122 relevant native cases** pass: **68** in the research build and
**54** standard-lane CPU compatibility cases. The full-size worker reports
**17 recording scopes**. Their maximum cumulative admission is **946,879
bytes**, with maximum raw depth **189**; these observations do not reduce
the quota. Both full-size finalizers retain the original registry, complete
all **16 arithmetic stages on OpenCL**, pass independent CPU verification
and altered-statement rejection, and verify after worker exit. The program
construction requirement remains **508,066,252 bytes** within the unchanged
**571,816,240-byte** assignment.

Cold/warm jobs take **72.8812 / 17.3984 seconds**. They finalize the same
terminal statement through distinct verified dependencies and do not
establish sustained transactions per hour. Worker host peak is
**1,099,341,824 bytes** over **184 samples**, with zero swap/OOM. Managed
GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**; idle storage is
**2,022,919,936 bytes** and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup confirms no workers or GPU leases and **35 empty parent
slices**.

[`gpu-symbolic-recording-2026-10-10.json`](evidence/gpu-symbolic-recording-2026-10-10.json)
pins **386 source files** and **132 root artifacts**. The audit verifies
**103 run artifacts** and **123 parent artifacts**. The successful native
run is `lattica-prover-p3/benchmark-results/gpu-symbolic-recording-20261010/run-01`.
Research executable, static library, native C service and CPU checks pass
under the established serial, offline, zero-swap limits. The first two audit
controller versions retained stale parent-run paths; their failure records
are preserved. The corrected third audit verifies the unchanged native
artifacts.

The goal remains incomplete. This quota bounds recorder-owned cumulative
requested storage, not physical RSS or arbitrary allocations inside AIR
callbacks. Normalization maps/output, lookup replay and packing, incoming
local-interaction arrays, public constant/periodic sources, decoded caller
proofs, cache overlaps and allocator/driver overhead still need complete
enclosing lifetime bounds. Scheduler phases, broader workloads, sustained
pool throughput, multiple GPUs and AMD/Metal qualification remain open.
Proof format, parameters, registry identity and activation are unchanged;
ordinary pool admission still rejects the qualification profile without
complete lifetime phases.

## 9.79 Symbolic normalization (2026-10-10)

Normalization now admits its traversal stack, visited-depth maps, expression
memo tables, child Arcs, constraint/index arrays and lookup output/name
storage before allocation against a shared **64 MiB cumulative quota**.
This sits within the unchanged **192 MiB** symbolic allowance. Retired
growth arrays and discarded nodes keep their admission; the counter bounds
requested storage across the pass, including its returned output. It does
not measure physical RSS or reserve the caller's subsequent output lifetime.

Explicit pointer-identity maps replace ordinary hash-map growth. Their
backing arrays have exact capacities, load stays at most one half, and
growth moves existing entries without cloning their values. Input pointer
identity still determines output sharing; structurally equal nodes with
different identities remain distinct. Separate base/extension visited maps
preserve the longer-path recheck used by graph-depth admission. Every map
borrows its quota, and old/new arrays share that same cumulative allowance.

Constraint and lookup output arrays use exact capacities. The lookup pass
preserves its original order: each local tuple's fields precede its count,
and all local interactions precede global ones. Known allocations are
admitted before initializer/normalization callbacks. A quota failure stays
latched and prevents subsequent arithmetic callbacks; partial output arrays
drop initialized values on error or unwind. The fixed public-constant
folding cache retains its existing separate reservation of at most **8 KiB**
within the public-hash host allowance.

Eleven new cases per lane configuration cover exact/undersized quotas,
overflow, cumulative growth and discarded storage, map collisions and
replacement, ownership through rehashing, node limits, partial-array cleanup,
shared pointer identity and backend rejection. There are now **24 symbolic
cases per configuration**. GPU geometry checks also exercise zero-byte
normalization quotas and confirm rejection without backend arithmetic,
GPU allocation or upload. Pinned DAG fingerprints, degrees and lookup
packing remain equal to the CPU reference.

All **144 relevant native cases** pass: **79** in the research build and
**65** standard-lane CPU compatibility cases. The full-size worker reports
**17 normalization scopes**, with maximum cumulative admission of
**4,154,832 bytes**. Both full-size finalizers preserve the original registry,
complete all **16 arithmetic stages on OpenCL**, pass independent CPU
verification and altered-statement rejection, and verify after worker exit.
Their completed operation counts match §9.78 for every arithmetic stage.
The program construction requirement remains **508,066,252 bytes**, within
the unchanged **571,816,240-byte** assignment.

Cold/warm jobs take **73.6916 / 18.6554 seconds**. These jobs finalize the
same terminal statement through distinct verified dependencies and do not
establish sustained transactions per hour or a performance improvement.
Worker host peak is **1,106,968,576 bytes** over **188 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle storage is **2,022,919,936 bytes** and shutdown storage is zero. The
**3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation**
caps remain unchanged. Cleanup confirms no workers or GPU leases and
**36 empty parent slices**.

[`gpu-symbolic-normalization-2026-10-10.json`](evidence/gpu-symbolic-normalization-2026-10-10.json)
pins **389 source files** and **128 root artifacts**. The audit verifies
**103 run artifacts** and **132 parent artifacts**. The successful native
run is `lattica-prover-p3/benchmark-results/gpu-symbolic-normalization-20261010/run-01`.
The initial test build caught a constructor error in the test-only quota
helper; that failed build log is preserved. Corrected research executable,
static-library and CPU builds, native C service linking and the artifact
audit pass under the established serial, offline, zero-swap limits.

The goal remains incomplete. Lookup replay/packing, overlapping retained
outputs, AIR/caller allocations, public constant/periodic sources, decoded
proofs, cache overlaps and allocator/driver overhead still need complete
enclosing lifetime accounting. Scheduler phases, broader workloads,
sustained pool throughput, multiple GPUs and AMD/Metal qualification remain
open. This checkpoint changes no proof format, parameters, registry identity
or activation, and ordinary pool admission still rejects the qualification
profile without complete lifetime phases.

## 9.80 Bounded lookup packing (2026-10-10)

The GPU preparation path now packs normalized lookups without replaying
the AIR into a second upstream builder. A **64 MiB cumulative quota**
admits packing arrays, bus names, trial copies and storage-census scratch
before allocation. Growth accounts for old and new arrays, and rejected
merge trials retain their admission. Packing creates no new expression
Arcs. Checked integer metadata reproduces the pinned LogUp degree formula
without allocating a temporary degree vector or performing field arithmetic.

The packed result has a separate **64 MiB retained-storage bound**. The
census includes outer and nested vector capacities, bus-name capacities
and each reachable child Arc once, including a conservative header and
padding allowance. It therefore includes storage inherited from
normalization. Its temporary traversal and pointer-identity maps use the
packing quota. The existing **192 MiB** symbolic reservation is unchanged;
these local checks do not establish all enclosing caller lifetimes.

A pinned local copy of **`p3-lookup 0.6.1`** adds
`Lookups::try_from_ordered`, which checks contiguous columns, parallel
tuple/count arrays, local-before-global order, zero local weights and
nonempty global tuples, then takes the admitted vector by ownership.
It allocates and clones nothing. AIR constraints remain responsible for
establishing declared count weights. The audit checks the original crate
archive against the previous lockfile checksum, verifies **19 original
package files**, and confirms that only this constructor was added to
`src/types.rs`. Upstream packing and all other dependency algorithms remain
unchanged; the rest of the lockfile is identical.

Eight new cases per lane configuration check ownership and Arc identity,
malformed metadata, packing parity across degree budgets, allocation-free
degree parity, integer overflow, exact and one-byte-short quotas, retained
capacities/sharing and rejection of oversized inputs. The frozen replay
reference verifies local and bus order, greedy merge decisions, empty
payloads and saturating count weights. The GPU geometry test also exercises
a zero-byte packing quota and confirms rejection without backend arithmetic,
GPU allocation or upload.

All **160 relevant native cases** pass: **87** in the research build and
**73** in the standard-lane CPU configuration, including **32 symbolic
cases per configuration**. Across **five packing scopes**, each full-size
layout packs **115 interactions into 16 lookups** at degree budget **8**,
admits **200,477 bytes** cumulatively and retains **121,176 bytes**. Both
full-size finalizers preserve the original registry, complete all **16
arithmetic stages on OpenCL**, pass independent CPU verification and
altered-statement rejection, and verify after worker exit. Every arithmetic
stage's completed-call count matches §9.79. The program construction
requirement remains **508,066,252 bytes** within the unchanged
**571,816,240-byte** assignment.

Cold/warm jobs take **72.3207 / 18.2350 seconds**. They finalize the same
terminal statement through distinct verified dependencies; these timings
do not establish sustained transactions per hour or a performance gain.
Worker host peak is **1,107,279,872 bytes** over **184 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle storage is **2,022,919,936 bytes** and shutdown storage is zero. The
**3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation**
caps remain unchanged. Cleanup confirms no workers or held GPU leases and
**38 empty parent slices**.

[`gpu-lookup-packing-2026-10-10.json`](evidence/gpu-lookup-packing-2026-10-10.json)
pins **411 source files** and **131 root artifacts**. The audit verifies
**103 run artifacts** and **128 parent artifacts**. The successful run is
`lattica-prover-p3/benchmark-results/gpu-lookup-packing-20261010/run-01`.
Research executable, static-library and CPU builds, C service linking and
the artifact audit pass under the serial, offline, zero-swap limits on the
authorized desktop RTX 5080.

The goal remains incomplete. Overlapping retained outputs, AIR/caller
allocations, public constant/periodic sources, decoded proofs, cache
overlaps and allocator/driver overhead still need complete enclosing
lifetime accounting. Scheduler phases, broader workloads, sustained pool
throughput, multiple GPUs and AMD/Metal qualification remain open. This
checkpoint changes no proof format, parameters, registry identity or
activation. Ordinary pool admission still rejects the qualification
profile without complete lifetime phases.


## 9.81 Lookup ownership transfer (2026-10-10)

GPU setup now transfers the packed lookup containers from §9.80 into
cached `CommonData` by ownership. It no longer clones their nested vectors,
bus names or child Arc references while the original symbolic output is
still live. `Prepared::into_parts` separates lookup layout metadata from
its constraint graph without allocating or cloning. Small outer metadata
arrays retain their existing AIR-count checks; this change does not remove
all metadata allocation or establish a complete cache lifetime bound.

Registered setup keeps the original constraints through canonical program
fingerprinting, then drops that graph before finishing its preprocessing
receipt. The batch setup test helper drops each unused constraint graph
before preparing the next AIR and removes the temporary array of borrowed
`Prepared` references. Shared expression nodes remain alive for whichever
owner still needs them. CPU reference construction is unchanged.

Three new cases per lane configuration check original nested buffer
addresses and spare capacities, bus-string identity, unchanged Arc
ownership, independent constraint/lookup release, batch metadata parity
against the trusted-cap CPU reference, and cleanup on metadata rejection.
Empty and oversized batches, mismatched counts, excessive degree and an
incorrect cap size reject while releasing the owned lookup graph.

All **166 relevant native cases** pass: **90** research/GPU and **76**
standard-lane CPU cases. Both full-size finalizers preserve the original
registry, complete all **16 arithmetic stages on OpenCL**, pass independent
CPU verification and altered-statement rejection, and verify after worker
exit. Their completed operation counts match §9.80 for every arithmetic
stage. The **five lookup-packing scopes** retain the same layout and bounds:
**115 interactions / 16 packed lookups**, **200,477 cumulative admitted
bytes** and **121,176 retained bytes** per scope. Program construction still
requires **508,066,252 bytes** within its **571,816,240-byte** assignment.

Cold/warm jobs take **71.7207 / 17.4025 seconds**. Both jobs finalize the
same terminal statement through distinct verified dependencies; they do not
establish sustained transactions per hour or a performance improvement. Worker host
peak is **1,108,316,160 bytes** over **181 samples**, with zero swap/OOM.
Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**; idle storage
is **2,022,919,936 bytes** and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup confirms no workers or held GPU leases and **39 empty
parent slices**.

[`gpu-lookup-ownership-2026-10-10.json`](evidence/gpu-lookup-ownership-2026-10-10.json)
pins **412 source files** and **144 root artifacts**. The audit verifies
**105 successful-run artifacts**, **131 parent artifacts** and both source
archives. The successful run is
`lattica-prover-p3/benchmark-results/gpu-lookup-ownership-20261010/run-02`.
The first run caught a test fixture that attempted to construct an empty
Merkle cap, which the upstream type rejects before metadata validation.
The corrected fixture supplies a valid cap of the wrong size. The audit
confirms that only this test file differs between the failed and successful
source snapshots; the original run's logs, binaries and archive are
preserved. Corrected research executable, static-library and CPU builds,
C service linking and the artifact audit pass under the established serial,
offline limits on the desktop RTX 5080.

The goal remains incomplete. Enclosing caller and retained-output lifetimes,
decoded proof/public-source storage, cache overlaps and allocator/driver
overhead still need complete accounting. Complete scheduler phases, broader
workloads, sustained pool throughput, multiple GPUs and AMD/Metal
qualification remain open. Proof formats, parameters, registry identity,
activation and scheduler allowances are unchanged. Ordinary pool admission
continues to reject the qualification profile without complete lifetime
phases.

## 9.82 Compiler constant storage (2026-10-10)

Public compiler constants now fill borrowed output slices. Both explicit
backends validate output geometry before arithmetic. Registered compiler
consumers admit selector inverses, selector differences, periodic coefficients
and quotient constants through the existing shared construction budget
before allocating storage or invoking a backend. The scratch owner releases
its allocation before returning the reservation, including error and unwind
paths. Returned selector wires use fixed stack arrays bounded to 64 entries.

The device backend no longer returns a coefficient vector or copies a
readback vector into a second scalar vector. Quotient constants occupy one
flat admitted array, split into borrowed inverse-shift and normalization
slices; the CPU reference also eliminates its temporary shift vector.
Inverse-generator output is one stack field. GPU periodic output is bounded
to **524,288 bytes** and quotient output to **8,448 bytes**. Fixed device
readback staging is **16,384 bytes** for periodic coefficients and **8,448
bytes** for other constants. Compile-time checks include the retained
**8 KiB folding cache** and small scalar input/output storage within the
existing **64 KiB public-hash host allowance**. Kernel source is unchanged.

All **178 relevant native cases** pass: **98** research/GPU and **80**
standard-lane CPU cases. Independent field and DFT identities cover all
subgroup heights, selector boundaries, periods through 65,536 and quotient
tables through 32 chunks. Existing CPU/GPU program comparisons and periodic
verifier tamper checks pass with the borrowed APIs. Short and long output
slices preserve sentinels at both the outer and device boundaries without
GPU allocation, upload or download. Four quota-rejection scenarios per
backend reject before any arithmetic, including exhaustion of the combined
selector inverse/difference allowance. The ordinary CPU and ignored GPU
cases exercise the actual compiler consumers.

Both full-size finalizers preserve the archived registry, complete all
**16 arithmetic stages on OpenCL**, pass independent CPU verification and
altered-statement rejection, and verify after worker exit. Every stage's
completed-call count matches §9.81. Each compilation reports five new
scratch releases: **88 / 88 bytes** for the mode selectors, **2,176 bytes**
for quotient constants and **48 / 48 bytes** for level selectors. The
prepacking peak remains **499,427,392 bytes**; final construction still
requires **508,066,252 bytes** within its **571,816,240-byte** assignment.

Cold/warm jobs take **72.1344 / 17.4311 seconds**. Both finalize the same
terminal statement through distinct verified dependencies; these timings
do not establish sustained transactions per hour or a performance gain.
Worker host peak is **1,110,142,976 bytes** over **182 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle storage is **2,022,919,936 bytes**, and shutdown storage is zero.
The **3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU / 1 GiB
allocation** caps are unchanged. Cleanup confirms no workers or held GPU
leases and **41 empty parent slices**.

[`gpu-compiler-constant-storage-2026-10-10.json`](evidence/gpu-compiler-constant-storage-2026-10-10.json)
pins **412 source files** and **146 root artifacts**. Its audit verifies
**111 successful-run artifacts**, **144 parent artifacts**, the original
dependency package and both source archives. The first build caught a
missing Rust trait import; its source and log are preserved, and the audit
confirms that the correction changes only that import. The successful run
is `lattica-prover-p3/benchmark-results/gpu-compiler-constant-storage-20261010/run-01`.
Research executable, static-library and CPU builds, C service linking,
formatting and artifact checks pass under the established serial, offline
limits on the desktop RTX 5080.

The goal remains incomplete. Decoded proof storage, caller-owned periodic
sources, enclosing symbolic lifetimes, cached-program overlaps and
allocator/driver overhead still need complete accounting. Ordinary pool
admission continues to reject this qualification profile without complete
lifetime phases. Broader transaction workloads, sustained pool throughput,
multiple GPUs and AMD/Metal qualification remain open. Proof formats,
parameters, registry identity, activation and scheduler allowances are
unchanged.

## 9.83 Decoded input storage (2026-10-10)

Typed worker requests now own one cumulative **64 MiB** decoded-storage
quota, capped by assigned worker RAM. The decoder admits each vector's
requested backing storage before fallible exact allocation and before
visiting its elements. Canonical re-encoding uses the same quota. Charges
remain cumulative across all request inputs, and decoder errors or unwind
latch failure. Existing per-proof item, depth, sequence, scalar-canonicality
and wire-format guards remain in force.

Explicit deserialization seeds construct the pinned native wallet and
recursive proof containers directly. Extension-field coefficients use
stack arrays, eliminating the upstream temporary vector for each scalar.
Malformed Merkle-cap lengths reject before reaching the upstream
constructor. Typed wallet admission returns the exact proof that was
verified, removing the second decode during worker preparation. Recursive
children also decode directly without a temporary outer vector. The
prepared-input owner holds the quota until the compiler/prover consumer
returns; proof values drop before their allowance on success, error or
unwind.

All **234 relevant native cases** pass: **126** research/GPU and **108**
standard-lane CPU cases. Six new cases in each configuration cover both
canonical encodings, exact and undersized quotas, combined-input charges,
admission before element callbacks, partial-value cleanup and unwind,
malformed fields/caps/envelopes, stack extension coefficients and real
wallet verification. The CPU-only cached-worker tests pass in the CPU
compatibility suite.

Both full-size finalizers preserve the archived registry, complete all
**16 arithmetic stages on OpenCL**, pass independent CPU verification and
altered-statement rejection, and verify after worker exit. Every stage's
completed-call count matches §9.82. Each finalizer releases one decoded
input scope with **2,094,232 vector bytes**, **1,683,940 canonical-buffer
bytes**, and **3,778,172 cumulative admitted bytes** across **16,739
allocations**, with no rejection. This bounds requested decoded storage;
raw packets, verifier scratch, allocator overhead and complete worker RSS
remain separate enclosing lifetimes.

Cold/warm jobs take **71.3881 / 17.5612 seconds**. Both finalize the same
terminal statement through distinct verified dependencies; these timings
do not establish sustained transactions per hour or a performance gain.
Worker host peak is **1,101,393,920 bytes** over **181 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle storage is **2,022,919,936 bytes**, and shutdown storage is zero.
Construction still requires **508,066,252 bytes** within its
**571,816,240-byte** assignment. The **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation** caps remain enforced. Cleanup finds
no workers or held GPU leases and **44 empty parent slices**.

[`gpu-decoded-input-storage-2026-10-10.json`](evidence/gpu-decoded-input-storage-2026-10-10.json)
pins **415 source files** and **185 root artifacts**. Its audit verifies
**117 successful-run artifacts**, **146 parent artifacts**, the original
dependency package and **six source archives**. The preserved earlier
attempts include a corrected upstream type path, a cleanup-test fixture
that initially rejected before element visitation, and a GPU controller
that selected a CPU-only worker test. A CPU selector-count correction
retains and reuses the already successful test logs; its fourth expected
native-worker case is GPU-only. No production guard was relaxed. The
successful run is
`lattica-prover-p3/benchmark-results/gpu-decoded-input-storage-20261010/run-03`.
Research executable, static-library and CPU builds, C service linking,
formatting and artifact checks pass under the established serial, offline
limits on the desktop RTX 5080.

The goal remains incomplete. Raw packets and verifier scratch,
caller-owned periodic sources, enclosing symbolic lifetimes,
cached-program overlaps and allocator/driver overhead still need complete
accounting. Ordinary pool admission continues to reject this qualification
profile without complete lifetime phases. Broader transaction workloads,
sustained pool throughput, multiple GPUs and AMD/Metal qualification remain
open. Proof formats, parameters, registry identity, activation and
scheduler allowances are unchanged.

## 9.84 Periodic source storage (2026-10-10)

Registered uni and batch compilers now use explicit periodic source
geometry and borrowed fill callbacks. JoinSplit, issuance and HTLC sources
generate one column at a time, without constructing a complete table or
temporary row-index vectors. Every source allocation is admitted by the
shared construction budget before its fill callback. Coefficient scratch
coexists under that same allowance, and source storage is freed before
the reservation becomes reusable. Output evaluation wires also retain
their existing scoped reservation.

All source columns match the unchanged AIR tables: **33** columns each
for JoinSplit and issuance, and **43** for HTLC. Their original field
payloads total **723,712 / 1,051,392 bytes**; the largest generated source
column is **32,768 bytes** for either family. At most one source and its
coefficient array coexist: **65,536 bytes** at the largest supported leaf
period, in addition to evaluated outputs and other builder storage. The
existing AIR table builders and constraint bodies are unchanged; only
feature-gated module declarations were added to those files. The generic
CPU compatibility entrypoint retains an adapter for caller-owned tables,
whose original storage remains outside the compiler allowance.

All **244 relevant native cases** pass: **131** research/GPU and **113**
standard-lane CPU cases. Four periodic-source cases per configuration
cover every field in the original tables, malformed indices and short/long
buffers with preserved sentinels, geometry rejection before callbacks,
CPU program/value parity, and real uni-proof acceptance and rejection.
The registered CPU compiler does not invoke the AIR's owned table builder.
An additional ownership case per configuration covers error and unwind
before quota reuse. Two new scenarios in each existing CPU/GPU rejection
case test insufficient source storage and insufficient combined
source/coefficient storage. Both reject before backend arithmetic; GPU
allocation/upload/download counters remain unchanged. The latter scenario
releases its **32-byte** source within a **63-byte** combined cap.

The GPU periodic uni-verifier conformance case preserves the CPU program
and witness and rejects altered input. Separately, both full-size
finalizers preserve the archived registry, complete all **16 arithmetic
stages on OpenCL**, pass independent CPU verification and altered-statement
rejection, and verify after worker exit. Every stage's completed-call
count matches §9.83. These finalizers have no periodic columns; their
results establish recursive-path regression coverage, while the dedicated
uni-verifier case exercises GPU periodic consumption.

Cold/warm finalizers take **71.8015 / 17.4314 seconds**. Both prove the same
terminal statement through distinct verified dependencies; these timings
do not establish sustained transactions per hour or a performance gain.
Worker host peak is **1,099,153,408 bytes** over **181 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle storage is **2,022,919,936 bytes**, and shutdown storage is zero.
Final construction still requires **508,066,252 bytes** within its
**571,816,240-byte** assignment. The **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation** caps remain enforced. Cleanup finds
no workers or held GPU leases and **47 empty parent slices**.

[`gpu-periodic-source-storage-2026-10-10.json`](evidence/gpu-periodic-source-storage-2026-10-10.json)
pins **420 source files** and **166 root artifacts**. Its audit verifies
**119 successful-run artifacts**, **185 parent artifacts**, the original
dependency package and **three source archives**. The first compile check
caught a test counter that needed to satisfy the AIR's `Sync` bound; the
correction changed only test instrumentation/imports. Earlier audit and
recorder attempts are also preserved: their corrections fix a parent
archive path and correction-metadata assembly. Production sources and
the successful qualification are identical across those attempts. The
successful run is
`lattica-prover-p3/benchmark-results/gpu-periodic-source-storage-20261010/run-01`.
Research executable, static-library and CPU builds, C service linking,
formatting and artifact checks pass under the established serial, offline
limits on the desktop RTX 5080.

The goal remains incomplete. Raw packets and verifier scratch, enclosing
symbolic/AIR callback lifetimes, cached-program overlaps and
allocator/driver overhead still need complete accounting. Ordinary pool
admission continues to reject this qualification profile without complete
lifetime phases. Broader transaction workloads, sustained pool throughput,
multiple GPUs and AMD/Metal qualification remain open. Proof formats,
parameters, registry identity, activation and scheduler allowances are
unchanged.

## 9.85 Request storage (2026-10-10)

Decoded legacy and typed requests now borrow their proof slices from the
original packet. Rust lifetimes keep that packet alive through proof
consumption. Request encoding computes the complete size before a single
fallible allocation; metadata vectors admit at most two elements each.
Dependency identity uses a two-entry stack array. Incoming typed process
frames also use fallible, exact-capacity vectors after their command and
length checks. The wire formats, ordering and validation are preserved.

Launch and artifact hashing stream the same length/domain-framed,
zero-padded little-endian words. Working storage no longer grows with
payload size. The unchanged slice hash remains the independent reference;
fixed permutation setup can still allocate round constants. This is not
a claim that every hash performs zero heap allocations.

All **357 qualification cases** pass: **186** research/GPU and **171** CPU.
Coverage includes maximum-size proofs and frames, exact metadata and packet
capacities, borrowed pointers into the original packet, digest parity at
protocol bounds, malformed packets, launch fencing and worker lifecycle
behavior. Over-bound frames reject before reading their bodies; truncated
frames still fail. Typed and legacy packet round trips retain their format.
The first run selected two CPU-only lifecycle cases in the GPU build and
failed at their explicit CPU-backend guard. That run is preserved. The
corrected GPU selection runs six compatible process cases; the CPU suite
runs all nine, including both cases. Sources and binaries are identical
between attempts.

Both full-size finalizers borrow **1,683,948 proof bytes** from a
**1,684,256-byte request packet**, with **200 bytes** of metadata vector
capacity under a **400-byte** per-request metadata limit on this host.
Neither decoder copies its proof payload. The request cap remains
**4,259,840 bytes**; the typed process frame cap is **4,260,532 bytes**.
These bounds describe protocol-owned vector capacity, not complete worker
RSS or an enclosing scheduler lifetime reservation.

Both finalizers preserve the archived registry and every stage's operation
count, complete all **16 arithmetic stages on OpenCL**, pass independent
CPU verification and altered-statement rejection, and verify after worker
exit. Cold/warm jobs take **68.0315 / 18.7212 seconds**. They prove the same
terminal statement through distinct verified dependencies; these timings
do not establish sustained transactions per hour or a performance gain.
Worker host peak is **1,099,542,528 bytes** over **176 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**,
idle storage is **2,022,919,936 bytes**, and shutdown storage is zero.
Construction still requires **508,066,252 bytes** within the existing
**571,816,240-byte** assignment. The **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation** caps remain enforced. Cleanup finds
no running Lattica services or held GPU leases and **49 empty parent slices**.

[`gpu-request-storage-2026-10-10.json`](evidence/gpu-request-storage-2026-10-10.json)
pins **421 source files** and **194 root artifacts**. The audit checks all
three source archives, the preserved selection failure, parent artifacts,
dependency ancestry and the successful run at
`lattica-prover-p3/benchmark-results/gpu-request-storage-20261010/run-02`.
Research executable, static-library and CPU builds, C service linking,
formatting and artifact verification pass under the established serial,
offline limits on the desktop RTX 5080.

The goal remains incomplete. Result serialization and coordinator copies,
verifier scratch, symbolic/AIR callback lifetimes, cached-program overlaps,
and allocator/driver overhead still need complete accounting and enclosing
scheduler phases. Ordinary pool admission continues to reject the
qualification profile without those phases. Broader transaction workloads,
sustained pool throughput, multiple GPUs and AMD/Metal qualification remain
open. Proof formats, parameters, registry identity and activation are
unchanged.

## 9.86 Result storage (2026-10-10)

Typed workers now serialize node proofs directly into a single, fallibly
allocated result-packet buffer. Its capacity is the **2 MiB** proof limit
plus the **181-byte** result header: **2,097,333 bytes**. Serialization
cannot exceed the proof limit, even when given a larger containing slice.
The native node values are released after serialization, before packet
completion. The result header and artifact identity are filled only after
serialization succeeds; unfinished packets cannot be published.

The coordinator consumes the received packet and compacts its proof bytes
in place. It retains the original frame capacity for the returned proof,
including unused space; memory accounting must use capacity rather than
serialized length. Compatibility APIs accepting borrowed serialized data
still make bounded, fallible copies. Compaction itself moves bytes, so this
is not a universal zero-copy claim.

Exact assignment/request binding now compares every canonical field,
dependency and original proof byte without constructing a second request
encoding. Typed dispatch sends its length prefix, token and retained request
as separate slices under the same frame header. It checks the combined size
before any write and preserves pending-work and poisoned-worker behavior on
transport failure. Packet formats and launch/assignment identities remain
unchanged.

All **365 qualification cases** pass: **190** research/GPU and **175** CPU.
New cases compare both result families against the previous wire layout,
check buffer pointers and capacities, reject oversized storage and truncated
results, and mutate every request byte and every result control byte outside
untrusted telemetry. Borrowed serialization matches the original envelope
and payload, respects exact and insufficient buffers, and preserves
sentinels beyond the proof cap. Multipart frames match their original bytes
through the maximum frame size and reject excessive size before writing a
header. Existing launch, process, cache and proof tests also pass.

Both full-size finalizers serialize **1,683,948 proof bytes** into
**1,684,129-byte result packets**, using the **2,097,333-byte** worker buffer.
The coordinator receives an exact **1,684,129-byte** buffer and reuses it for
the proof, with no second result-buffer allocation. Request decoding retains
the borrowed storage qualified in §9.85. Both proofs preserve the archived
registry and every stage's operation count, complete all **16 arithmetic
stages on OpenCL**, pass independent CPU verification and altered-statement
rejection, and verify after worker exit.

Cold/warm jobs take **68.1174 / 17.7549 seconds**, without establishing
sustained transactions per hour or a performance gain. Worker host peak is
**1,098,244,096 bytes** over **175 samples**, with zero swap/OOM. Managed GPU
peaks remain **7,467,246,016 / 7,467,247,040 bytes**; idle storage is
**2,022,919,936 bytes**, and shutdown storage is zero. Construction still
requires **508,066,252 bytes** within **571,816,240 bytes**. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
enforced. Cleanup finds no running Lattica services or held GPU leases and
**51 empty parent slices**.

[`gpu-result-storage-2026-10-10.json`](evidence/gpu-result-storage-2026-10-10.json)
pins **421 source files** and **173 root artifacts**, including both source
archives and the successful first compile and qualification attempts. The
successful run is
`lattica-prover-p3/benchmark-results/gpu-result-storage-20261010/run-01`.
The audit verifies the parent evidence, original dependency ancestry,
formatting, wire/capacity checks and native resource reports. Research
executable, static-library and CPU builds and C service linking pass under
the established serial, offline limits on the desktop RTX 5080.

The goal remains incomplete. Protocol bounds still need enclosing scheduler
phases. Native proof containers, CPU verifier scratch and metadata,
symbolic/AIR callback lifetimes, cached-program overlaps and allocator/driver
overhead remain to be accounted for. In particular, trusted-cap verification
still builds lookup metadata through `common_from_cap`; the bounded compiler
metadata path does not yet cover it. Ordinary pool admission continues to
reject the qualification profile without complete phases. Broader workload,
sustained pool throughput, multi-GPU and AMD/Metal qualification remain open.
Proof parameters, registry identity and activation are unchanged.


## 9.87 Verifier metadata (2026-10-10)

Trusted-cap CPU verification now uses bounded symbolic recording,
normalization and lookup packing. Previously, `RegisteredVerifier` called
`common_from_cap`, which constructed this metadata through the upstream
symbolic implementation without explicit storage quotas. That implementation
remains unchanged as a test reference; CPU reference proving is unchanged.
The new verification path explicitly selects CPU constants, preserving
independent CPU verification of GPU-generated proofs.

Recording, normalization and packing each have a **64 MiB** cumulative
requested-storage ceiling. Returned lookup metadata has a separate **64 MiB**
retained-storage ceiling that counts backing capacities and reachable child
Arcs. Unpacked lookups coexist with the recorded and normalized degree-analysis
graph; that graph is released before packing. The resulting default graph
workspace ceiling is **192 MiB**. This does not include arbitrary AIR callback
allocations, descriptor/cap storage, verifier arithmetic scratch or allocator
overhead, and is not a complete verifier RSS reservation.

Prepared lookup arrays, bus names and expression Arcs transfer into common
metadata by ownership. Descriptor vectors allocate exact capacities fallibly,
with at most **256 instances**; degree scratch uses a fixed stack array.
Invalid cap geometry rejects before graph preparation. Invalid limits reject
before layout/evaluation callbacks, and quota failure or callback unwind
releases the recording scope for subsequent preparation.

All **388 qualification cases** pass: **201** research/GPU and **187** CPU.
The new preparation tests compare lookup order, degree and canonical topology
with the upstream implementation for four public-input sizes and three trace
heights. They cover each quota independently, invalid ceilings, callback
unwind recovery, incorrect degree hints and excessive quotient degree.
Backend tests cover cap/shape rejection, metadata parity, native proof
acceptance and altered-public/opening rejection. Ownership tests verify exact
descriptor capacities through the 256-instance limit and cleanup on rejection.

The first qualification attempt stopped at a test-fixture error: an empty
Merkle cap triggered the upstream constructor's power-of-two assertion before
reaching the verifier. Only that fixture changed, to a constructible one-root
cap with the wrong registered size. The first attempt and both successful
compile checks remain archived. **Run-02** passes the complete qualification.

Both full-size finalizers preserve the archived registry and every arithmetic
stage's operation count, complete all **16 proving arithmetic stages on
OpenCL**, pass independent CPU verification and altered-statement rejection,
and verify after worker exit. The new verifier metadata appears in **7**
coordinator and **6** worker records. Each packs **115 interactions into 16
lookups**, with log quotient chunks **3** and **121,176 retained bytes**.
Existing GPU symbolic recording, normalization and packing reports are unchanged.

Cold/warm jobs take **70.3001 / 16.6938 seconds**; these isolated jobs do not
establish transactions per hour or a performance gain. Worker host peak is
**1,098,969,088 bytes** over **177 samples**, with zero swap/OOM. Managed GPU
peaks are **7,467,246,016 / 7,467,247,040 bytes**; idle storage remains
**2,022,919,936 bytes**, and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
enforced. Cleanup finds no running Lattica services or held GPU leases and
**53 empty parent slices**.

[`gpu-verifier-metadata-2026-10-10.json`](evidence/gpu-verifier-metadata-2026-10-10.json)
pins **424 source files** and **215 root artifacts**, including four source
archives spanning both compile checks and qualification attempts. Successful
artifacts are in
`lattica-prover-p3/benchmark-results/gpu-verifier-metadata-20261010/run-02`.
The audit verifies source and artifact hashes, parent/dependency ancestry,
formatting, native resource reports, metadata quotas and registry compatibility.
Research executable, static-library, C-link and CPU compatibility checks pass
under serial offline limits on the desktop RTX 5080.

The goal remains incomplete. Graph and protocol bounds still need enclosing
scheduler phases. Native proof containers, CPU verification scratch,
AIR callback/cache overlaps and allocator/driver overhead remain to be
accounted for. Ordinary pool admission continues to reject the qualification
profile without complete phases. Broader workloads, sustained pool throughput,
multi-GPU and AMD/Metal qualification remain open. Proof parameters, registry
identity and activation are unchanged.


## 9.88 FRI proof storage (2026-10-10)

Owned FRI now checks a combined host allowance for initial PCS queries,
FRI query batches and final proof assembly. Previously, it summed the
initial-query allowances but did not add the FRI outputs and assembly arrays
that coexist with them. The new check runs before FRI folding, commitments,
randomness draws or transcript changes. Earlier preprocessing and opening
work still require enclosing whole-job admission.

The plan preserves the existing initial-query allowance and adds every
layer's raw/converted rows, salts, paths and descriptors, commitment caps,
final coefficients, local indices and assembly vectors. It conservatively
sums all layer staging even though layers are queried sequentially. A fixed
stack schedule follows the pinned arity calculation for both quadratic and
cubic extensions, including mixed input heights and nonconstant final
polynomials. The executor consumes that schedule and checks its geometry.

Assembly vectors allocate exact capacities fallibly. Field conversion uses
fixed coefficient indexing without temporary coefficient vectors. Each FRI
row removes the queried element in place and retains its full arity-sized
backing array for sibling values; the plan charges capacity, not serialized
length. The final coefficient readback is released after conversion.

For each full-size finalizer, the admitted query/assembly region is:

| Component | Requested bytes |
| --- | ---: |
| Existing initial PCS query allowance | 7,069,696 |
| FRI query batches across 19 layers | 1,276,928 |
| Caps, coefficients and assembly arrays | 395,536 |
| Combined plan | **8,742,160** |

The proof-query ceiling remains **1 GiB**. These are requested-storage
bounds, not complete physical RSS. Engine/driver staging, transcript-owned
buffers, caller-owned inputs, allocator overhead and cache overlaps retain
separate lifetimes. No worker or scheduler allowance is reduced from these
numbers or observed peaks.

All **397 qualification cases** pass: **210** research/GPU and **187** CPU.
Seven new storage cases cover combined-budget boundaries, invalid geometry,
maximum schedules, exact capacities and a census of actual nested query
buffers for both extension fields. Two GPU conformance cases exercise **12
scenarios** across maximum log arities **1/2/3/4** and final polynomial log
lengths **0/3/8**. Insufficient storage leaves device work and randomness /
transcript streams unchanged; subsequent proofs match upstream bytes and
verify on CPU after GPU shutdown. That conformance harness uses CPU-fixture
initial openings; full-size native proofs exercise GPU initial PCS queries.

Both full-size finalizers preserve the archived registry and every stage's
operation count, complete all **16 proving arithmetic stages on OpenCL**,
pass independent CPU verification and altered-statement rejection, and
verify after worker exit. Cold/warm jobs take **68.0657 / 16.6945 seconds**,
without establishing transactions per hour or a performance gain. Worker
host peak is **1,097,879,552 bytes** over **172 samples**, with zero swap/OOM.
Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**, idle storage
is **2,022,919,936 bytes**, and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup finds no running Lattica services or held GPU leases and
**55 empty parent slices**.

[`gpu-fri-proof-storage-2026-10-10.json`](evidence/gpu-fri-proof-storage-2026-10-10.json)
pins **426 source files** and **176 root artifacts**, including both source
archives and successful first compile/build/qualification attempts. The run
is `lattica-prover-p3/benchmark-results/gpu-fri-proof-storage-20261010/run-01`.
The audit verifies parent/dependency ancestry, formatting, resource reports,
FRI storage components and unchanged registry/operation identities. Research
executable, static-library, C-link and CPU compatibility checks pass under
serial offline limits on the desktop RTX 5080.

The goal remains incomplete. Native proof-container handoffs, CPU verifier
scratch, callback/cache overlaps and allocator/driver overhead still need
complete host lifetime accounting. Component bounds must enter enclosing
scheduler phases; ordinary pool admission still rejects this qualification
profile without them. Broader workloads, nonempty-child full-size merges,
larger blocks, sustained pool throughput, multi-GPU and AMD/Metal qualification
remain open. Proof parameters, registry identity and activation are unchanged.


## 9.89 Native opening handoff (2026-10-10)

Batch and single-AIR GPU provers now move opened-value vectors into the
established native proof containers. Previously, assembly borrowed the PCS
outputs and cloned each random, main, quotient, preprocessing and permutation
row. The new shared assembler transfers each field allocation once, preserving
its pointer, length and capacity. The batch prover also moves the final
permutation commitment and releases its prover data after opening.

The handoff measures actual incoming capacities at every nested vector level,
including spare slots. Before allocating descriptors, it admits their combined
storage: instance layout metadata, preprocessing validation scratch, native
instance descriptors and quotient-row descriptors. New vectors allocate exact
capacities fallibly. Quotient ranges must partition their round; preprocessing
matrices must map one-to-one to participating instances, including reordered
and sparse mappings. Point counts and paired row widths are checked before
native assembly. No field `Clone` bound is required.

For each full-size finalizer, this component accounts for:

| Component | Requested bytes |
| --- | ---: |
| Incoming opened-value capacities | 13,752 |
| New metadata and native descriptors | 617 |
| Combined handoff plan | **14,369** |

This uses the existing `LATTICA_V2_HOST_OUTPUT_BYTES` allowance: **3 GiB** in
qualification, with the inherited **32 GiB** default maximum unchanged.
Admission occurs after PCS opening has produced its outputs; it does not
preflight or roll back earlier proving work. The FRI opening proof, commitment
caps, lookup terminals, caller-owned metadata, allocator overhead and
engine/driver storage still need enclosing lifetime reservations. Retained
field buffers keep their original spare capacity. The separate FRI proof-query
allowance remains **1 GiB**; no allowance is reduced from observed peaks.

All **409 qualification cases** pass: **222** research/GPU and **187** CPU.
Eight new unit cases cover non-Clone ownership and drop counts, original
pointers and capacities, all optional-round combinations, frozen native
encoding, reference parity, exact combined allowance, malformed geometry,
overflow and 256 instances. Four GPU cases produce **18 wallet/multi-AIR
proofs**: two cubic wallets, eight quadratic legacy wallets and eight
three-AIR batches. The batches match seeded CPU proof bytes in both instance
orders, with and without GPU randomness/transcripts. All verify independently
after GPU shutdown; wallet checks include altered statements and proof data.

Both full-size finalizers preserve the archived registry and every stage's
operation count, complete all **16 proving arithmetic stages on OpenCL**,
pass independent CPU verification and altered-statement rejection, and verify
after worker exit. Cold/warm jobs take **68.7546 / 16.6694 seconds**, without
establishing transactions per hour or a performance gain. Worker host peak is
**1,099,255,808 bytes** over **174 samples**, with zero swap/OOM. Managed GPU
peaks remain **7,467,246,016 / 7,467,247,040 bytes**, idle storage is
**2,022,919,936 bytes**, and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup finds no running Lattica services or held GPU leases and
**57 empty parent slices**.

[`gpu-opening-handoff-2026-10-10.json`](evidence/gpu-opening-handoff-2026-10-10.json)
pins **428 source files** and **287 root artifacts**, including four source
archives. The first compile check used an unavailable test serialization API;
the correction uses the repository's existing allocation-backed API. The
first qualification controller matched zero multi-AIR cases because its
module path was incomplete. Both failed attempts are preserved; corrected
compile check-02 and qualification run-02 pass. Research executable,
static-library, C-link, CPU compatibility, source/dependency ancestry,
formatting and resource audits pass under serial offline limits on the
desktop RTX 5080. The successful run is
`lattica-prover-p3/benchmark-results/gpu-opening-handoff-20261010/run-02`.

The goal remains incomplete. This closes the opened-value assembly boundary;
complete native proof lifetimes, CPU verifier scratch, callback/cache
overlaps and allocator/driver overhead still need enclosing reservations.
Component bounds must enter complete scheduler phases; ordinary pool
admission still rejects this qualification profile without them. Broader
workloads, nonempty-child full-size merges, larger blocks, sustained pool
throughput, multiple GPUs and AMD/Metal qualification remain open.


## 9.90 Machine AIR degree contract (2026-10-10)

Upstream batch verification was still constructing a symbolic constraint graph
to infer quotient degree, after the bounded metadata preparation described in
§9.87. `MachineAir` now supplies its exact base constraint degree through the
existing `BaseAir::max_constraint_degree` contract. This removes that repeated
graph allocation in release verification without modifying the upstream
verifier or its numerical constraint evaluation.

The base degree is **8**. Poseidon checkpoints reset each round to trace
variables, so a seventh-power constraint multiplied by `IS_HASH` has degree
eight. Three-bit opcode gates times scalar arithmetic have degree at most
five; cubic and public-bank gates have degree at most three. Plonky3 still
computes the lookup constraint degree separately and takes the maximum.
The new contract is independent of program instructions and trace height.
The upstream debug assertion still computes the original symbolic graph;
this checkpoint qualifies release execution, not debug memory admission.

The comparison uses an independent AIR wrapper that returns no degree hint.
For each of the **8-lane and 23-lane layouts**, its original symbolic graph
has exact base degree eight for every public-value count **0 through 64** at
heights **8 and 524,288**. Packed/unpacked lookup checks cover counts
**0/1/23/32/33/64**, heights **8/2,048**, and both hiding settings. All **48
comparisons per layout** retain quotient log-degree **3**. Instrumented release
degree inference performs **zero AIR callbacks instead of one**; complete
native verification performs **one instead of two**, retaining its numerical
AIR evaluation.

Full-strength CPU conformance constructs separately seeded original/hinted
provers in each layout. Native proof bytes are identical (**653,650 bytes**
for 8 lanes, **726,000 bytes** for 23 lanes); verification agrees on valid
proofs, altered public inputs and altered opening values. These fixed seeds
exist only in the tests. Production entropy, proof parameters, lookup packing,
transcript behavior and registry identities are unchanged.

All **420 qualification cases** pass: **225** research/GPU, **191** standard
CPU compatibility and **4** additional CPU-only wide-layout cases. Existing
wallet and multi-AIR GPU conformance passes, including the original seeded
CPU comparisons and verification after GPU shutdown. Both full-size
finalizers preserve the archived registry and every stage's operation count,
complete all **16 proving arithmetic stages on OpenCL**, pass independent CPU
verification and altered-statement rejection, and verify after worker exit.

Cold/warm full-size jobs take **70.3267 / 17.3992 seconds**, without establishing
transactions per hour or a performance gain. Worker host peak is
**1,098,616,832 bytes** over **178 samples**, with zero swap/OOM. Managed GPU
peaks remain **7,467,246,016 / 7,467,247,040 bytes**, idle storage is
**2,022,919,936 bytes**, and shutdown storage is zero. The **3 GiB worker /
4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation** caps remain
unchanged. Cleanup finds no running Lattica services or held GPU leases and
**59 empty parent slices**.

[`gpu-machine-degree-2026-10-10.json`](evidence/gpu-machine-degree-2026-10-10.json)
pins **429 repository source files** and **196 root artifacts**, including
three worktree source archives. The original **p3-air 0.6.1** and
**p3-batch-stark 0.6.1** package archives match the Cargo lockfile checksums;
all **25 upstream source files** match the installed source trees. This pins
the unchanged degree inference and native verifier used by the oracle. The
first compile check caught a moved lookup fixture in a test; its correction
and failed snapshot are preserved. Compile check-02, both CPU conformance
builds, research executable, static library, C-link and first qualification
run pass. The successful run is
`lattica-prover-p3/benchmark-results/gpu-machine-degree-20261010/run-01`.

The goal remains incomplete. Removing this inference graph does not bound
all numerical verifier/PCS scratch, native proof lifetimes, callback/cache
overlaps or allocator/driver overhead. Bounded metadata preparation remains
necessary, and complete scheduler phases must still combine the component
lifetimes. Ordinary pool admission continues to reject this qualification
profile without them. Broader workloads, nonempty-child full-size merges,
larger blocks, sustained throughput, multiple GPUs and AMD/Metal qualification
remain open.

## 9.91 Registered verifier shape admission (2026-10-10)

`RegisteredProgram::verify` and `RegisteredVerifier::verify` now check proof
dimensions before constructing the verification configuration, copying public
values, running transcripts or allowing upstream proof-data clones. The checker
uses borrowed slices, scalar dimensions and fixed arrays. Limits come from the
registered machine, its prepared quotient count, packed lookup metadata and the
existing cubic binary FRI profile; proof fields cannot choose their own limits.

The envelope covers instance openings, hiding rounds/matrices/points, commitment
caps, FRI layers and witnesses, final coefficients, query rows, salts,
authentication paths and binary fold steps. Cap and path bounds shrink with each
FRI layer. Public preprocessing retains its zero hiding-codeword width and four
salt elements. The exact prepared quotient count is retained by the verifier,
avoiding fresh inference during admission.

Conformance also exposed an upstream malformed-proof panic. Changing an otherwise
valid proof to carry `preprocessed_next = Some([])` passes the upstream initial
length check and PCS verification, then reaches a matrix row-width assertion.
The registered entry points now reject unexpected next rows before numerical
verification. Tests reproduce the original assertion in both machine layouts
and verify the new error return. The upstream numerical verifier is unchanged;
valid proof bytes and public-input/opening tamper decisions remain unchanged.

Both **8-lane and 23-lane** layouts cover **24 shape-only templates** across
public counts **0/1/23/32/33/64** and heights **8/64/524,288/16,777,216**, plus
**168 malformed shape mutations** per suite. These templates do not establish
proving feasibility at their larger heights. The tests also distinguish length
admission from caller-owned spare capacity and numerical verification.

All **440 qualification cases** pass: **231** research/GPU, **198** standard CPU
compatibility and **11** additional CPU-only wide-layout cases. Existing wallet
and multi-AIR GPU checks pass. Both full-size finalizers preserve the archived
registry and every stage's operation count, complete all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification and altered-statement
rejection, and verify after worker exit.

Cold/warm jobs take **68.0736 / 16.6593 seconds**, without establishing sustained
transactions per hour or a performance gain. Worker host peak is
**1,097,555,968 bytes** over **172 samples**, with zero swap/OOM. Managed GPU peaks
remain **7,467,246,016 / 7,467,247,040 bytes**, idle storage is **2,022,919,936
bytes**, and shutdown storage is zero. The **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation** caps remain unchanged. Cleanup finds no
running Lattica services or held GPU leases and **60 empty parent slices**.

[`gpu-verifier-envelope-2026-10-10.json`](evidence/gpu-verifier-envelope-2026-10-10.json)
pins **431 repository source files**, **377 root artifacts** and **five worktree
source archives**. The original `p3-air`, `p3-batch-stark` and `p3-matrix` package
archives match Cargo lockfile checksums; all **35 upstream source files** match
their installed sources. The first compile fixture incorrectly assumed native
proof containers implement `Clone`. The first CPU conformance attempt incorrectly
expected a nonempty unused next row to be accepted; investigating that failure
exposed the empty-row assertion. Both failures and the earlier passing GPU run
remain intact. The corrected compile check-03, CPU suites, research executable,
static library, C-link and qualification run-02 pass, followed by the artifact
audit. The final run is
`lattica-prover-p3/benchmark-results/gpu-verifier-envelope-20261010/run-02`.

The goal remains incomplete. This admits incoming proof dimensions, not all
numerical verifier/PCS scratch or caller capacities. Native proof lifetimes,
callback/cache overlaps and allocator/driver overhead still need complete
enclosing reservations. Debug symbolic inference remains outside the release
resource qualification. Complete scheduler phases must combine these lifetimes;
ordinary pool admission still rejects the qualification profile without them.
Broader workloads, nonempty-child full-size merges, larger blocks, sustained
throughput, multiple GPUs and AMD/Metal qualification remain open. Proof
parameters, registry identities and activation are unchanged.

## 9.92 Verifier inversion dispatch (2026-10-10)

The numerical verifier scratch review found that `p3-field` dispatched even
binary FRI's two-element inversions through Rayon. Lazy pool initialization adds
thread and runtime storage to cold worker verification. The pinned **0.6.1**
dependency now runs a slice of at most **1,024 elements** directly on the calling
thread. Larger slices retain the original parallel chunk schedule. The packed
four-lane prefix and scalar-tail arithmetic body is unchanged. This dependency
patch applies to all builds that resolve it, including CPU builds.

Conformance covers **25 lengths** around packing and chunk boundaries in
Goldilocks, quadratic and cubic fields: **75 comparisons** against archived
arithmetic and independent elementwise inverses, including serialized values
and vector capacities. Zero-input failures retain parity. Fresh nonroot child
processes lower only their own thread-creation resource limit: the selected
implementation succeeds through 1,024 elements for all three fields, while the
original two-element path and selected 1,025-element path still require the
Rayon pool. The parent process and user's resource limits are untouched.

The external oracle inlines the original crate-private `FieldArray::inverse`
body and skips an empty scalar-tail helper call. The audit verifies both the
inline body and the upstream helper's immediate return for empty equal-length
slices before normalizing that no-op. It separately verifies the selected
implementation's arithmetic body against the original package archive. Only
`src/batch_inverse.rs` differs from the archived package; its checksum matches
the prior lockfile. The only lockfile change since §9.91 is path resolution for
`p3-field`, with its version and other package entries preserved.

All **449 qualification cases** pass: **234** research/GPU, **201** standard CPU
and **14** additional CPU-only wide-layout cases. The default build check,
research executable, static library and C service link pass. Wallet and
multi-AIR GPU conformance passes. Both full-size finalizers preserve archived
registry identities and operation counts, complete all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification after worker exit and
reject altered statements. Cold/warm jobs take **68.1004 / 16.6640 seconds**;
these isolated timings establish neither sustained throughput nor a performance
gain.

Worker host peak is **1,099,964,416 bytes** over **172 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle GPU storage is **2,022,919,936 bytes**, and shutdown storage is zero.
The **3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU / 1 GiB
allocation** caps are unchanged. Cleanup finds no running Lattica services or
held GPU leases and **61 empty parent slices**.

[`gpu-verifier-inversions-2026-10-10.json`](evidence/gpu-verifier-inversions-2026-10-10.json)
pins **468 repository source files**, **219 root artifacts** and **four source
archives**. Two compile attempts exposed a missing trait import and access to
a crate-private helper in the oracle; their source snapshots and logs remain
intact. Corrected compile check-03 and qualification run-01 pass. The initial
audit compared the oracle's harmless empty-tail guard literally; the corrected
audit proves that adaptation is a no-op and passes. The executed audit
controllers and failure log are preserved. The successful native run is
`lattica-prover-p3/benchmark-results/gpu-verifier-inversions-20261010/run-01`.

The goal remains incomplete. Removing this small-input dispatch does not admit
all native numerical verifier/PCS scratch, caller proof capacities, result
storage, callback/cache overlaps or allocator/driver overhead. Checked bounds
must come from trusted geometry and source allocation behavior, including
container growth and overlapping old/new buffers. Complete scheduler phases
must combine those lifetimes; ordinary pool admission continues to reject the
qualification profile without them. Broader workloads, nonempty-child full-size
merges, larger blocks, sustained throughput, multiple GPUs and AMD/Metal
qualification remain open. Proof parameters, encodings and activation are
unchanged.

## 9.93 Native numerical verifier scratch (2026-10-10)

[The numerical scratch model](../lattica-prover-p3/src/block_v2/machine/backend/verification_scratch.rs)
now bounds the registered single-machine `verify_batch` path on **release
x86_64**. Both registered verification entry points apply it after the proof
length envelope and before configuration construction, public-value copying or
numerical verification. Checked arithmetic and trusted geometry reject overflow,
unsupported layouts and requests above a fixed **64 MiB component ceiling**.
Planning itself allocates no heap storage. The ceiling is separate from the
unfinished enclosing worker reservation.

The derivation sums allocation requests across batch geometry, quotient domains,
opening clones and hiding growth, transcript buffers and cap clones, lookup bus
indices, big-integer height checks, LogUp evaluation vectors, MMCS sorting and
schedules, reduced-opening maps, and binary FRI interpolation. It charges old
and replacement buffers cumulatively. The registered domains justify equal
heights within every MMCS batch and one reduced-opening map entry. The machine
uses one named global wire bus, so its hash table and cold hash-seed allocation
are included. The bounds follow pinned source and container behavior; observed
peaks neither define the formulas nor reduce the ceiling.

Both layouts cover **24 trusted templates** across public counts
**0/1/23/32/33/64** and heights **8/64/524,288/16,777,216**. Maximum cumulative
requests are **26,636,073 bytes** for the standard layout and **27,379,865 bytes**
for the wide layout. These templates do not establish proving feasibility at
the largest height. Tests check planning allocations, container growth, boxed
shrinking, sorting, the single-height map, arithmetic overflow, unsupported
metadata and the exact allowance boundary.

A test-only observer records allocation requests on the calling thread.
Across both CPU layouts, **eight fresh small proofs** drive **48 numerical
verification attempts**: **16 valid** and **32 tampered** attempts. These include
changed public inputs and openings, and changes in the last query and final
FRI layer. Decisions match the registered entry points and every observed
request sum fits its independently derived bound. Observations check the model;
they do not establish full-size allocator usage or a complete RSS bound.

All **460 qualification cases** pass: **237** research/GPU, **205** standard CPU
and **18** additional CPU-only wide-layout cases. Default compilation and
block-v2 compilation without `stream` pass. The static library and C service
link pass. Wallet and multi-AIR GPU checks pass. Both full-size finalizers
preserve archived registry identities and operation counts, complete all **16
proving arithmetic stages on OpenCL**, pass independent CPU verification after
worker exit and reject altered statements. Cold/warm jobs take **68.1159 /
17.8769 seconds**; these isolated timings establish neither sustained
transactions per hour nor a performance improvement.

Worker host peak is **1,099,563,008 bytes** over **174 samples**, with zero
swap/OOM. Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**;
idle GPU storage is **2,022,919,936 bytes**, and shutdown storage is zero.
The **3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU / 1 GiB
allocation** caps are unchanged. Cleanup finds no running Lattica services or
held GPU leases and **62 empty parent slices**.

[`gpu-verifier-scratch-2026-10-10.json`](evidence/gpu-verifier-scratch-2026-10-10.json)
pins **471 repository source files**, **257 root artifacts**, **six worktree
source archives**, **419 upstream files from 16 packages**, and **101 Rust
container source files**. Package archives match lockfile checksums; the
container model is pinned to **Rust 1.96.0**. Failed controller/compile attempts
and the first CPU conformance run remain intact. That CPU run caught the model's
incorrect local-bus assumption, which was corrected to account for the named
global wire bus and its allocations.

The initial research test build hit its **180-second** limit with a **2.8 GiB**
peak and zero swap. Retrying the test executable with **two code-generation
units** succeeded in **105.998 seconds**, with a **2.7 GiB** peak and zero swap,
under the same service caps. The preserved static library retains **one
code-generation unit** and completed in **68.764 seconds**, with a **1.9 GiB**
peak. Build settings and binaries are pinned separately. The successful GPU
qualification is
`lattica-prover-p3/benchmark-results/gpu-verifier-scratch-20261010/run-01`.

The goal remains incomplete. This model covers numerical allocation requests
for the registered single-machine verifier with a fresh CPU challenger and
reference PCS. Configuration construction, public-value copies, caller-owned
proof and metadata capacities, result/error storage, tracing callbacks, stacks,
and allocator/driver overhead still need enclosing bounds. Other verifier
families, debug symbolic inference and other targets are outside this component's
qualification. Dependency or toolchain changes require renewed qualification.
Complete scheduler phases must combine simultaneous lifetimes; ordinary pool
admission still rejects the qualification profile without them. Broader workloads,
nonempty-child full-size merges, larger blocks, sustained throughput, multiple
GPUs and AMD/Metal qualification remain open. Proof parameters, encodings and
activation are unchanged.

### 9.94 Native verifier call storage and proof backing capacities (2026-10-10)

The registered native verifier now checks caller-owned proof capacities and a
combined temporary allocation-request bound after its structural envelope and
before configuration construction, public-value copying or numerical work.
The two component ceilings are **64 MiB for proof backing buffers** and
**64 MiB for cumulative temporary requests**. Neither ceiling is a complete
worker reservation or an allocator/RSS bound.

The temporary model adds the numerical bound from §9.93, fresh configuration
storage, `8 * public_values` bytes for an exact-capacity public copy, and
**1,024 bytes** for a returned diagnostic. Configuration construction obtains
two fresh independent ChaCha20 seeds directly from OS entropy; entropy failure
returns a bounded error. This avoids initializing a thread-local RNG in the
verification entry point. Proving configuration factories retain their existing
behavior and entropy requirements.

Configuration storage follows the pinned sources: five Poseidon2 constant sets
of **688 bytes**, three empty Arc-backed DFT cache roots without `stream` or six
with it, and two CPU-MMCS Arcs plus two host ProofRng Arcs when GPU support is
compiled. The model uses the actual private RNG state size and pinned Arc,
spin-lock and BTreeMap layouts. It predicts **3,584 bytes** for non-stream CPU,
**3,728 bytes** for streaming CPU and **5,424 bytes** for the streaming research
GPU build. Twelve configuration observations match those predictions exactly;
observations validate the derivation and do not set its limits. OS/libc entropy
provider internals remain outside the Rust allocation-request model.

Public values use fallible exact-capacity allocation. Concrete upstream verifier
errors format into a fixed UTF-8 stack buffer before one final bounded String
allocation. Short diagnostics retain their text; oversized diagnostics return
a fixed rejection message. This accounts for the audited concrete Debug
implementations, not arbitrary user-provided formatting callbacks.

An allocation-free borrowed traversal charges every native proof Vec's
`capacity * size_of::<T>()`, including outer container headers and spare slots,
and descends only into initialized elements. It covers commitment caps, opened
values, hiding openings, FRI caps/witnesses/polynomials/queries, rows, salts,
authentication paths, degree bits and lookup terminals. A minimal vendored
`p3-symmetric` **0.6.1** patch exposes the cap backing vector's capacity through
a read-only accessor. Its original archive, license and source hashes are
preserved; proof fields, hashing, serialization and arithmetic do not change.
The check runs after the caller has allocated the proof, so it cannot reserve
that allocation retroactively. Borrowed public slices likewise do not expose
their owners' spare capacity.

Tests cover **34 spare-capacity mutations**, two empty optional buffers,
checked arithmetic, exact admission boundaries, UTF-8 diagnostic boundaries,
and allocation-free planning. Each tested configuration covers **24 trusted
templates** across public counts **0/1/23/32/33/64** and heights
**8/64/524,288/16,777,216**. The largest template proof backing storage is
**2,831,704 bytes**; the largest temporary request bound is **27,386,825 bytes**.
Templates at large heights do not establish proving feasibility. Across the
standard, wide and non-stream CPU configurations, six fresh small proofs drive
**18 complete entry-point observations**: **12 valid** and **six late FRI
rejections**. The largest observed request sum is **1,826,700 bytes**, within
the independently derived bound.

All **55 qualification cases** pass: **15** research/GPU, **17** standard CPU,
**17** wide CPU and **six** non-stream CPU cases. Default and research compile
checks, static-library construction and C service linking pass. Two full-size
finalizers retain archived registry identities and operation counts, complete
all **16 proving arithmetic stages on OpenCL**, pass independent CPU verification
after worker exit and reject two altered statements. Cold/warm jobs take
**68.1281 / 16.5835 seconds**. Worker host peak is **1,454,411,776 bytes** across
**172 telemetry samples**, with zero swap/OOM. Managed GPU peaks remain
**7,467,246,016 / 7,467,247,040 bytes**, idle storage is **2,022,919,936 bytes**,
and shutdown storage is zero. The **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation** caps are unchanged. Cleanup finds no
running Lattica services or held GPU leases and **63 empty parent slices**.
These isolated timings do not establish sustained throughput or an improvement.

The first non-stream test build caught an observer import that depended on
`stream`. The failed build and its source archive remain intact. A test-only
System allocator wrapper now supplies the same observer in non-stream test
executables. This correction followed full-size qualification: all production
sources and existing test bodies are identical to its pinned source, and the
final research/default compile checks and non-stream tests pass. Both source
revisions are explicitly recorded; finalized qualification artifacts were not
rewritten. The research executable uses two code-generation units; the static
library retains one.

[`gpu-verifier-call-storage-2026-10-10.json`](evidence/gpu-verifier-call-storage-2026-10-10.json)
pins **489 final source files**, **147 artifacts**, **12 worktree archives**,
and the distinct qualification source revision. It adds **528 upstream files
from eight packages** and **12 Rust library files** to the inherited source
audit. All **419 inherited upstream files** and **101 inherited Rust container
files** were reverified. Native artifacts are in
`lattica-prover-p3/benchmark-results/gpu-verifier-call-storage-20261010/run-01`.

The goal remains incomplete. This closes the registered verifier's configuration,
public-copy, diagnostic and proof-capacity components for the qualified release
x86_64 Linux path. Cached metadata, caller/result retention, simultaneous worker
and coordinator lifetimes, callbacks, stacks and allocator/driver/OS overhead
still need enclosing admission. Ordinary pool admission continues to reject
the incomplete phase profile. Broader workloads, nonempty-child full-size
merges, larger blocks, sustained throughput, multiple GPUs and AMD/Metal
qualification remain open. Dependency or toolchain changes require renewed
qualification; proof parameters, encodings and activation are unchanged.

### 9.95 Independent verifier lifetimes and worker reservation (2026-10-10)

The registered native verifier now plans construction and verification as
separate storage phases before allocating its trusted empty machine shape.
The checked plan includes the Arc-owned shape, reference and public-row vectors,
cap backing capacity, common-data containers, symbolic construction workspace,
retained lookup metadata, one admitted proof, and verification scratch. It uses
a **257 MiB (269,484,032-byte)** component allowance. Cap backing capacity is
limited to **64 KiB**, checked before shape or metadata allocation. This is a
component payload bound, not complete process RSS admission.

`Registry::verify` now admits native proof backing capacity before constructing
independent verifier metadata. The allocation-free traversal checks each outer
container before visiting its children; shape and numerical checks remain
separate. The verifier still builds its own trusted metadata. Caller-owned proof
and cap storage must already exist for these borrowed checks, so they cannot
reserve the caller's original allocations retroactively.

Matching Rust and Python witness reservations add the verifier allowance once
per serial worker. The full-size finalizer's witness host reservation increases
from **1,593,713,952** to **1,863,197,984 bytes**; combined additional host reserve
increases from **1,898,198,304** to **2,167,682,336 bytes**, below the unchanged
**3 GiB** worker cap. The two-entry full-size merge resource fixture increases
from **2,610,980,304** to **2,880,464,336 bytes**. That fixture validates accounting,
not execution of a full-size nonempty-child merge.

All **92 native qualification cases** and **55 Python resource-model cases**
pass: **36** research/GPU, **28** standard CPU, **22** wide CPU and **6** non-stream
CPU native cases. Each of the three lifecycle configurations checks **24 trusted
templates**, covering public counts **0/1/23/32/33/64** and heights
**8/64/524,288/16,777,216**. The largest bound within those geometry templates is
**268,438,320 bytes**. Separate tests cover cap capacity, invalid geometry, exact
admission boundaries, allocation-free planning, and phase composition. Nine
constructor allocation observations fit their source-derived bounds; the
observations validate the derivation and do not define its limits. Default
compilation, final native builds, C linking, formatting and whitespace checks
also pass. Research tests use two code-generation units; the static library
retains one.

On the desktop RTX 5080, both full-size finalizers preserve registry identities
and operation counts, complete all **16 proving arithmetic stages on OpenCL**,
pass independent CPU verification after worker exit, and reject two altered
statements. Cold/warm jobs take **68.1116 / 16.7032 seconds**. Host peak is
**1,102,585,856 bytes** over **172 telemetry samples**, with zero swap/OOM. Managed
GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**, idle storage is
**2,022,919,936 bytes**, and shutdown storage is zero. The **3 GiB worker / 4 GiB
aggregate host / 7 GiB managed GPU / 1 GiB allocation** limits are unchanged.
Direct fixtures acquire their device lease in native engine initialization;
cleanup finds no running Lattica services or held GPU leases and **64 empty
parent slices**. These isolated timings do not establish sustained throughput
or an improvement.

The first qualification attempt exposed stale test host budgets; the second
exposed a missing version in fake GPU assignments. Both failed before full-size
proving. Their source archives and logs remain intact. The third qualification
and all final compatibility checks use the same final source revision.
[`gpu-verifier-lifetimes-2026-10-10.json`](evidence/gpu-verifier-lifetimes-2026-10-10.json)
pins **491 source files**, **255 artifacts**, and **18 worktree archives**. Its
audit rechecks **947 source files from 24 inherited dependency packages** and
**113 Rust library files**. Native artifacts are in
`lattica-prover-p3/benchmark-results/gpu-verifier-lifetimes-20261010/run-03`.

The goal remains incomplete. This closes the independent registered verifier's
component lifetime bound. Enclosing caller caches, registry and result
containers, simultaneous worker/coordinator lifetimes, stacks, callbacks, and
allocator/driver/OS overhead still need admission. Ordinary pool admission
continues to reject the incomplete phase profile. Separating retained program
storage from construction peaks is the next accounting step. Broader workloads,
nonempty-child full-size merges, larger blocks, sustained throughput, multiple
GPUs and AMD/Metal qualification remain open. Proof parameters, encodings and
activation are unchanged.

### 9.96 Retained program source and construction lifetimes (2026-10-10)

GPU witness resource bounds now distinguish retained program source from its
construction/packing peak. `program_retained_host_bytes` counts the Arc
allocation, operation/reference/row vector capacities, packed row buffers and
nested hint buffers. The pinned Rust Arc layout includes its two reference
counters and aligned payload. Planning performs no allocations and counts spare
capacity without changing program identity or compiler geometry.

The matching Rust and Python reservations charge retained source once per cache
entry. They keep the full `program_host_bytes` allowance in the transient phase:
`max(compiler + staging, program_host_bytes + input_staging)`. The cached term
becomes `entries * (retained_source + compiler_host_bytes - metadata_bytes)`.
The remaining allowances are unchanged. Historical assignments that omit the
new field, or set it to zero, use the original combined source bound and retain
their exact conservative reservation. Invalid values and retained bounds larger
than the combined source peak are rejected. Workers compare both bounds against
each actual program before device upload; increasing the construction allowance
cannot conceal insufficient retained storage.

The qualified full-size program retains **506,224,960 bytes** of source capacity;
its construction/source peak remains **508,066,252 bytes**, a difference of
**1,841,292 bytes**. The historical workload assignment allows **571,816,240
bytes** for construction/source. A second assignment preserves that construction
allowance and separately allows **512 MiB (536,870,912 bytes)** for retained
source, rounded above the checked program capacities and enforced again by the
worker. Its witness host reservation decreases from **1,863,197,984** to
**1,828,252,656 bytes**, and combined additional host reserve decreases from
**2,167,682,336** to **2,132,737,008 bytes**. This releases **34,945,328 bytes
(33.33 MiB)** of conservative reservation for this assignment. It is a
reservation change, not an observed reduction in allocated memory or a measured
throughput improvement.

All **27 native qualification cases** and **57 Python resource cases** pass.
The native cases include nine resource tests in each of the standard and wide
GPU feature configurations, seven targeted GPU regressions and two full-size
worker cases. The standard-layout resource tests execute host planning only.
Normal standard CPU, wide CPU, non-stream CPU and default builds pass their
offline compile checks. Tests cover legacy decoding, malformed values, exact
admission boundaries, independent construction/retained limits, cache counts
**1/3/12**, Arc allocation size and nested spare capacities. The two allocation
observations confirm **120-byte** Arc allocations and **175,488 bytes** of added
spare capacity without altering identity; observations validate the model and
do not define its limits.

Both assignments produce two full-size finalizers on the desktop RTX 5080. All
**four fresh proofs** preserve registry identities and operation counts,
complete all **16 proving arithmetic stages on OpenCL**, pass independent CPU
verification after worker exit and reject four altered statements. Historical
cold/warm jobs take **68.0840 / 16.7154 seconds**, versus **68.0482 / 16.7406
seconds** for the retained assignment. Observed host peaks are **1,099,091,968 /
1,097,920,512 bytes**, each over **172 telemetry samples**, with zero swap/OOM.
Managed GPU peaks remain **7,467,246,016 / 7,467,247,040 bytes**, idle storage is
**2,022,919,936 bytes**, and shutdown storage is zero. All physical limits remain
**3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU / 1 GiB allocation**.
Cleanup finds no running services or GPU leases and **66 empty parent slices**.
These are assignment-conformance runs, not the five paired performance runs or
sustained promotion gate.

The first Python test attempt caught an edit to the wrong schema gate. Its two
failed tests, log and source revision are preserved; the corrected source
restores strict randomness bounds and extends only witness bounds. All native
qualification and final build checks use the same final source revision.
[`gpu-program-cache-lifetimes-2026-10-10.json`](evidence/gpu-program-cache-lifetimes-2026-10-10.json)
pins **492 source files**, **202 artifacts**, and **10 worktree archives**, and
reverifies **947 inherited dependency files** and **113 Rust library files**.
Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-program-cache-lifetimes-20261010`.

The goal remains incomplete. Retained compiler schedules still use a
conservative allowance that includes released workspace. That component and
the enclosing caller/cache/result, worker/coordinator, stack and allocator/OS/
driver lifetimes still need composition. Ordinary pool admission continues to
reject the incomplete phase profile. Broader workloads, nonempty-child full-size
merges, larger blocks, sustained throughput, multiple GPUs and AMD/Metal
qualification remain open. Proof parameters, encodings, arithmetic and
activation are unchanged.

### 9.97 Retained witness schedules and compiler workspace (2026-10-10)

GPU witness resource bounds now separate the launch schedule retained in a
cached program from released compiler readiness, level and ordering workspace.
The new optional `compiler_retained_host_bytes` field is independent of the
full `compiler_host_bytes` construction allowance. Historical omitted/zero
values preserve the exact `compiler_host_bytes - metadata_bytes` cache bound.
Rust and Python agree on both retained components, reject malformed or
inconsistent bounds, and compare schedule admission independently of the
compiler peak. A larger compiler allowance cannot conceal insufficient retained
schedule storage.

The source-derived upper bound is the inline schedule plus one
`Range<usize>` per operation: **64 + 16 × operations bytes** on the qualified
target. The compiler emits at most one dependency wave per operation. Planning
does not allocate dependency scratch or inspect private witness values.
`WitnessSchedule` now performs a checked, fallible, exact-capacity copy after
admitting its actual wave count and before device allocation or instruction
upload. The copied schedule retains neither source wave spare capacity nor
compiled instruction words. Original compiler metadata and the new schedule
can coexist during handoff within the unchanged compiler peak allowance.

For the full-size fixture, the former retained compiler allowance is
**56,775,136 bytes**; the new operation-count schedule bound is **21,025,984
bytes**, a **35,749,152-byte** difference in the runtime component bounds. The
actual retained schedule remains **63,152 bytes**. That observation validates
the bound and does not define its limit. The explicit qualification assignment
uses a **24 MiB (25,165,824-byte)** schedule allowance while preserving the full
**368,417,296-byte** compiler construction allowance and §9.96's source bounds.
Its witness host reservation decreases from **1,828,252,656** to
**1,796,643,344 bytes**; combined additional host reserve decreases from
**2,132,737,008** to **2,101,127,696 bytes**. This releases another **31,609,312
bytes (30.15 MiB)** of conservative reservation per cache entry for this
assignment. It does not demonstrate a reduction in actual allocated memory or
a throughput gain.

All **46 native qualification cases** and **59 Python resource tests** pass.
There are **17 host cases in each supported GPU lane layout**, **10 targeted
GPU regressions**, and **two full-size worker cases**. Standard CPU, wide CPU,
non-stream CPU and default compile checks also pass. Tests exercise empty and
parallel schedules, a **64-step dependency chain** that reaches the upper bound,
overflow, exact admission, allocation-free rejection, source-drop independence,
compiler/schedule overlap, legacy decoding and cache counts **1/3/12**. A
one-wave schedule retains **80 bytes** and makes one **16-byte** allocation in
both layouts. GPU conformance checks compare witness/preprocessing values with
CPU references, verify instruction storage release, and exercise rejection and
reuse. A deliberately undersized schedule uploads nothing; a subsequent valid
upload on the same session succeeds.

Historical and explicit schedule assignments each produce two full-size
finalizers on the desktop RTX 5080. All **four fresh proofs** preserve registry
identities and operation counts, complete all **16 proving arithmetic stages
on OpenCL**, pass independent CPU verification after worker exit, and reject
four altered statements. Historical cold/warm jobs take **68.0250 / 16.6989
seconds**; the explicit schedule assignment takes **69.0056 / 16.6963 seconds**.
Host peaks are **1,101,103,104 / 1,099,694,080 bytes**, over **172 / 174 telemetry
samples**, with zero swap/OOM. Managed GPU peaks remain **7,467,246,016 /
7,467,247,040 bytes**, idle storage is **2,022,919,936 bytes**, and shutdown
storage is zero. The **3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU /
1 GiB allocation** caps are unchanged. Cleanup finds no running services or GPU
leases and **68 empty parent slices**. These assignment-conformance timings do
not satisfy the paired performance or sustained promotion gates.

[`gpu-schedule-lifetimes-2026-10-10.json`](evidence/gpu-schedule-lifetimes-2026-10-10.json)
pins **494 source files**, **228 artifacts**, and **13 worktree archives**. The
audit reverifies **947 inherited dependency files** and **113 Rust library
files**. Preliminary compile snapshots preserve the versions before the GPU
rejection and maximum-chain tests were added; all final builds and qualification
use the same source revision. All native runs passed. Research executables use
two code-generation units; the static library retains one. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-schedule-lifetimes-20261010`.

The goal remains incomplete. This closes the retained launch-schedule payload
component. Cached prover metadata, registry/request/result ownership and the
complete worker/coordinator phase plan still need composition, including
stacks, callbacks and allocator/driver/OS overhead. Ordinary pool admission
continues to reject the incomplete phase profile. Broader workloads,
nonempty-child full-size merges, larger blocks, sustained throughput, multiple
GPUs and AMD/Metal qualification remain open. Proof parameters, encodings,
arithmetic and activation are unchanged.

### 9.98 Cached lookup graphs and construction overlap (2026-10-10)

GPU witness admission now reserves the symbolic packer's **64 MiB retained
lookup ceiling per cached AIR**, in addition to the full **192 MiB symbolic
workspace once per worker**. The packer's existing census enforces this ceiling
on backing capacities, global names and unique shared expression Arcs. The Rust
resource planner takes its constant directly from that ceiling; the Python
planner uses the matching allowance. Moving packed lookups into preprocessing
metadata preserves their ownership and does not duplicate the graphs.

Cached lookup graphs survive incoming source construction, proving and independent
verification. On a cache miss, eviction precedes registered-program setup, but
incoming source construction can already overlap the full cache. On a hit, the
incoming program is dropped before proving while cached lookup metadata remains.
Admission conservatively reserves every configured cache entry plus the complete
construction workspace, including its new output. Retained source and schedule
bounds, construction peaks, input staging and the **257 MiB** independent verifier
component remain intact. Historical bound fields still decode; old descriptors
that omit the additional reservation are rejected and must be regenerated.

For the qualified full-size fixture, the assigned witness host reservation grows
from **1,796,643,344 to 1,863,752,208 bytes**. Combined additional host reservation
grows from **2,101,127,696 to 2,168,236,560 bytes**. This is an additional
**67,108,864-byte** reservation per cache entry. The fixture's observed retained
lookup storage is **121,176 bytes**, with unchanged packing geometry. That
observation validates the enforced bound; it does not define the limit. This
checkpoint establishes a missing component reservation and makes no throughput
or measured memory-saving claim.

Final qualification passes **64 native cases** and **60 Python tests**. This
includes **24 host cases in the standard GPU layout**, **29 host cases in the
wide GPU layout**, **10 targeted GPU regressions**, and **one full-size worker
case producing two proofs**. Standard, wide, non-stream and default CPU compile
checks also pass. Tests cover cache entries **1/3/12**, incoming construction,
independent verifier overlap, rejection of stale assignments despite spare
physical capacity, exact admission boundaries, spare capacities/shared Arc
counting, and ownership transfer after packing workspace release. The packing
fixture retains **1,393 bytes**; its move allocates nothing and its one-byte-short
retained allowance is rejected.

The desktop RTX 5080 run completes two fresh full-size proofs with all **16
proving arithmetic stages on OpenCL**. Independent CPU verification follows
worker exit, two altered statements are rejected, and registry identities and
operation counts match §9.97. Cold/warm worker times are **69.6623 / 17.6472
seconds**. The worker cgroup peaks at **1,082,118,144 bytes** over **178 telemetry
samples**, with zero swap/OOM. Managed GPU peaks are **7,467,246,016 /
7,467,247,040 bytes**, idle storage is **2,022,919,936 bytes**, and shutdown storage
is zero. Limits remain **3 GiB worker / 4 GiB aggregate host / 7 GiB managed GPU /
1 GiB allocation**. Cleanup finds no running services or held GPU leases and
**71 empty parent slices**. These are conformance timings; the paired performance
and sustained promotion gates remain open.

The first Python run caught an outdated multi-entry expected value. The first
native host run exposed two existing **512 MiB** test-only fixture limits below
the enlarged reservation; those fixtures now use **1 GiB**. Failed logs and
source revisions are preserved. The first audit controller used an incorrect GPU
inventory field name; its corrected successor is preserved separately. Final
research build `research-build-03`, static library `staticlib-02`, and
qualification `run-02` use the same final source revision. Research executables
retain two code-generation units; the static library retains one.

[`gpu-cached-lookup-lifetimes-2026-10-10.json`](evidence/gpu-cached-lookup-lifetimes-2026-10-10.json)
pins **495 source files**, **194 artifacts** and **16 worktree source archives**.
The audit reverifies **947 inherited dependency files** and **113 Rust library
files**. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-cached-lookup-lifetimes-20261010`.

The goal remains incomplete. Cached PCS handles, inline prover/receipt/container
storage, registry/request/result ownership, and complete worker/coordinator phase
composition still need accounting, including stacks and allocator/driver/OS
overhead. Cache counts 3 and 12 are host admission tests; this full-size GPU run
uses one cached program. Ordinary pool admission continues to reject the
incomplete phase profile. Nonempty-child full-size merges, larger workloads,
paired performance comparisons, **24 hours AND 150 completed roots**, multiple
GPUs and AMD/Metal qualification remain open. Verification stays on CPU; proof
parameters, encodings and arithmetic activation are unchanged.

### 9.99 Cached PCS metadata and salt ownership (2026-10-10)

GPU witness admission now includes cached PCS, common-data and provenance
storage independently of program source, launch schedules and packed lookup
graphs. `pcs_retained_host_bytes` is an optional bound. Omitted/zero reserves
**1 MiB plus 1,024 bytes per trace row**, covering the compatible host-salt path.
An explicit **1 MiB** allowance covers device-salt metadata. Hiding preprocessing
doubles the domain and applies blowup 16; four eight-byte salt fields per LDE row
explain the host-salt term. Actual admission uses the preprocessing PCS's salt
mode, and an inflated compiler allowance cannot hide a smaller PCS cache bound.
Old descriptors must be regenerated even though historical bound fields decode.

The completed preprocessing data and registered prover pass an ownership census
before publication. It counts inline prover storage, outer common-data vectors,
commitment/tree cap capacities, prefix/dimension arrays, allocation Arc headers,
public salt wrappers or host salt matrix capacities, and cached provenance
backing. Source, schedules and lookup graphs retain their separate reservations.
Private prefixes, private/replayed salts and malformed salt geometry are rejected
at this boundary. Shared engine/accounting/context/driver state and unused cache
container capacity remain separate worker-level work. This is a checked logical
storage ceiling, not a process RSS estimate; aliases may be counted conservatively.

For the full-size fixture, both assignments retain **5,624 bytes** of counted
metadata below the **1,048,576-byte** ceiling. The small host-salt regression
retains **70,944 bytes** at 64 trace rows, including its **65,536-byte** salt
matrix. Spare vector capacity is counted. GPU regressions enlarge cap backing
without changing roots, verify rejection, restore the original cap, and confirm
that device allocation, upload and live-storage counters are unchanged in both
salt modes.

| Assignment | Witness host reservation | Combined additional host reservation |
| --- | ---: | ---: |
| §9.98, before this component | 1,863,752,208 | 2,168,236,560 |
| §9.99, omitted/zero PCS bound | 2,133,236,240 | 2,437,720,592 |
| §9.99, explicit device-salt bound | 1,864,800,784 | 2,169,285,136 |

The explicit device assignment adds the required **1 MiB** metadata component to
§9.98 while avoiding **268,435,456 bytes (256 MiB)** of unnecessary host-salt
reservation per cache entry. It does not demonstrate an RSS or throughput gain.
All physical RAM/GPU caps remain unchanged.

Final qualification passes **78 native cases** and **61 Python tests**. There are
**29 standard-layout host cases**, **34 wide-layout host cases**, **13 targeted
GPU regressions**, and **two full-size worker cases producing four fresh proofs**.
Standard, wide, non-stream and default CPU compile checks also pass. Tests cover
cache entries **1/3/12**, legacy decoding, mode-dependent storage, malformed
bounds, independently checked metadata limits, spare capacities, partial salt
rows, private-ownership rejection, and aligned Arc allocation requests. An aligned
Arc fixture requests exactly **128 bytes**. The expanded **16,384-row**
preprocessing fixture admits **564,726,792 bytes** of GPU-path host reservation
while CPU compact/full LDE lower bounds are **740,294,656 / 1,979,711,488 bytes**.
Its one-byte-short host allowance is rejected without GPU allocation or upload;
exact admission succeeds.

All four full-size proofs execute **16 proving arithmetic stages on OpenCL**, pass
independent CPU verification after worker exit, and reject four altered statements.
Registry identities and operation counts match §9.98. Historical/explicit
assignments have cold/warm worker times of **67.9745 / 16.6948** and **70.9467 /
17.2537 seconds**. Worker cgroup peaks are **1,097,744,384 / 1,098,133,504 bytes**
over **172 / 179 telemetry samples**, with zero swap/OOM. Managed GPU peaks remain
**7,467,246,016 / 7,467,247,040 bytes**, idle storage is **2,022,919,936 bytes**, and
shutdown storage is zero. Limits remain **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB allocation**. Cleanup finds no running services or GPU
leases and **73 empty parent slices**. These are conformance timings, not the
paired performance or sustained promotion gates.

The first research test build exposed a test-only malformed-matrix constructor
using a private field. Its correction mutates values after valid construction.
The first GPU qualification exposed an existing 8,192-row fixture whose CPU
compact-memory comparison had become stale as worker reservations grew. Increasing
that fixture to 16,384 rows preserves its intended comparison and exact admission
checks. Failed logs, controller versions and source snapshots remain unchanged.
Final `research-build-03`, `staticlib-02`, and qualification `run-02`/`run-03`
share the final source revision. Research tests retain two code-generation units;
the static library retains one.

[`gpu-cached-pcs-lifetimes-2026-10-10.json`](evidence/gpu-cached-pcs-lifetimes-2026-10-10.json)
pins **497 source files**, **335 artifacts**, and **17 worktree source archives**.
The audit reverifies **1,044 dependency files across 26 packages** and **113 Rust
library files**, including the OpenCL Rust wrappers' inline ownership layouts.
Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-cached-pcs-lifetimes-20261010`.

The goal remains incomplete. Unused cache-container capacity, shared engine and
context ownership, registry/request/result storage, and complete worker/coordinator
phase composition still need accounting, including stacks and allocator/driver/OS
overhead. Cache counts 3 and 12 are host admission checks; full-size GPU runs use
one cached program. Ordinary pool admission continues to reject incomplete phase
profiles. Nonempty-child full-size merges, larger workloads, paired performance
comparisons, **24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal
qualification remain open. Verification remains on CPU; proof parameters,
encodings and proving arithmetic activation are unchanged.


### 9.100 Fixed typed-session storage and registry ownership (2026-10-10)

Typed recursive sessions now use fixed inline cache slots for their **5, 6 or
12 registered keys**. The ownership census includes every slot, including unused
ones. Hits retain LRU order; eviction, clearing and reconfiguration cannot grow
or retain an uncharged cache-container allocation. Cached program source,
schedules, lookup graphs and PCS payloads retain their separate reservations.
Inline registered-prover storage is conservatively covered by both the slot
allowance and the existing PCS census.

A separate **1 MiB session allowance** covers the inline session and its registry
backing. The qualified wide and standard GPU builds report **14,688 / 17,608 /
35,128 bytes** for 5 / 6 / 12 keys. Registry admission counts inline storage and
cap-vector capacities against **64 KiB**, before identity hashing; excess spare
capacity is rejected without changing accepted registry identities. The typed
worker now borrows the session's registry instead of retaining its own clone.
The outer process bootstrap configuration still owns a separate registry, which
belongs to the remaining configuration/request lifetime work.

The shared checked active-memory calculation subtracts the session allowance
and the configured idle-cache reserve before allocating an active prover. Both
session construction and process configuration reject budgets with no remaining
active memory. Invalid cache reconfiguration preserves the previous state.
Rust and Python witness admission add **1 MiB per registered-program reservation**,
independent of its live-cache entry count; batch admission retains its existing
conservative summation. Historical descriptors must regenerate their reservation.

| Assignment | Witness host reservation | Combined additional host reservation |
| --- | ---: | ---: |
| Omitted/zero PCS bound | 2,134,284,816 | 2,438,769,168 |
| Explicit device PCS bound | 1,865,849,360 | 2,170,333,712 |

Both assignments add **1,048,576 bytes** relative to §9.99. The device assignment
still avoids the conservative **256 MiB** host-salt term. These are logical
ownership reservations; this change establishes neither an RSS reduction nor a
throughput improvement. Physical worker, aggregate-host, managed-GPU and
per-allocation caps remain **3 GiB / 4 GiB / 7 GiB / 1 GiB**.

Final validation passes **104 native cases** and **61 Python tests**: 41 wide
GPU-build host cases, 35 standard GPU-build host cases, 13 CPU lifecycle cases,
13 GPU regressions and two full-size worker cases. All four CPU compatibility
compile configurations pass. Coverage includes LRU order and destruction,
clearing/reconfiguration, registry spare-capacity boundaries, exact active-RAM
boundaries, pre-launch rejection, context rebinding, pending dispatch and
reservation retention through observed child exit. CPU-reference lifecycle
fixtures run in a CPU-only build; the GPU builds exercise the applicable
configuration and structural checks.

The final source revision produces **four fresh full-size proofs** with all
**16 proving arithmetic stages on OpenCL**. Independent CPU verification occurs
after worker exit; four altered statements are rejected. Registry identities
and arithmetic operation counts match §9.99. Historical/device assignments have
cold/warm times of **69.0508 / 16.7195** and **68.2209 / 17.4218 seconds**.
Worker cgroup peaks are **1,097,883,648 / 1,099,763,712 bytes**, with **174 telemetry
samples each**, zero swap and no sampled OOM events. Managed GPU peaks remain
**7,467,246,016 / 7,467,247,040 bytes**, idle storage **2,022,919,936 bytes**, and
shutdown storage zero. Cleanup finds no running Lattica services or held GPU
leases and **75 empty parent slices**.

[`gpu-session-storage-2026-10-10.json`](evidence/gpu-session-storage-2026-10-10.json)
pins **498 source files**, **539 artifacts** and **38 worktree source archives**;
the audit reverifies **1,044 dependency files across 26 packages** and **113 Rust
library files**. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-session-storage-20261010`. Final builds
are `research-build-04` (two code-generation units) and `staticlib-03` (one);
`qualify-03.py` runs `run-04` and `run-05`. Preliminary compiler, fixture,
selector and audit-diagnostic failures remain preserved, along with earlier
successful proving runs. Zero-case selections are not counted as validation.

The full goal remains incomplete. Shared engine/accounting/context storage,
bootstrap configuration and request/result ownership, complete worker/coordinator
phase composition, thread stacks and allocator/driver/OS overhead remain open.
Ordinary pool admission still rejects incomplete phase profiles. Host checks of
cache counts 3 and 12 do not qualify those live-cache workloads on GPU; full-size
runs retain one program. Nonempty-child full-size merges, broader workloads,
paired performance comparisons, **24 hours AND 150 completed roots**, multiple
GPUs and AMD/Metal qualification remain required. Verification stays on CPU;
proof parameters, encodings and proving arithmetic activation are unchanged.

### 9.101 Retained OpenCL engine storage (2026-10-10)

The retained OpenCL engine now has a checked **72 MiB host allowance**:
**8 MiB metadata plus 64 MiB mapped staging**. Its ownership census includes
the inline engine and initialization lock, shared accounting and job-lease
Arc allocations, selector string capacities, timing-event backing, and
staging/workspace container capacities. Shared allocations are counted once;
GPU payload storage retains its separate managed-device accounting.

Selector backing is limited to **256 bytes per selector**, container backing
to **four slots**, and the timing vector to **65,536 events**. Timing storage
uses fallible exact reservation and retains its capacity after draining. The
metadata envelope also covers old/new timing backing during reallocation.
Mapped staging must exactly match the configured byte count. Mappings that
own unmap wait lists or have already been unmapped fail the census. Admission
runs before publishing the initialized engine and at drain; new workspace
containers are checked before publication.

Rust and Python witness reservations add **75,497,472 bytes**, independently
of live-cache count. Batch admission retains its existing conservative
summation. Historical descriptors must regenerate their reservation. The
worker, quotient and witness regression fixtures now include the same engine
component; physical service limits remain unchanged.

| Assignment | Witness host reservation | Combined additional host reservation |
| --- | ---: | ---: |
| Omitted/zero PCS bound | 2,209,782,288 | 2,514,266,640 |
| Explicit device PCS bound | 1,941,346,832 | 2,245,831,184 |

The GPU storage regression measures **2,101,296 metadata bytes** and
**32,768 mapped bytes**, checks exact and one-byte-short admission, rejects
excess spare capacity, and confirms unchanged GPU allocation/upload counters.
Its synthetic timing intervals test storage capacity, not GPU performance.
The static-library full-size workers report **3,424 metadata bytes** and
**67,108,864 mapped bytes**. Opaque driver storage, initialization scratch
and transient per-job owners are separate unfinished phases; this logical
census is not an RSS bound.

Final validation passes **111 native cases**, **61 Python tests**, and all
four CPU compatibility compile configurations. Four fresh full-size proofs
record all **16 proving arithmetic stages on OpenCL**. Independent CPU
verification happens after worker exit; all four altered statements are
rejected. Registry identities and arithmetic operation counts match §9.100.
Historical/device assignments have cold/warm times of **67.7518 / 16.4767**
and **68.1666 / 17.5337 seconds**. These are correctness qualification runs,
not paired throughput comparisons.

Worker memory peaks are **1,061,007,360 / 1,097,637,888 bytes**, with
**171 / 174 telemetry samples**, zero swap and no sampled OOM events.
Managed GPU peaks are **7,467,247,040 bytes** for both assignments; idle
storage is **2,022,919,936 bytes**, and shutdown storage is zero. Cleanup
finds no running Lattica services or held GPU leases and **78 empty parent
slices**. Worker RSS, aggregate host, managed GPU and per-allocation limits
remain **3 GiB / 4 GiB / 7 GiB / 1 GiB**.

[`gpu-engine-retained-storage-2026-10-10.json`](evidence/gpu-engine-retained-storage-2026-10-10.json)
pins **499 source files**, **455 artifacts** and **26 worktree source
archives**. Its audit reverifies **1,044 dependency files across 26 packages**
and **113 Rust library files**, including the OpenCL ownership derivation.
Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-engine-retained-storage-20261010`.
Final builds are `research-build-04` and `staticlib-03`; `qualify-04.py` runs
`run-03` and `run-04`. Preliminary compiler, sandbox, fixture-budget and
audit-matcher failures remain preserved and are excluded from passing totals.

The census is qualified for **OpenCL**. Metal's additional container, queue
and Arc ownership remains unqualified. Initialization/per-job engine owners,
bootstrap configuration's separate registry, request/result storage,
allocator/driver/OS overhead, stacks, and complete worker/coordinator phase
composition remain open. Ordinary pool admission still rejects incomplete
phase profiles. Full-size runs retain one program; larger live-cache sets,
nonempty-child merges, broader workloads, paired performance comparisons,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal qualification
remain required. Verification stays on CPU; proof formats and proving
arithmetic activation are unchanged.

### 9.102 Process configuration ownership and fixed records (2026-10-10)

The trusted typed-process bootstrap now consumes `Config` into its typed
registry and a **248-byte descriptor with no owned heap storage**. The child
moves the registry into `TypedWorker` and its typed session, removing the
additional bootstrap clone identified in §9.100. `ProcessWorker::prepare`
discards its consumed registry after deriving the descriptor; the coordinator
no longer retains that unused registry through the worker lifetime.

Configuration and session wire records now use fixed **248-byte / 312-byte
arrays**. Their `LTTYIPC1` magic, digest order, little-endian resource/cache
words and 64-byte reservation suffix are unchanged. Context rebinding uses
the retained descriptor without cloning or rehashing the registry. Only the
policy digest changes; existing acknowledgement, idle-state, reservation
and failure behavior remain in place. The child's 36-byte ready record and
four decoded reservation words also use fixed arrays.

The **12-case native process lifecycle suite passes**. The new regression
checks that registry cap backing pointers survive ownership transfer, that
the descriptor needs no drop, and that the v1 wire fields retain their exact
positions and values. The existing context round trip additionally confirms
that rebinding preserves every byte outside the policy digest. Existing
startup, dispatch, shutdown, stale identity and reservation cases pass.
Three direct child fixtures remain ignored in the outer suite and are not
counted as standalone passing cases.

All **six compile configurations** pass: the four CPU compatibility variants
and both standard/wide GPU variants. Native work ran serially, offline, with
3 GiB memory, zero swap, four-thread/400% CPU limits and a 180-second service
limit; test compilation used two code-generation units. Cleanup reports
zero running Lattica services, zero held GPU leases and 78 empty parent slices.

[`gpu-process-config-ownership-2026-10-10.json`](evidence/gpu-process-config-ownership-2026-10-10.json)
pins **499 source files**, **39 artifacts**, seven source archives and the
CPU process-test executable, and reverifies the preceding checkpoint's
455 artifact hashes. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-process-config-ownership-20261010`.
This checkpoint changes only the process implementation and its tests.
There are **no new GPU runtime or performance measurements**: §9.101's four
full-size GPU proofs precede this ownership refinement. Proving arithmetic,
proof formats and resource reservations are unchanged.

This removes the process-owned registry duplicates and growable identity
records; it does not complete a worker lifetime profile. Caller-held registry
or `Config` copies, initial frame receive storage, dynamic context/request/
result packets, queues, engine initialization/per-job owners, opaque driver
storage, allocator/OS costs and stacks still need complete phase composition.
Ordinary pool admission continues to reject incomplete profiles. Broader
workloads, nonempty-child full-size merges, paired comparisons, **24 hours AND
150 completed roots**, multiple GPUs and AMD/Metal qualification remain open.

### 9.103 Worker protocol storage and admission (2026-10-10)

Typed workers now reserve a separate **8 MiB protocol allowance** before
assigning RAM to the typed session and active prover. Process configuration
checks this floor before launch, and cache reconfiguration preserves it.
Python workload admission adds the same component for both GPU-witness and
hybrid profiles. Witness reservations and managed-device geometry are
unchanged; this component is added once to each worker's host plan.

The envelope covers simultaneous input-frame/result backing and bounded
protocol metadata. Maximum frame/result capacities are **4,260,028 /
2,097,408 bytes**. A **128 KiB metadata allowance** covers fixed identities,
borrowed request descriptors, old/new policy context overlap, context codec
backing and bounded launch controls. The inline typed session is counted
conservatively here as well as in its separate session allowance. Proof
object heaps, caller-owned backing and opaque runtime/driver storage retain
separate accounting obligations.

Policy contexts now use **64 fixed inline slots** and occupy **3,624 bytes**
with no retained heap owner. Construction discards incoming vector spare
capacity before publishing the context. Encoding reserves exactly its wire
length, up to **2,924 bytes**; empty encoding remains 44 bytes. Binding,
policy validation and wire bytes are unchanged. The full-capacity test starts
with an oversized source vector, round-trips all 64 policies and verifies
that copying a context cannot retain a heap allocation.

The protocol census reports **41,780 metadata bytes** in the CPU build and
**47,924** in both GPU layouts. Maximum computed overlap is **6,399,216 /
6,405,360 bytes**, within the 8 MiB allowance. Tests cover exact and
one-byte-short admission, excessive buffer capacities and the boundary that
must leave positive prover memory after protocol/session reservations.
These are ownership bounds, not RSS measurements.

| Assignment | Witness host reservation | Combined additional host reservation |
| --- | ---: | ---: |
| Omitted/zero PCS bound | 2,209,782,288 | 2,522,655,248 |
| Explicit device PCS bound | 1,941,346,832 | 2,254,219,792 |

Combined additional host storage increases by **8,388,608 bytes** relative
to §9.101. Physical limits remain **3 GiB worker / 4 GiB aggregate host /
7 GiB managed GPU / 1 GiB per GPU allocation**. Shared CPU fixtures now
include the protocol allowance; the Python exact-fit fixture leaves that
allowance available before testing additional FRI/cache reservations.

Validation passes **129 native cases** (66 research, 44 standard GPU host,
19 CPU lifecycle/policy), **62 Python tests** and all four CPU compatibility
compile configurations. Four fresh full-size proofs execute all **16 proving
arithmetic stages on OpenCL**, pass independent CPU verification after
worker exit and reject four altered statements. Registry identities and
arithmetic operation counts match §9.101. Historical/device-PCS assignments
have cold/warm times of **67.0832 / 16.3150** and **67.1540 / 16.3056 seconds**;
these are correctness qualification runs, not paired throughput comparisons.

Worker memory peaks are **1,098,801,152 / 1,098,452,992 bytes**, with **169
telemetry samples each**, zero swap and no sampled OOM events. Managed GPU
peaks are **7,467,247,040 bytes**, idle storage is **2,022,919,936 bytes**, and
shutdown storage is zero. Cleanup finds zero running Lattica services, zero
held GPU leases and **81 empty parent slices**.

[`gpu-worker-protocol-storage-2026-10-10.json`](evidence/gpu-worker-protocol-storage-2026-10-10.json)
pins **500 source files**, **294 artifacts** and **22 source archives**.
Its audit reverifies 1,044 dependency files across 26 packages and 113 Rust
library files. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-worker-protocol-storage-20261010`.
The early CPU lifecycle run uses the final Rust sources; only the Python
exact-fit fixture changed afterwards. Its initial failure, the source
revisions and the passing rerun remain preserved.

This advances worker protocol admission without completing the worker/pool
lifetime plan. Coordinator pending assignments/results and queues,
caller-owned construction storage, engine initialization/per-job owners,
allocator/driver/OS costs and stacks still need complete phase composition.
Ordinary pool admission continues to reject incomplete profiles. Broader
workloads and live-cache sets, nonempty-child full-size merges, paired
performance comparisons, **24 hours AND 150 completed roots**, multiple
GPUs and AMD/Metal qualification remain required. Verification stays on CPU;
proof formats, parameters and proving arithmetic activation are unchanged.


### 9.104 Coordinator job storage admission (2026-10-10)

Each active typed coordinator job now requires a **337 MiB** host component
(**353,370,112 bytes**) before cached-worker construction, process launch or
request encoding. The shared floor lives in `execution/worker_budget.rs`, so
assignment validation does not depend on Linux IPC or the `stream` feature.

| Component | Allowance |
| --- | ---: |
| Assignment, transport and publication storage | 16 MiB |
| Bounded canonical proof decoding | 64 MiB |
| Independent registered CPU verifier | 257 MiB |

The verifier component already includes its owned proof. Adding the complete
decoding quota alongside it deliberately counts that proof twice. This is a
conservative component reservation, not a complete coordinator RSS bound; the
registered-verifier lifecycle remains qualified for release x86_64.

The request path checks actual exported `Assignment` and `Job` vector capacities,
including spare capacity and retained shared proof backing, before packet
revalidation/encoding. Its **1 MiB metadata limit** covers job clones and bounded
request/result controls; the structural fixture reports **69,644 bytes**. Two
maximum proof inputs, request/result frames, publication copies and Arc conversion
fit within the packet allowance. Launch and dispatch can briefly retain two
request copies; the phase calculation includes the larger of that second request
and publication storage. Maximum computed overlap is **15,860,000 bytes**, below
16 MiB. Tests reject oversized capacities, arithmetic overflow and one-byte-short
admission while retaining the existing exact wire layout.

`VerifiedNode::verify_typed` now uses the same bounded canonical decoder as typed
worker inputs. Its 64 MiB quota is checked before proof-vector allocation and
includes canonical re-encoding. Successful proof bytes and verifier behavior stay
unchanged. The DAG already retained a nonterminal job reservation after worker
stop and through independent CPU verification. That lifecycle is preserved and
asserted in the process tests; the misleading reconciliation comment is corrected.
Accepted outputs subsequently belong to the separate global DAG/store lifetime.

Automatic Python allocation reserves enough coordinator RAM for every worker
before assigning worker RAM, keeping the total fleet cap unchanged. For example,
two 337 MiB job components require a coordinator allocation of at least 768 MiB
under the existing 256 MiB rounding policy. Explicit pool policy retains its
existing rounding; an insufficient resulting reservation is rejected. The shared
runner splits an already-admitted physical coordinator cap without increasing it.
Rust and Python agree on the same per-job floor. Ordinary pool admission continues
to reject incomplete versioned phase profiles.

Final validation passes **654 native cases** (216 CPU execution, 220 research GPU,
218 standard GPU host), **132 Python tests** and all four CPU compatibility
configurations. Four fresh full-size proofs execute all **16 proving arithmetic
stages on OpenCL**, pass independent CPU verification after worker exit and reject
four altered statements. Registry identities and operation counts match §9.103.
Historical/device-PCS cold/warm times are **67.2150 / 16.3170** and
**67.8157 / 18.3652 seconds**. These runs qualify correctness and admission; they
are not paired throughput comparisons.

Worker memory peaks are **1,441,607,680 / 1,098,379,264 bytes**, with **170 / 175**
telemetry samples, zero swap and no sampled OOM events. Managed GPU memory peaks
at **7,467,247,040 bytes**, retains **2,022,919,936 bytes** while idle and returns
to zero at shutdown. Cleanup finds zero running Lattica services, zero held GPU
leases and **83 empty parent slices**. Worker and aggregate host caps remain
3 GiB and 4 GiB; the existing 1 GiB coordinator assignment exceeds the new floor.

Evidence:
[`gpu-coordinator-job-storage-2026-10-10.json`](evidence/gpu-coordinator-job-storage-2026-10-10.json)
pins **502 source files**, an additional **139-script Python snapshot**, **416
artifacts** and **28 source archives**. Its audit also reverifies 1,044 dependency
files across 26 packages and 113 Rust library files. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-coordinator-job-storage-20261010`.

Preserved preliminary runs identify two stale native-bootstrap budget fixtures,
two CPU-only process fixtures that were incorrectly available in GPU builds, and
a no-`stream` dependency error in the initial budget-parser hook. The final
fixtures include all existing worker allowances, the CPU-only cases remain tested
in CPU builds, and the shared budget helper is independent of the local runtime.
Earlier successful proofs and all unsuccessful runs remain intact; the four
final proofs use the final source snapshot.

This completes one coordinator component, not the full worker/pool lifetime plan.
Shared DAG/store/cache state, durable snapshots, persistent supervisors, queues,
caller construction/clones, remaining engine initialization/per-job owners,
allocator/driver/OS costs and stacks still need complete phase composition. More
queued or simultaneously verified jobs must reserve their own components.
Nonempty-child full-size merges, broader workloads and live-cache sets, paired
performance comparisons, **24 hours AND 150 completed roots**, multiple GPUs and
AMD/Metal qualification remain required. Verification stays on CPU; proof formats,
parameters and proving arithmetic activation are unchanged.


### 9.105 Bounded coordinator persistence buffers (2026-10-10)

Coordinator persistence now checks the configured snapshot limit before allocating
payload backing. A counting/validation pass measures the unchanged encoding, then
a second pass writes one exact-capacity buffer. Workspace snapshots no longer
materialize a separate base snapshot. Durable creation, ordinary persistence and
recovery publication all use `JournalLimits.snapshot_bytes`, rather than first
encoding against the larger hard maximum and checking the configured limit later.

Journal checksums now stream the same domain, generation, length and little-endian
payload words through the existing exact-framing hash implementation. The
payload-sized `Vec<u64>` is removed; fixed permutation/control storage remains
separate. Journal frames reserve exactly their payload length plus the unchanged
**52-byte header**. Journal and artifact reads allocate their checked file length,
read exactly that many bytes and use a single stack-byte EOF probe to reject
growth without expanding the buffer. Reopening a journal compacts its payload in
the existing frame allocation, eliminating the additional payload copy.

`JournalLimits::payload_storage_bytes` exposes the snapshot/frame component for
later coordinator-budget composition:

| Configured snapshot limit | Maximum snapshot plus journal-frame backing |
| --- | ---: |
| CLI: 1 MiB | **2,097,204 bytes** |
| Hard maximum: 8 MiB | **16,777,268 bytes** |

These bounds cover payload backing. Snapshot sorting/index vectors, the workspace
owner set, retained graph/store data, paths, verification, queues, allocator/OS
costs and arbitrary caller buffers remain separate. The counting pass adds a
metadata traversal; this checkpoint does not establish a throughput improvement.

A frozen copy of the §9.104 encoder remains a test-only wire oracle. **12 structural
states per suite** cover all four snapshot versions and direct, supervised,
unissued, preparing and authorized bindings, with and without workspaces. Every
accepted snapshot matches the previous bytes, retains exactly its length in
capacity and uses one payload allocation. A one-byte-short limit and invalid
invariants fail before payload allocation. Additional tests cover exact-length
reads, truncation, growth, interrupted EOF probes, independent checksum/frame
parity across generation boundaries and in-place journal reopening.

Final validation passes **663 native cases** (223 CPU execution, 221 research GPU,
219 standard GPU host) and all four CPU compatibility configurations. Four fresh
full-size proofs report all **16 proving arithmetic stages on OpenCL**, pass CPU
verification after worker exit and reject four altered statements. Registry
identities and operation counts match §9.104. Historical/device-PCS cold/warm times
are **67.7548 / 16.7741** and **67.1728 / 16.2860 seconds**; these are correctness
qualification runs, not paired throughput comparisons.

Worker memory peaks are **1,117,605,888 / 1,107,243,008 bytes**, with **171 / 169**
telemetry samples, zero swap and no sampled OOM events. Managed GPU memory peaks
at **7,467,247,040 bytes**, retains **2,022,919,936 bytes** while idle and returns
to zero at shutdown. Cleanup finds zero running Lattica services, zero held GPU
leases and **84 empty parent slices**. Physical assignments, worker admission and
the 337 MiB per-job coordinator floor are unchanged.

Evidence:
[`gpu-coordinator-journal-storage-2026-10-10.json`](evidence/gpu-coordinator-journal-storage-2026-10-10.json)
pins **506 source files**, **187 artifacts** and **11 source archives**. Its audit
also reverifies 1,044 dependency files across 26 packages and 113 Rust library
files. The unchanged 139-script Python snapshot and its 132 passing tests remain
linked to §9.104; those Python tests were not rerun here. Artifacts are in
`lattica-prover-p3/benchmark-results/gpu-coordinator-journal-storage-20261010`.
The initial passing compile predates only the payload-peak API and its test;
all final suites and proofs include them.

This completes the persistence payload component, not aggregate coordinator or
worker/pool admission. Shared DAG/store/cache metadata, durable recovery owners,
supervisors, queues, remaining engine initialization/per-job owners and opaque
runtime costs still require complete phase composition. Ordinary pool admission
continues rejecting incomplete versioned profiles. Broader workloads/live-cache
sets, nonempty-child full-size merges, paired performance comparisons, **24 hours
AND 150 completed roots**, multiple GPUs and AMD/Metal qualification remain
required. Verification and local-control hashing stay on CPU; proof parameters,
proof and journal formats, and proving arithmetic activation are unchanged.


### 9.106 Bounded retained coordinator state (2026-10-10)

The graph now retains wallet-input handles in an exact-capacity vector instead
of allowing an in-place `collect` to carry arbitrary caller capacity into the
DAG. Attempt manifests and input-handle vectors also allocate their exact input
counts, at most two. Payload Arcs share the record's backing. Release timing is
unchanged: an attempt retains its inputs until terminal, physically stopped and
outside verification; pruning remains fenced while any attempt is unreleased.

`Limits::retained_storage` exposes a conservative bound for retained graph
ownership. `Dag::retained_storage` counts actual Vec capacities, record payloads,
Arc headers/padding and conservative BTree backing, then checks the configured
bound. The bound includes the inline DAG, jobs, candidate memberships and
closures, attempt history and workspaces. Component admission accepts the exact
bound and rejects a cap one byte smaller without changing any physical cap.

The collection model uses the audited Rust 1.96 BTree implementation: 11 key/value
slots and 12 internal edges, with each field rounded for the largest alignment.
It conservatively charges an internal node per entry plus an empty/insertion
root. These are requested allocation-layout bounds, not allocator or RSS
measurements. They deliberately overestimate unused slots, especially at hard
limits; toolchain changes require requalification.

| Graph limits | Retained metadata bound | Retained artifact limit | Graph component total |
| --- | ---: | ---: | ---: |
| CLI: 256 jobs, 8 candidates, 256 attempts | 4,507,768 B | 268,435,456 B | **272,943,224 B** |
| Hard: 4,096 jobs, 256 candidates, 16,384 attempts | 716,877,944 B | 536,870,912 B | **1,253,748,856 B** |

Artifact inventories now own exact-length canonical names. Canonical artifact
name generation allocates exactly 72 bytes and preserves the previous spelling.
Refresh tracks unexpected hard links in a scalar instead of a separate Vec;
pending-name sorting is in place. `StoreLimits::inventory_storage` accounts for
old/new inventories coexisting with pruning's keep-map and removal list.
`ArtifactStore::inventory_storage_bytes` checks retained String/Vec capacities.

| Inventory entry limit | One retained inventory | Refresh/prune component peak |
| --- | ---: | ---: |
| CLI: 512 | 505,224 B | **1,531,656 B** |
| Hard: 16,384 | 16,139,144 B | **48,925,448 B** |

These components do **not** complete coordinator admission. Graph transition,
snapshot and recovery indexes, durable Weak-owner maps, paths, file/directory
iterator storage, launch/supervisor/fleet queues, external caller owners and
allocator/OS costs remain separate. An external assignment may keep an Arc alive
after the DAG releases its own handle; that caller lifetime needs its own
reservation. The existing 337 MiB per-job floor and physical worker/coordinator
assignments are unchanged. Ordinary pool admission still rejects incomplete
versioned phase profiles.

Validation passes **684 native cases**: 230 CPU execution, 226 standard GPU host,
and 228 research cases including the two full-size qualification fixtures. All
four CPU compatibility configurations pass. New structural cases cover excessive
caller capacity, a 127-node graph with eight candidate closures, 256 retries,
verification/output ownership, pruning, full published/pending inventories,
repeated retention identities and one-byte-short component admission. The
unchanged snapshot encoder still passes its 12 frozen-reference wire states per
suite. An independent standalone System-allocator observer passes **36 cases**
covering 48,868 allocations, insertion/deletion, cloning, empty retained roots,
16,384 entries and over-aligned keys. All observed backing stays within the
collection bounds and final live backing is zero.

Four fresh full-size proofs on the authorized desktop RTX 5080 report all **16
proving arithmetic stages on OpenCL**, pass independent CPU verification after
worker exit and reject four altered statements. Historical/device-PCS cold/warm
times are **67.0744 / 16.4150** and **67.0751 / 16.3192 seconds**. Worker peaks are
**1,442,418,688 / 1,097,715,712 bytes**, with 169 samples each, zero swap and no
sampled OOM events. Managed GPU peak is **7,467,247,040 bytes**, idle backing is
2,022,919,936 bytes and shutdown backing is zero. Cleanup finds no services or
GPU leases and 85 empty parent slices. These are correctness qualifications;
this checkpoint makes no throughput-improvement claim.

The [evidence](evidence/gpu-coordinator-retained-storage-2026-10-10.json) pins
**510 source files**, **194 artifacts** and **11 source archives** under
`lattica-prover-p3/benchmark-results/gpu-coordinator-retained-storage-20261010`.
The audit rechecks 26 dependency packages/1,044 files and 113 Rust library files,
including the BTree source. The 139 unchanged Python sources and their 132 tests
remain inherited from §9.104, not rerun. An initial test compile failed on a new
helper name and was corrected before all successful suites and GPU runs. A
controller import-path collision and an audit variable typo were resolved in
new invocations/versions; original controllers and executed artifacts remain
preserved. Use `python3 -P` for this checkpoint's control scripts.

The next composition work must include graph transitions/recovery, durable
owners, prepared-job copies and fleet queues before combining the shared
coordinator component with active-job reservations. Remaining worker phase and
runtime accounting, broader workloads/live-cache sets, nonempty-child full-size
merges, paired throughput comparisons, **24 hours AND 150 completed roots**,
multiple GPUs and AMD/Metal qualification still apply. Verification and
local-control hashing remain on CPU; proof parameters, formats, journal bytes,
registry identities and proving activation are unchanged.


### 9.107 Snapshot and recovery metadata composition (2026-10-10)

Snapshot encoding now builds one exact-capacity sorted job index and reuses it
for both the count and write passes. Sorting is in place. Attempts and launch
bindings stream directly from their maps, removing two temporary lists.
Workspace-owner validation uses one exact-capacity sorted vector and rejects
duplicate owners before allocating a payload. Graph cardinalities are checked
before building the index. The four snapshot versions and their bytes remain
unchanged.

Recovery now allocates artifact descriptors, dependency lists, workspace
conversion, expected manifests and wallet ticket/handle vectors at their exact
counts. Explicit BTree insertion avoids the temporary sorted vectors used by
bulk collection. Recovery checks a capacity census before loading proofs, then
drops its identity/ownership validation indexes before proof decoding and
independent CPU verification begin. Candidate-closure overflow is rejected as
soon as encountered.

`Limits::snapshot_storage` bounds encoding and recovery parse/validation
metadata under the pinned Rust collection layouts. `JournalLimits::graph_storage`
combines these with the retained graph component from §9.106 and the journal
payload buffers from §9.105. Recovery's returned candidate/attempt/workspace
vectors remain live while resume encodes the new snapshot, so the combined
bound **adds both metadata phases**. Taking only their maximum would omit that
overlap. Component admission rejects a limit one byte below the combined bound;
no physical memory cap is raised.

| Configuration | Encoding metadata | Recovery metadata | Combined graph persistence/recovery component |
| --- | ---: | ---: | ---: |
| CLI limits, 1 MiB snapshot | 6,192 B | 929,616 B | **275,976,236 B** |
| Hard limits, 8 MiB snapshot | 294,960 B | 31,343,888 B | **1,302,164,972 B** |

The totals include the retained graph/proof quota and the snapshot/frame
payload component. They conservatively charge parse/validation owners together,
including owners whose actual lifetimes are disjoint. They are requested
backing bounds, not measured RSS or complete coordinator admission. Durable
Weak-owner maps and handles, store inventory and reads, paths/directory
iterators, ordinary DAG transition/job-construction scratch, supervisors,
prepared-job copies, fleet queues, callers, proof decoding/verification and
allocator/OS costs still need their own reservations and phase composition.

The new structural recovery stress case uses a full **64-input, 127-node**
graph, **255 rejected but not physically stopped attempts**, and one retained
workspace. Their output reservations nearly fill the hard artifact quota,
without allocating those proof payloads or starting workers. Recovery preserves
all unresolved obligations and reconstructs the graph through private test-only
tickets. Its parse/validation census is **350,680 bytes**, below the configured
929,616-byte metadata bound. This test is ownership/serialization qualification,
not a cryptographic proof test.

Final validation passes **694 native cases**: 234 CPU execution, 230 research
GPU-feature host cases and 230 standard GPU-feature host cases, plus all four
CPU compatibility configurations. **13 wire-parity cases per suite** cover the
previous 12 structural states and the recovered graph against the unchanged
frozen encoder. Additional checks cover exact decoder capacities, truncation,
invalid cardinalities, duplicate owners, resume-phase composition and
one-byte-short component admission. Native services use the established serial,
offline, 3 GiB/no-swap/four-CPU/180-second limits. Cleanup finds no services or GPU
leases and 85 empty parent slices.

The [evidence](evidence/gpu-coordinator-snapshot-metadata-2026-10-10.json) pins
**512 source files**, **48 artifacts** and **nine source archives** in
`lattica-prover-p3/benchmark-results/gpu-coordinator-snapshot-metadata-20261010`.
Its audit rechecks 26 dependency packages/1,044 files and 113 Rust library files.
An initial new test used a four-input fixture while expecting 64; it was replaced
with the full stress fixture. The next suite passed before the final removal of
BTree bulk-collection scratch. Those preliminary artifacts are preserved; all
final suites use the final sources.

No GPU proofs or Python application tests were rerun here. Proving sources are
unchanged, and the four fresh desktop RTX 5080 proofs from §9.106 remain linked
as inherited evidence, along with its 36 allocator cases. The 139 unchanged
Python sources and 132 tests remain inherited from §9.104. This checkpoint makes
no throughput-improvement claim and does not broaden GPU qualification.

The remaining coordinator work includes durable/store/supervisor owners,
ordinary transition scratch, prepared jobs and pool queues before physical
admission can combine the shared component with the existing **337 MiB per-job**
minimum. Physical caps are unchanged and ordinary admission continues rejecting
incomplete phase profiles. Full worker/runtime accounting, broader workloads,
nonempty-child full-size merges, paired throughput comparisons, **24 hours AND
150 completed roots**, multiple GPUs and AMD/Metal qualification remain open.
Verification stays on CPU; proof formats, parameters, registry identities and
proving activation are unchanged.

### 9.108 Durable shared-state storage composition (2026-10-10)

`JournalLimits::durable_storage` and `DurableDag::storage_plan` now compose the
graph persistence/recovery component with ordinary DAG transition indexes,
artifact-store inventory/read/path work, and durable verification/workspace
guard metadata. Component admission checks the requested allowance without
increasing any physical cap. Complete physical coordinator admission remains
closed pending the other owners and runtime costs.

Guard accounting includes both Weak maps and their Arc allocations. Dropping
the last strong guard does not free Arc backing while the map retains a Weak;
the census continues charging that backing until the existing rejection or
workspace-drain path removes it. Tests exercise live and expired owners and
confirm that reservations remain fenced until the existing release conditions
are satisfied. No worker-exit or workspace release timing changes.

Readiness sorting is now in place and preserves the previous total ordering.
Ready-job, pending-stop and retained-artifact results have exact-capacity
backing. Pruning uses a BTree set for membership and an exact-capacity traversal
stack. A new structural test completes all 127 jobs in a full 64-input tree,
compares every readiness list to the previous policy, checks query capacities,
and cancels/prunes the graph while checking retained storage.

Store accounting adds one returned inventory list and one read buffer, bounded
by the smaller of the store quota and maximum proof size. Project-owned path
and name work has a 128 KiB allowance for each store/journal component. Input
paths and names are length-checked before constructing working paths;
descriptor anchors retain exactly 32 bytes, and pending journal names retain
their exact 41-byte capacity. Opaque directory/libc allocations, kernel state,
allocator overhead and additional caller-retained buffers remain separate.

The production release probe uses one codegen unit and initializes no GPU.
Its layouts match the test builds, which use two codegen units:

| Shared component | CLI limits | Hard limits |
| --- | ---: | ---: |
| Graph persistence/recovery (§9.107) | 275,976,236 B | 1,302,164,972 B |
| Transition indexes and query results | 482,712 B | 10,339,096 B |
| Store inventory, handle, query, read and path work | 3,780,552 B | 51,809,224 B |
| Durable guards, handles and retained journal names | 448,576 B | 28,446,784 B |
| Journal path work | 131,072 B | 131,072 B |
| **Durable component total** | **280,819,148 B** | **1,392,891,148 B** |

These are conservative requested-backing bounds under the pinned Rust 1.96
layouts, not measured RSS. The independent System-allocator observer passes
**36 BTree cases / 48,868 allocations** and **four Arc cases**, including
over-alignment and allocation survival after the last strong reference drops.
Both observers finish with zero live bytes. Arc's maximum observed allocation
is 1,040 bytes; the BTree maximum requested peak remains 58,140,896 bytes.

Final qualification passes **709 native cases**: 239 CPU execution cases,
235 research GPU-feature host cases and 235 standard GPU-feature host cases,
plus all four CPU compatibility builds. All three suites retain **13 snapshot
wire-parity cases**. Exact/one-byte-short component admission, pending-name
capacity and production/test layout parity pass. All native services run
serially and offline with the established 3 GiB/no-swap/four-CPU/180-second
limits. Cleanup finds no running services or GPU leases and 85 empty parent
slices.

The [evidence](evidence/gpu-coordinator-durable-storage-2026-10-10.json) pins
**516 source files**, **52 artifacts** and **eight source archives** in
`lattica-prover-p3/benchmark-results/gpu-coordinator-durable-storage-20261010`.
The audit rechecks 26 dependency packages/1,044 files, 113 Rust library files,
the parent artifacts and 139 unchanged Python source hashes. No native
preliminary revision failed. The four desktop RTX 5080 proofs from §9.106 and
132 Python cases from §9.104 are inherited evidence; neither was rerun here.
There is no new GPU-proof or throughput-improvement claim.

Next, compose job/assignment construction, registries and caller lifetimes,
supervisors, prepared-job copies, pool queues and runtime costs with this
shared component and the **337 MiB per-job** minimum. Ordinary admission still
rejects incomplete versioned phase profiles. Full worker-phase composition,
broader workloads/live-cache sets, nonempty-child full-size merges, paired
throughput comparisons, **24 hours AND 150 completed roots**, multiple GPUs
and AMD/Metal qualification remain open. Verification stays on CPU; proving
arithmetic, proof parameters/formats, registry identities and activation are
unchanged.

### 9.109 Pool and scheduler storage composition (2026-10-10)

`PoolCoordinator::storage_plan` now combines the durable shared-state component
with pool-owned job copies, candidate membership, worker slots, failure messages,
transition indexes and scheduler history/scratch. The existing pool limits remain
16 workers, eight candidates, 4,096 jobs and 64 retained failure messages. These
limits bound metadata backing; concrete endpoint and registry heaps, caller
selections/results, per-job verification and runtime costs remain separate.
`PoolStorage::admit` checks this component only and does not raise physical caps
or admit an incomplete proving phase profile.

Pool submission checks the job count before cloning selection jobs. Incoming
jobs, candidate IDs, slots, idle-worker lists and accepted-result lists use
explicit capacities. Readiness filtering retains its existing vector in place,
and deadline indexes use explicit BTree insertion instead of bulk collection.
Durable accounting already charges readiness and stop-list backing. Returned
accepted/failure lists become caller-owned and need their own lifetime allowance.

Failure formatting now writes directly into an 8,192-byte buffer, retaining the
same first 2,048 Unicode characters as before. This removes the unbounded
intermediate `error.to_string()` allocation. Tests cover fragmented formatting,
four-byte characters, mixed text and short messages. Allocations inside an
endpoint's own custom `Display` implementation remain endpoint/runtime costs.

Scheduler p95 estimates sort a fixed 64-sample stack array. Dependency traversal
uses in-place sorting with an explicit JobId tie-break, preserving the previous
stable level ordering. The selection bound charges parent/dependency lists,
downstream costs and job order together; each job is checked to have at most
two dependencies. History backing includes deque capacity retained after
samples/classes are removed.

The production probe and all three host test configurations agree:

| Shared component | CLI limits | Hard limits |
| --- | ---: | ---: |
| Durable state (§9.108) | 280,819,148 B | 1,392,891,148 B |
| Pool retained metadata | 13,551,368 B | 13,551,368 B |
| Pool transition metadata | 2,359,600 B | 2,359,600 B |
| Scheduler retained history | 9,110,656 B | 9,110,656 B |
| Scheduler selection work | 7,014,232 B | 7,014,232 B |
| **Combined shared component** | **312,855,004 B** | **1,424,927,004 B** |

These are conservative requested-backing bounds, not RSS or complete physical
coordinator admission. Pool/scheduler limits contribute **32,035,856 bytes**
independently of the durable graph profile. The new history stress test fills
all **4,096 classes with 64 samples each**, checks p95 results, evicts a class,
then forgets every worker. Its census is 6,784,128 bytes when full and 230,528
bytes after draining, including retained deque capacity, below the 9,110,656-byte
history component. The pool lifecycle test checks submission, dispatch, failed
transport cancellation, failure collection and retirement; stop/retry fencing
is unchanged.

Final qualification passes **718 native cases**: 242 CPU execution cases,
238 research GPU-feature host cases and 238 standard GPU-feature host cases.
Four CPU compatibility builds and 13 snapshot wire-parity cases per suite pass.
The initial new test had a fixture-call compilation error, then an incorrect
expected fixture message; both revisions and their results are preserved.
All successful runtime suites use the final library sources. A subsequent
example-only change added the missing `stream` feature gate and updated its help
text; a production rerun plus no-stream/default example checks qualify that
change without repeating unchanged library suites.

All native services remain serial, offline and bounded at 3 GiB RAM, no swap,
four CPUs and 180 seconds. Tests use two codegen units; production probes use
one. Final cleanup finds no running services or GPU leases and 85 empty parent
slices. The [evidence](evidence/gpu-pool-bookkeeping-storage-2026-10-10.json)
pins **521 source files**, **71 artifacts** and **13 source archives** in
`lattica-prover-p3/benchmark-results/gpu-pool-bookkeeping-storage-20261010`.
The audit verifies 26 dependency packages/1,044 files and 124 Rust library
files, including 11 newly pinned VecDeque files, and rechecks inherited evidence.

No GPU proofs or Python application tests were rerun. The four desktop RTX 5080
proofs from §9.106, 132 Python cases from §9.104, and independent BTree/Arc probes
from §9.108 remain explicitly inherited. This checkpoint makes no throughput
claim. Next, account for registry/concrete endpoint heaps, caller selection and
result lifetimes, launch/process supervisors and runtime costs, then integrate
the complete shared allowance with per-job reservations and the physical
coordinator assignment. The **337 MiB per-job** floor and physical caps remain
unchanged; ordinary admission still rejects incomplete phase profiles.

Full worker-phase composition, broader workloads/live-cache sets, nonempty-child
full-size merges, paired throughput comparisons, **24 hours AND 150 completed
roots**, multiple GPUs and AMD/Metal qualification remain open. Verification
stays on CPU; proving arithmetic, proof parameters/formats, registry identities
and activation are unchanged.

### 9.110 Registry and caller selection storage (2026-10-11)

Shared pool accounting now includes its registry owner using the existing
**64 KiB** registry admission ceiling. `Registry::storage_bytes` exposes the
existing census, including spare cap capacity, and `PoolCoordinator::storage_plan`
checks it before composing the allowance. The audit confirms that registry
identity and verification implementations remain byte-for-byte unchanged;
the registry source changes only expose the existing limit and accessor.

`Selection::storage_plan` adds a separate caller component for one immutable
selection, recursive construction metadata, one public-input conversion and one
entry's admission copies. Retained proof backing is charged once per Arc
allocation within a selection. Equal bytes in independent allocations are
charged separately, while the duplicate handle used by an odd typed pair is
charged once. Independent live selections remain separate caller reservations.

`PublicInput::new` now rejects input vectors with more than **8 MiB of allocated
capacity** before hashing or allocating shared backing. This bounds spare
capacity during ownership transfer; the encoded proof limit remains **2 MiB**.
Conversion allocates the Arc slice while the source Vec still exists, so the
model includes both. Admission builds an exact-capacity list of up to two
independent proof-byte copies. Selection construction, ordering, proof identity
and durable release fencing are unchanged.

The one-selection component has these production/test-consistent bounds:

| Selection owner or phase | Requested backing |
| --- | ---: |
| Retained metadata | 62,608 B |
| Up to 64 proof Arc allocations | 134,218,752 B |
| Construction/census metadata | 7,560 B |
| One input conversion, including source and destination | 10,486,000 B |
| One entry's job and proof admission copies | 4,194,744 B |
| **Selection component total** | **148,969,664 B** |

The shared pool component, including its registry, is **312,920,540 bytes**
under CLI limits and **1,424,992,540 bytes** under hard limits. Adding one
selection component gives **461,890,204 bytes** and **1,573,962,204 bytes**,
respectively. These are conservative requested-backing components, not complete
physical coordinator admission or RSS bounds. Caller input-list backing,
additional selections/results, preparation metadata and temporary registries
remain separate, as do concrete endpoint heaps, process supervisors and runtime
costs.

Tests cover **160 selection shapes** across legacy single-wallet, legacy paired
and typed paired construction. A maximum-size ownership case retains **64
separate 2 MiB buffers**, releases the original caller handles and checks that
admission copies remain independent. Its retained census is **134,267,616
bytes**, below the **134,281,360-byte** retained bound. These tests use private
structural tickets and repeated already-checked byte identities, not new
cryptographic proof-acceptance evidence. Exact/one-byte-over input capacity and
shared-versus-independent Arc allocation checks also pass.

The independent System-allocator observer now covers **seven slice-Arc cases**,
including empty slices, over-alignment, spare source capacity and maximum-size
conversion. The largest conversion requests **10,485,776 bytes** while source
and destination coexist. Weak references retain backing after the last strong
reference drops; final live bytes are zero. All **four sized-Arc** and **36 BTree
cases / 48,868 allocations** are rerun successfully against the expanded helper.

Final qualification passes **727 native cases**: 245 CPU execution cases,
241 research GPU-feature host cases and 241 standard GPU-feature host cases.
Four CPU compatibility builds, three example build configurations, production
layout parity and 13 snapshot wire-parity cases per suite pass. No native
preliminary revision failed. All native work remains serial and offline in
3 GiB/no-swap/four-CPU/180-second services, with two codegen units for tests and
one for production probes. Cleanup finds no running services or GPU leases and
85 empty parent slices.

The [evidence](evidence/gpu-coordinator-caller-storage-2026-10-11.json) pins
**524 source files**, **70 artifacts** and **11 source archives**. Runs started
on October 10 under
`lattica-prover-p3/benchmark-results/gpu-coordinator-caller-storage-20261010`.
The audit rechecks 26 dependency packages/1,044 files, 124 Rust library files,
parent artifacts and 139 unchanged Python source hashes. Four desktop RTX 5080
proofs from §9.106 and 132 Python cases from §9.104 remain explicitly inherited;
neither was rerun here. There is no new throughput claim.

Next, compose concrete endpoint/supervisor owners, preparation and returned-result
lifetimes, and runtime costs with these components, then connect the full shared
allowance to physical coordinator assignments and per-job reservations. Physical
caps and the **337 MiB per-job** floor are unchanged. Ordinary admission still
rejects incomplete phase profiles. Full worker-phase composition, broader
workloads/live-cache sets, nonempty-child full-size merges, paired throughput
comparisons, **24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal
qualification remain open. Verification stays on CPU; proving arithmetic,
proof parameters/formats, registry identities and activation are unchanged.


### 9.111 Local endpoint and launch storage (2026-10-11)

The persistent GPU pool now exposes a storage component for its actual local
endpoint owners: one shared `Arc<Mutex<LaunchStore>>`, each `ProcessWorker`,
owned service identities and policy contexts, and sequential process/OS
observation work. Launch accounting includes both the old inventory and the
replacement inventory, including the extra record inserted before overflow
rejection. Named paths and scanned filenames are checked before joins; owned
identity and service strings are checked by capacity.

Exact worker argv matching now uses a streaming iterator within the existing
16,384-byte read limit. Empty arguments, the required trailing NUL, and exact
argument count remain enforced. Seventy reference-parity cases cover prefix,
mutation and size boundaries. Removing the split vector does not imply that
error handling or the OS observation path performs no allocations.

Production and test layouts agree:

| Local owner or component | Requested backing |
| --- | ---: |
| Persistent process fields and owned identity | 66,888 B |
| Process control work | 65,536 B |
| OS observation control work | 1,048,576 B |
| CLI launch store, 256 records, including refresh/control | 386,808 B |
| Pool launch store, 16,384 records, including refresh/control | 16,127,736 B |
| Local pool component, one worker | **17,312,012 B** |
| Local pool component, 16 workers | **18,362,552 B** |

The local component charges the launch store once and each concrete endpoint
separately. Polling services one endpoint at a time, so its control allowance is
shared. These are conservative requested-backing components, not RSS bounds or
complete physical admission. Shared pool/caller storage from §9.110 remains
separate. Pending task/request/result heaps retain their per-job allowance;
remaining preparation/returned-result owners and opaque runtime costs still
need composition. The independent allocator observer checks the backing of an
Arc containing a Mutex value, not opaque lock/runtime allocations.

Qualification passes **742 regular host cases**: 250 CPU, 246 research
GPU-feature and 246 standard GPU-feature cases. **Two separately enabled
supervised lifecycle cases** also pass, each executing exactly one test against
real owned user services and IPC without GPU proving. Their nested services
have 128 MiB/no-swap/one-CPU/60-second limits with control-group kill and core
dumps disabled. They verify exact process/cgroup quiescence and stop/revocation
fencing; the observed persistent service census is 1,524 bytes.

Four CPU compatibility builds, three example configurations, production layout
parity and 13 snapshot wire-parity states per regular suite pass. The independent
allocator observer passes seven slice-Arc cases, five sized-Arc cases and 36
BTree cases/48,868 allocations, returning to zero live bytes. All outer native
work remains serial and offline in 3 GiB/no-swap/four-CPU/180-second services,
with two codegen units for tests and one for production probes. Cleanup finds
no running services, held GPU leases or populated parent slices (85 checked).
No native preliminary revision failed. The first audit controller rejected its
inherited CLI/hard profile-name assumption; a preserved second version accepts
the launch CLI/pool names and passes all checks.

The [evidence](evidence/gpu-local-endpoint-storage-2026-10-11.json) pins **530
source files**, **79 artifacts** and **13 source archives** in
`lattica-prover-p3/benchmark-results/gpu-local-endpoint-storage-20261011`.
It verifies 26 dependency packages/1,044 files, 124 Rust library files and 139
unchanged Python source hashes. Four desktop RTX 5080 proofs from §9.106 and
132 Python application cases from §9.104 remain inherited; no fresh GPU proof
or throughput measurement was performed.

Next, finish remaining caller/preparation/result/runtime accounting and deduct
shared coordinator storage from physical RAM assignments **before** dividing
per-job reservations. Physical caps and the **337 MiB per-job** minimum are
unchanged. Ordinary admission still rejects incomplete versioned phase
profiles. Full worker-phase composition, broader workloads/live-cache sets,
nonempty-child full-size merges, paired throughput comparisons, **24 hours AND
150 completed roots**, multiple GPUs and AMD/Metal qualification remain open.
Verification stays on CPU; proving arithmetic, proof parameters/formats,
registry identities and activation are unchanged.


### 9.112 Pool result and service report storage (2026-10-11)

`PoolOutputStorage` now describes the ownership transferred to a caller by one
accepted-job batch, one failure drain and one root copy. It includes vector
headers, spare capacity and bounded failure strings. Pool root retrieval checks
the existing proof-size ceiling before allocating its returned copy. Independent
root copies and additional retained batches require separate reservations.

Production/test output layouts agree:

| Returned owner | Requested backing |
| --- | ---: |
| Up to 16 accepted-job records | 920 B |
| One failure drain, up to 64 bounded messages | 528,408 B |
| One root copy, up to 2 MiB | 2,097,176 B |
| **Combined returned-output component** | **2,626,504 B** |

The persistent service now keeps exact-capacity typed report records instead of
accumulating JSON value trees. Successful records are bounded by the selection's
job count (at most 127); failures are bounded by the initial endpoint count
(at most 16). This sequential service does not replace endpoints during a
request. Failure strings transfer into reports without copying, and completion
serialization borrows both those strings and native-host metadata. Job identity
hexadecimal encoding uses fixed stack scratch.

Pool JSON publication now serializes directly into one exact-capacity buffer,
rejecting writes before crossing the existing **128 KiB** output limit. Parsed
JSON values and array order are preserved; object member order is not asserted
byte-for-byte. Publication ordering, proof availability versus native delivery,
and durable release fencing are unchanged.

The private report component, including one returned-output component and one
JSON buffer, is **2,773,000 bytes for one worker** and **2,896,360 bytes for 16
workers**, with 127 possible job records. Report layout values come from the
binary unit tests; only the public output component has a separate production
layout probe. These are requested-backing components, not RSS bounds or complete
physical coordinator admission. Serializer/allocator/runtime stacks and remaining
preparation/input-list/temporary-registry owners remain separate.

Qualification passes **757 fresh native cases**: 252 CPU execution cases,
248 research GPU-feature host cases, 248 standard GPU-feature host cases, and
three report cases in each of those binary configurations. Tests cover maximum
record/message capacities, drained ownership, independent root backing, rejection
without vector growth, unchanged parsed JSON fields, and exact/escaped/incremental
serialization overflow. Synthetic root buffers and accepted records qualify
ownership; they are not new cryptographic proof-acceptance evidence.

Four CPU compatibility builds, three example configurations, production output
layout parity and 13 snapshot wire-parity states per execution suite pass.
All native work remains serial and offline in 3 GiB/no-swap/four-CPU/180-second
services, using two codegen units for tests and one for production probes.
Cleanup finds no running services, held GPU leases or populated parent slices.
No preliminary native revision failed. The unchanged allocation observer and
two supervised lifecycle cases from §9.111 remain explicitly inherited.

The [evidence](evidence/gpu-pool-result-storage-2026-10-11.json) pins **532 source
files** and **14 source archives** in
`lattica-prover-p3/benchmark-results/gpu-pool-result-storage-20261011`. It verifies
the parent artifacts, 26 dependency packages/1,044 files, 124 Rust library files
and 139 unchanged Python source hashes. Four desktop RTX 5080 proofs from §9.106
and 132 Python application cases from §9.104 remain inherited. No fresh GPU
proof or throughput measurement was performed.

Remaining preparation and runtime owners still need composition. Shared storage
must then be deducted from physical coordinator RAM before dividing per-job
reservations; the current assignment still allocates the full cap to jobs.
Physical caps and the **337 MiB per-job** minimum are unchanged, and ordinary
admission still rejects incomplete versioned phase profiles. Full worker-phase
composition, broader workloads/live-cache sets, nonempty-child full-size merges,
paired throughput comparisons, **24 hours AND 150 completed roots**, multiple
GPUs and AMD/Metal qualification remain open. Verification stays on CPU;
proving arithmetic, proof parameters/formats, registry identities and activation
are unchanged.


### 9.113 Preparation input ownership and pool handoff (2026-10-11)

The persistent service now consumes each `Prepared` value during submission.
The returned value contains only candidate ID, expected-state metadata and job
count. Durable submission has already copied the required wallet inputs, so
the caller's selection and temporary registry are dropped before the service
seals or dispatches work. Expected-state metadata is dropped after publication.
The initial preparation is also consumed to extract only its registry, releasing
its unused selection, policies and expected-state metadata before the service loop.

Preparation input/policy lists now use exact checked capacities for one through
64 inputs. The caller input list is dropped once selection construction owns
the proof handles. Registry conversion checks its temporary vector capacity;
cap backing moves into the typed registry without copying. The new
`PreparationStorage` component includes:

| Preparation owner | Requested backing |
| --- | ---: |
| Caller input-list metadata | 12,824 B |
| Caller policy list | 3,608 B |
| One temporary registry allowance | 65,536 B |
| Registry-conversion metadata | 888 B |
| **Combined component** | **82,856 B** |

Production and test layouts agree. Shared proof Arc backing is charged once by
the existing selection component, including the phase before selection
construction. This component does not cover all preparation: body/expected-state
JSON parsing, task-plan metadata, key/input IO and decoding, preparation CPU
verification and opaque runtime costs still need enclosing phase composition.
It is not an RSS bound or complete physical admission.

A new durable ownership test admits three synthetic **64 KiB** wallet buffers,
drops all caller proof owners, and confirms that their strong references expire.
It then drops the Weak observers (which themselves retain backing), seals the
candidate and leases a two-input job. The independent durable input copies still
match their artifact identities and original bytes. Cancellation retains the
reservation until the simulated worker stop acknowledgement. This is structural
ownership/fencing evidence, not a new cryptographic proof or live GPU-service
handoff test. The consuming boundary is compiled in all three binary configurations.

Qualification passes **832 fresh native cases**: 254 CPU execution cases,
250 research GPU-feature host cases, 250 standard GPU-feature host cases, and
26 coordinator-driver cases in each configuration. The driver suites include
the existing report checks plus exact-capacity factories for all 64 input counts
and rejection of invalid counts before allocation. Four CPU compatibility builds,
three example configurations, production layout parity and 13 snapshot wire-parity
states per execution suite pass. No preliminary native revision failed.

All native work remains serial and offline in 3 GiB/no-swap/four-CPU/180-second
services, with two codegen units for tests and one for production probes. Cleanup
finds no running services, held GPU leases or populated parent slices. The
unchanged allocator observer and two supervised process lifecycle cases from
§9.111 remain inherited and their artifacts are reverified.

The [evidence](evidence/gpu-preparation-handoff-storage-2026-10-11.json) pins
**534 source files** and **14 source archives** in
`lattica-prover-p3/benchmark-results/gpu-preparation-handoff-storage-20261011`.
It verifies parent artifacts, 26 dependency packages/1,044 files, 124 Rust library
files and 139 unchanged Python source hashes. Four desktop RTX 5080 proofs from
§9.106 and 132 Python application cases from §9.104 remain inherited. No fresh
GPU proof or throughput measurement was performed.

Finish preparation parsing/verification/runtime accounting, then deduct the
composed shared allowance before dividing physical coordinator RAM among jobs.
The current physical assignment still allocates the full coordinator cap to
per-job reservations. Physical caps and the **337 MiB per-job** minimum remain
unchanged, and ordinary admission still rejects incomplete phase profiles.
Full worker-phase composition, broader workloads/live-cache sets, nonempty-child
full-size merges, paired throughput comparisons, **24 hours AND 150 completed
roots**, multiple GPUs and AMD/Metal qualification remain open. Verification
stays on CPU; proving arithmetic, proof parameters/formats, registry identities
and activation are unchanged.


### 9.114 Disjoint coordinator shared and job reservations (2026-10-11)

Shared fleet admission now reserves **512 MiB** from the existing coordinator
cap before distributing the remaining RAM among jobs. Every job still requires
at least **337 MiB**. The planner preserves the physical-cap formulas; an
existing assignment that cannot hold both reservations fails admission.
For example, a 2 GiB coordinator with two workers reserves 512 MiB for shared
state and 768 MiB per job. A 768 MiB coordinator cannot admit two jobs with this
shared reservation.

Rust independently composes the known shared owners using the compiled layouts:

| Shared owner | One worker | Sixteen workers |
| --- | ---: | ---: |
| Durable pool and registry | 312,920,540 B | 312,920,540 B |
| One caller selection | 148,969,664 B | 148,969,664 B |
| Local endpoints and launch inventory | 17,312,012 B | 18,362,552 B |
| Preparation metadata | 82,856 B | 82,856 B |
| Service report and caller outputs | 2,773,000 B | 2,896,360 B |
| **Known shared total** | **482,058,072 B** | **483,231,972 B** |
| **Minimum reservation** | **536,870,912 B** | **536,870,912 B** |

Admission checks both the 512 MiB floor and the computed total, so component
growth cannot silently overrun the reservation. Test and production layouts
agree. The original `coordinator_storage` diagnostic is preserved; the separate
`shared_coordinator_storage` example exposes the new composed totals.

Shared fleet plans now require **schema 2**, including the shared reservation
in the plan and each worker assignment. Checked arithmetic requires job RAM
plus shared RAM to equal the coordinator cap, and worker RAM plus job RAM plus
shared RAM to fit the fleet cap. The shared owner is charged once. Old full-cap
job splits, missing/mismatched reservations, short caps and overflow are
rejected. Standalone worker assignments without a shared field remain compatible.

Recovery requires the schema-2 partition, preserves any larger shared allowance,
and rejects a changed physical coordinator cap or worker count. Calibration
normalization removes the two subdivisions while retaining the physical
coordinator limit. Legacy shared plans require a new admitted run; recovery does
not silently migrate their memory assignments.

Qualification passes **844 fresh native cases**: 255 CPU execution cases, 251
research GPU-feature host cases, 251 standard GPU-feature host cases, and 29
coordinator-driver cases in each configuration. **135 fresh Python tests** cover
resource admission, shared recovery, calibration and native shared execution;
the partition matrix includes 192 combinations across all 1–16 worker counts.
Four CPU compatibility builds, three example configurations and two production
layout probes pass. Ordinary incomplete lifetime profiles remain rejected.

Two preliminary failures are retained: a probe counter type mismatch at compile
time and a new test selecting the worker tuple field instead of the coordinator
job field. Both are corrected in the final source. Two earlier passing driver
runs are also retained. All final native work is serial and offline in
3 GiB/no-swap/four-CPU/180-second services, with two codegen units for tests and
one for production probes. Cleanup finds no running services, held GPU leases
or populated parent slices.

The [evidence](evidence/gpu-coordinator-partition-2026-10-11.json) pins **536 native
source/configuration files**, **139 Python source files**, 15 final native source
archives, four preliminary archives and the fresh Python archive. The audit
reverifies parent artifacts, 26 dependency packages/1,044 files, 124 Rust library
files and the unchanged allocator/supervised lifecycle evidence from §9.111.
Four full-size desktop RTX 5080 proofs remain inherited from §9.106; no fresh
GPU proof or throughput measurement was performed.

The partition fixes a physical overlap, but **512 MiB is only a minimum for
known shared owners**. Preparation parsing, key/input IO, task metadata, direct
wallet Uni-STARK verification and allocator/serializer/OS/runtime lifetimes still
need composition. The registered BatchProof verifier component does not establish
the wallet preparation verifier bound. Full worker/coordinator phase accounting,
broader workloads/live caches, nonempty-child full-size merges, paired throughput,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal remain open.
This is not a complete admission or RSS claim. CPU verification, proof parameters
and formats, registry identities and activation remain unchanged.


### 9.115 Bounded preparation input payloads (2026-10-11)

Preparation now enforces collection bounds during deserialization. A body may
allocate at most 64 transaction records and the maximum supported public-statement
width for each record. Independent expectations admit at most 64 distinct issuance
authorizations; duplicate keys are rejected before decoding the second value.
An extra sequence element is rejected before its nested payload is decoded.
Existing semantic checks still validate counts, public fields and host policy.

Artifact reads preserve the regular-file, nonsymlink and byte-limit guards, then
allocate exactly the length reported by the opened file. A short read or an extra
byte fails instead of growing the vector; interrupted EOF checks are retried.
Registry loading uses a transparent bounded wrapper for exactly 64 roots and a
**2,578-byte** envelope ceiling derived from the existing legacy varint format.
Valid serialized keys and registry identities are unchanged.

Task construction reserves 64 entry slots and 127 task slots. It uses an in-place
unstable sort with the same priority tuple. The tuple includes level and tree
position, so priorities are unique and output order matches the previous stable
sort. Tests cover every input count from 1 through 64 for the five-key reference,
six-key finalizer and twelve-key paired CLI families, including unchanged JSON
round trips, expected root statements and exact capacities.

The new primary-payload component is composed into shared coordinator admission:

| Preparation payload owner | Requested backing |
| --- | ---: |
| Body and bounded transaction/public vectors | 17,984 B |
| Independent expectation and bounded authorization map | 19,376 B |
| Commitment entry list | 2,584 B |
| Task list | 16,280 B |
| One artifact read buffer | 2,097,176 B |
| Key canonical-encoding buffer allowance | 2,602 B |
| **Component total** | **2,156,002 B** |

The authorization map uses the existing source-qualified conservative BTree node
bound. Other counters use compiled private layouts and explicit vector capacities.
The composed known shared total becomes **484,214,074 B** for one worker and
**485,387,974 B** for 16 workers. Production and test layouts agree, and both fit
the unchanged **512 MiB** minimum reservation. Physical caps, the **337 MiB**
per-job minimum and the schema-2 partition remain unchanged.

Qualification passes **969 fresh native cases**: 255 CPU execution, 251 research
GPU-feature host execution, 251 standard GPU-feature host execution, 40 driver
cases for each of the three CPU CLI families, and 46 paired driver cases for each
GPU feature set. Four CPU compatibility builds, three example configurations
and two production probes pass. One preliminary 40-case driver pass is retained
from before additional wire-decoder rejection assertions; no native run failed.
All native work remains serial and offline in 3 GiB/no-swap/four-CPU/180-second
services, with two codegen units for tests and one for production probes.
Cleanup finds no running services, held GPU leases or populated parent slices.

The [evidence](evidence/gpu-preparation-ingress-2026-10-11.json) pins **538 source
and configuration files**, 17 final native source archives and one preliminary
archive. It reverifies 139 unchanged Python source hashes and their archive,
parent artifacts, 26 dependency packages/1,044 files and 124 Rust library files.
The 135 Python cases from §9.114, four desktop RTX 5080 proofs from §9.106 and
allocator/supervised lifecycle evidence from §9.111 remain inherited.

This closes primary preparation payload growth, not all parser/serializer scratch,
error paths, other coordinator metadata or allocator/OS/runtime lifetimes.
Direct wallet Uni-STARK verification still needs independent memory accounting;
the registered BatchProof verifier bound cannot substitute for it. Ordinary
incomplete lifetime profiles remain rejected. Full lifetime composition, broader
workloads/live caches, nonempty-child full-size merges, paired throughput,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal remain open.
No fresh GPU proof, throughput gain, complete admission or RSS bound is claimed.
CPU verification, proof formats and parameters, registry identities and activation
remain unchanged.


### 9.116 Wallet verifier input admission (2026-10-11)

Direct wallet verification uses Uni-STARK, so the registered BatchProof verifier
component does not bound its allocations. Wallet entry points now apply a
separate allocation-free envelope before constructing a configuration or calling
the unchanged upstream verifier. It checks commitments, trace/quotient openings,
hiding rounds, FRI layers and queries, authentication salts and paths, and the
final polynomial against the fixed cubic/binary profile. Empty and non-power-of-two
Merkle caps are rejected, including those created through derived deserialization
that bypasses the cap constructor. Degree bits are bounded
to 1–28 so the degree plus four blowup bits fits Goldilocks' 32-adicity.

After checking lengths, the gate counts every owned proof vector's backing,
including spare capacity and the wallet public vector. Checked arithmetic
enforces a **64 MiB** input-backing ceiling. This does not retroactively reserve
caller allocations; execution already uses the separately bounded proof decoder.
Direct callers must still construct or decode their proof safely.

Public arguments now use a fixed **376-byte array** containing the statement
followed by the same candidate profile and chain limbs. HTLC/issuance policy checks
precede argument construction. Wallet errors retain their labels through the
existing fixed diagnostic writer: output is at most **1,024 bytes**, and final
owned diagnostic storage is at most **1,048 requested bytes** on this toolchain.
This does not account for all stack frames or upstream error construction.

Allocation observers confirm zero requests for input admission across **56**
degree/geometry shapes, correct spare-capacity accounting at **31** nested
locations, and early rejection of **46** malformed shapes, an oversized spare
buffer and arithmetic overflow. All three feature configurations agree:

| Input-admission measure | Result |
| --- | ---: |
| Largest synthetic template backing | 2,955,640 B |
| Backing after the 31 capacity-growth checks | 1,238,808 B |
| Admitted proof-backing ceiling | 67,108,864 B |
| Public-value array | 376 B |
| Maximum final diagnostic heap requests | 1,048 B |

Four fresh randomized **CPU reference** proofs cover JoinSplit, HTLC redeem,
HTLC refund and issuance. Each passes an independent call to the unchanged
upstream verifier with the original AIR and the guarded wallet entry point.
Altered chain IDs, public values and opening values are rejected. Observed owned
proof backing is 1,026,368 B for JoinSplit/issuance and 1,044,632 B for HTLC.
These are unit-test conformance results; the tests did not export proof bytes.

Qualification passes **905 fresh native cases**: 255 CPU execution, 251 research
GPU-feature host execution, 251 standard GPU-feature host execution, 40 CPU driver
cases, 46 driver cases for each GPU feature set, four input-admission cases in
each configuration, and four fresh CPU proof cases. Four CPU compatibility
builds, three example configurations and two production layout probes pass.
All 22 preliminary runs passed before the malformed-cap fix; their immutable
artifacts are retained, and all 22 final runs use the corrected source snapshot. All work remains serial and offline in
3 GiB/no-swap/four-CPU/180-second services, with two codegen units for tests and
one for production probes. Cleanup finds no running services, held GPU leases
or populated parent slices.

The [evidence](evidence/gpu-wallet-verification-inputs-2026-10-11.json) pins **541
source/configuration files** and **22 final native source archives** (plus 22 preserved preliminary archives). It reverifies
parent artifacts, 139 unchanged Python hashes and their archive, 26 dependency
packages/1,044 files and 124 Rust library files. The 135 Python cases from §9.114,
four full-size desktop RTX 5080 proofs from §9.106 and allocator/supervised
lifecycle evidence from §9.111 remain inherited. AIRs, proving functions,
parameters, formats and registry identities are unchanged.

The gate is **not proof acceptance or a complete verifier budget**. Underfilled
or otherwise invalid inputs that fit it still reach the unchanged numerical
verifier and must be rejected there. Uni-STARK symbolic degree inference,
periodic-column construction/evaluation, numeric AIR/PCS/FRI scratch,
configuration construction and runtime lifetimes still need source-derived
bounds and composition. The 64 MiB ceiling is not added to physical reservations
as if the complete phase were qualified.

Shared/job reservations and physical caps remain unchanged, and ordinary
incomplete lifetime profiles stay rejected. Full lifetime composition, broader
workloads/live caches, nonempty-child full-size merges, paired throughput,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal remain open.
There is no fresh GPU proof, throughput gain, RSS bound or production activation
claim. Verification remains on CPU.


### 9.117 Wallet verifier degree metadata (2026-10-11)

Release wallet verification no longer builds a symbolic constraint graph merely
to infer quotient degree. Three verifier-only AIR adapters supply degree **8**
for the original context-bound JoinSplit, HTLC and issuance circuits. Their
fields are private and only those three constructors attach the hint. Every
other AIR metadata method and the entire constraint evaluation delegate to the
original AIR. Proving functions and original AIR definitions are unchanged.

Independent symbolic evaluation of each original AIR, over both the base and
cubic extension fields, confirms degree 8. The quotient log remains **3** with
and without hiding; no proof parameter, constraint or accepted statement is
changed. P3's existing release hint path avoids symbolic inference; debug builds
still perform upstream symbolic cross-checks and require their own resource bound.

Allocation observers agree across the CPU, research GPU and standard GPU feature
sets. These are cumulative requests **per degree-inference call**, not live memory
peaks or whole-verifier measurements:

| Original AIR | Constraints | Original requested bytes | Original requests | Hinted bytes / requests |
| --- | ---: | ---: | ---: | ---: |
| Context-bound JoinSplit | 82 | 56,904 | 814 | 0 / 0 |
| HTLC | 145 | 89,864 | 1,202 | 0 / 0 |
| Issuance | 81 | 56,872 | 814 | 0 / 0 |

Qualification passes **19 fresh native cases**: the four input-admission cases
and one degree-metadata case in each of three feature configurations, plus four
fresh CPU wallet proofs. Those proofs cover JoinSplit, HTLC redeem/refund and
issuance, pass independent verification with the original AIR and the adapted
wallet verifier, and reject altered chain/public/opening values. Four CPU
compatibility builds also pass. The first CPU build exposed an explicit-path
test-module lookup error; its failed build and source archive are preserved,
and the corrected snapshot passes every final qualification.

The [evidence](evidence/gpu-wallet-verifier-degree-2026-10-11.json) pins **543
source/configuration files**, 11 final native source archives and one preliminary
archive. It reverifies the parent artifacts, 139 unchanged Python files, 26
dependency packages/1,044 files and 124 Rust library files. Native work remains
serial and offline in 3 GiB/no-swap/four-CPU/180-second services, using two codegen
units for tests. Cleanup finds no running services, held leases or populated
parent slices. The 135 Python cases and four full-size RTX 5080 proofs remain
inherited; no new GPU proof or throughput benchmark was run.

This closes **release wallet quotient-degree inference**, not the complete wallet
verifier budget. Periodic-column construction/evaluation, numeric AIR/PCS/FRI
scratch, configuration construction and allocator/runtime composition remain.
The 512 MiB shared and 337 MiB per-job floors, physical caps and rejection of
ordinary incomplete profiles are unchanged. Full worker/coordinator lifetime
composition, broader workloads/live caches, nonempty-child full-size merges,
paired throughput, **24 hours AND 150 completed roots**, multiple GPUs and
AMD/Metal remain open. Verification continues to run on CPU.


### 9.118 Registered verifier cap invariants (2026-10-11)

The registered proof envelope now enforces the same Merkle-cap representation
invariant as wallet input admission: each present cap has a **nonempty,
power-of-two** root list within its existing profile ceiling. Derived
deserialization can bypass `MerkleCap::new`, so an upper length bound alone does
not establish that invariant. The check runs before configuration construction,
public-value copying and upstream numerical verification.

Regression tests deserialize empty and three-root caps into each of the five
registered proof locations: main trace, quotient, randomness, permutation and
FRI layers. All **10 cases** fail both the allocation-free envelope and the
registered verifier entry point. The existing trusted preprocessing cap guard
already compares against an exact root count; two additional tests confirm it
rejects these malformed forms before shape or symbolic metadata construction,
with **zero allocation requests**. Its production implementation is unchanged.

The wallet cap comment now states the representation requirement without
implying that this verifier calls `MerkleCap::height`. The unused import left by
the verifier-only degree adapter is removed. These two cleanups do not change
wallet verification behavior. Original AIRs, proving functions, numerical
verifiers, parameters, formats and physical reservations remain unchanged.

Qualification passes **71 fresh native cases**: 24 CPU registered-verifier cases,
21 for each GPU feature configuration and five CPU wallet-admission/degree
cases. Three existing conformance tests exercise **seven fresh CPU registered
proofs**, including independent upstream comparisons, altered-proof rejection
and numerical/call allocation observations below their source-derived bounds.
Four CPU compatibility builds pass. All eight runs archive the same 543-file
source/configuration snapshot; there are no preliminary runs for this checkpoint.
The tests do not export proof bytes.

The [evidence](evidence/gpu-registered-cap-invariants-2026-10-11.json) reverifies
parent artifacts, 139 unchanged Python files, 26 dependency packages/1,044 files
and 124 Rust library files. Native work remains serial and offline in
3 GiB/no-swap/four-CPU/180-second services, with two codegen units for tests.
Cleanup finds no running services, held GPU leases or populated parent slices.
The 135 Python cases, four wallet proofs from §9.117 and four full-size desktop
RTX 5080 proofs from §9.106 remain inherited; no fresh GPU proof was run.

This closes the registered cap invariant gap. Wallet periodic-column
construction/evaluation, numeric AIR/PCS/FRI scratch, configuration construction
and complete allocator/runtime lifetimes still need bounds and phase composition.
The 512 MiB shared and 337 MiB per-job floors are unchanged, and ordinary
incomplete profiles remain rejected. Broader workloads/live caches,
nonempty-child full-size merges, paired throughput, **24 hours AND 150 completed
roots**, multiple GPUs and AMD/Metal remain open. No new throughput, complete RSS
bound or production activation is claimed.


### 9.119 Wallet verifier scratch and payload lifetimes (2026-10-11)

Wallet CPU verification now admits an allocation-free, checked **release x86_64
temporary payload plan** before configuration construction or numerical
verification. Its 64 MiB ceiling is separate from the existing 64 MiB
caller-owned proof backing ceiling; neither increases physical reservations.
Verification uses the existing fresh `SysRng` configuration with explicit entropy
errors, avoiding thread-local RNG initialization. Original AIRs, numerical
verification, proving functions and proof parameters remain unchanged.

The plan covers configuration, Uni-STARK domain/round construction, transcript,
numeric AIR evaluation, hiding PCS and FRI/MMCS requests. Degree 8 plus hiding
requires exactly 16 quotient chunks. The three PCS rounds have `[1, 1, 16]`
matrices and `[1, 2, 1]` opening points. Growth of the trace's local/next point
vector and the hiding salt rows is included.

Periodic columns follow **p3-commit's two-adic domain into p3-matrix
interpolation**, rather than p3-fri's scalar periodic helper. The bound includes
the column clone, coset, differences, inverses, adjusted weights, packed
fold/reduce identities on every Rayon worker and result collection. A nonempty
indexed sequence of `n` rows has at most `n` leaves and two identities per leaf.
Every column evaluation joins its child work before returning, so only one
interpolation workspace coexists with the retained periodic table. Construction
and interpolation are separate phases; FRI follows the column evaluations.

The temporary peak is bounded by persistent components plus the greater of
periodic construction or `retained table + max(one interpolation, FRI)`.
A separate cumulative-request bound sums all interpolation calls and other
requests. **All-thread measurements are cumulative requests, not live peak or
RSS**, and are compared only with the cumulative bound.

All 56 admitted geometry plans allocate nothing. Their maximum modeled temporary
payload is **28,704,800 bytes** for CPU features and **28,706,496 bytes** for GPU
features, below 64 MiB. The largest cumulative bound is 68,718,544/68,720,240 bytes;
that larger lifetime sum is not a simultaneous reservation. A length-4096 column's
interpolation bound is 1,245,952 bytes. JoinSplit/issuance retain at most 725,296
periodic bytes; HTLC retains at most 1,053,456 bytes. Source-based construction,
AIR and configuration bounds all cover the fresh observations.

Qualification includes **425 native test-case executions**: 395 initial
behavioral executions and 30 final scheduling executions. The initial suite
includes 255 execution/coordinator cases, 40 driver cases, registered-verifier
conformance, wallet geometry and component probes. Four fresh CPU wallet proofs
cover JoinSplit, HTLC redeem/refund and issuance. For each proof, valid/restored
verification succeeds and chain, public-value, opening and last-FRI mutations
fail; all 24 calls fit cumulative request bounds. Independent original-AIR
verification remains in these tests. Registered conformance also exercises seven
fresh CPU proofs. Four CPU compatibility builds pass.

The process-wide observer has an allocation-free, lock-free allocator hook and
an unwind-safe serialized measurement scope. Its three probes require an
explicit serial ignored-test run so ordinary parallel tests cannot interfere.
Sixteen initial archives and six final archives each contain 547 source/config
files. **The final snapshot differs only by those three ignore attributes**;
the audit proves that production code and all test bodies are byte-identical and
preserves all 81 initial artifacts. The 30 final executions verify both normal
selection and explicit serial probes in CPU, standard GPU and research GPU
feature configurations.

The [evidence](evidence/gpu-wallet-verifier-scratch-2026-10-11.json) pins additional
`p3-maybe-rayon` 0.6.1, `rayon` 1.12.0 and `rayon-core` 1.13.0 sources and reverifies
the parent dependency/toolchain lineage and 139 unchanged Python sources. The
135 Python cases and four full-size desktop RTX 5080 proofs from §9.106 remain
inherited. No fresh GPU proof or throughput result is claimed. All native work
ran serially, offline, within 3 GiB/no-swap/four-CPU/180-second services. Cleanup
found no running services, held leases or populated parent slices.

This closes a wallet verifier payload component, not complete physical
admission. Stacks, allocator metadata/slack, OS entropy internals, tracing
callbacks, Rayon/runtime control ownership and enclosing worker/coordinator
lifetimes still need composition. Debug/non-x86_64 scratch, broader workloads
and live caches, nonempty-child full-size merges, paired throughput, **24 hours
AND 150 completed roots**, multiple GPUs and AMD/Metal remain open. Shared/job
floors stay at 512 MiB/337 MiB and ordinary incomplete profiles remain rejected.


### 9.120 Borrowed wallet registry approval (2026-10-11)

Candidate preparation now approves its registry **once**, then reuses that
approval across wallet intake. Previously it approved the registry before the
loop and repeated `RegistryPin::check_typed` for each wallet. Each check reruns
`programs::profile_id`, including symbolic AIR preparation and fingerprinting.
This CPU metadata work is outside proving arithmetic but competes with the
coordinator's proof verification and scheduling.

`TypedRegistryContext` has private fields and holds an immutable borrow of the
exact twelve-key registry it approved. Construction uses the existing pin
constructor, including expected profile, height, cap geometry and backing
checks. Rust's borrow rules prevent registry mutation while the context is in
use and prevent the context from outliving it. The context is local authority;
it has no deserializer or global identity cache.

The original public and worker-owned wallet entry points retain their per-call
registry check. All paths share the same framing guard and private numerical
verification implementation. **Every wallet still undergoes bounded decoding,
chain/policy checks, unchanged CPU proof verification and statement/artifact
derivation.** Original AIRs, proving functions, parameters, encodings and
accepted proof semantics are unchanged.

Four fresh CPU wallet proofs cover JoinSplit, HTLC redeem/refund and issuance.
Each produces identical pin, mode, summary and artifact tickets through the
original call and two calls using the same context. Both paths reject a changed
expected chain, and context verification rejects an altered public statement.
Existing independent original-AIR checks and the §9.119 mutation/all-thread
scratch checks still pass on those same proofs.

For the qualified height-64 registry, the independently measured identity check
requests **2,996,953 bytes in 18,480 allocations**. Matched calls that stop after
decoding on an incorrect chain show exactly that request difference between
direct and reused verification. This isolates registry work before Rayon and
numerical verification. These are avoided cumulative requests, **not peak RSS
or a transaction-throughput measurement**. Initial registry approval still runs
and remains an enclosing lifetime component to qualify.

Qualification passes **334 native test-case executions**, including 257 CPU
execution cases, 40 driver cases, six codec cases, wallet admission/degree
checks, four targeted fresh proofs and registry-context checks under CPU,
research GPU and standard GPU features. The codec suite also generates a fresh
wallet proof. Four CPU compatibility builds and two GPU-feature driver builds
pass. Four substitution cases and three framing cases run in each context
suite; reused pin access allocates nothing.

The [evidence](evidence/gpu-wallet-registry-context-2026-10-11.json) verifies 549
source/configuration files, 139 unchanged Python files, 29 dependency packages
with 1,223 files and 124 Rust library files. Ten earlier successful source
archives and nine final archives differ only by two test-only `stream` guards
and formatting; production code and stream test bodies are identical. A final
CPU context run and the remaining feature matrix validate those guards. Sixty
earlier artifacts, the initial missing-module-path build and the missing-feature
guard build remain preserved. Both build failures were corrected before final
qualification; neither produced a failed proof test.

Native work remained serial and offline in 3 GiB/no-swap/four-CPU/180-second
services. Cleanup found no running services, held GPU leases or populated parent
slices. The 135 Python cases and four full-size desktop RTX 5080 proofs from
§9.106 remain inherited; no fresh GPU proof or throughput result is claimed.

This removes repeated registry compilation from candidate wallet intake. Initial
registry compilation, wallet decoding/verification phase composition, allocator
and runtime ownership, broader workloads/live caches, nonempty-child full-size
merges, paired throughput, **24 hours AND 150 completed roots**, multiple GPUs
and AMD/Metal remain open. Shared/job floors stay at 512 MiB/337 MiB, and ordinary
incomplete profiles continue to be rejected.


### 9.121 Wallet intake lifetime composition (2026-10-11)

The coordinator now reserves the payload peak of **one sequential wallet
intake**, including bounded decoding, unchanged numerical verification and
ticket-summary derivation. This component uses the already-approved borrowed
registry context from §9.120. Initial registry compilation and allocator/runtime
costs remain separate; ordinary incomplete profiles are still rejected.

The concrete decoder admits exact-capacity Vec backing before each allocation.
A new checked source model counts every envelope-admitted vector, cap and FRI
layer. Across all 56 supported geometries, the largest decoded backing is
**2,955,640 bytes**. Adding the maximum 2 MiB input-sized canonical buffer gives
a valid-decoding request bound of **5,052,792 bytes**. The context's single-wallet
decoder now uses an **8 MiB** cumulative quota, including invalid shapes. This
does not change the generic decoder or direct/worker-owned entry-point allowance.
Every previously admissible encoded wallet shape fits the smaller quota.

All 56 shape templates decode with exactly the modeled backing. For each shape,
the exact request quota succeeds and one byte less fails: **168 decoding attempts
per feature configuration**. A malformed 584,056-byte artifact contains nested
empty vectors within the codec's generic sequence limits. It decodes to
9,266,680 bytes under the old allowance but violates the wallet envelope. The
smaller quota rejects it after 8,388,592 requested bytes, before verification.
No physical reservation is increased to accommodate it.

Canonical scratch is dropped before the decoder returns. Structural envelope
admission runs before numerical allocation. The valid decoded proof stays live
through verification and summary derivation, then is dropped when the context
returns a fixed-size ticket. Consequently the payload peak is:

`diagnostic + max(decoder allowance, decoded backing + max(numerical peak, summary requests))`

The private summary helper preserves the original statement, leaf and artifact
hashing. Its public-value Vec and three pinned width-eight Poseidon2 constructors
request at most **2,312 bytes**; independent observations cover that bound. Input
byte backing, the registry and caller lists retain their existing separate
components. The source-based maximum is **31,661,488 bytes** for CPU features and
**31,663,184 bytes** for both GPU feature configurations. Planning allocates
nothing, checks overflow and retains the original numerical/proving behavior.

`KnownShared` now includes this intake peak alongside its other retained owners.
Both test-layout and one-codegen-unit production probes agree:

| Feature configuration | One worker: known shared bytes | Sixteen workers: known shared bytes |
| --- | ---: | ---: |
| CPU | 515,875,562 | 517,049,462 |
| Research GPU | 515,877,258 | 517,051,158 |
| Standard GPU | 515,877,258 | 517,051,158 |

Every value fits the unchanged **536,870,912-byte (512 MiB)** shared floor. The
337 MiB per-job floor is unchanged. Tests check every worker count from one to
sixteen, reject a reservation below the floor, and reject compiled component
growth that would consume job RAM. The accounting bridge rejects unqualified
debug/non-x86_64/non-stream targets; a debug regression executes that rejection.
Ordinary CPU verification remains available independently of that shared-budget
bridge.

Four fresh CPU wallet proofs cover JoinSplit, HTLC redeem/refund and issuance.
Eight complete context verifications, measured across all Rayon threads, stay
within their **cumulative-request** bounds and return the same tickets as the
original entry point. Four isolated summary observations pass. Independent
original-AIR verification, altered-proof rejection, registry substitution checks
and all 24 §9.119 verifier observations remain in these tests. Cumulative
requests are not live peaks and are never compared with the modeled peak.

Qualification passes **437 native test-case executions**, four CPU compatibility
builds, a debug driver build and three production-layout probes. These include
257 execution cases, 40 CPU driver cases, 46 driver cases under each GPU feature
configuration and six codec cases. The codec suite also makes a fresh wallet
proof. All 23 runs archive the same **552-file** source/configuration snapshot;
there are no failed or preliminary runs at this checkpoint.

The [evidence](evidence/gpu-wallet-intake-lifetimes-2026-10-11.json) additionally
pins Postcard 1.1.3 and Serde/core/derive 1.0.228 source behavior: borrowed slice
decoding, fixed error variants and canonical serialization into preallocated
storage. The audit reverifies 33 dependency packages/1,347 files, 124 Rust
library files and 139 unchanged Python sources. Native work remains serial and
offline in 3 GiB/no-swap/four-CPU/180-second services, with two codegen units for
tests and one for production probes. Final cleanup finds no running services,
held GPU leases or populated parent slices.

The 135 Python cases and four full-size desktop RTX 5080 proofs from §9.106 remain
inherited. This is a payload lifetime component, not complete RSS admission or a
throughput result. Initial registry approval, allocator overhead, stacks,
entropy/tracing and Rayon/runtime ownership remain open, along with broader
workloads/live caches, nonempty-child full-size merges, paired throughput,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal. Concurrent
wallet intake would require additional reservations; the current CLI loop is
sequential.


### 9.122 Initial registry approval lifetime composition (2026-10-11)

The coordinator's initial `TypedRegistryContext` approval now uses explicit
allocation quotas for CPU symbolic recording, normalization, lookup packing and
canonical fingerprint encoding. The reference symbolic compiler and fingerprint
encoder remain available for compatibility checks and other entry points. This closes
the initial approval payload component left open in §9.121; complete pool/worker
lifetime admission remains open.

The empty trusted machine shape does not allocate height-sized trace storage.
Its retained shape requests **348 bytes**. Recording, normalization, packing and
retained lookup output each have a **4 MiB** ceiling, enforced before requests.
The final ordered constraints use the same bounded recorder/normalizer. Canonical
encoding uses the existing **32 MiB** fingerprint envelope. Both reference and
bounded paths share the original registry field order; the prefix has a fixed
64-word capacity and cap appending reserves its exact additional length.

The initial setup payload peak is **41,945,124 bytes**, including a conservative
hash-constructor and diagnostic allowance. Its independent cumulative-request
bound is **62,942,955 bytes**. These are distinct quantities: allocation observer
results are checked only against the cumulative bound. Observations at heights
8, 64 and 2,097,152 remain within that bound in all three feature configurations.

Registry approval finishes before the wallet loop starts. Its symbolic graphs,
fingerprint buffers and hash state are gone before decoding a wallet, while the
approved context retains only the pin and an immutable borrow. Consequently the
preparation payload is `max(registry_setup_peak, wallet_intake_peak)`. Registry,
input, policy/list and pool owners retain their existing separate reservations.
Concurrent intake would need additional reservations.

CPU, research GPU and standard GPU test layouts and one-codegen-unit production
probes agree on the known shared totals:

| Workers | Known shared payload | Reserved shared floor |
| --- | ---: | ---: |
| 1 | 526,159,198 bytes | 536,870,912 bytes |
| 16 | 527,333,098 bytes | 536,870,912 bytes |

The largest total is **502.904 MiB**, within the unchanged **512 MiB** shared
floor. The per-job floor remains **337 MiB**. Tests exercise every worker count
from one through sixteen, reject insufficient RAM and overflow, and reject
shared accounting in an unqualified debug build. Non-x86_64/non-stream accounting
also remains unavailable; ordinary CPU verification remains independently usable.

Registry identities match the reference at **all 19 supported heights** in each
feature configuration. Tests reject all five constrained setup stages and then
successfully retry, reject nine malformed geometries before heap requests, and
check allocation-free planning. Registry substitution and wallet mutation tests
remain active. Four targeted fresh CPU wallet proofs cover JoinSplit, HTLC
redeem/refund and issuance; their eight complete context verifications still pass
the §9.121 cumulative intake bounds and return the reference tickets.

Qualification passes **425 native test-case executions**, four CPU
compatibility builds, a debug driver build and three production-layout probes.
All **24 final runs** archive the same **554-file** source/configuration
snapshot. One earlier release run also passed five tests; explicit build guards
were added before the final snapshot. The initial preparation controller stopped
on a parent-evidence key mismatch before writing backups or editing sources; its
corrected version and the successful preliminary run are preserved separately.

The [evidence](evidence/gpu-registry-setup-lifetimes-2026-10-11.json) rechecks
**33 dependency packages/1,347 files**, **124 Rust library files**, and **139
unchanged Python sources**. The 135 Python cases and four full-size desktop RTX
5080 proofs from §9.106 remain inherited. No fresh GPU proof or throughput
measurement was performed. Native runs remain serial and offline in 3 GiB,
no-swap, four-CPU, 180-second services, with two codegen units for tests and one
for production probes. Cleanup finds no running services or held GPU leases.

This is a payload qualification component. Pool construction, submission and
worker paths still make additional reference registry checks; they require their
own bounds and lifetime composition. Allocator overhead, stacks, entropy/tracing
and Rayon/runtime ownership also remain open, along with broader workloads/live
caches, nonempty-child full-size merges, matched throughput, **24 hours AND 150
completed roots**, multiple GPUs and AMD/Metal. Ordinary incomplete profiles
continue to be rejected.


### 9.123 Immutable pool registry approval and capacity admission (2026-10-11)

The persistent pool now owns a checked registry together with its derived
identity. The crate-private value cannot be deserialized and exposes no mutable
registry access. Construction moves the existing cap allocations, validates
their backing and geometry, and uses the bounded CPU setup from §9.122 once.
This identity remains valid for the lifetime of the pool-owned registry.

Candidate submission and worker replacement reuse that identity. Result intake
also reuses registry approval, while still checking every field of the typed job
pin, the complete canonical proof encoding, the expected public statement and
the original independent numerical verifier. Only identity construction is
reused; proof results are never cached or accepted on the worker's claim. The
original generic numerical body is extracted verbatim into a private helper;
the direct verification entry point remains available as a reference.

This checkpoint also corrects a capacity-admission omission in §9.122. The
borrowed context's bounded identity path checked cap lengths but bypassed
`Registry::id`'s limit on spare cap capacity. CLI preparation checked the backing
afterward; the context constructor now checks it **before symbolic setup**.
Regression tests admit the boundary and reject one additional spare root. The
rejection requests only **56 diagnostic bytes**, with no symbolic construction.

A fresh CPU twelve-key empty-node proof at height **2,048** passes both entry
points with the same result ticket. Mutated public values, a substituted
registry, and an altered permutation opening reject. Full typed-pin substitution
tests also cover proof family, wrapper construction and profile before decoding.
The existing six-key session regression still passes, exercising the other
generic verifier family.

On the fresh twelve-key proof, complete direct verification requests
**14,315,898 bytes / 105,891 allocation calls**. Reusing registry approval requests
**8,262,376 bytes / 67,063 calls**. The difference is exactly the two eliminated
registry constructions: **6,053,522 bytes / 38,828 calls**. These are cumulative
allocation requests, not live peaks, RSS, latency or transactions per hour.

In the two-job CPU submission fixture, submission requests **99,283 bytes**;
one reference registry identity construction alone requests **2,995,049 bytes**.
Worker replacement requests **96 bytes** and still rejects a mismatched profile.
Equivalent ownership, admission, submission and replacement checks pass under
both research and standard GPU build configurations. Each configuration also
checks **3,072 identity reads with zero allocations**, without copying cap backing.

The cached profile adds **32 bytes** to the pool's retained value, automatically
included by its compiled storage model. Initial pool construction uses the same
setup quota as wallet registry approval. These construction and intake phases
are sequential, so the shared preparation phase remains **41,945,124 bytes**;
retained pool, registry, selection and input owners remain separately reserved.
All three feature configurations and production-layout probes agree:

| Workers | Known shared payload | Reserved shared floor |
| --- | ---: | ---: |
| 1 | 526,159,230 bytes | 536,870,912 bytes |
| 16 | 527,333,130 bytes | 536,870,912 bytes |

The largest known payload remains **502.904 MiB**, within the unchanged
**512 MiB** shared floor; the per-job floor remains **337 MiB**. Debug shared
accounting rejects, and the existing non-x86_64/non-stream guard is unchanged.

Qualification passes **446 native test-case executions**, four CPU
compatibility builds, a debug driver build and three production-layout probes.
All **23 runs** archive the same **557-file** source/configuration snapshot,
with no failed or preliminary native runs. The targeted fresh CPU node proof,
six-key regression and execution suite all exercise proving; this is not an
exhaustive fresh-proof count. No new GPU proof or throughput result is claimed.

The [evidence](evidence/gpu-pool-registry-lifetimes-2026-10-11.json) rechecks
**33 dependency packages/1,347 files**, **124 Rust library files**, and **139
unchanged Python sources**. The 135 Python cases and four full-size desktop RTX
5080 proofs from §9.106 remain inherited. Native work is serial and offline in
3 GiB/no-swap/four-CPU/180-second services, with two codegen units for tests and
one for production probes. Cleanup finds no running services or held GPU leases.

The pool's repeated identity compilation is removed, but complete lifetime/RSS
admission remains unfinished. Worker/session, restore and other direct registry
paths still need their own phase accounting. Allocator overhead, stacks, entropy,
tracing and Rayon/runtime ownership also remain open, along with broader
workloads/live caches, nonempty-child full-size merges, matched throughput,
**24 hours AND 150 completed roots**, multiple GPUs and AMD/Metal. Ordinary
incomplete profiles continue to be rejected.

### 9.124 Worker registry ownership and startup payload admission (2026-10-11)

Worker configuration now owns immutable registry approval and passes it through
descriptor construction, worker startup and twelve-key session construction.
These transfers reuse the already checked identity. A borrowed approval can
become owned by cloning only the twelve cap vectors: **24,576 requested bytes
in 12 calls**. Moving the resulting approval into a session requests **zero
allocations**, preserves cap addresses, and remains independent of later changes
to the caller's original registry. Each build checks **1,024 repeated worker
approval reads** and **128 descriptor encodings** without allocation. The existing
wire records remain **248 bytes** for configuration and **312 bytes** for sessions.

Worker input preparation reuses this approval for wallets and recursive children.
Complete typed pin, framing, canonical decoding, expected statement, policy and
numerical verification checks remain. The original generic numerical verifier
and proof-generation/session methods are unchanged. Native bootstrap construction
obtains configuration and policy together before GPU initialization; separately
called encode/decode operations still validate their publicly mutable input.

Startup now checks a source-derived registry payload ceiling before compilation.
The coarse ceiling is **42,010,312 bytes**, covering the enforced symbolic phase
quotas and fixed empty-shape storage. Combined with the existing **8 MiB protocol**
and **1 MiB session** allowances, the worker startup minimum is **51,447,496 bytes**.
Boundary tests reject a byte less before registry allocation. This temporary
setup storage is released before proving, so later prover/cache accounting
continues to subtract only its actual protocol/session/cache owners. This is a
payload component, **not a complete process lifetime or RSS budget**. Physical
service caps and the **512 MiB shared / 337 MiB job** floors are unchanged; all
three production probes reproduce §9.123's known shared payloads.

A fresh CPU JoinSplit wallet proof passes both input slots of a padded pair.
Unauthorized issuance policy and an altered opening with recomputed artifact
hashes are rejected. The wrong-chain comparison requests
**4,875,441 bytes** through reference approval versus
**1,880,392 bytes** with the retained identity, a difference
of exactly **2,995,049 bytes** for one registry construction.
A fresh CPU twelve-key empty-node proof also passes direct and approved numerical
verification, while altered public values, registry and openings reject. Its
allocation difference remains exactly two registry constructions
(**6,053,522 bytes / 38,828 calls**).
These are cumulative allocator-request observations, not latency or throughput.

Qualification passes **950 native test-case
executions**, four CPU compatibility builds, a debug driver build/rejection test
and three production-layout probes. All **25 final
runs** archive the same **558-file** source/configuration manifest.
**15 preliminary archives** are preserved,
including four failed attempts: missing test imports/assertion traits, a stale
synthetic cache boundary, a test calling a private helper, and GPU-only tests
using the earlier validation return type. The final runs
resolve all four. The [evidence](evidence/gpu-worker-registry-lifetimes-2026-10-11.json)
rechecks **33 dependency packages / 1,347 files**, **124 Rust library files** and
**139 unchanged Python sources**. The 135 Python cases and four full-size desktop
RTX 5080 GPU proofs from §9.106 remain inherited. Native work stays serial and
offline in **3 GiB/no-swap/four-CPU/180-second** services, with two codegen units
for tests and one for production probes. Cleanup finds no running services or
held GPU leases. No new GPU proof or transaction-throughput result is claimed.

The all-GPU proving goal remains incomplete. Generic session self-verification,
recovery/restore and other direct registry paths still compile reference identity.
Complete caller/bootstrap and worker/coordinator lifetime/RSS accounting,
allocator/runtime overhead, broader workloads/live caches, nonempty-child
full-size merges, five matched throughput pairs, **24 hours AND 150 roots**,
multiple GPUs and AMD/Metal qualification remain open.

### 9.125 Session registry identity reuse during numerical verification (2026-10-11)

Typed sessions now reuse their immutable registry/profile binding for post-proof
self-verification and for merge/finalize child verification. The constructor
already validates this binding, and callers receive no mutable registry or
profile access. A private helper checks the mode, expected profile and exact
public statement before calling the **unchanged numerical verifier** every time.
No proof-verification result is cached. The public direct registry verifier and
session constructor remain unchanged.

The source audit reconstructs the entire previous session source exactly after
removing this helper, its four substituted callers and the test-module declaration.
Thus proof-generation arithmetic, circuits, parameters, registration, cache
behavior and encodings are preserved. No retained fields or memory floors change.
At these session checks, successful wraps, pairs and empty nodes eliminate one
registry identity construction each, merges eliminate three, and the existing
six-/twelve-key finalizers eliminate two. Five-key finalization remains unsupported.

Fresh CPU height-**2,048** empty-node proofs pass both direct and session verification
for all three registry families. Altered profile/public values, mismatched node
statements, three invalid modes, substituted registries and corrupted permutation
openings reject. Invalid children also reject through merge/finalize entry points.
For each family, allocation-request differences equal exactly one registry
construction:

| Registry keys | Direct bytes | Reused-identity bytes | Eliminated bytes | Eliminated calls |
| --- | ---: | ---: | ---: | ---: |
| 5 | 8,910,988 | 5,922,115 | 2,988,873 | 19,413 |
| 6 | 8,910,988 | 5,922,115 | 2,988,873 | 19,413 |
| 12 | 8,948,876 | 5,922,115 | 3,026,761 | 19,414 |

These are cumulative allocation requests, not simultaneous memory peaks, RSS,
latency or transaction throughput. All three production-layout probes reproduce
§9.124's known shared totals within the unchanged **512 MiB shared** floor. The
**337 MiB job** floor and physical service caps are unchanged.

Qualification passes **957 native test-case
executions**, four CPU compatibility builds, a debug build/rejection test and three
production-layout probes. All **19 runs** archive the
same **559-file** source/configuration snapshot; there are no preliminary native
revisions or failed native runs. The [evidence](evidence/gpu-session-registry-lifetimes-2026-10-11.json)
rechecks **33 dependency packages / 1,347 files**, **124 Rust library files** and
**139 unchanged Python sources**. The 135 Python cases and four full-size desktop
RTX 5080 GPU proofs from §9.106 remain inherited. Native commands remain serial,
offline and bounded by **3 GiB/no-swap/four-CPU/180-second** services, with two
codegen units for tests and one for production probes. Cleanup finds no active
services or held GPU leases. No fresh GPU proof or throughput result is claimed.

The all-GPU proving goal remains incomplete. Direct generic session construction,
restore/recovery and other registry paths still need enclosing lifetime accounting.
Complete caller/bootstrap and worker/coordinator RSS admission, allocator/runtime
overhead, broader workloads/live caches, nonempty-child full-size merges, five
matched throughput pairs, **24 hours AND 150 roots**, multiple GPUs and AMD/Metal
qualification remain open.


### 9.126 Recovery registry reuse and sequential verification allowance (2026-10-11)

Typed durable recovery now constructs one borrowed registry approval and reuses
it while loading wallet and node artifacts. Export and diagnostic import loops
also reuse their approval. It remains private validation authority over an
immutable registry, with no added retained heap allocation. Every artifact still
passes its kind, exact bytes/hash, full pin, policy/chain or node statement,
original numerical verifier, and derived identity checks. The direct reference
loaders and verifiers and the entire snapshot parser/reconstruction body are
unchanged, checked by source reconstruction.

The sequential recovery payload uses the existing **337 MiB** job allowance.
Registry setup, wallet verification and node verification do not overlap; the
16 MiB control allowance remains live throughout. The wallet decoder retains
the reference path's general 64 MiB allowance, rather than the narrower intake
allowance.

| Component | Bytes |
|---|---:|
| Bounded registry setup | 41,945,124 |
| Wallet decoder plus numerical/summary workspace and diagnostics | 95,814,712 |
| Node decoder plus native verifier component | 336,592,896 |
| Recovery control allowance | 16,777,216 |
| Control plus largest sequential phase | **353,370,112** |

Fleet recovery checks this component against assigned coordinator RAM after
subtracting its shared reservation. Standalone recovery and diagnostic import
check their job allowance before reading proof artifacts. Exact-floor admission,
floor-minus-one rejection, early family/construction rejection, and unqualified
debug rejection are covered. This is a payload component: graph, snapshot/store,
registry backing and caller ownership keep their separate reservations. The
512 MiB shared floor and all physical limits are unchanged; incomplete lifetime
profiles still reject admission.

A fresh CPU wallet proof and height-2048 typed Empty proof exercise two wallet
loads and one retained node in an actual partial DAG and durable journal.
Reference and approved recovery produce identical snapshot state except for
their independently fresh session IDs; the test explicitly checks those fresh
IDs. It rejects a changed issuance policy, changed registry and a corrupted
permutation opening even after the proof is rehashed, its snapshot identity is
replaced and the journal checksum is recomputed. Reopening and resuming the
original durable checkpoint preserves the retained node bytes.

The deterministic one-Rayon-worker allocation comparison replaces five reference
identity constructions with one bounded setup. The small case makes **61,746
fewer allocation calls** but requests **8,927,836 more cumulative bytes**.
Setup requests 24,061,641 bytes; each reference identity requests 3,026,761 bytes,
so the requested-byte crossover in this model is eight identity constructions.
These are allocation requests, not simultaneous peak, RSS, latency or throughput.
Ordinary execution suites continue to use four Rayon threads.

Validation records **949 passing top-level native
test-case executions**, plus 12 successful
child-process cases, 20 final native runs, four CPU
compatibility builds, a debug driver build, two debug rejection tests, and three
production-layout probes. All use serial offline services with 3 GiB RAM,
zero swap, four-CPU quota and 180-second per-service limits. Test/production
codegen settings remain two/one units. All 561 source/configuration hashes and
the inherited 33 dependency packages (1,347 files), 124 Rust library sources and
139 Python sources are checked. Four failed preliminary source archives are
preserved: test API fixes, fresh-session comparison, a four-thread
allocation-count mismatch, and a debug-library compile stopped at the 3 GiB cap.
The debug recovery test was repeated without compiler debug symbols; debug
assertions, two codegen units and every physical limit remain enabled.
Cleanup confirms no running Lattica services or
held GPU leases and only empty retained parent slices.

Evidence: [recovery registry qualification](evidence/gpu-recovery-registry-lifetimes-2026-10-11.json).
Four full-size desktop RTX 5080 GPU proofs remain inherited from 9.106; this
checkpoint adds no GPU proof or transaction-throughput result. Direct generic
session construction, remaining registry paths, complete worker/coordinator and
runtime/RSS admission, broader workloads/live caches, full-size merges with
nonempty children, five matched throughput pairs, **24 hours AND 150 completed
roots**, multiple GPUs and AMD/Metal remain open. The overall goal is incomplete.


### 9.127 Bounded identity construction for generic sessions (2026-10-11)

Direct `Session<5/6/12>::new` now reserves bounded registry setup before
compilation. The session and its owned registry remain live during that phase;
the setup workspace is released before proof work. Construction no longer uses
the older unbounded reference identity compiler. The source audit reconstructs
the previous session implementation exactly outside this constructor change
and the new test-module declaration: numerical verification, proof generation,
child checks, immutable profile binding and cache behavior are preserved.

The bounded metadata builder now accepts the existing **3/5/6/12-key families**.
The original family validation runs before any symbolic allocation, and the
unchanged conservative twelve-key envelope covers all four families. Shape,
symbolic graph and fingerprint quotas, prefix/hash order, profile framing and
the public reference identity builder remain unchanged. Differential checks
match every admitted height, from 8 through 2²¹, for each family under CPU,
research GPU and standard GPU features. Each family also rejects all five
independently exhausted setup quotas, recovers for a successful retry, and
rejects malformed cap lengths before allocation. Unsupported family counts
reject before symbolic allocation.

| Startup component | Bytes |
|---|---:|
| Retained session/registry allowance | 1,048,576 |
| Existing portable registry setup ceiling | 42,010,312 |
| Direct session constructor floor | **43,058,888** |
| Existing worker protocol allowance | 8,388,608 |
| Existing complete worker-startup payload floor | **51,447,496** |

Direct constructors now reject budgets below the new constructor floor. Tests
admit its exact value and reject zero, session-only and floor-minus-one budgets
before symbolic setup. Changed profiles, caps, invalid heights and unsupported
session families reject as well. Allocation observations show that successful
construction requests exactly one bounded identity setup within each feature
configuration. CPU and standard-GPU builds request 24,047,305 bytes for five
keys, 24,049,353 for six keys, and 24,061,641 for twelve keys, with 35,324
requests each. The wide-lane research build requests 29,799,268, 29,801,316 and
29,813,604 bytes respectively, with 63,247 requests each. These cumulative
requests are not live peak, RSS or throughput.
Existing worker, 512 MiB coordinator-shared and 337 MiB job floors are unchanged.
Passing this constructor gate does not admit a proof or complete process lifetime;
caller ownership, stacks, allocator/runtime overhead and RSS remain separate.

Three fresh CPU Empty proofs at height 2048 cover the five-, six- and twelve-key
sessions. The original numerical verifier still accepts them and rejects altered
statements, modes, registries, openings and invalid children. Validation records
**997 passing top-level native test-case executions**,
plus 12 child-process cases, across
24 final native runs. It includes four CPU
compatibility builds, a debug driver build/rejection, two debug constructor tests
and three production-layout probes. There are no failed preliminary native runs.
An initial source-audit comment anchor and an audit assumption of identical
allocation counts across features were corrected in separately retained
controller versions without source changes. Allocation comparisons use the
independent bounded-builder observations for each feature configuration.

All native work used serial offline services with 3 GiB RAM, zero swap,
four-CPU quota, four Cargo/Rayon threads and 180-second per-service limits.
Tests use two codegen units and production probes one. Debug constructor tests
omit compiler debug symbols while retaining debug assertions and all limits.
The audit covers all 562 source/configuration hashes, 33 pinned dependency
packages (1,347 files), 124 Rust library sources, 139 inherited Python sources,
all native source archives, unchanged physical floors and rejection of incomplete
lifetime profiles. Cleanup confirms no running Lattica services or held GPU
leases and only empty retained parent slices.

Evidence: [generic session construction qualification](evidence/gpu-session-construction-lifetimes-2026-10-11.json).
Four full-size desktop RTX 5080 GPU proofs remain inherited from 9.106; this
checkpoint adds no GPU proof or transaction-throughput result. The three-key
metadata builder is available, but legacy orchestration and other direct registry
paths still need their enclosing phase accounting and integration. Complete
worker/coordinator and runtime/RSS admission, broader workloads/live caches,
full-size merges with nonempty children, five matched pairs, **24 hours AND 150
completed roots**, multiple GPUs, AMD/Metal and the pending Mac source integration
remain open. The overall goal remains incomplete.


### 9.128 Legacy session startup and assigned worker budgets (2026-10-11)

Legacy `ProverSession` and `ConstructionSession` now accept explicit immutable
memory budgets and bound registry setup before compilation. Their compatibility
constructors retain the existing 48 GiB default. Cold CPU execution and packet
execution pass the bound assignment's RAM into the session and reject short
startup budgets before input proof verification. The private proving helper
rejects short budgets before cloning its registry.

This fixes a concrete cached-worker mismatch: the worker reserved **44 GiB**
for its workspace but previously passed the **48 GiB** global default to
preprocessing. It now passes its existing workspace budget, with 1 MiB withheld
for retained session storage. The separate 1 GiB job reservation, existing host
headroom, workspace/scratch/thread caps and close/release behavior are unchanged.

| Session component or assignment | Bytes |
|---|---:|
| Registry value/backing ceiling, including spare cap capacity | 65,536 |
| Retained ProverSession allowance | 1,048,576 |
| Existing bounded registry setup ceiling | 42,010,312 |
| Constructor startup floor | **43,058,888** |
| Cached workspace assignment | 47,244,640,256 |
| Cached active preprocessing budget | **47,243,591,680** |

Registry approval uses the already qualified three-key bounded identity builder.
The public reference identity and numerical verifier remain unchanged. Exact-floor
startup succeeds; zero, session-only and floor-minus-one budgets reject before
symbolic setup. The last cap root fitting the storage ceiling succeeds and the
next root rejects before symbolic allocation, while its reference identity is
unchanged. Wrong profiles, changed caps and invalid heights reject. Successful
constructor requests match one bounded builder in each feature configuration.
Setup is sequential: its transient workspace is released before proving, so only
retained session storage is subtracted from the active backend budget.

Source reconstruction preserves all proof-generation methods except the memory
argument sent to preprocessing, original numerical verification, packet/wire
codecs, launch checks, and cache lifecycle/close logic. A new test creates a real
durable owner and cached CPU worker, confirms the session receives its 44 GiB
reservation, then closes it and confirms resource release. It performs no full
44 GiB workload. Three fresh height-1024 CPU Empty proofs use an explicit
512 MiB assignment and a 535,822,336-byte active budget: two session proofs
exercise one setup plus a cache hit, and one exercises the cold-worker proving
helper. Original verification accepts them and rejects mutated public statements
and permutation openings. Public inline/packet budget wiring is source-audited.

Validation records **1005 passing top-level native
test-case executions**, plus 13 child-process
cases, across 25 final native runs. It includes the
legacy recursive suite, CPU/research-GPU/standard-GPU startup, typed-session,
execution and driver suites, four CPU compatibility builds, debug driver
build/rejection and three startup tests, and three production-layout probes.
There are no failed preliminary native runs. Source-audit controllers retain
their earlier formatting assumptions and the corrected final version.

Native runs remain serial/offline with 3 GiB RAM, zero swap, four-CPU quota,
four Cargo/Rayon threads and 180-second per-service limits. Tests use two codegen
units and production probes one; debug startup tests omit compiler debug symbols
while retaining debug assertions. The audit covers 565 source/configuration
hashes, 33 pinned dependency packages (1,347 files), 124 Rust library sources,
139 inherited Python sources and every native source archive. Existing 512 MiB
shared and 337 MiB job floors and incomplete-profile rejection remain unchanged.
Cleanup confirms no running Lattica services or held GPU leases and only empty
retained parent slices.

Evidence: [legacy session and worker budget qualification](evidence/gpu-legacy-session-lifetimes-2026-10-11.json).
This bounds a payload component and fixes budget propagation; construction
wrappers, worker/packet/input owners, stacks, allocator/runtime overhead and RSS
still need enclosing admission. Remaining direct registry paths also need their
phase accounting. Four full-size desktop RTX 5080 typed GPU proofs remain
inherited from 9.106. Legacy GPU budget behavior needs fresh hardware
qualification; this checkpoint adds no GPU proof or throughput measurement.
Broader workloads/live caches, full-size merges with nonempty children, five
matched pairs, **24 hours AND 150 completed roots**, multiple GPUs, AMD/Metal
and the pending Mac source integration remain open. The overall goal is incomplete.


### 9.129 Legacy explicit-budget GPU session qualification (2026-10-11)

The desktop RTX 5080 now has fresh hardware evidence for the legacy explicit-budget
session path introduced in 9.128. Six height-2048 Empty proofs passed: three with
`block-v2-wide-lanes,gpu,stream` and three with `block-v2,gpu,stream`. Each run
exercises a cold session, a cache hit for the identical public statement, and a
new setup after explicit cache eviction. Cold/warm refers to the session cache;
the fixture initializes the GPU engine and prepares the registration key first.

Both configurations use an explicit **1,073,741,824-byte** session assignment and
**1,072,693,248-byte** active preprocessing budget, withholding the existing
1 MiB session allowance. Zero, session-only, and startup-floor-minus-one budgets
reject without any new GPU allocation or upload. Each run records two setups and
one cache hit. The two identical-statement proofs have different encodings.

All six whole requests report all **16 proving arithmetic stages on OpenCL**.
The audit checks every one of the 36 emitted scope reports for successful,
complete coverage, completed device events and no CPU proving fallback. All five
whole-request components complete; only the middle request marks preprocessing
as cached. The original numerical verifier runs on CPU after explicit GPU
shutdown. It accepts all six proofs and rejects six wrong expected roots, six
altered in-range public counts, and six altered permutation openings.

| GPU test configuration | Proofs | Test service memory peak | Swap peak |
|---|---:|---:|---:|
| Research wide lanes | 3 | 682,774,528 bytes (651.14 MiB) | 0 |
| Standard lanes | 3 | 356,061,184 bytes (339.57 MiB) | 0 |

These cgroup peaks include the test process and its descendants; they are not a
complete ownership or worst-case RSS admission model. The session assignment and
the engine's independent 3 GiB host-output cap remain distinct. Managed GPU and
driver reserve caps stay at 7 GiB and 4 GiB. No physical cap, ordinary lifetime
admission rule, proving arithmetic, or numerical verifier changed.

The only Rust additions are an ignored GPU regression test and its test-only
module declaration. Validation consists of two release GPU builds, two GPU test
runs and three CPU startup tests: **five passing top-level test-case executions**
across five bounded native runs, with no preliminary native failures. All native
work ran serially and offline with 3 GiB RAM, zero swap, a four-CPU quota, four
Cargo/Rayon threads, two test codegen units and a 180-second service limit. Both
GPU builds reached the memory cap without OOM events; the GPU test process peaks
are reported separately above.

The audit verifies 566 source/configuration hashes, every native source archive,
all 130 immutable parent artifacts, actual cgroup/service limits, the selected
desktop UUID `GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`, and all stage receipts.
Cleanup found no running Lattica services or held GPU leases; all 85 retained
parent slices were empty. The broader dependency, Python and host regression
qualification remains inherited from 9.128. Evidence:
[legacy explicit-budget GPU qualification](evidence/gpu-legacy-session-gpu-budgets-2026-10-11.json).

This is small-fixture session qualification. Full-size legacy jobs, public worker
wire execution, caller/bootstrap/input ownership, remaining direct registry
paths, allocator/runtime lifetimes and complete worker/coordinator RSS admission
remain open. The four full-size typed RTX 5080 proofs remain inherited from 9.106.
Broader workloads/live caches, full-size merges with nonempty children, five
matched throughput pairs, **24 hours AND 150 completed roots**, multiple GPUs,
AMD/Metal and pending Mac source integration are also unfinished. No transaction
throughput claim follows from these fixtures. The overall goal remains active
and incomplete.


### 9.130 Assigned host budgets in GPU PCS and quotient work (2026-10-11)

The 9.129 hardware traces exposed a remaining budget propagation gap. A legacy
session assigned 1 GiB correctly limited witness preparation, but its PCS and
quotient compiler still used the process-wide 3 GiB host-output allowance. This
checkpoint carries the assigned allowance through registered GPU preprocessing,
fresh proving configuration, quotient compilation and opening validation.

New internal configuration constructors admit the smaller of the assigned and
configured limits before obtaining entropy or creating device state. They reject
zero assignments, invalid configured limits and an unavailable resident backend.
The existing PCS host allowance is immutable and shared by PCS clones. Batch and
single-AIR quotient paths now query that allowance instead of reading the global
limit directly. Reference configurations retain their existing behavior. No
process environment or thread-local budget is mutated.

The registered-program backend passes its existing admitted GPU host allowance
to both preprocessing and each fresh proof configuration. Default configuration
constructors still use their original path. A source reconstruction audit checks
that the original implementation is unchanged outside these budget changes,
including proof parameters, entropy construction, public preprocessing seeds,
proving arithmetic and numerical verification. No physical cap, retained struct
layout or incomplete-lifetime admission rule changed.

| Observed budget in each GPU configuration | 9.129 | 9.130 |
|---|---:|---:|
| Session assignment | 1,073,741,824 bytes | 1,073,741,824 bytes |
| Retained session allowance | 1,048,576 bytes | 1,048,576 bytes |
| Active preprocessing allowance | 1,072,693,248 bytes | 1,072,693,248 bytes |
| Each of 15 emitted LDE plan host limits | 3,221,225,472 bytes | **1,072,693,248 bytes** |
| Each of three quotient-storage caller limits | 3,221,225,472 bytes | **1,072,693,248 bytes** |

Six fresh height-2048 Empty proofs passed on desktop RTX 5080 UUID
`GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`: three research wide-lane proofs and three
standard-lane proofs. Every proof reports all 16 arithmetic stages on OpenCL;
all 36 component/whole-request reports pass the strict coverage audit. Cold
session setup, same-statement cache reuse and explicit eviction/rebuild retain
their behavior. CPU verification after GPU shutdown accepts every proof and
rejects altered expected roots, public counts and permutation openings. Both
new configuration constructors also reject zero budgets without device
allocation or upload. Cold/warm labels describe only the session cache.

Validation records **34 passing top-level test-case executions** across 13
successful native runs: both GPU fixtures, budget/profile tests under both GPU
configurations, 22 CPU recursive tests, two CPU profile tests, two GPU library/test
checks and wide-CPU, no-stream and default compatibility checks. Eleven existing
CPU-suite integration tests remain ignored. There were no failed native runs.
The initial research build differs from the final source only in two test-macro
indentation lines; the following GPU run rebuilt and tested the final source.
The first source-audit controller's indentation assumption was corrected in a
new controller version, preserving the earlier version and source archive.

All native work ran serially and offline in 3 GiB, zero-swap user services with
four-CPU quotas, four Cargo/Rayon threads, two test codegen units and 180-second
limits. No OOM event occurred. The research GPU run includes a rebuild, so its
cgroup peak includes compiler memory and is not a standalone proof-memory
measurement. Managed GPU and driver reserve caps remain 7 GiB and 4 GiB. The
audit verifies 567 source/configuration hashes, all native source archives, the
91 immutable parent artifacts, actual service limits and all budget/stage
receipts. Cleanup confirms no running Lattica services or held GPU leases and
85 empty retained parent slices. Evidence:
[assigned GPU PCS host-budget qualification](evidence/gpu-assigned-pcs-budgets-2026-10-11.json).

This fixes propagation of an existing assignment; it does not establish a total
worker/coordinator memory reservation across overlapping phases. Caller/input
ownership, allocator/runtime lifetimes, remaining direct registry paths, full-size
legacy and nonempty-child workloads, live-cache qualification, five matched
throughput pairs, **24 hours AND 150 completed roots**, multiple GPUs, AMD/Metal
and pending Mac source integration remain open. The original four full-size typed
GPU proofs remain inherited from 9.106. No transaction-throughput improvement is
claimed, and the overall goal remains active and incomplete.


### 9.131 Bounded public registry-pin construction and checking (2026-10-11)

Public legacy and typed registry-pin paths now use the existing bounded identity
builders. `RegistryPin::new` and the legacy registry check call `bounded_id`;
`new_typed` obtains its identity through the borrowed `CheckedRegistryRef`.
`check_typed` continues to use the public constructor and compare the complete
pin. Existing approved-context paths keep their receipt reuse behavior.

This closes direct reference-identity construction in the pin checks used by
public wallet/node acceptance and legacy transport validation. Legacy pins now
also reject registry backing above the existing **64 KiB** ceiling, including
unused vector capacity, before symbolic setup. Values with excess capacity have
the same reference identity but are outside this component's storage allowance.
The original public reference identity functions, shape/family checks, proof
codecs, numerical verifier, proving arithmetic and physical resource caps remain
unchanged. The bounded setup uses the previously qualified registry setup
envelope; caller-owned registry/input storage and runtime overhead remain separate.

New tests cover both three-key legacy and twelve-key typed registries at every
one of the 19 admitted heights, from 8 through 2^21. Under CPU, research GPU and
standard GPU feature configurations, constructor and check allocation requests
match the corresponding bounded builder within that same configuration. Their
identities match the independent original reference functions. Separate cases
reject excess backing before symbolic work, wrong families/construction, changed
caps, wrong pins, invalid heights and malformed cap lengths.

A fresh height-1024 CPU Empty proof uses a 512 MiB session assignment and passes
both the original verifier and public `VerifiedNode::verify` with the bounded
pin checks. Substituted chain context or registry, altered permutation openings
and trailing bytes all reject. This is an explicit CPU correctness oracle; it is
not new GPU proof qualification.

Validation records **813 passing top-level test-case executions**, plus 13 child
process cases, across 15 final native runs: the focused pin tests in all three feature configurations, the fresh
CPU public-acceptance test, execution suites with 271/266/266 passing cases, GPU
library/test checks and wide-CPU, no-stream and default compatibility checks.
Existing ignored integration tests remain recorded in the evidence. The initial
CPU build failed because the new fixture referenced a private helper; it was
corrected to the same explicit subtraction using the existing crate-visible
session allowance. The failed run, its controller and its source archive are
preserved; the following build and all final tests passed.

All native work remained serial and offline in services limited to 3 GiB RAM,
zero swap, four CPUs, four Cargo/Rayon threads, two test codegen units and 180
seconds. No OOM event occurred. The audit checks 568 source/configuration hashes,
every native archive, the 229 immutable parent artifacts, actual service limits
and the source reconstruction outside the three identity call-site changes.
Cleanup confirms no running Lattica services or held GPU leases and only empty
retained parent slices. Evidence:
[public registry-pin lifetime qualification](evidence/gpu-public-registry-pin-lifetimes-2026-10-11.json).

The latest six small RTX 5080 GPU proofs remain inherited from 9.130, and the four
full-size typed GPU proofs remain inherited from 9.106. Wallet-local workers
already validate their assigned host-output limit against their startup
environment; that path required no change here. Complete caller/bootstrap/input
ownership and worker/coordinator RSS admission, remaining direct registry paths,
broader/live-cache and nonempty-child workloads, five matched throughput pairs,
**24 hours AND 150 completed roots**, multiple GPUs, AMD/Metal and pending Mac
source integration remain open. No throughput gain or complete memory-admission
claim follows from this checkpoint. The overall goal remains active and incomplete.

### 9.132 Reused registry approval during public proof acceptance (2026-10-11)

Public legacy node and candidate-wallet acceptance now retain a borrowed registry
approval for the duration of verification. The approval computes the existing
bounded identity once, remains tied to an immutable registry borrow, and supplies
the approved profile to the original numerical verifier or wallet-summary body.
Public typed node acceptance now uses the existing `TypedRegistryContext`, which
also avoids a second identity construction. The approval cannot be serialized or
used as a worker ticket, and no global cache is introduced.

Legacy node and candidate-wallet acceptance now use the existing bounded proof
decoder. Its **64 MiB** input-storage limit covers decoded vector backing and
canonical re-encoding; caller-owned input bytes and runtime overhead are separate.
Registry backing retains its **64 KiB** limit and the existing **42,010,312-byte**
setup component envelope. No physical cap or incomplete-lifetime admission rule
changes. Here, legacy wallet means the untyped block-v2 candidate wallet, not the
separate quadratic production-wallet ABI.

The original public registry verification and wallet-summary APIs retain their
reference identity checks. A source reconstruction audit confirms that shared
statement checks, numerical verification calls, wallet-summary calculation and
surrounding implementation are preserved. Proving arithmetic and codec
implementations are unchanged.

Three fresh CPU proofs passed: a height-1024 legacy Empty node, a height-2048 typed
Empty node and a legacy candidate wallet. Public and retained-approval acceptance
agree with the original verifier and summaries. Wrong statements, registries and
altered openings reject; legacy acceptance also rejects trailing proof bytes.
Measurements on a dedicated one-thread Rayon pool show that retained approval
avoids exactly one bounded identity construction:

| Public acceptance path | Direct requested bytes | Reused-approval requested bytes | One identity's requested bytes / calls |
|---|---:|---:|---:|
| Legacy node | 32,042,619 | 7,999,426 | 24,043,193 / 35,324 |
| Typed node | 32,324,137 | 8,262,496 | 24,061,641 / 35,324 |
| Legacy candidate wallet | 36,660,482 | 12,617,289 | 24,043,193 / 35,324 |

These are cumulative allocation requests comparing current direct and retained
approval paths. They are not before/after RSS or throughput measurements.

Validation records **948 passing top-level test-case executions**, plus 12 child
process cases, across 23 successful native runs. The CPU/research/standard
execution suites passed 273/268/268 cases, recursive suites 22 each, and codec
suites 21/22/21. Focused approval tests passed in all three configurations; GPU
library/test, wide-CPU, no-stream and default compatibility checks also passed.
Ignored integration cases remain recorded in the evidence. GPU-feature host
regressions did not initialize the GPU and are not fresh GPU proof qualification.

All native work remained serial and offline in services limited to 3 GiB RAM,
zero swap, four CPUs, four Cargo/Rayon threads, two test codegen units and 180
seconds. No native failure or OOM event occurred. The source audit's first
controller stopped on an expected comment absent from an extracted private
helper; a new controller corrects that comparison while preserving the original.
The successful audit verifies 570 source/configuration hashes, every native
source archive, 239 immutable parent artifacts, actual service limits and proof
receipts. Cleanup confirms no running Lattica services or held GPU leases and 85
empty retained parent slices.

Evidence: [public proof approval lifetime qualification](evidence/gpu-public-proof-approval-lifetimes-2026-10-11.json).

The latest desktop RTX 5080 GPU arithmetic qualification remains 9.130; full-size
typed GPU qualification remains 9.106. Complete caller/bootstrap/input ownership
and worker/coordinator RSS admission, remaining direct registry paths, broader
and live-cache nonempty-child workloads, five matched throughput pairs,
**24 hours AND 150 completed roots**, multiple GPUs, AMD/Metal and pending Mac
source integration remain open. The overall goal remains active and incomplete.

### 9.133 Reused legacy session approval for child verification (2026-10-11)

Legacy `ProverSession::merge` now reuses the identity validated when the session
was created. It borrows the session's immutable owned registry and verifies each
child with the original numerical verifier, expected statement and cap selection.
Neither proof acceptance nor child results are cached. Session methods never
mutate the registry, and eviction changes only preprocessing ownership. No
retained struct layout, wire format, verifier arithmetic or proof parameter
changes.

The one-shot `wrap`, `empty` and `merge` helpers now share an admitted borrowed
constructor. It checks the existing registry-backing and startup allowances
before constructing one bounded identity and copying three cap vectors. This
removes the reference identity construction followed by a second identity check
inside the prior owned-session constructor. The public owned constructor and
reference identity/verifier APIs retain their original behavior.

Focused tests cover heights 8, 1024 and 2^21. Constructor requests equal one
bounded identity builder plus the three cap-buffer copies, while 3,072 retained
profile reads request no allocation. Changing the caller's original registry or
evicting cached preprocessing leaves the owned session's approval intact. Short
startup budgets and excess cap capacity reject before cap copying or symbolic
setup; the existing **64 KiB** registry ceiling, **1 MiB** retained session
allowance and **42,010,312-byte** setup component envelope are unchanged.

A fresh height-1024 CPU Empty proof checks the original and retained-approval
verifiers. Corrupted proof openings reject in either child position of the real
merge entry point before new preprocessing, and changed public statements reject.
After eviction, retained approval still accepts the valid proof. On a dedicated
one-thread Rayon pool, two child-verification calls request **17,576,952 bytes /
142,514 allocations** through the original registry API and **11,637,318 bytes /
103,690 allocations** with retained approval. The difference is exactly two
reference identity builds: **5,939,634 bytes / 38,824 allocation requests**.
These cumulative requests are not RSS, end-to-end latency or throughput results.
The test does not produce a new full-size valid merge proof.

Six fresh height-2048 Empty proofs passed on the desktop RTX 5080, UUID
`GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`: three research wide-lane and three
standard-lane proofs. All 16 proving arithmetic stages execute on OpenCL, and all
36 component/whole-request scope reports pass strict coverage checks. The tests
cover cold setup, same-statement reuse and eviction/rebuild. Session approval
accepts all six proofs and rejects altered expected roots and openings. After
session drop and GPU shutdown, the independent original CPU verifier accepts all
six and rejects altered expected roots, public counts and openings.

The session assignment remains **1 GiB**, with **1,072,693,248 bytes** propagated
to every active preprocessing/LDE/quotient host allowance. GPU managed and driver
reserve caps remain 7 GiB and 4 GiB. These are small-proof qualification runs;
the full-size typed GPU evidence remains inherited from 9.106.

Validation records **884 passing top-level test-case executions**, plus
12 child process cases, across 17 successful native runs. CPU, research
and standard recursive suites each pass 24 cases; the corresponding execution
suites pass 273/268/268. GPU library/test, wide-CPU, no-stream and default
compatibility checks pass. Existing ignored tests remain recorded in evidence.
All native work ran serially and offline with 3 GiB RAM, zero swap, four CPUs,
four Cargo/Rayon threads, two test codegen units and 180-second service limits.
No native failure or OOM event occurred.

The audit reconstructs the prior proving implementation outside the approved
registry-call substitutions and checks every native source archive against 571
source/configuration hashes. All 341 parent artifacts remain unchanged. Cleanup
confirms no running Lattica services or held GPU leases and 85 empty
retained parent slices.

Evidence: [legacy session registry-approval qualification](evidence/gpu-legacy-session-approval-lifetimes-2026-10-11.json).

Complete caller/bootstrap/input ownership and worker/coordinator RSS admission,
other direct registry paths, broader/live-cache and nonempty-child full-size
workloads, five matched throughput pairs, **24 hours AND 150 completed roots**,
multiple GPUs, AMD/Metal and pending Mac source integration remain open. This
checkpoint supports no throughput promotion. The overall goal remains active
and incomplete.

### 9.134 Decoded-input reservation outside cached worker sessions (2026-10-11)

Typed workers now reserve the existing **64 MiB** bounded-decoder allowance
outside the cached prover session. `PreparedInputs` retains decoded child proofs
and its quota until the complete proving call returns, so this storage can
overlap registered programs, preprocessing and proof work. The reservation is
constant across Empty and input-bearing jobs: a PCS created for an Empty job
must also respect the allowance when reused for a later job with children.
The inline `PreparedInputs` owner is now counted in the existing protocol
metadata allowance as well.

| A worker assigned 3 GiB | Prior assignment to session | Current assignment to session |
|---|---:|---:|
| Protocol allowance outside session | 8,388,608 bytes | 8,388,608 bytes |
| Decoded-input allowance outside session | 0 bytes | 67,108,864 bytes |
| Session budget, including its retained storage | 3,212,836,864 bytes | 3,145,728,000 bytes |
| Active prover allowance after 1 MiB session storage | 3,211,788,288 bytes | **3,144,679,424 bytes** |

Startup admission also retains the input reservation beside the existing
registry-setup/session allowance; its minimum becomes **118,556,360 bytes**.
Registry setup is still released before active proving, and its workspace is
not deducted again from later proof RAM. Cache admission, native configuration
and worker construction use the same reduced session allowance. No physical
service, GPU, decoder, registry or protocol cap is increased.

The Python planner adds the same 64 MiB to its worker host reservation without
changing witness geometry or adding another copy of the existing verifier
component. Exact-boundary tests admit the accounted sum and reject one byte
above it. The inherited full-size profile's known extra-host reservation moves
from **2,254,219,792** to **2,321,328,656 bytes**. Its missing enclosing lifetime
plan still prevents ordinary workload admission.

Two fresh, transaction-bearing **height-262144 finalizer proofs** passed through
the native C service on the desktop RTX 5080, UUID
`GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`. The cold and warm jobs use distinct
archived child DAGs with the same two-transaction terminal statement. They retain
one preprocessing setup and one cache hit, produce distinct randomized proof
bytes, and pass independent CPU verification; altered public counts reject.
CPU verification after observed worker exit also passes. All 16 proving
arithmetic stages report OpenCL, and all 11 component/whole-request scope reports
pass strict coverage checks.

Every emitted native-worker LDE plan uses the new **3,144,679,424-byte** allowance.
The worker remains capped at 3 GiB, with the same 1 GiB coordinator reservation
and 4 GiB enclosing test fleet. GPU managed/driver reservations remain 7/4 GiB.
Live cgroup samples verify the 3 GiB worker limit, zero swap and four-CPU quota;
the observed worker peak is 1,434,796,032 bytes across 169 samples, with no
OOM event. These sampled observations do not prove worst-case process RSS.

Validation records **811 passing native top-level test-case executions** and
**155 Python tests**, plus 13 child process cases. There are 18 final
host validation runs and two final native C-link/full-size runs. The CPU,
research and standard execution suites pass 273/268/268 cases. A fresh CPU
wallet passes both worker input slots and rejects wrong policy and altered
openings. Library/test and wide-CPU, no-stream and default checks pass. Test
builds use two codegen units; the production static library uses one. All native
work is serial and offline, with 3 GiB, zero-swap, four-CPU and 180-second
per-service limits.

Two preliminary test failures are preserved. A native cache-limit fixture still
subtracted only protocol storage; its expected cache budget now subtracts
decoded inputs too. A previously ignored fresh-wallet allocation oracle still
measured the old reference identity builder after public approval had switched
to the bounded builder. It now measures that bounded builder on a dedicated
one-thread Rayon pool using all-thread allocation accounting. These corrections
change test expectations, not proving or numerical verification. Subsequent
CPU suites and fresh-wallet qualification pass; no build or OOM failure occurred.

The audit checks 571 source/configuration hashes, every source archive including
the preserved preliminary fixture versions, and all 265 immutable parent
artifacts. It reconstructs production storage code and the Python planner AST
outside the declared reservation changes. Cleanup confirms no running Lattica
services or held GPU leases and 87 empty retained parent slices.

Evidence: [worker decoded-input reservation and full-size qualification](evidence/gpu-worker-decoded-input-reservation-2026-10-11.json).

The new evidence qualifies two full-size finalizer proofs with the tighter
allowance. It does not complete caller/bootstrap, allocator/runtime/stack,
engine/driver or all overlapping-phase RSS admission. Broader/live-cache
workloads, five matched throughput pairs, **24 hours AND 150 completed roots**,
multiple GPUs, AMD/Metal and pending Mac source integration remain open. No
throughput gain is claimed, and the overall goal remains active and incomplete.


### 9.135 Partition registered witness and PCS host allowances (2026-10-11)

`RegisteredProgram` previously checked that its witness/source/compiler/staging
reservation fit the assigned host allowance, then passed that same entire
allowance to PCS. Those independently admitted components could overlap. It now
subtracts the existing reservation and gives PCS only the positive remainder.
Preprocessing and fresh proofs use the same immutable PCS allowance; the
witness compiler retains its existing allowance and reservation arithmetic.
Short budgets, arithmetic overflow and a zero PCS remainder reject before setup.
CPU and non-witness configuration paths are unchanged.

| Qualification | Active host allowance | Existing witness reservation | PCS remainder |
|---|---:|---:|---:|
| Research, height 2048 | 1,072,693,248 | 621,929,748 | 450,763,500 |
| Standard, height 2048 | 1,072,693,248 | 621,979,080 | 450,714,168 |
| Full-size native finalizer, height 262144 | 3,144,679,424 | 1,906,561,040 | 1,238,118,384 |

Each registration reports both components and their exact sum. Every cold/warm
LDE plan and small-proof quotient budget uses the PCS remainder. The new retained
allowance field increases registered metadata from 5,624 to 5,632 bytes, measured
by the existing dynamic guard inside its unchanged 1 MiB reservation. The 64 MiB
decoded-input and 8 MiB protocol reservations remain outside the session.

Six fresh height-2048 Empty proofs passed on the desktop RTX 5080, UUID
`GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`, covering research and standard lanes,
cold setup, warm reuse and eviction/rebuild. Two fresh transaction-bearing
height-262144 finalizer proofs also passed through the C worker, using distinct
archived child DAGs with the same two-transaction terminal statement. There is
one full-size setup and one cache hit. All 16 proving arithmetic stages execute
on OpenCL, and all 47 component/whole-request scope reports pass. Independent CPU
verification and mutation rejection pass, including verification after GPU
shutdown or observed worker exit.

The full-size jobs took 67.024494176 and 16.901845727 seconds in this qualification.
The sampled worker peak was 1,105,272,832 bytes across 171 live cgroup samples,
with zero swap or OOM events. These are observations, not a worst-case RSS bound
or a matched throughput comparison. The worker, coordinator and enclosing fleet
caps remain 3/1/4 GiB; GPU managed/driver reservations remain 7/4 GiB.

Validation records **573 passing top-level test-case executions**, plus five
child process cases, across 17 successful native runs. Both resource suites pass
17 cases, both GPU execution suites pass 268 cases, and focused GPU tests pass.
CPU, research, standard, wide-CPU, no-stream and default compatibility checks
pass. All native work ran serially and offline with 3 GiB RAM, zero swap, four
CPUs, four Cargo/Rayon threads and a 180-second service limit. Test builds use
two codegen units; the production static library uses one. There were no native
failures. Existing ignored tests remain recorded in the evidence.

The audit validates all 571 source/configuration hashes and native source
archives, reconstructs production code outside the declared partition changes,
and checks all 426 immutable parent artifacts. Cleanup confirms no running
Lattica services or held GPU leases and 90 empty retained parent slices.

Evidence: [registered host budget partition qualification](evidence/gpu-registered-host-budget-partition-2026-10-11.json).

This partitions known overlapping payloads; complete process RSS admission still
requires caller/bootstrap, allocator/runtime/stack, engine/driver and remaining
phase accounting. Ordinary workload admission continues rejecting the incomplete
lifetime profile. Broader/live-cache workloads, five matched throughput pairs,
**24 hours AND 150 completed roots**, multiple GPUs, AMD/Metal and pending Mac
source integration remain open. No throughput gain is claimed. The overall goal
remains active and incomplete.


### 9.136 Bound native bootstrap identity serialization (2026-10-11)

Native worker identity construction previously cloned the complete assignment
and bootstrap into a JSON value, then serialized a growing output buffer before
enforcing the existing 1 MiB identity limit. It now serializes borrowed fields
twice: a bounded counting pass rejects oversized identities before output
allocation, and the second pass writes into exactly the admitted capacity.
Assignment, registry caps, policy bytes and launch paths are borrowed throughout.
The configuration digest shares the same named 1 MiB limit. Original bootstrap
encoding, registry/policy validation, hashing and HELLO identity semantics remain
unchanged. This bounds one startup output; caller input, decoding, allocator and
runtime ownership still need enclosing reservations.

Five fixtures compare the new bytes and digest with the original JSON-value
construction, including nested assignment objects, scalar values, escaped text,
Unicode, changed bootstrap fields and a large assignment. Each succeeds with
one allocation exactly equal to output length. The original fixtures request
162,404–466,145 cumulative bytes through 808–821 allocations; the new outputs
range from 8,220 to 106,541 bytes. Separate tests admit the exact 1 MiB boundary
and one byte below it, and reject three oversized identities without allocating
their output. These allocation requests are neither RSS nor throughput results.

CPU, research and standard execution suites pass 275/270/270 top-level cases.
The total is **816 passing top-level executions**, including one full-size GPU
test, plus 12 child process cases across
15 successful native runs. CPU/research/standard,
wide-CPU, no-stream and default compatibility checks pass. Host regression suites
do not initialize a GPU. All native work remains serial and offline, with 3 GiB
RAM, zero swap, four CPUs, four Cargo/Rayon threads and a 180-second service limit.
Test codegen units remain two; the production static library uses one.

The rebuilt C worker produces two fresh height-262144 finalizer proofs on the
desktop RTX 5080, UUID `GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`. Distinct archived
child DAGs carry the same two-transaction terminal statement. Cold/warm execution
retains one setup and one cache hit. All 16 arithmetic stages execute on OpenCL,
all 11 scope reports pass, independent CPU verification and mutation rejection
pass, and CPU verification succeeds after observed worker exit. The existing
registered host partition remains 1,906,561,040 bytes for witness/compiler storage
plus 1,238,118,384 bytes for PCS.

The two jobs take 68.944937202 and 16.686118472 seconds. The observed
worker peak is 1,168,334,848 bytes across 174
live cgroup samples, with zero swap or OOM events. These qualification samples
do not establish a worst-case RSS bound. Worker/coordinator/fleet caps remain
3/1/4 GiB, and GPU managed/driver reservations remain 7/4 GiB.

The audit verifies 571 source/configuration hashes, native source archives and
all 305 immutable parent artifacts. Source reconstruction confirms changes are
limited to identity serialization and its tests. The first source-audit controller
stopped on an extra blank line in its reconstruction; its preserved successor
corrects that comparison. No native failure occurred. Cleanup confirms no running
Lattica services or held GPU leases and 93
empty retained parent slices.

Evidence: [native bootstrap identity storage qualification](evidence/gpu-native-bootstrap-identity-storage-2026-10-11.json).

Complete caller/bootstrap decoding, allocator/runtime/stack, engine/driver and
remaining overlapping-phase RSS admission are still open. Ordinary workload
admission continues rejecting the incomplete lifetime profile. Broader/live-cache
workloads, five matched throughput pairs, **24 hours AND 150 completed roots**,
multiple GPUs, AMD/Metal and pending Mac source integration remain open. No
throughput gain is claimed; the overall goal remains active and incomplete.


### 9.137 Consume native bootstrap into checked worker ownership (2026-10-11)

The native C worker now consumes its decoded bootstrap before GPU initialization.
An owned handoff validates one `CheckedRegistry`, binds the expected profile
through a borrowed approved context, and moves the registry and launch path into
the worker configuration. The original encoded policy backing is released when
the handoff returns; the decoded policy context remains owned by the service.
This removes the previous second registry-identity construction, twelve cap
copies, and retention of the original bootstrap throughout the service loop.

The private parse-only helper grants no authority. Shape, executable, directory,
assignment, registry/profile and policy checks still finish before GPU
initialization. Public `Bootstrap::decode` and borrowed `config` retain their
validation behavior, and the existing HELLO descriptor and bootstrap wire format
remain unchanged. The new approved-context constructor is internal and still
checks the expected profile and registry shape. The 1 MiB bounded identity
serialization from 9.136 is unchanged.

Allocation tests cover heights 8, 1024 and 2²¹ in CPU, research and standard
configurations. The owned handoff produces identical descriptor bytes and policy
context while preserving the original launch-path backing. Its reduction in
cumulative allocation requests is exactly one bounded registry approval plus
24,576 cap bytes and twelve cap allocations. Across these fixtures, it removes
24,054,505–29,838,180 requested bytes per startup. These are allocation
requests, not measured RSS savings or transaction-throughput gains. Nine malformed
bootstrap variants and three short assignment variants still reject without GPU
initialization. Existing public bootstrap and worker protocol tests also pass.

Validation records **822 passing top-level test-case executions**, plus
11 child process cases, across
15 successful native runs. CPU/research/standard execution
suites pass 277/272/272 cases. CPU, research, standard, wide-CPU, no-stream and
default compatibility checks pass. Native work remains serial and offline with
3 GiB RAM, zero swap, four CPUs, four Cargo/Rayon threads and 180-second service
limits. Test codegen units remain two; the production static library uses one.

The first CPU test build is preserved: the new fixture called a nonexistent
`Config::identity_bytes` method. The fixture now calls the existing descriptor
byte helper, whose visibility is widened only under `cfg(test)`. The replacement
build and all subsequent checks pass. This fixture correction changes no
production configuration or proving behavior. No OOM event occurred.

The rebuilt C service produces two fresh height-262144 finalizer proofs on the
desktop RTX 5080, UUID `GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c`. Distinct archived
child DAGs have the same two-transaction terminal statement. Cold/warm execution
retains one setup and one cache hit. All 16 arithmetic stages execute on OpenCL,
all 11 scope reports pass, independent CPU verification and mutation rejection
pass, and verification succeeds after observed worker exit. The registered host
partition remains 1,906,561,040 bytes for witness/compiler storage plus
1,238,118,384 bytes for PCS.

The two jobs take 70.053425619 and 16.645652012 seconds. The sampled
worker peak is 1,425,489,920 bytes across 176
live cgroup samples, with zero swap or OOM events. Worker/coordinator/fleet caps
remain 3/1/4 GiB; GPU managed/driver reservations remain 7/4 GiB. These observations
are not a worst-case RSS bound or a matched throughput comparison.

The audit validates 571 source/configuration hashes and every native source
archive, including the preserved initial fixture, plus all 267 immutable parent
artifacts. Source reconstruction isolates the handoff, approved-context factoring
and test-only changes; numerical verification, proving arithmetic and physical
limits are unchanged. Cleanup confirms no running Lattica services or held GPU
leases and 94 empty retained parent slices.

Evidence: [native bootstrap ownership qualification](evidence/gpu-native-bootstrap-handoff-2026-10-11.json).

Caller input/decoding, allocator/runtime/stack, engine/driver and remaining
overlapping-phase RSS admission remain open. Ordinary workload admission still
rejects the incomplete lifetime profile. Broader/live-cache workloads, five
matched throughput pairs, **24 hours AND 150 completed roots**, multiple GPUs,
AMD/Metal and pending Mac source integration remain open. The overall goal remains
active and incomplete; no throughput promotion is supported by this checkpoint.

### 9.138 Paused Linux source checkpoint (2026-10-11)

The GPU implementation goal is now **paused**. This checkpoint preserves the
accumulated Linux GPU proving, distributed worker, host admission, integration,
documentation, and evidence changes. Section 9.137 remains the last finalized
GPU qualification; the work described below is only partially validated.

Assignment decoding now checks a 48 MiB startup allowance before reading the
assignment, bounds encoded input at 1 MiB, and applies a 32 MiB decoded payload
quota while constructing JSON values. Its read buffer and parser workspace are
bounded separately. This is a payload bound, not a complete RSS admission proof.
The three changed/new admission files match the source captured by the latest
validation runs; the full captured source inventory contains 573 files.

The serial controller completed ten native runs successfully: CPU, research,
and standard builds, execution suites, and compatibility checks, plus the
wide-CPU compatibility check. The execution suites passed 282, 277, and 277
top-level cases respectively, with 12 additional child process executions.
The no-stream compatibility check then failed with three `E0433` test compilation
errors: `assignment_tests.rs` references `spill_alloc` and `worker::typed`, which
are unavailable in that feature configuration. The controller exited with status
101. The default compatibility check, production static-library rebuild, and
new full-size GPU qualification were not run. No controller or matching
validation service remained active at checkpoint time. The existing artifacts
are retained unchanged under
`lattica-prover-p3/benchmark-results/gpu-startup-assignment-storage-20261011`.

Formatting checks for the three admission files, `git diff --check`, JSON syntax
checks for the evidence files, and verification of all 573 captured source hashes
passed. These checks do not resolve the no-stream failure or establish a new
GPU qualification. Resume with that feature-gating failure, then use fresh run
names for the outstanding compatibility, production, and GPU checks.

Staged whitespace review additionally flags existing trailing whitespace in the
archived Linux concurrency HTML report and final blank lines in three vendored
upstream changelogs. Those files are preserved verbatim. The staged whitespace
check passes with those four files excluded, and every captured source hash
matches the staged copy. Ignored build products and raw benchmark directories
are excluded from Git and retained in the local disk backup.

The remote `main` branch has newer Apple Silicon source and benchmark commits
through `510d02b`. This Linux working tree is preserved separately on
`checkpoint/gpu-proving-2026-10-11`; integration with those remote commits and
validation of the combined source remain future work. The original pending Mac
handoff instruction in this tree predates that remote integration. No Mac SSH
access was attempted. No throughput improvement or production promotion is
claimed.

Checkpoint receipt:
[partial assignment-decoder validation](evidence/gpu-startup-assignment-storage-checkpoint-2026-10-11.json).
