# Multi-GPU solving research

The grouped-eight research prover can run independent jobs on separate NVIDIA
GPUs. Each worker has one OpenCL engine and a per-user exclusive lease for its GPU UUID.
The shared compatibility lease excludes older workers that require all GPUs.

This path preserves q128, blowup16, cubic challenges, hiding, query proof of
work, and fresh proof randomness. Every completed job receives an independent
CPU audit and must produce a root proof below 2 MiB. Production activation and
four-wallet geometry remain gated.

## Compact prover data

`LATTICA_V2_GPU_COMPACT_PROVER_DATA=1` requires resident LDE commitments, GPU
quotient transforms, and compact GPU openings. It retains:

- Half of preprocessing, main, and permutation LDEs for quotient evaluation.
- The degree-bound prefix for quotient and randomization matrices.
- Only the degree-bound main/permutation prefixes after quotient evaluation.
- The original full salts and retained GPU Merkle trees.

Commitments still hash every LDE row. The planner reserves the reduced host
readback and reorder space before allocating them. Logical committed heights
are separate from stored prefix heights; the full-matrix accessor rejects
compact data.

The local `p3-fri 0.6.1` adapter samples queries in their original order, prepares
input openings together, and emits all original queries, including duplicates.
Each requested row is reconstructed from its degree-bound prefix using bounded
GPU transform tiles. Only queried rows are downloaded. The adapter records its
upstream source digest and license in `batched_fri.rs`.

## Resource policy

`block_v2_resources.py` records detection inputs and versioned GPU, CPU, and host
budgets for each attempt. The worker checks the actual cgroup limits and Rayon
pool before initializing its GPU or spill allocator.

Detection includes both the controller's cgroup ancestry and the systemd
workers' parent slices. A run starts the empty worker hierarchy before reading
its limits. Only the controller's previous fleet `MemoryMax` is excluded from
recalculation; parent RAM limits, CPU quotas, and CPU masks remain binding.
Read-only plans also record any worker slices that are not yet active.

| Resource | Assignment |
| --- | --- |
| GPU identity | `LATTICA_GPU_DEVICE_UUID`; an optional OpenCL index must agree |
| GPU capacity | Minimum of OpenCL capacity and NVIDIA free memory on that UUID |
| GPU headroom | Maximum of 512 MiB and 5% of capacity, rounded up to 256 MiB |
| GPU context | Maximum of 512 MiB and 125% of measured overhead, rounded up |
| Managed VRAM | Remaining capacity, rounded down to 256 MiB; individual allocations obey the device limit |
| CPU | Online, affinity, cpuset and ancestor quota limits; reserve one CPU when capacity permits, then divide Rayon threads by UUID |
| RAM | Available RAM after OS headroom, limited by ancestor cgroup headroom; reserve coordinator memory, then divide among workers |
| Spill | Scratch availability after filesystem headroom, divided among workers; include allocation headers and alignment |

Context overhead is measured against live managed allocations at a synchronized
checkpoint. It does not subtract independent peaks or count NVIDIA reserved
memory as worker overhead. Calibration is bound to UUID, driver/runtime, binary
and proof geometry. Bootstrap calibration uses at most half of free capacity
after headroom for managed allocations.

Tmpfs spill also consumes the worker's RAM budget. The workload model lists
allocations that overlap in each phase, including temporary mappings, pinned
buffers, caches, and driver host memory. The engine separately bounds GPU tiles
against its live allocation counters. RAM, VRAM, spill usage, CPU quotas, pool
sizes, and memory events are retained in evidence.

The current concurrent research path admits explicitly selected tmpfs scratch
without separate filesystem quotas. Other filesystems and quota-enabled mounts
are rejected until their quota accounting is qualified. There is no automatic
NVMe fallback.

## Runner

The tools are in `lattica-prover-p3/scripts/`:

- `block-v2-multi-gpu-run.py`: plan, run, reconcile interrupted attempts, and summarize evidence.
- `block_v2_resources.py`: detection and admission policy.
- `block-v2-multi-gpu-workload.json`: grouped-eight allocation lifetime model.
- `block-v2-multi-gpu-compare.py`: alternating sequential/concurrent comparisons.

A configuration supplies a pinned GPU worker, CPU worker, auditor, GPU UUIDs,
maximum concurrency, scratch directory, workload model, and FIFO jobs. Each job
pins its source wallet/key files and external profile, chain, and expected root.
An optional job GPU UUID fixes placement. `worker_slots` allows serial
qualification under the budgets intended for concurrent workers.
`qualification_mode: true` exercises stricter limits: RAM is the modeled peak
plus one 256 MiB quantum after rounding, and managed VRAM is capped at half the
detected capacity after headroom. These limits remain bounded by the actual
fleet plan. This avoids invalidating qualification for small later changes in
available memory.

```sh
python3 scripts/block-v2-multi-gpu-run.py --config run.json --plan
python3 scripts/block-v2-multi-gpu-run.py --config run.json --evidence /path/to/fresh-evidence
python3 scripts/block-v2-multi-gpu-run.py --summarize /path/to/fresh-evidence
python3 scripts/block-v2-multi-gpu-run.py --recover /path/to/interrupted-evidence
```

The controller records reservations before launching services. It rechecks
capacity before admitting another job and preserves active workers' budgets.
A process must terminate before its reservation is released. Recovery reconciles
existing attempts; it never restarts a proof or completes an interrupted job.

Concurrency greater than one requires a CPU-audited full-size qualification on
each GPU with the same binary and geometry, under budgets at least as restrictive
as the requested assignments. The comparison runner performs five alternating
rounds, each comparing two sequential jobs on the selected single GPU against
two concurrent jobs. It preserves individual latency, pair makespan, jobs/hour,
resource peaks, assigned and actual limits, and first/cached proof timings.

## Validation

The compact path has fixed-seed tests for commitment values, reconstructed rows,
salts, Merkle paths, full proof bytes, and challenger state. Resource tests cover
heterogeneous VRAM, fractional CPU quotas, host headroom, spill mapping overhead,
rounding, and interrupted-attempt reservations. GPU queue cleanup tests remain
part of the bounded engine suite.

Qualification and comparison results are recorded separately in repository
evidence. Existing frozen benchmark artifacts are retained unchanged.

## Completed hardware comparison — 2026-10-04

Five alternating rounds compared two sequential jobs on the faster RTX 5080
Laptop GPU against one job on each GPU concurrently. Both arms used the same
preserved GPU binary, public inputs, compact prover data, and fresh randomness.
The CPU has 24 logical processors: sequential workers received 23 Rayon
threads, while concurrent workers received 12 and 11. One CPU was reserved
for coordination.

| Round | Sequential pair (s) | Concurrent pair (s) |
| --- | ---: | ---: |
| 1 | 433.509 | 453.896 |
| 2 | 436.539 | 354.541 |
| 3 | 441.237 | 322.199 |
| 4 | 454.586 | 325.456 |
| 5 | 432.394 | 314.738 |
| **Median** | **436.539** | **325.456** |

Median pair completion time fell **25.4%**. Throughput at those medians rose
from **16.49 to 22.12 jobs/hour**, an increase of **34.1%**. Across the entire
suite, including the slower first concurrent pair, aggregate throughput was
16.38 versus 20.33 jobs/hour. Individual job latency increased: the median was
218.4 seconds sequentially and 315.6 seconds concurrently. Use the concurrent
path when multiple jobs are queued and total throughput is the priority.

All 20 comparison jobs and six qualification jobs passed their independent CPU
audits: **182 full-size proofs**, with 26 distinct root proofs of 1,683,948 bytes.
There were no memory-limit or OOM events. Concurrent workers peaked at
15.73–15.86 GiB of host RAM and 11.01–11.07 GiB of sampled process VRAM.
Their assignments varied with availability: 20.75–21.25 GiB RAM,
12.5–13.75 GiB managed VRAM, 512 MiB context allowance, and 14.5 GiB spill each.
The earlier serial qualification used tighter 19 GiB RAM and roughly
6.5–7 GiB managed VRAM limits.

The frozen release passed 36 focused Rust checks, including fixed-seed proof
equivalence on both GPUs. The final controller passed 17 resource and lifecycle
tests, a live resource-plan check, and formatting checks. No benchmark workers
remain running. The benchmark controller was preserved before the final
cleanup-timeout and worker-ancestor checks; the GPU binary is unchanged, and
the actual worker parents were unlimited during these measurements.

See [the complete evidence](evidence/block-v2-multi-gpu-2026-10-04.json) for
binary/input hashes, per-worker budgets, actual resource use, proof hashes,
qualification records, and cold/cached timings. Local frozen artifacts are in
`lattica-prover-p3/target/block-v2-multi-gpu-20261003-e`; the comparison records
are in `lattica-prover-p3/target/block-v2-multi-pairs-20261003-e`.

Production activation, four-wallet geometry, and concurrent NVMe spill remain
gated. The next performance investigation should measure host marshalling,
decoding, and transfers during concurrent execution; the first round showed
substantial host-time variability.
