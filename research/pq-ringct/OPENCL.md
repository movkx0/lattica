# OpenCL qualification for post-quantum RingCT research

The `codex/pq-ringct-opencl` worktree provides an explicit OpenCL proving path
for NVIDIA and AMD GPUs. It reuses the prover's field arithmetic, transforms,
commitments, openings, and recursive verifier circuits. The CPU acceptance
worktree and the separate CUDA worktree remain independent.

**Qualified on the local NVIDIA RTX 5080:** the byte probe, AES recursive
component, nested binary diagnostic, and full standalone MatRiCT aggregation
for N3 and N4. The full runs repeat one native fixture: CPU preparation
verifies the complete 91-leaf graph, then OpenCL proves two fresh merges
for N3 and three for N4. **AMD execution remains unqualified.** These are
historical CPU-child results. The current full-mode CLI has been migrated to
strict GPU child preparation with `FreshOnly` proof caches and requires new
same-source qualification; those historical results do not qualify that change.
See [the full accepted result](data/opencl-matrict-accepted-result-v1-20261022.json) and
[the historical diagnostic result](data/opencl-recursive-accepted-result-v1-20261021.json).

The NVIDIA inventory reports 16,303 MiB of device memory; the OpenCL runtime
exposes 16,703,946,752 bytes (15,930.125 MiB). Accepted runs used OpenCL device
index 0 with driver 615.78.08. These are measured configurations, not a claim
that another driver or GPU vendor has passed.

## Accepted local measurements

| Run | Runner wall time | Managed GPU allocation peak | Whole-process cgroup RAM peak |
| --- | --- | --- | --- |
| `opencl-aes-v2` | 85.355 s | 8,509,103,304 bytes (7.925 GiB) | 1,638,834,176 bytes (1.526 GiB) |
| `opencl-recursive-v1` | 105.383 s | 8,498,815,240 bytes (7.915 GiB) | 1,329,864,704 bytes (1.239 GiB) |
| `opencl-matrict-n3-v1` | 30,512.858 s | 8,536,648,960 bytes (7.950 GiB) | 43,645,042,688 bytes (40.648 GiB) |
| `opencl-matrict-n4-r47-v1` | 8,330.825 s | 8,536,630,880 bytes (7.950 GiB) | 15,578,959,872 bytes (14.509 GiB) |

The AES wrapper has 262,144 rows; its 32.871 s proving phase includes
verification inside `PreparedNode::prove()` and excludes registration.
The nested diagnostic artifact is 1,994,782 bytes.

Full N3/N4 CPU preparation took 30,380.287 s and 8,164.637 s;
their summed merge timers were 130.028 s and 161.699 s.
Merge timers include compilation, registration, proving, and CPU verification.
The full runs share a source-specific cache. N4 recorded 335 CPU preprocessing
reports and generated no fresh CPU proofs. These wall times are not a matched
performance comparison or a cold-start benchmark.

All listed runs ended successfully with subprocesses reaped and source
preservation checks passing. Managed GPU peaks exclude untracked
driver/display/context allocations; runner wall times include observation
and cleanup. Proof payload sizes are not transaction or block sizes.

The accepted cases used these process resource policies:

| Case | MemoryMax | MemoryHigh | Fresh available RAM required |
| --- | --- | --- | --- |
| N3 | 48 GiB | 46 GiB | 50 GiB |
| N4 | 47 GiB | 45 GiB | 49 GiB |

N3 used the frozen runner. N4 used the separately reviewed [stricter resource wrapper](../../.tools/pq-opencl/control/run-pq-opencl-n4-stricter-resource-profile-v2.py). The prover binary, source, environment, and proof profile stayed unchanged. Both policies retain two GiB between MemoryHigh and MemoryMax and another two GiB between MemoryMax and fresh admission.

Both runs used zero swap and eight Rayon threads. The separate 32 GiB host/native allowances are admission limits within the process cap. GPU work uses an 8 GiB managed allowance plus a 4 GiB context reserve; that reserve is not a measurement or bound on total physical VRAM. There is no automatic budget expansion or proof-profile reduction.

### Earlier failure and CPU diagnostics

The original [N4 attempt](../../.tools/pq-opencl/runs/opencl-matrict-n4-v1.json) (`opencl-matrict-n4-v1`) failed during CPU graph preparation with `Verification(InvalidOpeningArgument(FinalPolyMismatch))`. Its recorded stages were CPU-only. The service exited with code 1 (`Result=exit-code`); its host peak was 44,966,952,960 bytes (41.879 GiB) under a 48 GiB cap. This was not a recorded OOM kill.

The [registration diagnostic](../../.tools/pq-opencl/diagnostics/cpu-parent50-20261022/registration/runs/pair50-registration-replay-v1.json) passed in 125.749 s. Reconstructed leaf and parent registrations matched the expected manifests, cache identities, and preprocessing caps. The cached parent `[50,2]` proof verified in two separately reconstructed registrations. It generated no fresh proofs and performed no GPU work.

The [fresh-parent diagnostic](../../.tools/pq-opencl/diagnostics/cpu-parent50-20261022/fresh-proof/runs/pair50-fresh-proof-replay-v2.json) passed in 175.938 s, including 73.208 s to generate one fresh CPU parent proof. Its host peak was 42,836,447,232 bytes (39.895 GiB). All four checks passed: the returned proof and its serialized/decoded form each verified through both verifier entry points in the same implementation. These are separate verifier objects, not independent cryptographic implementations. The diagnostic performed no GPU work.

The diagnostics preserved the original caches and source; all three runs recorded successful process cleanup. They did not reproduce or resolve the original failure. The original requested cache key was not logged and cannot be equated conclusively with the key reconstructed later. A successful single-parent diagnostic does not establish full aggregation acceptance, and a subsequent full-run pass does not explain the earlier failure.

## Entry points and scope

| Entry point | What it proves | What passing establishes |
| --- | --- | --- |
| `pq-ringct-opencl-probe --stage pq-byte` | A small PQ byte/modular relation | Strict GPU execution, CPU verification, and public/proof mutation rejection for that relation. |
| `pq-ringct-opencl-probe --stage pq-aes-component` | The typed recursive verifier of a native AES component proof | A recursive component works on this GPU. Native AES child preparation runs on the CPU. |
| `pq-ringct-opencl-aggregate --mode diagnostic` | A byte leaf, a parent verifying two leaf instances, then a parent verifying the aggregate and a leaf | Three actual GPU proofs and two recursive layers, including an aggregate-child witness check. This is a small recursion check, not a complete MatRiCT graph. |
| `pq-ringct-opencl-aggregate --mode matrict` | Ordered N3/N4 batches of one repeated complete MatRiCT fixture | Current command uses strict GPU graph preparation/proving and fresh GPU merges; new qualification pending. Historical accepted results used CPU child preparation. One graph proof is repeated, so neither path qualifies distinct ledger transactions. |

The batch API holds one OpenCL session and proves merges serially. It carries
odd tails unchanged and releases prepared proving state between merges. See
[the recursive aggregator guide](../pq-ringct-batch/OPENCL.md) for its API,
commands, artifact scope, and full graph preparation requirements.

All stages preserve the existing proof profile: 128 queries, 16-fold blowup,
Goldilocks cubic extension, and hiding. Enabling the Cargo `opencl` feature
only compiles support. Actual qualification requires the explicit
`gpu-required` policy, all owned GPU switches, successful strict stage reports,
and observed completed device work. CPU verification and host orchestration
remain intentional. Silent CPU proving fallback cannot satisfy qualification.

## Admission and memory limits

The CPU baseline and N3/N4 CPU acceptance have completed. Admission checks
exact hashes of their passed, terminal, reaped records. A historical systemd
unit may be absent after reboot; if it still exists, its state must agree with
successful terminal completion. This replaces the old requirement to wait for
a live CPU baseline service.

Every execution still requires fresh available RAM, disk space, no competing
local compiler/prover workload, and coordinator admission through
`--exclusive-window`. The runner locks its own jobs, but does not schedule the
separate CUDA worker. Do not run CUDA and these GPU stages simultaneously.
Known protected desktop/session processes are recorded explicitly when Linux
prevents inspection; unknown inaccessible same-user processes refuse admission.

The table below describes the unmodified runner's defaults. The accepted N4
run used the reviewed wrapper's 47 GiB MemoryMax, 45 GiB MemoryHigh, and
49 GiB fresh-RAM requirement shown above.

| Limit | Build / CPU checks | Byte / recursion diagnostic | AES component probe | Full MatRiCT aggregate |
| --- | --- | --- | --- | --- |
| Whole process cgroup RAM cap | 8 GiB | 16 GiB | 40 GiB | 48 GiB |
| MemoryHigh | 6 GiB | 14 GiB | 38 GiB | 46 GiB |
| Fresh available host RAM required | 10 GiB | 20 GiB | 44 GiB | 50 GiB |
| Rayon threads / CPU quota | 2 / 200% | 4 / 400% | 4 / 400% | 8 / 800% |
| Swap allowance | 0 | 0 | 0 | 0 |
| Default runtime | 30 minutes | 30 minutes | 30 minutes | 30 minutes; explicitly raise for full preparation |
| Maximum runtime argument | 2 hours | 2 hours | 2 hours | 24 hours |

The AES recursive wrapper retains a conservative CPU LDE admission bound even
when the GPU backend tiles its work. Its initial 8 GiB host allowance was
rejected before registration. The AES-only runner path now accepts
`--host-mib 32768` inside a 40 GiB process cap, with 44 GiB fresh available RAM.
This does not increase the byte/diagnostic caps or the GPU allowance, and does
not claim that the full host allowance will actually be allocated.

Host RAM and VRAM are separate limits. Byte-only smoke checks can begin with a
2 GiB managed device allowance. The accepted AES and recursive configuration is
**8 GiB managed VRAM plus a 4 GiB context/driver reserve**. Against the OpenCL-exposed
15,930.125 MiB capacity, that leaves 3,642.125 MiB outside those reservations.
Existing desktop use also consumes VRAM. The context reserve is an admission
allowance, not an enforced bound on all driver allocations. The prover enforces
its managed allocation budget and the device's allocation limits; the host
cgroup does not cap VRAM. Allocation or geometry rejection fails the stage
without automatically increasing budgets or weakening the proof profile.

The unmodified full MatRiCT runner separately permits a 32 GiB host proving
allowance and a 32 GiB native preparation allowance inside its 48 GiB
whole-process cap. The accepted N4 wrapper retains those allowances inside
its tighter 47 GiB process cap.
Those are admission ceilings, not measured requirements or extra VRAM. The
shared GPU context also requires `--native-mib <= --host-mib`; incompatible
limits are rejected before launch rather than enlarged. Full
mode consumes a preexisting native MatRiCT fixture; creating that original spend
proof remains a separate CPU research operation. After CPU input validation,
one strict OpenCL context performs GPU relation lowering, child preparation and
proving, and aggregation. Endpoint/proof checks, symbolic compilation, and host
orchestration still use CPU work. `FreshOnly` prevents proof-cache reads, while
source markers continue to reject caches from a different compiled source.
The obsolete `--allow-cpu-child-preparation` switch must be removed; the CLI and
wrapper reject it and cannot change policy to CPU. See the batch guide for the
current result contract and a workload-free command plan.

## Guarded probe commands

Run from the OpenCL worktree root. A command without `--execute` prints a plan
and starts no compiler, test, device context, or proof:

```sh
python3 research/pq-ringct/tools/opencl_qualify.py --target probe --stage build
python3 research/pq-ringct/tools/opencl_qualify.py --stage probe --relation pq-byte
python3 research/pq-ringct/tools/opencl_qualify.py --stage aggregate --mode diagnostic
```

The isolated offline Cargo cache and both research lockfiles have been prepared.
Builds use Rust 1.96.0, `--locked --offline`, `.tools/cargo-opencl`, and
`.tools/target-opencl`. The runner neither fetches dependencies nor substitutes
a shared writable cache. Its embedded baseline metadata was copied exactly
from the CPU worktree; the original remains unchanged.

Full-run evidence uses `opencl-probe-build-v4`, `opencl-byte-v4`, and
`opencl-aggregate-build-v4`; their manifests match the accepted full runs.
The earlier diagnostic examples below retain their original labels.

These example labels are linked consistently. Labels are single use: after a
failed or completed run, choose a new label and update downstream
`--build-label` and `--probe-label` references to the successful records.
Execute only within the admitted exclusive window:

```sh
python3 research/pq-ringct/tools/opencl_qualify.py \
  --target probe --stage build --label opencl-probe-build-v2-r3 \
  --seconds 3600 --execute --exclusive-window

python3 research/pq-ringct/tools/opencl_qualify.py \
  --target probe --stage check --label opencl-probe-check-v3 \
  --seconds 3600 --execute --exclusive-window

python3 research/pq-ringct/tools/opencl_qualify.py \
  --stage probe --relation pq-byte --label opencl-byte-v3 \
  --build-label opencl-probe-build-v2-r3 --host-mib 8192 --device-mib 8192 \
  --execute --exclusive-window

python3 research/pq-ringct/tools/opencl_qualify.py \
  --stage probe --relation pq-aes-component --label opencl-aes-v3 \
  --build-label opencl-probe-build-v2-r3 --host-mib 32768 --device-mib 8192 \
  --seconds 7200 --execute --exclusive-window
```

The `check` stage runs focused CPU tests. Device probes use release binaries;
debug constraint auditing conflicts with strict GPU proving policy. Every
probe checks the successful build's binary and source identities. Changes to
any hashed source require a new matching build/probe record before aggregation.
Records and raw logs are under `.tools/pq-opencl/runs/`. The runner stops the
service, verifies process/cgroup termination, audits source preservation, and
validates proof reports before accepting a run. Sandbox sessions without the
host systemd bus or GPU devices cannot execute these stages.

## NVIDIA and AMD portability

`--device-index` uses the backend's OpenCL GPU enumeration, which may differ
from vendor management-tool order. Results retain device name, driver,
identity, limits, and managed allocation observations. Device-level workgroup
admission is not proof that every compiled kernel launches successfully; both
vendors need actual execution evidence using the same relation and profile.

The portable kernels use OpenCL integer operations. NVIDIA-specific shuffle
and quotient paths are selected conditionally; AMD uses the portable hashing
and quotient paths. The research runner does not require NVIDIA management
tooling, but the separate production worker-budget path still uses
`nvidia-smi` and NVIDIA-specific resource scripts. Passing an AMD research
probe would not qualify that production accounting path. OpenCL supplies no
standard process-attributed VRAM counter, so a production AMD provider must
independently demonstrate correct device mapping, allocation/context coverage,
and rejection when accounting is unavailable.

Correctness evidence must precede performance claims. Neither a small
recursive diagnostic nor a full repeated-fixture aggregate measures production
transaction size, cold-start latency, ledger validity, or total compute
savings. Compare like-for-like CPU and GPU stages only after qualification,
including CPU preparation and transfer costs where measured.
