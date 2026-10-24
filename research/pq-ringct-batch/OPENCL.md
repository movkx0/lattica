# OpenCL recursive aggregator

The optional `opencl` feature exposes `opencl::Aggregator` and the release
binary `pq-ringct-opencl-aggregate` in this worktree. It uses the same ordered
batch relation as the CPU prototype with explicit GPU registration/proving
requests. The full-mode command now uses one strict `ProvingContext` for GPU
graph lowering, child preparation/proving, and serial merges, with `FreshOnly`
proof caches. Each parent is verified on the CPU, and prepared proving state is
released between operations. CPU input validation, endpoint recomputation,
independent proof verification, symbolic compilation, and orchestration remain.
The input fixture already contains a native MatRiCT spend proof; this command
does not create that original spend proof on the GPU.

This migrated command requires new same-source qualification. The historical
results below used CPU child preparation and do not qualify the migrated path.

**Full standalone MatRiCT N3/N4 aggregation passed on the local RTX 5080.**
Both runs repeat one native fixture. CPU preparation verifies its complete
91-leaf graph; OpenCL proves two fresh merges for N3 and three for N4.
The earlier nested diagnostic and AES component also passed. AMD execution
remains unqualified. See the
[full accepted result](../pq-ringct/data/opencl-matrict-accepted-result-v1-20261022.json),
[historical diagnostic result](../pq-ringct/data/opencl-recursive-accepted-result-v1-20261021.json),
and [shared qualification guide](../pq-ringct/OPENCL.md).

The earlier byte diagnostic took 105.383 seconds of runner wall time. Its managed GPU
allocation peak was 8,498,815,240 bytes (7.915 GiB), inside the 8 GiB allowance;
its cgroup RAM peak was 1,329,864,704 bytes (1.239 GiB). The 1,994,782-byte final
artifact was decoded and verified after GPU shutdown. All strict GPU reports,
CPU verification, public/proof mutation checks, source preservation, and
terminal/reaping checks passed. Those diagnostic measurements do not include a full
MatRiCT graph and do not establish total compute savings.

## Small recursive diagnostic

Diagnostic mode proves a small byte relation, a parent checking two leaf
instances, and a second parent checking the first aggregate plus a leaf. It
therefore exercises real recursive aggregation across two layers with three
GPU proofs. It checks CPU verification, changed public values, changed proof
payloads, and a corrupted aggregate-child witness followed by restoration and
a valid parent. It serializes the final artifact and decodes/reverifies it
after GPU shutdown.

The accepted layers were:

| Layer depth | Padded rows | Measured layer duration | Rejected public mutations |
| --- | --- | --- | --- |
| 0: byte leaf | 8 | 19.378 s | 1 |
| 1: pair | 131,072 | 24.806 s | 2 |
| 2: aggregate plus leaf | 262,144 | 58.183 s | 3 |

The aggregate-child witness diagnostic returned `Unsatisfied` with the same
compiled program and public values, restored the original witness, and proved
a valid parent as its positive control. No invalid STARK proof was generated.
Layer durations are the program's measured stage durations; they are not a
matched CPU/GPU benchmark or isolated cold-start timings.

This mode is deliberately reported as a byte recursion diagnostic:
`complete_matrict_relation_qualified=false`. It does not establish a complete
RingCT transaction or complete MatRiCT graph.

After the successful probe sequence in the shared guide, build and check the
aggregator, then run diagnostic mode. Keep all source inputs unchanged between
the build, prerequisite probe, and aggregate run:

```sh
python3 research/pq-ringct/tools/opencl_qualify.py \
  --target aggregate --stage build --label opencl-aggregate-build-v3 \
  --seconds 3600 --execute --exclusive-window

python3 research/pq-ringct/tools/opencl_qualify.py \
  --target aggregate --stage check --label opencl-aggregate-check-v3 \
  --seconds 3600 --execute --exclusive-window

python3 research/pq-ringct/tools/opencl_qualify.py \
  --stage aggregate --mode diagnostic --label opencl-recursive-v1 \
  --build-label opencl-aggregate-build-v3 --probe-label opencl-byte-v3 \
  --host-mib 8192 --device-mib 8192 --seconds 7200 \
  --execute --exclusive-window
```

The managed device allowance is 8 GiB with a separate 4 GiB context reserve.
The local RTX 5080 reports 16,303 MiB in NVIDIA inventory; OpenCL exposes
15,930.125 MiB, which is the capacity used for device admission. A 16 GiB host cgroup and four
Rayon threads bound this diagnostic; these host limits do not allocate VRAM.
The successful diagnostic used `opencl-byte-v3` as its same-source prerequisite.
The runner refuses a missing, failed, or changed-source prerequisite probe.
Use fresh run labels if the example labels already exist.

## Full repeated-fixture MatRiCT mode

Current full mode verifies an existing native fixture, lowers its relation on
the GPU, and freshly proves its complete graph using the strict GPU APIs. The
one resulting graph proof is deliberately repeated at the requested three or
four ordered leaves. `FreshOnly` prohibits cached component-proof reads; it
does not turn repeated leaves into distinct transactions. The result records
`fresh_complete_graph_proofs=1`, `unique_fixture_statements=1`,
`repeated_child_proof=true`, and `fresh_distinct_transaction_qualified=false`.
The historical `--allow-cpu-child-preparation` switch is rejected with an
instruction to remove it; no CPU policy override remains.

The wrapper retains its host/device admission and fixed cryptographic profile.
The shared GPU context requires the native allowance to fit within its host
allowance; `--native-mib` greater than `--host-mib` is rejected before launch.
Neither allowance is expanded automatically.
A plan for the migrated command can be inspected without starting a workload:

```sh
python3 research/pq-ringct/tools/opencl_qualify.py \
  --stage aggregate --mode matrict --label opencl-matrict-gpu-child-n3-new \
  --build-label NEW_MATCHING_BUILD --probe-label NEW_MATCHING_BYTE_PROBE \
  --fixture PATH_TO_EXISTING_NATIVE_FIXTURE.json \
  --cache-dir .tools/pq-opencl/aggregate-cache/NEW_SOURCE_SPECIFIC_DIRECTORY \
  --count 3 --host-mib 32768 --native-mib 32768 --device-mib 8192 \
  --max-rows 1048576 --seconds 86400
```

### Historical CPU-child preparation results

The accepted N3/N4 results below reconstructed the complete 91-leaf graph and
trusted keys on CPU before starting OpenCL. They use
`fixture_pattern=repeated_single_fixture`; they do not establish distinct
ledger transactions or reproduce the CPU [A,B,A] / [A,B,A,B] workload.

| Run | CPU preparation | Summed merge timers | Serialized proof/public-value bytes |
| --- | --- | --- | --- |
| `opencl-matrict-n3-v1` | 30,380.287 s | 130.028 s | 1,994,837 |
| `opencl-matrict-n4-r47-v1` | 8,164.637 s | 161.699 s | 1,995,099 |

Whole-run timings and GPU/host peaks are in the shared guide. Merge timers
include compilation, registration, proving, and CPU verification. Both
runs reuse the same source-specific cache path; their timings establish
neither cold-start latency nor a matched speedup. N4 recorded 335 CPU
preprocessing reports and generated no fresh CPU proofs. Cache hits can skip
CPU proof generation after trusted-key registration, so CPU stage-report
counts are not a completion fraction.

The accepted ordered merges use `[first, count]` spans:

```text
N3: [0,1] + [1,1] -> [0,2] (level 1); [0,2] + [2,1] -> [0,3] (level 2)
N4: [0,1] + [1,1] -> [0,2] (level 1); [2,1] + [3,1] -> [2,2] (level 1); [0,2] + [2,2] -> [0,4] (level 2)
```

N3/N4 produced two/three fresh GPU merge proofs and four/six strict GPU
stage reports. Each final proof rejected all 25 public-value mutations
and one proof-opening mutation. The original graph was released before
final verification. Decoded persisted proofs were CPU-verified after
GPU shutdown. Full runs do not repeat the separately accepted CPU
aggregate-child witness negatives or the nested GPU witness diagnostic.

The historical full runs used these v4 prerequisites and shared cache. These
are archived invocations, not commands for the migrated binary; its removed
CPU-preparation switch now causes an actionable error:

```sh
python3 research/pq-ringct/tools/opencl_qualify.py \
  --stage aggregate --mode matrict --label opencl-matrict-n3-v1 \
  --build-label opencl-aggregate-build-v4 --probe-label opencl-byte-v4 \
  --allow-cpu-child-preparation \
  --fixture ../pq-ringct-research/.tools/pq-child-cache/pq-ringct-batch-accept-recovery-v2-r1/fixture-0.json \
  --cache-dir .tools/pq-opencl/aggregate-cache/matrict-fixture0-v1 \
  --count 3 --host-mib 32768 --native-mib 32768 --device-mib 8192 \
  --max-rows 1048576 --seconds 86400 \
  --execute --exclusive-window

python3 .tools/pq-opencl/control/run-pq-opencl-n4-stricter-resource-profile-v2.py \
  --label opencl-matrict-n4-r47-v1 \
  --wrapper-sha256 186de083eb77dfb87cc3d560e55aa49c001e5db252eb4b2e9fc97852bb6210e1 \
  --execute --exclusive-window
```

These labels already identify completed evidence. Use fresh case labels
for reruns; the build and byte-probe records must match current sources.
The historical diagnostic above retains its original v3 prerequisites.
Do not relabel or import an old cache for a changed source identity.

The accepted cases used these process resource policies. The shared guide's
general admission table describes the unmodified runner's defaults:

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

## Result and artifact contract

The final JSON uses `lattica-pq-opencl-recursive-aggregation-v1`. Both modes
must report the unchanged 128-query, 16-fold-blowup, Goldilocks cubic, hiding
profile; strict GPU stage coverage; CPU verification and mutation rejection;
actual GPU allocation/commitment counters; and resource/device identities.
Full mode additionally records ordered merge spans, aggregate-child counts,
91-leaf coverage, 25 public-value mutations, GPU child-preparation wall time,
`FreshOnly` cache counters, and release of the original graph before final
verification. The `context` report must show a closed strict GPU session, zero
native CPU proving calls, and complete successful native/preparation/proving
accounting. `gpu_child_preparation_begin` / `gpu_child_preparation_end` bound
child-stage receipts; merge receipts follow them. Independent CPU checks are
included in the preparation wall time. Historical CPU-preparation fields and
events are not accepted as evidence for this migrated command.

Artifacts default to `.tools/pq-opencl/artifacts/LABEL.postcard`; output must
be a new file inside the isolated OpenCL tools directory. The runner checks
its byte count and SHA3-256 against the result and records SHA256 separately.
Artifacts exclude the trusted registered key, original statements, and
ledger body. Sizes measure serialized public values and proof payloads,
not transactions or blocks.

The inherited CPU `README.md` and frozen CPU acceptance/build helpers remain
unchanged. Use the guarded OpenCL runner for these binaries: the frozen CPU
helpers intentionally retain different source, binary, and cache identities.
Accepted full GPU runs establish execution correctness for the measured
repeated-fixture scope. They do not establish total compute savings,
production throughput, ledger integration, or cross-vendor speedup.
