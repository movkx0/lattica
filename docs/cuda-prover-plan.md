# CUDA GPU prover implementation plan

Build a native CUDA backend for Lattica's existing prover, then optimize the
dominant arithmetic and command-submission costs. Keep the current proof
formats, verification rules, security parameters, and worker resource limits.
The initial targets are Linux workers on Tesla V100 and desktop RTX 5080, with
the same job interface usable by a future distributed worker pool.

This plan is based on `ec1c93700d9f3755446ba143501efb136294729e`, pulled into
`main` from `origin/main` on 2026-10-18. The pull includes the V100 benchmark
harness and the query reconstruction optimization. CUDA implementation is in
progress.

## Current checkpoint

The opt-in `gpu-cuda` feature provides an experimental Linux transport: explicit
device selection, shared OpenCL/CUDA leases, bounded allocations, private-buffer
cleanup, NVRTC compilation, kernel launches and completion events. Native CUDA
now implements base/quadratic/cubic field arithmetic, tiled coset transforms,
query reconstruction from device prefixes, Poseidon2 commitments, and resident
quadratic/cubic quotient evaluation with partitioned prefix reconstruction.
Resident Poseidon2 transcripts now support observation, sampling, bounded
snapshots and deterministic grinding. An explicit CUDA challenger adapter
produces a mixed proof accepted by the unchanged CPU verifier; it does not
select CUDA for the other proving stages.
Commitment fragments preserve padding-free absorption across column boundaries;
fresh salts remain explicit caller inputs. Merkle nodes stay on the GPU, with bounded cap and
path reads that preserve query order and duplicates. Matrix geometry, immutable
roots and the query memory planner are shared with OpenCL. Intermediate
polynomials remain on the device; explicit transfer counters check this boundary.
The public AIR compiler and its 64-instruction specialization/liveness pass are
shared between OpenCL and CUDA. CUDA prepares immutable public program handles;
unsupported specialization shapes retain GPU interpretation. Current/next rows,
alpha powers, selectors, constraints and vanishing-polynomial division execute
on CUDA, with only a public domain-validity word read back per evaluation.

Wallet and recursive proofs are not yet routed through CUDA. Cached twiddle
tuning, PCS/backend integration, complete proof-stage coverage, controller
admission and pool integration remain outstanding. Prepared quotient handles
support reuse without retaining witnesses or sampled parameters. A bounded
public program cache now supports repeated preparation within an evaluator;
disk and cross-worker caches remain absent. Use the existing OpenCL backend
for complete proof benchmarks at this checkpoint.

Install the pinned development components with
`python3 lattica-prover-p3/scripts/setup-cuda-toolchain.py --prefix .tools/cuda-12.9.1`.
This leaves the system driver unchanged. From the prover crate, build with
`cargo test --locked --no-default-features --features gpu-cuda,block-v2-capacity-128 --lib cuda_compute:: --no-run`.
Run the resulting test executable in a bounded 3 GiB, four-thread, zero-swap
service with `LD_LIBRARY_PATH` pointing to the toolchain's `lib` directory and
`LATTICA_GPU_DEVICE_UUID` selecting the device. The filter
`cuda_compute:: --include-ignored --test-threads=1` covers arithmetic, transforms,
query reconstruction, salted commitments, quotient evaluation, host limits and device lifecycle
checks. The separate
`gpu_matrix:: --test-threads=1` filter checks shared roots and planner boundaries.
These tests do not establish a complete CUDA prover or transaction throughput.

The [2026-10-18 algebra qualification](evidence/cuda-algebra-2026-10-18.json)
passed 15 CUDA host/device tests and four shared planner/root tests on the desktop
RTX 5080. Compute Sanitizer reported zero memory errors and leaks across 14 tests;
the deliberate missing-kernel test passed outside memcheck. Transform/query race
and synchronization checks also passed. OpenCL regression coverage passed 144
host tests and six device tests. CPU-only and aarch64 Apple Metal library builds
checked successfully. NVRTC compiled the field and transform kernels for both
Volta and Blackwell; V100 CUDA execution and Metal execution remain untested.
The evidence records source and executable hashes for the implementation under
test, including its uncommitted source files at qualification time.

The [commitment qualification](evidence/cuda-commitments-2026-10-18.json) adds
independent CPU oracles for Poseidon2, salted leaves, partial-rate absorption,
Merkle caps and paths, plus bounded readback and allocation rejection tests.
All 22 CUDA tests and four shared planner tests passed on the RTX 5080.
Memory, race and synchronization checks passed across 21 tests; the intentional
missing-kernel API-error test passed outside the sanitizer runs. CPU-only,
OpenCL, Apple Metal cross-compilation and standalone CUDA builds also passed.
The new tests exposed a default-stream ordering gap: legacy clears and copies
could return before the nonblocking compute stream consumed their results.
Explicit completion now precedes compute and private-buffer retirement, with
a larger-buffer regression covering initialization, uploads and device copies.
These correctness results do not qualify complete CUDA proofs or performance.

The [quotient qualification](evidence/cuda-quotient-2026-10-18.json) passed all
30 CUDA host/device tests, four shared planner tests, 33 OpenCL host tests and
two OpenCL device comparisons. The CUDA comparisons cover both field extensions,
mixed physical row orders, 16,384-row tile boundaries, generic fallback and
specialized register reuse. The real machine AIR with LogUp matched the upstream
CPU Batch-STARK quotient evaluator. Quotient outputs were consumed by CUDA
commitments before any polynomial readback. Compute Sanitizer found zero memory
errors, leaks, race hazards or synchronization errors across 29 tests; the
intentional missing-kernel test passed separately. CPU/OpenCL libraries, Apple
Metal cross-compilation and standalone CUDA builds passed. Public programs have
a 16 MiB per-entry and 64 MiB aggregate retained host allowance, with at most 32
live prepared handles per runtime. The first OpenCL device check required a
retry with `LATTICA_V2_GPU_RETAIN_TREES=1`; that setup failure is retained in the
evidence. V100 execution and complete CUDA proofs remain unqualified.

The [OpenCL comparison at `bce8830`](evidence/gpu-tuning-rtx5080-2026-10-18.json)
completed 56 four-entry trials with full stage coverage and independent CPU root
audits. Event batching reduced median aggregation time from 23.892 to 23.402
seconds (2.05%); combined tuning increased it by 25.82%. Optional candidates
remain disabled by default while wider-workload qualification is outstanding.

The [partition qualification](evidence/cuda-partition-2026-10-18.json) covers
whole-operation byte admission and reconstruction of up to 256 component cosets.
Main, preprocessing and permutation prefixes may have different heights and row
orders. A single coset aliases compatible inputs; larger domains expand one
component at a time and scatter into a resident quotient. Only public domain
status and component shifts are downloaded. A 64-column case whose full main
LDE needs a 4 MiB allocation succeeds with a 2 MiB managed budget and a 512 KiB
allocation ceiling, including a resident commitment checked against the CPU.
This remains an experimental primitive, not an integrated CUDA prover.

The opt-in `cuda_partitioned_quotient_benchmark` test compares materialized and
partitioned cubic quotient evaluation on the same inputs. Set
`LATTICA_CUDA_PARTITION_BENCHMARK=1` and run that test with `--ignored
--test-threads=1 --nocapture` in the bounded CUDA service described above. It
reports cold preparation separately, then two warmups and five alternating pairs
for each case, with an independent CPU audit of every output. The benchmark
prints its build profile; debug-host timings are exploratory and do not qualify
production performance. It does not measure recursive proofs or transactions.

The [post-push microbenchmark at `968e403`](evidence/cuda-partition-benchmark-2026-10-18.json)
completed 20 measured samples and eight warmups, all independently CPU-audited.
With 16 cosets, median materialized/partitioned times were 1.09/13.32 ms; with
256 cosets, they were 1.04/175.41 ms. The measured command counts grew from 21
to 285 and 4,349, respectively. Partition byte plans required about 1.27 MiB and
263 KiB including retained inputs and public code; the full main LDE alone needs
4 MiB. These are small synthetic AIR workloads using debug host orchestration.
They demonstrate a memory/latency tradeoff, not a proving speedup. Future CUDA
backend admission should favor materialization when it fits. Adaptive component
sizes and scratch/command reuse need qualification before partitioning is used
as a performance optimization.

The [program-cache qualification](evidence/cuda-cache-2026-10-18.json) covers
public AIR reuse across proof attempts. `prepare_cached(profile, program, mode)`
keys the entire bytecode/layout, profile, specialization policy, generator and
kernel sources, compiler options, target, driver API and the loaded NVRTC library
instance. This identity is intentionally local to one evaluator/process; disk
or distributed reuse will need toolchain binary hashes including NVRTC builtins.
The default cache holds at most eight entries, 32 MiB of retained public host
storage and 8 MiB of device IR buffers, reduced for smaller runtime allowances.
These are additional cache ceilings within the existing runtime budgets, not
extra memory reservations. Native modules remain subject to the runtime module
limit and its separate context allowance.

Concurrent preparation of the same program compiles one copy. Cache hits allocate no device buffers and issue no uploads or GPU launches. Eviction plans all required releases before
retiring the least recently used unpinned entries; impossible requests preserve
existing entries. Active handles retain their allocations and host charges after
cache retirement, and failed runtimes reject hits as well as misses. Public
metadata includes hit, miss, eviction and retained-byte counters. Cache tables
and handle overhead are conservatively charged with retained programs. The real
machine AIR/LogUp oracle now exercises this cached preparation path. This is a
correctness/resource checkpoint; no complete-proof speedup is claimed.

The [transcript qualification](evidence/cuda-transcript-2026-10-18.json) passed
50 native CUDA tests, five challenger tests and four shared planner tests.
Memory, race and synchronization checks passed across 49 native tests and three
challenger device tests per tool. Three OpenCL challenger device tests and the
existing CPU/OpenCL/Metal build and quotient regression checks also passed.
The device owns the duplex state; public sampling can read back bounded values,
while resident samples feed native commitments without host transfers. Shared
family retirement prevents continuation after a failed or abandoned attempt.
Whole-operation admission covers grinding scratch before state mutation, and
each grinding batch downloads only two public status words. Zero-bit grinding
does not change state; zero-bit sampling still consumes a sample.

The integration test preserves the production hiding PCS, security parameters
and Postcard format, verifies using the original CPU proof type, and rejects
altered public inputs. Only its challenger runs on CUDA. Native scalar
derivations, randomness/hiding, witness/preprocessing/lookup, openings/FRI/final
polynomials, complete PCS/backend selection, stage receipts, worker admission
and pool integration remain outstanding. This checkpoint does not establish
complete CUDA proving or transaction throughput.

## Implementation sequence

The [V100 results](../lattica-prover-p3/scripts/v100-specialized-benchmark/README.txt)
support keeping the wider query batches as the starting point. The planner now
prefers 2 GiB plus 64 KiB of scratch, enough for sixteen columns in the tall
transform case, and reduces the batch when the remaining memory or allocation
limit is smaller. This is a preference within admission, not a new minimum.

| Evidence | Recorded result | Consequence for CUDA |
|---|---|---|
| V100 query batching, three alternating pairs | Median aggregation 57.545 to 52.499 seconds; 9.61% higher aggregated-input throughput | Port the current query planner and its sixteen-column geometry first. |
| V100 query reconstruction in that comparison | 7.902 to 2.931 seconds; 1,416 to 123 tile readbacks | Preserve device-resident prefixes and reduce repeated transforms and transfers. |
| V100 combined optional candidates, five pairs on earlier source | 57.697 to 64.822 seconds; 12.35% slower | Qualify each optimization separately for each architecture. |
| RTX 5080 typed comparison on `152adf1`, five pairs per candidate | Events reduced median aggregation time 2.13%; cooperative commitments increased it 27.05%; all candidates increased it 24.42% | Investigate submission overhead, and retain the existing hash layout as the initial CUDA implementation. |

The V100 four-input case creates three recursive proofs from four JoinSplit
proofs. The RTX typed case creates four recursive proofs for three user
transactions and one issuance entry. Their timings are separate workloads and
do not establish a hardware speed ratio. The V100 numbers above are recorded
in the pulled documentation; its raw machine-local results are not included in
Git. The RTX results and audit logs are retained locally under
`lattica-prover-p3/benchmark-results/gpu-tuning-20261018-runtime`.

The old RTX baseline's median sums of device event durations were approximately
7.06 seconds for transforms, 5.70 seconds for commitments, and 2.45 seconds for
quotients. A representative root issued 25,652 witness commands, 8,288 quotient
commands, and 5,144 lookup commands. These are profiling signals from the old
source, not a decomposition of elapsed time. Reprofile the newly pulled source
before choosing fusion boundaries or setting speedup expectations.

1. **Establish the baseline and strengthen the qualification tests.**

   Rebuild the current OpenCL prover and independently verify fresh proofs on
   each target GPU. Retain the three host query-planner checks that passed
   after this pull, then run the GPU reconstruction oracle and constrained
   memory cases. Add guard words to the event-batch test and recheck enqueue
   failures, missing timestamps, and unwind cleanup. Its original
   `MatrixSpec::new(1, 1, ...)` reserves two words because the first argument is
   a logarithmic row count; the V100 note describing a one-word allocation was
   mistaken. Explicit guards will test writes beyond the two-word result.

   Pin the fixture, profile, source, executable, driver, device UUID, clocks,
   budgets, and environment. Capture cold initialization and compilation
   separately from warm aggregation. Preserve both the V100 container workload
   and the typed worker workload as separately named cases. The V100 harness's
   28 GiB free-VRAM admission cannot be copied to a 16 GiB RTX 5080.

   **Exit evidence:** CPU-verified OpenCL baselines at this commit, valid test
   buffers, and a stage/launch/transfer profile for every selected workload.

2. **Add CUDA as an explicit backend with complete resource ownership.**

   Add `gpu-cuda` and a `cuda_compute` module. Keep `gpu` selecting OpenCL for
   existing builds and keep Metal independent. Introduce a small typed backend
   interface for contexts, device allocations, streams, events, modules, and
   launches at the current `block_v2::compute` boundary. Separate shared
   scheduling from direct `ocl` calls. Audit feature gates throughout the
   native entry points, wallet worker, recursive PCS, compiler, and reporting;
   adding a third alias alone will not make those paths available.

   Use Rust ownership around the CUDA Driver API, with a pinned binding version
   and a narrow unsafe boundary. Start with one retained context, one compute
   stream, and one worker process per GPU. Select devices by UUID and PCI
   identity, and reuse the existing GPU leases. Preserve allocation admission,
   host staging limits, per-attempt ownership, cancellation, draining, and
   private-buffer erasure before reuse. Account retained allocator capacity,
   events, graph state, modules, compiler scratch, and driver/context memory;
   live tensor bytes alone are insufficient.

   Extend `proving::Backend` with `Cuda`, its serialized reports, GPU-required
   policy, stage observers, native initialization, inventory, and controller
   validators. An accepted CUDA proof must report CUDA execution for all
   required arithmetic stages. Preserve the existing public lifecycle ABI.

   Pin CUDA **12.9.1** initially and compile explicit `sm_70` and `sm_120`
   variants. NVIDIA's [12.9.1 NVRTC target list](https://docs.nvidia.com/cuda/archive/12.9.1/nvrtc/index.html#supported-compile-options)
   includes both; [CUDA 13 removed Volta offline compilation and library support](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-toolkit-release-notes/#deprecated-architectures).
   Verify compiler targets and driver compatibility with a compile/load/launch
   smoke test on both devices. This host has the CUDA driver library, but
   `nvcc`, `nsys`, and `ncu` were not found on PATH or in the inspected CUDA
   locations. Install a pinned development toolchain as an implementation step.

   **Exit evidence:** allocation, copy, launch, event, teardown, and injected
   failure tests on both GPUs; CPU-only, OpenCL, and Metal builds remain valid.

3. **Port exact field arithmetic, transforms, and query reconstruction.**

   Implement Goldilocks arithmetic over `2^64 - 2^32 + 1`, including canonical
   and supported noncanonical inputs, and the existing quadratic and cubic
   extension operations. Use exact integer multiplication and carry reduction,
   including CUDA high-half multiplication where useful. Test boundaries and
   randomized inputs against the CPU implementation before optimizing PTX.

   Port the existing tiled NTT, inverse NTT, coset scaling, bit-reversed storage,
   cached twiddles, prefix reconstruction, and query gathering. Preserve the
   new query scratch accounting and exact sixteen-column boundary. Tune
   workgroup size, columns per block, shared memory, and register use against
   actual matrix shapes. Consider asynchronous global-to-shared copies only
   on architectures that support them, with a separately tuned V100 path.
   Keep outputs on the device between stages. These operations require exact
   finite-field transforms; floating-point FFT kernels do not implement them.

   **Exit evidence:** independent CPU DFT comparisons, both row orders, forward
   and inverse transforms, extension widths, zero padding, repeated queries,
   allocation-boundary tests, and preserved query order and duplicates.

4. **Port commitments and generate CUDA quotient kernels from the existing IR.**

   Port the established Poseidon2 permutation, leaf absorption, Merkle
   compression, and retained paths first. Measure state layouts separately:
   the eight-lane commitment candidate already regressed on both measured
   devices. Explore fusion of compatible transform, normalization, and hashing
   passes only when profiling shows reduced total traffic and elapsed time.

   Reuse validated public AIR bytecode and liveness analysis to emit CUDA
   quotient code. Start with the current bounded 64-instruction blocks, then
   measure block boundaries, register count, spills, occupancy, and scratch
   traffic. Preserve instruction/source-size limits and generic GPU execution
   for shapes outside specialization. Keep a CUDA-only policy fail-closed if
   no correct CUDA implementation exists for a required operation.

   Compile stable kernels ahead of time. Compile public program specializations
   during worker preparation with NVRTC and cache them by program/profile hash,
   code-generator version, compiler options, toolkit, and SM target; bind timing
   qualification to the driver and executable as well. Bound both cache size
   and compilation resources. Cache public code and constants only. The V100
   report's 119.324-second first specialization makes cold preparation worth
   measuring explicitly.

   **Exit evidence:** CPU oracles for hashing and quotient evaluation, valid
   specialized and generic CUDA paths, cache invalidation tests, and measured
   compilation/resource limits.

5. **Complete wallet and recursive proving across all sixteen stages.**

   Port public values, witness traces, preprocessing, lookup evaluation and
   batch inversion, randomness, hiding, openings, FRI folding and queries,
   final polynomial work, scalars, transcript updates, and grinding. Integrate
   the transform, quotient, and commitment implementations from the preceding
   steps. Cover both legacy quadratic wallet proofs and cubic recursive block
   proofs, including the existing JoinSplit and HTLC operations.

   Preserve the current randomness construction, transcript order, hiding
   parameters, domains, and proof encoding. Use controlled randomness only in
   differential tests; production attempts must obtain fresh randomness.
   Host scheduling, public program compilation, serialization, and independent
   verification may remain on CPU. GPU-required arithmetic must have actual
   CUDA execution receipts. A partial GPU path must not be reported as a
   complete CUDA prover.

   **Exit evidence:** fresh wallet and recursive proofs accepted by the
   unchanged CPU verifier, complete stage reports, and rejection of altered
   proofs, missing stages, CPU fallback, and invalid witnesses.

6. **Reduce submission and memory overhead after correctness parity.**

   Reuse kernel handles, public program modules, admitted scratch arenas, and
   bounded event pools across jobs. Profile launch gaps before introducing
   CUDA Graphs for repeated witness waves, lookup sequences, and tiled
   quotient/opening operations. Graph replay must bind the current attempt's
   buffers and fresh randomness. Capture stable public shapes and split
   execution at transcript or host-control boundaries that require it.

   Retain timing and completion receipts for every stage. Start with one
   stream; overlap transfers or independent operations only where measured
   dependencies and memory allowance permit it. Inspect generated instructions,
   register spills, memory efficiency, and occupancy using profiler versions
   that support each GPU. Use separate profiler runs so instrumentation does
   not contaminate the paired throughput measurements. Charge cached and
   in-flight memory until completion, including failure and cancellation paths.

   **Exit evidence:** independently audited proofs with a measurable reduction
   in whole-job time, unchanged memory limits, and correct cleanup under
   injected asynchronous errors and cancellation.

7. **Connect CUDA workers to the existing pool and qualify concurrency.**

   Keep job payloads backend-independent: bind program/profile identity, input
   artifact hashes, dependencies, attempt identity, resource assignment, and
   output identity. Advertise CUDA support, compute capability, driver, binary
   identity, qualified shapes, and available memory through worker inventory.
   Retain existing lease, retry, recovery, and result-acceptance rules. A failed
   attempt must not cause duplicate accepted work or reuse private randomness.

   Schedule independent wallet and recursive DAG nodes across GPUs, beginning
   with one persistent worker per device. Measure additional workers per GPU
   as a separate experiment. On the dual-socket R740, bind worker CPUs and host
   staging allocations to the NUMA node serving each GPU where the topology
   allows. Exchange bounded proof artifacts between workers; raw device
   pointers and CUDA contexts stay local. Peer transfers or splitting one
   transform across GPUs remain later, separately measured options.

   **Exit evidence:** throughput and resource accounting for one and multiple
   devices, durable results after worker failure, and identical verification
   behavior through the existing host/node integration.

8. **Qualify the CUDA backend against current OpenCL before activation.**

   Compare CPU-verified CUDA and OpenCL runs built from the same source and
   proof profile. Warm each arm, then use at least five alternating pairs with
   fixed resource budgets per device. Run the common four-entry and eight-entry
   cases, full 64-entry and separately built 128-entry profiles, wallet proving,
   and complete block processing. Use matching fixtures and auditors for each
   capacity. Preserve the separate grouped V100 case as an additional screen.

   Report aggregation latency, cold preparation, user transactions per hour,
   aggregate inputs per hour, complete-block throughput, host/VRAM peaks,
   launches, transfer bytes, and board energy with explicit measurement
   boundaries. Keep issuance counts separate. Run device memory, race, and
   synchronization checks with supported tools, alongside arithmetic oracles,
   tamper tests, and resource/failure tests.

   Require correctness, full CUDA stage coverage, and valid admission for every
   accepted sample. Apply the existing performance rule per qualified
   device/workload: at least 2% lower median aggregation time and no measured
   workload median regression above 2%; repeat inconclusive comparisons. Keep
   architecture-specific choices opt-in until their full workload set passes.
   A speedup is a benchmark outcome, not an assumed consequence of the API port.

The first implementation increment should combine step 1 with the CUDA runtime
and exact arithmetic tests in steps 2–3. It produces an independently testable
backend foundation before expanding into proof generation. Subsequent changes
can add transforms/query reconstruction, commitments/quotients, complete proof
coverage, graph submission, and pool integration as separately reviewable commits.

The principal integration points are
[`Cargo.toml`](../lattica-prover-p3/Cargo.toml),
[`lib.rs`](../lattica-prover-p3/src/lib.rs),
[`block_v2::compute`](../lattica-prover-p3/src/block_v2/mod.rs),
[`gpu_hash::engine`](../lattica-prover-p3/src/block_v2/gpu_hash/engine.rs),
[`device/query.rs`](../lattica-prover-p3/src/block_v2/gpu_hash/engine/device/query.rs),
[`quotient/specialized.rs`](../lattica-prover-p3/src/block_v2/gpu_hash/engine/quotient/specialized.rs),
[`proving.rs`](../lattica-prover-p3/src/proving.rs),
[`native_public_gpu.rs`](../lattica-prover-p3/src/block_v2/native_public_gpu.rs),
and the existing typed worker controllers. The
[benchmarking guide](gpu-benchmarking.md) defines the existing evidence and
measurement conventions.
