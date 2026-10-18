GPU tuning candidates (OpenCL)

These implementations are experimental and disabled by default. GPU correctness
tests and proof benchmarks are pending: the implementation host has no working
NVIDIA driver/device. Host tests and OpenCL syntax checks do not qualify them for
production. Proof formats, cryptographic parameters and worker budgets are unchanged.

Host validation on 2026-10-18 passed 147 engine tests in the tuning build and
158 with the streaming/host features, plus default and CPU-only build checks.
The source and log hashes are recorded in
docs/evidence/gpu-tuning-implementation-2026-10-18.json (repository root).

Build with the additional Cargo feature `gpu-tuning`, then set
LATTICA_V2_GPU_TUNING in the actual proving worker before initialization:

  unset or empty              existing implementations
  events                      batches of at most 64 completion receipts;
                              reuse the witness-wave kernel within the attempt
  commitment                  eight-lane NVIDIA leaf/sponge/Merkle kernels
  scale                       shared row scales for 2^18 -> 2^19 rows,
                              exactly 98 or 200 flattened field columns
  ntt                         combined root/scale powers for 2^23 rows,
                              exactly 3, 4, 8 or 16 flattened field columns
  events,commitment,scale,ntt  combined candidate

Selections are immutable after engine initialization. Unknown/duplicate names
are errors. A nonempty selection in a build without gpu-tuning is rejected.
Commitment and transform candidates require NVIDIA SM7+ / 32-lane warps; other
devices retain the original kernels. Selection is logged as bounded_gpu_tuning,
including device support and production_qualified=false. Merely building the
feature does not select any candidate.

Event storage is a fixed inline array included in the engine's host-storage
census. A scoped owner attributes completed commands to its own proof session
and stage. Batches flush at capacity and before status reads/completion. Errors,
missing profiling timestamps and unwinds reject completion and drain outstanding
work; private-buffer cleanup remains in the original ownership guards.

Validation commands, from lattica-prover-p3 with the Rust toolchain on PATH:

  python3 scripts/check-gpu-tuning-kernels.py
  cargo test --offline --lib --features gpu-tuning,block-v2-capacity-128 \
    block_v2::gpu_hash::engine:: -- --test-threads=1
  cargo test --offline --lib \
    --features gpu-tuning,block-v2-host,block-v2-capacity-128,stream \
    block_v2::gpu_hash::engine:: -- --test-threads=1

The first command checks OpenCL C syntax, including NVIDIA inline-assembly
syntax, without assembling or executing PTX. The second runs host tests and
compiles the hardware tests. Ignored tests are NOT successful GPU executions.

After restoring GPU access, build tests outside the runtime memory envelope:

  cargo test --offline --lib --no-run --features gpu-tuning,block-v2-capacity-128

Then run the hardware tests serially in the usual <=3 GiB, zero-swap test
service. With an already compiled test binary, Cargo can select the tests via:

  cargo test --offline --lib --features gpu-tuning,block-v2-capacity-128 \
    gpu_tuning_ -- --ignored --test-threads=1 --nocapture

These tests cover partial warps, noncanonical field inputs, leaf offsets and
guard words, streamed sponge boundaries, Merkle compression, padded row scaling,
forward/inverse multi-stage transforms in both row orders, batch boundaries,
session isolation, enqueue errors, missing profiling timestamps and unwinds.
Numerical expectations come from the CPU field/permutation or an independent
DFT, not from the original GPU kernel.

Proof benchmark qualification (still pending)

1. Rebuild the bounded typed benchmark adapter against this source with
   gpu-tuning. Historical binaries cannot execute these candidates. Preserve
   source/binary hashes, device UUID, driver, profile, fixtures and resource
   assignments. The historical four-entry reference is
   benchmark-results/cpu-gpu-recursive-20261017; use its workload and audit rules.
2. In fresh worker processes, warm up each arm, then run five paired baseline /
   candidate repetitions, reversing order on alternating pairs. Baseline uses
   the same research binary with an empty tuning selection. Measure events,
   commitment, scale and ntt independently before testing their combination.
   Check the worker's selection log so an unforwarded environment variable
   cannot silently measure the baseline twice.
3. Use the same four-entry workload/profile for iteration. Validate the chosen
   combination separately on the 128-entry workload with its matching capacity
   build, fixture and CPU auditor. Keep one worker per GPU, four host threads,
   and the existing RAM/VRAM limits; record cold and warm results separately.
4. Independently CPU-verify every root proof and retain complete reports for all
   16 GPU stages. Reject CPU fallback, missing receipts, failed audits, OOM,
   memory-budget violations or absent timing evidence.
5. Production selection requires >=2% lower median aggregation time and no
   measured workload regression above 2%, under unchanged memory limits. Keep
   inconclusive candidates opt-in. Kernel timings alone do not establish proof
   throughput, and historical qualification records do not qualify this image.

GPU proof correctness, measured throughput, repeated workload comparisons and
production activation are deliberately outstanding until those gates pass.
