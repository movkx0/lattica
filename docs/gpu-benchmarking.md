# Comparing GPU performance

Use a clean checkout of `main`, then pin one commit for the entire comparison. Rebuild and requalify after changing source, driver, proof capacity, or resource settings. The branch consolidation does not establish a new throughput result.

## Supported runners

| Hardware | Workflow | Current boundary |
|---|---|---|
| NVIDIA on Linux | OpenCL plus the typed systemd controllers below | Requires `nvidia-smi`, OpenCL inventory, cgroups, and a systemd user session. |
| NVIDIA on Linux, native CUDA | [CUDA implementation and qualification](cuda-prover-plan.md) | Opt-in CUDA workers and private wallet assignments; RTX 5080 qualification does not qualify other devices or pool concurrency. |
| V100 in a bounded Linux container | [Four-input specialized-kernel and power harness](../lattica-prover-p3/scripts/v100-specialized-benchmark/README.txt) | Research screen using an existing 56..64 GiB, zero-swap cgroup and sampled watchdogs; separate from the typed systemd runner. |
| Apple Silicon | [Native Metal recipe](../lattica-prover-p3/scripts/apple-current-benchmark-README.txt) | Run correctness qualification on the Mac before timing. Its eight-input screen differs from the Linux typed workload. |
| AMD or Intel OpenCL | Backend development | The Linux admission controller currently joins NVIDIA UUIDs to OpenCL devices. Portable inventory/admission and device qualification are still needed. |

Do not bypass resource admission to run another vendor. A backend compiling is not hardware qualification.

## Freeze the comparison

Record the commit, dirty-tree status, CPU/RAM, GPU model/UUID/VRAM, driver/OpenCL runtime, power mode, and toolchain versions. Use AC power where applicable and stop other compute workloads.

From the repository root:

```sh
git switch main
git pull --ff-only origin main
git rev-parse HEAD
git status --short
rustc --version
nvidia-smi --query-gpu=uuid,name,memory.total,driver_version --format=csv
```

Keep the proof profile, fixture, CPU thread budget, memory budgets, and timing boundary identical across devices. If GPU-specific budgets differ, report them explicitly. Preserve successful and failed attempt directories; use a fresh path every time.

## Linux: build separate binaries

Requirements: Rust 1.96, Python 3, an OpenCL ICD and development loader, NVIDIA management tools, and a working `systemctl --user`. The example builds the default 64-entry candidate profile. Builds are outside timing and use bounded resources; adjust the build cap to fit the host.

```sh
cd lattica-prover-p3
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=200% \
  env CARGO_BUILD_JOBS=1 cargo build --locked --release --no-default-features \
  --features block-v2-wide-lanes,stream --bin block-v2-paired-probe \
  --target-dir target/bench-cpu
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -p CPUQuota=200% \
  env CARGO_BUILD_JOBS=1 cargo build --locked --release --no-default-features \
  --features block-v2-wide-lanes,stream,gpu --bin block-v2-paired-probe \
  --target-dir target/bench-gpu

cpu_binary="$PWD/target/bench-cpu/release/block-v2-paired-probe"
gpu_binary="$PWD/target/bench-gpu/release/block-v2-paired-probe"
"$cpu_binary" capacity
"$gpu_binary" capacity
sha256sum "$cpu_binary" "$gpu_binary"
```

For the separate 128-entry profile, add `block-v2-capacity-128` to **both** feature lists, use separate target directories, and pass `--block-capacity 128` to preparation and runs. Regenerate fixtures and keys. Capacities 256 and 512 are not supported primary profiles.

## Prepare public inputs and run one device

The preparation controller can generate a synthetic public fixture from a fresh checkout. It does not depend on ignored benchmark artifacts. Preparation and registration can be substantial; their resource checks must pass before work starts.

```sh
benchmark_dir="$PWD/benchmark-results/gpu-comparison-$(date -u +%Y%m%dT%H%M%SZ)"
python3 scripts/block-v2-typed-cpu-prepare.py \
  --construction paired --block-capacity 64 --cpu-binary "$cpu_binary" \
  --evidence "$benchmark_dir/preparation"
```

Set `gpu_uuid` to the exact UUID from `nvidia-smi`, then run the compact bootstrap screen:

```sh
gpu_uuid=GPU-REPLACE_WITH_DEVICE_UUID
python3 scripts/block-v2-typed-gpu-run.py \
  --construction paired --ram-admission compact --block-capacity 64 \
  --gpu-binary "$gpu_binary" --cpu-binary "$cpu_binary" \
  --fixture "$benchmark_dir/preparation/fixture" --gpu-uuid "$gpu_uuid" \
  --count 4 --scratch /tmp --evidence "$benchmark_dir/device-a-count4-r1"
```

This exercises GPU-assisted recursive aggregation and a separate CPU root audit. It is not an assertion that every prover stage ran on the GPU. The controller retains assignments, source/binary pins, outputs, telemetry, and audit results. Admission failures stop the attempt; do not remove the limits to obtain a timing.

Repeat with a new evidence path and another UUID while retaining the same binaries and public fixture. Start with count 4, then use 8, 16, 32, and 64 as resources permit. Qualify each count/device combination before making a full-capacity claim. Use at least three successful repeats per setting for a performance comparison and retain variation, not just the fastest run.

Persistent device-owned proving, preseal work, recovery, and durable native delivery use the more extensive [pool workflow](../lattica-prover-p3/scripts/block-v2-pool-README.txt) and `block-v2-typed-shared-gpu-run.py --help`. Qualify that execution mode separately from this bootstrap screen.

## Starting settings

Use one worker per GPU. Keep the controller's admission model: managed buffers, maximum allocation, driver/context allowance, free-memory headroom, host RAM, and scratch all matter. Additional VRAM does not by itself imply higher throughput.

The retained RTX 5080 [128-entry experiment](evidence/block-v2-parallel-aggregation-128-2026-10-17.json) measured 602.367 seconds sequentially versus 732.593 seconds with two workers on one device: 17.8% lower throughput with concurrency. That single-block experiment excluded wallet generation, key preparation, and audits. The [VRAM experiment](evidence/block-v2-gpu-vram-comparison-2026-10-16.json) also found no useful speedup from its larger memory settings. These observations guide the starting point, not another GPU's tuning.

The V100 [four-input specialized-kernel comparison](../lattica-prover-p3/scripts/v100-specialized-benchmark/README.txt) at `152adf1` measured a 57.697-second baseline median across five alternating pairs. Enabling all four optional tuning candidates increased the median to 64.822 seconds, 12.35% slower. Both arms required all 16 GPU proving stages and an independent CPU audit for every root. This four-input result does not establish a hardware speed ratio against the RTX 5080's 128-entry workload.

A separate V100 power repeat took 57.503 seconds for aggregation. The full worker, including initialization and shutdown, used 1.723706 Wh over 58.051 seconds: 106.895 W average and 207.022 W sampled peak, against a 26.460 W idle baseline. Energy came from the NVML hardware counter; board power was sampled every 100 ms. CPU/system power, wallet proving and full-block finalization are excluded. The harness retains raw telemetry, audit logs and source/binary hashes in each run's local evidence directory.

## Report the same timing boundary

The [native CUDA wallet benchmark at `6fc3570`](evidence/cuda-wallet-batch-routing-benchmark-2026-10-19.json)
measured eight-entry JoinSplit and HTLC batches at 0.335 and 0.597 seconds median
on the RTX 5080, using a persistent private CUDA context. It includes C ABI
admission, witness decoding, proving, serialization and output copies; setup and
independent CPU audits are outside timing. All 44 saved outputs passed those
audits and tamper checks. These wallet batch and legacy tree measurements
exclude recursive aggregation and complete transaction processing, so compare
them only with the same workload and timing boundary.

The [larger CUDA wallet screen at `0b135b7`](evidence/cuda-wallet-capacity-2026-10-19.json)
used the same production library and resource limits. All 88 outputs passed
independent CPU verification and tamper checks, including padded 63-entry
batches and 64-leaf legacy containers. Selected batch medians were:

| Wallet batch entries | JoinSplit | HTLC |
|---|---:|---:|
| 16 | 0.621 s | 1.121 s |
| 32 | 1.202 s | 2.195 s |
| 64 | 2.529 s | 4.671 s |

Managed GPU memory peaked at 4.99 GiB under the existing 7 GiB allowance.
These are direct wallet batch proofs; full recursive block workloads remain
separate qualification tasks. Choosing a batch size needs a matched comparison
because the 32- and 64-entry measurements came from separate fixed-order runs.

The [RTX 5080 four-entry comparison at `bce8830`](evidence/gpu-tuning-rtx5080-2026-10-18.json)
completed 56 trials: a warmup for each selection and five alternating pairs per
candidate. Each trial aggregated three user transactions and one issuance entry
through four fresh recursive proofs, using the 64-entry capacity build. All roots
passed independent CPU verification with complete sixteen-stage GPU coverage.

| OpenCL candidate | Baseline median | Candidate median | Aggregation time change |
|---|---:|---:|---:|
| Event batching | 23.892 s | 23.402 s | −2.05% |
| Cooperative commitments | 23.865 s | 30.758 s | +28.89% |
| Shared scales | 23.851 s | 23.944 s | +0.39% |
| Cached NTT powers | 23.873 s | 23.801 s | −0.30% |
| All four candidates | 23.880 s | 30.047 s | +25.82% |

Workers retained four CPU threads, 3 GiB host RAM, zero swap, 7 GiB managed GPU
memory, a 4 GiB context reserve, 1 GiB free-memory headroom, and a 1 GiB allocation
limit. These are aggregation timings, excluding preparation and independent CPU
audit. Full-capacity and end-to-end throughput remain unqualified; all candidates
remain opt-in. The separate [CUDA arithmetic/transform checks](evidence/cuda-algebra-2026-10-18.json)
validate native primitives and do not yet measure CUDA proof generation.

The [native-wallet CUDA recursive screen at `8971a2b`](evidence/cuda-native-wallet-recursive-benchmark-2026-10-19.json)
uses four fixed, CPU-verified native CUDA wallet outputs: JoinSplit, HTLC redeem,
HTLC refund and issuance. One warmup and three measured runs produced a
**53.084-second median** (53.028–53.087), or about **271 aggregated inputs/hour**.
The timer covers the whole maintained Python launcher, including preparation,
fresh worker startup, four recursive proofs with collection verification, and
shutdown/accounting. Additional independent CPU audits followed outside timing;
all sixteen recursive proofs passed. Wallet generation, network/consensus,
native durable application and steady-state reuse are excluded. Compare against
the same whole-launcher boundary; the rate includes one issuance entry per four
inputs and is not delivered transaction throughput. Pool timing approval remains
separate.

The [128-input CUDA correctness run at `bcb8754`](evidence/cuda-full-recursion-128-2026-10-20.json)
completed 127 recursive proofs and 544 complete CUDA reports, independent CPU
audits, native durable application and a fresh-process journal audit. Its body
contains 96 user transactions and 32 issuance entries. The run used eighteen
separate bounded phases with imported, CPU-verified dependencies. Summed proof
observations total 1,364.216 seconds, excluding wallet generation, separate CPU
audits and native application. This is not a single deadline-qualified workflow
or a transactions-per-hour measurement; timing-approved pools and multi-GPU
qualification remain open.

The native CUDA wallet screen is the ignored release test
`cuda_compute::wallet::tests::benchmark::cuda_wallet_request_benchmark`.
Build the library tests with `--release --no-default-features --features
gpu-cuda,block-v2-capacity-128 --lib --no-run -j 1`. After correctness
qualification, run that exact test with `--ignored --exact --test-threads=1
--nocapture`, `LATTICA_CUDA_WALLET_BENCHMARK=1`, an explicit
`LATTICA_GPU_DEVICE_UUID`, and `RAYON_NUM_THREADS=4`. Use bounded services:
6 GiB RAM and one compiler job for the build; 3 GiB RAM, zero swap and four
assigned CPU threads for execution. Keep GPU tests serial.

This screen measures fresh raw witness through serialized proof for JoinSplit,
HTLC redeem and HTLC refund. It records one warmup and five alternating CPU/CUDA
pairs per case, with independent CPU verification outside timing. CUDA public
preparation is recorded separately, and every CUDA sample requires a complete
fourteen-stage report. It measures wallet proof latency; recursive aggregation,
block processing and durable delivery remain separate workloads.

The [RTX 5080 wallet screen on `7f8489f`](evidence/cuda-wallet-benchmark-2026-10-18.json)
verified all 36 proofs. Five measured pairs per case, using four Rayon threads
and a four-core CPU quota on the Ryzen 9 9950X3D2, produced these medians:

| Wallet case | CPU | CUDA | CPU/CUDA latency ratio |
|---|---:|---:|---:|
| JoinSplit | 929 ms | 94 ms | 9.85 |
| HTLC redeem | 1,009 ms | 98 ms | 10.28 |
| HTLC refund | 1,000 ms | 112 ms | 8.94 |

Public engine preparation took 342 ms with existing compiler/driver caches.
Desktop GPU clients remained active. GPU reports contain all fourteen wallet
stages; this screen does not qualify recursive or delivered-transaction throughput.

For each run, retain:

- Commit and binary hashes, device/runtime identity, capacity, fixture hash, and all settings.
- Total entries, user transactions, issuance entries, and fresh recursive proofs.
- Preparation/registration, aggregation, CPU audit, and durable-delivery durations separately.
- Host RAM and GPU memory peaks, scratch use, errors, retries, and audit outcome.
- Median and range across repeats, with the number of attempts and failures.

`transactions/hour = verified user transactions × 3600 / elapsed seconds`.

If elapsed time covers only aggregation, label the result **aggregation throughput**. End-to-end delivered throughput must include the declared wallet/preparation boundary, final audit, and durable host acceptance. Do not count issuance as user payments or recursive proofs as transactions. Apple and Linux reports with different workloads or timing boundaries cannot establish a hardware speed ratio.

Historical evidence stays in [evidence/](evidence) and the [benchmark report](benchmarks/README.md). The [archive](archive/README.md) retains older commands and progress logs for provenance.
