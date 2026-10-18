V100 four-input specialized-kernel benchmark

This is the bounded container research harness used on 2026-10-18. It aggregates
four existing JoinSplit wallet proofs into two pair wrappers and one level-two
merge root. Every sample requires all 16 GPU proving-stage receipts, three
specialized quotient executions and an independent CPU-only root audit.

The adapter preserves the measured research source, including its grouped
artifact reader. It is a separate Cargo workspace; the production library and
proof profile are unchanged. It is not the typed systemd production runner.

Requirements

- Linux with Python 3.11+, NVIDIA OpenCL, nvidia-smi and a working Rust toolchain.
- An existing cgroup v2 with 56..64 GiB RAM, at least 54 GiB free, zero swap,
  and at least four CPU cores of quota and affinity.
- One idle NVIDIA GPU with at least 28 GiB free VRAM. This workload was measured
  on Tesla V100-PCIE-32GB with driver 580.173.02 and four Rayon threads.
- Power measurement additionally requires libnvidia-ml and supported NVML
  board-power and cumulative-energy queries. No Python NVML package is needed.
- A previously prepared public grouped fixture with height 262144, key.1..3,
  and wallet.0..3. Registration and wallet proving are outside the timed run.
  Preparation copies only these eight files, validates the wallet proofs and
  pins their profile, chain, expected root and hashes. No recursive proof is
  reused. Retain the fixture separately; binaries and fixtures are not in Git.

The harness does not change cgroups, driver settings, clocks or power limits.
It retains the existing container limit and applies sampled watchdogs at
36 GiB process-group RSS and 20 GiB NVML VRAM. Managed GPU memory is capped at
16 GiB, with a 4 GiB context allowance; host scratch is capped at 32 GiB.

Build and prepare, from lattica-prover-p3

  adapter="$PWD/scripts/v100-specialized-benchmark/adapter/Cargo.toml"
  CARGO_BUILD_JOBS=2 RUSTFLAGS='-C target-cpu=native' cargo build --locked \
    --release --manifest-path "$adapter" --target-dir target/v100-specialized-cpu
  CARGO_BUILD_JOBS=2 RUSTFLAGS='-C target-cpu=native' cargo build --locked \
    --release --manifest-path "$adapter" --features gpu \
    --target-dir target/v100-specialized-gpu

  gpu_uuid=GPU-REPLACE_WITH_DEVICE_UUID
  fixture=/absolute/path/to/registered-public-fixture
  evidence="$PWD/benchmark-results/v100-specialized-$(date -u +%Y%m%dT%H%M%SZ)"
  python3 scripts/v100-specialized-benchmark/run.py prepare \
    --evidence "$evidence" --gpu-uuid "$gpu_uuid" --fixture "$fixture" \
    --cpu-binary target/v100-specialized-cpu/release/v100-specialized-bench \
    --gpu-binary target/v100-specialized-gpu/release/v100-specialized-bench

Builds must fit the existing container memory allowance and are outside timing.
Use separate CPU and GPU binaries from the same pinned source. The GPU feature
enables gpu-tuning in the library, but optional tuning selections remain empty
unless explicitly requested. Source, controller, adapter, fixture and binary
hashes are checked before each sample; changed inputs require fresh preparation.

Run one sample, the paired comparison, or a power measurement

  python3 scripts/v100-specialized-benchmark/run.py sample \
    --evidence "$evidence" --gpu-uuid "$gpu_uuid" --name baseline-01
  python3 scripts/v100-specialized-benchmark/compare.py \
    --evidence "$evidence" --gpu-uuid "$gpu_uuid"
  python3 scripts/v100-specialized-benchmark/power.py \
    --evidence "$evidence" --gpu-uuid "$gpu_uuid"

For an individual tuning sample, add --tuning events, commitment, scale, ntt,
or a comma-separated combination to run.py sample, with a fresh --name.
compare.py runs warmups, one screen per candidate and five alternating pairs
of baseline versus events,commitment,scale,ntt. It writes comparison.json.
Successful existing samples can be revalidated; failed attempts are preserved.
Use a fresh evidence directory for another campaign.

The adapter's aggregation timer includes program setup, proving, verification
and serialization, but excludes GPU context initialization and the separate CPU
root audit. The first specialized quotient compilation was 119.324 seconds on
the measured V100; report cold runs separately from warm-cache measurements.

power.py records ten seconds idle before and after the GPU worker and samples
NVML every 100 ms. Its energy window starts immediately before process launch
and ends when wait() reports exit. This includes initialization and shutdown;
the idle periods and separate CPU audit are excluded. Total energy uses the
hardware counter difference; average power is energy divided by window length.
Trapezoidal integration of sampled power is retained as a cross-check. Peak
power is a sampled peak, not a guarantee about shorter transients. Board power
includes GPU memory and associated circuitry, but excludes CPU/system power.
Results include raw JSONL/CSV readings, interval timing, command/environment
records, resource telemetry, proof receipts, CPU audit and summary JSON/text.

Retained measurements

See ../../../docs/gpu-benchmarking.md for the historical comparison. Raw
measurements and machine-specific evidence remain local; each new invocation
retains its own telemetry and audit records under --evidence.
The five-pair baseline median was 57.697 seconds; the combined candidates took
64.822 seconds, 12.35% slower. All optional tuning remains opt-in.

The separate power repeat took 57.503 seconds for aggregation and 58.051 seconds
for the metered worker: 106.895 W average, 207.022 W sampled peak, 1.723706 Wh.
Each run aggregates four existing transaction proofs; wallet proving, full-block
finalization and durable delivery are outside this measurement. Neither the
128-entry workload nor production activation is qualified by this screen.
