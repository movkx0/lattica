V100 four-input specialized-kernel benchmark

This is the bounded container research harness used on 2026-10-18. It aggregates
four existing JoinSplit wallet proofs into two pair wrappers and one level-two
merge root. Every sample requires all 16 GPU proving-stage receipts, three
specialized quotient executions and an independent CPU-only root audit.

The adapter preserves the measured research source, including its grouped
artifact reader. It is a separate Cargo workspace that links the repository's
prover library and preserves the proof profile. It is not the typed systemd
production runner.

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

Owned query reconstruction workspace

The default owned-query planner prefers 2 GiB plus 64 KiB of scratch. This fits
sixteen columns of two 2^23-row transform buffers together with roots, indices
and gathered query rows. A strict 2 GiB cap fits only fifteen columns and misses
the existing NVIDIA sixteen-column NTT geometry. The previous 64 MiB preference
forced one column at a time for these tall recursive domains.

The complete workspace is accounted against the configured managed GPU budget
and device allocation limit. Tiles shrink when less memory is available. The
wallet admission planner uses the same preference, including host output
bounds. No optional tuning flag is required. Rebuild and prepare a fresh
evidence directory to measure this source; keep historical measurements pinned
to their original binaries.

A three-pair V100 follow-up on 2026-10-18 compared the original 64 MiB preference
against this planner, alternating run order with four Rayon threads in each
process and all optional tuning selections empty. Each root used four existing
wallet proofs and three fresh recursive proofs. Median aggregation time fell
from 57.545 to 52.499 seconds: 250.24 to 274.29 aggregated inputs/hour, a 9.61%
throughput gain. Query reconstruction fell from 7.902 to 2.931 seconds per root,
with 123 tile readbacks instead of 1416. All six roots passed independent CPU
verification, with all 16 GPU stages and three specialized quotient executions
confirmed for every root.

Median GPU board energy for the launch-to-exit worker window fell from 1.729486
to 1.561814 Wh (9.69%). Peak managed GPU allocation was 12.694 GiB in both arms;
the larger query workspace did not set the whole-run peak. The existing 16 GiB
managed budget and 4 GiB context allowance were retained. These are aggregation
measurements on this V100; wallet proving and complete block finalization are
excluded. Fourteen planner tests and the GPU/CPU query reconstruction oracle
also passed, including constrained-memory execution and exact tile boundaries.

One subsequent two-worker validation produced two independent eight-input roots
in 221.451 seconds, including process initialization and shutdown: 260.10
aggregated inputs/hour, 109.24 W average GPU power, 6.719666 Wh and 17.020 GiB
sampled peak VRAM. Both roots passed CPU verification and all fourteen recursive
proofs used the specialized quotient path with complete GPU-stage coverage.
This is one optimized concurrency sample, compared with the earlier three-run
median of 245.237 seconds and 234.87 inputs/hour (10.74% higher throughput).
Worker limits were unchanged: 11.25 GiB managed GPU memory, 4 GiB context reserve
and two Rayon threads each, with the normal device admission and leases active.
