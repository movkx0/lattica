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
enables gpu-tuning in the library. An empty tuning selection uses device
defaults; see the pass-two V100 defaults below. Source, controller, adapter, fixture and binary
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
This preserves the original experiment. The pass-two qualification uses frozen
baseline and candidate binaries, as described below.
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
64.822 seconds, 12.35% slower. At that revision all tuning remained opt-in.

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

V100 OpenCL quotient and NTT follow-up

A further three-pair comparison on 2026-10-18 uses ec1c937 as the baseline.
The owned quotient workspace allowance increases from 64 to 128 MiB, with the
same bound in the runtime and Python admission planner. The measured recursive
program consequently uses 8192 rows per tile instead of 4096. Smaller configured
budgets still shrink tiles. Gather and quotient kernel objects are reused within
each operation; only row offsets change between enqueues.

On V100 devices, the owned NTT path admits cached twiddles against the reported
48 KiB local-memory allowance after subtracting the compiled kernels' static
usage. The measured driver permits 6143 u64 words of dynamic local storage.
The tile and its power cache must fit together. Other devices and the generic
GPU DFT retain the previous 32 KiB preference. Exact field arithmetic is
unchanged. Work-groups of 64/128, coalesced gathers, combined selector inverses
and 128-instruction specialization blocks did not provide useful full-prover
gains in screening; the final quotient geometry retains work-groups of 32 and
64-instruction blocks.

Median warmed results from three alternating pairs per workload:

  Workload                         Baseline       Optimized      Inputs/hour
  Four-input root                  52.546 s       46.063 s       274.05 -> 312.61
  Two concurrent eight-input roots 218.455 s      186.047 s      263.67 -> 309.60

Throughput improved 14.07% for the four-input root and
17.42% for the concurrent workload. Four-input time ranges were
52.544..52.998 seconds baseline and 45.943..46.224 optimized.
Concurrent ranges were 217.817..219.773 and 182.201..188.749 seconds,
respectively. The single-root timer excludes GPU initialization; concurrent
latency is the union of both complete worker launch-to-exit windows. CPU-only
root audits are outside both timers. Builds and cold specialized compilation
are excluded. Every sample used fresh recursive proofs and empty optional
tuning selections, with four total Rayon threads.

Median GPU board energy fell from 1.578470 to 1.453293 Wh per
four-input worker (7.93%), and from 6.749635 to
6.178027 Wh per concurrent pair (8.47%). Optimized median average
board power was 112.21 W and 119.68 W respectively. Energy windows
include process initialization and shutdown; CPU and system energy are excluded.
Clock settings, driver settings and the 250 W power limit were unchanged.

Whole-run peak managed allocation stayed at 12.694 GiB for the single
worker and 9.241 GiB per concurrent worker. The added quotient workspace
fits below the existing whole-run peak. Maximum sampled total VRAM in the
concurrent runs was 17.293 GiB baseline and 17.020 GiB optimized; sampled
peaks are not a bound on shorter transients. The original managed/context
limits remain 16/4 GiB for the single worker and 11.25/4 GiB per concurrent
worker. No proving-window memory-limit events occurred.

All 18 benchmark roots passed independent CPU verification. All 102 fresh
recursive proofs had complete GPU-stage coverage and specialized quotient
execution. Focused checks passed: 15 Rust planner/source tests, nine GPU test
executions and 90 Python resource tests. GPU checks cover both NTT directions,
scaling, row orders, in-place stages, query reconstruction, both extension
degrees and queued kernel reuse across multiple tiles. All 614 library/source
pins match the correctness build and both measured optimized binaries.

One optimized concurrent attempt was rejected by the existing 54 GiB free-host
memory guard before launching any GPU worker. Its artifacts were preserved and
a fresh attempt was used. Clean cached pages for completed benchmark/build
artifacts were released with file-specific POSIX advisories outside timing;
file contents, the driver compiler cache and resource limits were preserved.
Later concurrent samples applied the same completed-artifact cache advisory.

Evidence for this campaign is under
/workspace/code/benchmark-v100-opencl-20261018: evidence/final-comparison.json,
source and binary manifests, raw power/resource samples, and CPU audit logs.
This is aggregation of existing wallet proofs on the measured V100; wallet
proof generation, full-block finalization, other GPUs and production deployment
are outside this qualification.

Pass-two OpenCL implementation

On NVIDIA V100-PCIE-32GB, an empty tuning selection now enables 64-event batches,
batched retained-tree paths, and authenticated public compilation/input-layout
reuse in the legacy recursive session. The first binding is checked against the
original compiler witness. Subsequent calls validate the complete registry caps,
profile, height, mode and input count before binding fresh, verified children.
Cache entries contain public metadata, never witnesses or prover randomness.
All 16 actual GPU stages are still required for every newly generated proof.

Path batches preserve input order and duplicates, accept at most 256 indices,
and charge at most 1 MiB scratch against the existing managed-memory limit.
Tight budgets fall back to individual paths. Failure and unwind paths fence
commands before releasing storage. Event batches likewise retain individual
stage receipts and drain before releasing their owners.

Standalone runs with at least 11 GiB managed memory use a 256 MiB owned-quotient
workspace, allowing 16384 rows for the measured program. Smaller configured
tiles and device allocation limits still constrain it. An externally assigned
worker retains its existing 128 MiB workspace profile. Experimental admission
profiles may explicitly set geometry.gpu_quotient_workspace_bytes to 256 MiB.
Both the Rust phase planner and Python reservation model account for the choice.

Explicit LATTICA_V2_GPU_TUNING selections replace device defaults and require
the gpu-tuning feature. `reference` disables these new defaults for research.
The measured combination is events,public_cache,paths,quotient256. Additional
opt-in experiments are events256, tables, hash32 and hash_unroll. The public NTT
table cache is context-owned, limited to 32 entries / 64 MiB, keyed by actual
roots, direction and stage geometry, and falls back to the existing GPU kernel
under pressure. Experimental admission profiles must reserve that cache with
geometry.gpu_ntt_table_cache_bytes=67108864. It is disabled by default.

Set both LATTICA_PROFILE=1 and LATTICA_PROFILE_TIMELINE=1 for diagnostics. The
adapter installs the host profiler, and OpenCL events include queued, submitted,
start and end timestamps. Launch geometry, kernel work-group preferences,
static local/private memory and NVIDIA compiler build logs are also recorded.
Host spans cover circuit construction, compilation, preprocessing, allocation
and event waits. OpenCL host timelines allow 262144 segments per checkpoint;
loss counts remain visible and the report rejects incomplete traces.

  python3 scripts/v100-specialized-benchmark/profile.py \
    /path/to/four.log /path/to/worker-0.log /path/to/worker-1.log \
    --output /path/to/profiles.json

Device execution is the union of recorded intervals, not their sum. Queue waits
overlap and are reported as nonadditive distributions. Uncovered intervals
include host work and unrecorded commands; they do not establish GPU idle time.
Host spans measure wall time rather than CPU time. Worker clock domains stay
separate. Driver-reported private memory is not a spill-traffic or occupancy
measurement. The installed Nsight tools do not provide OpenCL tracing or Volta GPU
metrics on this instance, so these are native OpenCL diagnostics.

Exploratory screens (one sample each, not the final qualification):

  Four-input selection                    Aggregation seconds
  Warmed control                          46.446
  Public compilation/input-layout cache   43.635
  Event batches of 64 / 256                45.081 / 45.080
  Batched Merkle paths                    45.452
  Public NTT table cache                   45.892
  Quotient workspace 256 MiB               44.019
  Hash work-group 32                      46.604
  Bounded hash lane unrolling              46.141
  Combined selected changes               39.561

The concurrent screen took 188.439 seconds for the frozen c325074 baseline,
151.529 for the selected combination and 161.964 without wider quotient tiles.
Every screen generated fresh proofs and passed independent CPU root audits.
The first candidate control took 73.355 seconds with cold compilation and was
excluded; the warmed control above was used to interpret the screens.

A separate hash microbenchmark checked widths 16/64/200, work-groups selected by
the driver or 32/64/128/256 items, constant-memory round data, bounded unrolling,
and local staging for coalesced reads. The first four rows were checked against
an independent Python field/hash oracle; all rows were compared with the
reference GPU output.
Microbenchmark gains did not justify enabling the hash changes in the prover.
Full permutation unrolling crashed this driver's OpenCL compiler twice during
program build; those attempts are preserved and that variant was discarded.
The retained hash experiment only unrolls fixed eight-lane loops. Relaxed
floating-point compiler options and reduced precision are inapplicable to the
exact integer field arithmetic and were not introduced.

The pass-two campaign lives at /workspace/code/benchmark-v100-pass2-20261018.
Its controllers preserve the original four/eight-input adapters and CPU-only
auditors, pin both workload binaries and all shared library sources, and retain
fresh proof artifacts, resource telemetry, NVML power/energy readings and root
audit logs. The frozen baseline is c325074b074f120379270209ba833c98d4d68539.
The optimized binaries use identical library sources to the correctness build.

On this instance, repeat an individual frozen-binary measurement with a fresh
name (run the commands sequentially so the GPU admission guard remains valid):

  cd /workspace/code/benchmark-v100-pass2-20261018
  python3 release_cache.py
  python3 run.py sample final replay-four-01
  python3 release_cache.py
  python3 concurrent.py final replay-concurrent-01

Use baseline in place of final for the frozen control. The advisory only drops
clean cached pages of completed benchmark/build artifacts; it does not delete
files, clear the driver's compiler cache or change system limits. Builds must
finish before a timed sample begins. The final experiment uses an empty tuning
selection in both binaries, five alternating pairs per workload, independent
CPU verification of every root, and a gate requiring both medians to improve,
at least 5% less time in one workload, and at least four paired wins out of five
in each. An inconclusive campaign extends once to ten pairs with an 80% paired
win requirement. Diagnostic runs, warmups and exploratory screens are excluded.

Re-evaluate the preserved five-pair evidence from lattica-prover-p3:

  python3 scripts/v100-specialized-benchmark/qualification.py \
    /workspace/code/benchmark-v100-pass2-20261018 --candidate final --pairs 5 \
    --output /tmp/v100-pass2-rechecked.json

The output path must be new. The checker rejects changed binaries, incomplete
samples, reused root hashes, missing GPU-stage/CPU-audit receipts and memory
pressure events. Campaign controller/build hashes are in campaign-manifest.json;
the controller refuses changes while measuring or resuming that campaign.

Final pass-two measurements

Five alternating pairs per workload passed the qualification gate. The selected
defaults won all five pairs in each workload. Median warmed measurements:

  Workload                         c325074        Optimized      Inputs/hour
  Four-input root                  46.166 s        39.455 s       311.92 -> 364.97
  Two concurrent eight-input roots 188.984 s       150.045 s       304.79 -> 383.89

Time fell 14.54% and 20.60%, respectively; throughput rose 17.01% and 25.95%.
Four-input ranges were 46.029..46.359 seconds baseline and 39.300..39.460 seconds
optimized. Concurrent ranges were 187.182..191.015 and 146.866..152.166 seconds.
These are aggregation rates for already-proved wallet transactions. Wallet
proving, full-block finalization, other devices and production deployment are
outside the measurement. Four-input timing excludes GPU initialization;
concurrent timing includes both worker lifetimes. CPU audits are outside both.

Median GPU board energy fell from 1.457514 to 1.376451 Wh per four-input worker
(5.56%), and from 6.262108 to 5.789860 Wh per concurrent cohort (7.54%). Median
average board power increased from 112.223 to 123.899 W and from 119.206 to
138.915 W, respectively. Energy covers launch through exit, including context
initialization and shutdown, and excludes the CPU audit and idle observation
periods. It is GPU board energy, not CPU or complete-system energy. The power
limit remained 250 W; clocks and resource samples are retained with every run.

Peak managed allocation did not increase: approximately 12.694 GiB for a
four-input worker and 9.241 GiB per concurrent worker. The larger quotient
workspace did not set the whole-run peak. Limits stayed at 16 GiB managed plus
4 GiB context for the single worker, or 11.25 GiB managed plus 4 GiB context per
concurrent worker with 1 GiB shared headroom. Rayon threads remained four for a
single worker and two for each concurrent worker.

The final paired series generated 170 fresh recursive proofs. All 30 roots
passed independent CPU verification and every proof retained all 16 GPU-stage
receipts. No memory-pressure events were recorded. Focused validation passed
46 Rust test executions (including 10 GPU executions), 108 Python tests, GPU
library compilation both with and without gpu-tuning, and source completeness
through an isolated temporary index. All 619 library/source pins match the
correctness build and both frozen optimized binaries.

The primary evidence is evidence/qualification-5-pairs.json under the campaign
directory. evidence/final-build.json and eight/final-build.json pin the binaries;
evidence/final-source.tar.gz preserves the optimized source snapshot, including
new modules. evidence/campaign-manifest.json pins the measurement controllers.
Diagnostics and cold runs are retained separately and excluded from these
medians. The defaults remain limited to the measured V100 model; experimental
NTT tables, 256-event batches, hash work-group changes and hash unrolling remain
explicit opt-ins because the full-prover screens did not justify promotion.

Complete diagnostics contain 62563 recorded events for the initial four-input
run and 141478 / 141481 for the two concurrent workers, with no dropped host,
GPU or performance-span records and submission metadata on every GPU event.
The first diagnostic included 118.994 seconds of cold specialized compilation.
A separate warmed four-input diagnostic contains 62560 events, also with zero
drops. It recorded 24.988 seconds of execution-interval union within a 41.663
second device span. The remaining 16.675 seconds are uncovered intervals, not
measured GPU idle time. Hash absorption, LDE NTT and quotient event durations
were 8.621, 7.607 and 3.100 seconds, respectively. Inclusive host circuit
construction was 5.630 seconds, public input binding 0.001 seconds and warmed
specialized compilation 0.323 seconds. These overlapping diagnostic measures
are excluded from the qualification medians.

See evidence/final-profiles.json and evidence/warm-four-profile.json for the
trace summaries. Active-worker telemetry retained the same 877 MHz memory
clock, with sampled SM clocks from 1230 to 1380 MHz in both arms under the
unchanged power policy. Maximum sampled temperatures were 55 C for the
optimized four-input runs and 58 C for optimized concurrent runs. No clocks
or power settings were changed for this experiment.

evidence/final-controller-source.tar.gz preserves the exact campaign scripts,
eight-input adapter, build manifests and supporting benchmark modules.
evidence/final-integrity.json records successful revalidation of the source,
binary, controller and qualification hashes. evidence/final-review.patch also
preserves every changed/new source file and this final documentation. To rebuild,
apply that patch to the pinned c325074 checkout and restore the frozen adapters
from the archives; retain the separately pinned public fixtures and CPU auditor.
Use fresh campaign directories and labels
when changing source or controls; do not overwrite this evidence.

2026-10-19: random-stream batching and queue scheduling

A fresh campaign against bf8b7b44369deb4cbef950c372eff7f7ea19c212 measured
the same four-input aggregation on the Tesla V100-PCIE-32GB. Five alternating
pairs reduced median aggregation time from 39.391191213 to 38.580211758 seconds
(2.059% less time, 2.102% more throughput). The optimized arm won all five pairs.
These are warmed aggregation timings: producing the four input wallet proofs,
GPU initialization and the independent CPU root audit are outside the timer.
This result does not qualify full-block, concurrent-worker or other-device
performance.

OpenCL random generation now prefers 4,194,304 candidates per batch, with a
bounded fallback to the previous 1,048,576-candidate batch when memory is tight.
The prefix scan carries offsets through 4096-tile chunks using its existing
16 KiB local array. Generation, counts, offsets and scatter are enqueued on the
existing in-order queue before collecting their event timings. The status read,
queue drain, failure fences, rejection ordering and secret cleanup remain in
place. CPU and Metal retain the previous batch preference.

The matched diagnostics recorded 6,070 baseline random batches and 1,591
optimized batches. Their random kernel durations were 0.700145 and 0.542737
seconds; gaps between the four kernels within each batch totaled 0.697625 and
0.042897 seconds. No events were dropped (62,557 baseline / 44,641 optimized).
Hash absorption, LDE NTT and quotient remained the largest recorded kernels.
Uncovered trace intervals are not a measurement of GPU idle time. Diagnostics
are excluded from the paired medians. The earlier wait-only experiment had a
0.306% slower median and only two wins in five pairs; its evidence is retained.

The final arm passed eight host tests, eleven OpenCL random-stream tests and
two integration tests. An independent CPU prefix-sum oracle also matched 27
GPU scan cases, including chunk boundaries, partial chunks, all-rejected inputs
and output guards. All 14 final-campaign roots passed independent CPU audits,
covering 42 fresh recursive proofs with all 16 required GPU stages. Together
with the earlier experiment, the campaign retains 28 audited roots. Two other
existing witness-pipeline fixtures fail identically on baseline and the
wait-only candidate because their 64 MiB host allowance is below their compiler
scratch requirement; those fixtures were not changed.

Peak managed GPU accounting increased from 13,629,840,176 to 13,655,202,608 bytes
(24.1875 MiB), within the unchanged 16 GiB managed limit. Host/GPU watchdogs and
zero-swap admission remained enabled; no memory-pressure events occurred.
The new program required about 36 seconds of cold OpenCL initialization in
each compiler mode: profiling adds -cl-nv-verbose, so the normal warmup needs
its own cache entry. All ten measured runs then initialized in 0.409-0.430
seconds. Initialization and monitored process durations are preserved alongside
the aggregation timings.

The tracked summary is docs/evidence/v100-random-batching-2026-10-19.json at
the repository root. Raw logs, telemetry, profiles, frozen source trees,
binaries, test output and the complete local controller are in
benchmark-results/gpu-opt-20261019. The summary pins source/binary hashes and
includes every paired timing. The baseline, queue-only candidate and optimized
snapshots are separate; the earlier benchmark campaigns remain untouched.

For an exact local rerun from the repository root, choose unused sample names:
  python3 benchmark-results/gpu-opt-20261019/campaign.py sample baseline replay-baseline-01
  python3 benchmark-results/gpu-opt-20261019/campaign.py sample optimized replay-optimized-01
  python3 benchmark-results/gpu-opt-20261019/campaign.py profile optimized replay-profile-01
The controller verifies its frozen sources and binaries and retains the
original admission checks and CPU auditor. For a rebuild, the controller's
build and tests-build actions record the Cargo commands and compiler settings;
use fresh labels and freeze the new binary before measuring it.

2026-10-19: extensive arithmetic and witness profiling

A fresh campaign compares the previous RNG-optimized worktree with cheaper
Goldilocks subtraction, a coefficient-guarded Poseidon2 internal diagonal,
and bounded fusion of narrow witness dependency levels. The final selection
is the combined fused candidate. Five alternating pairs per workload give:

  four-input aggregation: 38.447818 -> 36.816988 seconds
    4.242% reduction in median time; 5/5 paired wins.
  eight-input worker window: 73.479930 -> 71.401975 seconds
    2.828% reduction in median time; 5/5 paired wins.
  two concurrent eight-input worker windows: 143.899439 -> 137.291549 seconds
    4.592% reduction in median time; 5/5 paired wins.
  native JoinSplit proving: 0.334169 -> 0.375421 seconds
    -12.345% reduction in median time; 3/5 paired wins.

Four-input and native wallet timers exclude GPU initialization and the
independent CPU audit. Eight-input measurements cover the complete worker
launch-to-exit window. Wallet creation for aggregation inputs is excluded.
Warmups, instrumented profiles, isolated screens and controlled cache runs
are retained separately and are excluded from the qualification medians.

The arithmetic-only screen won all three pairs (2.93% median paired gain).
Witness fusion won four of five direct pairs (0.80% median paired gain,
-0.99% to +1.58% range; effectively neutral unpaired medians). Its benefit
is small and variable without instrumentation. Four-input witness launches
fell from 21,415 to 1,304. Profiling overhead also falls with launch count,
so the profile-only wall-time difference is not used as the speedup claim.

The final source passed 26 targeted tests and CPU-only/OpenCL-without-tuning
compile checks. Tests cover full-width field arithmetic, guarded and generic
Poseidon2, CPU DFT/MMCS parity, full reference/fused witness trace parity,
long chains and lane boundaries, invalid metadata/witnesses, memory admission,
cleanup/session reuse, and native wallet proofs verified after GPU shutdown.
The benchmark ledger has 142 audited roots or wallet proofs, representing
506 fresh benchmark proofs. All audits passed and proof hashes are unique.
Required GPU stage counts remain 16 for recursive proofs and 15 for native
wallet proofs. Original RNG batching changes and all proof parameters are
unchanged. Managed allocation peaks and admission budgets are preserved.

The report includes NVML board energy, per-worker/cohort telemetry, a
controlled empty-cache/repeat experiment, and a description of the complete
GPU proving process. Source, binary, controller and fixture hashes are
preserved. These are fixed-fixture V100 OpenCL results; production-qualified
flags remain false, and other hardware/full-block delivery are not qualified.

Repository report: docs/v100-gpu-profile-2026-10-19.html
Process description: docs/gpu-acceleration.md
Machine-readable evidence: docs/evidence/v100-gpu-profile-2026-10-19.json
Local raw archive: benchmark-results/gpu-extensive-20261019
The local final-controller-source.tar.gz and final-review.patch preserve
the campaign code and complete changed/new files. final-integrity.json
records the final source, artifact and frozen-evidence checks.

For an exact local replay, choose unused sample names:
  python3 benchmark-results/gpu-extensive-20261019/campaign.py four fused replay-four-01
  python3 benchmark-results/gpu-extensive-20261019/campaign.py eight fused replay-eight-01 single
  python3 benchmark-results/gpu-extensive-20261019/campaign.py eight fused replay-concurrent-01 concurrent
  python3 benchmark-results/gpu-extensive-20261019/wallet.py sample fused replay-wallet-01
Use a new label and directory for source or control changes. The source
snapshots, build commands, CPU auditors and original admission checks are
part of the frozen campaign; do not overwrite historical evidence.

Native wallet follow-up:
The initial five wallet pairs were mixed and had a slower candidate median.
A fixed twenty-pair follow-up was added after the cache experiment; all samples are retained.
  Additional twenty pairs: 0.323469 -> 0.323534 seconds; -0.020% median-time reduction, 11/20 paired wins.
  All twenty-five pairs: 0.323885 -> 0.324833 seconds; -0.293% median-time reduction, 14/25 paired wins.
The original qualification numbers above remain unchanged. See the report for paired reductions and individual results.

The larger native-wallet follow-up was effectively unchanged; it does not show a repeatable end-to-end wallet improvement.
The selected changes are retained for consistent aggregation gains.

2026-10-20: shared NTT twiddle profiling

A fresh campaign starts from the previously optimized final worktree.
The selected change shares butterfly twiddle factors within each GPU workgroup.
Extra local storage is admitted explicitly. Small shapes keep their existing
path; the shared path selects wide transforms from 16,384 rows / 16 columns
or tall transforms from 262,144 rows / 3 columns on the measured V100.
The original cached fallback is retained when extra local storage does not fit.

  four-input aggregation: 36.897855 -> 35.861694 seconds
    2.808% reduction in median time; 5/5 paired wins.
  eight-input worker window: 70.003775 -> 67.934992 seconds
    2.955% reduction in median time; 5/5 paired wins.
  two concurrent eight-input jobs: 136.731544 -> 131.598916 seconds
    3.754% reduction in median time; 5/5 paired wins.
  native JoinSplit: 0.320606 -> 0.328514 seconds
    -2.467% reduction in median time; 9/20 paired wins.

The protocol specified five alternating pairs for each aggregation workload
and twenty for native wallet proving. Every result is retained. Warmups,
diagnostic profiles and controlled cache measurements are separate from these
medians. Four-input and wallet timers exclude initialization and external CPU
audits; eight-input timers cover complete worker launch-to-exit windows.
Aggregation starts from existing wallet proofs. Two concurrent jobs produce
two independent eight-input roots, not one sixteen-input tree.

The kernel screen covered independent integer CPU oracles and direct small
DFT sums, full-output equality, and interleaved event timings across large
and small shapes. Small-shape regressions drove the dispatch restrictions.
The broad all-shape release build is preserved and was superseded before
proof qualification. Source, binaries and every unsuccessful case remain
in the local campaign archive.

The selected source passed 35 targeted tests (16 host and 19 GPU) plus
CPU-only and GPU-without-tuning compile checks. Tests cover exact local
memory boundaries, shared/reference transforms and cached/uncached fallback,
ordering, coset scaling, arithmetic, commitments, witness parity and rejection,
and native wallet verification after GPU shutdown.
The benchmark ledger contains 108 independently CPU-audited outputs,
representing 400 fresh benchmark proofs. All audits passed and hashes are unique.
Original RNG, Poseidon2, witness fusion, proof parameters, verifier and
managed global allocation plans are preserved. Production-qualified flags
remain false; these measurements cover this V100 and these fixed fixtures.

Report: docs/v100-gpu-profile-2026-10-20.html
Evidence: docs/evidence/v100-gpu-profile-2026-10-20.json
Proving process: docs/gpu-acceleration.md
Raw archive: benchmark-results/gpu-extensive-20261019-pass2
The archive includes final-controller-source.tar.gz, final-review.patch and
final-integrity.json. The report documents replay commands, timer boundaries,
power observations and cold/repeated driver-cache behavior.

2026-10-20: scalar sponge absorption and delayed sum reduction
--------------------------------------------------------------

This fresh campaign starts from the source-matched shared_bounded build
preserved in gpu-extensive-20261019-pass2. Previous immutable evidence
and frozen binaries remain unchanged; the proving guide is maintained.

The OpenCL LDE absorb loop now uses constant state indices for pending
prefixes, full four-word blocks and partial suffixes. The measured V100
private allocation drops from 64 bytes to zero. The shared Poseidon2
internal sum accumulates 32-bit limbs and reduces once. Both limb sums
fit below 2^35, including arbitrary noncanonical u64 representatives.
No proof parameters, verifier rules, randomness or memory limits change.

Warmed, alternating complete-proof comparisons (seconds, medians):
  Four inputs: 35.859733 -> 35.315009; +1.52% time reduction; 5/5 paired wins.
  Eight inputs: 67.618271 -> 66.740613; +1.30% time reduction; 3/3 paired wins.
  Two concurrent eight-input jobs: 132.127000 -> 129.255557; +2.17% time reduction; 3/3 paired wins.
  Native JoinSplit: 0.322419 -> 0.342041; -6.09% time reduction; 12/20 paired wins.

Both binaries became faster midway through the original native series,
making its pooled medians disagree with its matched-pair comparison.
One separate twenty-pair native follow-up was specified before running.
Follow-up native medians: 0.317906 -> 0.313551;
+1.37% pooled median reduction, +1.65% median paired reduction,
with 14/20 paired wins. Both complete series are retained.

Four-input and native timers exclude initialization and artifact output.
Eight-input timers run from cohort launch through worker exit, including
initialization, barrier waiting, output and shutdown. CPU audits are outside
all timers. First-use profiles and warmups are retained and excluded from
the qualification medians. There is no cold-cache qualification in this run.

37 targeted tests passed, plus CPU-only and GPU-without-tuning compile checks.
The benchmark ledger contains 126 independently CPU-audited outputs representing
302 fresh benchmark proofs. All required GPU stages are covered, hashes are
unique, and native public-input tampering is rejected. This is measured
V100 fixture evidence, not Apple, full-block or production qualification.

Explicit 32-bit squaring, PTX squaring, balanced sums, carry-count sums,
aligned-only absorption and additional loop unrolling were screened. Only
the scalar absorption plus limb-sum combination was selected. The report
links the NVIDIA primary documentation that guided these experiments.

Report: docs/v100-gpu-profile-2026-10-20-pass3.html
Evidence: docs/evidence/v100-gpu-profile-2026-10-20-pass3.json
Raw archive: benchmark-results/gpu-extensive-20261020-pass3
Review patch: benchmark-results/gpu-extensive-20261020-pass3/incremental-review.patch
The archive also contains final-controller-source.tar.gz and final-integrity.json.
Replay a frozen four-input build with a new output name:
  python3 benchmark-results/gpu-extensive-20261020-pass3/campaign.py four scalar_limb replay-01
Replay native proving and its independent CPU audit:
  python3 benchmark-results/gpu-extensive-20261020-pass3/wallet.py sample scalar_limb replay-01
These replay commands require the pinned local workspace and V100 environment.

2026-10-20: external matrix reduction and fixed-stage bit reversal
------------------------------------------------------------------

This campaign starts from the exact scalar_limb source and release binaries
preserved in gpu-extensive-20261020-pass3. Previous immutable evidence and
CPU verifier binaries are preserved.

The OpenCL Poseidon2 external matrix now accumulates 32-bit limbs and
reduces once per output. Coefficients sum to 21, so each limb fits in 37
bits and the reconstructed high word is at most 20. One modular fold
and one carry correction suffice, including noncanonical u64 inputs.
Bit reversal uses five fixed mask/shift stages, handling 0..32 bits.

Warmed alternating complete-proof measurements (seconds, medians):
  Four inputs: 35.659293 -> 34.374682;
    +3.60% pooled median reduction, +3.60% median paired reduction, 3/3 paired wins.
  Eight inputs: 67.212648 -> 65.057490;
    +3.21% pooled median reduction, +3.21% median paired reduction, 2/2 paired wins.
  Two concurrent eight-input jobs: 129.415464 -> 125.101093;
    +3.33% pooled median reduction, +3.33% median paired reduction, 2/2 paired wins.
  Native JoinSplit: 0.320216 -> 0.316293;
    +1.23% pooled median reduction, +1.08% median paired reduction, 7/12 paired wins.

The selected change lowers median latency by 3.60% for four-input aggregation, 3.21% for eight-input aggregation, and 3.33% for two concurrent eight-input jobs; all seven aggregation pairs favor the candidate. Native JoinSplit has a 1.23% lower pooled median and seven wins in twelve pairs, but paired changes range from a 5.53% regression to a 6.31% improvement. This run does not establish a stable native latency gain. All 60 benchmark outputs passed independent CPU verification.

Four-input and native timers exclude initialization and artifact output.
Eight-input cohort timers include initialization, barrier waiting, proof
output and shutdown. CPU audits are outside every proving timer.
All first-use profiles and warmups are retained separately.

40 targeted tests passed, plus CPU-only and GPU-without-tuning compilation.
60 independently CPU-audited outputs represent 192 fresh benchmark proofs.
Required GPU stages are covered, hashes are unique, and native public-input
tampering is rejected. Proof parameters, randomness, verifier rules,
resource budgets, NTT admission and the 250 W cap remain unchanged.

This is evidence for the tested V100 and fixed benchmark fixtures.
The limited pair counts do not establish general production performance.
Apple, cold-cache and full-block qualification require separate checks.

Report: docs/v100-gpu-profile-2026-10-20-pass4.html
Evidence: docs/evidence/v100-gpu-profile-2026-10-20-pass4.json
Raw archive: benchmark-results/gpu-extensive-20261020-pass4
Review patch: benchmark-results/gpu-extensive-20261020-pass4/incremental-review.patch
The archive also contains final-controller-source.tar.gz and final-integrity.json.
Replay a frozen four-input build with a new output name:
  python3 benchmark-results/gpu-extensive-20261020-pass4/campaign.py four external_brev replay-01
Replay native proving and the independent CPU audit:
  python3 benchmark-results/gpu-extensive-20261020-pass4/wallet.py sample external_brev replay-01
These commands require the pinned local workspace and V100 environment.

2026-10-20: internal matrix reduction and shared quotient inversion
-------------------------------------------------------------------

This campaign starts from the exact external_brev source and release binaries
preserved in gpu-extensive-20261020-pass4. Previous immutable evidence and
CPU verifier binaries are preserved.

The OpenCL Poseidon2 internal matrix folds the guarded fast diagonal into
unreduced 32-bit limb sums, with exact nonnegative bounds. The common
matrix reducer handles both external and internal layers.
Field inversion uses a fixed 72-multiplication chain. The quotient
kernel shares one inverse across three denominators after its existing
nonzero-domain guard. The generic diagonal fallback remains available.

Warmed alternating complete-proof measurements (seconds, medians):
  Four inputs: 34.332247 -> 33.940245;
    +1.14% pooled median reduction, +1.14% median paired reduction, 3/3 paired wins.
  Eight inputs: 65.322456 -> 63.712023;
    +2.47% pooled median reduction, +2.46% median paired reduction, 2/2 paired wins.
  Two concurrent eight-input jobs: 125.428711 -> 123.472854;
    +1.56% pooled median reduction, +1.56% median paired reduction, 2/2 paired wins.
  Native JoinSplit: 0.306494 -> 0.309939;
    -1.12% pooled median reduction, -0.13% median paired reduction, 6/12 paired wins.

All seven aggregation pairs improved: median latency fell 1.14% for four inputs, 2.47% for eight inputs and 1.56% for two concurrent eight-input jobs. Native results were mixed: its pooled median was 1.12% slower, with six wins in twelve pairs and a median paired reduction of -0.13%. This run establishes no native speedup. The candidate is retained for its consistent aggregation gains on the tested V100 fixtures.

Four-input and native timers exclude initialization and artifact output.
Eight-input cohort timers include initialization, barrier waiting, proof
output and shutdown. CPU audits are outside every proving timer.
All first-use profiles and warmups are retained separately.

42 targeted tests passed, plus CPU-only and GPU-without-tuning compilation.
60 independently CPU-audited outputs represent 192 fresh benchmark proofs.
Required GPU stages are covered, hashes are unique, and native public-input
tampering is rejected. Proof parameters, randomness, verifier rules,
resource budgets, NTT admission and the 250 W cap remain unchanged.

This is evidence for the tested V100 and fixed benchmark fixtures.
The limited pair counts do not establish general production performance.
Apple, cold-cache and full-block qualification require separate checks.

Report: docs/v100-gpu-profile-2026-10-20-pass5.html
Evidence: docs/evidence/v100-gpu-profile-2026-10-20-pass5.json
Raw archive: benchmark-results/gpu-extensive-20261020-pass5
Review patch: benchmark-results/gpu-extensive-20261020-pass5/incremental-review.patch
The archive also contains final-controller-source.tar.gz and final-integrity.json.
Replay a frozen four-input build with a new output name:
  python3 benchmark-results/gpu-extensive-20261020-pass5/campaign.py four internal_inverse replay-01
Replay native proving and the independent CPU audit:
  python3 benchmark-results/gpu-extensive-20261020-pass5/wallet.py sample internal_inverse replay-01
These commands require the pinned local workspace and V100 environment.

2026-10-21: explicit V100 field carry instructions
--------------------------------------------------

This campaign starts from the exact internal_inverse source and release binaries
preserved in gpu-extensive-20261020-pass5. Previous immutable evidence and
CPU verifier binaries are preserved.

Goldilocks addition, subtraction and reduction use explicit PTX carry
chains on NVIDIA V100 devices with compute capability 7.0. The original
portable OpenCL arithmetic remains the fallback for all other devices.
Each assembly block owns its condition-code chain and preserves both
possible folds for arbitrary u64 field representatives. The main engine,
legacy DFT path and specialized quotient programs share the device gate.

Warmed alternating complete-proof measurements (seconds, medians):
  Four inputs: 33.839157 -> 30.666227;
    +9.38% pooled median reduction, +9.70% median paired reduction, 3/3 paired wins.
  Eight inputs: 63.963903 -> 57.280311;
    +10.45% pooled median reduction, +10.45% median paired reduction, 2/2 paired wins.
  Two concurrent eight-input jobs: 123.096835 -> 107.931966;
    +12.32% pooled median reduction, +12.32% median paired reduction, 2/2 paired wins.
  Native JoinSplit: 0.320642 -> 0.302193;
    +5.75% pooled median reduction, +4.50% median paired reduction, 9/12 paired wins.

All seven aggregation pairs improved: median latency fell 9.38% for four inputs, 10.45% for eight inputs and 12.32% for two concurrent eight-input jobs. Native median latency fell 5.75%, with nine wins in twelve pairs and a 4.50% median paired reduction; the short native measurements remain variable. Sampled peak GPU memory rose by 672 MiB for the single eight-input workload and 640 MiB for concurrent jobs, while all unchanged resource budgets passed. The V100-gated candidate is retained for these measured gains on the fixed fixtures.

Four-input and native timers exclude initialization and artifact output.
Eight-input cohort timers include initialization, barrier waiting, proof
output and shutdown. CPU audits are outside every proving timer.
All first-use profiles and warmups are retained separately.

43 targeted tests passed, plus CPU-only and GPU-without-tuning compilation.
60 independently CPU-audited outputs represent 192 fresh benchmark proofs.
Required GPU stages are covered, hashes are unique, and native public-input
tampering is rejected. Proof parameters, randomness, verifier rules,
resource budgets, NTT admission and the 250 W cap remain unchanged.

This is evidence for the tested V100 and fixed benchmark fixtures.
The limited pair counts do not establish general production performance.
Apple, cold-cache and full-block qualification require separate checks.

Report: docs/v100-gpu-profile-2026-10-21-pass6.html
Evidence: docs/evidence/v100-gpu-profile-2026-10-21-pass6.json
Raw archive: benchmark-results/gpu-extensive-20261021-pass6
Review patch: benchmark-results/gpu-extensive-20261021-pass6/incremental-review.patch
The archive also contains final-controller-source.tar.gz and final-integrity.json.
Replay a frozen four-input build with a new output name:
  python3 benchmark-results/gpu-extensive-20261021-pass6/campaign.py four field_carry replay-01
Replay native proving and the independent CPU audit:
  python3 benchmark-results/gpu-extensive-20261021-pass6/wallet.py sample field_carry replay-01
These commands require the pinned local workspace and V100 environment.

2026-10-21: delayed V100 cubic product reduction
------------------------------------------------

This campaign starts from the exact field_carry source and release binaries
preserved in gpu-extensive-20261021-pass6. Previous immutable evidence and
CPU verifier binaries are preserved.

Cubic extension multiplication uses three dot products with one delayed
reduction per output. Each dot product retains the carry beyond bit 127
and uses B^4 = -B mod p for B=2^32. The existing V100 device gate selects
the PTX implementation; portable cubic and quadratic code is unchanged.

Warmed alternating complete-proof measurements (seconds, medians):
  Four inputs: 30.601513 -> 30.420979;
    +0.59% pooled median reduction, +0.48% median paired reduction, 2/3 paired wins.
  Eight inputs: 59.156003 -> 57.079258;
    +3.51% pooled median reduction, +3.51% median paired reduction, 2/2 paired wins.
  Two concurrent eight-input jobs: 107.217330 -> 105.840166;
    +1.28% pooled median reduction, +1.28% median paired reduction, 2/2 paired wins.
  Native JoinSplit: 0.311007 -> 0.305699;
    +1.71% pooled median reduction, +2.11% median paired reduction, 7/12 paired wins.

Kept the V100 cubic dot-product reduction. Warmed median latency fell 0.59% for four inputs, 3.51% for eight inputs, and 1.28% for two concurrent eight-input jobs; six of seven aggregation pairs improved. Native results were mixed: a 1.71% lower pooled median with seven of twelve paired wins. Sampled GPU peaks increased by 460 MiB for a single eight-input job and 920 MiB for the concurrent cohort; all unchanged resource budgets passed. These are limited fixed-fixture V100 measurements, not general production qualification.

Four-input and native timers exclude initialization and artifact output.
Eight-input cohort timers include initialization, barrier waiting, proof
output and shutdown. CPU audits are outside every proving timer.
All first-use profiles and warmups are retained separately.

45 targeted tests passed, plus CPU-only and GPU-without-tuning compilation.
60 independently CPU-audited outputs represent 192 fresh benchmark proofs.
Required GPU stages are covered, hashes are unique, and native public-input
tampering is rejected. Proof parameters, randomness, verifier rules,
resource budgets, NTT admission and the 250 W cap remain unchanged.

This is evidence for the tested V100 and fixed benchmark fixtures.
The limited pair counts do not establish general production performance.
Apple, cold-cache and full-block qualification require separate checks.

Report: docs/v100-gpu-profile-2026-10-21-pass7.html
Evidence: docs/evidence/v100-gpu-profile-2026-10-21-pass7.json
Raw archive: benchmark-results/gpu-extensive-20261021-pass7
Review patch: benchmark-results/gpu-extensive-20261021-pass7/incremental-review.patch
The archive also contains final-controller-source.tar.gz and final-integrity.json.
Replay a frozen four-input build with a new output name:
  python3 benchmark-results/gpu-extensive-20261021-pass7/campaign.py four extension_dot replay-01
Replay native proving and the independent CPU audit:
  python3 benchmark-results/gpu-extensive-20261021-pass7/wallet.py sample extension_dot replay-01
These commands require the pinned local workspace and V100 environment.

2026-10-21: bounded V100 matrix carries
---------------------------------------

Fresh baseline: exact source-matched extension_dot build from
gpu-extensive-20261021-pass7. Previous immutable evidence and independent
CPU verifier binaries are preserved.

The existing V100 gate selects explicit PTX reconstruction/fold carries
inside the bounded Poseidon matrix reducer. The portable preprocessed
body is unchanged. NTT experiments were screened and rejected; NTT source
and scheduling are unchanged. No proof parameters or verifier changes.

Warmed alternating complete-proof measurements (seconds, medians):
  Four inputs: 30.642396 -> 29.614815; +3.35% latency reduction.
    Within-pair median +3.35%; faster in 3/3 pairs.
  Eight inputs: 57.028974 -> 55.248946; +3.12% latency reduction.
    Within-pair median +3.12%; faster in 2/2 pairs.
  Two concurrent eight-input jobs: 106.733194 -> 102.648635; +3.83% latency reduction.
    Within-pair median +3.82%; faster in 2/2 pairs.
  Native JoinSplit: 0.310122 -> 0.296667; +4.34% latency reduction.
    Within-pair median +2.99%; faster in 10/12 pairs.

Retained the V100 matrix carry optimization. All seven aggregation pairs improved: median latency fell 3.35% for four inputs, 3.12% for eight inputs and 3.83% for two concurrent jobs. Native median latency fell 4.34%, with 10/12 paired wins and a 2.99% median within-pair reduction. All 45 targeted tests and 192 fresh benchmark proofs passed. These are bounded V100 fixture measurements with limited sample counts, not production qualification.

Four-input/native timing excludes initialization and CPU auditing.
Eight-input timing includes cohort startup, proof output and shutdown;
CPU auditing is excluded. First-use profiles and warmups are separate.
All 45 targeted tests and CPU-only/GPU-without-tuning compile checks passed.
60 independently CPU-audited outputs represent 192 fresh benchmark proofs.
Required GPU stages, unique proof/root hashes and public tamper checks passed.
Resource budgets and the fixed 250 W power cap are unchanged. Per-workload
sampled memory peaks and all paired timings are retained in the report.
No Apple, cold-cache, full-block or production qualification is claimed.

Report: docs/v100-gpu-profile-2026-10-21-pass8.html
Structured evidence: docs/evidence/v100-gpu-profile-2026-10-21-pass8.json
Raw campaign: benchmark-results/gpu-extensive-20261021-pass8
Incremental patch: benchmark-results/gpu-extensive-20261021-pass8/incremental-review.patch
Archive and integrity: final-controller-source.tar.gz and final-integrity.json.

Fresh four-input replay (new tag; includes independent CPU audit):
  python3 benchmark-results/gpu-extensive-20261021-pass8/campaign.py four matrix_carry replay-01
Fresh native replay:
  python3 benchmark-results/gpu-extensive-20261021-pass8/wallet.py sample matrix_carry replay-01
Use the recorded pinned binaries and V100 environment.

2026-10-21: rejected V100 round-constant addition experiment
------------------------------------------------------------

Fresh baseline: exact source-matched matrix_carry build from
gpu-extensive-20261021-pass8. Previous immutable evidence and independent
CPU verifier binaries are preserved.

The candidate used one carry fold for canonical Poseidon round constants
behind the existing V100 gate. It was rejected after mixed complete-proof
timings and higher sampled peak VRAM. The exact pass-8 matrix_carry source
is restored; no candidate source changes remain in the worktree.

Warmed alternating complete-proof measurements (seconds, medians):
  Four inputs: 29.712295 -> 29.630083; +0.28% latency reduction.
    Within-pair median +0.28%; faster in 2/3 pairs.
  Eight inputs: 55.267896 -> 55.459622; -0.35% latency reduction.
    Within-pair median -0.35%; faster in 0/2 pairs.
  Two concurrent eight-input jobs: 102.593129 -> 102.655379; -0.06% latency reduction.
    Within-pair median -0.06%; faster in 1/2 pairs.
  Native JoinSplit: 0.304917 -> 0.299436; +1.80% latency reduction.
    Within-pair median +1.15%; faster in 8/12 pairs.

Rejected the canonical round-constant addition candidate and restored the exact pass-8 optimized source. Matched row-hash event totals improved 1.99% for four-input aggregation and 2.93% for native proving, but only 3 of 7 aggregation pairs improved. Eight-input median latency regressed 0.35%; concurrent median latency regressed 0.06%. Four-input median latency improved 0.28%, and native median latency improved 1.80% (8 of 12 pairs). Sampled peak VRAM increased by 428 MiB for four-input aggregation and 920 MiB for concurrent jobs. These tradeoffs do not justify changing the current prover. All candidate tests and independent proof audits passed; every sample and the rejected patch are retained.

Four-input/native timing excludes initialization and CPU auditing.
Eight-input timing includes cohort startup, proof output and shutdown;
CPU auditing is excluded. First-use profiles and warmups are separate.
The evaluated candidate passed 46 tests and both feature compile checks.
60 independently CPU-audited outputs represent 192 fresh benchmark proofs.
Required GPU stages, unique proof/root hashes and public tamper checks passed.
Resource budgets and the fixed 250 W power cap are unchanged. Per-workload
sampled memory peaks and all paired timings are retained in the report.
Rejected carry, multiplication, squaring, power and NTT-table screens are
retained. No Apple, cold-cache, full-block or production qualification.

Report: docs/v100-gpu-profile-2026-10-21-pass9.html
Structured evidence: docs/evidence/v100-gpu-profile-2026-10-21-pass9.json
Raw campaign: benchmark-results/gpu-extensive-20261021-pass9
Incremental patch: benchmark-results/gpu-extensive-20261021-pass9/incremental-review.patch
Archive and integrity: final-controller-source.tar.gz and final-integrity.json.

Fresh four-input replay (new tag; includes independent CPU audit):
  python3 benchmark-results/gpu-extensive-20261021-pass9/campaign.py four round_add replay-01
Fresh native replay:
  python3 benchmark-results/gpu-extensive-20261021-pass9/wallet.py sample round_add replay-01
Use the recorded pinned binaries and V100 environment. The round_add
label replays the rejected candidate; baseline replays the retained build.

2026-10-21: V100 first-butterfly load fusion (pass 10)

Selected label: ntt_load.
Retained for consistent aggregation improvements in all seven paired comparisons: median time reductions of 1.71% for four inputs, 4.03% for eight inputs, and 2.07% for two concurrent eight-input jobs. Matched NTT event time fell 9.42%. Native timings have a small observed cost: the original pooled median was 4.53% slower, the fixed twenty-pair follow-up was essentially flat (+0.09% reduction), and the combined thirty-two-pair median was 0.49% slower (median paired regression 0.45%; 13/32 faster pairs). No native speedup is claimed. Qualification GPU peaks fell by 212 MiB for four inputs and 296 MiB for concurrent jobs, with a 66 MiB increase for single eight-input jobs; all resource budgets passed.
four: 29.546746 -> 29.041878 seconds; +1.709% pooled median reduction; 3/3 faster pairs.
single: 56.504475 -> 54.230047 seconds; +4.025% pooled median reduction; 2/2 faster pairs.
concurrent: 102.668805 -> 100.546544 seconds; +2.067% pooled median reduction; 2/2 faster pairs.
wallet: 0.303637 -> 0.317385 seconds; -4.528% pooled median reduction; 6/12 faster pairs.
native followup: 0.305184 -> 0.304923 seconds; +0.085% pooled reduction; 7/20 faster pairs.
native combined: 0.304537 -> 0.306023 seconds; -0.488% pooled reduction; 13/32 faster pairs.
45 targeted tests passed; CPU-only and GPU-without-tuning checks passed.
100 independently CPU-audited outputs contain 232 fresh proofs, including a fixed twenty-pair native follow-up. Original and follow-up native series are both retained. Required GPU
stage coverage, unique root/proof hashes and native public tamper checks passed.
The initial missing publication barrier was caught by the integer oracle,
fixed before timings, and retained with its failed experimental source.
The corrected screen passed 112 oracle configurations; the final source
passed 56 more. All 22 active shared-NTT timed cases improved. Every timed
case, including four unchanged-path controls, remains in the evidence.
No new local storage, launch changes, proof parameter changes or power changes.
No Apple, cold-cache, full-block or production qualification.
Report: docs/v100-gpu-profile-2026-10-21-pass10.html
Structured evidence: docs/evidence/v100-gpu-profile-2026-10-21-pass10.json
Raw campaign: benchmark-results/gpu-extensive-20261021-pass10
Incremental patch: benchmark-results/gpu-extensive-20261021-pass10/incremental-review.patch
Archive and integrity: final-controller-source.tar.gz and final-integrity.json.
Fresh four-input replay (new tag; includes independent CPU audit):
python3 benchmark-results/gpu-extensive-20261021-pass10/campaign.py four ntt_load replay-01
Fresh native replay:
python3 benchmark-results/gpu-extensive-20261021-pass10/wallet.py sample ntt_load replay-01
Use the pinned binaries and recorded V100 environment.

2026-10-22: V100 NTT and S-box scheduling experiments (pass 11)
Selected label: baseline.
Retain the pass 10 implementation. Eight-lane S-box scheduling reduced the matched four-input row-hash GPU event sum by 0.330%, but complete aggregation medians changed by -0.105% (four inputs), +0.121% (eight inputs), and +0.007% (two concurrent jobs), with only 3 of 7 aggregate pairs faster. Native JoinSplit improved by 1.335% pooled and 1.135% paired, with 9 of 12 pairs faster; this positive result is retained and does not establish a broad aggregation benefit. Sampled single-job GPU peak increased 428 MiB; four-input peak was unchanged and concurrent peak was 1344 MiB lower. The candidate does not meet the prespecified requirement for broadly consistent complete-proof benefit. All four NTT candidates were rejected after large-transform regressions, and the two smaller S-box schedules were mixed.
four: 28.933498 -> 28.963746 seconds; -0.105% pooled reduction; 1/3 faster pairs.
single: 53.814758 -> 53.749466 seconds; +0.121% pooled reduction; 1/2 faster pairs.
concurrent: 100.528306 -> 100.520784 seconds; +0.007% pooled reduction; 1/2 faster pairs.
wallet: 0.303246 -> 0.299197 seconds; +1.335% pooled reduction; 9/12 faster pairs.
45 targeted tests and CPU-only/GPU-without-tuning compatibility checks passed.
60 independently CPU-audited outputs contain 192 fresh proofs. Required GPU
coverage, unique proof/root hashes and native public tamper checks passed.
Four NTT candidates passed 200 integer-oracle configurations but regressed
important large shapes. Three hash schedules passed independent integer
arithmetic and Poseidon2 oracles. Eight-lane scheduling advanced after a fixed
24-pair confirmation on six hash workloads. All samples remain in evidence.
No host allocations, launch geometry, proof parameters or power settings changed.
Compiler caches were cleared before baseline first-use/warmup runs for storage;
no compiler caches were cleared during qualification. Cold timings are retained separately.
No Apple, cold-cache, full-block or production qualification.
Report: docs/v100-gpu-profile-2026-10-22-pass11.html
Structured evidence: docs/evidence/v100-gpu-profile-2026-10-22-pass11.json
Raw campaign: benchmark-results/gpu-extensive-20261022-pass11
Incremental patch: benchmark-results/gpu-extensive-20261022-pass11/incremental-review.patch
Archive and integrity: final-controller-source.tar.gz and final-integrity.json.
Fresh four-input replay (new tag; independent CPU audit):
python3 benchmark-results/gpu-extensive-20261022-pass11/campaign.py four baseline replay-01
Fresh native replay:
python3 benchmark-results/gpu-extensive-20261022-pass11/wallet.py sample baseline replay-01
Use pinned binaries and unchanged budgets. Every replay must use a fresh tag.
