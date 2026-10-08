Lattica: run the current committed sources on Apple Silicon
=========================================================

main is the integration branch for the committed Apple Silicon/Metal backend,
benchmark tooling, shared prover, and persistent multi-GPU pool. Start new work
and create current-source benchmark packages from main.

Completed Mac source integration
--------------------------------

The pending Mac implementation is preserved in checkpoint 1604392 and integrated
with current main at 9733a24. All six previously omitted Rust/Metal modules and
the new benchmark helpers are tracked. The original October 4 and October 6
source archives and measurement evidence are unchanged. See:

  docs/apple-main-integration-2026-10-06.html
  docs/evidence/apple-main-integration-2026-10-06.json

The checkpoint was taken in .tools/worktrees/mac-metal, which contained the
pending source; the older root checkout's local edits were preserved. On this
Mac, the main worktree is /Users/access/code/lattica/.tools/worktrees/main.
Future source commits can use scripts/check-apple-source-commit.py --repo .. to
check completeness, followed by review and relevant correctness tests.

Minimal comparison: two jobs on this 18-thread Mac
-------------------------------------------------

Use focused checks and this two-job screen for routine integration validation.
It compares compact baseline versus direct readback, one fresh eight-input job
per arm. Each arm produces seven recursive proofs and receives an independent
CPU audit. Wallet proof generation and compilation are outside the timing.
A single pair is a screening result, not a repeatable speedup claim.

From lattica-prover-p3 in a clean checkout of the intended main revision, with
Rust 1.96.0, Python and Xcode command-line tools on PATH:

  python3 scripts/build-apple-metal.py --target-root target
  RUSTFLAGS="-C target-cpu=native" cargo test --offline --locked --release \
    --no-default-features --features block-v2-wide-lanes,stream,gpu-metal \
    --lib --no-run

Set native_test_binary to the native libtest executable printed by Cargo, and
screen_output to a new output directory. Then:

  python3 scripts/check-apple-latency.py --binary "$native_test_binary" \
    --out "$screen_output/qualification"
  caffeinate -is python3 scripts/bench-apple-latency.py \
    --build target/metal-build-metadata.json \
    --qualification "$screen_output/qualification/result.json" \
    --fixture fixtures/apple-benchmark-eight \
    --linux ../docs/evidence/block-v2-gpu-default-ram-bench-2026-10-02.json \
    --out "$screen_output/screen" --compact-data --order baseline-first

The qualification checks source/binary hashes and both compact readback layouts
before full-job timing. The screen uses shared Metal storage, specialized
Poseidon, cached NTT tables, CPU quotient and query gather. Direct readback is the
only difference between its arms. The report is screen/report.html. No total
screen timeout or fixed worker RSS cap is applied; system memory pressure remains
monitored. Use a new output directory for each attempt and retain failures.

Optional repetition package for a larger campaign
-------------------------------------------------

The following standard package runs nine full jobs (three settings, three
repetitions). Generate it to freeze a reproducible recipe; execute it only when
a larger repetition campaign is intended. Routine checks use the two-job recipe
above. The integration validation generated this package but ran the minimal
screen, not its nine-job schedule.

Benchmark the current committed integration
------------------------------------------

The original package remains pinned to revision 094cade. To measure the newly
committed sources, create a new package with --revision HEAD. The builder resolves
HEAD to an exact commit and records it in the package, run plan and results.
The repository now includes the same hash-verified public eight-input fixture.

Requirements: native Apple Silicon macOS, at least 64 GiB unified memory, 20 GiB
free disk space, Python 3.11+, Git, Xcode command-line tools and Rust 1.96.0.
Use AC power and keep other heavy workloads idle. Every output path must be new.

In your existing Mac repository:

  git fetch origin main
  benchmark_tag="$(date -u +%Y%m%dT%H%M%SZ)"
  benchmark_package="$HOME/lattica-apple-current-package-$benchmark_tag"
  benchmark_results="$HOME/lattica-apple-current-results-$benchmark_tag"
  git worktree add --detach "../lattica-mac-benchmark-$benchmark_tag" origin/main
  cd "../lattica-mac-benchmark-$benchmark_tag"
  git rev-parse HEAD

  python3 lattica-prover-p3/scripts/prepare-apple-benchmark-package.py \
    --revision HEAD \
    --fixture lattica-prover-p3/fixtures/apple-benchmark-eight \
    --out "$benchmark_package"

Inspect the pinned recipe, then run it:

  python3 "$benchmark_package/run-apple-benchmark-package.py" \
    --repo "$PWD" --out "$benchmark_results" --plan

  caffeinate -is python3 "$benchmark_package/run-apple-benchmark-package.py" \
    --repo "$PWD" --out "$benchmark_results"

The runner creates its own pinned checkout, builds CPU and Metal binaries with
locked dependencies, runs Metal correctness checks, then measures three Metal
settings three times each: quotient control, deferred timing, and compact prover
data with deferred timing. The middle repetition reverses their order. Each
trial produces seven fresh recursive proofs and gets an independent CPU audit.
Thread selection fits the detected CPU count; --threads can select a supported
value explicitly. The selected revision's RSS policy is retained in the
manifest and a hashed policy overlay. Current main observes RSS without a
fixed process cap; the original 094cade recipe retains its 44 GiB limit.
Managed Metal buffers, scratch reservations and stage timeouts remain explicit.

This recipe measures the current shared Metal proving sources on the retained
eight-input workload. The Linux typed two-GPU scheduler uses cgroups/systemd and
needs a separate macOS integration. The direct-readback and opening-denominator
cache switches remain disabled in this optional repetition recipe. The minimal
recipe above explicitly qualifies direct readback on Metal before comparing it;
opening-denominator caching still needs a declared full-job performance comparison. NVIDIA observations
do not qualify their performance or resources on Apple Silicon.

The completed 2026-10-06 workstation capacity qualification is retained in
docs/evidence/block-v2-vram16-capacity-qualification-2026-10-06-r1.json. Its
optimized 16, 32 and 64-input roots passed independent CPU audits. The earlier
interrupted 32-input attempt remains retained. This establishes capacity through
the requested/protocol limit of 64 on the NVIDIA laptop GPU, not a Metal result.
Preserve the original 094cade, baf339e and 6f9faa0 packages when making a new one.

Keep the complete result directory, including failed attempts. Return its
portable-results.tar.gz. After extraction, import the JSON on the development
host with:

  python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py ingest \
    --input /path/to/extracted/portable

These measurements track proving latency and development milestones. Wallet
proof creation, delivered transaction throughput and the two-hour pilot require
their own measurements. The Linux workstation capacity campaign remains complete and its workers are
stopped. The separate Mac integration result above measures eight-input Metal
aggregation and does not establish the NVIDIA capacity limits on Apple Silicon.

Three-worker Apple memory screen (2026-10-07)
--------------------------------------------
The opt-in --memory-optimized mode in bench-apple-concurrency.py adds:
  * Two process-shared permits for preprocessing and trace/quotient stages.
    Trace/quotient permits retire after large trace prefixes and GPU scratch
    are released. Opening work can overlap the next worker's heavy stage.
  * A 2 GiB allowance for the pair of transform scratch buffers, inside the
    existing 7 GiB managed allowance. LDE planning reserves backend NTT tables;
    drained command buffers and completed hash/transform scratch are retired.
  * One read-only, file-backed public preprocessing prefix per circuit mode.
    Cache hits are checked against freshly computed GPU readback. Witnesses,
    hiding RNGs, salts and commitment trees remain private to each worker.

After building and running check-apple-latency.py on the current source:
  python3 scripts/bench-apple-concurrency.py --workers 3 --managed-gib 7     --memory-optimized --build target/metal-build-metadata.json     --qualification <current-qualification>/result.json     --reference <earlier-memory-allowance-comparison>/result.json     --comparison <earlier-two-worker-screen>/result.json --out <fresh-directory>

This mode allows a clearly labelled historical-source comparison. Candidate
binaries must match the current qualified sources; fixture hashes still match
exactly. Every eight-input job needs seven fresh recursive proofs and a separate
CPU root audit. The controller checks the shared file identities and the complete
permit timeline, then removes shared scratch after all owned workers exit.
System pressure monitoring remains enabled. Summed worker RSS double-counts
shared pages and must not be described as unique physical RAM consumption.

The first optimized screen completed three six-thread jobs in 375.566964 s:
230.052 transaction-equivalents/hour, versus the earlier two-worker 204.439/h.
All 21 recursive proofs and three CPU audits passed; pressure stayed normal,
with zero swap growth. Per-worker peak physical footprints were 16.55, 16.73 and
18.13 GiB. This is one screen, not a sustained production throughput result.

Local report and raw evidence:
  /Users/access/code/lattica/benchmark-results/apple-memory-priorities-20261007/report.html
  /Users/access/code/lattica/benchmark-results/apple-memory-priorities-20261007/screen-01/result.json

The controls are isolated to Apple research workers. They do not qualify or
activate the Linux pool runtime. Prior failed screens remain preserved.

Four-worker Apple memory screen (2026-10-07)
-------------------------------------------
The dedicated concurrency runner accepts --workers 4 only with
--memory-optimized. Integer CPU division selects four Rayon threads per worker,
16 total; the three-worker comparison uses 18 total. Use --comparison with the
verified three-worker result. The proof build and fixtures remain identical.

One four-worker, 7 GiB-per-worker attempt stopped after 116.155776 seconds when
macOS memory pressure changed from normal (1) to warning (2). Three of 28 fresh
recursive proofs completed, but no full job or independent CPU root audit did.
No throughput rate can be assigned to this interrupted attempt. Swap growth was
zero; existing swap was unchanged. Sampled aggregate RSS peaked at 57.1539 GiB
and includes duplicated shared-page accounting. The final system snapshot had
28.2655 GiB physically occupied by the compressor and about 45.5 MiB free.

All four workers reused one 6.25 GiB public preprocessing inode (one writer,
three validated cache hits). The observed heavy-stage maximum was two, as
configured. Later readback work overlapped the next heavy stages, so the
current permits do not bound total four-pipeline memory sufficiently for this
machine. All owned processes exited, pressure returned to normal, and shared
scratch was removed. No retry or baseline repetition was launched.

The verified three-worker result remains 230.052 transaction-equivalents/hour.
Retain that configuration while investigating later-stage allocation lifetimes
or broader stage scheduling before another four-worker attempt. This attempt
reused 28 focused correctness checks of unchanged proof binaries; 17 controller
checks passed, and all 197 proof-source hashes matched before and after it.

Local report and raw evidence:
  /Users/access/code/lattica/benchmark-results/apple-four-workers-20261007/report.html
  /Users/access/code/lattica/benchmark-results/apple-four-workers-20261007/screen-01/result.json

Three-worker memory headroom profile (2026-10-07)
------------------------------------------------
The recommended local three-worker screen now adds --query-scratch-mib 2048 to
--memory-optimized. Each worker still has six CPU threads, a 7 GiB managed
allowance, 2 GiB LDE transform scratch and the shared public preprocessing.
The independent query transform pair now uses at most 2 GiB; additional column
tiles preserve every field value, salt, commitment and proof query.

The opt-in memory profile also retires obsolete cached hash/LDE scratch before
opening/query allocations and releases coset, adjusted weights and inverse
denominators after their last consumers. Adjusted weights use only the degree
prefix required for interpolation. Full denominators remain available until
GPU opening reduction completes. Linux and ordinary CPU policies are unchanged.

Optional tighter scheduling is exposed as --late-phase-slots 1|2|3. It uses a
separate file-lock pool from quotient commitment through opening, FRI and query
reconstruction. Handoff acquires the late permit before releasing the early
permit; queue draining and proof-state destruction precede late release. The
pool defaults to disabled. Do not add it to the accepted profile below: the
allocation-only candidate met both targets, so no second window was necessary.

Example after building and qualifying current source (use fresh output paths):
  python3 scripts/bench-apple-concurrency.py --workers 3 --managed-gib 7 \
    --memory-optimized --query-scratch-mib 2048 \
    --build target/metal-build-metadata.json \
    --qualification <current-qualification>/result.json \
    --reference <earlier-memory-allowance-comparison>/result.json \
    --comparison <verified-three-worker-baseline>/result.json \
    --out <fresh-directory>

Native controls:
  LATTICA_APPLE_QUERY_SCRATCH_BYTES=2147483648 (query transform pair only)
  LATTICA_APPLE_LATE_PHASE_SLOTS=2 (optional, requires the private phase directory)
Absent query scratch control preserves the existing managed-allowance planner.
These settings tile scratch and schedule stages; they do not impose a new
worker RSS ceiling or a total benchmark timeout. Invalid CLI settings are
rejected before creating result directories or launching workers.

The single completed candidate screen took 355.822295 seconds:
  Throughput: 242.817837 transaction-equivalents/hour (+5.55% versus 230.052183).
  Worst-worker peak physical footprint: 14.7852 GiB versus 18.1327 GiB (-18.46%).
  Individual peaks: 14.0054, 13.8072 and 14.7852 GiB, sampled every 500 ms.
  All 21 fresh recursive proofs and three independent CPU root audits passed.
  Pressure stayed normal; no swap growth; all processes exited and scratch
  was removed. Existing swap remained allocated from earlier attempts.

Acceptance required >=207.046965/h, <=85% of the baseline's worst-worker peak
and lower compressor growth. All three targets passed. Do not interpret the
sum of process footprints or RSS as unique system RAM usage. This is one
screening window with a historical baseline, not sustained production proof.
The optional late-stage scheduler passed focused correctness and process-death
checks but was not enabled in a full benchmark. No four-worker retry was run.

Generate the HTML comparison with scripts/report-apple-headroom.py --baseline
<baseline>/result.json --attempt <candidate>/result.json --out <report-directory>.
The reporter supports at most two candidate windows and records each acceptance
decision. A second candidate is eligible only after a pressure stop or when
throughput passes but additional memory headroom is needed.

Local report:
  /Users/access/code/lattica/benchmark-results/apple-memory-headroom-20261007/report.html
Raw result:
  /Users/access/code/lattica/benchmark-results/apple-memory-headroom-20261007/screen-01/result.json
Validation: 36 focused native tests, including proof-byte equivalence, CPU
verification, scratch retirement, and early/late permit recovery; 19 controller
checks passed. No full benchmark baseline or matrix was repeated.


FOUR-WORKER SALT CHECKPOINTS AND QUERY SCHEDULING (7 OCTOBER 2026)

Completed two four-worker windows on the 64 GiB Apple M5 Pro. Both completed
28 fresh recursive proofs and four independent CPU root audits, with normal
memory pressure and no additional swap. Settings remain opt-in and separate
from Linux. The existing three-worker benchmark remains available.

Common settings: four worker processes, four Rayon threads each; 7 GiB managed
allowance per worker; 2 GiB LDE scratch; 1 GiB query scratch; two heavy-stage
permits; one query permit; compact salts; shared public preprocessing.

Two late permits: 446.381869 s, 258.074998 transaction-equivalents/hour.
Compressor growth was 12.714 GiB (14.920 GiB peak), exceeding the agreed 6 GiB
headroom criterion even though macOS pressure stayed normal and swap did not grow.

One late permit: 518.719142 s, 222.085500 transaction-equivalents/hour.
This is 8.54% below the earlier 242.817837/hour three-worker screen, within the
accepted 10% tolerance. Compressor growth and additional swap were zero; peak
compressor occupancy was 1.902 GiB. This is the qualified four-worker profile.
Four processes remain in flight, but stage waits limit the observed overlap from
heavy-stage admission through late-stage completion to three proofs. This does
not install a whole-job admission cap or change the four-thread worker pools.

Compact salt matrices keep private ChaCha20 checkpoints every 1,024 rows.
The original field sampler, rejection draws, commitment values and proof bytes
are preserved. A temporary dense matrix still exists while its commitment runs;
it is released only after GPU completion. The largest observed group replaces
4 GiB of retained salt matrices with 38 MiB of checkpoints. This is storage
accounting, not a measured reduction in system peak RAM.

New runner options:
  --compact-salts                 LATTICA_APPLE_COMPACT_SALTS=1
  --query-phase-slots 1            LATTICA_APPLE_QUERY_PHASE_SLOTS=1
Both require --memory-optimized. Query permits are acquired before the engine
mutex and allocations; heavy -> late -> query is the only acquisition order.
Each pool uses process-shared locks released on normal exit, unwind or process
termination. A 500 ms worker sampler emits progress every five seconds as well
as its complete exit record; incomplete interleaved progress lines are counted
and skipped by the report, without discarding complete exit sampling evidence.

Qualified runner arguments (supply fresh output and current build/qualification):
  --workers 4 --managed-gib 7 --memory-optimized --compact-salts
  --query-scratch-mib 1024 --late-phase-slots 1 --query-phase-slots 1
Use bench-apple-concurrency.py with the established fixture/reference arguments.
The accepted throughput floor is 218.536053/hour (527.144140 seconds for four
jobs). This is a report acceptance threshold, not a benchmark timeout. The
controller's historical 200/hour screening target is recorded separately.
No total benchmark timeout or fixed proving-worker RSS ceiling was restored.

Validation: 43 focused native tests in 27 groups, 20 controller checks, and five
report checks passed. Deterministic full proofs match the CPU reference bytes;
independent proofs use fresh randomness. Query error/unwind, four competing
processes and process-death permit recovery are covered. Both timed windows
preserve full raw evidence; no third run was launched.

Evidence:
  /Users/access/code/lattica/benchmark-results/apple-four-workers-salts-20261007/report.html
  /Users/access/code/lattica/benchmark-results/apple-four-workers-salts-20261007/qualified-profile.json
  /Users/access/code/lattica/benchmark-results/apple-four-workers-salts-20261007/qualification-01/result.json

The HTML report includes both windows, the earlier three-worker reference,
horizontal throughput bars, memory measurements, stage waits and cleanup checks.
Single-window measurements do not establish sustained production capacity.


FIVE-WORKER CAPACITY SCREEN (7 OCTOBER 2026)

The concurrency runner now supports --workers 5: three Rayon threads each,
15 total. Five workers require --memory-optimized, --compact-salts,
--late-phase-slots 1, --query-phase-slots 1 and --query-scratch-mib 1024.
The trial kept the 7 GiB managed allowance, 2 GiB LDE scratch, two heavy-stage
permits, shared public preprocessing and staggered starts. There is no total
timeout or fixed worker RSS ceiling; macOS pressure monitoring remains active.

One fresh window completed all five eight-input jobs, 35 fresh recursive proofs
and five independent CPU root audits in 676.556903 seconds: 212.842407
transaction-equivalents/hour. That is 3.61% below the latest four-worker result
(220.811130/hour) and 12.34% below the earlier three-worker result (242.817837/hour).
It exceeded the original 200/hour target but missed the existing 218.536053/hour
optimization threshold. Five workers fit in this sample without improving speed.

Memory pressure stayed normal; additional swap was zero. System compressor
start/peak: 1.7532 / 1.8937 GiB, growth 0.1405 GiB. Sampled aggregate RSS peaked
at 59.8816 GiB and can count shared mappings repeatedly. Worst worker physical
footprint was 11.988964 GiB. Observed stage maxima were heavy=2, late=1, query=1;
maximum concurrent proofs after heavy-stage admission was three (waiting workers
are excluded). All tracked processes exited and shared scratch was removed.

Only Python runner/analysis support changed; all 198 proof-source hashes and
qualified binaries matched the four-worker run. The 21 controller checks and
six report checks passed, including native worker control. Existing 43 native
correctness tests were reused by matching proof-source hashes; they were not
rerun. Report evidence requires all five distinct audited jobs and seven fresh
proofs per worker; partial or duplicate results cannot pass.

Source snapshot, runner diff, proof logs, resource samples and CPU audit logs:
  /Users/access/code/lattica/benchmark-results/apple-five-workers-20261007
Shareable HTML with horizontal throughput bars:
  /Users/access/code/lattica/benchmark-results/apple-five-workers-20261007/report.html
Raw result:
  /Users/access/code/lattica/benchmark-results/apple-five-workers-20261007/screen-01/result.json
This is one screening sample, not sustained production qualification. Earlier
comparison jobs were reused; no extra benchmark window was launched.

Repository copy of the shareable 3/4/5-worker HTML comparison (with embedded
evidence and a JSON download button):
  ../../docs/apple-memory-concurrency-2026-10-07.html

Checkpoint validation (8 October 2026): 31 focused controller/report tests
passed. All 198 native proof-source hashes and qualified binaries still match
the existing 43-test native qualification and the completed four- and five-worker
runs. No full benchmark was repeated to create the source checkpoint.
