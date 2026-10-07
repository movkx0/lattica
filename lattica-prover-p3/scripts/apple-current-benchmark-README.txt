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
