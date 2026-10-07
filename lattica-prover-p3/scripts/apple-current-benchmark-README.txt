Lattica: run the current committed sources on Apple Silicon
=========================================================

main is the integration branch for the committed Apple Silicon/Metal backend,
benchmark tooling, shared prover, and persistent multi-GPU pool. Start new work
and create current-source benchmark packages from main.

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
needs a separate macOS integration. The new direct-readback and opening-denominator
cache switches remain disabled in this recipe; they need explicit Metal
qualification before adding them to a declared comparison. NVIDIA observations
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
their own measurements. No new workstation experiment was started for this
handoff; the workstation capacity campaign is complete and its workers are stopped.
