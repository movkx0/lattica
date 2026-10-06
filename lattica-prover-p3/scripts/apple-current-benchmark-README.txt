Lattica: run the current committed sources on Apple Silicon
=========================================================

The original package remains pinned to revision 094cade. To measure the newly
committed sources, create a new package with --revision HEAD. The builder resolves
HEAD to an exact commit and records it in the package, run plan and results.
The repository now includes the same hash-verified public eight-input fixture.

Requirements: native Apple Silicon macOS, at least 64 GiB unified memory, 20 GiB
free disk space, Python 3.11+, Git, Xcode command-line tools and Rust 1.96.0.
Use AC power and keep other heavy workloads idle. Every output path must be new.

In your existing Mac repository:

  git fetch origin v3
  git worktree add --detach ../lattica-mac-benchmark origin/v3
  cd ../lattica-mac-benchmark

  python3 lattica-prover-p3/scripts/prepare-apple-benchmark-package.py \
    --revision HEAD \
    --fixture lattica-prover-p3/fixtures/apple-benchmark-eight \
    --out "$HOME/lattica-apple-current-package-20261006"

Inspect the pinned recipe, then run it:

  python3 "$HOME/lattica-apple-current-package-20261006/run-apple-benchmark-package.py" \
    --repo "$PWD" --out "$HOME/lattica-apple-current-results-20261006" --plan

  caffeinate -is python3 "$HOME/lattica-apple-current-package-20261006/run-apple-benchmark-package.py" \
    --repo "$PWD" --out "$HOME/lattica-apple-current-results-20261006"

The runner creates its own pinned checkout, builds CPU and Metal binaries with
locked dependencies, runs Metal correctness checks, then measures three Metal
settings three times each: quotient control, deferred timing, and compact prover
data with deferred timing. The middle repetition reverses their order. Each
trial produces seven fresh recursive proofs and gets an independent CPU audit.
Thread selection fits the detected CPU count; --threads can select a supported
value explicitly. The fixed memory policy is retained in the manifest.

This recipe measures the current shared Metal proving sources on the retained
eight-input workload. The Linux typed two-GPU scheduler uses cgroups/systemd and
needs a separate macOS integration. The new direct-readback and opening-denominator
cache switches remain disabled in this recipe; they need explicit Metal
qualification before adding them to a declared comparison. NVIDIA observations
do not qualify their performance or resources on Apple Silicon.

Keep the complete result directory, including failed attempts. Return its
portable-results.tar.gz. After extraction, import the JSON on the development
host with:

  python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py ingest \
    --input /path/to/extracted/portable

These measurements track proving latency and development milestones. Wallet
proof creation, delivered transaction throughput and the two-hour pilot require
their own measurements. No new workstation experiment was started for this
handoff; the workstation performance work is paused at the user's request.
