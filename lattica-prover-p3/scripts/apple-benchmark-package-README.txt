Lattica Apple Silicon proving benchmark — revision 094cade
========================================================

Purpose
Measure recursive proving latency and development milestones on your Mac.
This package repeats three Metal settings three times each. The second round
reverses their order. Every trial builds seven fresh recursive proofs from the
same eight public wallet proofs and independently audits the root on the CPU.
The measurements do not include wallet input proving or transaction delivery.

Requirements
- Apple Silicon macOS with at least 64 GiB unified memory and 20 GiB free disk.
- Python 3.11+, Git, Xcode command-line tools, and Rust/Cargo 1.96.0.
- An existing Lattica checkout containing commit
  094cade18a59d38d7d65bd805511a7809b348a9e.
  If needed, run: git -C /path/to/lattica fetch origin codex/mac-metal
- Dependencies can be downloaded before building. Use --offline if they are
  already cached. With rustup, install the pinned compiler using:
  rustup toolchain install 1.96.0 --profile minimal
- Use AC power and leave other heavy workloads idle during measurement.

Run
Extract the archive, then run these commands from its directory. Replace the
repository path. Choose a NEW output directory on a volume with free space.

  python3 run-apple-benchmark-package.py --repo /path/to/lattica \
    --out "$HOME/lattica-apple-repetitions-20261004" --plan

  caffeinate -is python3 run-apple-benchmark-package.py --repo /path/to/lattica \
    --out "$HOME/lattica-apple-repetitions-20261004"

The runner creates a detached worktree at the pinned revision. It overlays only
the benchmark controller to enable fresh repetitions. Your active checkout is
left intact. The default thread count is the largest supported setting up to
18 that fits the detected CPUs. --threads 8, 16, 18, or 24 selects another
setting, capped by the actual CPU count. All nine trials use that same value.

Sequence
1. Verify package hashes and environment; record the plan.
2. Build separate CPU audit and Metal proving binaries with locked dependencies.
3. Build and run the Metal correctness suite in shared/copy memory and
   immediate/deferred timing modes. Any failed test stops measurement.
4. Measure quotient control, quotient with deferred timing, and quotient with
   compact prover data plus deferred timing. Repeat each three times, with
   independent CPU audits and seven fresh proofs per trial.
5. Export immutable portable JSON records and package them for repository import.

Limits and interpretation
Mapped scratch: 34 GiB. Managed Metal buffers: 8 GiB. Worker RSS: sampled 44 GiB
limit. Each stage has a 7,200-second timeout. macOS swap and thermal/power state
are observed. Qualification uses a 3 GiB RSS limit and 180 seconds per test.
Expect compilation, qualification and nine trials to take a substantial period;
the package makes no completion-time guarantee. Each step prints its log path.

The controller records proving time as wrapper plus merge worker timers,
including shader initialization and excluding preparation and CPU auditing.
Use repeated results to evaluate these settings on this workload. Mixed-root
transaction throughput and the two-hour pilot remain separate milestones.

Results and recovery
Keep the full output directory. It contains the pinned checkout, binaries,
source archive, hardware qualification, root artifacts, resource samples, logs,
campaign/result.json and package-result.json. Interrupt with Ctrl-C if needed.
Failures remain visible; completed audited trials can be exported as partial
evidence. A fresh output directory is required for another attempt.

Return portable-results.tar.gz for import into the Git benchmark repository.
It includes portable/*.json, the run plan, package manifest and completion or
failure status. Public proof payloads and private wallet data are excluded from
this portable result archive. This package itself includes only the pinned
public test proofs and their verification material.

To import the portable JSON on the development host after extracting results:
  python3 lattica-prover-p3/scripts/block-v2-benchmark-report.py ingest \
    --input /path/to/extracted/portable

Keep the full Mac output until that import is checked. When it is no longer
needed, git -C /path/to/lattica worktree remove --force /path/to/output/checkout
removes the benchmark checkout and its build artifacts. Retain campaign/
and the result JSON as evidence.
