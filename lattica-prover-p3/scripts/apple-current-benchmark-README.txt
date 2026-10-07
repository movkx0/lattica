Lattica: run the current committed sources on Apple Silicon
=========================================================

main is the integration branch for the committed Apple Silicon/Metal backend,
benchmark tooling, shared prover, and persistent multi-GPU pool. Start new work
and create current-source benchmark packages from main.

Next Mac source commit: preserve the pending Apple implementation
--------------------------------------------------------------

Run this handoff locally on the MacBook Pro, in /Users/access/code/lattica.
The October 4 Apple reports include research source that is still uncommitted
there. The Linux main branch contains the previously committed Apple history
and the persistent pool, but does not yet contain those additional Mac changes.
Do not reset, clean, stash away, or replace the Mac working files with main
before capturing them. Fetching main and creating a branch at the current HEAD
preserve the working files and index.

The commands below fetch the checker without merging main into the dirty Mac
checkout. They create a checkpoint branch and stage source/configuration changes
from root src/scripts/.cargo and lattica-prover-p3 src/scripts/tests, plus the
declared build/Cargo/toolchain files. Each parenthesized block stops on failure.

  (
    set -eu
    cd /Users/access/code/lattica
    git status --short
    git fetch origin main
    checkpoint_tool="$(mktemp "${TMPDIR:-/tmp}/lattica-apple-source-commit.XXXXXX")"
    git show origin/main:lattica-prover-p3/scripts/check-apple-source-commit.py > "$checkpoint_tool"
    checkpoint_tag="$(date -u +%Y%m%dT%H%M%SZ)"
    git switch -c "checkpoint/apple-source-$checkpoint_tag"
    python3 "$checkpoint_tool" --repo "$PWD" --stage
    git diff --cached --stat
    git diff --cached
  )

The checker requires these six previously omitted modules in the index:

  lattica-prover-p3/src/block_v2/gpu_hash/prefix_storage.rs
  lattica-prover-p3/src/block_v2/gpu_quotient_prover/metal.rs
  lattica-prover-p3/src/metal_compute/backing.rs
  lattica-prover-p3/src/metal_compute/diagnostics.rs
  lattica-prover-p3/src/metal_compute/quotient.metal
  lattica-prover-p3/src/metal_compute/resident.rs

It also rejects unstaged source edits, new source files, ignored source files,
merge conflicts and whitespace errors. New Python helpers such as
check-apple-priorities.py and metal_kernel_variants.py are in scope. If it fails,
resolve and explicitly stage the reported paths on this checkpoint branch,
then review the staged diff and continue with the second block below, which
reruns the checker. Do not restart the whole branch-creation block.
Missing modules must be recovered
from the actual Mac source or preserved archive, not reconstructed from reports.

Review the entire staged diff. --stage includes the current contents of files
that were only partially staged. It does not unstage unrelated files already in
the index. Add intended documentation or files outside the declared source scope
explicitly. Keep generated binaries/results out of the commit and retain the
original benchmark evidence and source archive at:

  benchmark-results/apple-priorities-20261004/run-01

After review, run this second block to recheck the index, commit locally, and
push the checkpoint branch. If any source changed since staging, the check
stops the commit; restage and review it first. A failed push leaves the local
checkpoint commit intact; retry the push without creating another commit.

  (
    set -eu
    cd /Users/access/code/lattica
    checkpoint_branch="$(git branch --show-current)"
    case "$checkpoint_branch" in
      checkpoint/apple-source-*) ;;
      *) echo "Stop: use the reviewed Apple source checkpoint branch." >&2; exit 1 ;;
    esac
    checkpoint_tool="$(mktemp "${TMPDIR:-/tmp}/lattica-apple-source-commit.XXXXXX")"
    git show origin/main:lattica-prover-p3/scripts/check-apple-source-commit.py > "$checkpoint_tool"
    python3 "$checkpoint_tool" --repo "$PWD"
    git commit -m "feat: preserve pending Apple Silicon research source"
    git push -u origin "$checkpoint_branch"
  )

This is an explicit check in the workflow, not an automatically installed Git
hook. It proves completeness within the declared source scope, not build or
proof correctness. Before integrating the checkpoint into main, run the relevant
Apple controller and Metal correctness checks and record their results. Merge
the changes while preserving the shared pool/native-delivery work already on
main; do not overwrite main with an older source snapshot. Generate a benchmark
package from the resulting integration commit to measure the combined code.

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
