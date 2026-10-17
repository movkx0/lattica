Parallel recursive aggregation of a complete 128-transaction block
RTX 5080, isolated experiment, 2026-10-17

Evidence directory (relative to this prover crate):
  benchmark-results/gpu-parallel-aggregation-128-20261017

Each trial starts from the same 128 wallet proofs, twelve registry keys, body,
and independently pinned expected statement. It generates all 127 recursive
proofs afresh for 96 user transactions plus 32 issuance transactions.

The tree is split into two balanced 64-transaction subtrees. Each subtree needs
63 proofs; the final root merge needs one. The sequential mode runs left,
right, then root. The parallel mode runs left and right concurrently, waits
for both verified/durably written subtree outputs and successful worker exits,
then runs the root. A parent reads and verifies its children against their exact
planned statements before proving. No output is reused between trials.

Both modes use the same three-process plan, binary, GPU kernels, fixture, and
budgets. Timing spans the first proving process start through root-process exit,
including dependency and launch gaps. Independent CPU audits, resource admission
waits, wallet proof generation, and registry generation are excluded. Each
worker authenticates the complete wallet fixture. This is a matched comparison
of subtree concurrency, not a new monolithic single-process control.

There is one complete block per mode, sequential first. Before parallel
admission, all 127 proofs in the sequential baseline must pass CPU verification
and demonstrate at least 25% margin within the context allowance. The final
parallel block also receives root-only verification, all-wallet and all-node
CPU verification, and durable journal replay. Every recursive proof must report
all 16 stages on OpenCL and select/execute its specialized quotient kernel.

The two-worker GPU admission and kernel controls are inherited unchanged from
gpu-two-workers-specialized-20261017:
  - 7,064 MiB managed VRAM and 224 MiB context allowance per worker.
  - 1 GiB maximum GPU buffers; scratch cache disabled.
  - 128 MiB shared GPU headroom; 14,704 MiB free required for admission.
  - 3 GiB RAM per worker, 7 GiB aggregate RAM, zero swap.
  - Four Rayon threads per worker, sharing CPUs 0-3 and a 400% total CPU quota.
  - Controller-owned canonical exclusive device flock, transferred only to
    assigned systemd services after peer/cgroup validation.
  - Specialized quotient private backing capped at 64 MiB, synchronized
    context-limit checks, and continuous sampled free-memory/PID monitoring.

Ordinary workers retain their normal GPU lease, context, and specialization
rules. Production sources and defaults are unchanged by this experiment.
This is static partitioning on one GPU, not dynamic work stealing or a native
shared-service qualification. Kernel simultaneity and compute/bandwidth limits
are not established by overlapping GPU process residency.

The isolated driver adds LATTICA_V2_AGGREGATION_PARTITION=left|right|root.
Partitioned output uses distinct result-left/right/root.json receipts and a
controller-created expected.json in one shared proof directory. Only the root
partition claims a root output. The controller publishes the whole-block
result after all three partitions succeed. Existing proof output files are
rejected, not overwritten.

Three focused Rust tests cover complete tree partitioning from four to 128
transactions, dependency closure until the final join, and invalid coordinates
or names. Full GPU proof generation plus independent CPU audits validate the
integrated driver/controller path.

Validate and summarize a completed run from the repository root:
  python3 lattica-prover-p3/scripts/report-gpu-parallel-aggregation.py \
    lattica-prover-p3/benchmark-results/gpu-parallel-aggregation-128-20261017

Prepare a repeat from its validated pinned source/binary snapshot:
  python3 lattica-prover-p3/scripts/repeat-gpu-two-worker-benchmark.py \
    lattica-prover-p3/benchmark-results/gpu-parallel-aggregation-128-20261017 \
    lattica-prover-p3/benchmark-results/gpu-parallel-aggregation-128-repeat

Add --run to execute the copied controller with GPU/systemd access. It copies
source, inputs, binaries, and receipts for unchanged-source tests; it does not
copy recursive proof outputs, rebuild, or rerun those source tests. The pinned
support snapshots and CPU audit binaries must remain available. Afterward run
report-gpu-parallel-aggregation.py against the new directory.

gpu-parallel-aggregation-research.patch reconstructs the measured changes from
the gpu-host-pipeline-128-20261016 snapshot. Apply from a copy of that experiment
root with -p1. The exact command, build result, and compiler output are retained
in control/build-command.json, build-results.json, and build.log. The complete
source/control archive and manifests bind the measured implementation.

When copying Cargo targets, dep-info for the external control/driver module can
still reference its original absolute path. The initial incremental build was
therefore rejected as stale; its unchanged binary was never run. A bounded
cargo clean --package lattica-prover-p3 in this experiment's own target directory
preceded the successful measured rebuild. Both attempts are retained.

One run per mode is exploratory evidence. Memory samples can miss short peaks;
individual worker RAM peaks use cgroup counters. CPU audit time is separate from
proving throughput. The cancelled 256-transaction benchmark is not resumed.
