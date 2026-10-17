Same-GPU two-worker experiments, 2026-10-16/17

This is an isolated comparison of two independent, complete 8-transaction
recursive proofs on the RTX 5080. Each block contains six user transactions and
two issuance transactions, produces eight fresh recursive proofs, and ends in
the depth-seven root of the 128-capacity profile. It does not parallelize the
DAG of one full 128-transaction block. Existing wallet proofs and registry keys
are inputs; wallet proving is outside the measured interval.

Evidence directories (relative to the prover crate):
  benchmark-results/gpu-two-workers-specialized-20261017 (specialized kernels)
  benchmark-results/gpu-two-workers-full-budget-20261017 (normal managed budget)
  benchmark-results/gpu-two-workers-20261016-v3 (smaller managed budget)
  benchmark-results/gpu-two-workers-context-20261016 (separate calibration)
  benchmark-results/gpu-two-workers-20261016-v2  (startup rejection retained)
  benchmark-results/gpu-two-workers-20261016     (reservation rejection retained)

All variants change only isolated source under their evidence directories:
  - The controller owns the existing exclusive canonical GPU device flock.
    It passes descriptors over a private Unix socket to its assigned systemd
    services. Peer credentials and cgroups are checked. Each worker validates
    the descriptor's owner, permissions, inode, and exclusive lock ownership.
    Ordinary workers remain excluded until all holders exit.
  - After the transferred device lease is validated, the experimental worker
    may use a 192 MiB context allowance (224 MiB in the smaller-budget and
    specialized runs).
    Ordinary workers retain the 512 MiB minimum. A complete single-worker
    calibration must show at least 25% context margin before concurrent work
    starts.

The normal-budget and smaller-budget variants retain the original 4 GiB
context gate for specialized quotient kernels. Their smaller context allowance
therefore selects the generic
GPU quotient interpreter. This explains their roughly 44-to-55-second single-
worker slowdown; restoring the full managed allocation budget does not fix it.
All 16 proving stages still execute on OpenCL, without CPU arithmetic fallback.

The specialized variant records whether the device lease was validated and
permits specialization at 224 MiB context only with that transferred lease.
It retains the compiler/device/shape checks, caps resident private backing at
64 MiB (versus the normal 128 MiB), and enforces the context allowance at every
synchronized checkpoint. The controller requires eight selected specialized
quotients per worker, plus a fresh complete calibration with 25% context margin.
Ordinary workers retain the original 4 GiB specialization gate. This is an
empirically calibrated experiment for this fixture, not a general context limit.

The original GPU allocation path is retained. All managed allocation,
host-memory, per-buffer, randomness, witness, and transcript
reservation checks remain active. There is no admission override for their
aggregate reservation. The attempted unused-buffer optimization was reverted:
it shifted approximately 128 MiB into measured driver overhead.

The normal-budget run gives each worker 7 GiB managed VRAM and 192 MiB context;
the smaller-budget and specialized runs use 7,064 MiB managed VRAM and 224 MiB
context. All use 1 GiB maximum GPU buffers, 3 GiB RAM per worker, four Rayon
threads per worker, no swap, and no scratch cache. Both workers share CPUs 0-3
and a 400% aggregate CPU quota. The fleet RAM cap is 7 GiB and
is restored to its prior value afterward. Admission requires 14,848 MiB free
VRAM for the normal-budget run, or 14,704 MiB for the other runs,
including 128 MiB shared headroom. Sampled free VRAM below 128 MiB or
an unexpected compute process aborts the experiment.
Admission waits up to three minutes for that envelope, outside measured time.

Run order: one standard single-worker reference; one calibration with the
selected budget; then a sequential pair and a concurrent pair. The smaller-
budget and specialized experiments repeat in reverse order, for two pairs per
mode. Only those pairs enter the comparison. Per-process timing spans process
startup, GPU initialization, proving, serialization, and shutdown. Sequential
pair time is the sum of its two process durations; concurrent pair time is
the union makespan. Controller wall time and actual overlap are also recorded.
Throughput divides 16 total transactions (12 user transactions) by pair time.
Every root, selected wallet, recursive node, and journal replay is separately
CPU verified. Audit time is excluded from proving throughput.

Validate retained evidence from the repository root:
  python3 lattica-prover-p3/scripts/report-gpu-two-worker-benchmark.py \
    lattica-prover-p3/benchmark-results/gpu-two-workers-specialized-20261017

Prepare another run from that complete source/binary snapshot (no proofs are
reused). The destination must be a new sibling directory:
  python3 lattica-prover-p3/scripts/repeat-gpu-two-worker-benchmark.py \
    lattica-prover-p3/benchmark-results/gpu-two-workers-specialized-20261017 \
    lattica-prover-p3/benchmark-results/gpu-two-workers-repeat

Add --run to execute the bounded controller. GPU/systemd access is required.
This repeat helper needs the original pinned support, CPU binaries, fixture,
and source archives to remain available; it verifies their hashes. It does
not download dependencies, rebuild code, or generate wallet proofs. Afterward
run the reporter on the new directory. A failed controller may leave its own
failed systemd unit loaded; inspect it and reset only that experiment's failed
unit before retrying into another fresh evidence directory.

The specialized source delta is gpu-two-worker-specialized-research.patch;
the normal-budget delta is gpu-two-worker-full-budget-research.patch;
the smaller-budget delta is gpu-two-worker-research.patch. Each evidence
directory also has its own source.patch. The patches apply to a copy of the pinned
gpu-host-pipeline-128-20261016 snapshot, from its experiment root with -p1.
The final build command and compiler output are in control/build-command.json,
build-results.json, and build.log. Source, control, fixture, support, binary,
and proof manifests bind the retained evidence. The measured controller and
all helper sources are preserved under control/; do not edit a measured run.

One or two repetitions per mode are exploratory evidence, not a sustained-
throughput qualification. GPU memory and combined RAM peaks are sampled; worker RAM
peaks use cgroup counters. Overlapping GPU processes do not establish that
their kernels execute simultaneously. Production defaults are unchanged.
