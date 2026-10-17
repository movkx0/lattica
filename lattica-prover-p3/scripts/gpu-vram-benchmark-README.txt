GPU VRAM comparison over the pinned 128-transaction prover

benchmark-gpu-vram.py runs small, independently audited comparisons using the
executables, source manifests, wallets and keys preserved by the 2026-10-16
128-transaction and host-pipeline benchmarks. Those input directories are
required; a clean checkout alone does not contain them. No compilation or
production-profile change occurs. The cancelled 256-transaction experiment is
not used or resumed.

Each default trial contains eight transactions (six user, two issuance), eight
fresh recursive proofs, and a final depth-seven root. Every trial is followed
by CPU root verification, verification of all selected wallets and recursive
nodes, and durable journal replay. Preparation and CPU audits are outside the
full GPU process timing. The default host pipeline is enabled in every arm.

Physical limits remain 3 GiB worker RAM, 1 GiB controller/auditor RAM, 4 GiB
aggregate RAM, four CPU threads and zero swap. GPU context allowance remains
4 GiB and headroom remains 1 GiB. Larger-memory arms require at least 14 GiB
free VRAM and 14 GiB usable capacity before launch; every GPU stage rechecks
free memory. Per-buffer assignments must fit the OpenCL hardware limit.

Configuration       Managed VRAM   Buffer limit   Scratch cache ceiling
baseline            7 GiB          1 GiB          disabled
wide                9 GiB          2 GiB          disabled
cached              9 GiB          2 GiB          2 GiB
roomy               9 GiB          1 GiB          disabled
roomy-cached        9 GiB          1 GiB          2 GiB

These are ceilings, not predicted or observed physical peaks. The existing
scratch cache clears attempt data before retaining buffers and only reuses
matching shapes. Larger VRAM does not imply that caching or larger batches
will improve throughput.

From the repository root, using a NEW output directory for every experiment:

  python3 lattica-prover-p3/scripts/benchmark-gpu-vram.py \
    --source-run lattica-prover-p3/benchmark-results/gpu-host-pipeline-128-20261016 \
    --fixture-run lattica-prover-p3/benchmark-results/gpu-capacity-128-20261016 \
    --output lattica-prover-p3/benchmark-results/NEW-vram-comparison \
    --count 8 --repetitions 2 --variants baseline wide cached

To isolate added memory from the doubled per-buffer limit, use another NEW
output directory and --variants baseline roomy roomy-cached.

Both commands run one excluded baseline warm-up followed by the selected
variants in forward order, then reverse order. Existing output directories
are refused. A cooperative GPU fleet lease prevents overlapping experiments;
unrelated applications are never stopped. Logs, stage receipts and sampled
RAM/VRAM telemetry are retained even when a stage fails or is interrupted.
Completion requires completion.json, not just a zero systemd shutdown status.

After successful completion:

  python3 lattica-prover-p3/scripts/report-gpu-vram-benchmark.py \
    lattica-prover-p3/benchmark-results/NEW-vram-comparison

The report verifies input/source/binary hashes, all CPU audits, the 16-stage
OpenCL proof reports, memory/swap receipts, transform plans and GPU teardown.
It writes summary.json and proof-manifest.json. It reports full-process
timings, per-stage device times, actual tile sizes, scratch reuse and sampled
memory peaks. Small-workload results must not be represented as complete
128-transaction timings or as sustained production throughput.

Admission regression checks:

  python3 lattica-prover-p3/scripts/test-benchmark-gpu-vram.py

Recorded results (2026-10-16):

  lattica-prover-p3/benchmark-results/gpu-vram-pilot-20261016/
  lattica-prover-p3/benchmark-results/gpu-vram-roomy-20261016/
  docs/evidence/block-v2-gpu-vram-comparison-2026-10-16.json

The wider-buffer arms were 1.98% and 2.16% slower than their matched control.
Keeping 1 GiB buffers with the larger managed budget was 0.31% faster, or
0.39% faster with scratch reuse, in this small two-repetition pilot. All 14
trials and 112 recursive proofs passed independent CPU audits. The current
prover defaults are retained; these results do not establish a substantial or
general speedup from the extra VRAM.
