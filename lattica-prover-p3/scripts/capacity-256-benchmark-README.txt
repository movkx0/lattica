Isolated 256-transaction GPU benchmark (2026-10-16)

Cancelled at the user's request: 256 wallet artifacts and 247 of 255 recursive
node artifacts were written before the controller and prover were stopped.
No final root or complete independent CPU audit was produced. This is not a
completed 256-transaction proof or throughput result. Partial artifacts and
source snapshots are preserved; cancellation.json records the stopped run.
The outer launcher's zero exit status reflects service shutdown, not successful
benchmark completion. The workflow described below remains incomplete.

This experiment extends the paired standalone prover to a depth-eight,
256-transaction research profile. It is an overlay on a pinned source copy,
not activation of 256 transactions in the native service or shared checkout.

The complete source change is capacity-256-research.patch. The benchmark's
base-source.tar.gz, source.tar.gz, source manifests, build/test receipts,
executables, controller, inputs, proofs and CPU audits are retained under:

  benchmark-results/gpu-capacity-256-20261016/

Apply the patch only to the preserved base source (or a copy verified against
base-source-manifest.json). The controller and build commands are in control/;
their recorded command.json and build/test receipts preserve exact invocation
arguments. Source, binary and proof manifests identify the measured artifacts.
Do not overwrite the archived run to reproduce it; use a new output directory.

The overlay adds block-v2-capacity-256, a separate candidate/program identity,
16-bit transaction counts, versioned node/worker/calibration/host envelopes,
larger bounded JSON input, and a 1 GiB disk artifact quota. The selected 64/128
count widths and encoding versions are unchanged. Slot indices remain 8-bit;
512 transactions require further work and are not admitted.

The fixture contains 192 user transactions and 64 issuance transactions. A full
run generates 255 recursive proofs with LATTICA_V2_HOST_PIPELINE=1. Wallet and
key preparation are timed separately. The final audit independently verifies
the root, every wallet and every recursive node, then replays the journal.
GPU stage reports must show all 16 required stages on OpenCL for every proof.

Limits remain 3 GiB worker RAM, 1 GiB auditor/coordinator RAM, 4 GiB aggregate
RAM, four CPU threads, zero swap, 7 GiB managed VRAM, 4 GiB context allowance
and 1 GiB GPU headroom. Fresh geometry is measured before GPU admission.

Validation scope: 29 standalone count, parser, plan and pipeline tests pass.
The initial broad driver suite passed 72 and failed 20 tests involving legacy
native-pool fixtures and resource assumptions. Those logs are preserved; native
pool support is outside this standalone experiment. The final selected suite
uses --skip driver::execution::, while the complete proof is separately audited
through the CPU execution/journal path. This is not native-delivery, production
deadline, repeated matched-speedup or sustained-throughput qualification.
