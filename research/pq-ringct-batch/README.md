# Ordered post-quantum RingCT batch research

This standalone package extends complete registered MatRiCT graph proofs with
aggregate-child recursion. Its source is outside the frozen RingCT/prover source
roots. The two-graph baseline, its source identity, and its caches remain
independent. The original run lost its owning session without a terminal result.
Build and acceptance tools now require the separate
`complete-spend-acceptance-recovery-v2-1db18b9e1bece2fd.json` record; the original
and first recovery lost their owning sessions without terminal results, and their
records and partial caches are preserved. Recovery reuses byte-identical copies
and re-verifies cache hits under reconstructed trusted keys.

The intended contract binds the graph profile, common context, original statement
count, ordered interval coverage, and an ordered statement root. Base children
come from complete `graph_tree::NodeKey` proofs through the public
`compile_complete` API. Recursive children use this package's own registered batch
keys. Canonical splits use the largest power of two strictly below the combined
count; an odd tail is carried without duplicating a statement.
For one original statement, final verification uses its complete graph proof
directly. For `N >= 2`, a complete binary batch has `N - 1` merge nodes, each
proving both child verifiers. This reduces the number of proofs presented at the
root while adding proving work. Expected-root verification still takes the
original ordered statements, and aggregation does not supply data availability.

The existing `spend_pair::PairKey` has no public recursive-verifier emitter.
This package starts from complete graph children and gives its own batch keys the
metadata required for further recursion. It does not require an accessor change
inside the frozen child library.

## Prepared build and check stages

`tools/frozen_build.py` prepares direct `rustc` commands against the exact
Cargo-emitted artifacts from `graph-prefix-first4-v2-build.json`. It does not run
Cargo or resolve dependencies. Its default mode reads and prints a plan without
writing or launching a subprocess.

```sh
python3 research/pq-ringct-batch/tools/frozen_build.py --stage build --label v1
```

Execution is a separate, explicitly coordinated action after the existing full
baseline is terminal and reaped:

```sh
python3 research/pq-ringct-batch/tools/frozen_build.py --stage build --label v1 \
  --execute --exclusive-window-note "Coordinator released the build window"
python3 research/pq-ringct-batch/tools/frozen_build.py --stage check --label v1 \
  --execute --exclusive-window-note "Coordinator released the check window"
```

Each subprocess receives an 8 GiB address-space limit and two Rayon threads.
Admission requires 10 GiB currently available memory and 16 GiB free disk.
Build and ordinary non-ignored tests have separate records. This harness has no
proof stage; actual graph replay and recursive proof qualification need their own
guarded acceptance runner described below. These commands being documented does not establish a
successful build, test, or proof.

The Cargo manifest describes a future independent workspace. A Cargo build must
first pin and audit its own dependency resolution and features; the child
package's lockfile is not the resolver lockfile of this workspace. The initial
direct-link route avoids that ambiguity.

## Reusing baseline proofs

Baseline cache payloads contain actual proofs and public values, but do not
persist trusted graph keys. A later client can recover those keys and proofs
through the unchanged `SpendPipeline` with byte-identical copied caches. This
still compiles/registers trusted programs and verifies cache hits. Missing entries
can trigger proving through the existing load-or-prove APIs, so replay must first
qualify the complete inventory and use its own job directory.

An untrusted cache cap cannot supply a trusted key. Editing frozen sources or
manifests changes the child source fingerprint and cache identities; old entries
must not be relabelled. Batch artifacts require an independent
version/source identity, trusted-key binding, and cache namespace.

Once an authenticated final `BatchKey` exists, final verification needs the
aggregate proof and the expected ordered statement digests, without the child
proofs. Independently deriving those digests still requires the original public
statements. Today's key-reconstruction path uses the original statement and native
MatRiCT proof bytes, reconstructed graph, and descendant STARK proofs. The native
proof is an outer-proof witness, not the wallet's signing secrets.

The saved `(public, proof)` artifact omits its trusted key. No supported,
qualified reconstruction or authenticated key-import path starts from that
artifact and public statements alone. A registration-only path using proof-shape
templates is possible future work; templates are not valid proofs. Production
block sizing must account for the chosen trusted-key mechanism and required
public/ledger data. It need not assume that every cached proof is permanent block
data. See the [key-availability source assessment](../pq-ringct/data/batch-key-availability-source-assessment-v1.json).

Complete graph/batch proofs establish the standalone relation. Ledger membership,
spent-state checks, fees, data availability, and transaction integration remain
separate requirements. Qualification requires successful runtime evidence;
source preparation and proof-artifact size alone establish neither production
block size nor compute savings.

## Prepared N3/N4 acceptance

`tools/accept_recursive_batch.py` is a separate build/prove runner for
`tools/accept_recursive_batch.rs`. Both stages require a successful terminal
two-graph baseline, exact frozen artifacts, both original fixture hashes, the
complete baseline cache inventory, and matching successful batch-library
build/check records. Default invocation only validates and prints its plan:

```sh
python3 research/pq-ringct-batch/tools/accept_recursive_batch.py \
  --stage build --label v1 --batch-label v1
```

Execution additionally requires `--execute --exclusive-window-note "..."` in a
coordinated window. The build stage uses the same 8 GiB address-space limit,
10 GiB available-memory admission, two threads, and direct-link dependencies as
the core builder. The prove stage requires a fresh 50 GiB available memory,
48 GiB address-space limit, eight Rayon threads, and 16 GiB free disk after
copying the complete cache and fixtures. It never writes to the original job.

The client recovers original complete graph proofs A and B once. It then proves
N3 `[A, B, A]` and N4 `[A, B, A, B]` under separate batch plans, generating five
merge proofs and preserving every intermediate and final artifact. These are
repeated standalone relations. After both batches are proved, it drops A/B and
reverifies both final proofs and persisted artifacts against their original
ordered statements. Artifacts live in separate `artifacts/case-3` and
`artifacts/case-4` directories.

The prepared acceptance client also checks a corrupted private proof opening for
each aggregate child: one in the final N3 merge and two in the final N4 merge.
It changes the first base coefficient of the child's first trace opening after
normal native admission, keeping the compiled program, trusted caps, and public
values unchanged. It requires the machine's assertions to return `Unsatisfied`,
restores the original witness, and registers that same program for the existing
valid parent proof. Missing diagnostics, other errors, or an accepted mutation
fail acceptance. The runner accepts diagnostic reports only alongside the valid
parent artifact and its verification. These are three sequential assertion
evaluations; they add no STARK proofs and do not establish exhaustive mutation
coverage or corrupt-child negative STARK verification.

Each evaluation admits at most 1 GiB of principal temporary buffers, calculated
with checked arithmetic from the wire count and full trace size. The full trace
is included in case a mutation unexpectedly passes. The resident program and
witness, allocator overhead, and other process memory remain subject to the
existing 48 GiB process guard. Checks run before registration so these buffers do
not overlap the new parent's retained proving LDE. Their wall time is reported
separately and is also included in `case_proving_seconds` and whole-run timings.
The added diagnostic path is source preparation only; compilation and actual
assertion-rejection/positive-control qualification remain pending.

The frozen pipeline has no replay-only API. Admission relies on the completed
baseline and identical sources, parameters, fixtures, and complete copied cache.
Observed proof generation during recovery, missing source-proof cache hits, or
any replay-cache change rejects the run. Every cache hit still undergoes trusted
key reconstruction and cryptographic verification; those registration costs can
be substantial. Only the new batch merges are intended to generate fresh proofs.

The runner records whole-process wall time, CPU time, and peak RSS. Client case
timings cover proving and final verification separately; they are not isolated
per-case CPU or peak-memory measurements. Proof artifact sizes exclude trusted
keys, original transaction/ring data, and ledger availability requirements.
Successful build, replay, and N3/N4 proof claims must be supported by the
corresponding terminal, reaped, and audited runner records.

The client also times the single existing `Plan::verify_expected` call after the
shared graph children have been dropped. `single_plan_verification_seconds`
includes expected ordered-root construction from the supplied statement digests
and one batch STARK verification. The trusted key, plan, decoded proof, and
statement digests are already in memory. Registration, statement-byte hashing,
proof decoding, artifact I/O, and subsequent acceptance/rejection checks are
outside this timer. This is one wall-clock observation per case in a previously
exercised process; caches are not reset, and preceding activity differs between
N3 and N4. It is neither isolated CPU time nor a cold-start or production latency
qualification. The existing `case_final_verification_seconds` still measures the
broader final acceptance phase. No additional verifier call or merge proof is
introduced by this instrumentation.


## OpenCL worktree scope

This worktree carries the current batch relation, public source-fingerprint API
fix, and recursive child-witness diagnostics from `pq-ringct-research`. The copy
is source preparation only; no batch build, proof, or GPU qualification has run.

The optional batch `opencl` feature forwards to
`lattica-pq-ringct-research/opencl`, enabling the shared OpenCL backend for
registered outer proofs. Compilation does not initialize a GPU or request GPU
proving. Execution still requires `LATTICA_PROVING_POLICY=gpu-required`, the
existing complete OpenCL switches, explicit device selection, resource admission,
and successful stage reports. See [the OpenCL qualification notes](../pq-ringct/OPENCL.md).

Native algebra, AES, SHAKE, and auxiliary producers still use CPU-configured
`profile::make_config()` and `p3_uni_stark::prove`. CPU verification and the
explicit compiled-witness diagnostic evaluations also remain CPU work. The
feature therefore enables GPU recursive wrappers; it does not establish GPU
execution of an entire spend or reduce the cost of native proof generation.

Existing full-LDE admission checks in component, graph, producer-branch, and
batch preparation remain conservative and unchanged. GPU feature selection does
not relax those checks or the separate process, host, device, and context limits.

`tools/frozen_build.py` and `tools/accept_recursive_batch.py` remain the CPU
baseline qualification helpers. They link pinned CPU dependency artifacts and
require the frozen CPU source/cache identity. OpenCL source and feature changes
are expected to fail that frozen-input comparison. Do not relabel their results
as GPU evidence or weaken their pins to make this tree pass. A future GPU batch
qualification needs a separate GPU build and source/cache identity, freshly
registered trusted keys, and strict stage evidence after the existing component
qualification gates pass. No such GPU batch runner is provided here.
