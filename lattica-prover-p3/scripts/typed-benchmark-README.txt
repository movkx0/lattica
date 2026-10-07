Mixed-root research benchmark tooling
====================================

Linux GPU bootstrap
-------------------

The typed driver also has explicit register-gpu and prove-gpu commands when
built with the gpu feature. CPU fixture preparation and root audits remain
separate commands. GPU work requires a fresh typed qualification assignment;
the grouped-eight qualification does not authorize a typed run.

Build after other timed comparisons finish:

  cargo build --locked --offline --release --no-default-features \
    --features block-v2-wide-lanes,stream,gpu --bin block-v2-typed-probe

With an independently CPU-registered fixture and a pinned CPU-only audit
binary, the controller launches one GPU worker and a separate CPU root audit:

  python3 scripts/block-v2-typed-cpu-prepare.py \
    --cpu-binary /absolute/pinned/cpu/block-v2-typed-probe \
    --evidence /absolute/fresh/cpu-preparation

Use cpu-preparation/fixture below. Preparation runs the 64 public leaf proofs,
geometry discovery and all five CPU registrations in a dedicated cgroup. It
retains every stage and accounting record, including failed attempts.

  python3 scripts/block-v2-typed-gpu-run.py \
    --gpu-binary /absolute/pinned/gpu/block-v2-typed-probe \
    --cpu-binary /absolute/pinned/cpu/block-v2-typed-probe \
    --fixture /absolute/pinned/typed-fixture --gpu-uuid GPU-UUID \
    --count 4 --scratch /tmp --evidence /absolute/fresh/evidence

The count-four fixture includes JoinSplit, HTLC redeem, HTLC refund and issuance.
The controller derives CPU, RAM, spill and device allowances from this host,
checks compiled geometry, pins every input, records cgroup/GPU telemetry, and
retains the public root, body, expected policy and registry for CPU replay.
Memory-limit events, altered inputs, missing fresh nodes and failed CPU audits
invalidate the attempt. Existing evidence directories are never resumed.

This initial GPU bootstrap keeps RegisteredProgram's conservative full-storage
RAM lower bound (31,675,383,808 bytes). It runs one worker and does not claim
two-GPU mixed throughput. A compact-storage admission model, all required
counts, independent per-device qualifications, and durable application remain
separate gates. The worker time includes fixture copying, proving and the CPU
root audit; preparation/registration is excluded, so it is not the cold-full-64
measurement.

block-v2-typed-probe prepares public synthetic wallet proofs, registers the
five typed programs, plans ordered depth-six trees, runs bounded CPU research
proofs, and independently audits a root plus its public body. It does not
implement durable host application or establish GPU/throughput qualification.

Build (outside timed comparisons):

  cargo build --locked --offline --release --no-default-features \
    --features block-v2-wide-lanes,stream --bin block-v2-typed-probe

From lattica-prover-p3, with a fresh artifact directory:

  target/release/block-v2-typed-probe fixture /absolute/path/to/fixture
  target/release/block-v2-typed-probe geometry /absolute/path/to/fixture

The fixture has 64 distinct public transactions under one anchor and chain,
ordered as JoinSplit, HTLC redeem, HTLC refund, issuance, repeating. Both HTLC
paths use block height 10; issuance uses independently declared amount 7.
Witnesses are deterministic demo values; proving randomness remains fresh.
Only public statements and proofs are written. No real funds are involved.

For native commitment checks without leaf proving, fixture-statements OUT
writes just the public body. The Zig block-v2-expected-root calculator accepts:

  block-v2-expected-root root-mixed PROFILE_HEX CHAIN_HEX KIND:PUBLIC_HEX ...

KIND is 1 (JoinSplit), 2 (HTLC), or 3 (issuance). PUBLIC_HEX is 26 canonical
little-endian u64 fields for JoinSplit/issuance and 31 for HTLC, hex-encoded
without separators. It preserves the supplied order and pads 1..64 entries to
depth six. This independent native calculation is not proof verification or
host policy approval. Compare its root with the controller's expected document.

After building both tools, run the repeatable native cross-check:

  python3 scripts/block-v2-typed-interop.py \
    --rust target/release/block-v2-typed-probe \
    --zig ../zig-out/bin/block-v2-expected-root --evidence /fresh/interop

It checks all required counts against both implementations and rejects altered
root, height and mint expectations. It retains tool pins, commands and results
as JSON. Its profile ID is deliberately synthetic; no registered proof or
durable host acceptance is claimed by this native check.

Geometry does not register preprocessing or prove a recursive node. Retained
LDE bytes are a lower bound, excluding other allocations and system reserves.
Each new binary/geometry/device still needs measured resource qualification.

Register modes 1 through 5 in separate, bounded worker processes:

  block-v2-typed-probe register FIXTURE MODE WORKER_BYTES

Each register/prove-cpu process must already be in a dedicated Linux cgroup v2
with MemoryMax exactly WORKER_BYTES and MemorySwapMax=0. Reserve OS/coordinator
headroom and account for other processes before launching. Rayon threads are
capped by std::thread::available_parallelism (including process CPU limits),
and may be lowered with RAYON_NUM_THREADS. GPU configuration variables must be
unset or zero. GPU initialization is never performed by this CPU tool.

After all five registrations, create the expectation in a trusted controller
location, before starting the proof worker:

  block-v2-typed-probe expected FIXTURE COUNT /trusted/expected-COUNT.json
  block-v2-typed-probe plan FIXTURE /trusted/expected-COUNT.json
  block-v2-typed-probe prove-cpu FIXTURE /trusted/expected-COUNT.json OUT WORKER_BYTES

Required counts are 1, 2, 3, 4, 8, 16, 32, 63 and 64. Each uses the ordered
prefix and canonical empty subtrees to reach depth six. Wrapper proofs are
grouped by transaction type to reuse preprocessing. Merges preserve the
original positions. OUT must be fresh: nodes are never silently resumed or
overwritten. The full-64 reference path makes 127 recursive proofs; the count-1
path makes 13. These counts describe work, not measured execution times.

Run a separate CPU audit with independently retained expected policy/body:

  block-v2-typed-probe audit-root REGISTRY_DIR /trusted/expected-COUNT.json \
    /trusted/body.json OUT/node.6.0

REGISTRY_DIR needs only height.json and key.1 through key.5. The audit does not
read wallet proofs, intermediate nodes or the worker's result/expected file.
It checks body order, transaction labels, height, authorized mint amounts,
chain, profile, count, depth, proof size and the recursive proof. The trusted
controller must pin the binary, registry, expected document and body before
launch and retain their hashes with timing/resource evidence.

Artifacts use bounded canonical codecs and exclusive, synced regular-file
writes. Failures retain their artifacts for diagnosis; incomplete runs are not
successful timing samples. These are research artifacts, not a crash-recovery
protocol for a production node.

The root/body audit is only a cryptographic gate. Complete host-ready timing,
durable state application, restart/reorg/resource-failure recovery, mixed GPU
admission, cold-64 <=600s and post-seal <=180s remain separate pilot gates.

Finalizer compiler research
---------------------------
src/block_v2/machine/typed_finalizer.rs defines a separate six-key registry and
a terminal mode that verifies one smaller subtree, then constrains its canonical
right padding to depth six. The separate executable
block-v2-finalized-probe selects this registry. The default block-v2-typed-probe
continues to use five keys. Key artifacts, profile identities and GPU workload
markers differ between them. Qualification remains specific to each binary,
registry, device, geometry and assigned budget.

Planned recursive proof counts (wallet proofs and registration excluded):

  Inputs        1   2   3   4   8  16  32   63   64
  Reference    13  13  15  15  21  35  65  127  127
  Finalizer     2   4   8   8  16  32  64  127  127

Counts above 32 already need a depth-six subtree and bypass the finalizer.
Proof counts do not predict elapsed time. All six programs must be registered
at a stable shared height before proving, with a new trusted registry/profile,
separate resource qualification and an independent root-only CPU audit.

Compiler and interpreter checks, run from lattica-prover-p3:

  cargo test --locked --release --no-default-features \
    --features block-v2-wide-lanes,stream --lib \
    block_v2::machine::typed_ -- --test-threads=1

The real-child test verifies genuine small CPU proofs inside the finalizer
interpreter. It does not generate a complete finalizer proof or measure GPU
performance. The retained JSON documents that distinction:
docs/evidence/block-v2-typed-finalizer-2026-10-04.json (repository-relative).

Preparing and qualifying the finalizer construction
-------------------------------------------------
Build separate CPU and GPU copies of block-v2-finalized-probe. Both use
--no-default-features --features block-v2-wide-lanes,stream; the GPU copy adds
,gpu. Preserve the binaries and their source snapshot before measurement.

Prepare six CPU keys in a NEW evidence directory. --public-fixture optionally
reuses all 64 pinned public leaf proofs; height and keys are always prepared
anew for this construction:

  python3 scripts/block-v2-typed-cpu-prepare.py --construction finalizer \
    --cpu-binary /pinned/cpu-block-v2-finalized-probe \
    --public-fixture /existing/public-fixture --evidence /new/preparation

Run a fresh root with an independent CPU audit using a NEW run directory:

  python3 scripts/block-v2-typed-gpu-run.py --construction finalizer \
    --gpu-binary /pinned/gpu-block-v2-finalized-probe \
    --cpu-binary /pinned/cpu-block-v2-finalized-probe \
    --fixture /new/preparation/fixture --gpu-uuid GPU-ASSIGNED-UUID \
    --count 4 --evidence /new/count4-run

The root-only audit bundle includes all six keys. The worker must produce every
planned fresh node, including the terminal mode-six proof for counts <=32.
Controllers retain the full-storage RAM guard and single-worker admission.
Do not transfer grouped-eight or five-key resource qualification to these runs.

After a real mixed root succeeds, preserve and run the negative-audit script:

  python3 scripts/block-v2-typed-negative-audit.py \
    --cpu-binary /pinned/cpu-block-v2-finalized-probe \
    --bundle /new/count4-run/001-typed/root-only --keys 6 \
    --out /new/negative-root-audits

The output directory must be new. The script requires a passing original-root
audit, then ordinary CPU rejection of altered root, height, issuance, body order,
proof bytes, wrapper registry key and finalizer registry key. It preserves the
original artifacts, mutation hashes, commands and logs. These checks reuse the
root and do not measure fresh proving or delivered throughput.

The first count-four finalizer GPU root and all seven rejection checks passed.
Results are in docs/evidence/block-v2-typed-finalizer-gpu-2026-10-04.json,
relative to the repository root. It is one observation under conservative
budgets; repeated equal-resource comparisons and the other qualification gates
remain pending.

Matched reference/finalizer measurements
---------------------------------------
Use CPU and GPU executables built from the same pinned proof sources. Prepare
fresh five-key and six-key registries before timing; both fixtures must have the
same shared height and all 64 identical public wallet proofs and body bytes.

  python3 scripts/block-v2-typed-compare.py \
    --reference-gpu /pinned/gpu-block-v2-typed-probe \
    --reference-cpu /pinned/cpu-block-v2-typed-probe \
    --reference-fixture /reference/preparation/fixture \
    --finalizer-gpu /pinned/gpu-block-v2-finalized-probe \
    --finalizer-cpu /pinned/cpu-block-v2-finalized-probe \
    --finalizer-fixture /finalizer/preparation/fixture \
    --gpu-uuid GPU-ASSIGNED-UUID --count 4 --pairs 5 --evidence /new/comparison

The first pair runs reference then finalizer; subsequent pairs alternate order.
All trials use one recorded CPU/GPU/RAM/spill assignment. The controller derives
it from the actual system, leaves 10 percent of the available worker and spill
allowances unused where the full-storage guard permits, and checks live admission
before every trial. It preserves the CPU topology, GPU context/headroom margins,
driver identities, host reserves, no-swap policy and scratch filesystem. Capacity
loss stops the campaign and preserves the failed attempt; limits never change
silently between trials. No builds or report rendering should overlap these runs.

Every trial produces fresh recursive proofs and a separate CPU root-only audit.
summary.json records individual runs, complete pairs, median worker times and the
median reduction calculated within each pair. Partial pairs never become matched
measurements. Registration, wallet proving and durable host application remain
outside this timing boundary. The controller does not qualify delivered throughput.
Keep the entire evidence directory and import it after the campaign stops.

Compact GPU prover data is already enabled in these runs. The conservative
31,675,383,808-byte full-storage admission guard remains in place; qualifying a
lower bound for the compact layout is separate work.

Experimental compact admission and a mixed-root fleet
----------------------------------------------------
The new compact admission path needs rebuilt binaries and its own hardware
qualification. The ordinary typed runner still defaults to --ram-admission full.
The compact path checks retained prefixes and the phase-aware RAM/spill/GPU model;
neither a payload calculation nor controller tests establish a safe worker cap.

Prepare the public fixture and six trusted keys before these runs. First qualify
one root on each device sequentially, using the resource shares for both slots:

  python3 scripts/block-v2-typed-multi-gpu-run.py \
    --construction finalizer --ram-admission compact \
    --gpu-binary /pinned/new-gpu-block-v2-finalized-probe \
    --cpu-binary /pinned/new-cpu-block-v2-finalized-probe \
    --fixture /pinned/six-key-fixture --count 4 \
    --gpu-uuid GPU-FIRST-UUID --gpu-uuid GPU-SECOND-UUID \
    --mode sequential --evidence /new/two-slot-sequential

Then use a new evidence directory and the same binaries, fixture, devices and
count with these additional options:

  --mode concurrent \
  --resource-assignment /new/two-slot-sequential/resource-assignment.json \
  --evidence /new/two-slot-concurrent

Both modes reserve the same number of worker slots. The sequential control uses
the same per-worker CPU/RAM/spill quotas as the concurrent run. Every worker gets
the limits for its actual GPU UUID and an independent CPU root audit. The parent
cgroup's memory-event deltas are checked as well as each worker's counters.
Capacity loss rejects a fixed assignment; execution never quietly falls back to
fewer workers. Failures stop the remaining workers and preserve their evidence.
Scratch is retained until both the worker cgroup and its GPU contexts are gone.
These are separate fresh roots over the pinned public fixture; delivered
transaction throughput and within-root scheduling remain separate milestones.

Paired typed construction
-------------------------
The separate block-v2-paired-probe uses twelve trusted keys and the
construction name paired. It verifies both wallet slots, including the
repeated proof used when only the left input is occupied. Tree order and
canonical right padding are preserved. A separate key format and workload
profile prevent reuse of a reference/finalizer qualification.

Build pinned CPU and GPU copies with the same source and feature geometry:
  --no-default-features --features block-v2-wide-lanes,stream
  --no-default-features --features block-v2-wide-lanes,stream,gpu

Prepare fresh paired keys while reusing the pinned public wallet proofs:
  python3 scripts/block-v2-typed-cpu-prepare.py \
    --construction paired --cpu-binary /pinned/cpu-block-v2-paired-probe \
    --public-fixture /pinned/existing-public-fixture \
    --evidence /new/paired-cpu-preparation

Then qualify a count-four paired root with independent CPU replay:
  python3 scripts/block-v2-typed-gpu-run.py \
    --construction paired --ram-admission compact \
    --gpu-binary /pinned/gpu-block-v2-paired-probe \
    --cpu-binary /pinned/cpu-block-v2-paired-probe \
    --fixture /new/paired-cpu-preparation/fixture --count 4 \
    --gpu-uuid GPU-DEVICE-UUID --evidence /new/paired-count-four

Run block-v2-typed-negative-audit.py with --keys 12 on the retained root-only
bundle. Paired device/context calibration must use paired evidence with the
same binary, profile and managed allocation. Six-key timing and admission
results do not qualify this construction. The compiler proof-count plan
is not an elapsed-time measurement; preserve all failed attempts and resource
accounting before comparing fresh roots under matched assignments.

Query readback experiment
-------------------------

The query-gather mode is opt-in. Add geometry.query_readback_layout = "gather"
to a copy of the direct-readback workload JSON. Omitting the field keeps "rows".
The runner pins this choice in the workload hash and sets
LATTICA_V2_GPU_QUERY_GATHER explicitly. The proof parameters, resource limits and
CPU auditor remain the same. The Metal kernel still needs validation on a Mac.

First qualify a fresh root with block-v2-typed-gpu-run.py and that workload.
Then use the same pinned GPU binary for both modes:

  python3 scripts/block-v2-query-compare.py \
    --gpu-binary /absolute/pinned/gpu/block-v2-paired-probe \
    --cpu-binary /absolute/pinned/cpu/block-v2-paired-probe \
    --fixture /absolute/pinned/paired-fixture \
    --rows-workload /absolute/pinned/rows-workload.json \
    --gather-workload /absolute/pinned/gather-workload.json \
    --gpu-uuid GPU-UUID --count 4 --pairs 5 \
    --evidence /absolute/fresh/query-comparison

The controller alternates trial order, holds the resource assignment fixed,
checks every fresh proof plan and CPU root audit, and retains query counters.
Checkpoint counters are cumulative within the process; do not sum checkpoints.
The report withholds both rates if the series, input pins, profiles, assignment,
timings or run mappings are incomplete or inconsistent. A reduction in download
calls alone does not establish a reduction in solving time.

Mixed-count qualification matrix
--------------------------------

  python3 scripts/block-v2-typed-count-matrix.py \
    --gpu-binary /absolute/pinned/gpu/block-v2-paired-probe \
    --cpu-binary /absolute/pinned/cpu/block-v2-paired-probe \
    --fixture /absolute/pinned/paired-fixture \
    --gpu-uuid GPU-LAPTOP-UUID --gpu-uuid GPU-DESKTOP-UUID \
    --prior-trial /absolute/qualified/laptop-count4 \
    --prior-trial /absolute/qualified/desktop-count4 \
    --evidence /absolute/fresh/count-matrix

The default counts are 1, 2, 3, 4, 8, 16, 32, 63 and 64. Use --counts for a
subset; subset completion cannot establish full count coverage. Each new job
runs serially with live CPU, RAM, spill and GPU admission and the conservative
bootstrap context allowance. It does not transfer count-four context calibration
to other counts. A retained trial is reused only if its binary, profile, GPU,
public fixture, complete proof plan, root-only CPU audit and artifacts revalidate.
A failed job stops the matrix and remains in its evidence directory. Each new
trial has a 7100-second controller limit within the worker's 7200-second service
limit. Large counts may take substantially longer than count four.

This matrix qualifies recursive roots using previously created wallets and
registered keys. It does not measure complete cold-full-64 or post-seal time,
concurrent admission at every count, durable transaction application or recovery.
Import and render the HTML report after timed proving has stopped.

Count-matrix analysis and retention
----------------------------------

Use the frozen controller that launched the matrix. The analyzer copies the
summary into a new directory, revalidates every completed trial, and records
stage costs, GPU-specific coverage, and separate new/prior proof totals.
It can capture partial progress while proving continues; partial coverage
never establishes full count qualification. It does not launch a prover.

  python3 scripts/block-v2-typed-count-analysis.py \
    --summary /absolute/count-matrix/summary.json \
    --controller /absolute/frozen/controllers/block-v2-typed-count-matrix.py \
    --output /absolute/new/count-analysis

Retain analysis.json and matrix-summary.json together, with the controller,
analysis source, test log, and original trial artifacts. Copy the analysis into
docs/evidence under a new filename; never overwrite an earlier progress record.
First-versus-subsequent node timing does not isolate setup cost because their
inputs and levels can differ. Rates remain fixture-processing measurements.
Complete wallet proving and durable application are separate timing gates.

Research host boundary (validation pending)
------------------------------------------

The optional block-v2-host feature adds a separate twelve-key CPU root-verifier
ABI. The paired probe can export a trusted registry and a versioned expected
statement using export-host-registry and export-host-expected. The node derives
its expectation from complete transaction envelopes and requires explicit
host-supplied issuance grants. This does not activate the candidate in production.

The current mixed benchmark body.json files contain public statement vectors,
not complete native transaction envelopes. Their synthetic bindings cannot be
used to claim native state application. Native/Rust interoperability, complete
body proving, durable state, and recovery remain separate validation work.
Do not compile this source or render the report during timed proving.

Complete-body host qualification
--------------------------------
After native host validation passes, prepare two fixtures with
block-v2-native-fixture.py: indices 0 1 2 3 and 4 5 6 7. Generate a fresh paired
recursive root for each fixture using block-v2-typed-gpu-run.py --count 4 and
retain its independent CPU audit. Existing statement-only benchmark roots do
not authorize these complete bodies.

Run qualify-block-v2-native-host.py between timed campaigns. Supply:
  --library /absolute/frozen/bridge/liblattica_host_bridge.so
  --registry /absolute/trusted/host-registry.bin
  --genesis /absolute/trusted/genesis.bin
  --profile-id TRUSTED_32_BYTE_PROFILE_HEX
  --chain-id TRUSTED_32_BYTE_CHAIN_HEX
  --issuance-grant 3:7
  --fixture /absolute/native-fixture
  --proof /absolute/first-trial/001-typed/root-only/node.6.0
  --alternate-fixture /absolute/alternate-fixture
  --alternate-proof /absolute/alternate-trial/001-typed/root-only/node.6.0
  --output /absolute/new/host-qualification

The host selects registry, context, genesis and issuance authority separately
from the proposed block. The runner checks fixture and binary pins, uses the
real native/Rust CPU verifier, and retains all journals and child logs. It
checks exact native state and ciphertext retention, fresh-process restart,
reorg and rollback, five process-exit boundaries, ENOSPC/EIO injection at five
boundaries each, and two writers released together against the same head.
Published history is reverified after each fault; orphan records are retained.

The original native run passes 55 checks using two CPU-audited complete-body
roots at height 10 (docs/evidence/block-v2-native-host-qualification-2026-10-05.json).

Multi-height delivery qualification
-----------------------------------
block_v2_native_delivery.py prepares fresh complete bodies and leaves from a
verified Store.snapshot(). Its returned head token fences eventual application.
Funding supports 1..2048 synthetic slots; 704 are exercised, with all four wallet
participants rotating through all transaction kinds. The native delivery ABI
verifies supplied history and rejects missing or spent slots before leaf proving.
Host height and issuance grants come from independently selected configuration.

Use block-v2-typed-gpu-run.py --expected /absolute/host/expected.json for those
prepared bodies. This pins the full host expectation, validates the requested
count against its plan, and retains independent CPU root auditing. Omitting the
option retains the fixed height-10 synthetic fixture policy.

qualify-block-v2-native-delivery.py --config PINNED_INPUTS_JSON --output NEW_DIRECTORY
runs four serial count-four roots: heights 10, 11, 12 and an alternative height 11.
The configuration supplies the independently selected library, registry, context,
genesis, per-height issuance grants, CPU probe, registry fixture, artifact pins,
GPU command and explicit tmpfs scratch root. See the retained complete example:
lattica-prover-p3/target/block-v2-native-delivery-20261005-a/qualification-tooling-r4/inputs.json
Run outside other timed campaigns; compile all binaries before starting.

The completed run passes 41 checks, including independent host-policy mutation
rejection, fresh-process recovery, exact supply/notes/nullifiers/events, rollback,
reorg and stale-head/ancestry rejection. Evidence is retained at:
docs/evidence/block-v2-native-delivery-2026-10-05.json
This does not establish sustained delivery, proving-worker failure recovery,
physical power-loss recovery, production activation or delivered throughput. The
bounded journal replays up to 128 blocks per commit; include that cost in complete
finalization measurements.

Typed scheduler plans and durable artifact replay
-------------------------------------------------

Build the paired CPU-only probe on Linux:

  cargo build --release --no-default-features --features block-v2-host,stream \
    --bin block-v2-paired-probe

It supports:

  block-v2-paired-probe execution-plan FIXTURE EXPECTED_JSON PLAN_JSON
  block-v2-paired-probe execution-audit FIXTURE EXPECTED_JSON NODES HEAD_HEX NEW_OUT

EXPECTED_JSON must come from the independent host policy. HEAD_HEX is the native
snapshot's 32-byte head token. The diagnostic CPU-verifies the retained wallet
proofs and compares each scheduler job against the paired reference plan. The
audit also CPU-verifies retained nodes, persists them, rejects a changed head
token, and reopens the journal under a new epoch with independent wallet policy.
Recovery rechecks every wallet and node before reusing the exact cached root.

Use a frozen CPU binary and retained count-matrix/native-delivery artifacts:

  python3 scripts/qualify-block-v2-typed-execution.py \
    --cpu-binary /absolute/pinned/block-v2-paired-probe \
    --native-campaign /absolute/native-delivery/qualification-r4 \
    --count-matrix /absolute/count-matrix/matrix/summary.json \
    --output /absolute/new/typed-execution-audit

The harness checks counts 1,2,3,4,8,16,32,63,64 and all four native branches. It
retains input hashes, commands, logs and JSON results. The 2026-10-05 run passed
all nine plans and four journal replays containing 16 retained nodes. Evidence:

  docs/evidence/block-v2-typed-local-dag-2026-10-05.json

This is CPU artifact replay. It starts zero proving workers, creates zero proofs
and applies zero native blocks. Journal reopen happens inside the diagnostic
process. Legacy CPU workers reject typed jobs explicitly. The separate typed
GPU path below now proves through the DAG; persistent cross-process dispatch
and live worker/coordinator termination still need integration and qualification.

Typed GPU DAG and cached worker
-------------------------------
The paired Linux stream/GPU binary supports:

  block-v2-paired-probe prove-execution-gpu FIXTURE EXPECTED_JSON OUT WORKER_BYTES

Use the controller so hardware admission, enforced memory limits, device
identity, source pins, telemetry and an independent CPU root audit are retained:

  python3 scripts/block-v2-typed-gpu-run.py \
    --construction paired --execution-backend typed-dag --ram-admission compact \
    --gpu-binary /absolute/frozen/gpu-block-v2-paired-probe \
    --cpu-binary /absolute/frozen/cpu-block-v2-paired-probe \
    --fixture /absolute/pinned/fixture --gpu-uuid GPU-ASSIGNED-UUID \
    --count 8 --scratch /tmp --evidence /absolute/new/trial

For one independent root on each GPU under shared host reservations, use
block-v2-typed-multi-gpu-run.py with the same options, repeat --gpu-uuid for
each device, and add --mode concurrent. The fleet controller reserves each
device's managed VRAM and driver/context allowance, and divides the detected
CPU, RAM and spill capacity across the selected workers. Calibration trials
must match the binary, profile, allocation and execution backend.

Each GPU process owns its DAG and reusable typed worker. Idle preprocessing
keeps its RAM, managed VRAM and spill reservations, with zero CPU slots.
Completed jobs drain the GPU before reconciliation. Teardown releases the
workspace only after dropping the GPU context. Per-node logs retain cache
setups/hits, CPU input checks, proving and serialization timings.

The proof-only runner uses the expected profile as a local head token. Native
arrival integration must supply an independently captured host-head token.
Results explicitly report arrival_backend_integrated=false,
durable_host_applied=false and production_ready=false. These fixture runs do
not measure new wallet proofs or delivered transactions. The retained trial
scope and source hashes are in:

  docs/evidence/block-v2-typed-worker-2026-10-05.json

Persistent GPU child dispatch
-----------------------------

The paired Linux/stream/GPU probe also supports a separate DAG owner and one
persistent GPU child. Use the same single-GPU or fleet command above with:

  --construction paired --execution-backend typed-process-dag

The parent reserves the workspace before starting the child. The inherited
socket carries bounded packets; launch permission binds each request to the
session, executable, registry, policy and hardware assignment. The child retains
preprocessing across jobs and drains GPU queues before returning each result.
The parent revokes the launch and independently CPU-verifies the returned proof.
Idle cached memory remains reserved. Clean GPU teardown, matching cumulative
cache counters and a successful observed child exit are all required before
workspace release. Failed sessions retain journal reservations for recovery.

The proof runtime retains worker-session, worker-start.json and worker-exit.json.
The result reports typed_process_dag_v1, distinct worker/coordinator PIDs and
worker_process_exited=true only after successful shutdown. The internal
serve-process-gpu command requires the inherited socket and is not a terminal
entry point. Physical CPU, RAM, spill and device limits still come from the
assigned worker's existing systemd admission; both processes share that service.

The first qualified scope is one eight-input laptop-GPU root, eight fresh proofs,
four cache setups and four hits. Its benchmark monitor was interrupted while the
original proving processes continued. Worker-owned timing and final cgroup
accounting were recovered, but host telemetry has a documented gap. The first
failed trial exposed a per-job/cumulative cache-counter error; its proof, journal
and logs remain retained alongside the corrected source and successful trial:

  docs/evidence/block-v2-typed-process-2026-10-05.json

The desktop follow-up and one concurrent count-eight trial also passed:

  docs/evidence/block-v2-typed-process-concurrent-2026-10-05.json

They add three CPU-audited roots and 24 fresh recursive proofs. Standalone desktop
worker time was 291.247 seconds; concurrent laptop/desktop times were 303.486 /
342.703 seconds, within a 343.268-second fleet execution window. Each root used
four setups and four cache hits. The two-worker assignment uses 12/11 Rayon
threads, 22.25 GiB host RAM and 14.25 GiB spill per worker, with a 45.75 GiB fleet
cap. Managed VRAM is 7/6.5 GiB and conservative context allowance is 7.25/7 GiB.
Both new controllers ran in separate systemd monitor services; their exit status,
telemetry samples and maximum sampling intervals are retained.

Each service still has its own candidate DAG owner. A shared DAG owner across
GPUs, native arrival integration, active worker/coordinator recovery and larger
shared counts remain separate work. Differing standalone/concurrent assignments
do not establish a matched speedup. Do not treat benchmark-monitor durability as
proving-coordinator recovery. The completed inline-journal recovery controller
below still targets its original backend.

Fresh CPU-process recovery of a completed GPU journal
----------------------------------------------------

The paired CPU-only Linux/stream probe supports:

  block-v2-paired-probe execution-recover FIXTURE EXPECTED_JSON RUNTIME BUDGET_JSON \
    ROOT HEAD_HEX NEXT_EPOCH NEW_OUT

Supply the original runtime directory and independently trusted fixture, policy,
registry, resource assignment, root and head token. Recovery rechecks retained
proofs, requires a sealed eligible candidate, refuses unresolved attempts or
workspaces, and advances the original journal epoch. It checks that the cached
root is unchanged, no jobs become ready and no worker resources remain reserved.
Directory device/inode identity is part of the journal binding, so copying a
journal into a different directory is not a valid recovery test.

For the research qualification, first create a dedicated eight-input typed-DAG
GPU trial using the command above and an unused evidence directory. Wait for its
independent CPU root audit to finish. Then run a frozen controller and CPU binary:

  python3 scripts/qualify-block-v2-typed-recovery.py \
    --trial /absolute/new/completed/gpu-trial \
    --cpu-binary /absolute/frozen/cpu-recovery-block-v2-paired-probe \
    --fixture /absolute/pinned/fixture \
    --output /absolute/new/recovery-evidence

This controller starts no prover. It rejects active fleet services, archives the
original runtime, and checks wrong budget, wrong head, stale epoch and corrupt
root in separate CPU processes. Rejected requests must leave the runtime intact.
Two more CPU processes recover at epochs 2 and 3; the controller archives each
result and checks byte-identical roots, exact node counts and zero new work.
The fixture's profile is a diagnostic head token here; native arrival integration
still needs the actual independently captured host head.

Use a new dedicated GPU trial for each qualification. The positive checks mutate
its journal, so do not run this controller against previously published benchmark
journals or rerun it blindly after a partial failure. Retain failed attempts and
inspect the recorded epoch before continuing. No compilation, tests or report
rendering should overlap the timed GPU trial.

The 2026-10-05 qualification passed both fresh-process recoveries and all four
rejection checks. It produced zero new proofs during recovery. Original and
post-recovery archives, child process records, source pins, logs and a corrected
controller failure are retained in:

  docs/evidence/block-v2-typed-recovery-2026-10-05.json

This covers clean completed-journal recovery. Active worker termination,
persistent cross-process GPU dispatch, native arrival integration and production
readiness remain unqualified.

Phase analysis for validated counts
----------------------------------
block-v2-count-phase-analysis.py reads the output of the frozen count analyzer.
It verifies input hashes, exact proof counts, and preprocessing calls against
mode changes in the completed plan. Use --analysis PATH_TO_ANALYSIS_JSON,
--repository-root PATH_TO_REPOSITORY and --output A_NEW_DIRECTORY. It launches
no prover and retains a copy of its input. Preserve the output and frozen
source alongside the count evidence. Inclusive phase totals can overlap;
they do not form an additive decomposition of solving time.

Native arrival revalidation and policy-aware selection
-----------------------------------------------------
With an existing trusted native host configuration, journal and durable intake:

  python3 scripts/block-v2-native-arrivals.py \
    --host-config HOST_CONFIG --host-journal HOST_JOURNAL --store INTAKE \
    prepare --registry TRUSTED_REGISTRY_FIXTURE --cpu-probe CPU_PAIRED_PROBE \
    --output NEW_CANDIDATE_DIRECTORY --limit 4 --scan-limit 256 --seal

The scan reads unclaimed arrivals from current and prior heads. Native prefix
validation checks state and host-supplied issuance grants. CPU verification
checks each candidate wallet proof; invalid entries remain in intake and the
preparation manifest records their rejection. Selection preserves arrival order
within compatible policy slots. The full candidate must satisfy every required
issuance slot before it can be sealed. --request-id arguments instead request an
exact order, which remains subject to the same complete native policy checks.

The default scan bound is 256 arrivals, with a maximum of 4096; --limit is the
candidate bound in 1..64. Inputs beyond the scan bound remain available to later
work. Every selected old-head arrival is bound to the new native head through
the pinned preparation and sealed event. Its original body, proof, request ID,
receipt timestamp and retry response stay unchanged. An unsealed preparation
does not permanently approve an arrival for another head.

HTLC proofs include their height. The wallet must provide new proof/body bytes
when that height is no longer valid; the intake never rewrites a wallet proof.
The retained 2026-10-05 qualification covers count four at height eleven,
including a deferred joinsplit and issuance, current-height HTLCs, and rejection
of altered ciphertext, an old-height HTLC and a spent nullifier. All wallet
proofs and the setup block root were reused; the two GPUs produced four fresh
recursive proofs for the selected height-eleven candidate. Pre-seal dispatch,
active proving recovery and sustained throughput remain unqualified.


Native pre-seal subtree proving and reuse
----------------------------------------
Prepare with --prefix (without --seal). Later required issuance slots may be
absent from a prefix. Full preparation and sealing still require every grant.

python3 scripts/block-v2-native-arrivals.py \
  --host-config HOST_CONFIG --host-journal HOST_JOURNAL --store INTAKE \
  prepare --registry TRUSTED_REGISTRY_FIXTURE --cpu-probe CPU_PAIRED_PROBE \
  --output NEW_PREFIX_DIRECTORY --limit 4 --prefix

Run block-v2-typed-shared-gpu-run.py with the normal GPU/CPU binaries, explicit
GPU UUIDs, count, fixture, host config/journal, and arrival store, plus --preseal.
Omit --arrival-selection for this phase. It proves complete non-root subtrees,
CPU-audits them, and leaves the native head and arrival claims unchanged.

Prepare and seal the enlarged candidate, then run the same controller with its
sealed selection and --reuse-preseal PREFIX_RUN/owner/proofs. Every imported
subtree must match the native head, host policy, and semantic job and pass fresh
CPU verification. Cache files and manifests are SHA-256 pinned. Changed bytes
or a proof for another job are rejected before workers launch. A fully cached
prefix phase is rejected because no new GPU work is needed.

Phases have separate immutable per-device CPU/RAM/spill/VRAM assignments. The
2026-10-05 staged qualification used three prefix proofs and five subsequent
proofs to audit and apply one count-eight root; eight wallet proofs were reused.
Prefix audits do not count as completed roots. The report retains reuse sources
separately from fresh proof timing. This single qualification does not measure
matched speedup, complete seal-to-host-ready latency, sustained throughput,
active proving recovery, or Apple Silicon runtime behavior.


Explicit coordinator recovery during native proving
--------------------------------------------------
Use block-v2-typed-shared-gpu-run.py with the original sealed native candidate,
GPU and CPU binaries, host config/journal, arrival store/selection, count and GPU
UUID order. Choose a new --evidence directory and add:

  --recover-owner /absolute/PREVIOUS_RUN/owner

The controller pins the original inputs and allocations. Recovery requires the
same executable fingerprint, GPU drivers, CPU/RAM/spill/VRAM/context limits and
native head. It confirms old coordinator and worker process/cgroup exit, revokes
unresolved launches, reconciles reservations, and CPU-reverifies retained nodes
from the original durable journal before advancing its epoch. New service names
are required. Do not edit or remove the old run, its launch store or source files.
A changed binary requires a separate experiment; it cannot resume this journal.

--recovery-admission-timeout defaults to 120 seconds and accepts values greater
than zero and no more than 300.
Only transient fixed host/VRAM capacity rejection is retried, every two seconds.
Observations go to recovery-admission-waits.json. Limits are never reduced and
no GPU jobs start while admission is pending. Other validation failures abort.

The retained 2026-10-05 qualification killed the coordinator after one accepted
subtree with another GPU job active. Epoch-two recovery reused that subtree and
produced three new proofs. One idle shared worker shut down cleanly. An independent
CPU root audit, one isolated native application, fresh-process replay and exact
receipt retries passed. Resumed proving took 115.032 seconds; the whole experiment
including initial proving, interruption, admission waiting and replay took 267.566
seconds. All processes exited and memory-limit/OOM counters stayed zero.

  docs/evidence/block-v2-native-coordinator-recovery-2026-10-05.json

This trial covers explicit recovery with an exported accepted subtree and
existing wallet proofs. The later cached, receipt and initialized startup,
dispatch and export trials below extend that coverage. Automatic supervision,
resource exhaustion, active reorg/stale results
and sustained throughput remain unqualified. The benchmark page distinguishes
journal recovery from pre-seal reuse and preserves failed attempts.


Cached-only native continuation
------------------------------
Add --recover-cached-only together with --recover-owner PREVIOUS_RUN/owner.
The candidate, binaries, native binding and original allocation identity must
remain pinned. This mode admits only the original CPU coordinator against current
host CPU capacity, available RAM, OS reserve and cgroup headroom. It performs no
GPU inventory query and creates no GPU launch request or spill directory. The
retained GPU/driver budgets identify earlier journal work; no GPU capacity is
reserved for new jobs.

The Rust owner reconciles exact old services and CPU-reverifies the original
journal. Every planned proof, including the root, must already be accepted.
Missing proofs cause rejection without GPU launch. This can advance the journal
epoch while preserving accepted work: to resume proving after that rejection,
use the rejected attempt's owner directory with ordinary --recover-owner. Keep
all prior run directories, binaries and journals; do not retry from an old epoch.

A complete cache proceeds to an independent CPU root audit, fenced native
application and durable intake publication. The 2026-10-05 qualification tested
incomplete-cache rejection at epoch two, GPU continuation from that CPU-only
epoch, interruption after accepted final root at epoch three, and cached native
application at epoch four. Four earlier proofs were reused, zero new proofs and
zero GPU workers were created, and fresh-process native/intake replay and exact
receipt retries passed. Journal recovery took 3.479 seconds; owner continuation
20.943 seconds. The benchmark page excludes this phase from proving throughput.

  docs/evidence/block-v2-native-cached-recovery-2026-10-05.json

Native application and intake receipt recovery
----------------------------------------------
The same --recover-owner PREVIOUS_RUN/owner --recover-cached-only invocation can
recover after native head publication, including a crash before either the
native receipt or intake receipt was saved. The prior owner's root-only/node.6.0
is pinned. Native replay must confirm that exact block body and proof, the
original parent head, and exactly one journal generation advance. A different
proof, parent, later block or reorg is rejected. The block is not committed again.
A matching existing intake receipt is idempotent; a sealed selection can finish
publication. Conflicting or cancelled selections remain rejected.

Owner results distinguish native_application_recovered=true and
fresh_native_blocks_applied=0. The CPU root audit and full native replay still
run. A native publication crash, intake crashes before/after commit, all five
native storage publication boundaries, and fresh-process exact retries passed:
docs/evidence/block-v2-native-application-recovery-2026-10-05.json

Initialized startup, dispatch and proof export recovery
------------------------------------------------------
New fleet plans write durable startup intents for all workers before launching
any. Each intent binds the exact service, executable, arguments and assigned
resources. Authorization follows workspace reservation. The worker records its
own OS identity before GPU initialization and holds its startup lock until OS
process exit. A missing coordinator READY record can therefore be reconciled.
Recovery revokes future entry, confirms process/service/cgroup quiescence and
only then releases the workspace. Legacy plans still require READY records.

The retained trial passes coordinator SIGKILL before launch, before readiness
and after dispatch, plus delayed entry against a revoked gate. A directory at
the root output path forces an export I/O error after durable proof acceptance.
The same --recover-owner ... --recover-cached-only command restores all four
accepted proofs, audits the root and applies one native block with one intake
event. Fresh-process replay and two exact retries pass. No proving was repeated
when correcting the observer's expected OS error. The report pins the internal
artifact and journal when no previous proof export exists:
  docs/evidence/block-v2-native-startup-recovery-2026-10-06.json

Coverage begins after coordinator metadata, candidate sealing and launch-store
creation. The new-candidate bootstrap cases are qualified in the next section.
SIGKILL at the export instruction remains untested. Automatic supervision, worker replacement, OOM, active reorg/stale
results, all-worker failure and sustained throughput remain unqualified.

New-candidate coordinator bootstrap recovery
-------------------------------------------
Each new controller run creates owner/coordinator-startup with a durable intent
binding the exact Python service, executable, command, configuration and fleet
plan. The owner enters it once and holds its lock until OS process exit. The
Rust child checks its admitted parent and publishes initialized.json atomically
after journal setup, candidate sealing, launch-store creation and worker intents,
before any worker workspace reservation.

--recover-owner also accepts an unfinished new-candidate bootstrap. Recovery
first revokes future owner entry and confirms the old process, service and cgroup
are quiescent. It refuses this path if any worker was reserved or any recursive
node was accepted. It preserves partial files and uses a new journal under the
same assignments. Coordinator origin and worker launch paths are selected
together. An initialized run continues to use its original journal. Recovery now publishes
an atomic admission after recording the new coordinator metadata and before
changing that journal. Before admission, a retry uses the previous source. After
admission, it traces interrupted generations to the last initialized worker owner,
checks every coordinator's identity, reconciles the original launch reservations,
and CPU-reverifies accepted proofs. The new epoch and sealed candidate are written
in one checkpoint. Bootstrap provenance and the original journal source must both
remain in the controller plan. This protocol never treats an existing accepted
journal as an empty candidate.

Four early SIGKILL boundaries, delayed owner entry rejection, subsequent dispatch
recovery, native application and fresh-process exact retries passed:
  docs/evidence/block-v2-native-bootstrap-recovery-2026-10-06.json

The retained trial includes an initial launch-path failure before GPU reservation
and its correction. No accepted recursive proofs were discarded. Four existing-journal initialization interruptions also passed with one accepted
proof preserved through epochs 2–5, three remaining proofs produced, one native
block and one intake event, and fresh-process replay with two exact retries:
  docs/evidence/block-v2-native-recovery-initialization-2026-10-06.json
Controller admission and recovery
---------------------------------
Normal CLI runs now launch a dedicated systemd controller service. The request
pins arguments, cwd, Python executable, script, binaries, fixture inputs, and
Python source. Separate launcher and controller locks last until OS process
exit. The controller publishes an atomic owner handoff only after configuration,
plan, and owner bootstrap metadata are durable. The owner checks the exact live
controller invocation before entry. BindsTo/After dependencies stop the owner
and its GPU workers when the controller stops.

The controller has a 4 GiB memory cap, no swap, a 100% CPU quota, and Rayon 1.
GPU worker admission still uses assigned-worker cgroup scope and actual device,
CPU, RAM, and spill observations; the controller quota does not shrink the worker
thread allocation.

To explicitly recover a stopped controller into a new evidence directory:

  python3 lattica-prover-p3/scripts/block-v2-typed-shared-gpu-run.py \
    --recover-controller OLD_EVIDENCE --evidence NEW_EVIDENCE

For an already-complete accepted root, request the existing CPU-only path:

  python3 lattica-prover-p3/scripts/block-v2-typed-shared-gpu-run.py \
    --recover-controller OLD_EVIDENCE --recover-cached-only \
    --evidence NEW_EVIDENCE

Recovery refuses a live foreground launcher or active/pending controller service.
It revokes delayed controller/owner entry and checks service/cgroup quiescence.
Before handoff it retries the original pinned arguments, preserving any earlier
accepted journal source. After handoff it routes through owner recovery. All
original evidence remains retained. An interrupted summary may still say running;
controller-startup/launcher-result.json, exact service observations, and drain
receipts establish termination.

Four pre-admission crashes, one after handoff before owner launch, and one after
accepted work passed. Controller termination alone stopped the bound owner and
workers. Recovery preserved one accepted proof and produced three fresh proofs,
with one CPU-audited native block and one intake event. A subsequent cached
continuation reused all four proofs, started no GPU workers, and added no block
or intake event. See:
  docs/evidence/block-v2-native-controller-admission-2026-10-06.json

Worker memory failure and loss of all workers
--------------------------------------------
With --allow-worker-failover, nonzero worker memory counters are retained only
for a failed worker whose launch was revoked and whose process/cgroup exit,
workspace release, and GPU teardown were confirmed. Healthy workers and the
owner still require clean counters. Fleet event deltas must exactly equal the
sum of those failed-worker counters; missing/reset counters and unexplained
fleet events fail validation. The report independently checks this attribution.

A real isolated OOM trial lowered one active worker's RAM cap from 20.75 GiB to
1 GiB after its peer had accepted a proof. The failed job was retried on the
surviving GPU under its original assignment. One accepted proof was preserved,
four proofs completed across five dispatches, and one native block/intake event
was applied. The original cap, fault command, kernel OOM counters, accounting,
proofs, and source/binary identities remain retained.

A separate trial terminated both exact worker services after one accepted proof.
The attempt failed without applying a block. --recover-controller preserved the
accepted proof, reconciled old reservations, started new worker services, and
produced the three remaining proofs. Native/intake replay and two exact retries
confirmed a single application. See:
  docs/evidence/block-v2-native-worker-failure-2026-10-06.json

Automatic supervision/replacement, GPU VRAM/spill exhaustion, active reorg/stale
results, and complete throughput gates remain open.


Active native head changes and stale result rejection
----------------------------------------------------
During proving, the controller observes a bounded published-head token without
replaying the native chain on each poll. A change stops the owner and workers;
exact service and cgroup quiescence is required before the sealed intake selection
is cancelled. Proof bytes and partial journals remain available for diagnosis.
The token observation grants no native validity authority.

After root CPU audit and worker drain, the owner publishes a handoff bound to its
PID, original native binding, head token, and audited root hash. Native application
then enforces the head compare-and-swap. This handles a late reorg and prevents the
owner's own successful head publication from causing false cancellation.

Real count-four trials published a different verified block and rolled back to the
original state. The journal generation advanced to two. Both partial-controller
and complete-root cached recovery rejected the stale candidate before an owner or
GPU worker started. The old token also failed a direct native write. Revalidating
all four arrivals produced four fresh recursive proofs and one replacement block;
fresh-process replay and two exact retries produced no duplicate native or intake
application. Existing wallet proofs were reused; no cold throughput claim is made.

See: docs/evidence/block-v2-native-reorg-cancellation-2026-10-06.json
Readiness: docs/evidence/block-v2-throughput-readiness-2026-10-06-r33.json
The report preserves interrupted controllers that never wrote owner/result.json,
the failed cleanup attempt, and the late CPU-audited but rejected root. Failed
candidates have no throughput rate. VRAM/spill exhaustion, automatic supervision,
matched repetition, full-count and complete timing gates remain open.


Physical spill and GPU VRAM exhaustion
--------------------------------------
The r34 qualification filled a private worker scratch filesystem and observed
SIGBUS, then separately held 13.5 GiB of CUDA allocations on the laptop GPU and
observed CL_MEM_OBJECT_ALLOCATION_FAILURE in the prover. Scratch namespace
identity was included before configuration/launch pinning. The original resource
sizes remained admitted. The CUDA helper freed memory and destroyed its context.

In both count-four trials, accepted proofs survived and the remaining GPU retried
the unfinished job, completed four recursive proofs, passed CPU root audit, and
applied one native block. Fresh-process replay and two exact retries per case
retained one history entry and one intake application. Spill proving/invocation:
160.718/191.343 seconds. VRAM proving/invocation: 155.011/184.621 seconds. These
intervals include failure and retry; wallet proving and preparation are outside.

The parent now drops Command's configured stdin after spawning a worker. A child
that exits before READY produces prompt EOF; reservations remain until confirmed
cleanup. CPU and GPU feature validation passed 111 selected Rust tests; report
validation passed 67 Python tests. The existing CPU-only serve test was covered
in the CPU build and explicitly excluded from the GPU feature selection.

All 25 observed processes exited, 26 services are terminal, and 12 solver accounts
have zero host memory-limit/OOM events. Early failed attempts and the spill
observer assertion are retained. The successful spill proof was validated and
replayed without repeating GPU work. Automatic supervision/worker replacement,
matched repetitions, larger counts, complete timing boundaries, returned Mac
results, and the transaction pilot remain pending.

See: docs/evidence/block-v2-native-resource-exhaustion-2026-10-06.json
Readiness: docs/evidence/block-v2-throughput-readiness-2026-10-06-r34.json


Automatic sealed-candidate supervision
--------------------------------------
Use --supervise with a fresh sealed native intake candidate. The supervisor has a
4 GiB host cap, one CPU, no swap, durable attempt records and bounded retries.
--supervisor-max-restarts defaults to 2 (range 0..8); --supervisor-restart-delay
defaults to 2 seconds (range 0..60). It waits for confirmed process/cgroup cleanup
before entering controller recovery with the original GPU/resource assignments.
Systemd restarts the supervisor after a crash; it adopts a live controller.
Observation timeouts cause another observation of the same attempt. They never
mean termination or authorize a duplicate launch. --supervise currently rejects
preseal/reuse-preseal and externally supplied recovery modes.

The r35 native qualification passed loss of both GPU workers (one accepted proof
reused, three fresh proofs) and supervisor SIGKILL adoption (four fresh proofs,
original workers unchanged). Full invocation / final owner / final proving:
  Fleet replacement: 234.063 / 128.069 / 113.478 seconds.
  Supervisor restart: 164.515 / 144.431 / 129.808 seconds.
Each applied one native block with three user transactions and one issuance.
Independent CPU audit, fresh-process replay and two exact retries passed without
duplicate application. An already-applied candidate was rejected before any
controller or GPU worker started and changed no native/intake data.

All 29 observed processes exited; 18 services are terminal; 18 accounting records
show zero host memory-limit/OOM events. Validation passed 148 Python tests.
The report uses full supervision time for elapsed time and per-run rate. Owner
and proving intervals are subsets; preparation, wallet proving and separate replay
are excluded. Required recovery cases pass, while typed hardware/context and
complete cold/post-seal timing gates still block the pilot. Automatic cached-root
and active reorg injections through the supervisor remain pending; staged
supervision is not yet supported.

Evidence: docs/evidence/block-v2-native-supervision-2026-10-06.json
Readiness: docs/evidence/block-v2-throughput-readiness-2026-10-06-r35-r2.json


Fixed-allocation native comparison qualification
-----------------------------------------------
The shared-owner runner also accepts repeatable --calibration-trial PATH arguments
pointing to completed single-GPU shared-owner evidence directories. Supply an exact
--resource-assignment for the selected GPUs. Each source must contain a fresh full
root, an independent CPU audit, clean memory accounting, matching proving/audit
binaries, and the same workload and fixed managed VRAM, CPU, RAM, and spill limits.
Every selected GPU needs complete evidence. Prefix work may use a larger completed
source only when that source explicitly covers every prefix task geometry.

The controller pins source artifacts before admission. Calibration changes only
the context allowance; the live planner still verifies the actual device, driver,
available capacity, measured peak plus margin, and current host limits. Recovery
inherits the original calibration and rejects a changed override. New runs pin
their workload path and normalized profile; recovery rejects changed workload
options. Imports of older evidence accept repeated workload pins only when their
normalized profiles agree. Importing a
measurement alone does not qualify the reduced allowance on hardware.

The shared-owner runner accepts --resource-assignment PATH using schema
lattica-typed-fleet-assignment-v1. Every selected GPU must have one complete
limits_by_gpu entry. CPU topology, effective system capacity and driver identities
must match. CPU quota and Rayon threads can retain a smaller share of current
capacity; limits cannot grow beyond live capacity or undersupply admitted threads.
Host, spill and GPU margins remain enforced. Recovery rejects an override of its
original assignment. Use a single-entry subset for a one-GPU arm that retains
its two-worker CPU/RAM share.

The r36 count-eight native cycle passes each GPU alone, both GPUs and staged
prefix reuse on identical public/wallet fixture bytes. Final proving / complete
candidate pipeline, in seconds:
  Laptop GPU only: 277.691 / 343.278
  Desktop GPU only: 353.895 / 416.132
  Shared owner: 226.302 / 286.793
  Staged reuse: 161.449 / 372.719
The pipeline starts before pending-candidate preparation after arrivals are stored.
Staged prefix work is included; wallet proof generation and separate replays are
excluded. The final invocation starts after preparation, sealing and selection
checks. It does not establish complete seal-to-ready timing. Each isolated arm
applied six user transactions and two issuances; CPU audit, fresh-process replay
and two exact retries passed without duplicates. There are 32 fresh recursive
proofs across the cycle and three reused proofs in the staged arm. Five timing
repetitions remain pending.

Context peaks were 209713424 / 278919440 bytes. The planner's 512 MiB candidate
allowance requires a separate bounded qualification before use. All 32 observed
processes exited; 20 services are terminal; 18 accounting records show zero host
memory-limit/OOM events. Validation passed 177 Python tests.

Evidence: docs/evidence/block-v2-native-fixed-allocation-2026-10-06.json
Readiness: docs/evidence/block-v2-throughput-readiness-2026-10-06-r36.json

Experimental opening denominator cache (implementation awaiting validation)
------------------------------------------------------------------------
A new pinned workload may set geometry.opening_denominator_cache to true. The
planner records this choice and passes LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE
to the worker. The default workload leaves it disabled.

The compact opening consumer can upload repeated ordered denominator slices
once per opening call. It retains the largest required prefix for each admitted
group and uses the existing reduction kernel. Cache buffers use only the space
remaining inside the worker's managed VRAM and per-allocation limits; groups
that do not fit use tiled uploads. Host admission includes 64 KiB of bounded
cache metadata. Counters report cached calls, bytes saved, peak cache bytes, and
groups skipped for capacity. Data is scoped to one opening call.

The implementation includes CPU-reference GPU comparisons, bounded-capacity
fallback and error/unwind checks. These checks and new builds are deferred until
the frozen context comparison campaign finishes. A solving-time improvement and
Mac hardware qualification have not been established for this option.
