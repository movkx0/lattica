# Bounded execution and candidate GPU hashing — experimental

## Compact opening worker/controller and recursive qualification — 2026-10-02

The [full-workload evidence](evidence/block-v2-gpu-opening-compact-recursive-2026-10-02.json)
records a separate `block-v2-gpu-compact-trial.py` controller with schema
`gpu-compact-eight-v1`; the frozen CPU/GPU controllers remain unchanged.
Every GPU worker receives an explicit compact policy. CPU stages receive
`COMPACT=0`; every stage receives `PINNED=0`. Configuration, registration
and resume bind the policy along with binary/source/device/fixture pins.
The worker and controller require the actual compact call count, saved-input
bytes, compression/NTT activity, and zero pinned uploads. Missing, duplicate
or contradictory final markers reject. New worker flags default to the
original path when unset, preserving historical invocations.

Validation passed **46 selected Rust tests**, **42 compact-controller tests**,
the **35 frozen-controller tests**, **39 compact executable rejection cases**
and **three synthetic service-lifecycle cases**. The older 24-case entrypoint
suite also passed against the current CPU-only runner; these overlap with the
39 cases and are not 63 distinct cases. The evidence preserves an initial
historical-CPU test-fixture mismatch and a pre-worker CLI invocation failure,
alongside their corrected successful attempts.

All three full-size GPU keys matched independently preserved CPU registrations.
The eight-wallet/seven-proof run used all **seven compact opening calls** and
passed independent CPU-only root verification after pruning local inner
artifacts. The shared CPU fixture remains for matched controls.

| Observed quantity | Result |
|---|---:|
| Paired-wrapper / merge commands | 331.523 / 275.305 s |
| Combined proving commands / complete controller | 606.828 / 609.075 s |
| Final merge (not complete post-seal) | 85.446 s |
| Root proof | 1,683,948 bytes |
| Peak worker RAM / sampled VRAM | 32.320 GiB / 6,856 MiB |
| Swap | 0 |
| Actual opening uploads | 43,453,078,368 bytes |
| All recorded proof-stage host/device transfers | 246,799,588,208 bytes |

Opening spans total **41.416 seconds** within the proving commands; compression,
NTT, kernel and wall spans overlap and must not be added. Resource observations
are not physical scratch quotas or instantaneous VRAM enforcement. This is one
level-three/count-eight subtree, not a full64 or complete post-seal result.
Historical timings are not a same-build control: performance promotion remains
withheld. Next are fresh same-build original-opening and retained-hashing
controls, then at least five alternating matched pairs before any positive
performance claim. Compact remains opt-in, with all production/security gates
unchanged.

The [compact opening consumer](evidence/block-v2-gpu-opening-compact-2026-10-02.json)
passes **42 distinct selected native tests**, sixteen GPU regression cases
under both selection modes, and five alternating large-input component pairs.
Exact transcript/proof equality, original CPU proof replay, low-degree/hiding
equivalence, aggregate admission, and compression/NTT failure drains pass.
The qualification service peaked at **1.906 GiB RAM**, with zero swap and no
OOM events.

For the same **1.5625 GiB** synthetic low-degree input, median opening-call
time fell from **1.171276 to 0.123347 seconds (89.469%)**. Uploaded bytes fell
from **1,728,058,144 to 155,194,464 (91.019%)**; every one of 1,048,576 output
rows was checked. This is an **isolated component result**, not an equivalent
reduction in block-proving time or the required end-to-end five-pair series.

The PCS-only path uploads low-coset rows after the unchanged batching challenge
is sampled, compresses to three cubic coefficient columns, then reconstructs
and reduces on the GPU. It assumes the existing PCS degree bound; arbitrary
row vectors still require the original reducer. Masks, transcript order,
security parameters, proof encoding and CPU verification are unchanged.
`LATTICA_V2_GPU_OPENING_COMPACT=1` is an opt-in; the default stays unchanged.
Full-size registered-cap checks and one eight-wallet root-only replay now pass
in the continuation above. Matched end-to-end timing and all production gates
remain pending.

The [pinned opening-upload investigation](evidence/block-v2-gpu-opening-pinned-2026-10-02.json)
passes **39 distinct selected native tests**, thirteen GPU regression cases
under **both upload modes**, and **five alternating component comparison pairs**.
Partial rows/cubic coefficients, exact transferred bytes, return to pageable
operation, allocation accounting, error/unwind drains and small full-strength
CPU proof replay pass. The qualification service peaked at **1.850 GiB RAM**,
with zero swap and no OOM events.

Pinned staging did **not** improve the isolated 1.5625 GiB input: median opening
call time was **0.959514 seconds pageable / 0.971697 seconds pinned**
(**1.270% higher**), while median upload API spans were **0.832802 / 0.832513
seconds**. Every comparison arm checked all 1,048,576 output rows. Timings
overlap and are not additive; these are component results, **not** the required
five-pair end-to-end recursive qualification. No performance promotion.

`LATTICA_V2_GPU_OPENING_PINNED=1` remains a research-only opt-in; unset or `0`
keeps the existing path. That investigation selected representation-size
reduction; the compact-consumer continuation above establishes its component
degree/coset/mask equivalence and transfer benefit. Full-block and production
gates remain open.

The [GPU opening timing diagnostic](evidence/block-v2-gpu-opening-profile-2026-10-02.json)
passes **39 distinct selected native tests and twelve explicit GPU checks**,
including small full-strength cubic proofs replayed through the original CPU
PCS. The isolated **1.5625 GiB** affine input checks every one of **1,048,576**
output rows against an independent closed-form reference, with exact transfer
accounting and no managed allocation leak. Qualification peaked at **2.223 GiB
RAM**, with zero swap and no OOM events.

The opening call took **1.179 seconds**: blocking upload API spans were
**1.025 seconds**, device upload intervals **1.012 seconds**, host packing
**0.114 seconds**, and kernel execution **0.003918 seconds**. These intervals
**overlap and are not additive**. This is an instrumented arithmetic-component
diagnostic, not a FRI proof or block benchmark; no speedup is claimed.
That checkpoint selected bounded reuse of already-reserved pinned staging
for the comparison now recorded above. Device-local consumption
or validated recomputation remains the broader transfer-reduction direction.
Post-test PCIe/load observations do not establish in-test contention or causality.
Full-block deadlines, lifecycle/resource and security/host gates remain open.

## Matched cache-workload pilot — 2026-10-02

The [matched-pilot evidence](evidence/block-v2-cache-bench-pilot-2026-10-02.json)
adds a test-only workload harness around the existing inline cached worker.
Native validation passes **148 selected tests (46 ignored), nineteen explicit
CPU checks and ten Zig tests**, with no compiler warnings, in 134.534 seconds
and 2.1G rounded peak RAM/no swap. Default/narrow/all-feature/all-target checks,
scoped formatting, diff checks and source/archive comparisons pass. Production
adapter/verifier code and the preserved CPU worker/probe binaries are unchanged.

### Workload and control contract

Five workloads pass public-fixture preflight, dependency-order validation and
idle-only cache-reset checks. Expected retained-cache counts are:

| Workload | Proof jobs | Setups | Hits |
|---|---:|---:|---:|
| Paired four | 3 | 2 | 1 |
| Eight, wrappers grouped before merges | 7 | 2 | 5 |
| Eight, wrappers and merges interleaved | 7 | 4 | 3 |
| Four with an empty-subtree transition | 5 | 4 | 1 |
| Three with single wrappers and an empty leaf | 7 | 5 | 2 |

These are supported test sequences, not measured throughput for every workload.
Each arm uses the same pinned CPU executable, public wallet bytes, registry,
semantic jobs, proof parameters and resource bounds. Cold-preprocessing clears
only an idle session's preprocessing before every job; its workspace remains
reserved. It is **not process-cold, OS-cache-cold, or the cold64 acceptance test**.
Generated child-proof bytes differ because every proof uses fresh randomness.

Each selected proof passes owner-side CPU verification and durable acceptance.
Output publication, launch revocation, cache close and cancellation of the
unfinished depth-six candidate are included in the complete loop timer.
The final measured output is a **level-two/count-four subtree**, not a block.
Fresh replay checks every saved output with pinned public fixtures and registry,
rejecting a wrong job and a mutated proof. It is not no-wallet root-only replay.

### First live pair: correct, no performance promotion

Only paired-four has been run live. The order was cold-preprocessing, fresh
replay, retained, fresh replay. Both arms prove two wrappers and one merge:

| Measurement | Cold-preprocessing | Retained |
|---|---:|---:|
| Complete measured workload, including cleanup | 562.650 s | 601.444 s |
| Whole proof-service wall time | 562.761 s | 601.513 s |
| Cumulative setups / hits | 3 / 0 | 2 / 1 |
| First cache-miss worker proving span | 170.282 s | 247.401 s |
| Second wrapper worker proving span | 191.793 s | 153.310 s |
| Merge worker proving span | 193.027 s | 192.574 s |
| Every proof envelope | 1,683,948 bytes | 1,683,948 bytes |
| Cgroup peak RAM | 42,950,377,472 bytes | 42,954,936,320 bytes |
| Peak live mapped spill | 34,288,652,288 bytes | 34,288,652,288 bytes |
| Swap | 0 | 0 |

Retained is **38.794 seconds / 6.895% slower in this one pair**. The first job
is a cache miss in both arms, yet differs substantially; this experiment does
not isolate the cause of across-arm variation. Avoiding one setup is real, but
it does not establish an end-to-end gain. The post-trial process snapshot was
taken after proving ended and cannot establish contention during either arm.
An attempted pressure snapshot found the proof service already collected.

Both fresh CPU replays pass (1.387 / 1.327 seconds), and both arms release all
logical reservations and live mappings. Proof services retain MemoryMax44 GiB,
MemoryHigh40 GiB, CPUQuota800%, TasksMax16 and no swap within the 48 GiB slice.
Scratch has a 120 GiB internal spill ceiling and a 132 GiB free-NVMe admission
gate; these are not physical disk quotas. No full64 or post-seal gate is passed.

Preserve this single-pair observation without promoting a cache speedup or
claiming that retention necessarily slows production. At least five alternating
matched pairs, mixed-mode trials and arrival/deadline integration remain open.
Continue profiling-led GPU/proving work in parallel with local integration.
The preserved GPU opening run spent 83.891 seconds across three opening calls
but only 0.369 seconds in its arithmetic kernel; these cumulative, nested
counters motivate finer host/API/device measurements, not a new speedup claim.
Full-block, host, lifecycle/resource, soundness/ZK and activation gates remain open.

## Cache-owning inline CPU adapter — 2026-10-02

The [cached CPU evidence](evidence/block-v2-cached-cpu-2026-10-02.json) closes the
first actual retained-preprocessing trial through the local durable execution
contract. This extends the reservation foundation below; it is not an
autonomous warm-worker daemon, network scheduler or production block path.

### Ownership and security contract

Linux/stream `worker::cached::CachedCpuWorker` owns one `ConstructionSession`
and executes serially through `&mut self`. Its whole-session reservation is
**44 GiB RAM / 0 VRAM / 120 GiB scratch / eight threads**; each job separately
reserves **1 GiB RAM / 0 VRAM / 8 GiB scratch / one thread**. Combined admission
is 45 GiB RAM / 128 GiB scratch / nine threads, leaving 3 GiB host RAM inside
the 48 GiB aggregate gate. These reservations are not physical filesystem quotas.

Each task is tied to its issuing owner and workspace-use guard. Execution
consumes one inline launch gate and rejects autonomous-process-bound tokens.
`CompletedJob` acknowledges that the synchronous CPU call returned and its
launch guard dropped; **it does not assert that the cache-carrier process exited**.
Per-job quiescence does not release the workspace. The owner still CPU-verifies
the returned proof and durably accepts it.

The cache retains only exact immutable-program/registered-cap preprocessing,
not wallet witnesses, proof randomness or completed-proof outputs. Every proof
uses fresh CSPRNG hiding material. Only one program type is retained; a mode
change drops it before allocating its replacement. Equal matrix shape alone
does not authorize reuse.

Spilling is armed during proving calls; retained mappings remain alive and
fully charged between calls. A returned prover error clears preprocessing.
A panic after taking the proving session drops it and leaves the adapter
unusable for further proving; this is not a claim about every preflight panic.
Close requires all local task/result users to drain and drops cache buffers
before durably releasing their reservation.

### Native and live validation

The pinned native service passes **146 selected native tests (43 ignored),
eighteen explicit CPU checks and ten Zig calculator tests**, with no compiler
warnings. Default/narrow/all-feature/all-target checks, scoped execution
formatting, diff checks and source archive comparison pass. New checks cover
policy budgets, `Send` ownership, wrong-owner and close-lifetime rejection, and
process-bound token rejection before proving. Native validation took 223.495
seconds, with 1.8G rounded peak RAM and zero swap; it is not a proving benchmark.

The live service proved two GroupedPair/WrapPair jobs, each level one/count two:
four public transactions across **two intermediate proofs**, not one block root.

| Measurement | First pair | Second pair |
|---|---:|---:|
| Proof bytes | 1,683,948 | 1,683,948 |
| Input verification | 184 ms | 211 ms |
| Worker proving span | 158.441 s | 112.056 s |
| Setup span | 45.980 s | 0.108 s |
| Registered prove-and-verify span | 109.778 s | 109.337 s |
| Cumulative setups / hits | 1 / 0 | 1 / 1 |
| Retained live mapped bytes | 14,445,207,552 | 14,445,207,552 |
| Loop elapsed through acceptance | 159.493 s | 272.821 s |

The loop timer excludes fixture loading and admission; its last timestamp
precedes final export/revocation/cache close. It is not complete block
finalization. The **whole proof service took 274.689 seconds**, with exact
cgroup peak RAM **42,950,197,248 bytes (40.0005 GiB)** and zero swap.
The exact mapped-spill peak was not printed; a passing assertion bounded it at
120 GiB. Mapped bytes are not additional RSS. Close checked zero live spill
bytes and zero remaining logical reservations.

A separate fresh CPU process verified both saved outputs and rejected reversed
ordering and mutation in 1.040 seconds. It loads pinned public fixtures and a
registry; **this is not a five-file/no-wallet block-root replay**. Controller,
proof and replay exited successfully. The controller's own 17.7M rounded RAM
peak is not proving memory.

An earlier controller attempt is preserved: it exited one before launching any
stage because it called nonexistent helper `H.sha`. The corrected controller
uses frozen helper `H.digest`; prover source was unchanged. Neither attempt
reruns the historical arrival/full-root trial.

### Next qualification gate

The two inputs differ and no cold control was run: **no matched speedup** is
claimed. Next compare identical public sequences with preprocessing retained
versus explicitly cleared: repeated wrappers, repeated merges and mode changes.
Both arms must retain one workspace, fresh randomness, exact program/cap checks
and independent CPU acceptance. Report setup, execution, verification,
publication, cache hits/evictions and resources separately. Alternate matched
arms before promotion; a small paired series is not p95/p99 qualification.

Integrate measured results into arrival/deadline estimates while prioritizing
proving/GPU data-movement work under the unchanged implementation plan. A full
paired 64-transaction tree requires 32 wrappers plus 31 merges; its one-worker
600-second cold budget averages under 9.524 seconds per job before overhead.
This is a budget model, not a measured full64 runtime or a passed deadline.

Autonomous cached-worker supervision, general external-verifier reconciliation,
no-identity startup liveness, cancellation/panic/OOM/timeouts under load,
physical scratch quotas/reference-aware retention, real arrivals and eligibility,
issuance/HTLC, complete host finalization, full64 and full-tree soundness/ZK
review remain open. Production defaults, historical encodings, ABI and
activation remain unchanged.

## Persistent workspace reservation foundation — 2026-10-02

The [workspace-reservation evidence](evidence/block-v2-workspace-reservations-2026-10-02.json)
implements separate persistent resource admission in the local DAG and durable
journal. It does not allocate preprocessing, retain a proving session, dispatch
warm jobs or change the cold worker's termination requirement.

### Admission, ownership and recovery

`reserve_workspace` charges RAM, VRAM, scratch and threads against the same
aggregate ledger as job attempts. The reservation survives idle time, candidate
cancellation, deadlines and pruning until explicitly released. A workspace
worker identity cannot also be leased to a cold attempt, and an unreleased cold
attempt cannot be reclassified as a workspace.

The durable reservation holds a duplicate of the journal's locked open-file
description. Local `WorkspaceUse` guards retain that barrier after the
coordinator or reservation handle drops. Close checks exact issuing ownership,
directory and lock identity; outstanding local users reject close without
consuming the handle. Callers must also drop the actual cache and drain external
users. These guards do not authenticate hostile same-UID code, stop processes,
free buffers or enforce physical quotas.

A new **local-only `LVDAG004` envelope** contains the existing base snapshot and
a bounded, ordered workspace inventory. Snapshots with no active workspaces
keep the previous `LVDAG001/002/003` encoding. The decoder rejects nested
workspace envelopes, trailing/truncated data, invalid identities, worker
aliases and combined over-budget reservations before loading proof artifacts.
Proof encodings, security parameters and C ABI entry points are unchanged.

Recovery lists `unresolved_workspaces` separately. The old `resume` path refuses
to discard them; `resume_with_workspaces` requires explicit reconciliation of
old job/verifier work followed by each cache lifetime. An available journal lock
or a missing service is not automatic drain authority. Only after successful
reconciliation does the fresh epoch start with no live reservations or revived
host eligibility.

### Validation and limitations

The final native revision passes **144 selected execution tests (39 ignored),
sixteen explicit CPU checks and ten Zig calculator tests**, with no compiler
warnings. Ten new structural tests cover persistent charging, combined resource
admission, worker identity separation, local-use/owner lifetime, exact cold
snapshot preservation, malformed envelopes and interrupted reserve/close writes.

The new explicit CPU test accepts an existing real pair proof, preserves its
accepted artifact alongside a workspace reservation, and CPU-reverifies it on
snapshot recovery. Recovery still requires the workspace callback, old
eligibility remains inactive and proof mutation is rejected. The test allocates
no actual preprocessing cache and launches no prover.

The bounded service finishes in **162.699 seconds**, with **1.8G rounded peak
RAM** and zero swap. Default/narrow/all-feature/all-target checks, scoped
execution-module formatting, source archive comparison and diff checks pass.
The first run is preserved with **141 passed / 3 failed**: three new test cases
used an epoch-1 assertion helper after recovering to epoch 2. Revision b fixes
only those test assertions by checking the next recovery at epoch 3. It does not
weaken recovery's epoch check. Whole-crate formatting remains the separately
recorded pre-existing module-order issue, not a claimed full-crate pass.

Source/binary snapshots and a documentation archive are preserved with the new
manifest. Previous process-loss/guard/arrival runs remain historical revisions;
they were not re-proved with this change. No latency or warm-cache benefit is
claimed by that foundation-only checkpoint. The continuation above implements
the cache-owning adapter and its first real reuse trial; matched cold/warm and
mixed-mode comparisons are still required. General
external-verifier reconciliation, no-identity startup liveness, OOM/timeouts,
physical scratch quotas/retention, full64 and complete post-seal/host/security
qualification remain open.

## Managed verifier process-loss boundaries — 2026-10-02

The [process-loss evidence](evidence/block-v2-verifier-crash-2026-10-02.json)
adds an explicit CPU fixture test with two actual child-process crashes. No
new proof is generated and no production verifier hook is added.

In both cases, the child durably begins guarded verification, drops its
coordinator handle and keeps the guard on a local thread. In the `task` case
the thread holds the task before its CPU verification call. In the `result`
case it has successfully run strict CPU verification of the existing public
pair proof and holds the unaccepted result. The parent verifies the readiness
phase and exact child PID, confirms recovery is locked, sends SIGKILL and
reaps that child. These are deterministic ownership boundaries; they are not
an instruction-level kill inside the verifier's arithmetic.

Recovery then reports `verification_active=true`. Refusing reconciliation
still refuses recovery. With explicit knowledge that this fixture has no
external verifier and that the exact child is reaped, recovery releases its
reservation without reviving old eligibility. A valid result submitted with
the old lease is rejected; a new guarded attempt rejects a mutated proof.

The revision passes **134 selected native tests (38 ignored), fifteen
explicit CPU checks and ten Zig calculator tests**. The bounded validation
service exits zero in **120.100 seconds**, using **1.9G rounded peak RAM** and
zero swap; no compiler warnings are recorded. Default/narrow/all-feature and
all-target build checks, execution-module formatting, source archive comparison
and diff checks pass. The CPU worker, public export, SingleWallet probe and Zig
calculator hashes match the preceding guard revision. A separate whole-crate
`cargo fmt --all -- --check` inspection reports pre-existing module-order
differences in `block_v2/mod.rs`; that file is not changed and a whole-crate
format pass is not claimed.

The earlier guard evidence is now closed with a **325-file manifest**, checked
before these new test/documentation edits. It is a historical revision manifest,
not a hash assertion about subsequently edited current source. The nine-stage
guard live run and the fifteen-proof arrival run are preserved, not rerun here.

### Consequence for warm preprocessing

The existing DAG requires authoritative worker termination before verification
and owns resources per attempt. A live preprocessing cache cannot be retained
by pretending that worker has stopped. A warm worker needs a separately
accounted session lifetime, with explicit job quiescence and process-termination
rules, bounded immutable preprocessing, fresh per-proof randomness and crash
reconciliation. No warm worker or latency improvement is introduced by this
process-loss checkpoint.

General unmanaged/external verification reconciliation, no-identity startup
liveness, OOM/timeouts, physical scratch quotas and reference-aware retention
remain open. The measured count-three arrival seal-to-root interval remains
33.403 minutes, excluding complete host finalization. Full64, mixed operation
coverage, deadline/resource qualification and full-tree soundness/ZK review
remain required; defaults and activation are unchanged.

## Guarded local CPU verification ownership — 2026-10-02

The [verifier-guard evidence](evidence/block-v2-verifier-guard-2026-10-02.json)
adds a managed verification task/result boundary to the durable local DAG.
It closes an in-process ownership gap: a coordinator handle could otherwise be
dropped while a separately running verifier still accessed its assigned work.

### Ownership contract

`begin_guarded_verification` duplicates the already locked journal file
description before durably beginning verification. The task can move to a local
thread and owns its expected job and exact lease. CPU verification consumes that
task and returns a result retaining the same lock. Recovery cannot acquire the
journal while either object survives, even after the coordinator handle drops.

`finish_guarded_verification` checks journal directory identity, locked-file
identity and the unique issuing ownership token. The ordinary completion path
rejects an attempt while its guarded task/result is alive. If a task is abandoned
or unwinds without delivering a result, only explicit rejection is allowed;
an arbitrary successful ticket cannot replace the lost result. Cancellation
continues holding the reservation until the verifier has drained.

Only the expected public proof is verified, with the unchanged strict CPU
verifier. No proof randomness is cached, and no proof, token, snapshot or default
ABI encoding changes. The supervised proof and arrival harnesses now use this
managed completion path. Low-level unmanaged verification remains an explicit
caller-responsibility boundary.

### Validation

The native revision passes 134 selected execution tests (36 ignored), fourteen
explicit pinned CPU checks and ten Zig calculator tests, plus default/narrow/
all-feature checks, formatting and archived-source comparison. There are no
compiler warnings. Its six new structural tests cover task/result lock lifetime,
raw-completion fencing through cancellation, abandoned-task rejection, wrong
owner results, thread handoff and durable accepted completion.

The new ignored real-CPU fixture test verifies an existing pinned public pair
proof on a thread after the coordinator handle is dropped. Recovery is rejected
both while the task waits and while its completed result remains held. After
joining the only verifier and discarding the result, explicit reconciliation
rebases the owner without reviving old eligibility. A newly submitted mutated
proof is rejected. This test launches no prover process and is not an OS-crash
or resource-performance qualification.

All nine live stages pass on the new revision: check, live cancellation,
captured-coordinator crash/recovery, missed-observation completion and
crash/recovery, a new full-strength pair proof, and fresh CPU replay. The crash
stages intentionally exit 73 and still occur before verification begins; their
logs explicitly report `prior_verifier_active=false`.

| New guarded-completion pair proof | Result |
|---|---:|
| Proof bytes | 1,683,948 |
| Dispatch through owner acceptance/export | 162.062 s |
| Worker input verification / reported proving | 0.391 / 160.069 s |
| Worker RAM peak / swap | 43,053,895,680 bytes (40.10 GiB) / 0 |
| Mapped spill peak | 34,003,439,616 bytes (31.67 GiB) |
| Setup / registered prove-and-verify | 46.679 / 110.574 s |

The worker's terminal journal matches its persisted invocation and live resource
snapshot. Fresh raw-pair replay uses the existing public fixture/registry and
rejects wrong ordering and mutation; it is not the earlier five-file arrival
root replay. Fixture loading, initial admission and task publication are excluded
from dispatch timing. Controller memory (14M rounded) is not worker RAM.

### Scope still open

This is a trusted-local-thread barrier, not authentication against hostile
same-UID software and not automatic drain authority for legacy or external
verifiers. In particular, a journal lock or missing service alone does not prove
arbitrary external verifier termination. Process crash during active verification,
no-identity startup liveness, OOM/timeout, physical scratch enforcement and
reference-aware retention remain separate work.

The earlier fifteen-proof arrival run remains preserved on its own source and
binary revision; it was not re-run under this new guard. Its 33.403-minute
seal-to-root result still misses the three-minute target. Full64/host/deadline and
full-tree security gates remain open. Resource-accounted preprocessing reuse and
GPU transfer reduction remain performance work; no speedup or activation is
claimed here. All experimental services are terminal, current source matches
the guard-native-a archive, and the four frozen files are unchanged.

## Controlled odd-count arrival/reuse proof — 2026-10-02

The [arrival checkpoint](evidence/block-v2-cpu-arrivals-2026-10-02.json) extends the
local CPU path with immutable ordered selections and a real three-transaction,
level-six result. The controller and separate proof/replay services exited
successfully. All fifteen workers have invocation-bound terminal journals,
recorded kernel-stop checks and owner-side CPU verification.

### Selection and arrival behavior

`Selection` builds a complete depth-six dense-prefix graph from CPU-verified
public wallet proofs, with immutable bytes bound to verification tickets.
SingleWallet supports structural counts 1–64; GroupedPair requires even counts,
without duplicate padding or construction fallback. Equal semantic jobs reuse
accepted artifacts. Replacement attachment precedes cancellation of the old
candidate. Partial admission grants no launch authority, and the host still
supplies ordering and current transaction eligibility.

The live test completes two wrappers and their merge, then admits a third
transaction while retaining those three jobs. It seals that selection, attaches
and cancels a separate four-transaction selection to model deferral, and executes
only the remaining work. The level-two merge checks that its left input is
exactly the accepted two-wallet artifact. Fifteen unique jobs complete: three
wrappers, five empty proofs and seven merges. Empty levels 0, 2, 3, 4 and 5 are
exercised in this specific padding shape.

All eight existing public join-split fixtures are loaded before these admission
events. This is a controlled selection sequence, not a network/mempool test.
Its explicit deadline is two hours, not production admission. No aggregator
wallet witnesses are introduced.

### Validation and statement handoff

The pinned native build passes 128 selected execution tests (35 ignored),
thirteen explicit CPU checks, ten Zig calculator tests, default/narrow/all-feature
checks, formatting and source-archive comparison, with no compiler warnings.
Failed native attempt `arrivals-native-20261002-a` is preserved; two test-only
compilation errors were corrected in revision b before the live run.

Two separate CPU registrations reproduce the SingleWallet height, three keys and
eight public wallet files byte-for-byte. This uses the same implementation; it
is not registry approval or independent cryptographic review. Native Zig
`root-padded` accepts 1–64 canonical join-split public statements, preserving
the existing eight-transaction commands. Counts 1, 2, 3, 4 and 8 are checked;
generic eight matches legacy padded-eight, and reordered three changes the root.

The fresh CPU replay directory contains exactly `height`, `key.1`, `key.2`,
`key.3` and `root.bin`. Replay loads zero wallet or intermediate proofs and
rejects a wrong expected root and a mutated proof. Debug inner artifacts elsewhere
in the trial are retained; no pruning is claimed.

### Measured result and limits

| Measurement | Result |
|---|---:|
| Root statement | MERGE, level 6, count 3 |
| Root envelope | 1,683,948 bytes |
| Fixture load/check through accepted root export | 2,508.284 s (41.805 min) |
| Selection seal through accepted root export | 2,004.169 s (33.403 min) |
| Maximum worker RAM | 43,423,404,032 bytes (40.44 GiB) |
| Maximum worker mapped spill | 34,288,652,288 bytes (31.934 GiB) |
| Worker swap peak | 0 |
| Summed preprocessing setup spans | 738.237 s; zero cache hits |
| Summed registered prove-and-verify spans | 1,700.625 s |

These named phase sums are not a complete end-to-end attribution. Mapped spill
is not additional RSS. Worker RAM is not the controller's 32.7M rounded peak or
the proof coordinator's 106,909,696-byte peak.

This CPU-only run used an Intel Core Ultra 9 275HX, eight Rayon threads, an
eight-CPU quota, worker MemoryMax44 GiB/TasksMax16 and aggregate MemoryMax48 GiB,
with no swap. The 120 GiB scratch reservation/internal ceiling is a free-space
admission mechanism, not a physical quota. Live limits and per-worker journals
are preserved. Source matches the native-b archive after the run, and all four
frozen planning/controller files remain unchanged.

**The measured seal-to-root time alone exceeds the 180-second requirement.**
It excludes complete host state application and durable block publication.
Registry generation and original wallet proving are outside fixture-to-root
timing. This correctness pass is not a matched speedup, full64, complete post-seal
or production qualification.

### Next work and preservation

This closes the controlled SingleWallet/Empty/Merge arrival case, not no-identity
startup liveness, concurrent verifier recovery, physical scratch/retention, other
arrival schedules, issuance/HTLC, host eligibility/reorgs, full64 deadlines or
full-tree soundness/ZK review. Preprocessing reuse must preserve fresh proof
randomness, exact program/profile identity and explicit resource ownership; the
current per-job worker exits before its reservation is released. The existing
GPU opening pilot remains slower than retained hashing and is not promoted.
Production defaults, historical verification and activation are unchanged.

Canonical evidence and pins are linked above. Run artifacts are in
`target/block-v2-arrivals-live-20261002-a/`, with separate preserved native,
registration and statement-handoff directories. The historical worker-start
manifest is not a pin for this newer source. Earlier checkpoints below retain
their historical scope.

## Worker-published startup identity recovery — 2026-10-02

The [worker-start checkpoint](evidence/block-v2-cpu-worker-start-2026-10-02.json)
closes the selected missed-live-observation case: a worker can finish before its
coordinator captures the process, but a complete task-bound startup record now
allows recovery of the exact identity and an independent kernel exit check.

### Identity and authority

The optional immutable `worker-start` file uses `LVWST001`. It binds the complete
execution-bound launch token to boot, service invocation, PID birth, cgroup and
its device/inode. The worker checks its own service/image/arguments and publishes
this identity before entering the launch gate, Rayon, spill allocation or
proving. Failed publication prevents proving. Existing task/spec/token formats,
proof formats, default verifier and production ABI are unchanged.

The supervisor first attempts live kernel observation. Only when no live process
is observable does it consult the strict bounded startup reader. This ordering
avoids mistaking the normal temporary two-link publication window for a failed
live observation. Record recovery checks the token, execution specification,
task-directory identity and pinned image; it rejects copied directories,
substitution, unsafe files and incomplete linked publication. It is independent
of whether result or scratch publication completed.

A startup record is **not a stop acknowledgement** and grants no proof-validity
or verifier-drain authority. Reconciliation still revokes permission and requires
exact process/cgroup termination plus the idle launch gate. Missing identity,
partial publication or a delayed never-observed launch remains quarantined if
no authoritative live observation is available. An absent service or helper exit
alone is never sufficient to release resources. This is trusted-local-runtime
metadata, not authentication against hostile same-UID software.

### Validation and real proof

Final-source `block-v2-birth-native-20261002-b` passes **122 native execution
tests and eleven explicit pinned CPU checks**, including the existing unknown
dispatch quarantine check. New coverage includes exact token/identity binding,
copied-task and unsafe-file rejection, and six abrupt publication boundaries.
The native suite reports 31 ignored tests; selected CPU/live gates are exercised
separately, not counted as a complete all-tests run. Default/narrow/all-feature/
all-target checks, worker build, formatting, whitespace and archived-source
comparison pass with zero compiler warnings. The bounded offline validation took
199.937 seconds, with a rounded 2.1G peak and zero swap.

Final-source `block-v2-birth-live-20261002-b` passes all **nine stages**:
check, live cancellation, intentional captured-coordinator exit73, fresh recovery,
missed-live-observation recovery, intentional unobserved-coordinator exit73,
fresh unobserved recovery, actual WrapPair proving and independent CPU replay.
Cancellation reproduces the temporary linked-publication window and confirms
live kernel capture still succeeds and is durably recoverable. Both missed
observation cases confirm exact kernel stop before resource release and rebase;
historical candidate eligibility is not revived. The crash cases precede
coordinator verification, so concurrent-verifier recovery remains unqualified.

| Actual two-transaction WrapPair | Result |
|---|---:|
| Proof / result-envelope bytes | 1,683,948 / 1,684,129 |
| Dispatch through owner acceptance/export | 164.410 s |
| Worker input verification / reported proving | 0.390 / 162.365 s |
| Worker peak RAM / swap | 42,729,635,840 bytes (39.80 GiB) / 0 |
| Peak mapped spill | 34,003,439,616 bytes (31.67 GiB) |
| Setup, cache miss / registered prove-and-verify | 47.625 / 111.386 s |

The terminal worker journal matches the persisted invocation and live resource
snapshot. Fresh CPU replay rejects wrong ordering and mutation. All experimental
services were terminal afterward, and archived proving source still matched.
The prior native/live revision is preserved: it passed nine stages before the
kernel-first ordering fix and therefore is not final-source validation.

This is recovery correctness, not matched performance evidence. Initial fixture
loading, admission and publication are outside the dispatch timing; neither
full64 nor complete post-seal finalization is demonstrated. Scratch remains a
free-space gate/internal spill ceiling rather than a physical filesystem quota.

### Next integration milestone

Resolve no-identity/partial-startup recovery and verifier-drain ownership without
unsafe stop inference. Qualify OOM/timeout and repeated lifecycle behavior,
physical scratch enforcement and reference-aware retention. Exercise real
SingleWallet/Empty/Merge generation through an arrival-driven local DAG, including
host eligibility/reorgs, issuance and HTLC. Incremental scheduling must reuse
unaffected completed subtrees and measure the entire post-seal path. Separately,
profile resource-accounted immutable setup reuse and reduce GPU transfers before
repeating matched comparisons. All full64/deadline, full-tree security, host
integration and explicit activation gates remain open.

## Previous checkpoint: interrupted-admission recovery — 2026-10-02

The [preparation checkpoint](evidence/block-v2-cpu-preparation-2026-10-02.json)
closes the durable no-permission admission gap. It does not infer worker death
from missing files, elapsed time, an idle lock or an absent service.

### Durable ordering and recovery authority

New DAG journals pin their own device/inode at creation, before any lease or
launch-store selection. `LVDAG003` stores that identity and distinguishes:

1. `Unissued`: no execution permission has been issued. The store identity may
   be the explicit zero/unassigned placeholder.
2. `Preparing(path)`: worker/reservation markers are durable in the assigned
   launch store, but supervisor authorization is not committed.
3. `Authorized(path, directory)`: the exact supervisor journal is durable and
   its directory identity is committed in the DAG. Only this phase may issue
   a supervised task permit or dispatch work.

Reservation precedes the Preparing transition. Direct issuance also reserves
before binding its direct role. Partial reservation errors poison both owners
until recovery. `LaunchStore::reconcile_preparation` accepts only the two
durable no-permission phases and rejects active verification or uncertain
historical/authorized attempts. Its preparation receipt is held through rebase;
it is not an OS-stop acknowledgement. An Unissued attempt without a registry
record needs no new slot, even at full capacity. Existing partial records are
revoked, gated and retained as tombstones.

V3 requires a pinned journal; an unassigned store is legal only with no active
bindings or Unissued bindings. Historical V2 requires an assigned store. V1/V2
readers and historical supervisor recovery remain supported. Copying an Unissued
DAG journal does not transfer authority. Launch-token, proof, default verifier
and ABI formats are unchanged. `CpuWorker::execute` now requires a live launch
guard matching the canonical assignment, closing an unguarded internal entry.
These are trusted-local-runtime controls, not authentication against hostile
same-UID processes. Operator journal migration is not supplied.

### Validation and live replay

`block-v2-preparation-native-20261002-c` passes **119 selected native tests and
eleven explicit pinned-CPU checks**, including copied-Unissued-journal rejection,
full-capacity recovery, malformed staged metadata, historical codecs and the
default/narrow/all-feature/all-target builds. Abrupt subprocess tests cover four
reservation boundaries plus supervisor-journal creation before authorization
and authorization before task publication. The latter tests replay structural
fixtures; the separate public recovery checks reverify real pinned proofs.
Formatting, whitespace and archived-source comparison pass with zero compiler
warnings. The bounded offline run took 170.179 seconds, with a rounded 2.1G
terminal memory peak and zero swap. Failed compile run a and passing run b
(two non-stream unused-helper warnings) are preserved. Run c feature-gates those
helpers; it does not change the admission protocol.

`block-v2-preparation-live-20261002-b` passes all six stages: actual check, captured
live cancellation, intentional coordinator exit73, fresh-actor recovery,
full-strength WrapPair proving and fresh CPU replay. Recovery confirms exact old
worker termination before rebase and does not revive candidate eligibility.
The crash precedes coordinator verification; concurrent-verifier recovery is
still unqualified.

| Actual two-transaction WrapPair | Result |
|---|---:|
| Proof / result-envelope bytes | 1,683,948 / 1,684,129 |
| Dispatch through owner acceptance/export | 166.247 s |
| Worker input verification / reported proving | 0.413 / 163.804 s |
| Worker peak RAM / swap | 42,321,920,000 bytes (39.42 GiB) / 0 |
| Peak mapped spill | 34,003,439,616 bytes (31.67 GiB) |
| Setup, cache miss / registered prove-and-verify | 47.280 / 113.626 s |

The worker journal is bound to the persisted and observed invocation. Fresh CPU
replay rejects wrong ordering and mutation. The earlier six-stage live run a,
using warning-bearing native run b, is also retained (167.232 seconds for its
pair proof); it is not a matched performance control. All experimental service units were
terminal afterward. No proving-source edits occurred during validation/live work.
This is not a matched speedup; initial admission/publication is excluded, and
neither full64 nor complete post-seal finalization is demonstrated. Scratch is
still a free-space gate/internal spill ceiling, not a physical filesystem quota.

Next: same-boot unseen/delayed authorized launches, concurrent verifier drain,
OOM/timeout and repeated lifecycle qualification, physical quotas and
reference-aware retention. Resource-accounted immutable setup reuse and GPU
transfer reduction remain separate performance work. Actual SingleWallet/Empty/
Merge generation, arrival/host eligibility, issuance/HTLC, all fixed full-block
gates, full-tree security and explicit activation remain open.

## Previous checkpoint: durable launch admission — 2026-10-02

The [admission checkpoint](evidence/block-v2-cpu-admission-2026-10-02.json)
adds authoritative local launch binding and repeats the real CPU lifecycle.
It does not qualify the complete runtime or production block deadlines.

- The DAG records its journal device/inode, launch-store device/inode and each
  admitted attempt's direct or supervised role. The supervised role pins the
  canonical supervisor-journal path. Root, store and role substitution are rejected.
- Unbound snapshots retain `LVDAG001`; launch-bound snapshots use `LVDAG002`.
  Recovery retains the global root after epoch rebase. Supervisor `LVOSR002`
  also pins its journal directory identity; historical `LVOSR001` remains
  readable for recovery, not new task issue/dispatch. Existing launch-token,
  proof and production ABI formats are unchanged.
- Successful `Supervisor::prepare` reserves a launch-store key before task/permit
  publication. `Supervisor::issue_task` performs admitted publication and token
  binding. Generic direct issuance cannot consume this reservation. Revoking a
  successfully reserved key does not require new registry capacity.
- Errors after durable binding poison the launch-store handle. A retry is rejected
  even if interruption preceded the first marker. This is a retry fence, not a
  complete recovery protocol for admission that never created a supervisor journal.
  Before that marker, capacity is not yet reserved; revocation may still require
  a new key. Do not release the DAG resource reservation based on missing files.
- Copying/replacing admitted journal directories fails closed. An operator migration
  procedure is not supplied. These checks assume trusted local metadata and an
  exclusive service namespace; they do not authenticate hostile same-UID software.

### Validation and actual proof

Native run `block-v2-admission-native-20261002-d` passed **115 selected execution
tests and ten explicit checks**, including CPU-reverified copied-DAG rejection.
Tests cover both snapshot versions, malformed admission trailers, dispatch roles,
journal/store substitution, revocation at full capacity, and injected error/abrupt
exit after admission binding, worker-marker persistence and reservation persistence.
CPU worker and narrow/default/all-feature/all-target builds, formatting, whitespace
and archived-source comparison passed with zero compiler warnings.
The bounded offline run took 165.347 seconds, with a rounded 1.6G memory peak and
zero swap. Failed compilation runs a/b and warning-bearing successful run c are
preserved separately.

Live run `block-v2-admission-live-20261002-a` passed check, captured live
cancellation, intentional coordinator exit73, fresh-actor recovery, full-strength
WrapPair proving and fresh CPU replay. Recovery used the recorded old worker
identity before epoch2 rebase and did not restore historical host eligibility.
The crash was **before CPU verification**, so concurrent-verifier recovery is
still unqualified.

| Actual two-transaction WrapPair | Result |
|---|---:|
| Proof / result-envelope bytes | 1,683,948 / 1,684,129 |
| Dispatch through owner acceptance/export | 166.028 s |
| Worker input verification / reported proving | 0.390 / 164.024 s |
| Worker peak RAM / swap | 42,439,647,232 bytes (39.53 GiB) / 0 |
| Peak mapped spill | 34,003,439,616 bytes (31.67 GiB) |
| Setup, cache miss / registered prove-and-verify | 47.688 / 113.452 s |

The structured worker journal matches both the persisted process identity and
the captured live invocation. Controller accounting is not worker accounting.
Independent replay accepts the result and rejects wrong ordering and proof mutation.
All experimental service units were terminal afterward.

This was an admission change, **not a matched proving optimization**. The lower
time than the prior 193.623-second sample is not a qualified speedup. Timing excludes
fixture loading, admission and task publication; it proves neither full64 nor
complete post-seal finalization. Scratch remains a free-space gate/internal
spill ceiling, not an OS-enforced physical quota.

### Next work

The preparation checkpoint above closes the durable no-permission admission gap.
Unseen/delayed authorized launch liveness, concurrent verifier drain, OOM/timeout
coverage and reference-aware retention remain open.
Keep reservations until actual reconciliation; an idle lock or missing service
does not prove worker shutdown.

For the setup experiment, `CpuWorker` currently creates a local
`ConstructionSession` per job and clears it before return. Reuse requires an
explicit, resource-accounted lifecycle or immutable cache, exact program/registered
cap identity, fresh hiding/salt randomness and independent CPU verification.
Do not treat all setup time as cacheable. GPU transfer optimization and matched
comparisons, actual SingleWallet/Empty/Merge and arrival/issuance/HTLC coverage,
the unchanged full64/post-seal gates, full-tree soundness/ZK and explicit activation
remain separate open requirements.



## Autonomous CPU worker and immutable tasks — 2026-10-02

The [CPU process checkpoint](evidence/block-v2-cpu-process-2026-10-02.json)
passes **87 execution native checks and seven explicit CPU fixture checks**,
a check-only run of the actual executable, a fresh two-transaction WrapPair
through immutable task/result files, independent owner CPU verification/durable
acceptance, and a separate raw-node replay. The clean native run took
**103.210 seconds**, reported **2G** peak under 3 GiB, zero swap and no warnings.
Narrow/default/all-feature builds, formatting and source-archive comparison pass.

The Linux-only `block-v2-cpu-worker` accepts `--fingerprint` or
`--task /absolute/task/path`. Tasks are issued through `TaskOwner::issue`
from a current durable assignment, not hand-authored launch tokens. The caller
must launch the exact token-named service with the reserved limits; this CLI
does not implement a durable coordinator or network listener.

- Legacy 148-byte LVCPU001 inline tokens remain unchanged. Autonomous entry
  requires a 180-byte LVCPU002 token binding the execution specification.
- The bounded LVCPUT01 specification pins the executable fingerprint, registry,
  profile/construction/chain, task directory identity, launch path, mode and
  timeout. The worker fingerprints its actual running inode via /proc/self/exe.
  Runtime fingerprints are local Poseidon2 identities; evidence hashes are SHA256.
- Private descriptor-anchored tasks publish specification/request first, bound
  launch permission next and token last. Payloads use non-overwriting staged
  publication and fsync; partial tasks remain untrusted and are never reused.
- Before proving, the worker checks its exact cgroup, finite RAM/CPU/thread
  limits, zero swap, the 48 GiB aggregate slice and disabled core dumps. Spill
  uses a held scratch-directory descriptor and a 16 MiB metadata margin inside
  its reservation. A bounded process alarm supplements the external unit timeout.
- Result publication remains under the single-use worker guard, after mapped
  spill cleanup. The owner reopens the persisted response, independently verifies
  it against its original assignment and journals acceptance.

The primary real-process trial produced a **1,683,948-byte** level-one/count-two
proof in **178.290 seconds** through dispatch, execution, OS-exit checks,
owner verification/acceptance and raw-node export. Fixture loading, admission
and task/launch publication are excluded. Packet verification took **419 ms**;
proving/setup/cleanup took **176.642 seconds**. Specification/request/token/result
sizes were **6,377 / 1,707,443 / 180 / 1,684,129 bytes**.

The worker ran for **177.557 seconds**, with **42,529,280,000 bytes** peak cgroup
RAM under 44 GiB, **34,003,439,616 bytes** peak mapped spill and zero swap.
Spill is not additional RSS. Controller, owner and worker measurements are
separate; the shared slice remains capped at 48 GiB.

The experiment captures a live service InvocationID, a PID handle immune to
PID reuse, and its actual cgroup descriptor. Successful unit wait, pidfd exit
and cgroup quiescence precede stop acknowledgement and reservation release.
The initial successful trial exposed that systemd can garbage-collect completed
units and return default post-exit fields. Those fields are **not** accepted as
standalone stop evidence. The strengthened trial passes; its executable is
byte-identical to the earlier one, and the source delta is test-only.

The separate **0.950-second** replay rejects wrong ordering and mutated proof
bytes. Its existing fixture loader reads retained public wallet proofs to derive
the expected pair job: this is raw-node replay, not an inner-archive pruning or
journal-restart qualification. All runs, including early build failures and the
initial weaker lifecycle record, remain preserved.

This establishes a local experimental process boundary, **not a production
supervisor, performance speedup, full block or complete post-seal result**.
Same-uid code, kernel and filesystem are trusted; checksums/fingerprints are not
remote-worker authentication. Logical task/spill limits are not physical disk
quotas, and process-interruption tests do not qualify storage power-loss behavior.
No default verifier, historical proof format, C ABI or activation changed.

Next: durable service dispatch/reconciliation and cancellation, physical quotas,
task/launch-record admission and pruning, complete operation generation and
arrival-driven candidates. GPU transfer reduction, full64/deadlines, all types,
complete-tree soundness/ZK and host activation remain open. Earlier checkpoints
below retain their original measurement scope.


## Bounded CPU packets and guarded proof — 2026-10-02

The [worker-packet checkpoint](evidence/block-v2-worker-packets-2026-10-02.json)
passes **77 execution native checks and six explicit CPU fixture checks**, plus
a separately bounded real paired-wrapper proof and independent fresh-process
raw-node replay. The clean native run took **106.577 seconds**, with a reported
**1.5G** peak under 3 GiB and zero swap. Narrow/default/all-feature builds,
formatting and source-archive comparison also pass.

The local request codec serializes an immutable scheduler assignment: exact
lease process key and resource reservation, externally expected profile,
construction and chain, semantic job identity, ordered child statements and
bounded public artifact bytes/digests. Preprocessing keys stay in separately
pinned worker configuration. Counts, lengths and canonical fields are checked
before copying inputs; only two proof inputs are allowed. Requests are capped at
4 MiB + 64 KiB, results at 2 MiB + 256 bytes. Local tags LVCPUR01/LVCPUS01 allocate
neither a public network format nor a C ABI; no witness-bearing API is added.

Decoding never constructs a scheduler Assignment or a proof-validity ticket.
The CPU worker requires a caller-held single-use launch guard and checks the
packet against its token, including exact process key and resource equality.
It CPU-verifies public wallet/child proofs against the externally pinned registry
and derives/checks the requested statement before large proving allocations.
The existing direct adapter and packet path share the same proving dispatcher,
with fresh proof randomness and workspace cleanup on every call.

Results bind the original assignment and exact encoded request. They return
UnverifiedResult: the coordinator must independently CPU-verify against its own
Job, recheck current attempt/candidate eligibility, and journal acceptance.
Worker timing/cache reports never authorize acceptance or resource release.
Tests show that a well-formed result containing a valid but wrong-job proof is
still rejected by the owner's verifier.

The additional merge-input CPU check passes two real root proofs to the worker.
Its setup reads retained wallet fixtures to construct external expected jobs
and repeats the known subtree at two ordered ranges. Repeated spends are not
host-eligible. This is child-verification coverage, not a new 16-transaction
proof, throughput measurement or shared-fixture pruning claim.

One new packet-driven WrapPair proof for **two transactions**, level one, passed:

- Raw proof **1,683,948 bytes**; request **1,707,443 bytes**; result **1,684,129 bytes**.
- Execution through owner acceptance/output publication **185.854 seconds**,
  excluding initial fixture loading, admission and launch issuance.
- Input decode/binding/verification **435 ms**; proving/setup/cleanup **184.807 s**;
  raw node serialization **1 ms** (result-envelope work is additional).
- Proving-worker RAM peak **41,294,438,400 bytes** under 44 GiB; mapped spill peak
  **34,003,439,616 bytes** under 120 GiB; zero swap.
- Owner CPU verification and durable acceptance passed. A separate **0.968-second**
  service replayed the saved raw node and rejected wrong ordering/mutated bytes.

These are one correctness observation, not a controlled speedup, full block,
journal-recovery replay or complete post-seal result. The test runs the packet
API synchronously inside the existing exclusive experiment controller; it is
not an autonomous worker executable, file/network transport or durable OS
supervisor. The guard remains held through proving/cleanup; runtime process and
verifier quiescence remain distinct from the idle-lock check.

Next: a bounded worker entry point and immutable local transport, exact
lease-to-service reconciliation, physical quotas and launch-record retention.
Real SingleWallet/Empty/Merge generation through this adapter, arrival-driven
candidates, GPU data movement, full64/deadlines, full-type host integration,
complete-tree security and activation remain open.

## Durable single-use CPU launch gate — 2026-10-02

The [launch-fencing checkpoint](evidence/block-v2-launch-fencing-2026-10-02.json)
passes **69 execution native checks and four explicit CPU fixture checks**,
including 16 launch checks and one exact lease-key check. Ten new abrupt-exit
cases cover issuance, revocation and single-use entry; the existing artifact and
journal cases also run. A separate owned child holds the worker lock through
revocation and store reopen until the test kills and reaps that exact child.
This establishes process-interruption/lock behavior, not a systemd supervisor.

The clean CPU-only validation finished in **93.469 seconds**, with a reported
**1.5G** peak under its 3 GiB cap and zero swap. Narrow/default/all-feature build
checks, formatting and complete source-archive comparison pass without warnings.
The earlier successful run is preserved; its one test-only unused-guard warning
was corrected before the clean rerun. No new recursive proof or speedup is claimed.

Each local CPU token binds the exact lease process key, directory device/inode,
resource reservation and bounded opaque request digest. The process key covers
session, epoch, attempt sequence, job, worker and deadline. Tokens are fixed
148-byte local metadata, not proof authority, a network protocol or a new ABI.
The gate hashes request bytes but does not serialize, store or transport tasks.

Permission is published only after the worker-lock file and immutable intent
are durable. A worker locks the exact file, checks the intent/request and
revocation, then creates and fsyncs a single-use started marker before admission.
Even a crash before the entry returns consumes that attempt; a retry requires a
fresh lease. Revocation durably records an irreversible tombstone before removing
permission, including for a lease whose launch may never have been issued.
Partial records remain untrusted inventory and are never promoted automatically.

Required runtime sequence:

1. Provision launch-record capacity and commit the lease/reservation before
   issuing permission. Bind the eventual executable, request decoder and OS
   limits to that exact assignment; none of those runtime steps is supplied here.
2. Keep the worker guard alive through proving and cleanup. Do not allow detached
   descendants to outlive the guard. Permission is single-use; disable automatic
   service restart/replacement.
3. On cancellation, expiry or recovery, durably revoke before stopping/querying
   the exact service/cgroup. Keep all resource reservations on uncertain errors.
4. Acquire the revoked idle gate, confirm the exact OS work is gone, and drain
   CPU verification before acknowledging scheduler stop/releasing resources.
   An available file lock alone never establishes process or verifier termination.
5. Retry under a fresh lease and CPU-verify returned proof bytes before durable
   acceptance. Historical candidate eligibility still requires host revalidation.

The store requires a dedicated private operator-owned Linux directory. Five
recognized bounded filenames per lease and a configured record cap bound its
inventory; records/tombstones are neither reused nor automatically pruned.
At capacity, existing records remain revocable, but a never-issued lease may
require another record. Runtime admission must reserve that capacity, retain
reservations on failure, and eventually implement reference-aware pruning.
These are logical bounds, not physical filesystem quotas or power-loss
qualification. Checksums are not authentication against malicious same-uid
software; same-uid processes, kernel and filesystem remain trusted.

Next: bounded worker packets/executable, actual OS lifecycle and resource
enforcement, complete operation coverage and arrival-driven candidates. GPU
data movement, full64/complete post-seal timing, full transaction types,
complete-tree security and production activation remain open.

## First leased CPU-adapter proof — 2026-10-02

The [synchronous CPU adapter](evidence/block-v2-cpu-worker-2026-10-02.json)
now captures a current scheduler lease, ordered dependency jobs, exact artifact
identities and immutable public input bytes. It verifies inputs before large
proving allocations and dispatches the existing registered Wrap/WrapPair/Empty/Merge
operations. The CPU reference rejects GPU builds and alternate proving switches.
No wallet witness API, proof parameter, historical verifier or production ABI changes.

**52 native checks and four explicit CPU fixture checks pass**, together with
narrow/default/all-feature build checks, formatting and source-archive comparison.
An additional, separately bounded real test generated one full-strength
**paired wrapper for two transactions** from the pinned eight-wallet public
fixture. It passed owner CPU verification, durable acceptance and CPU-reverified
recovery. A fresh process independently replayed the saved output and rejected
wrong ordering and mutated bytes.

- Proof: **1,683,948 bytes**, level one/count two, not a complete block.
- Leased execution through owner acceptance/recovery: **231.705 seconds**.
  Initial fixture loading/admission is excluded; this is not post-seal timing.
- Proving/compilation/setup/native verification/workspace release: **226.157 seconds**.
- Worker peak RAM: **39,931,117,568 bytes (37.189 GiB)**, zero swap, under 44 GiB.
- Peak mapped spill: **34,003,439,616 bytes (31.668 GiB)**, under a 120 GiB ceiling.
- Fresh replay service: **3.105 seconds**, including fixture checks; not an
  isolated measurement of root-verifier latency.

The native validation used a 3 GiB service. Actual proving used the existing
exclusive experiment controller and a separate 44 GiB child within the aggregate
48 GiB slice, with finite runtime, bounded output capture and CPU-only settings.
A local session drops its preprocessing workspace before returning; no live spill
mappings remain when completion is acknowledged. Retaining warm preprocessing
across released leases would evade reservation accounting, so persistent warm
worker reuse remains a separately scoped runtime requirement. Proof randomness
is fresh for every call.

This is **not an autonomous worker supervisor**. Assignment/Output are local Rust
contracts, not a new network protocol. Returned worker bytes are not verification
tickets: the owner must independently verify against its own expected Job, check
current attempt/candidate eligibility and durably commit completion. The external
experiment controller does not provide a durable lease-to-process map, a worker
cancellation API or automatic post-crash reconciliation. A trusted runtime must
enforce resource requests and acknowledge actual stop/drain, never timeout alone.

Real adapter-driven SingleWallet/Empty/Merge proof generation, process supervision,
arrival-driven complete candidates, warm workspace ownership, GPU performance,
full64/deadlines, full transaction types, complete-tree security and activation
remain open. One pair proof is not throughput or production qualification.

## Durable snapshot-journal checkpoint — 2026-10-02

The [Linux snapshot journal](evidence/block-v2-journal-2026-10-02.json) passes
**48 native checks**, including 16 journal checks, and three explicitly run
pinned CPU replays. Four journal abrupt-exit cases and five artifact-publication
abrupt-exit cases run inside two of those native checks. Narrow/default/all-feature
build checks, formatting and a complete source-archive comparison also pass.
The CPU-only validation finished in **95.480 seconds**, with a reported **1.5G**
memory peak under a 3 GiB cap and zero swap. This is validation runtime, not
recursive proving throughput.

The coordinator now commits bounded current-state metadata before exposing a
mutation. A private staging file is written and fsynced, renamed over the
authoritative snapshot, and the directory fsynced. A generation, length and
domain-separated checksum bind the frame. This is a snapshot journal, not an
append-only audit/event history; it does not alter network or proof encodings.
Failed or uncertain journal commits disable further dispatch. Ordinary
pre-write input/quota rejections no longer disable the coordinator unless its
artifact store actually requires recovery.

Recovery checks bounded metadata, configuration and epoch, reconstructs jobs
through their original constructors, and CPU-reverifies every referenced wallet
and accepted node. Historical candidates are reports, never revived host
eligibility. Uncompleted work is dormant, and old handles are fenced. A stored
orphan is not a completed job. The real replay recovers eight wallets and their
level-three/count-eight root, rejects wrong context and corrupted bytes, and
prunes only temporary store copies after the retention window. Standalone CPU
root replay still passes afterward. This is not full64 proof generation.

Operator recovery contract:

1. Stop dispatch after an uncertain persistence result and drop/reopen the owners.
   Preserve the private directories; never promote staging files or substitute
   an empty graph for corrupt/missing authoritative state.
2. Explicitly clean recognized interrupted artifact writes; load the journal with
   the same limits/profile/chain and a strictly newer epoch. Configuration/format
   migration is not implemented.
3. Authoritatively reconcile every recorded unresolved lease, including proving,
   device events and verification work. Timeout alone is not proof of termination.
   The callback must be idempotent if recovery is retried.
4. Resume only after reconciliation; the retention window is rebased and a fresh
   session snapshot is committed. The host must recheck anchors, spends, heights,
   issuance and other eligibility before attaching/sealing a new candidate.
5. Prune through the durable owner: commit removal of references first, then
   remove unreferenced artifacts. Never manually delete referenced proofs.

The recovery callback is a boundary, **not an OS worker supervisor**. Real
CPU/GPU worker adapters, process reconciliation, physical RAM/VRAM/disk enforcement,
host eligibility checks and arrival-driven integration remain open. Journal and
store bounds are logical accounting, not filesystem quotas; same-uid software,
kernel and filesystem remain trusted. Abrupt process exits do not establish
storage-device power-loss durability. Full64, complete post-seal, complete-tree
security, mixed transaction types and production activation remain unqualified.

## Immutable artifact-store checkpoint — 2026-10-02

The [Linux artifact store](evidence/block-v2-artifact-store-2026-10-02.json) now
passes **32 native checks**, including 11 store checks, and two explicitly run
pinned CPU fixture replays. One native check launches five abrupt-exit child
processes across the publication boundaries. Narrow/default/all-feature builds,
formatting and source-archive comparison also pass in a 3 GiB service with zero
swap. The earlier and expanded successful validations are preserved separately.

The store accepts only existing verified public-proof tickets and their exact
bytes. It writes a private temporary file, fsyncs it, atomically publishes a
non-overwriting hard link, fsyncs the directory, then removes the temporary name
and fsyncs again. Reopening reports interrupted writes for explicit cleanup.
Inventory entries and published orphans are not completed jobs: loaded proofs
are reverified by the original CPU verifier against external registry, chain and
expected-job bindings. The real replay covers all eight preserved wallets and
their root; only temporary store copies are pruned, and the shared fixtures stay
intact. A final CPU root replay succeeds after deleting those local wallet copies.

Operator requirements: a dedicated private directory on a qualified local Linux
filesystem, procfs, exclusive file locks, atomic hard links and directory fsync.
The open directory descriptor remains authoritative if its path is renamed.
Unsafe filesystem entries, changed locks and corruption fail closed. Publication
errors poison the live handle; reopen and explicitly recover before further use.
Published files are never automatically deleted. The caller must not equate a
stored artifact with a journal-committed current attempt.

Admission bounds logical file bytes and directory-entry counts, including
temporary publication overhead. It is not physical disk enforcement: filesystem
block rounding, metadata and the forthcoming journal belong in the aggregate
128 GiB scratch accounting. The tests establish process-interruption behavior,
not device power-loss durability or isolation from malicious same-uid software.
Transition journaling, candidate recovery/host revalidation, surviving-worker
reconciliation, reference-aware garbage collection and real proving adapters
remain pending. No latency, full64, security or activation gate is closed here.

## Local in-memory DAG checkpoint — 2026-10-02

The [bounded local DAG](evidence/block-v2-local-dag-2026-10-02.json) is now connected
and passes **21 structural checks**, including 15 scheduler checks, plus the
separate pinned eight-wallet/root CPU replay. Narrow/default/all-feature builds,
formatting and source-archive comparison pass in a 3 GiB, zero-swap service.
The initial failed test used an incorrect ready-priority expectation; its log
is preserved with the corrected validation.

Implemented behavior includes immutable public input manifests, dependency-driven
readiness, exact candidate eligibility/sealing, shared-work cancellation, session
and attempt fences, idempotent CPU-ticket completion, aggregate admission and
bounded pruning. Cancellation and expiry retain worker/output reservations until
the worker is stopped and CPU verification has finished. Result lookup advances
the monotonic clock before returning a sealed candidate. A synthetic 127-node
graph completes under shuffled workers; this is not a full64 cryptographic proof.

This is an in-memory state machine, not a durable proving service. The caller
must drive time and authoritative worker/verification acknowledgements; resource
reservations do not enforce OS or physical device quotas. Durable journaling,
artifact recovery/revalidation, surviving-worker reconciliation, real worker
adapters and arrival-driven tests are next. Full64/deadline/security/host gates
and production activation remain unchanged. The GPU measurements below are
preserved historical checkpoints, not measurements of this new scheduler.

## Opening-enabled versus retained-hashing pilot — 2026-10-02

The [fresh same-build matched pilot](evidence/block-v2-gpu-openings-matched-pilot-2026-10-02.json)
passes both recursive workloads and independent CPU-only root audits after local
inner-artifact pruning. Resident commitments with GPU opening reduction took
**686.046 seconds**, versus **607.112 seconds** for retained hashing: **13.002%
slower in this one pair**. Final merges were **92.427 / 71.812 seconds**.
Both roots were **1,683,948 bytes**; both used zero swap. No performance promotion.

Recorded upload-plus-download totals were **454,669,291,872 bytes** for the
opening-enabled backend and **195,561,873,152 bytes** for retained hashing.
Opening transfers are included exactly once. This comparison changes both
resident commitment selection and opening reduction; it does not isolate the
opening consumer's contribution. The shared public CPU fixture remains intact.
The preserved benchmark inputs match; new local job-contract code was connected
to the build only after both proof services were terminal.

Keep retained hashing as the research control. Next acceleration work should
measure and remove host materialization/re-upload through resident consumer
access or validated recomputation. Kernel-only improvement is insufficient.
Repeat qualification, local incremental scheduling/recovery, full64 and complete
post-seal deadlines, complete-tree security and host activation remain open.

## GPU opening recursive checkpoint — 2026-10-02

The [opening-enabled recursive trial](evidence/block-v2-gpu-openings-recursive-2026-10-02.json)
passes all four wrappers and three merges, local wallet/intermediate pruning,
root-only export and independent CPU-only auditing. Recursive commands total
**686.046 seconds**; the root is **1,683,948 bytes**, and the final merge is
**92.427 seconds**. The audit loaded no inner proofs and rejected 38 native,
four registry-policy and two expected-statement policy mutations. The independent
shared CPU fixture remains available for matched controls.

All seven expected opening calls were observed. Recorded transfers across proof
stages total **351,247,880,032 uploaded bytes** and **103,421,411,840 downloaded
bytes**, including the separately counted opening traffic exactly once. Opening
wall time is a subset of recursive command time, not another additive phase.
Peak observed proving-worker RAM was **40,534,675,456 bytes**, mapped spill was
**31,671,332,864 bytes**, and sampled worker VRAM was **5,960 MiB**, with zero
swap. Per-worker peaks and sampled VRAM are not simultaneous aggregate peaks or
instantaneous physical driver limits; the existing aggregate budgets stayed enforced.

This is one correctness-qualified count-eight run, not a speedup, full64,
complete post-seal or security qualification. The subsequent matched control
above shows a regression; repeated matched qualification remains open.
The prior readback regression is preserved separately. Local DAG, full-type and
full64 closure, complete-tree soundness/ZK, host integration and activation remain open.

## GPU opening runner/controller checkpoint — 2026-10-02

The [bounded runner integration](evidence/block-v2-gpu-openings-runner-2026-10-02.json)
now binds the opening mode, source archive, executables, registration and expected
statement. The v2 controller manifest requires four opening calls for the wrapper
stage and three for merges when enabled, zero for key registration or disabled
mode. CPU-only stages force opening selection off. Opening transfers are counted
separately and summed once; opening time remains a nonadditive stage subset.

The preserved build passes 35 controller checks, 27 selected native library
checks, 14 runner/common checks, 24 actual executable rejection cases, three
lifecycle checks and 11 explicit GPU regressions. The original validation failure
from an older CPU test dependency remains recorded; the corrected check builds a
current CPU-only test runner without replacing the independent audit reference.
All three full-size GPU preprocessing keys match that independent CPU reference.

This checkpoint does not exercise openings in a complete recursive workload.
The next gate is a full eight-wallet proof with local pruning and CPU-only root
audit, followed by fresh same-build matched controls. No recursive speedup,
full64, complete post-seal, local DAG, security review or activation is claimed.

## GPU opening-consumer checkpoint — 2026-10-01

The [opening-reduction adapter](evidence/block-v2-gpu-openings-2026-10-01.json)
passes **27 selected native checks and 11 explicit GPU checks**. One tiled
matrix upload serves all opening points; reduced cubic vectors remain on device
across matrices of equal height, then return as compact FRI input vectors.
The arithmetic uses the unchanged cubic Goldilocks basis. Same-seed opening
proofs and subsequent challenger samples match the reference, with preprocessing
both off and on. Four small full-strength proofs exercise the new consumer,
fusion off/on and active PCS clones, and pass the original CPU verifier.

The adapter is default-off. Explicit research initialization accepts
`LATTICA_V2_GPU_OPENINGS=1` only with resident commitments; selection after PCS
sharing/use is rejected. Queue-fence tests hold work pending and confirm safe
draining and reservation release on both errors and unwinds. All 11 GPU checks
passed in a 3 GiB/no-swap service with empty final scratch and no OOM events.

This is not a fully resident prover: host LDE readback, CPU barycentric evaluation
and inverse denominators, and upstream FRI work remain. New opening counters are
separate from existing hashing counters. Recursive controller integration was
pending at this component checkpoint; the 2026-10-02 entry above records its
subsequent validation. Preserve the retained-hash control and prior readback
regression below. The native assertion error and rejected undoubled-domain
test fixture remain in the evidence ledger.

## Prior readback checkpoint

The [banded host-readback checkpoint](evidence/block-v2-gpu-readback-2026-10-01.json)
records 18 selected native checks, seven explicit GPU regressions, and three
full-size keys matching the independent CPU registrations. One complete
eight-wallet recursive run now passes local pruning and CPU-only root auditing:
**783.952 seconds (13.066 minutes)**, a **1,683,948-byte** root, and an
**81.324-second** final merge. Host decode totals **69.628 seconds**, including
**36.454 seconds** of reorder work. The fresh [same-build control](evidence/block-v2-gpu-readback-matched-pilot-2026-10-01.json)
also passes local pruning and CPU-only auditing in **623.868 seconds (10.398
minutes)**, with a **72.412-second** final merge and the same proof size. Resident
mode remains **25.660% slower in this one pair**. Do not promote its performance.
The run order included test-only validation and an interruption/idle gap; this is
not repeat qualification or a full-block deadline measurement. Retained hashing
remains the research control while quotient/opening/FRI consumer reuse proceeds.
The corrected Rayon-scatter pressure comparison and all seven GPU regressions
now pass. Every pressure run checked all **427,819,620** canonical field values
under a 3 GiB RAM cap, with zero swap and complete spill cleanup. Layout time was
**21.443 / 23.857 seconds** for parallel scatter and **7.174 / 7.076 seconds** for
banded materialization, including reordering. These are two isolated host-layout
pairs, not a recursive speedup or five-pair qualification. The initial sequential
control remains preserved but excluded. The corrected sources differ from the
preserved recursive-prover archive only in tests; every production portion and
other archived file is byte-identical. The new layout admits an additional
output-sized workspace, and reorder time remains included in decode counters.

For proposed remote workers and multiple-GPU scheduling, see the
[distributed proving roadmap](distributed-proving.md). It uses the measurements
below as constraints, not distributed-throughput evidence. The existing aggregate
workstation limits and pinned measurement/replay obligations remain unchanged.

The selected [execution DAG and GPU implementation plan](dag-gpu-implementation.md)
prioritizes a local proof DAG and GPU transform-to-commitment pipeline, followed
by quotient/opening/FRI work. It specifies the new implementation; the measurements
and historical checkpoints below do not claim that pipeline already exists.

## Current measurement and implementation checkpoint — 2026-10-01

The five matched serial-transfer/overlap pairs are complete. Median total proving
time was **20.550 / 19.933 minutes**; worst time was **23.275 / 21.555 minutes**.
Overlap improved median total time by **3.005%**, but its final merge was slower
in four pairs (median **171.445 s**, versus **165.467 s** serial). Keep overlap
experimental and opt-in. All ten roots and the original diagnostic root passed
fresh CPU-only replay after the shared wallet fixtures were pruned, with 38 native
and four registry-policy mutations rejected per root and no inner proofs loaded.

The device-retained Merkle-tree prototype is now **integrated and compiled**.
The release build, 16 Python reporting tests, nine targeted CPU tests, ten explicit
GPU tests, and broad regression (**201 passed, zero failed, 51 ignored**) passed.
The targeted CPU tests are part of the broad suite; the ten GPU tests were run
separately from its ignored cases. These include real wallet-proof CPU verification
and lifetime/failure checks. A subsequent full-size recursive pilot also passed,
as recorded below; these component tests alone were not that proof gate.
The new runner and test executable are preserved separately; the CPU-only artifact
auditor remains unchanged. A fresh four-wallet public fixture has matching trusted
keys, expected statement, height and profile. Older draft/in-progress entries
below are historical snapshots, superseded by this checkpoint and the
[machine-readable validation record](evidence/block-v2-scalability-2026-10-01.json).

The first full-size retained-tree pilot completed seven recursive proofs in
**1,042.021 s (17.367 minutes)**. Its final merge took **133.367 s** and its
**1,913,496-byte** root passed the unchanged CPU audit after all ten local inner
artifacts were deleted (38 native and four registry-policy rejections; zero inner
proofs loaded). This is one pilot, **not a matched or repeat-qualified speedup**.
The report checked all 94 pinned sources/artifacts/inputs. Prover cgroup peak was
**42,962,817,024 bytes**, peak mapped spill **41,670,574,080 bytes**, managed GPU
peak **7,449,083,816 bytes**, and sampled prover VRAM **7,366 MiB**. Mapped spill
is not additional RSS, and sampled VRAM is not a physical quota. Uploads were
**328,028,118,272 bytes** and downloads **7,297,536 bytes**. Physical transfer
durations were cross-checked against labeled device events, separately from API
enqueue time. The pilot remains a historical single-sample result; shared-fixture
pruning and fresh replay are now complete as recorded below.

Five matched **retention-off/on pairs with serial transfers held fixed** are now
complete. Every trial has complete proving/helper accounting. All 86 pinned
source, executable and input hashes were rechecked before the four shared public
wallet-proof fixtures were removed. All ten roots **plus the retained pilot**
then passed fresh verification using the preserved CPU-only auditor, requested
GPU flags and an invalid GPU device. Each root rejected 38 native and four
registry-policy mutations; no inner proofs were loaded. The bounded replay
service exited successfully with zero swap. See the
[complete measurement and decision record](evidence/block-v2-retention-matched-2026-10-01.json).

| Four-transaction/seven-proof metric | Retention off | Retention on |
|---|---:|---:|
| Median recursive proving time | 19.627 min | 17.642 min |
| Worst observed recursive proving time | 21.402 min | 19.291 min |
| Median final merge | 170.902 s | 167.426 s |
| Worst observed final merge | 187.451 s | 201.993 s |

Retention improved total time in all five pairs, by 6.637–22.867%; the reduction
between medians was **10.114%**. Its final merge was slower in pairs one and four.
Both variants exceeded 180 seconds for the final merge alone in two trials.
Five samples do not establish a production tail-latency bound, and the final
merge is not the complete post-seal finalization workload.

Every trial uploaded **328,028,118,272 bytes**, unchanged by retention. Downloads
fell from **39,728,434,880** to **7,297,536 bytes**. Peak managed GPU allocation
rose from **1,006,633,672** to **7,449,083,816 bytes**; sampled prover VRAM rose
from 1,222 to 7,366 MiB. This remains allocation accounting plus sampling, not a
hard physical-driver quota. Peak live mapped spill fell from **47,442,042,880**
to **41,670,574,080 bytes**, not an additional RSS figure. Every root was below
2 MiB (largest 1,913,743 bytes).

**Decision:** keep retention experimental and opt-in, and prefer it for subsequent
bounded GPU research comparisons when its allocation admission succeeds. Keep
CPU proving/verification defaults and security parameters unchanged; transfer
overlap remains experimental. This is a useful compatible optimization, not a
solution to the block-proving target. At unchanged geometry and average node
cost, the new median-based 64-transaction models are **356.087 minutes off /
320.072 minutes on**. Hypothetically reducing 127 nodes to 63 with paired wrappers
would still model **158.776 minutes**, not a grouped benchmark. Polynomial/data-
movement and geometry work remains necessary. No depth-six, incremental or
production gate is passed.

The eight-wallet grouped CPU prototype completed four level-one paired wrappers,
two level-two merges and one level-three merge. Its **1,914,091-byte** root passed
the controller audit and a separate fresh CPU replay after all **14 local inner
artifacts** were pruned. Both audits checked the externally preserved profile,
chain and expected root. The latter requested a GPU with an invalid device and
loaded no inner proofs. Each rejected 38 native, four registry-policy and two
external-statement policy mutations; these are not independent cryptographic audits.

The seven proving stages took **1,988.005 seconds (33.133 minutes)** on CPU:
paired wrappers took 1,050.552 seconds and merges 937.453 seconds. The final merge
took **280.993 seconds**. Peak proving-stage cgroup memory was **42,960,003,072
bytes (40.010 GiB)**, zero swap. Maximum live mapped spill was **47,442,042,880
bytes (44.184 GiB)**, not additional RSS. Wallet proving, key registration and
external statement preparation are excluded. Summed recorded stage wall time
including check/prune/export/audit helpers was 1,989.206 seconds, excluding
controller overhead outside those stages.

Common geometry remains height **524,288**, with 340,437 active paired-wrapper
rows, 439,125 merge rows and the **39 GiB** retained-LDE lower bound. The compiler
fixed point now has real pair -> merge -> second-merge evidence. Separate key
reproduction and native-Zig expected-root derivation passed before proving.
The frozen source archive matched the worktree after completion, before
subsequent comparison-runner integration.

This earlier result is **one level-three/count-eight CPU sample**, not a padded
level-six block, production-profile approval or a comparative speedup claim.
The later same-eight pilot below supplies one controlled comparison; repeated
qualification remains required. Security, padding, mixed-workload, incremental
and production gates stay open. The
[grouped evidence](evidence/block-v2-grouped-integration-2026-10-01.json)
records the original stage accounting, source/artifact identities and fresh replay.
Older draft/in-progress entries below retain their historical scope.

The [single-eight comparison control](evidence/block-v2-eight-comparison-2026-10-01.json)
passed 31 synthetic controller tests, seven new native runner tests, 19 adjacent
native tests and the real non-proving crash/admission test. Its freshly generated
keys match the previous single-wallet research caps. Both constructions now have
identical eight-wallet proof bytes and separate native-Zig-derived external roots.
The [same-eight CPU pilot](evidence/block-v2-eight-matched-pilot-2026-10-01.json)
has now completed, using those exact shared wallet-proof bytes and preserved
CPU binaries (single first, grouped second):

| One matched eight-transaction pilot | Single wrappers | Paired wrappers |
|---|---:|---:|
| Recursive proofs | 15 | 7 |
| Total recursive proving commands | 69.941 min | 33.552 min |
| Final merge alone | 264.760 s | 287.332 s |
| Root proof bytes | 1,913,413 | 1,913,375 |
| Peak proving-stage cgroup memory | 42,961,842,176 B | 42,964,910,080 B |

Grouping reduced total proving-command time by **52.028% (2.085x)** in this
single pair, while the final merge was **8.525% slower**. Both runs used zero
swap and peaked at 47,442,042,880 bytes of live mapped spill; this is not
additional RSS. Both recorded CPU audits passed after pruning all local
inner artifacts (22 single / 14 grouped), with no inner proofs loaded.
The root/log/artifact hashes, timings and external statements were rechecked.
Shared wallet fixtures remain preserved for the required repeated comparison;
post-shared-pruning replay and five-pair qualification are still pending.
This is not a padded depth-six block, a finalization-deadline result, or
production/security approval. Quotient fusion was integrated only after the
pilot finished and is not part of either measured binary.

### Quotient-transform fusion: experimental implementation and gates

The [fusion validation ledger](evidence/block-v2-quotient-fusion-2026-10-01.json)
records a separate, default-disabled optimization in
`lattica-prover-p3/src/block_v2/quotient_pcs.rs`. The candidate interpolates each
small quotient chunk, combines its coefficients with the hiding mask, and runs
one large forward transform. It preserves the upstream normalized vanishing
polynomial, selector weights, random-column/mask draw order and last-mask
cancellation. The output owns its physical bit-reversed storage. This does **not**
reduce retained matrix geometry or GPU upload volume by itself.

Only an explicit research-runner initialization accepts
`LATTICA_V2_QUOTIENT_FUSION=1`; unset or `0` disables it, and other values fail.
Registered execution proving then uses an independent full-entropy quotient RNG.
Cloned PCS objects share that stream instead of replaying its initial masks.
Wallet proving, deterministic preprocessing and verification do not select
fusion. The original proof types and verifier are unchanged. Cubic Goldilocks,
q128, blowup16, cap6, four random codewords and PoW16 remain fixed. There is no
new C ABI or production activation. Component equivalence does not establish
complete-tree zero knowledge or soundness.

Fresh bounded CPU checks passed: **10** regular fusion tests, a separate
**112 MiB-per-output** mapped-workspace equivalence test, and the library suite
with **204 passed / 30 ignored**. The ten regular cases include small
full-strength cubic proofs replayed through the original unwrapped CPU PCS.
The workspace case observed 117,444,608 mapped bytes and retained no mapped
allocation in returned outputs; it is not a full recursive proof or job-peak
measurement. Test logs and hashes are in the ledger. Earlier GPU-feature compile,
ABI and Zig checks are distinct gates, not GPU fusion performance evidence.

`scripts/block-v2-fusion-trial.py` is a separately pinned controller, leaving the
original single/grouped controllers and binaries unchanged. Its **18 synthetic
tests** cover explicit mode propagation, observed fused-operation counts,
resource/dependency preservation, exact input/cap binding, durable attempted-stage
records, interruption, immutable copies and refusal to reuse an output directory.
These tests do not prove a full service/crash lifecycle or cryptographic result.
The underlying worker lifecycle was tested separately by the original controller.

Full-size validation is deliberately ordered:

1. `reproduce --fusion 1` copies the exact eight public wallet proofs and height
   into a new private job, generates all three initially absent keys, and compares
   every cap with the externally pinned original grouped registry. It then checks
   the original external profile, chain and expected root. This is deterministic
   preprocessing compatibility, not a fused proof.
2. `prove --fusion 1` requires that successful registration manifest and its SHA256,
   revalidates its artifacts/logs/implementation pins, and uses another new job.
   Seven recursive proofs must contain seven measured `fused quotient ldes`
   operations. A mode flag alone is insufficient. Local inner proofs are pruned;
   the resulting five-file root bundle must pass the **preserved CPU-only auditor**.
3. Repeat using `--fusion 0` with the **same candidate binary, inputs and controls**
   for a matched performance comparison. Each mode needs its own matching
   registration record. Compare measured times and resources; do not infer a
   speedup from transform counts or component tests.

Run each invocation as a named `lattica-v2-*.service` in
`lattica-v2-grouped.slice`, with controller `MemoryMax=3G`, `MemorySwapMax=0`,
`RuntimeMaxSec=21600`, and `LimitCORE=0`. Before admission, verify the dedicated
slice has `MemoryMax=48G` and `MemorySwapMax=0`; runtime overrides do not survive a
reboot. Workers retain `MemoryHigh=40G`, `MemoryMax=44G`, zero swap, eight Rayon
threads, a 7,200-second timeout and a 120 GiB managed-spill bound. Worker lifetime
is bound to its controller. Do not run builds or other heavy workloads alongside
measured proving. An incomplete attempt is evidence to inspect, not an invitation
to rerun it. The CLI requires explicit runner/archive SHA256 pins:

```text
python3 -B scripts/block-v2-fusion-trial.py reproduce --fusion 1 \
  --output NEW_REPRODUCTION_DIRECTORY \
  --runner PRESERVED_CANDIDATE_BINARY --runner-sha256 RECORDED_SHA256 \
  --source-archive PRESERVED_SOURCE_ARCHIVE --source-archive-sha256 RECORDED_SHA256

python3 -B scripts/block-v2-fusion-trial.py prove --fusion 1 \
  --output NEW_PROOF_DIRECTORY \
  --runner PRESERVED_CANDIDATE_BINARY --runner-sha256 RECORDED_SHA256 \
  --source-archive PRESERVED_SOURCE_ARCHIVE --source-archive-sha256 RECORDED_SHA256 \
  --registration COMPLETED_REPRODUCTION_MANIFEST --registration-sha256 RECORDED_SHA256
```

These are the commands **inside** the bounded controller service, not commands
to run in an unbounded shell. All paths must be simple absolute paths.
Current full-size progress is recorded in the ledger; no fusion latency claim or
production qualification follows from the completed native tests.

The first full-size reproduction completed at **2026-10-01 13:35:48 UTC**: all
three 2,048-byte caps at height 524,288 exactly matched the original grouped
registry, followed by a successful external-statement check. Peak registration
worker cgroup memory was 12,402,225,152 bytes with zero swap. This is **not** a
proving-memory measurement. The separate fused seven-proof run completed at
**14:06:22 UTC** and its **1,913,701-byte** level-three/count-eight root passed the
preserved CPU-only auditor after pruning all 14 local inner artifacts. Total
recursive-command time was **1,738.999 seconds (28.983 minutes)**; the final merge
alone took **252.026 seconds**. Peak proving-worker cgroup memory was
**42,968,530,944 bytes**, zero swap; peak live mapped spill was
**47,442,042,880 bytes**, not additional RSS. Seven fused quotient operations were
observed, each with 16 chunks. A further independent 3 GiB CPU-only replay passed
38 native, four registry-policy and two external-statement mutation checks,
loading no inner proofs. The reporter revalidated all seven per-node profiles,
artifact/log hashes, external statement and root/bundle identity.

The same-binary fusion-off control completed at **2026-10-01 14:44:31 UTC**,
including exact registered-cap reproduction, local inner pruning, preserved CPU
audit and an additional independent 3 GiB CPU-only replay. Both additional
replays rejected 38 native, four registry-policy and two external-statement
mutations, loading no inner proofs. The [checked matched comparison](evidence/block-v2-quotient-fusion-matched-2026-10-01.json)
records one pair in on-then-off order:

| Eight-transaction/seven-proof CPU metric | Fusion off | Fusion on |
|---|---:|---:|
| Total recursive-command time | 1,931.865 s (32.198 min) | 1,738.999 s (28.983 min) |
| Final merge alone | 270.047 s | 252.026 s |
| Root bytes | 1,913,317 | 1,913,701 |
| Peak worker cgroup bytes | 42,965,905,408 | 42,968,530,944 |
| Peak live mapped spill bytes | 47,442,042,880 | 47,442,042,880 |

Observed total-time reduction was **9.983%**, and final-merge reduction **6.673%**.
This is **one matched pair**, not repeated/tail-latency qualification, a padded
depth-six block, a GPU comparison or complete-tree security approval. The final
merge alone still exceeds the three-minute complete-finalization target.
Retained geometry did not improve: spill was identical, worker memory essentially
unchanged, and fusion alone does not reduce GPU upload volume. Mapped spill is
not additional RSS. Keep fusion **default-disabled / opt-in**.

Final-merge inclusive spans identify continued measurement targets: Merkle-tree
construction was 127.968 s on / 131.450 s off, first digest layer 119.302 / 115.989 s,
and matrix-quotient reduction 45.229 / 47.111 s. These nested/concurrent lifetimes
are **nonadditive**, not a total-time breakdown or a 64-transaction projection.
Original single/grouped baseline binaries and fixtures are unchanged.
Registration-job wallet copies must also be pruned once all matching proof
consumers finish, before final shared-fixture deletion and fresh replay of both
fusion roots in addition to the original series and pilot roots.

`scripts/report-block-v2-fusion.py` validates **completed** trial manifests and
their separately pinned registration manifests without starting work or writing
artifacts. `inspect` rechecks the source/binary pins, archived controller sources,
stage logs, exact external statement, local pruning, root/bundle identity and
recorded CPU-auditor result. It also binds profiler checkpoints to each of the
seven nodes. `compare` requires an off/on pair with the same binary, source
archive, controls, wallet bytes, height and caps, and refuses overlapping runs.
Its command-time and final-merge comparisons stay separate; inclusive profiler
spans are returned individually, never summed into an additive time breakdown.

The reporter passed **20 synthetic tests**, rejected the trial while it was still
running, and subsequently accepted its completed pinned evidence. This is
parser/evidence-checker validation, not an additional cryptographic audit by the
reporter. A one-pair report cannot grant repeat, tail-latency,
depth-six or production qualification. Registration fixtures must still exist
when making this report; post-shared-pruning replay remains a separate gate.
Use `inspect --help` or `compare --help` for the explicit manifest/registration
path and SHA256 arguments. Stage output can remain buffered during a multi-node
command: inspect the named systemd service and newly written artifacts before
interpreting a quiet log. Do not restart work just because a log is quiet.

`scripts/block-v2-fusion-prune.py` provides a separate, fail-closed cleanup path
for the **16 copied wallet proofs in the two fusion registration jobs**. It does
not change the frozen proving controllers, manifests, keys, roots, audit bundles
or shared wallet fixture. `plan` is read-only and requires both completed
off/on consumers to pass the pinned full reporter. `apply` repeats that validation
inside an idle bounded controller with the shared experiment lease, then journals
the attempt durably before unlinking exact, private, single-link wallet files
through checked directory handles. Symlink/identity/membership changes and an
existing receipt directory are refused. An interrupted prune requires manual
inspection; there is no automatic resume.

The [cleanup validation record](evidence/block-v2-fusion-prune-2026-10-01.json)
records **26 synthetic tests** covering those filesystem and interruption
boundaries. They stub the cryptographic report step and do not establish a real
systemd lifecycle, successful cleanup of the measured fixtures, or a fresh root
replay. Actual cleanup is deferred until the intended consumers finish and no
other experiment service is live. Use `--help` for the off/on manifest and
registration SHA256 arguments; `apply` additionally requires a new `--output`
receipt directory. It rebuilds its plan rather than accepting an untrusted saved
plan. The receipt preserves the checked comparison and pre-deletion identities.
The original pre-pruning reporter intentionally cannot be rerun after these
registration wallet copies are absent. Final shared-fixture pruning and fresh
CPU replay of both fusion roots remain separate, mandatory gates.

The original repeated single/grouped comparison remains separate. Its
`scripts/block-v2-eight-series.py` controller executes one matched pair per bounded
invocation, alternating order across at least five pairs. Use the preserved
`target/block-v2-eight-comparison-pilot-20261001-a/launcher.py` as `--helper`;
its hash exactly matches the former `/tmp` helper. Clean completed-prefix
continuation is allowed; uncertain attempts are refused. Finalization deletes
the shared wallet fixture and freshly audits all ten series roots **and both
pilot roots** before research repeat qualification. Its real non-proving
service/journal lifecycle passed with explicitly stubbed fixture/crypto checks;
that is not full CLI/proof qualification. Preserve the shared fixture until all
experiments that need it are complete.

The [original repeated-series evidence](evidence/block-v2-eight-repeated-series-2026-10-01.json)
records the first completed single/grouped pair, started at **2026-10-01
14:47:25 UTC** using the original non-fused binaries. Its controller exited
successfully after both recorded CPU audits and local inner-artifact pruning:

| First original-series pair | Single wrappers | Paired wrappers |
|---|---:|---:|
| Recursive proofs | 15 | 7 |
| Recursive-command time | 3,943.403 s (65.723 min) | 1,949.942 s (32.499 min) |
| Final merge | 266.774 s | 282.205 s |
| Root bytes | 1,913,436 | 1,913,221 |
| Peak proving-worker cgroup bytes | 42,966,364,160 | 42,966,777,856 |
| Peak live mapped spill bytes | 47,442,042,880 | 47,442,042,880 |

Both audits rejected 38 native, four registry-policy and two external-statement
mutations, loading no inner proofs. Mapped spill is not additional RSS. Grouping
reduced total time by **50.552%**, but the final merge was **5.784% slower**.
That first checkpoint completed one of five required pairs. The second pair's
grouped trial subsequently completed in **1,939.981 s (32.333 min)**, with a
**263.058-second** final merge and **1,913,303-byte** root. Its recorded CPU audit
passed after removing all 14 local inner artifacts, rejecting the same 38 native,
four registry-policy and two external-statement mutations and loading no inner
proofs. The root, manifest and audit-log hashes were rechecked; this inspection
did not run a new proof or audit.

As of **2026-10-01 17:40 UTC**, the second pair's single-wrapper worker and
controller remain live: **three completed variants, one completed pair**, not
repeat or production qualification. Shared-fixture pruning and fresh replay
remain required. Original-series binaries and controller pins remain unchanged.
Do not compile or run native tests until both variants, audits and the controller
finish cleanly. Revalidate the series manifest before continuing, and never
resume an uncertain or failed attempt automatically.

At **18:00 UTC**, the single trial's eight wrapper proofs had completed in
**2,250.523 s (37.509 min)**. Their worker exited successfully with a
**42,963,881,984-byte** cgroup peak, zero swap and **46,942,916,608 bytes** of
peak live mapped spill (not additional RSS). The completed stage log hash and
per-node timing sum were checked. The merge worker started at **17:58:44 UTC**
and was confirmed live. This is a completed wrapper stage, not a completed
single trial, second matched pair or root audit; the whole-pair idle gate remains
closed to native builds and tests.

The second pair subsequently finished cleanly. Its controller/session exited
**0**, both recorded CPU audits passed, and no experiment services were active
at the **18:33 UTC** checkpoint. The single root, manifest and six recorded
stage-log hashes were rechecked. Both variants loaded zero inner proofs in their
audits and rejected 38 native, four registry-policy and two external-statement
mutations after local pruning (22 single / 14 grouped artifacts).

| Second original-series pair (grouped first) | Single wrappers | Paired wrappers |
|---|---:|---:|
| Recursive-command time | 4,247.146 s (70.786 min) | 1,939.981 s (32.333 min) |
| Final merge | 286.794 s | 263.058 s |
| Root bytes | 1,913,124 | 1,913,303 |
| Peak proving-worker cgroup bytes | 42,963,881,984 | 42,967,207,936 |

Grouping reduced total time by **54.323%** and final-merge time by **8.276%** in
this pair. Both final merges alone still exceed the complete 180-second
finalization budget. This is **four completed trials, two of five completed
pairs**, not repeat, tail-latency or production qualification. Shared fixtures
remain retained for all intended consumers, including the wider-layout
investigation. The original binaries/controllers remain preserved; the next
pair has not started. Native validation proceeds at this clean checkpoint.

### Program usage attribution: validated diagnostic, unchanged geometry

The candidate source now includes read-only `machine::usage::analyze` and a
`block-v2-grouped-probe geometry-report DIR` diagnostic. Neither is in the
preserved measured executables. No frozen controller, binary or source archive
is replaced. The diagnostic reads existing completed public wallet proofs and
the recorded height, verifies the wallets, and compiles wrapper/empty/merge
templates. It does not create wallet proofs, register keys, prove an aggregate,
write job artifacts or approve a profile. Like other full-size compiler work,
run it only under the existing resource bounds at an idle experiment checkpoint.

Attribution reports physical row families; all 13 operation kinds, including
separate unconstrained hints; authenticated read counts; scalar/cubic lane
occupancy; and natural-main-trace assigned/unassigned cells. It cross-checks
packed-row counts against operations and reference metadata. Assigned cells
include assignments of zero. Natural-trace cells are **not LDE bytes or peak
RAM**, and unassigned cells are **not automatically removable storage**.
The report also provides the active-row reduction needed to fit half the current
height, explicitly as arithmetic rather than a recompiled/qualified geometry.
Smaller child proof shapes change the compiler workload and must be re-evaluated.

The existing compiler already folds constants, reuses scalar/cubic/select/hash
expressions and densely packs arithmetic rows. Measure the remaining row-family
and width costs before choosing another rewrite. Specialized tables still need
the unresolved lookup privacy/composition work; this diagnostic neither bypasses
the single-zero-terminal checks nor changes an AIR constraint.

The [implementation checkpoint](evidence/block-v2-program-usage-2026-10-01.json)
records **eight passing native usage tests and nine passing grouped-runner CLI
tests**, including both new diagnostic tests. The CPU library regression passed
**212 tests, with 30 explicitly ignored and zero failures**. The default ABI
retains exactly 12 exports and no recursion/block-v2 symbols; Zig Debug passed
111 tests, and ReleaseSafe passed 143 including 32 real FFI tests. These checks
ran after the first original matched pair finished, under 3 GiB, zero-swap,
ten-minute service limits and the shared exclusive lease. Original measured
executables were not replaced.

The separately preserved CPU diagnostic passed the original externally pinned
registry/statement check and completed the full-size report in **4,002 ms**.
This is diagnostic runtime, not proof latency. Peak diagnostic-worker cgroup
memory was **928,354,304 bytes**, with zero swap and **855,646,208 bytes** peak
mapped spill (not additional RSS). All twelve input artifacts still matched the
original registration record afterward. No keys or proofs were generated, and
no profile was approved or fixture pruned.

| Template | Active rows | Scalar rows | Cubic rows | Hash rows | Rows to remove for half-height |
|---|---:|---:|---:|---:|---:|
| Paired wrapper | 340,437 | 167,997 | 97,974 | 74,465 | 78,293 |
| Empty | 680 | 455 | 0 | 224 | 0 |
| Merge | 439,125 | 281,067 | 10,417 | 147,640 | 176,981 |

Each template also has one public row and retains height 524,288. The wrapper
and merge have only three and one unused scalar slots respectively, with **no
unused cubic slots**. Ordinary lane compaction is therefore not a material
remaining opportunity. Merge operations include 898,816 scalar selects. The
half-height target of 262,144 requires removing 40.303% of current merge rows;
this arithmetic holds the old child-proof shape fixed, not recursive closure.

The next structural candidate is **wider scalar/cubic lanes within one AIR**,
with their offsets separated from the fixed Poseidon layout. As an occupancy
illustration only, 21 scalar and seven cubic lanes would fit the current
operation counts in 166,458 wrapper rows and 257,692 merge rows. This is not
recompiled recursive geometry or a speed estimate: preprocessing width, lookup
counts and degree, retained LDEs, proof size, keys and recursive child geometry must all be
recomputed. Existing unassigned cells are not removable storage. Preserve the
single zero lookup terminal and every security parameter; do not bypass the
unresolved privacy/composition obligations of a split-table construction.

No modified geometry or performance improvement is established by this report.
Keep the repeated comparison on its original binaries, and retain public
fixtures until all consumers finish before the planned pruning and root replays.

### Wider-lane single-table candidate: native gate failed

The preserved revision-two source used the default-disabled `block-v2-wide-lanes`
Cargo feature; the current source revision is described separately below.
Its [evidence checkpoint](evidence/block-v2-wide-lanes-2026-10-01.json) now records
a compiled wider build with a **failed native qualification gate**. It postdates
the validated diagnostic snapshot above.
At the clean second-pair checkpoint, the refactored default `block-v2,stream`
CPU library compiled and passed **216 tests, 30 ignored, zero failures** in
113.35 seconds. Its bounded service exited 0 with **2,868,379,648 bytes** peak
cgroup memory and zero swap. The default grouped CLI passed all nine tests;
the ABI gate retained exactly 12 exports with zero recursion/block-v2 symbols.
Zig Debug passed 105 main tests plus six separate expected-root tests;
ReleaseSafe passed 105 main, 32 real FFI, and six separate expected-root tests.
All checks used the exclusive lease, 3 GiB/no-swap service cap and 600-second
limit. Default runner/auditor binaries and a source archive including
`.cargo/config.toml` were preserved separately. These rebuilt tools replayed all
six original pilot/series roots and checked the externally pinned grouped
registry; each root audit rejected 38 native, four registry-policy and two
external-statement mutations with zero inner proofs loaded. The runner also
rejected all four altered external inputs (chain, order, profile, root). All 44
input hashes matched before and after. Shared fixtures remain retained, so this
is compatibility evidence, not the final post-shared-pruning replay. Wide native
validation compiled in 65 seconds but finished with **214 passed, three failed,
30 ignored**, in 117.76 seconds. The service exited 101, peaking at
**2,231,558,144 bytes** with zero swap. Its source is preserved in the default
build archive (which includes the opt-in wide source).

Revision two packs 21 scalar or seven cubic operations per arithmetic row while
keeping the fixed 94-column Poseidon layout and two 32-value public banks. The
first eight arithmetic lanes preserve the original A/B/C/D positions 0/8/16/24.
Lanes 8..20 occupy hash-only columns on arithmetic rows: A 32..44, B 45..57,
C 58..70 and D 71..83. Shared column helpers are used by both native trace writing
and scalar/cubic constraints, including cubic groups crossing lanes 7/8.

Hash rows use input opcodes in all lanes, but only the first eight have hash bus
reads/writes with nonzero addresses or multiplicities. Extra ports are hash
checkpoints, constrained by the permutation, and have zero bus multiplicities.
Canonical inactive-port constraints still apply on non-hash rows; columns 84..93
are zero there. This removes revision one's extra hash lookup entries and its
`1 - IS_HASH` multiplication of arithmetic constraints/counts. Both layouts retain
one AIR and the strict zero lookup-terminal requirement; no split-table masking
protocol is used. The archived first draft is superseded and was never compiled
or proved; its seven-file archive is not a complete runnable project snapshot.

This is not a cost-free packing change: preprocessing still grows from 70 to
**184 columns**. Even at half the height, that preprocessing matrix has 31.4% more
cells than the old one; this is cell accounting, not measured RAM. Actual
quotient/lookup widths, degree, proof size, changed child-verifier workload and
recursive closure must be recompiled and measured. The 257,692-row illustration
leaves just 4,452 rows below half-height before those feedback costs, and is not
a demonstrated half-height AIR. No security parameter or proof-size/resource
limit is relaxed.

The revised wide build uses lookup domain `lattica-v2-ssa-wire-wide21-v2` and a
version-four program manifest; the registry already binds dimensions and full
AIR/lookup fingerprints. It needs
new independently reproduced keys and an externally pinned profile. The default
build retains the original domain and manifest encoding by design, but exact
legacy root/registry compatibility must be revalidated at the next idle checkpoint.
Never substitute this executable into the frozen original comparison.

Four row-layout/native-trace tests and one actual-proof test with seventeen trace
mutations were added. The four layout tests and the actual-proof test passed in
the wide build. The proof test exercised all seventeen distinct trace mutations,
measured degree eight, and checked exactly one zero lookup terminal. Existing adversarial
tests use layout-aware offsets, keeping their rejection requirements. The wide
proof test also requires degree eight and exactly one zero lookup terminal.
Formatting/parser checks and `git diff --check` pass. Default CLI/ABI/Zig and
preserved root/registry compatibility checks passed at the clean second-pair
checkpoint. The wide suite failed its 524,288-row worst-case serialization bound:
**2,199,832 bytes > 2,097,152 bytes**. This is an intentionally invalid shape
template, not a measured valid proof. Two session tests also failed because their
fixture registered the natural-height empty program before the session padded it
to 1024 rows. A test-only fix now pads registration explicitly; all three focused session
tests passed in both default and wide layouts. The envelope limit and rejection assertions are unchanged.
Actual common-height feedback must be diagnosed before any full-size key/proof
work; no wide geometry or performance benefit is admitted. Keep the retained public fixtures for this additional
intended consumer before any cleanup. First validate both default and wide builds,
then compile common-height geometry before admitting new-key or proof work. A
failed geometry, degree, size or resource gate remains a failure, not permission
to weaken the construction.

The subsequent public-proof-only common-height search **failed admission**. At
child height 262,144, wrapper/empty/merge active rows were **166,458 / 399 /
266,034**. The merge misses half height by **3,890 rows**. At child height 524,288,
its merge grew to **279,404 rows**, and retained LDE payloads alone required
**60,800,630,784 bytes (56.625 GiB)** against **51,539,607,552 bytes (48 GiB)**.
The bounded diagnostic exited 1 after 8.057 seconds, with 1,201,065,984 bytes peak
cgroup memory and zero swap; that small diagnostic peak is not proving memory.
The job still contains only eight copied public wallet proofs: no height file,
keys or recursive proofs were produced. `geometry-report` was not run after the
failed admission. Preserve this rejected candidate's logs and separate binaries.

### 23-lane revision-three candidate

The [pre-codec source checkpoint](evidence/block-v2-wide23-lanes-2026-10-01.json) uses
23 scalar/seven cubic lanes inside the same 94-column single AIR. Extra A/B/C/D
ports occupy 32..46 / 47..61 / 62..76 / 77..91; non-hash columns 92..93 remain
zero-constrained. First-eight ports, 32-value public banks and the default layout
are unchanged. Preprocessing is expected to grow to 200 columns; this is a cost,
not a demonstrated speedup. The new lookup domain is
`lattica-v2-ssa-wire-wide23-v3` and the wide program manifest version is five.

This candidate retains all security and resource limits and uses the same real
17-mutation test. The envelope test derives the largest height admitted by the
existing retained-LDE RAM gate (and asserts the default remains 524,288 rows),
then checks the unchanged 2 MiB bound. A separate wide test preserves rejection
of the oversized full-height template. These tests do not prove compiler closure,
valid proof size, peak-memory feasibility, or cryptographic security.
The first full native run compiled in 71 seconds and finished with **209 passed,
nine failed, 30 ignored** in 125.67 seconds. The small real proof rejected all 17
mutations and measured degree eight with one zero lookup terminal. Eight failures
came from the usage reporter's explicit reviewed-layout guard still naming 21
lanes. Its per-operation counting formulas were reviewed against the trace writer,
the guard was updated to 23, and all eight focused accounting tests passed. The
nine CLI tests and seven default codec tests passed too. The default bound remains
**2,014,183 bytes at height 524,288**. This is not a fresh all-tests-passing wide
run: the envelope test still fails at **2,100,001 bytes**, **2,849 bytes over 2 MiB**.
The larger 524,288-row wide template (**2,224,812 bytes**) is explicitly rejected.

A fresh private job containing only the eight copied public wallet proofs then
passed `common-height` and `geometry-report`. Actual structural compilation closes
at **262,144 rows** with active wrapper/empty/merge rows **160,893 / 384 / 258,973**.
The merge has 3,171 rows of padding. Geometry is main width 94, preprocessing 200,
permutation width 51 base columns, 16 quotient chunks and degree eight. Retained
LDE payloads are **31,675,383,808 bytes (29.5 GiB)** versus the default 39 GiB:
24.36% less retained payload, **not a measured proving-memory or latency gain**.
The bounded diagnostic took 9.192 seconds and peaked at 1,124,765,696 cgroup bytes
with zero swap. The final job contains the eight public proofs and computed
height only; **no keys or recursive proofs were generated**.

At that checkpoint the next gate was reducing the encoded envelope without
relaxing any security/resource limit. The following continuation resolves the
codec/regression/structural gates; actual recursive closure remains unproved.

### Fixed-width node encoding — regression and geometry gates passed

The [2026-10-01 codec evidence](evidence/block-v2-fixed-node-codec-2026-10-01.json)
records research format **`LBV2RC02`**, selected by the locally trusted wide
build/profile, never by header-driven verifier selection. Nested Serde `u64`
words occupy exactly eight little-endian bytes; Postcard framing remains intact.
The wide program manifest is now **six**, binding node-codec revision **two**.
The AIR remains wide23 layout revision three. Default `LBV2RC01`, its registry
and wallet encoding/profile remain unchanged.

All research node readers/writers and the common prover's size check now use
the bounded codec. Encoding uses a fixed 2 MiB output buffer including the header;
canonical decoding re-encodes into an input-sized buffer and retains length,
depth and aggregate-item guards. A new composite test exposed a schema-known
zero-byte tuple case; using its fixed arity corrects that case without accepting
unknown variable-length allocation hints. Tests cover little-endian vectors,
composite types, malformed/noncanonical fields and framing, truncation, oversized
output, wrong/downgrade headers and a real small proof's codec/verification round
trip. Earlier failed attempts and corrections remain recorded in the evidence.

The wide maximum-value template is **1,683,948 bytes**, leaving **413,204 bytes**
below 2 MiB. Default remains **2,014,183 bytes** at height 524,288. The old wide
full-height legacy template remains **2,224,812 bytes** and is explicitly rejected.
Compact bytes cannot override that height's failing retained-LDE RAM admission.
These are serialization bounds, not newly generated full-size proofs.

Validation passed **223 default / 225 wide library tests** (30 ignored each),
**26 CLI/auditor tests per build**, the unchanged 12-export/no-recursion default
ABI gate and **111 Debug / 143 ReleaseSafe Zig tests**, including 32 real FFI tests.
Separately preserved default tools replayed six original pilot/series roots and
the original externally pinned registry. Each root rejected 38 native, four
registry-policy and two external-statement mutations with zero inner proofs
loaded. All 44 input hashes matched before and after.

Fresh public-proof-only common-height/geometry checks under the new registry
binding still yield **262,144 rows**, with **160,893 / 384 / 258,973** active
wrapper/empty/merge rows. Main/preprocessing/permutation widths remain
**94 / 200 / 51**, degree eight and 16 quotient chunks. Retained LDEs remain
**31,675,383,808 bytes (29.5 GiB)**. The diagnostic took **9.731 seconds**, with
**1,124,691,968 bytes** peak validation-service memory and zero swap. Its job
contains eight copied public wallet proofs and height only: **no keys or
recursive proofs**. Diagnostic memory is not proving RAM; fewer retained bytes
are not a latency measurement.

Subsequent bounded registration produced identical key bytes in two isolated
jobs from the same public proofs. The expected root was independently derived
with the preserved native Zig calculator; both registries accepted it and
rejected altered profile, chain, root and ordering. Maximum registration-worker
memory was **16,160,698,368 bytes**, zero swap, with **15,360,835,584 bytes** peak
mapped spill (not additional RSS). This is key setup, not proving memory.
A missing empty scratch directory stopped an earlier attempt before any worker;
that failed initialization is preserved separately.

The first full-strength eight-transaction candidate run completed by
**2026-10-01 21:06:09 UTC**. Four paired wrappers and three merges produced a
**1,683,948-byte** level-three/count-eight root. Recursive commands took
**1,166.413 seconds (19.440 minutes)**; the final merge took **157.817 seconds**.
The complete controller service took **1,168.178 seconds**, excluding earlier
wallet proving and key registration. Quotient fusion and GPU hashing were off.

Peak proving-worker cgroup memory was **42,950,197,248 bytes (40.000 GiB)**,
controller peak **34,820,096 bytes**, zero swap, and peak mapped spill
**34,288,652,288 bytes (31.934 GiB)**. Mapped spill is not additional RSS;
per-service peaks are not a measured simultaneous combined peak. The aggregate
48 GiB/no-swap slice and worker 44 GiB limits remained enforced.

After deleting **14 local inner artifacts**, fresh CPU root verification passed.
The separately preserved CPU auditor accepted the five-file exported root bundle
and rejected **38 native, four registry-policy and two external-statement**
mutations while loading **zero inner proofs**. Post-run verification matched all
16 source/binary/stage-log/job hashes and all five exported artifact hashes.
The controller exited successfully; no automatic retry occurred.

This establishes recursive closure for this one level-three/count-eight research
run. It is not a matched speedup, repeated performance qualification or a
measurement of the **complete** post-seal path. Empty/padded, full 64/depth-six,
mixed/incremental, full-tree security and host-integration gates remain open.
Original repeated-series and shared-fixture pruning/replay obligations also
remain open. No production activation or C ABI was added.

### Retention-only comparison controller

The integrated schema-3 controller now supports `--comparison retention` with
`--transfer-mode serial` (the default for that comparison). It alternates
retention off/on, using the same preserved runner, CPU auditor, public fixture,
profile and transfer mode. `--comparison transfer` retains the earlier serial/
overlap experiment; `--retain-trees` is only valid for that transfer comparison.
Conflicting settings fail rather than silently changing the experiment.

The controller pins source files, `.cargo/config.toml`, input/executable hashes,
GPU index and NVIDIA UUID/bus/driver inventory. Resume requires the same schema-3
configuration. Durable attempted-trial history prevents missing logs/artifacts
from authorizing another prover, even across repeatedly interrupted resumes.
Old schema-1/2 series are report-recovery-only. Recovery takes the controller lock
and refuses changed existing root/log hashes. Physical upload/download durations
must match correctly labeled device events; missing historical counters stay
unknown. Thirty synthetic/accounting tests and both historical and retained-pilot
real-log parser checks passed. This is reporting validation, not another proof.

The completed five-pair run used the preserved retained-tree runner and original
CPU-only auditor (from `lattica-prover-p3/`, inside a <=3 GiB, zero-swap controller
service). This is a historical invocation: its shared wallet proofs are now
pruned. Do not restart or resume this completed series; a new comparison requires
a fresh pinned fixture and a new output directory.

```sh
python3 -B scripts/block-v2-scalability.py \
  target/block-v2-retained-fixture-20261001 \
  target/block-v2-retention-matched-20261001-a \
  --profile e90be22347a149b82c2a961cb14a33414b6db2d8221d0eda9fdfc174bf0143be \
  --runner target/block-v2-retained-binaries-20261001/block-v2-recursion-probe \
  --auditor target/block-v2-scalability-binaries-20261001/block-v2-artifact-audit \
  --comparison retention --transfer-mode serial --pairs 5
```

During a timed series, do not rebuild or edit pinned sources, and retain the
shared fixture until every trial finishes. The repetition gate and independent
shared-fixture pruning/replay are now passed for this four-transaction retention
comparison. The decision above preserves the separate, unmet full-block
performance and security gates.

The `block-v2` feature now demonstrates a **real two-level recursive proof**:
four distinct wallet JoinSplit proofs → four wrappers → two sibling merges →
one final merge. On 2026-09-30, the root verified in a fresh process after all ten
inner artifacts were deleted. A separate artifact checker also accepted the root
and rejected its public-input, proof, and registry mutations. Repeated root-only
checks passed after the pipeline terminated.

This completes the four-transaction recursion demonstration, **not** the full
block-proving feasibility or production gate. The candidate remains inactive and
outside the frozen audit. Depth-six/64-transaction performance, common-height
empty/padding proofs, complete-tree soundness/zero-knowledge review, HTLC/issuance,
and live-network integration remain open. The Zig protocol layer continues to use
the approved Plonky3 Rust backend; no production acceptance ABI was added.

The later [profiled cache-reuse experiment](#profiled-cache-reuse-experiment-2026-09-30)
preserved root-only verification but took **36.820 minutes**, versus the earlier
34.002-minute baseline. It demonstrates safe reuse and identifies hotspots,
**not an end-to-end speedup**. Profiling and reuse remain opt-in.

The [bounded GPU hashing experiment](#gpu-hashing-experiment-2026-09-30) passed
five full two-level trials with an unchanged CPU verifier: **23.396 minutes
median, 24.488 minutes worst**. All five roots verified again after deleting the
shared wallet-proof fixtures. This is a completed repeated GPU experiment, not a
passed full-block performance or production gate.

## Original CPU baseline result

- Final envelope: **1,913,373 bytes** (1.825 MiB), below the 2 MiB limit.
- Seven serial recursive proving stages: **2,040.123 s** (34.002 minutes),
  excluding original wallet proving/key registration and the earlier failed trials.
- Largest measured proving-service memory peak: **42,966,003,712 bytes**
  (40.015 GiB), zero swap; peak live mapped spill: **47,442,042,880 bytes**
  (44.184 GiB), not an additional RAM measurement.
- Fresh-process root verification: **65 ms**; separate mutation audit: **246 ms**.
  These are single-run observations, not latency guarantees.
- CPU with disk-backed research proving; **no GPU proving was run**. A validator
  needs only the final proof, expected public statement, and independently pinned
  registry/profile—not wallet witnesses or an inner-proof archive.
- The research runner is a bounded command-line workflow, not a wallet UI,
  network-facing service, production coordinator, or deployment recommendation.

## Implemented

- A fixed-width, 94-column execution AIR with eight scalar lanes, two cubic lanes,
  constrained selection, and Poseidon2-8 permutation rows. Program length increases
  height, not width.
- Immutable SSA programs with unique definitions. Authenticated preprocessing fixes
  instructions, wire addresses, and reference counts. LogUp binds every consumed
  value to its definition; inactive ports and padding are constrained.
- Exact `p3-batch-stark = 0.6.1` and `p3-lookup = 0.6.1`, enabled only by
  `block-v2`. The batch engine proves one AIR with a mandatory zero lookup terminal.
  This is not batching private transaction witnesses.
- Full candidate uni-STARK and single-table batch-STARK verifier compilers:
  transcript, canonical field bits, hiding PCS, salted MMCS, DEEP reductions, all
  binary FRI queries, AIR/lookup evaluation, and quotient equality. Their emitted
  instructions accept real native proofs and reject mutations.
- Deterministic public program preprocessing; fresh CSPRNG randomness for every
  witness proof. The deterministic setup configuration must never prove a witness.
- Execution fingerprints binding program, parameters, constraint DAG/emission order,
  and preprocessing cap. These are not an activated recursive registry.
- Checked retained-LDE lower bounds and lookup-aware FRI/ALI estimates. Separate
  lookup soundness and recursive composition accounting remain incomplete.
- Rust/Zig canonical statement digests:
  `hash_fields(STATEMENT + kind, public_fields)`, `STATEMENT = 0x4c42563204`,
  kind codes 1–3, with a shared known-answer test. Hashing alone validates neither
  statement schema nor proof.

## Recursive programs and current evidence (2026-09-30)

The candidate compiler now builds wrapper, empty, and merge programs in
`machine/programs.rs`. Each has 23 public fields: eight u32 profile limbs, eight
u32 chain limbs, mode, level, real-transaction count, and four root fields.

- Wrapper verifies an actual candidate JoinSplit proof and binds its public-statement
  digest into the ordered leaf root. It does not receive the wallet's private witness.
- Empty constrains the canonical zero-count subtree root for levels 0 through 6.
- Merge verifies two child proofs, selects keys using constrained child modes, binds
  their contexts, checks equal child levels and the parent count/level, enforces
  dense-prefix padding, and hashes the ordered roots.

Three preprocessing caps are witness parameters hashed into the aggregate profile.
The hash also binds the fixed AIR/lookup constraint DAG, geometry, protocol
parameters, and wallet-component profile. Canonical decomposition binds that hash
to the public profile bytes. **A root verifier must pin keys produced from the
approved compiled programs. Hashing arbitrary prover-supplied keys is not approval.**
The research runner freezes its demo keys/profile; there is no production registry
or activated recursive acceptance ABI.

Tests demonstrate a real wallet proof accepted by the wrapper interpreter and
actual STARK proofs of an empty-node fixture accepted by the merge interpreter.
They also reject altered statements, modes, roots, keys, and proof openings. Proof
values do not change the emitted program manifest. Shape-only templates are
deliberately invalid proofs and are used only to compile fixed geometry.

SSA optimization includes constant-only folding, common-subexpression elimination,
independent packing of immutable DAG operations, native constrained cubic multiply/
inverse and scalar selection, and shared DEEP row/claim reductions. Cap authentication
builds a constrained tree above the cap once and shares it across queries; generated
upper-path hints are authenticated against that root, not trusted as lookup answers.
This retains the Merkle collision-resistance assumption and needs inclusion in the
eventual complete-tree hash/security accounting.

The next compaction encodes each scalar opcode in three authenticated bits,
shares constant values with an unused address port, and moves public multiplicities
into two dedicated rows. Hash-only intermediates share the B/D scalar ports; every
shared column is constrained in both modes. Symbolic lookup packing and quotient
geometry are recomputed, not assumed unchanged.

| Closed common geometry | Active rows | Padded height | Retained-LDE lower bound |
|---|---:|---:|---:|
| JoinSplit wrapper | 172,320 | 524,288 | 41,875,931,136 bytes (39 GiB) |
| Canonical empty node | 680 | 524,288 | 41,875,931,136 bytes (39 GiB) |
| Recursive merge | 439,125 | 524,288 | 41,875,931,136 bytes (39 GiB) |

Main width is 94, preprocessing width 70. The common height is a verified compiler
fixed point: compiling a merge of height-524,288 proofs fits height 524,288. These
are compiler geometry and retained-data estimates, **not measured proof time or
peak RAM**. The successful lower-bound preflight does not establish safe admission.

A verification-only backend now uses the trusted preprocessing cap and public
statement without retaining a program or preprocessing LDE. A real execution-proof
test drops all prover state and verifies with this backend. Standalone verification of the actual two-level root passed as recorded below.

### Bounded real-proof runner

Build and run from `lattica-prover-p3/`:

```sh
env RAYON_NUM_THREADS=8 cargo build --offline --release --features block-v2,stream --bin block-v2-recursion-probe --bin block-v2-artifact-audit
bash scripts/block-v2-two-level.sh
# Resume a registered private job using the profile pinned from its original setup:
bash scripts/block-v2-two-level.sh --resume-registered JOB_DIRECTORY PINNED_PROFILE_HEX
```

The script requires the user systemd service manager and cgroup memory controls.
Each serial stage has `MemoryHigh=40G`, `MemoryMax=44G`, `MemorySwapMax=0`,
`LimitCORE=0`, and a two-hour runtime ceiling.
A per-process hard spill-allocation ceiling of 120 GiB leaves room under the
128 GiB job scratch budget for small proof artifacts. With that ceiling configured,
allocation/mapping failures fail closed; there is no silent heap fallback. The
ordinary unconfigured streaming allocator's behavior is unchanged.

The runner generates four distinct wallet proofs under one shared anchor, closes
the common geometry, registers all three actual program keys, builds four wrappers,
two sibling merges, and one final merge. It derives the expected root independently
from the four wallet public statements. Inner proof artifacts are removed before a
fresh process verifies the root using only the proof, expected statement, and pinned
registry/profile. Every node envelope must fit 2 MiB. These local diagnostic
envelopes are not a frozen wallet/network wire format or a hostile-input service.

### Profiling and single-entry preprocessing reuse

The research runner supports an opt-in, serial reuse mode:

```sh
env LATTICA_PROFILE=1 LATTICA_CACHE_PREPROCESSING=1 \
  bash scripts/block-v2-two-level.sh
# Or resume a registered job with its independently recorded pin:
env LATTICA_PROFILE=1 LATTICA_CACHE_PREPROCESSING=1 \
  bash scripts/block-v2-two-level.sh --resume-registered JOB_DIRECTORY PINNED_PROFILE_HEX
```

`wrap-all` retains one wrapper preprocessing workspace for its four proofs;
`merge-all` retains one merge workspace for the two sibling merges and final merge.
The default remains one process per node. The same cgroup and scratch ceilings
apply; in reuse mode the two-hour timeout applies to each **grouped command**, not
to each node within it. These commands are private research tools, not a durable
coordinator or a production cache. A completed root-only job cannot resume proving
after its inner artifacts have been deliberately removed.

`ProverSession` requires an independently pinned registry/profile, caches at most
one immutable registered program, and drops the previous mode before preparing a
new one. A first setup recomputes and checks the registered cap. Every hit checks
the **entire compiled program**, including operations, hints, witness indexing,
references, padding and authenticated rows; matching mode/height alone is not
enough. Existing artifacts are verified before they are skipped. Wallet witnesses,
proof results and proving RNGs are not cached; each proof still constructs fresh
hiding/salt randomness. Tests check cache reuse, randomized proof bytes, exact
program mismatch rejection, explicit eviction, pin/key substitution rejection and
verification after the session is dropped. These are regression checks, not a
zero-knowledge security proof.

`LATTICA_PROFILE=1` installs a subscriber only in this CLI. It records static
upstream span names/targets and elapsed lifetimes, never span fields or events.
The profiler bounds live spans and timing keys, and reports dropped/open span
counts at quiescent checkpoints. **Span durations are inclusive and non-additive**:
nested or concurrent totals must not be summed into an exclusive breakdown.
Linux counters report per-checkpoint I/O, faults, CPU ticks, memory-high events and
memory-pressure stall deltas. I/O counters are cumulative traffic, not live scratch
occupancy; memory-high events are not OOM failures. Disabled profiling installs no
subscriber. Invalid environment values or a conflicting subscriber fail explicitly.

### Candidate-only bounded GPU hashing

With `block-v2,gpu` compiled, the candidate has a separate prove-side MMCS adapter
in `src/block_v2/gpu_hash.rs`. **CPU remains the default.** The research runner
selects GPU hashing only when `LATTICA_V2_GPU_HASH=1` is set for a proving command;
`LATTICA_V2_GPU_DEVICE` selects the OpenCL GPU index (default zero). This does not
select the legacy GPU PCS or its quadratic challenge field. Candidate challenges
remain cubic, and the proof/commitment encodings and all security parameters are
unchanged. DFT, quotient evaluation, polynomial-opening reductions and FRI
arithmetic remain CPU work; only salted leaf hashing and Merkle compression move
to the GPU.

Verification always delegates to the standard strict CPU hiding MMCS, including
matrix dimensions, widths, indices, salts and authentication paths. Verification
commands do not initialize OpenCL or acquire the GPU lease, even if the opt-in
environment flag is set. Compiling a GPU-capable verifier executable still
requires the OpenCL loader at link/load time; a CPU-only build has no such device
dependency. The unchanged CPU artifact-auditor executable is retained for
cross-backend root verification.

The engine uses one mutex-protected context/queue across threads and a private,
fixed-location per-user process lease under `/tmp/lattica-v2-gpu-lease-UID/`.
A second candidate GPU process fails before creating its job directory. It has
an **8 GiB aggregate managed-allocation ceiling**, allowing a **4 GiB reserve**
below the 12 GiB job target for context/driver costs. Checked admission includes
input tiles, two digest buffers, constants and pinned staging; device allocation
limits are checked separately. Old buffers are dropped before replacements grow.
The default input tile is at most 128 MiB and pinned staging is 64 MiB. Unsupported
unequal-height batches fail explicitly; they do not silently fall back to CPU.
The CPU branch retains its original matrix support. Salts use each configuration's
fresh RNG, with the same draw schedule as upstream; proof randomness and wallet
witnesses are never cached.

**Managed accounting is not a physical VRAM quota.** The driver can allocate
additional memory, and other users/applications are outside the cooperative lease.
The NVIDIA research launcher samples scoped prover-process VRAM about every
0.5 seconds, sums concurrent readings, and aborts on an observed total over 12 GiB,
an unavailable per-process reading, or repeated monitoring errors. Sampling can
miss short peaks; it is not an instantaneous hard GPU-memory limit or a production
admission service. Operators must reserve the device and enforce host-wide job
admission. The 44 GiB proving-service cap and at-most-3 GiB controller cap remain
separate parts of the 48 GiB job budget; full-sized provers run serially.

For repeat trials, first retain a trusted **public-only** registered fixture
(`wallet.0` through `wallet.3`, three keys, `height`, `expected`, `profile.hex`).
The launcher copies only those files to a new private directory and revalidates
them against an independently supplied pin before proving. It then proves four
wrappers and three merges, deletes all ten inner artifacts, and runs CPU root
verification and the separate auditor. Never substitute an untrusted fixture's
own claimed profile for the independent pin.

```sh
# Build the CPU-only auditor first; do not rebuild it with the GPU runner.
cargo build --offline --release --features block-v2 --bin block-v2-artifact-audit
sha256sum target/release/block-v2-artifact-audit
cargo build --offline --release --features block-v2,stream,gpu --bin block-v2-recursion-probe
systemd-run --user --wait --pipe --collect \
  --property=MemoryMax=3G --property=MemorySwapMax=0 --property=LimitCORE=0 \
  --property=RuntimeMaxSec=14400 \
  bash "$PWD/scripts/block-v2-gpu-trial.sh" \
  REGISTERED_PUBLIC_FIXTURE NEW_JOB_DIRECTORY INDEPENDENT_PROFILE_HEX
```

The launcher requires Linux cgroup v2, the user systemd manager, `flock`, OpenCL
and NVIDIA process-memory reporting. Its CSV and explicit monitor-failure marker
live in the new job directory. The engine logs cumulative transferred bytes,
marshal/upload/download/decode wall times, leaf/compression kernel event times,
total hashing wall time and managed allocation peaks. Per-node costs require
subtracting successive cumulative checkpoints within a process. The enclosing
commitment span also includes salt generation; nested spans are non-additive.
Explicit shutdown finishes the queue, releases device objects before the process
lease, and requires managed live bytes to return to zero.

Component validation includes same-seed CPU/GPU commitments and openings over
122 commits, repeated RNG draws, matrix order, heights/caps, field edge values,
bit-reversed views and forced tiled remainders. Malformed openings and unsupported
unequal heights are rejected. A real cubic-extension wallet proof generated using
GPU commitments cross-verifies after decoding into entirely standard CPU proof
types; changing its public input is rejected. These GPU component tests use a
256 MiB managed ceiling, not the full-size job setting, and do not establish the
depth-six or production gates. Live isolation also checks that CPU root verification
works with an invalid GPU index while another process holds the GPU lease.

### Bounded transfer-overlap and scalability investigation (2026-10-01, in progress)

The next candidate experiment is explicitly opt-in:
`LATTICA_V2_GPU_HASH=1 LATTICA_V2_GPU_PIPELINE=1`. Serial transfer remains the
default, and GPU support remains prove-only. The overlap path uses two input
slots and two mapped host staging slots in one OpenCL context, with separate
copy and compute queues. The **whole** input pool remains bounded to 128 MiB
and the whole staging pool to 64 MiB; these are not per-slot allowances.
Cross-queue events protect device-buffer reuse, upload completion protects
host-buffer reuse, and both queues are drained on normal return and unwinding.
Merkle compression and downloads remain serial. No proof parameters, wire
types, CPU verifier rules, or default backend changed.

`LATTICA_PROFILE=1 LATTICA_PROFILE_TIMELINE=1` adds bounded diagnostics:

- The host timeline records static span metadata only, with at most 128 threads,
  64 entered frames per thread, and 65,536 segments per checkpoint. Segments are
  disjoint **within a thread**. They are entered-thread wall time, not CPU time;
  parallel threads overlap, and uninstrumented work is not fully attributed.
- Selected coarse phases record inclusive process-counter deltas for CPU ticks,
  I/O, faults, and memory pressure. Nested/concurrent deltas are non-additive.
- Device events record uploads, leaf kernels, compression, and downloads, with
  at most 65,536 intervals per checkpoint. Device timestamps use the OpenCL
  device clock; host timestamps are process-relative monotonic time. Do not
  directly align these clock domains.
- `upload_api_ns` measures host API time; in overlap mode this is enqueue time,
  not physical DMA duration. `upload_device_ns` and `download_device_ns` are
  device-event durations. Upload/compute intersection is calculated within the
  device clock, not by subtracting nested host spans.
- Missing records, malformed exits, and open scopes are reported explicitly.
  The paired-trial analyzer rejects incomplete timelines. Profiling never visits
  span fields or events, including witness-bearing Debug/Display fields.

The bounded component validation passed under a 3 GiB service ceiling, no swap,
one Cargo build job, and two Rayon threads: all-target compile; **12 profiler
tests**, **five non-device GPU-adapter tests**, and **five device tests**. Device
coverage includes 122 same-seed commitment/opening comparisons per transfer
mode, real cubic wallet proofs accepted by unchanged CPU types, injected async
failure/unwind, a killed lease-owning child followed by lease reacquisition and
valid hashing, and a >64 MiB spill-backed bit-reversed matrix compared with
resident CPU commitments/openings. The process-death test establishes lease
recovery, not interruption at every possible driver instruction. These are
component correctness checks, **not full recursive speedup evidence**.

The [component evidence ledger](evidence/block-v2-scalability-2026-10-01.json)
pins tested source files, the preserved baseline artifacts, exact validation
service memory accounting, and the conditional historical cost model.

A broader `block-v2,stream,gpu` library run passed 196 tests, failed one, and
ignored 46. The failure was the legacy streaming quotient test's implicit OpenCL
platform selection: platform 0 is AMD with zero devices on this machine. The
isolated test passed in 0.38 seconds with `OCL_DEFAULT_PLATFORM_IDX=2`, the
enumerated NVIDIA platform. No legacy source was changed. This is evidence from
the broad run plus a targeted retry, not a claim of a single clean full-suite
invocation. The candidate adapter's explicit device enumeration and its five
device tests were already passing without this legacy environment override.

The paired runner is `scripts/block-v2-scalability.py` in the prover crate. It
requires an independently pinned public-only fixture, explicit preserved runner
and auditor binaries, and a controller cgroup with MemoryMax <=3 GiB and no
swap. It alternates serial/overlap order, defaults to five matched pairs, pins
sources/binaries/inputs, retains per-trial logs and JSON, and collects exact
per-service RAM/swap/CPU accounting. Proving jobs remain serial sibling services
with MemoryHigh=40 GiB, MemoryMax=44 GiB and 120 GiB mapped spill limits. No builds
or heavy tests may run during timed proving. The existing sampled VRAM watchdog
is retained; it is still not a physical driver quota.

`--recover-reports SERIES_DIRECTORY` analyzes existing completed logs without
starting any prover; use it after a reporting failure rather than rerunning
successful expensive proofs. The runner does not automatically delete the
shared fixture. Explicit fixture pruning and fresh CPU replay of all retained
roots remain a separate final gate. Parser tests are runnable with
`python3 -B scripts/test-block-v2-scalability.py`.

#### Accounting recovery and separately pinned comparison (2026-10-01)

The initial matched controller stopped after its first **successful serial**
trial: all seven proofs, pruning, CPU root verification and the artifact audit
passed, but the reporter assumed every short-lived service emitted a final
systemd journal accounting record. Four helper services did not. This was a
reporting failure, not a failed proof or a completed matched comparison.
The recovered trial records **1,378.591 s** of recursive command time, a
**191.881 s** final merge and a **1,913,277-byte** root. Both long proving
services have exact final accounting; the four missing helper measurements
remain `null`, never zero. The root and original logs were preserved, and
report recovery started **zero provers**. The old series is explicitly marked
failed after successful proving rather than left with a stale `RUNNING` label.

The reporting repair adds opt-in `LATTICA_V2_CAPTURE_ACCOUNTING=1` and a small
`scripts/block-v2-accounting.py` **ExecStopPost** reader. It captures kernel
memory/swap peaks, CPU usage and configured cgroup limits before collection.
These integer snapshots include the main process but exclude cleanup after the
snapshot; they are not mislabeled as final post-cleanup CPU totals. When final
journal accounting exists it is preferred and cross-checked against the
snapshot. An accounting record alone never indicates proof correctness.
Eleven harness/accounting tests, shell syntax checks and a live bounded helper
service passed. A live registration-check stage also emitted its expected
snapshot with zero swap. No prover binary or proof parameters changed.

The incomplete original series is retained under
`target/block-v2-scalability-matched-20261001/`, including an archive of its
original reporting sources and manifest. It is **not** counted as a fully
measured pair. A separately pinned five-pair comparison is running under
`target/block-v2-scalability-matched-b-20261001/`, using the same preserved
prover/auditor binaries and public fixture, with direct accounting enabled.
Its manifest and live service state, not this paragraph, determine progress.

The measured runner matches the preserved binary byte-for-byte. Its current
Cargo fingerprint records `-C target-cpu=x86-64-v3`; the pinned Goldilocks
implementation selects AVX2 packing for that target. These measurements should
not be interpreted as a scalar-only CPU baseline with an unenabled SIMD switch.
This metadata check did not rebuild anything or change the timed configuration.

An initial device-retained-tree implementation is being prepared in an isolated
scratch copy, archived under `target/block-v2-retained-merkle-draft-20261001.tar.gz`.
It has been syntax-formatted but **not compiled, executed, integrated, or used to
produce a proof**. It includes a flat device-tree layout, bounded cap/path reads,
whole-job admission, shared context-lease lifetime and draft error/lifetime tests.
The active benchmark's source/binary pins remain unchanged. It cannot receive a
speedup or correctness claim until bounded compilation, differential tests and
real recursive measurements pass. Retaining trees alone does not reduce the
large input-matrix uploads or the number of recursive proofs.

The updated isolated draft is preserved separately as
`target/block-v2-retained-merkle-draft-f-20261001.tar.gz`; the earlier archives
are unchanged. It adds a draft pending-query failure test and moves copy/query error
injection before profiling waits, so eventual device tests can exercise queue
draining rather than rely on a profiler having already waited. **All nine new
Rust/GPU tests remain unexecuted**, and the prototype remains uncompiled.

Static lifetime review also found that separate ordinary/retained lease drops
could expose inconsistent intermediate allocation totals to a concurrent
observer. The latest isolated draft uses one allocation lease to release total
bytes, retained bytes and tree count under the same accounting lock. A new
concurrent-drop invariant test is drafted; it has not run. This is a correction
to the unintegrated prototype, not a change to the running benchmark engine.

The draft also requires at least 32 bytes in each staging slot: a narrow input
row alone does not guarantee space for the four fields decoded per digest.
The boundary test covers both transfer modes and below/exact/above-minimum
pool sizes. It remains unrun; the default benchmark's 64 MiB staging pool is
unaffected, and its pinned source remains unchanged.

Additional static review found that ignoring a failed queue drain could release
allocation accounting without establishing device completion, and default mapped
buffer destruction only enqueued unmapping. The latest isolated draft fail-stops
the worker on uncertain drain/unmap completion and explicitly waits for unmapping
before its reservation is released. Tests now cover a geometry that fits alone
but is rejected with a previous live tree, simulated drain failure in a subprocess,
and copy errors/unwinds and query errors behind controlled pending events. Test
cleanup restores the engine, joins helpers and drops event handles before checked
shutdown even on assertion unwinding. **These changes and tests have not compiled
or executed.** Static review is not an independent security audit, nor does an
abort/lease test establish instantaneous physical-driver memory reclamation.

The isolated launcher/reporter changes explicitly forward and pin retention mode
for both transfer modes. They collect per-service copy/query deltas and live/peak
tree gauges, cross-check device events and managed allocations, reject incomplete
or mixed-mode evidence, and preserve unknown historical telemetry as unknown.
**Sixteen synthetic reporting/accounting tests passed** in 0.084 seconds, and
launcher shell syntax passed. These checks do not execute a prover or validate
GPU code. The draft controller is not launchable from its scratch directory;
integration and real-log validation wait for the pinned comparison to finish.
The benchmark's engine, adapter and reporting source hashes were rechecked
unchanged at 2026-10-01 02:38 UTC.

For new schema-2 series, `--resume` with the same arguments requires identical
source/binary/input pins and an exclusive controller lock. Completed logs are
reparsed and reused; an incomplete log or orphan job causes an explicit error,
never an automatic restart or overwrite. Caught controller failures update the
manifest and preserve artifacts. At least five **fully measured** pairs are
required for the comparison's repetition gate. The shared fixture still needs
explicit pruning followed by fresh CPU replay of all retained roots.

The historical median trial gives a conditional unchanged-cost model of
127 recursive proofs for 64 transactions: **424.477 minutes**, not a measured
64-transaction result. Its 44,023,413,504 cache-hit upload bytes per node imply
5,590,973,515,008 bytes across 127 nodes. If the observed PCIe 4.0 x4 link and
transfer volume are unchanged, even ideal one-way link capacity gives a
709.792-second upload floor, before computation. Removing all measured hashing
while holding other costs fixed still leaves 1,045.422 seconds for four
transactions. These models motivate investigating polynomial/data-movement and
recursive geometry costs; they do not establish an achievable speedup.

The preserved pre-overlap runner, original CPU auditor, and source/documentation
archive are under `target/block-v2-scalability-baseline-20260930/`. Historical
evidence pins remain historical and must not be relabeled as measurements of
this new code. Matched full-size performance, the architecture/security decision,
and subsequent padding/depth/workload qualification remain outstanding. The
production coordinator and activation remain gated.

### Data-retention and geometry findings (2026-10-01; source model)

`scripts/block-v2-retention-model.py` derives logical matrix, salt, and tree sizes
from the unchanged common-height geometry. Its upload **and** download predictions
match every node in the historical five-trial/35-node evidence exactly; four small
arithmetic/model tests pass. The [machine-readable model](evidence/block-v2-retention-model-2026-10-01.json)
is a source-accounting result, not a new proof, peak-memory measurement, or speed
prediction. Reproduce it from the repository root with:

```sh
python3 -B lattica-prover-p3/scripts/block-v2-retention-model.py docs/evidence/block-v2-gpu-hash-2026-09-30.json
python3 -B lattica-prover-p3/scripts/test-block-v2-retention-model.py
```

The committed base-field domain is 16,777,216 rows: common height 524,288,
hiding-domain doubling, and unchanged blowup16. The main/preprocessing widths are
94/70, permutation width is 21 base columns, and there are 16 cubic quotient
chunks. Non-preprocessing matrices retain four additional random-codeword columns.

| Matrix family | Retained LDE GiB | Cache-hit GPU upload GiB, including salts |
|---|---:|---:|
| Main | 12.250 | 12.750 |
| Preprocessing | 8.750 | 0; an initial setup adds 9.250 |
| Lookup/permutation | 3.125 | 3.625 |
| Quotient chunks | 14.000 | 22.000 |
| Randomization round | 0.875 | 1.375 |
| FRI commitment inputs | Not included in the 39 GiB LDE admission figure | Just under 1.250 |

The quotient matrices account for **22 of approximately 41 GiB** of cache-hit
uploads. `CandidateMmcs::ProverData::Gpu` also retains four salt columns per
matrix and complete host Merkle trees. Including the cached preprocessing data,
those salts occupy approximately **10.5 GiB** and full trees approximately
**6 GiB**, in addition to the **39 GiB** LDE estimate. Thus the listed logical
data alone totals approximately **55.5 GiB**, before FRI input/fold vectors,
coefficients, temporary arithmetic workspaces, allocator and program metadata.
This explains why a valid run can require file-backed storage despite passing
the 39 GiB LDE admission check. It is **not** a measured RSS figure; do not add it
to cgroup memory or mapped-spill peaks, whose resident pages overlap.

Consequences for the post-comparison implementation decision:

1. **A standalone GPU DFT port is not automatically a data-movement win.** If it
   downloads a complete LDE only for the MMCS to upload it again, it retains the
   transfer bottleneck. Evaluate bounded producer/consumer reuse across transform,
   commitment, quotient and opening phases; the 12.25 GiB main LDE alone exceeds
   the 8 GiB managed-device budget. The old thread-local GPU PCS is not a bounded
   cubic-profile drop-in replacement.
2. **Device-retained Merkle trees are a concrete compatible-backend candidate.**
   Approximately 6 GiB of full trees could fit within the 8 GiB managed budget only
   if all live trees, compute buffers, staging and constants are admitted together.
   A prototype would fetch caps and query paths rather than downloading every
   layer, preserve matrix/salt order and CPU proof types, and test outstanding
   handle lifetime, cancellation, allocation failure and lease teardown. No such
   prototype or speedup has yet been demonstrated.
3. **Reducing AIR degree must account for added columns.** An optimistic thought
   experiment that adds one auxiliary column for each of 86 Poseidon S-boxes and
   halves quotient chunks to eight, keeping other widths/height unchanged, raises
   retained LDE storage from 39 to **42.75 GiB**, while reducing cache-hit uploads
   by only **0.25 GiB**. Actual lookup packing and recursive closure could make it
   worse. This rules out treating that isolated algebraic rewrite as an established
   memory optimization; it does not rule out a redesigned, degree-partitioned AIR.
4. **Sparse row types and proof grouping require structural prototypes.** The
   current machine gives ALU, cubic and hash rows a common width and degree budget.
   Separate fixed-purpose AIRs could reduce that waste but require authenticated
   cross-table wiring, support for their proof shapes, and a new closure analysis.
   The current GPU MMCS rejects unequal matrix heights and the recursive merge
   compiler uses a single registered child geometry. Public-proof grouping likewise
   cannot be credited merely for reducing the number of nodes: a larger padded
   trace, wider proof or broken recursive closure may erase the benefit. Neither
   approach authorizes transaction witnesses at the aggregator.

All structural experiments must preserve q128, blowup16, cubic challenges,
fresh per-proof entropy, and the approved hash/FRI assumptions during comparison.
Recompute the AIR degree/lookup/multiplicity accounting, profile/program identity,
standalone CPU verification, and final-proof bound for any changed geometry.
The min-proof-bits-minus-composition-loss helper is not a complete-tree security
review. In particular, upstream batch proving describes its randomization as
statistical rather than perfect ZK; its error and composition assumptions need
explicit accounting. Classical hash/FRI bit estimates do not establish a quantum
random-oracle security claim. No changed construction is approved or activated by
this source analysis.

The split-table investigation has an additional concrete privacy constraint.
In the pinned `p3-batch-stark 0.6.1`, `proof.rs` serializes one lookup terminal
per AIR; `prover.rs` derives each from that table's lookup trace and observes
the terminals in the transcript. `verifier/mod.rs` checks that their sum is
zero. The current candidate deliberately requires **one terminal equal to
zero**, both in `machine/backend.rs` and in the constrained verifier
`machine/verifier/batch.rs`. Splitting one machine into several AIRs with
cross-table wires generally makes the individual terminal values nonzero and
dependent on the recursive witness. The zero-sum condition alone is not a
zero-knowledge argument for publishing those values. This is a design-review
requirement, not a demonstrated attack on the current single-table candidate.

A split-table prototype must therefore supply a reviewed hiding/composition
argument or a sound blinded lookup construction, not simply remove the
single-table terminal rejection. It also needs instance-count/height/width
binding, authenticated cross-table values and multiplicities, a transcript and
registry identity covering the changed construction, heterogeneous PCS opening
checks, and a child/merge/second-merge closure demonstration. The current
recursive compiler explicitly accepts one instance and one registered geometry;
upstream support for multi-AIR proving does not implement that recursive path.
Until a proof-producing prototype and its accounting exist, the source model
supports investigating this direction but does not establish its speed, memory
use, privacy or feasibility.

#### Historical paired public-proof wrapper draft — uncompiled at this checkpoint

An isolated additional compiler, `wrapper_pair`, is archived as
`target/block-v2-grouped-wrapper-draft-b-20261001.tar.gz`; the original archive
is preserved separately. It accepts two public
wallet proofs and their public statements, verifies **both** with the unchanged
cubic wallet verifier, and emits a level-one subtree with a constrained count
of one or two. For one entry, the right committed leaf is canonical empty
padding; the caller can repeat its available public proof in the second slot.
Neither verifier is disabled or replaced with a fabricated empty-wallet proof.
The ordered binary commitment, single AIR and zero lookup terminal remain
unchanged. No wallet-private witness enters the proposed wrapper interface.

This is an **uncompiled, unexecuted draft**, not a registered proving path.
Its drafted full-parameter wallet/interpreter test checks ordering, context,
count, padding, both verifier slots, witness-independent program identity and
whether the compiler still fits height 524,288. Only syntax formatting has run.
The existing registration/prover/auditor policy has not been changed. Any future
grouped construction needs independently approved preprocessing keys and a new
profile pin, actual wrapper/merge/second-merge proofs, strict CPU verification,
resource measurements and the full security review. The old policy must not
silently approve these new keys.

Read-only review identified that stale-root rejection could mask omissions in
some negative tests. The updated isolated test recomputes the root for invalid
counts and altered statements, and mutates each proof's final polynomial and
trace commitment while leaving statements and roots unchanged. Both count-one
and count-two cases are covered in the draft. These stronger tests are still
**uncompiled and unexecuted**; syntax formatting is not validation. A grouped
second-merge demonstration would require eight transactions and a level-three
root. The existing level-two/count-four auditor gate would demonstrate only one
merge above pair wrappers and must not be relabeled as recursive closure.

For a full 64-entry tree, pairing would change 64 wrappers plus 63 merges into
32 wrappers plus 31 merges: **127 → 63 recursive proofs**. Holding geometry and
each proof's cost unchanged, that is only a **2.016× count-based improvement**;
the historical cost model would still be **210.567 minutes**, about 21× the cold
deadline. This is arithmetic, not measured speedup or a closure result. Grouping
therefore remains a supporting structural experiment, not an explanation for
how the complete performance gap will be closed. HTLC/issuance, full padding,
depth-six and incremental qualification are still pending.

#### Conditional lookup-mask algebra experiment — not a protocol

`scripts/block-v2-lookup-mask-model.py` investigates a possible response to the
per-table terminal issue. It does **not** change the prover. A proposed mask
edge uses a domain-separated tuple `[tag, edge_id, r0, r1, r2]`, with three fresh
independent base-field values; adjacent tables add/subtract the same dummy
lookup. The cycle preserves the sum of all terminals. Real-wire tuples would
need a distinct constrained tag and the same registered tuple width.

The pinned upstream LogUp code combines tuple entries in Horner order. The
three random coefficients therefore multiply `beta^2`, `beta`, and `1`.
In a degree-three extension these are a base-field basis whenever `beta`
is outside the base field. Under **uniform independent challenges and hidden
mask values**, each dummy denominator is uniform in the extension field, and
its inverse is uniform over nonzero elements conditional on a nonzero
denominator. A cycle of ideal uniform masks hides individual table totals
subject to their sum; conditioning inverses to be nonzero introduces a small
statistical difference rather than perfect hiding.

Five small tests passed: cubic arithmetic/inversion, exhaustive rank and
denominator enumeration over the analogous 27-element toy field, selected
actual-Goldilocks basis checks, sum preservation and exact toy statistical
distance, and explicit incomplete-security status. **No reduced-parameter
STARK is generated.** The [algebra evidence](evidence/block-v2-lookup-mask-model-2026-10-01.json)
records source pins and the conditional component bound
`N * (1/p^2 + K/p^3)`. With illustrative `K=2` tables and conservative
`N=191` statements its inverse-bit floor is 120. This is **only that masking
component under its stated assumptions**, not a complete-tree ZK bound.

Missing work includes the joint PCS/lookup transcript, Fiat–Shamir dependence
and simulator construction, quantum assumptions, soundness of wider tagged
tuples and multiplicities, non-mask zero denominators, padded/empty tables,
the existing PCS's statistical error, and an actual recursive proof-producing
implementation. The two-table choice is illustrative, not a selected AIR
layout or approved profile. Do not remove current zero-terminal enforcement
on the strength of this algebra model.

### GPU hashing experiment (2026-09-30)

Five full-size trials passed **35 recursive proofs** with the existing independent
profile pin, the same four public wallet proofs, the same runner, and fresh outer
proof randomness. GPU-generated keys and the expected statement matched the CPU
baseline byte for byte. Every intermediate and final envelope stayed below 2 MiB.

| Trial | Recursive command total (minutes) | Root envelope (bytes) | Final merge (seconds) |
|---|---:|---:|---:|
| 1 | 24.143 | 1,913,746 | 202.765 |
| 2 | 23.396 | 1,913,876 | 183.645 |
| 3 | 21.980 | 1,913,336 | 214.290 |
| 4 | 22.641 | 1,913,813 | 182.237 |
| 5 | 24.488 | 1,912,769 | 175.346 |

The recursive command total was **23.396 minutes median, 24.488 minutes worst**,
excluding wallet proving, initial registry creation and controller/root-audit
overhead. Each trial deleted all ten inner artifacts before fresh-process CPU
verification (61–65 ms) and the unchanged CPU artifact audit (216–233 ms). Each
audit rejected 38 native mutations and four registry-policy mutations.

After the series, the shared fixture's four wallet proofs were also deleted.
All five roots then passed CPU verification again (62–89 ms) and the original CPU
auditor (219–242 ms), loading zero inner proofs. The runner's GPU flag was set with
an invalid device index during these replays; verification did not initialize
OpenCL. These are command timings, not production verification-latency guarantees.

The largest proving-service peak was **40.016 GiB** RAM, with zero swap and
**44.184 GiB** peak live mapped spill. The repeat-series controller separately
peaked at 58.9 MiB under its 3 GiB cap. Managed device allocations peaked at
**960.001 MiB**; **13,261** process-VRAM readings peaked at **1,222 MiB** including
driver overhead. All explicit GPU shutdowns returned managed live bytes to zero.
These are sampled observations, not a physical VRAM quota. The host is an Intel
Core Ultra 9 275HX with eight Rayon threads and an RTX 5080 observed at PCIe 4.0 ×4.

The earlier CPU runs took 34.002 minutes without reuse and 36.820 minutes with
reuse. Each is a historical single sample, **not a controlled repeated CPU/GPU
A/B result**. The GPU observations are lower, but do not establish an isolated
backend speedup or production throughput. Final-merge time was **183.645 s median,
214.290 s worst**; only one of five was below three minutes. No incremental-arrival
deadline workload was run, and this four-transaction experiment does not satisfy
the 64-transaction cold gate. Security, padding and network gates remain open.

The [machine-readable evidence](evidence/block-v2-gpu-hash-2026-09-30.json) records
per-node times, transfer/kernel profiles, resource measurements and artifact
identities. Across 35 nodes, hashing took 47.254–59.634 s, including 25.663–32.283 s
of upload wall time and 13.553–16.038 s of leaf/compression kernels. The first
node in each service also includes preprocessing. Inclusive quotient spans ranged
from 49.698–110.531 s and opening-reduction spans from 14.206–65.195 s. Enclosing spans
are inclusive and **must not be added** into a percentage breakdown. Reducing or
overlapping bounded transfers, then quotient/opening work and spill traffic,
are the next profiling-led optimization candidates; kernel tuning alone cannot
remove these costs.

The reusable launcher's fault tests cover query errors, unavailable per-process
memory and an injected over-limit reading. All three abort the scoped job without
starting another stage. The initial test exposed systemd treating SIGTERM as a
successful service stop; explicit pre/post-stage monitor checks closed that
launcher issue. It was not a proof-verification or cryptographic failure.

The measured runner and unchanged CPU auditor were preserved under
`lattica-prover-p3/target/block-v2-gpu-hash-binaries-20260930/` before regression
builds. The five jobs retain only their root and public registry/statement
metadata, plus resource logs—not an inner-proof archive.

Final post-change validation passed under a separate **3 GiB** cap, after timed
proving ended: **64 streaming candidate tests** (358.47 s), **two explicit GPU
tests** (3.30 s), **153 non-streaming library tests** (227.81 s), and **two artifact
auditor tests** (0.19 s). The streaming suite's four exclusions were two standalone
wide-resource tests and the two GPU tests subsequently run explicitly. The full
non-streaming suite had 19 intentional exclusions. Ignored tests are not passed
qualification gates. The explicit GPU run repeated all 122 same-seed commitment
comparisons, cubic-proof CPU cross-verification and zero-allocation shutdown.

All-feature/all-target compilation, Rust/Zig formatting, shell syntax, Zig Debug,
ReleaseSafe and ReleaseSafe FFI tests, and the default ABI gate passed. The default
library still exposes exactly 12 existing `lattica_*` symbols, with zero recursion
or block-v2 symbols. The combined service peaked at **2,688,360,448 bytes**
(2.504 GiB), with zero swap, and emitted `bounded_gpu_regression_gates=PASS`.
Its script and log are `/tmp/lattica-gpu-hash-final-checks.sh` and
`/tmp/lattica-gpu-hash-final-checks.log`; identities and a requirement-by-requirement
checklist are in the machine-readable evidence. No runtime source or measured
runner was replaced during the timed series.

### Historical bounded-workspace experiments

These trials preceded the successful two-level run recorded below.

**Baseline result (2026-09-30):** the first bounded experiment did not complete.
The first wallet-wrapper stage timed out after two hours without a proof artifact.
Its observed cgroup memory peak was 36,248,715,264 bytes (about 33.8 GiB), with no
swap. Heavy writeback activity was observed; cumulative disk writes are not live
scratch storage. This is a prover-performance failure, not a passing recursion gate.
Preparation verified
all four wallet proofs and the common geometry; its service peak was 1 GiB.
All three keys were registered at the common height. Wrapper registration took 664.253 s with a 10.8 GiB
service peak; empty registration took 789.286 s with a 10.4 GiB service peak.
Merge registration took 611.704 s with an 11.5 GiB service peak. The demo registry
profile is `e90be22347a149b82c2a961cb14a33414b6db2d8221d0eda9fdfc174bf0143be`.
These are setup observations, not transaction-proving or block benchmarks.
That baseline produced no wrapper/merge/root proof; the successful normalized run is recorded below. The baseline binary SHA-256 was
`82d93b27060aee4dd9ade5cbf3285f2046d6c23ea0c76066bd63eee8dae5fe81`.
The first registration service's live kernel limits were independently checked:
high 42,949,672,960 bytes, max 47,244,640,256 bytes, swap zero.

The streaming candidate now uses a bounded heap workspace for temporary forward
FFTs of 64 MiB through 2 GiB. It delegates all arithmetic to the same upstream
transform and leaves retained coset LDEs spill-backed. It neither globally disarms
spilling nor changes cryptographic parameters. Ownership/deallocation tests and
full-field/canonical-byte equivalence tests passed for both width eight (64 MiB)
and the actual width-seven layout (112 MiB); the expanded FFT test job peaked at
1.1 GiB. These are component checks, not evidence that the full-size retry succeeds.
Optional `LATTICA_FFT_TRACE=1` logs only FFT geometry and elapsed time.

The resume path verifies the independently pinned registry, all four wallet proofs,
the independently derived expected root, and any existing node artifacts before
skipping completed stages. Each subsequent proof recomputes its preprocessing cap
and checks it against the original registration. It preserves the baseline wallets
and keys. The script now runs both fresh root verification and the separate artifact
auditor after deleting the ten inner proof files. This remains a private research
runner, not a network-facing service or a production activation path.

The selected streaming profile passed **46 candidate tests** (30.01 s test time,
1.4 GiB service peak). A further wallet-verification regression passed, explicitly
binding the separately stored chain context and transaction statement. The saved
checkpoint then verified all four original wallet proofs and the expected root.
The temporary-FFT-only retry (binary SHA-256
`18af8f4dcd6e63226f5c92b967c3ae284c77f97ca3548fc1d56a59df7b15dd1f`)
was deliberately stopped after about 66 minutes, without a wrapper artifact.
Setup took 909.334 s and its recomputed key matched the original registration.
Five large FFTs completed in roughly one second each, but the surrounding
quotient work took about 6–8 minutes between them. Observed peak memory was
33,086,656,512 bytes. This was an early performance stop, not a timeout or a
cryptographic rejection. These results do not establish
the full-size performance gate or root-only recursive verification.

The post-change non-streaming library regression also passed: **145 passed,
19 intentionally ignored**, 211.07 s test time and a 1.4 GiB service peak under the
3 GiB auxiliary cap. During the retry, the host reported a 64 MiB dirty-background
threshold and a 256 MiB dirty-page limit. Those host settings were recorded, not
changed; they are relevant context for interpreting mmap writeback timings.

The same follow-up also passed all-feature/all-target compilation, Zig Debug and
ReleaseSafe tests, ReleaseSafe FFI tests, and default-ABI isolation: exactly 12
existing exports and no recursion/v2 exports. The check service peaked at 577.3 MiB.

An additional `coset_workspace` candidate builds each retained LDE
using one coefficient workspace and one coset workspace, then writes the output
through the ordinary spill allocator. Its explicit heap buffers are limited to
1 GiB each; other allocations and twiddle caches still require a process memory
cap. It preserves upstream's bit-reversed transform callback layout and RNG draw
ordering. Two matrix-equivalence tests passed, including a 112 MiB input and
mmap-backed retained outputs (1 GiB service peak; those tests used tmpfs).
A separate test at the actual preprocessing input geometry (height 1,048,576,
width 70) compared every field/canonical encoding against a resident upstream
reference, with a reduced output expansion of two for the test's memory budget.
The candidate's output used NVMe scratch and matched exactly: 73.595 s transform
time, 2.7 GiB service peak under a 3 GiB hard cap. The resident reference took
1.611 s. These differently backed, shared-host component timings are not block
benchmarks or an end-to-end speedup claim. Earlier wide attempts with a tmpfs
reference and an NVMe-backed reference were stopped before completion and are
not passing tests. The later normalized run below supplies full-blowup cap equality
and full-size proving evidence for the selected composition.

After these additions, the streaming candidate regression passed **49 tests**
(36.00 s), with the two explicit wide-resource tests ignored in that routine run;
the resident-reference wide test had passed separately as described above.
All-feature/all-target compilation passed again. The combined check service
peaked at 1.4 GiB, and the running recursion binary's hash remained unchanged.

A further `normalization_workspace::HeapNormalizedDft` addresses
the upstream hiding PCS's normal-order conversion and later bit reversal of
quotient LDEs. Coset outputs of 64 MiB through 2 GiB move to explicit heap storage
only when natural-order materialization is requested. Extracting the already
bit-reversed commitment storage does not copy it. Large main/preprocessing LDEs
remain mapped. Unlike the temporary FFT workspace, this policy retains the
common shape's sixteen 896 MiB quotient LDEs in RAM (14 GiB); the job-wide cap and
a full proving trial are still essential. It is not a 2 GiB total-memory claim.

Three matrix/ownership tests and a full-strength native recurrence-proof fixture
passed. The fixture uses the candidate's unchanged hiding/FRI/grinding parameters,
compares commitments exactly, cross-verifies both implementations' proof encodings,
and rejects altered public inputs. The proof test took 36.52 s and peaked at 2 GiB
under a 3 GiB RAM cap. Its initial 1 GiB mapped-spill ceiling was too small; it
passed with a 3 GiB spill allowance, still within the job's resource budget.
These are component compatibility results; recursive evidence is recorded below.
The old experiment was terminated before rebuilding. Both follow-ups were then
selected for the streaming research run with the same pinned wallets/keys,
44 GiB proving cap, 3 GiB auxiliary cap, 120 GiB proving-spill limit, and unchanged
cryptographic parameters. The selected-profile build and regression passed before
the successful full-size run.

The expanded streaming candidate suite then passed **53 tests** (77.76 s), with
the two explicit wide-resource tests ignored in the routine run. All-feature/
all-target compilation passed again; the combined service peaked at 2 GiB.

### Completed two-level recursive proof (2026-09-30)

The selected `HeapNormalizedDft` run used the original registered wallet proofs,
common height 524,288, and independently pinned profile
`e90be22347a149b82c2a961cb14a33414b6db2d8221d0eda9fdfc174bf0143be`.
Every full-size preprocessing cap matched the original registration before
proving. No query, hiding, grinding, or other cryptographic parameter was reduced.

| Completed node | Envelope bytes | Setup (s) | Prove + native verify (s) | Full stage (s) | Cgroup peak (GiB) |
|---|---:|---:|---:|---:|---:|---:|
| Wallet wrapper 0 | 1,912,991 | 38.058 | 279.707 | 319.458 | 40.003 |
| Wallet wrapper 1 | 1,913,665 | 38.051 | 269.395 | 308.857 | 40.015 |
| Wallet wrapper 2 | 1,913,418 | 39.222 | 259.485 | 300.145 | 40.015 |
| Wallet wrapper 3 | 1,913,039 | 40.864 | 230.121 | 272.381 | 40.001 |
| Sibling merge 0 | 1,913,737 | 45.024 | 241.559 | 287.760 | 40.003 |
| Sibling merge 1 | 1,913,501 | 42.388 | 223.590 | 275.257 | 40.014 |
| Final merge | 1,913,373 | 43.163 | 231.931 | 276.265 | 40.003 |

All seven proofs passed native verification. Sizes include the eight-byte
`LBV2RC01` envelope. Wrapper stages each reported a peak mapped-spill allocation
of 46,942,916,608 bytes; each merge reported 47,442,042,880 bytes. All were below
the 120 GiB mapped-spill ceiling, with zero swap. Cgroup memory peaks include the
service's charged memory and are distinct from process RSS and mapped scratch.
These are serial per-stage measurements, not a sampled aggregate peak of the
entire workstation or cumulative disk-write volume.

The successful seven-stage sum is 2,040.123 s. It excludes original wallet proof
generation, original common-height key registration, the two earlier unsuccessful
trials, and controller/verification overhead. Each stage includes recomputing its
prover preprocessing. This is one measured four-transaction research run on an
Intel Core Ultra 9 275HX, with eight Rayon threads, disk-backed spill, Rust 1.96.0,
and Linux 7.2.8-1-cachyos-gcc. It is **not a 64-transaction cold or incremental
benchmark**, does not meet the ten-minute cold target, and does not demonstrate
the three-minute finalization window. No GPU/VRAM performance result is claimed.

After the final merge, the runner deleted exactly ten files: four wallets, four
wrappers, and two sibling merges. The root statement had `count=4`, `level=2`,
and `mode=MERGE`. A fresh process verified `node.2.0` against the expected statement
derived independently from the original wallet public statements and the pinned
registry, loading zero inner proofs. Verification took 65 ms (7.8 MiB service
peak). The separate artifact checker then passed in 246 ms (12.6 MiB service
peak), rejecting 38 native mutations and four registry-policy mutations. Its root
mode explicitly checked that all inner files were absent. Both root-only commands
were repeated successfully in separate processes after the pipeline completed.

Intermediate read-only audits had also accepted wrapper 0 and sibling merge 0,
each rejecting the same 38 native mutations and four policy mutations without
loading inner proofs (470 ms and 480 ms respectively). A separate executable and
mutation tests provide implementation evidence, **not an independent security
audit**; the checker shares the underlying native verifier.

Retained local evidence:

- Job directory: `lattica-prover-p3/target/block-v2-two-level-1790733105-323847/`.
  Only `node.2.0`, `expected`, `height`, the three public keys, `profile.hex`,
  and an empty scratch directory remain.
- Runner SHA-256:
  `879856cc338d8c6f0d08a8afd37dc5d0ef2de44919044ddfc08bb3b8ca6fb3b0`.
- Separate checker SHA-256:
  `c9d4b084e46675707ed172e0d9d46444c1a891e184ee146ad57e664b69a3758b`.
- Root SHA-256:
  `6367e91fc43012b49b07176827ad4b01451b9e53aac76374bda46bf2d419dd11`.
- Raw local run log: `/tmp/lattica-two-level-normalized.log`; exact RAM/CPU
  counters are in journal records for `lattica-v2-484088-2.service` through
  `lattica-v2-484088-8.service`. These local/ignored artifacts are not a release
  archive; [the version-controlled evidence record](evidence/block-v2-two-level-2026-09-30.json)
  preserves their identities and measurements.

### Profiled cache-reuse experiment (2026-09-30)

The full four-wallet/two-level run passed again with `LATTICA_PROFILE=1` and
`LATTICA_CACHE_PREPROCESSING=1`. All seven recursive proofs verified, all ten inner
artifacts were deleted, and the **1,913,704-byte** root verified in a fresh process.
The pre-change artifact-auditor executable accepted it and rejected 38 native
mutations plus four registry-policy substitutions. Root-only verification and the
unchanged auditor also passed again after the pipeline ended. The expected public
statement and all three keys matched the baseline **byte for byte**, as did the
independently pinned profile. No cryptographic parameter was reduced.

**Performance conclusion: no end-to-end improvement was demonstrated.** The
single-entry cache eliminated five expensive setups, but the measured grouped
runtime was longer. Keep it optional; do not advertise a block-throughput
improvement or promote the production coordinator on this evidence.

| Measurement | Earlier one-process-per-node run | Profiled reuse run |
|---|---:|---:|
| Successful recursive proofs | 7 | 7 |
| Preprocessing setups / cache hits | 7 / 0 | 2 / 5 |
| Sum of reported setup/check time | 286.770 s | 83.922 s |
| Recursive proving-command wall time | 2,040.123 s (34.002 min) | 2,209.216 s (36.820 min) |
| Proving-service CPU time | 11,823.216 s | 11,426.406 s |
| Largest proving-service cgroup peak | 40.015 GiB | 40.011 GiB |
| Peak live mapped spill | 47,442,042,880 bytes | 47,442,042,880 bytes |
| Swap | 0 | 0 |

The observed wall time was 8.3% longer despite 3.4% less aggregate CPU time.
These are **one sample per configuration**, not controlled repeated A/B trials:
profiling, process grouping, fresh proof randomness and shared-host/cache state
differ. They do not isolate a cache regression or profiling overhead. They do
show that setup savings alone do not meet the latency targets. Both totals exclude
wallet proving, key registration and controller/root-audit overhead. CPU time is
summed across threads and must not be interpreted as elapsed time.

| Node | Reuse hit | Setup/check (s) | Prove + native verify (s) | Node elapsed (s) |
|---|---|---:|---:|---:|
| Wrapper 0 | no | 38.679 | 309.000 | 349.076 |
| Wrapper 1 | yes | 0.087 | 303.507 | 304.987 |
| Wrapper 2 | yes | 0.087 | 293.887 | 295.381 |
| Wrapper 3 | yes | 0.076 | 267.999 | 269.517 |
| Sibling merge 0 | no | 44.596 | 308.354 | 361.791 |
| Sibling merge 1 | yes | 0.202 | 287.276 | 288.632 |
| Final merge | yes | 0.195 | 337.109 | 338.457 |

The wrapper service took 1,219.611 s and peaked at 42,953,351,168 bytes; the merge
service took 989.605 s and peaked at 42,961,612,800 bytes. These are **group-level**
peaks, not separately measured per-node peaks. Their sum includes 1.375 s of
process/checkpoint/cleanup work outside the individual node timers. All checkpoints
reported zero dropped and zero open spans. A read-only audit of cache-hit wrapper 1
also passed during wrapper 3 (515 ms service runtime, 16.9 MiB peak); no substantial
auxiliary build/test job overlapped the timed proving commands.

On the five cache-hit nodes, inclusive Merkle-construction totals were
**134.239–144.721 s**, with **125.042–133.916 s** in their first digest layers.
Inclusive quotient work ranged from **48.692–113.158 s**; polynomial-opening
reductions ranged from **45.209–65.171 s**. These overlap other spans and **must not
be added into a percentage breakdown**. Native completed-node verification was
34–41 ms across the run. This identified prove-side Merkle/Poseidon2 work as the
next accelerator target, followed by remeasurement of quotient/opening work and I/O.
The later GPU experiment above follows the [compatibility and resource gates](block-proving-v2.md#performance-engineering-while-a3-remains-open), which
require strict CPU verification and a job-wide GPU memory bound. Enabling the
existing GPU feature alone does not accelerate this v2 configuration.

The fresh root-check command took 67 ms and the unchanged auditor 224 ms. Their
post-pipeline repeats took 58 ms and 216 ms respectively with two Rayon threads;
these are single command timings, not verification-latency guarantees. The final
merge itself took **338.457 s**, so this sample does not demonstrate the three-minute
finalization window. The 64-transaction/depth-six workload remains unrun, the
ten-minute cold target remains unmet, and complete-tree security, padding,
HTLC/issuance and network integration remain open. No GPU proof was run in this
CPU-only cache experiment; the later GPU result is recorded separately above.

Retained evidence and identities:

- [Machine-readable measurements](evidence/block-v2-perf-cache-2026-09-30.json).
- Local job: `lattica-prover-p3/target/block-v2-perf-cache-20260930/`.
- Runner SHA-256: `ccd3b4d308047624201cb53ba177ead34b2f17cf6c08711a2f2046bfb2823ed1`.
- Unchanged auditor SHA-256: `c9d4b084e46675707ed172e0d9d46444c1a891e184ee146ad57e664b69a3758b`.
- Root SHA-256: `3d4ce9d282bdb46451af3fc1e601bc4da56f5c220d0f383908b69a8e15336d1f`.
- Raw log: `/tmp/lattica-perf-cache-run.log`; wrapper/merge journal units:
  `lattica-v2-733807-2.service` and `lattica-v2-733807-3.service`.

Post-change validation passed under a separate 3 GiB cap: **61 streaming candidate
tests** (two explicit wide-resource tests ignored), **153 non-streaming library
tests** (19 intentional ignores), and **two artifact-auditor tests**. This includes
five profiler tests and three session/cache tests. All-feature/all-target
compilation, Rust/Zig formatting, shell syntax, Zig Debug and ReleaseSafe tests,
ReleaseSafe FFI tests, and the default ABI gate passed. The ABI remains exactly
12 `lattica_*` exports with zero recursion/v2 symbols. The combined validation
service peaked at **2,686,681,088 bytes** (2.502 GiB), with zero swap; its transform
compatibility tests used NVMe-backed scratch. Root-only repeats ran before the
test builds, using the measured runner and preserved pre-change auditor. Three
test-only cases and extra assertions were added after the timed runner was built;
the running binary and its runtime implementation were not replaced.

### Independent bounded artifact audit

`block-v2-artifact-audit` is a separate, read-only executable. Building it does
not replace a running `block-v2-recursion-probe`. It loads public registry caps,
the expected statement and one node proof, never preprocessing LDEs or wallet
witnesses. Its root mode also requires all ten inner proof files to be absent.

```sh
cargo build --offline --release --features block-v2 --bin block-v2-artifact-audit
target/release/block-v2-artifact-audit root JOB_DIRECTORY INDEPENDENTLY_PINNED_PROFILE_HEX
# Optional intermediate-node diagnostic; this does not certify a two-level root:
target/release/block-v2-artifact-audit node JOB_DIRECTORY INDEPENDENTLY_PINNED_PROFILE_HEX node.0.0
```

The auditor checks the independent registry pin, then bypasses the outer metadata
comparison to test all 23 public-input slots directly against the native verifier.
It also tests 14 proof mutations and a changed preprocessing cap, plus four registry
policy mutations. A successful root audit must therefore report 38 native mutation
rejections, four policy rejections and no inner proofs loaded. This is executable
evidence of those checks, not a cryptographic security proof.

The new research decoder enforces a 2 MiB envelope, sequence-length limits before
allocation, a cumulative item budget, a nesting limit, canonical field/serialization
encodings and no trailing bytes. Its shape-only round-trip test is deliberately not
a valid proof. These protections do not establish a production network parser,
protocol version policy, rate limiter or complete denial-of-service analysis.
At height 524,288 the same proof shape with every field replaced by a
maximum-length canonical encoding occupies **2,014,183 bytes**, including the
eight-byte envelope magic, below the 2,097,152-byte limit. This conservative
serialization bound is not a measured recursive proof or a verification result.
The baseline runner used its earlier private-artifact reader. The retry runner and
the separate auditor use the bounded decoder; the live baseline was not hot-swapped.

## Reproduction

From `lattica-prover-p3/`:

```sh
env RAYON_NUM_THREADS=8 cargo test --offline --release --features block-v2 --lib block_v2:: -- --test-threads=1
env RAYON_NUM_THREADS=8 cargo run --offline --release --features block-v2 --bin block-v2-execution-probe
```

The probe proves an arithmetic/hash/bit-decomposition fixture at the full candidate
parameters, then verifies it in a fresh process using a reconstructed registered
program and expected public statement. It creates one temporary `LBV2EX01`
execution artifact in a private directory, passes **no inner proofs**, and deletes
the artifact afterward. This does not demonstrate root-only recursive verification.

Successful execution diagnostics print `execution_gate=PASS`,
`recursion_gate=NOT_TESTED_BY_THIS_PROBE`, and `final_block_proofs=0`, then **exit 2**.
Execution/verification failures exit 1. The internal fresh-process verifier exits
0 on a valid execution fixture. Do not treat the parent exit as a passed recursive
feasibility gate.

`LBV2EX01` is a local diagnostic envelope, not a wallet, network, recursive, or
consensus format. The CLI's artifact loader has byte/canonical-encoding checks;
it is not the production hostile-input parser required by the recursive plan.

## Resource and security boundaries

### Captured execution-only smoke result (2026-09-29)

The uncommitted working tree produced the following single sample using the probe
command above. These are **not wallet-wrapper, recursive-merge, block-capacity or
GPU measurements**; no transaction proof is verified by the fixture.

| Observation | Result |
|---|---:|
| Trace height / active rows | 64 / 56 |
| Main / preprocessing / permutation base columns | 102 / 105 / 15 |
| Quotient chunks / constraints / maximum degree | 16 / 243 / 8 |
| Retained-LDE payload lower bound | 5,718,016 bytes |
| Setup / proving / native verification | 15 / 45 / 23 ms |
| Execution envelope size | 789,558 bytes |
| Parent-process RSS high-water mark | 12,484 KiB |
| Fresh-process execution verification | PASS; no inner proofs loaded |
| Recursive proof / parent exit | NOT_TESTED_BY_THIS_PROBE / 2 |

The reported 127-bit figure is the **FRI/ALI estimate only**, including the AIR's
lookup constraints but not the separate lookup-argument or composition loss.
It is not a 127-bit recursive security result.

### Interpretation

Preflight counts retained LDE payloads for main, preprocessing, permutation,
quotient and randomization matrices. It rejects a lower bound exceeding 48 GiB
**before preprocessing allocation**. Passing the bound is not admission assurance:
compiler storage, source matrices, Merkle trees, salts, temporary buffers, concurrent
processes and allocator overhead still need a job-wide enforced budget. The probe
reports its parent-process RSS high-water mark, not a certified job-wide peak.

Parameters remain cubic Goldilocks challenges, hiding PCS, 128 binary-FRI queries,
blowup 16, cap height 6, four random codewords and 16-bit query grinding. A zero
single-table terminal avoids publishing witness-dependent per-table lookup totals;
it does not establish a complete zero-knowledge proof or a security audit.

Negative tests cover changed public inputs, changed preprocessing/program identity,
bad copy values whose local arithmetic still holds, altered permutation openings,
nonzero lookup terminals, unregistered degree, modulus-alias bit decompositions,
and changed authenticated Merkle data. Repeated proof bytes differ; that is a
randomness regression check, not a proof of zero knowledge.

## Earlier foundation verification (2026-09-29)

The regression counts below predate the new verifier/program tests. Current results
are recorded in the update at the end of this document.

- Final Rust library regression: **126 passed, 19 intentionally ignored**, 73.82 s:
  `env RAYON_NUM_THREADS=8 cargo test --offline --release --features block-v2 --lib -- --test-threads=1`.
- Targeted candidate suite: **26 passed, none ignored**, 3.81 s, using the test
  command under Reproduction. This includes a native-comparison grinding test.
- Zig Debug and ReleaseSafe suites passed with
  `env ZIG_GLOBAL_CACHE_DIR=/tmp/lattica-zig-cache zig build test`
  and the same command with `-Doptimize=ReleaseSafe`.
- ReleaseSafe FFI tests passed:
  `env RAYON_NUM_THREADS=8 ZIG_GLOBAL_CACHE_DIR=/tmp/lattica-zig-cache zig build test-ffi -Doptimize=ReleaseSafe`.
- `cargo check --offline --features block-v2,recursion,stream,gpu` passed; no v2
  GPU or streaming proof was run.
- Default ABI gate passed: exactly **12** `lattica_*` exports and **zero** recursion
  or candidate-v2 symbols. No production acceptance API was added.

These earlier checks validate the foundation components, not a completed recursive proof.

## Earlier verifier/program regression update (2026-09-29)

- Full Rust library regression: **136 passed, 19 intentionally ignored**, 89.16 s:
  `env RAYON_NUM_THREADS=8 cargo test --offline --release --features block-v2 --lib -- --test-threads=1`.
- Targeted machine/verifier/program tests: **22 passed, none ignored**:
  `env RAYON_NUM_THREADS=8 cargo test --offline --release --features block-v2 --lib block_v2::machine -- --nocapture --test-threads=1`.
  Includes real proof acceptance, statement/key/opening mutations, shape rejection,
  constrained cubic/selection proofs, and deliberately corrupted cap-path hints.
- Zig Debug, ReleaseSafe, and ReleaseSafe FFI tests passed with the commands above.
- All-feature/all-target compilation passed:
  `cargo check --offline --features block-v2,recursion,stream,gpu --all-targets`.
- Default ABI isolation passed: 12 existing exports, no recursion or v2 symbols.
- No two-level recursive proof, full-tree security result, or GPU/streaming v2
  benchmark is claimed by these checks.

## Compact-core regression history

After opcode/public-table compaction, shared trace columns, and verification-only
state were added, **23 targeted machine tests passed**, none ignored. This includes
both public-count banks and verification after dropping the prover. The new runner
built successfully, and its preparation stage verified all four distinct wallet
proofs. The follow-up regression passed **137 Rust tests, 19 intentionally ignored**
(96.97 s). All three allocator tests passed, including subprocess checks for the
hard ceiling, invalid settings, and mapping failure. That separate verification job
was capped at 3 GiB and peaked at 1.4 GiB. Zig Debug/ReleaseSafe/FFI tests,
all-feature/all-target compilation, and default ABI isolation also passed in a
separate 3 GiB-capped job (892 MiB peak). The proof runner's binary hash is unchanged.

The decoder/auditor follow-up passed **142 Rust library tests, 19 intentionally
ignored** (250.85 s with two Rayon threads). The 3 GiB-capped job peaked at 1.4 GiB.
This includes all five bounded-decoder tests and expanded constrained-verifier
mutation matrices: 12 batch-proof mutations and 10 uni-STARK mutations must fail
both native verification and execution of the unchanged verifier program. The
separate auditor's two tests also passed, including all 37 public/proof mutations
against a real small execution proof after dropping prover state. A subsequent
six-test decoder run also passed a real wallet-proof round trip (3.10 s); future
runner builds now use this bounded reader, without changing the live binary.
The subsequent seven-test decoder suite also passed the worst-case common-height
encoding test (3.16 s; 918.1 MiB compile/test peak under the same 3 GiB cap).
These component checks preceded the successful full-size recursive run above.

## Earlier CPU two-level verification pass (2026-09-30)

- Selected streaming candidate suite: **53 passed, 2 intentionally ignored**,
  270.06 s with two Rayon threads and NVMe scratch under a 3 GiB auxiliary RAM
  cap. This is a test-suite duration, not a proving benchmark. The earlier
  selected-profile run passed the same suite in 60.20 s under different scratch
  conditions; neither is an end-to-end block timing.
- Separate artifact-checker unit tests: **2 passed**, including native mutation
  rejection against a real execution proof.
- All-feature/all-target compilation passed. Final format checks, shell syntax,
  Zig Debug/ReleaseSafe/ReleaseSafe-FFI tests, and default-ABI isolation passed.
  Two module-order formatting differences were fixed before the final gate pass;
  no cryptographic behavior or proof profile changed.
- Default static library: exactly **12 existing exports**, no recursion or v2
  symbols. The final gates service peaked at 699.3 MiB with zero swap.
- The already completed non-streaming library regression was **145 passed,
  19 intentionally ignored**; no separate full rerun is claimed here.
- After the pipeline, root-only verification passed again in 57 ms, and the
  separate checker passed in 219 ms with all 38 native and four policy mutations
  rejected. Both loaded zero inner proofs. Root and binary hashes were unchanged.

The 3 GiB-capped candidate/auditor test service peaked at 2 GiB. Its first combined
check stopped at formatting, not a test failure; the corrected final gate service
completed successfully. Local logs are `/tmp/lattica-final-recursion-checks.log`
and `/tmp/lattica-final-recursion-gates.log`.

## Common-height padding continuation (2026-10-01)

The [padding evidence](evidence/block-v2-padding-2026-10-01.json) records a new
CPU-only research runner that extends the preserved level-three/count-eight root
to level six. It proves real empty subtrees at levels three, four and five, then
three ordered merges. Both source and padded commitments are externally pinned
and independently derived from the eight public inputs by the native Zig tool.
No wallet proof or private witness is needed by this extension; the original
verified source bundle is preserved unchanged.

The runner rejects implicit context, wrong padded roots, unexpected/nonregular
artifacts, noncanonical encodings, and overwriting existing outputs. The extended
CPU auditor has an explicit `root-padded-eight` command and requires exactly the
level-six root plus the height and three keys. Its existing `root-eight` command
and historical decoding remain unchanged. The one-shot controller retains the
exclusive lease, aggregate 48 GiB/no-swap slice, 44 GiB worker bound and 120 GiB
spill cap, with durable attempts and no automatic retry. It must delete its six
local inner artifacts before a separate CPU root-only audit.

Validation passed **8 runner and 10 auditor tests in each of default/wide
builds**, **8 native Zig tests**, and **9 controller tests**. Seven preserved
roots passed compatibility replay with **35 input-file hashes** unchanged.
Two corrected test-fixture/exception-expectation failures remain recorded.
The full-strength proof trial now **passes** this padding case. Three empty
proofs and three merges produced a **1,683,948-byte** level-six/count-eight root
in **872.198 seconds (14.537 minutes)** of recursive-command time. This extension
starts from the previously proven subtree: its timing excludes wallet proving,
key registration and the earlier seven proofs. Empty and merge commands took
**434.770 / 437.428 seconds**; the final merge alone took **122.209 seconds**.
The complete controller service took **873.827 seconds**.

Peak proving-worker memory was **42,950,414,336 bytes**, controller peak
**37,670,912 bytes**, zero swap, and peak mapped spill **34,288,652,288 bytes**.
Mapped spill is not additional RSS; separate service peaks are not a measured
simultaneous combined peak. The configured aggregate limits remained enforced.
After six local inner artifacts were removed, fresh CPU root verification and
the separate five-file artifact audit passed. The auditor rejected 38 native,
four registry-policy and two external-statement mutations with zero inner proofs
loaded. All 31 post-run implementation, log, source, job and export hashes matched;
the source subtree bundle is unchanged. No retry occurred.

No AIR, registry, codec, C ABI or activation changed. This demonstrates real
common-height empties at levels three through five and this count-eight padded
tree only—not odd counts, all padding shapes, a full-count block, repeated
performance or either latency target. The full three-merge command exceeds
three minutes even though its final merge is below that threshold.

## Resident GPU LDE/commitment executor — component validation

The [resident-pipeline evidence](evidence/block-v2-gpu-lde-pipeline-2026-10-01.json)
records the first real execution slice beyond the allocation planner.
`gpu_hash::coset_lde_commit` replans under the candidate engine mutex, allocates
through the existing shared accounting, performs whole-height column-tiled inverse
NTT/coset scaling/forward NTT, and feeds resident results into one continuous
matrix-then-salt sponge. Partial tiles do not pad or flush the sponge. Output
matrices use physical bit-reversed row order; the existing retained-tree machinery
builds caps and serves paths. CPU consumers still require explicit host LDE
readback. This is not a claim of eliminating host matrices or all PCIe transfers.
The first executor uses synchronous transfers and stage completion, including
when the enclosing engine has its two-slot overlap mode configured; both slots
remain accounted. No new transfer-overlap gain is claimed.

The final planner-only validation passed six planner and eight existing accounting
tests, without running device kernels. The executor's targeted native validation
then passed **17 tests** with **13 hardware cases ignored**, no compiler warnings,
and zero swap. The first compile's two invalid matrix test-fixture constructions
were corrected and its source/log retained. All **13 explicit GPU tests** subsequently
passed on the RTX 5080, including three new executor tests and ten existing GPU
regressions. CPU comparisons check every LDE value, leaf/cap construction and
Merkle path; cases cover partial column/salt tiles, unequal input heights with
equal output heights, multiple NTT stage groups and varying coset shifts.
Upload/readback accounting is checked against actual input, salt, twiddle,
matrix and cap sizes. Injected pending-kernel errors and unwinds verify queue
draining before transform/tree reservations are released; later work recovers.

These are bounded component cases, not the full-size recursive proof geometry.
The 10.796-second GPU validation service is **test-suite time, not proving
performance**. Its peak cgroup memory was 863,617,024 bytes with zero swap.
The broader preserved-binary suite passed **244 tests** (including the 17 targeted
native tests), with **60 ignored**, under the same 3 GiB/no-swap service cap.
Its first attempt passed 243 and failed one legacy streaming test because that
path selected the empty AMD OpenCL platform. The unchanged binary passed with
NVIDIA explicitly selected (`OCL_DEFAULT_PLATFORM_IDX=2`,
`OCL_DEFAULT_DEVICE_TYPE=GPU` on this host). This suite is not CPU-only: that
legacy streaming test invokes GPU arithmetic. Both attempts remain in the evidence.

At that checkpoint the API took explicit per-attempt evaluations and salts and
was not connected to the hiding PCS. The adapter milestone below follows that
historical component record; its original source pins are not rewritten. The
existing wallet-proof GPU regression exercises the prior hashing path, not this
new executor. No AIR, proof profile, codec, C ABI, default backend, or activation
changes.

## Resident hiding-PCS adapter — small-proof validation

The [adapter evidence](evidence/block-v2-gpu-resident-pcs-2026-10-01.json) records
the next integration slice. `CandidatePcs` now dispatches between the existing
reference PCS and an explicitly constructed resident attempt. The adapter
replaces main, public-preprocessing, and randomization commitments only. Quotient
generation, openings, periodic evaluation and verification still delegate to the
pinned upstream hiding PCS; independently seeded quotient fusion remains optional.
The existing proof and prover-data types are unchanged.

An active resident clone shares the entire upstream attempt, not a copied seed.
The adapter and upstream PCS consume one hiding stream and one input-MMCS salt
stream, preserving the order of masks, random codewords and salts. Fresh proving
configurations still draw independent CSPRNG seeds. Public preprocessing retains
its existing deterministic setup convention and must never prove a witness.
Matrix collection is bounded, geometry/admission precedes mask and salt draws,
and unsupported modes fail closed. A per-commit host-output allowance is not a
substitute for the combined 48 GiB worker-memory gate.

The recursion research runner can explicitly initialize
`LATTICA_V2_GPU_RESIDENT_LDE=1` after `LATTICA_V2_GPU_HASH=1`; retained trees
(`LATTICA_V2_GPU_RETAIN_TREES=1`) are mandatory. Merely compiling GPU support or
setting the environment does not select the library backend. Default/wallet
configuration does not select resident commitments even after research proving
selection. The resident switch is independent of `LATTICA_V2_GPU_PIPELINE`, which
controls the older transfer-overlap mode; resident transforms still use synchronous
transfers. The original grouped-eight runner remains deliberately CPU-only. The
separate GPU grouped runner/controller is qualified at the workflow/key level in
the following checkpoint; it does not change the CPU runner's gate.

The final targeted native slice passed **17 tests** in two disjoint filters and
the GPU-enabled recursion runner passed compilation, without warnings. The
preserved RTX 5080 binary passed **17 explicit GPU tests**: four adapter tests and
the prior thirteen executor/GPU regressions. An isolated selection subprocess
also passed. Adapter coverage includes every committed LDE value, cap, sampled
opening/path, preprocessing and randomization commitments, upstream quotient
masks/commitments after resident draws, and subsequent operations through an
active clone. Failed shape/admission checks leave masks and salts unconsumed.
Four small full-strength cubic proofs (fusion off/on, original/cloned handles)
were decoded and verified through the original CPU PCS; altered public statements
were rejected and commitments advanced across clones.

The broader preserved GPU-feature binary passed **248 library tests / 64 ignored**,
including the targeted native cases. NVIDIA was explicitly selected for the
legacy streaming GPU test, so this was not a CPU-only run. The separate non-GPU
default-profile build passed **223 tests / 30 ignored**. CPU and GPU recursion
runner checks, the no-feature library check, all-features/all-targets, and wide
CPU-only all-targets compilation passed without warnings. Source archives,
binaries and logs are pinned separately from the earlier executor milestone.
The initial compile failure and an intermediate passing revision's two corrected
must-use warnings remain recorded rather than being overwritten.

These are small proof-system integration tests, not recursive block proofs,
performance qualification, or a complete-tree soundness/zero-knowledge review.
The final GPU suite took **11.741 seconds**, with a **462,458,880-byte** peak
cgroup memory and zero swap; that duration is **not a proving benchmark**.
At this adapter checkpoint, full-size independently registered key equivalence,
real compact recursive proofs, pruning and CPU replay, matched end-to-end
measurements, the local DAG, full64/deadline qualification and host integration
remained open. The next checkpoint closes only workflow validation and resident
key reproduction.

## Separate GPU grouped workflow and resident key reproduction — 2026-10-01

The [workflow evidence](evidence/block-v2-gpu-grouped-workflow-2026-10-01.json)
records a separate `block-v2-gpu-grouped-probe` binary and
`scripts/block-v2-gpu-grouped-trial.py` controller. Shared grouped operations
retain the existing artifact, external-statement, registry, wrapping, merging,
pruning and verification rules. The CPU runner still rejects GPU-enabled builds
and nonzero/invalid resident selection before work; no CPU gate was weakened.
Preparation, reference checks, pruning, root verification and final auditing use
the preserved CPU tools. GPU workers admit only registration, wrapping and merges.

The controller requires explicit `retained` or `resident` backend selection,
GPU index/UUID, quotient-fusion mode, source/binary paths and externally pinned
profile/chain/root. Retained trees are required and transfer overlap is disabled.
It imports the exact hash-pinned frozen helper bytes without changing helper
policy. Both the grouped helper and accounting script remain unchanged.

Registration starts from public wallet proofs and height, not copied keys. Each
GPU-generated key must immediately match the independent CPU key. Proving is
admitted only against completed registration evidence bound to the same backend,
device, fusion mode, external statement and implementation pins. Every completed
stage's actual log/hash, parsed telemetry and VRAM evidence are rechecked. Replay
also binds the device index to configuration. An attempted record is durable
before launch or artifact writes; an interrupted/failed attempt is never retried
automatically. The original failure is saved before cleanup, so a failed stop or
observation cannot erase it or authorize another attempt.

The complete trial owns an exclusive lease. A <=3 GiB/no-swap controller and
44 GiB/no-swap worker share the 48 GiB slice; workers have finite runtimes,
120 GiB spill limits, and `BindsTo`/`After` ties to the controller. Each GPU worker
validates its actual accounting-bound cgroup before device initialization. Stage
logs are bounded to 64 MiB and VRAM evidence to 8 MiB. NVIDIA sampling scopes PIDs
to the exact worker cgroup and descendants, checks the expected UUID and sums
memory against 12,288 MiB. Missing positive samples, three consecutive query
failures or an observed excess fail closed. This sampled watchdog is **not an
instantaneous driver-enforced VRAM quota**. Internal managed-device admission
remains 8 GiB plus a 4 GiB driver reserve.

Validation passed **30 native controller tests**, **18 actual executable rejection
checks**, and **three synthetic service-lifecycle checks**. The lifecycle tests
observed live bounded Python workers and tested nonzero exit propagation,
observation-failure cleanup and abrupt controller death; they did not initialize
a GPU or prove anything. The first executable test failed only because an
expected message omitted the word "the". Both builds had succeeded; the corrected
assertion passed against the preserved binaries in a new validation service.
The build archive and corrected qualification archive are separately preserved.

On the RTX 5080, all three full-size compact-profile resident preprocessing keys
then matched the independent CPU registration byte-for-byte (2,048 bytes each).
The surviving independent reproduction fixture supplied the exact eight public
wallet proofs; the primary fixture's wallet artifacts had already been pruned.
All 12 surviving inputs match both historical registration manifests. Quotient
fusion remained disabled for this first comparison.

| Registration stage | Elapsed seconds | Peak worker RAM bytes | Peak mapped spill bytes | Sampled VRAM peak MiB |
|---|---:|---:|---:|---:|
| Key 1 | 82.837 | 15,429,636,096 | 14,814,298,112 | 4,934 |
| Key 2 | 75.308 | 14,807,220,224 | 14,529,081,344 | 4,934 |
| Key 3 | 84.685 | 15,790,399,488 | 15,099,510,784 | 4,934 |

All workers reported zero swap; reference and final CPU registration checks
passed. The controller service took 244.444 seconds. These are registration
measurements, not recursive-proof timings; RAM and mapped spill are overlapping
accounting scopes and must not be added together. Key 1's host decode/scatter
counter was 65.916 seconds versus 0.425 seconds of device transforms, motivating
further profiling after complete-proof validation, not a speedup claim.

At this workflow/key checkpoint, real compact-eight recursive proving, local
pruning and CPU root-only replay, retained-backend key reproduction, and at least
five alternating matched backend pairs remained required. The original repeated series remains separately 2/5
complete with its own shared-fixture pruning/replay obligations. Neither this
workflow nor key equality qualifies A3, full64/post-seal deadlines, complete-tree
soundness/ZK, a local DAG, host integration or production activation.

## First complete resident-GPU grouped proof — 2026-10-01

The [resident proof evidence](evidence/block-v2-gpu-grouped-resident-proof-2026-10-01.json)
records one full-strength compact eight-wallet proof using the separately
qualified GPU controller. The seven recursive proofs completed in **842.100
seconds (14.035 minutes)**, including in-process preprocessing setup. The complete
controller took **844.647 seconds**. Separate wallet proving and key-registration
work are excluded, and this is not a measured complete post-seal path.

| Stage | Recursive command seconds | Peak worker RAM bytes | Peak mapped spill bytes | Sampled VRAM peak MiB |
|---|---:|---:|---:|---:|
| Four grouped wrappers | 485.648 | 39,912,570,880 | 31,386,120,192 | 5,960 |
| Three merges | 356.452 | 40,276,992,000 | 31,671,332,864 | 5,960 |

All workers reported zero swap. Worker RAM and mapped-spill scopes overlap;
do not add them. The shared 48 GiB/no-swap slice and unchanged VRAM/scratch gates
remained enforced. Final merge time was **84.524 seconds**; quoting that alone as
post-seal finalization would omit required preceding work and the host path.

The **1,683,948-byte** level-three/count-eight root passed local verification
after deleting **14 local inner artifacts**, and then a separate preserved
CPU-only auditor accepted the five-file exported bundle with zero inner proofs
loaded. It also rejected **38 native mutations**, **four registry-policy cases**
and **two expected-statement-policy cases**. The auditor received GPU hashing
enabled and an invalid GPU device index while resident selection remained zero;
it performed CPU-only verification. The independent public reference fixture is
deliberately retained for comparison, so complete shared-fixture pruning is not
claimed. Controller and worker services were confirmed terminal after acceptance.

The wrapper-stage GPU counters recorded **153.802 seconds** of host decode/scatter
and **1.940 seconds** of device transforms. Inclusive CPU quotient spans were
approximately 28.6–38.3 seconds per wrapper; these nested spans must not be added
to one another or to device durations to derive elapsed time. The pipeline still
materializes host LDE matrices; this is not a fully device-resident prover.

This single proof closes the first real resident recursive-integration check,
not a speedup series. Retained-hash key reproduction and the matched control proof
were the next gates, followed by at least five alternating matched pairs before
performance claims. The compact CPU observation of 19.440 minutes is historical,
not the matched retained-hash control. Full64, general padding/odd/mixed/issuance,
cold and complete post-seal deadlines, the local DAG, complete-tree soundness/ZK,
host integration and production activation remain unqualified.

## First matched GPU backend pilot — 2026-10-01

The [matched-pilot evidence](evidence/block-v2-gpu-grouped-matched-pilot-2026-10-01.json)
compares the preceding resident run with a subsequent retained-hash control on
the same eight public wallet proofs, CPU-registered caps, GPU, binaries/source,
external statement, fusion-off setting and resource gates. All three retained
keys matched the same independent CPU reference; all retained stages reported
zero resident-LDE commits. Both complete runs passed local pruning and the
unchanged CPU-only auditor's root and adversarial checks. Shared reference
pruning is still deferred until the comparison boundary.

| One matched observation | Retained-hash control | Resident LDE |
|---|---:|---:|
| Four-wrapper command | 343.973 s | 485.648 s |
| Three-merge command | 289.250 s | 356.452 s |
| Total recursive-command time | 633.223 s / 10.554 min | 842.100 s / 14.035 min |
| Final merge alone | 81.116 s | 84.524 s |
| Root bytes | 1,683,948 | 1,683,948 |
| Peak worker RAM bytes | 40,556,945,408 | 40,276,992,000 |
| Peak mapped spill bytes | 31,671,332,864 | 31,671,332,864 |
| Sampled worker VRAM peak | 3,910 MiB | 5,960 MiB |
| Swap | 0 | 0 |

Resident proving took **208.877 seconds longer (32.986%) in this pair**. This is
an observed difference, not repeated qualification or a population estimate.
The order was resident then retained; at least five alternating matched pairs
are still required before speedup claims. This is separate from the older 2/5
single-versus-grouped series, whose unfinished obligations are unchanged.

Across the two workers, resident mode uploaded **93.062 GiB** and downloaded
**95.006 GiB**; the retained control uploaded **182.125 GiB** and downloaded only
**6.344 MiB**. Upload savings therefore did not produce an end-to-end transfer
reduction. Resident host decode/scatter counters totalled **283.886 seconds**,
versus **0.706 seconds** for control. Device transforms totalled **3.440 seconds**
in resident mode. These counters identify a data-movement/layout problem to
investigate; they do not establish a standalone kernel speedup or an additive
breakdown of all proving time.

**Decision:** retain both backends as explicit research modes and do not promote
resident performance. Keep retained hashing as the comparison control. Prioritize
bounded host readback/layout work and GPU quotient/opening/FRI integration that
can avoid materializing and rereading complete LDE matrices. Preserve CPU proof
compatibility, fresh per-attempt randomness, one AIR, full security parameters,
and all RAM/VRAM/scratch gates; do not improve a result by weakening them.
After changing the pipeline, requalify keys, proof replay and matched performance.
Neither backend qualifies the cold64 or complete post-seal target, and this pilot
does not authorize production activation or a production coordinator.

## Remaining gates

The in-circuit verifier, wrapper/empty/merge program builders, common-height demo
registry, real two-level proving, root-only verification after inner-file deletion,
and native root mutation checks are now demonstrated. The following remain:

1. Extend the proven count-eight and controlled count-three/level-six cases to
   remaining counts, irregular shapes, mixed transactions and adversarial statements.
   The earlier padding trial covers empty levels three, four and five; the new
   count-three arrival trial also exercises levels zero and two. This is not
   general padding, full64 or mixed-type qualification.
2. Establish depth-six/64-transaction correctness, repeated full-strength resource
   measurements, and both cold and incremental latency gates. Four-transaction
   success does not establish those gates.
3. Complete separate lookup/composition/hash and zero-knowledge review, including
   program-key approval, transcript assumptions, and the maximum-size tree.
4. Add HTLC/issuance coverage, reviewed wallet/aggregation/root APIs, hostile-input
   service hardening, coordinator recovery/backpressure, and host-node integration
   before any explicit production activation.

Depth-six/64-transaction feasibility, GPU/streaming performance optimization,
HTLC/issuance, coordinator/node integration, and production activation remain later
gates. Nothing here changes historical v1 verification or adds a production ABI.


## CPU supervisor journal checkpoint (2026-10-02)

The subsequent [native supervisor evidence](evidence/block-v2-cpu-supervisor-2026-10-02.json)
adds Linux process observation and an experimental per-lease service driver
inside the approved Plonky3 backend exception. This is **not a completed
production supervisor** and does not supersede the earlier pinned actual-worker
proof measurements with a new performance claim.

The local LVOSR001 record is bounded to 32 KiB and reuses the existing
owner-locked, checksummed, fsynced atomic snapshot implementation. It binds the
authoritative lease key/resources, task/executable/launch paths, launch directory
device/inode, executable fingerprint, timeout and execution-bound LVCPU002
token. It records dispatch boot identity, optional observed process birth/unit
invocation/cgroup identity, and monotonic cancellation/revocation/stop state.
The legacy inline token remains supported on its original path; this supervisor
requires the execution-bound form.

### Ordering and stop authority

Preparation must precede task creation, after the scheduler's durable resource
reservation. Immutable task publication/binding precedes dispatch. The dispatch
snapshot is durable **before** spawning the sole launcher; a spawn error never
returns the journal to a retryable state. Exact process observations are
persisted when captured.

Cancellation is journaled first, then the launch permit is durably revoked,
before any stop request. A stop receipt requires the idle gate and one of:

- No dispatch ever recorded under the exclusively owned journal.
- A different kernel boot, so prior-boot work cannot remain alive.
- The exact observed process has exited and its exact cgroup is empty or removed.

The runtime must own exactly one supervisor journal/launch store per lease and
must not dispatch outside that journal or reuse its service name. Global
uniqueness/admission orchestration is not supplied by this per-lease component.
Local checksums/fingerprints do not authenticate malicious same-UID software.
Systemd has no compare-and-stop primitive; the exclusive namespace is a trust
assumption, and an observed replacement invocation is rejected.

| Persisted state | Recovery behavior |
|---|---|
| Prepared or bound, never dispatched | Cancel/revoke and acquire the gate before issuing a never-dispatched receipt. |
| Dispatch requested, no captured identity, same boot | Attempt exact observation; otherwise quarantine and retain the reservation. |
| Exact identity captured | Use pinned live handles or persisted boot/birth/cgroup identity; confirm OS quiescence. |
| Worker stopped | OS-only receipt; independent CPU verification and current-attempt fencing still apply. |

A missing unit, a completed launcher helper, a timeout or an available lock is
not standalone exit evidence. Conversely, a known process/cgroup's authoritative
kernel exit evidence does not depend on systemd retaining its invocation fields.
The receipt cannot accept a proof or drain coordinator verification. Recovery
still needs the separate authoritative worker-and-verifier reconciliation
required by Recovery::resume.

### Validation scope

The preserved lattica-v2-supervisor-native-20261002-b.service run passed:

- 105 native execution tests, including eight new OS-observation/parser/kernel
  checks and ten new supervisor checks.
- Five abrupt subprocess exits at persisted journal boundaries.
- Eight explicit pinned CPU fixture checks, including task preparation, binding,
  reopen and the separation between OS stop and result verification.
- One explicit user-service absence check: a never-started, unique unit and an
  idle gate cannot release a same-boot uncertain launch, including after reopen.
- CPU worker build, narrow/default/all-feature/all-target checks, formatting,
  whitespace checks and exact archived-source comparison, with no compiler warnings.

The run used the exclusive existing experiment controller, offline builds, one
build job, Rayon eight, a 3 GiB memory cap, zero swap and GPUs disabled. It finished
in 172.438 seconds wall / 170.665 seconds CPU, with a rounded systemd peak of
1.6G. No worker service or large proof was launched by these new tests. The prior
failed run is preserved: its supervisor fixture incorrectly attached an empty
candidate, which the scheduler correctly rejected; the corrected fixture uses
a nonempty synthetic tree.

The earlier actual WrapPair result and fresh CPU replay remain evidence for
their own pinned worker binary. This native-only checkpoint did **not** qualify
the supervisor's actual dispatch, cancellation or restart path; the subsequent
live checkpoint below covers selected cases. The
frozen experiment plan and three harness/accounting scripts retain their
previous SHA-256 hashes. No default verifier, historical proof format, C ABI or
production activation changed.

### Next development effort and decision gates

1. **Qualify the real supervisor lifecycle.** Run actual worker dispatch,
   observation, normal completion, cancellation, OOM/timeout and coordinator
   crash/restart cases. Resolve or explicitly manage the unseen-launch window:
   a worker that finishes before capture can currently leave its same-boot
   reservation quarantined indefinitely. Do not replace this with a
   missing-unit or elapsed-time release rule.
2. **Close physical and aggregate resource accounting.** Reserve launch-record
   capacity before issue/revoke, enforce physical scratch quotas, enforce unique
   per-lease admission, and add reference-aware task/launch/artifact retention.
   The in-memory reservation and worker spill ceiling are not a disk quota.
3. **Cover the complete arrival-driven pipeline.** Exercise executable-driven
   SingleWallet, Empty and Merge operations, all transaction types including
   issuance/HTLC, host eligibility and reorg/cancellation fences. Reuse completed
   immutable subtrees as public proofs arrive; no aggregator wallet witnesses
   or individual transaction proofs in blocks.
4. **Make a measured performance decision.** Keep retained hashing as the GPU
   control, remove redundant host materialization/re-upload, then run at least
   five alternating matched comparisons. The existing resident/openings pilot
   regressed from 607.112 to 686.046 seconds for eight wallets while transferred
   bytes grew from about 195.6 to 454.7 GB. It changed two mechanisms at once:
   it is not evidence that GPUs generally lose. Do not repeat that unchanged pilot.
5. **Require end-to-end acceptance before activation work.** Demonstrate 64 total
   transactions including issuance at the 12-minute cadence, cold proving at
   most 600 seconds, and complete post-seal finalization at most 180 seconds.
   Include dispatch/queueing, remaining recursive work, CPU root verification
   and durable publication. Retain one root at most 2 MiB and aggregate
   RAM48/VRAM12/scratch128 GiB. Full-tree soundness/ZK review and host integration
   remain separate requirements even if timing passes.

The prior two-transaction process execution-to-acceptance result was 178.290
seconds, excluding fixture loading/admission/task publication. That is not a
64-transaction or complete post-seal result and gives no basis to claim the
production latency gates are met. Keep the cubic Goldilocks field, q128,
blowup16, cap6, four random codewords, PoW16, fresh CSPRNG and strict CPU
verification fixed throughout; no weakened profile, curve/SNARK wrapper,
multiple-root workaround or production activation is authorized by this
checkpoint.


## Live supervisor cases and fresh proof (2026-10-02)

The [live supervisor evidence](evidence/block-v2-cpu-supervisor-live-2026-10-02.json)
now exercises actual worker services through the supervisor API, including
reopening its persisted identity before stop confirmation. The latest preserved
native run passes 105 native tests and nine explicit checks, with no compiler
warnings; all six live stages pass under the exclusive existing experiment
controller.

| Case | Observed result | Scope limitation |
|---|---|---|
| Check-only worker | 1.183 s dispatch-to-handling; no proof; persisted identity and exact kernel stop confirmed. | Input checking is not proof generation. |
| Cancel active prover | Captured process confirmed live before revoke/stop; 0.771 s dispatch-to-handling; no result. | Not a host reorg or a concurrent-verifier cancellation test. |
| Coordinator exit | Intentional process exit 73 after durable worker identity and guard entry, without Rust drops. | The coordinator has not begun result verification. |
| Fresh-actor recovery | Public inputs revalidated; exact old worker stopped before epoch-2 rebase; resources released and historical candidate eligibility not revived. | Does not qualify recovery while CPU verification is concurrently active. |
| Actual WrapPair | New full-strength two-transaction proof, owner reopens result and independently verifies before durable acceptance/export. | Level one/count two, not a 64-transaction block. |
| Fresh CPU replay | Exported proof accepted; wrong ordering and mutated proof rejected. | Replay uses the retained public wallet fixtures; not archive-pruning qualification. |

Two preliminary runs are preserved. The first exposed a test mistake:
systemd can report a requested SIGTERM stop as success. The corrected test
requires that the exact captured process is live before cancellation and that
the process/cgroup stop receipt succeeds; helper status is only diagnostic.

The second passed check/cancel but failed during identity capture with a
permission error, before the planned coordinator exit. Its journal had
persisted dispatch, but not observed identity, and retained the reservation.
The precise denied syscall was not logged. An exec-startup barrier
(Type=exec) and stage-specific capture diagnostics were added; the subsequent
run passed all selected cases. This is evidence for the mitigation, not
conclusive localization of the original permission error or proof that every
startup race is resolved. Unseen same-boot launches still fail closed.

### Actual proof and resource evidence

The raw pair proof is **1,683,948 bytes**. Dispatch through owner acceptance and
export took **193.623 seconds**, excluding fixture loading, admission,
supervisor preparation, and task/launch publication/binding. Worker-reported
input verification was 412 ms and proving was 191,577 ms. This two-transaction
path already exceeds 180 seconds; neither the complete post-seal gate nor the
64-transaction cold gate is demonstrated, and no speedup is claimed.

The worker's own structured systemd journal reports:

- Peak RAM: 42,604,490,752 bytes (39.68 GiB).
- Peak swap: zero.
- CPU time: 1,108.356684 seconds.
- Wall time: 192.447 seconds, as reported in the systemd consumption message.
- Worker-reported spill peak: 34,003,439,616 bytes (31.67 GiB).

The journal's invocation ID matches both the persisted worker identity and a
live systemd snapshot. Coordinator ExecStopPost accounting is stored separately
and must not be mistaken for the prover's memory use. The worker had a 44 GiB
RAM cap, zero swap, eight CPU threads/800% quota and TasksMax16, within the
48 GiB aggregate slice. Scratch reservation was 120 GiB on NVMe; the free-space
gate and spill limit are still **not** a physical disk quota.

The worker log reports 65.061 seconds of setup with a preprocessing-cache miss
and 123.070 seconds in registered proving plus internal verification. The
existing recursive prover already checks exact program equality before
in-process preprocessing reuse. Profile the setup/cache path as a concrete
optimization candidate alongside GPU transfer work; do not assume all setup
time is reusable or claim an unmeasured saving. Any cross-process cache must
preserve program/registered-cap identity, immutable public preprocessing,
fresh proof salt/hiding randomness, and independent CPU verification.

### Remaining qualification

The service lifecycle is no longer native-test-only, but a complete durable
runtime is still unproven. Remaining work includes unseen/delayed dispatch
reconciliation, concurrent CPU-verifier drain/recovery, OOM/timeout and other
crash boundaries, repeated lifecycle trials, globally unique per-lease
admission, reserved revocation capacity, physical scratch enforcement and
reference-aware retention.

Actual SingleWallet/Empty/Merge generation, arrival-driven host eligibility,
issuance/HTLC coverage, matched GPU improvements, full64 timing/resource gates
and full-tree soundness/ZK review remain required. All security parameters,
the one-root/public-proof-only design, historical verifier/ABI paths and the
production-disabled state remain unchanged. The frozen plan and three
experiment/accounting scripts retain their prior hashes; final live-service
inventory was empty. No commit was made.
