Persistent local pool and delivered-throughput campaigns

Development checkpoint: coordinator costs and isolated request binding (section 9.309)
Bounded optimized CPU diagnostics complete and recover ten two-wallet trials and
three single-pair completions in 64-wallet/63-job DAGs. They generate no proofs,
apply no block and consume no funded slot. Metadata setup is about 5.5 ms;
numerical verification 29 ms; artifact hashing 44.6 ms. Preparing a request in
the larger DAG takes about 181 ms. Snapshot encoding is small; durable clock
persistence remains enabled. These are diagnostic costs, not delivered speedups.
An isolated 882-file candidate retains each immutable assignment/request binding
through collection, while checking every returned packet and independently
verifying its proof. It is not yet installed in the shared source tree.
Two complete selected test runs report 138 passed / 14 ignored, but overlap from
another session excludes their resource qualification. Short serial batches have
qualified 123 tests at this checkpoint. The resource conflict recurs across three
goal turns. Only this candidate's two idle orchestration processes are stopped;
all completed checks remain intact. Resume the unfinished batches when the other
session releases the validation resources. Full-size replay, CPU/GPU all-target
checks, integration and fresh production-image qualification remain pending.
The accepted ten-block height-19 history, production images, timing approvals,
original budgets and all full-GPU qualification gates remain unchanged.
Continuation (crate relative):
benchmark-results/gpu-bound-assignment-result-20261016/control/continuation-03.json
Diagnostic results (crate relative):
benchmark-results/gpu-coordinator-cost-review-20261016/cost-01/summary.json
benchmark-results/gpu-coordinator-cost-review-20261016/cost-scaled-01/summary.json

Current delivered checkpoint: owned-completion native delivery (section 9.308)
The rebuilt images deliver a fresh block from slots 1280-1343: 64 GPU wallet
proofs and 63 GPU recursive proofs, with independent CPU wallet/graph/history
verification and durable native application. Accepted: 48 user transactions and
16 issuance transactions. History: ten blocks at height 19. Root: 1683948 bytes.
Prefix phases complete 22, 20 and 14 jobs. With only 35363 ms left, the third
worker defers before sealing because admission requires 105000 ms. It drains;
a replacement admits the 75000 ms continuation reserve and completes seven jobs.
Workflow: 587303 ms, leaving 12697 ms. Sealing: 503968 ms into that clock.
Post-seal through application: 81165 ms. Campaign including final chain audit
and cleanup: 602.594 seconds. The latter has different deadline endpoints.
Coordinator job intervals total 397807 ms; recorded worker timers total
333372 ms. The remaining 64435 ms gap is 5985 ms smaller than the prior run.
Full workflow time is 2671 ms shorter. This is not exclusive cost attribution,
a matched speedup or sustained-throughput qualification. Margin remains narrow.
All required stages report OpenCL. Native builds and runtime share the same
880-file source; independent audits pass without hard memory-limit/OOM events
or service/lease overlap. The original resource/deadline/cadence limits remain.
Next native slots: 1344-1407. Unused funded slots: 8096. At least 1504 more slots
are needed for a separate fresh 150-root campaign before controls.
Next: attribute remaining costs, recover adequate margin, matched delivered
controls and the outstanding full-GPU qualification gates.
Metadata/continuation (crate relative):
benchmark-results/gpu-owned-completion-workflow-20261016/control/current-validation-01.json
benchmark-results/gpu-owned-completion-workflow-20261016/control/continuation-02.json
Evidence (repository relative):
docs/evidence/gpu-owned-completion-workflow-2026-10-16.json

Preceding checkpoint: owned-completion production qualification (section 9.307)
The frozen 880-file source now has rebuilt CPU/GPU static libraries, CLI images
and host bridges at opt-level 3, one codegen unit and thin LTO. A matching
GPU-enabled correctness harness is rebuilt at opt-level 1.
32 CPU interface tests pass (one GPU-only skip), as do all 36 GPU interface
tests. Fresh proofs: five wallets, eight native recursive proofs, two retirement
finalizers and 17 CLI calibration proofs. Total: 32. All required 15 wallet / 16
recursive stages report OpenCL. The new pool completion path accepts two roots;
separate CPU processes verify nonempty outputs after worker exit.
14 fresh timing classes pass independent approval. The CPU CLI verifies all
63 graph nodes and 64 archived wallets. A duplicate-order preflight is retained;
a distinct new candidate passes. No proving worker or funded slot was used by
that rejected preflight. A stale service-summary archive count is independently
corrected during packaging, retaining its original report.
No new native block or funded slots are consumed. Accepted history remains nine
blocks at height 18; next native slots are 1280-1343, with 8160 unused slots.
Next: fresh delivery with the 75000 ms continuation reserve and measured margin.
Original resource/deadline limits and all remaining full-GPU gates remain.
Metadata/continuation (crate relative):
benchmark-results/gpu-owned-completion-native-20261016/control/current-validation-01.json
benchmark-results/gpu-owned-completion-native-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-owned-completion-proving-2026-10-16.json

Preceding checkpoint: owned local node completion (section 9.306)
Pool completion now consumes the immutable bytes authenticated by its local CPU
verifier through artifact publication and DAG acceptance. Two repeated artifact
digest passes are removed. Detached ticket/buffer and existing-file checks remain,
as do worker/verifier ownership, cancellation, expiry, job/duplicate fencing,
durable publication and resource release. No proof or wire format changes.
159 selected CPU regressions pass, including six new completion cases. One
separate full-size CPU test passes, replaying an archived pair twice through
verification, durable completion and recovery, with truncation and wrong-job
rejection. Total: 160 passing test executions. CPU/GPU all-target checks pass.
An optimized read-only probe measures a median 44.078 ms per 1683948-byte node
digest across ten samples. This is not a measured workflow saving or throughput
gain. The correctness test image uses opt-level 1; the diagnostic uses opt-level
3, one codegen unit and thin LTO. Both are explicitly separate from production.
The 880-file snapshot changes seven Rust source/test files. Production images
have not been rebuilt/qualified for it; prior timing approvals do not transfer.
Next: production-image qualification, fresh workflow margin and matched controls.
Accepted baseline history: nine blocks, height 18. Next native slots: 1280-1343.
Unused funded slots: 8160. This source checkpoint consumes no slots or proofs.
Original limits and all remaining full-GPU qualification gates remain.
Metadata/continuation (crate relative):
benchmark-results/gpu-owned-node-completion-20261016/control/current-validation-01.json
benchmark-results/gpu-owned-node-completion-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-owned-node-completion-2026-10-16.json

Preceding checkpoint: reserved handoff delivers a fresh native block (section 9.305)
Fresh slots 1216-1279 produce 64 wallet and 63 recursive GPU proofs. Independent
CPU verification and durable native application pass: 48 user transactions and
16 issuance transactions. Accepted history is nine blocks at height 18.
The third prefix phase has only 33409 ms left, below the required 105000 ms.
The unsealed prefix defers, its worker drains, and a replacement admits handoff
with a 75000 ms continuation reserve before completing the seven final proofs.
Full workflow: 589974 ms, leaving 10026 ms under the unchanged 600000 ms limit.
Post-seal-through-application: 79899 ms. Campaign including cleanup/final chain
audit: 604.750 seconds. These intervals have different endpoints. This run does
not qualify production latency, matched speedup or sustained throughput.
All 15 wallet and 16 recursive stages report OpenCL. Original resource limits
remain; independent audits pass without hard memory-limit/OOM events or overlap.
The original native build manifests and separate four-file Python overlay remain.
The first supplemental auditor's path-type failure is retained; delivery-audit-02
passes on the same proof artifacts. No proofs or transactions are repeated.
Next native slots: 1280-1343. Unused funded slots: 8160. Prior failed slots remain
terminal. Next: adequate workflow margin, matched controls and the original
remaining proving/lifetime/fault/history/sustained/hardware qualification gates.
Metadata/continuation (crate relative):
benchmark-results/gpu-handoff-reserved-workflow-20261016/control/current-validation-01.json
benchmark-results/gpu-handoff-reserved-workflow-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-handoff-reserved-workflow-2026-10-16.json

Preceding checkpoint: reserve final proving time before live handoff (section 9.304)
An optimized delivery trial generated 64 fresh wallet and 56 recursive GPU
proofs, all independently CPU audited, but delivered no block. Its completed
prefix left 34180 ms in the worker dispatch window; sealing left 15608 ms and
the final request completed no jobs. Slots 1152-1215 are terminal and must never
be retried. Accepted history remains eight blocks at height 17.
The callback contract now requires exactly command, pins and
continuation_reserve_ms. The reserve must be an integer strictly between 0 and
120000 ms. Admission needs 30000 ms plus that reserve; a shorter live-worker
window defers the unsealed prefix, drains the worker and starts a replacement
within the original workflow clock. The callback service cannot use the
reserved final-proving time. Missing/invalid reservations fail before preparation.
All 43 CPU regressions pass (13 handoff, 30 phase). A 75000 ms trial reserve
requires 105000 ms initially; it is not a qualified production latency bound.
The native binaries and their 14 timing approvals are unchanged. The four
Python changes have a separate runtime source manifest; image build manifests
retain the original source hashes. Fresh live validation remains pending.
Next native slots: 1216-1279. Unused funded slots: 8224. Original resource and
deadline limits remain; failed candidates are never renewed.
Audit (crate relative):
benchmark-results/gpu-handoff-continuation-window-20261016/change-audit-01/summary.json
Evidence (repository relative):
docs/evidence/gpu-handoff-continuation-window-2026-10-16.json

Preceding checkpoint: optimized native images and CLI calibration (section 9.303)
The same 880-file snapshot is qualified with release opt-level 3, one codegen
unit, thin LTO and two Cargo jobs. CPU ABI tests: 32 pass, one GPU-only skip.
GPU ABI tests: all 36 pass, with five fresh wallet proofs and one tree operation.
The native service adds eight recursive proofs and four rejection cases;
startup/retirement checks add four admission rejections and two finalizers.
Fresh CLI calibration adds 17 proofs and 14 independently approved timing
classes. CPU replay verifies all 63 graph nodes and 64 archived wallets.
Total fresh GPU proofs: 32. No native block or funded slot is consumed.
All 15 wallet or 16 recursive request stages run on OpenCL as applicable.
Original 3 GiB worker, 1 GiB coordinator/auditor, 4 GiB fleet, CPUs 0-3,
zero swap, 150/180-second GPU work/service limits and 12288 MiB free-GPU gate
remain. Optimized-image approvals are fresh; baseline approvals do not transfer.
Next: fresh current-source native delivery with adequate deadline margin,
then matched delivered-transaction controls and remaining original gates.
Metadata/continuation (crate relative):
benchmark-results/gpu-current-optimized-native-20261016/control/current-validation-01.json
benchmark-results/gpu-current-optimized-native-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-current-optimized-proving-2026-10-16.json

Preceding checkpoint: current CLI calibration (section 9.302)
Eight serial phases produce 17 fresh GPU proofs and 14 independently approved
timing classes for the current CPU/GPU CLI images. Mixed-policy pair modes 4
and 8, merge levels 2-5 and depth-6 64-input finalization have cold/warm worker
samples. All 16 required request stages complete on OpenCL. Every phase has
a separate 1 GiB CPU proof audit; a final audit verifies the complete 63-node
graph and all 64 archived wallets. The final proof is 1683948 bytes.
The candidate ordering differs from recorded prior and failed roots. Its
56 imported public subtrees are independently reverified. Seventeen fresh
proofs cover 15 unique jobs, including two repeated jobs whose new encodings
differ. This is calibration over archived inputs, not a fresh 63-proof
workflow or native delivery. No native block or funded slot is consumed.
The unchanged 880-file source snapshot is checked across 11 archives.
Original 3 GiB worker, 1 GiB coordinator/auditor, 4 GiB fleet, CPUs 0-3,
zero swap, 150/180-second GPU work/service limits and 12288 MiB free-GPU gate
remain. Independent audits record no new memory-limit events and verify
shutdown, proof dependencies, image hashes and timing-record identities.
These approvals bind the opt-level 1, 64-codegen-unit, no-LTO images. They
do not transfer to rebuilt images. The repository's optimized release
settings need fresh native qualification and calibration before a delivery
trial. Complete resource ownership, remaining routes/fault paths, matched
controls, 24 hours AND 150 roots and other hardware remain open.
Metadata/continuation (crate relative):
benchmark-results/gpu-current-production-calibration-20261016/control/current-validation-01.json
benchmark-results/gpu-current-production-calibration-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-current-cli-calibration-2026-10-16.json

Preceding checkpoint: native startup and retirement (section 9.301)
The current C service rejects retained/unlimited caller stacks, retained
allocator capacity and excessive private writable mappings before HELLO
and GPU startup. Four cases pass across three test processes, preserving
caller descriptors and coordinator reservations.
A fourth test process completes two fresh 262144-row finalizer proofs.
Test-only retained libc capacity forces the first worker to retire after
returning a valid result. Further dispatch and premature replacement reject.
Physical pidfd observers confirm the first exit before the replacement
observer arms and replacement launches. The replacement has a fresh PID,
execution digest, setup and proof bytes. Both 1683948-byte proofs verify
again on CPU after both workers exit; changed statements reject. All 16
required recursive request stages run on OpenCL, with zero managed storage
at shutdown. This does not establish complete allocator/RSS lifetime bounds.
The initial lifecycle attempt stopped after its first verified proof because
the controller read unit instead of replacement_unit from the observer plan.
Its evidence is preserved, and its proof is excluded from the accepted
two-proof lifecycle count. The corrected controller completes a fresh full
lifecycle. A failed preparation audit of structured historical hash records
is also preserved. No production source or allocator policy changes occur.
Original 1 GiB coordinator/auditor, 3 GiB worker, 4 GiB fleet, CPUs 0-3,
zero swap, 150/180-second GPU work/service deadlines and 12288 MiB free-GPU
gate remain. No native block or funded slot is consumed. Calibration,
larger workloads, remaining fault/route coverage, complete resource ownership,
matched delivery controls, 24 hours AND 150 roots and other hardware remain open.
Metadata/continuation (crate relative):
benchmark-results/gpu-native-current-lifecycle-20261016/control/current-validation-01.json
benchmark-results/gpu-native-current-lifecycle-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-current-native-lifecycle-2026-10-16.json

Preceding checkpoint: native worker jobs and pool roots (section 9.300)
The unchanged 880-file snapshot and newly linked C service execute eight
fresh GPU proofs: two small 2048-row padding jobs, two full-size pairs,
two merges and two pool finalizers. All 16 recursive request stages run on
OpenCL. Nonempty proofs use the 12-key, 262144-row registry and are each
1683948 bytes. Four archived JoinSplit wallets (0,4,8,12) are reused.
New pair outputs feed the merges, and these outputs feed finalizers. Each
successful worker has one cold setup and one cache hit. Context updates,
observed exit, zero managed storage at shutdown and reservation release pass.
The finalizer test uses the real local pool adapter and accepts two roots;
it does not apply native blocks or deliver new user transactions.
Three separate 1 GiB CPU-only processes verify both persisted outputs per
operation after coordinator and worker exit, rejecting four mutations per
proof. Four malformed configuration/executable/job/disconnect cases retire
the GPU and preserve caller descriptors while retaining reservations for
explicit recovery. All five native test processes and three CPU verifiers pass.
The 1 GiB coordinator and 3 GiB worker share a 4 GiB fleet, CPUs 0-3, zero
swap and the unchanged 150/180-second GPU work/service deadlines. GPU runs
retain the 12288 MiB free-memory gate. A current measured merge assignment
conservatively covers pair, merge and finalizer geometry; its reservations
are recomputed from the pinned source. Worker samples check physical caps;
sampled worker peaks are lower bounds, while retained fleet peaks are final.
Evidence reopens 14 inherited source archives, pins 78 fixture files and
links all native/CPU outputs to the current images. No proving source changes,
native blocks or funded-slot consumption occur. Current native calibration,
larger workloads, retained-arena replacement qualification, complete resource
ownership, remaining routes, matched controls, 24 hours AND 150 roots,
multi-GPU, AMD OpenCL and native Apple Metal/local Mac integration remain open.
Metadata/continuation (crate relative):
benchmark-results/gpu-native-current-service-20261016/control/current-validation-01.json
benchmark-results/gpu-native-current-service-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-current-native-worker-2026-10-16.json

Preceding checkpoint: native builds and wallet ABI (section 9.299)
The unchanged 880-file snapshot builds CPU/GPU Rust static libraries, worker
CLIs and Zig host bridges. Both bridges independently report capacity 64.
Zig unit/root checks and the public-service rejection test pass. CPU FFI:
32 passed, one GPU-only skip. GPU FFI: all 36 passed, five fresh wallet proofs
(four JoinSplit, one HTLC) plus one tree-root operation. All 15 required
wallet stages have completed OpenCL observations. CPU verification and
tamper/replay checks occur after GPU shutdown; all three shutdowns release
the GPU lease with zero managed bytes live.
Evidence checks 14 source archives and eight native images. The C/Zig
service harnesses were separately frozen and are already included among
the 880 canonical sources; generated GPU options are separately pinned.
Original collector/auditor failures remain preserved. Successful proofs
were not rerun to repair evidence collection.
Original 3 GiB build/worker, 1 GiB auditor, 4 GiB fleet, four CPUs, zero swap,
150/180-second GPU work/service limits and 12288 MiB free-GPU gate remain.
Builds use two Cargo jobs, opt-level 1, 64 codegen units and no LTO. Previous
production timing approvals do not transfer to these newly linked images.
This standalone wallet ABI run has no private/public worker assignment.
The C public service is linked but still needs real assigned-job execution.
No native block or funded slot was consumed. Complete resource lifetime
ownership, remaining routes, current worker execution, calibration and
matched delivered-transaction controls, 24 hours AND 150 roots, multi-GPU,
AMD OpenCL and native Apple Metal/local Mac integration remain open.
Metadata/continuation (crate relative):
benchmark-results/gpu-native-current-integration-20261016/control/current-validation-01.json
benchmark-results/gpu-native-current-integration-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-current-native-integration-2026-10-16.json

Preceding checkpoint: mixed-policy tree and cache reuse (section 9.298)

The final 880-file snapshot produces four fresh GPU proofs: cold and cached
level-2 merge, then cold and cached depth-6 finalization. The two inherited
pair proofs from section 9.297 cover archived wallets 0,5,2,7: JoinSplit,
HTLC redeem, HTLC refund and issuance. The finalizer consumes the new cold
merge output. The 12-key registry has 262144 rows and default capacity 64.
Only the fixture harness changes; proving implementation is unchanged.

Each operation has one setup and one cache hit. Cold/warm proof bytes differ
while the expected statement remains identical. All 16 request stages have
completed OpenCL observations; registry/preprocessing cache hits are explicit.
All four proofs verify after GPU shutdown, and two separate 1 GiB CPU-only
processes verify both persisted outputs for their operation after worker exit.
Both verification paths reject changed context, level, count and root. Each
proof is 1683948 bytes. Two geometry checks, the GPU-host all-target check and
the rebuilt image pass.

Evidence verifies 880 sources, three archives and 163 artifacts, including
parent dependencies and the 78 pinned fixture files. The shared whitelist
matches at packaging. GPU service peaks are 1141.24 MiB for merge and 672.22
MiB for finalization; separate CPU verifiers peak at 32.92 and 32.55 MiB.
The image build peaks at 2860.12 MiB. Original limits and the 12288 MiB free-GPU
gate remain, with no observed overlap or memory-limit/OOM events. No native
block, new wallet issuance or funded slot is consumed.

This is one four-input direct Rust tree with inherited parent proofs. Other
registries and warm-cache combinations, mixed redeem/refund HTLC pairs,
complete resource and entrypoint coverage, native Zig/ABI and production
images, calibration and delivery controls, sustained tests and other hardware
remain open. The full goal is active; no throughput or production claim follows.

Metadata/continuation (crate relative):
benchmark-results/gpu-mixed-tree-qualification-20261016/control/current-validation-01.json
benchmark-results/gpu-mixed-tree-qualification-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-mixed-policy-tree-cache-2026-10-16.json

Preceding checkpoint: full-size ordered wallet-policy pairs (section 9.297)

The final 879-file snapshot produces 14 fresh GPU pair proofs across all nine
ordered JoinSplit/HTLC/issuance combinations and five HTLC-refund cases. The
12-key registry uses 262144 rows and default capacity 64. Each proof covers
two archived inputs at level 1 and is 1683948 bytes. Inputs are reused across
cases; this does not represent 28 newly delivered user transactions.

All 16 request stages complete on OpenCL. Every proof verifies on CPU after
GPU shutdown and again in a separate 1 GiB process after worker exit. Both
paths reject changed context, level, count and root. Nine CPU geometry tests,
the final GPU-host all-target check and the rebuilt test image pass. Each GPU
request uses one cold setup. Only test harness source changes.

Evidence verifies 827 artifacts, 78 fixture files, three final source archives
and three preserved initial source archives. The shared source whitelist
matched at packaging. GPU service peaks span 799.56-875.46 MiB; separate CPU
verifiers span 31.06-33.54 MiB. The final image build peaks at 2820.41 MiB.
Original resource limits and the 12288 MiB free-GPU gate remain unchanged,
with no observed overlap or memory-limit/OOM events in accepted services.

Preserved failures include a controller prefix rejected before GPU startup,
a corrected test-only shutdown assertion and a stale collector directory
reference. They are excluded from accepted coverage. No native block or
funded slot is consumed. Mixed redeem/refund HTLC pairs, warm-cache cases,
mixed-policy merge/finalizer trees, other registries, complete lifetime and
entrypoint coverage, native Zig/ABI and production images, calibration and
delivery controls, sustained tests and other hardware remain open. These
correctness cases establish no throughput or production-readiness claim.

Metadata/continuation (crate relative):
benchmark-results/gpu-mixed-pair-qualification-20261016/control/current-validation-01.json
benchmark-results/gpu-mixed-pair-qualification-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-mixed-policy-pairs-2026-10-16.json

Preceding checkpoint: nonempty recursive proof tree (section 9.296)

The unchanged 878-file section 9.295 snapshot produces four fresh GPU proofs:
two pairs from four distinct archived JoinSplit inputs, a four-transaction
level-2 merge and its depth-6 finalizer. The 12-key registry uses 262144 rows
and default capacity 64. All 16 request stages report OpenCL, and all four
proofs verify on CPU after GPU shutdown. Three separate 1 GiB CPU processes
also verify the persisted right pair, merge and finalizer after worker exit,
rejecting altered context, level, count and root. Each proof is 1683948 bytes.

Evidence pins 180 artifacts, 78 fixture files, eleven inherited source archives
and the unchanged test image. Three CPU geometry checks supply reservations.
The shared source whitelist matched the snapshot at packaging. GPU service
peaks are 800.10, 795.95, 1145.46 and 704.93 MiB for left pair, right pair,
merge and finalizer, respectively. Original worker/auditor/fleet, CPU, swap,
deadline and 12288 MiB free-GPU limits remain, with no observed service overlap
or memory-limit/OOM events. No native block or funded slot is consumed.

This is direct Rust API qualification with native GPU initialization. Native
Zig/ABI/service delivery, full-capacity roots, other nonempty registry/policy
routes, complete lifetime ownership and command/cfg/raw-arithmetic inventory,
production images/calibration, matched controls, long history, 24 hours AND
150 roots, multi-GPU, AMD OpenCL and native Apple Metal/local Mac integration
remain open. These correctness samples establish no throughput claim.

Metadata/continuation (crate relative):
benchmark-results/gpu-recursive-lifetime-audit-20261016/control/current-validation-01.json
benchmark-results/gpu-recursive-lifetime-audit-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-current-nonempty-recursion-2026-10-16.json

Preceding checkpoint: recursive size reporting without allocation (section 9.295)

Legacy recursive proof diagnostics now use a bounded counting serializer in
place of a temporary 2 MiB encoded output buffer. Both established encodings,
the proof-size cap and serializer errors are preserved. 25 codec tests, four
all-target checks (CPU/GPU, fixed-width and no-stream configurations) and three
fresh CPU-verified GPU proofs pass on the final 878-file snapshot. Independent
allocation observations report zero requests for sizing both wire encodings.
All 16 GPU request stages remain covered across cold setup, reuse and eviction.

Evidence verifies 11 source archives, 169 artifacts and a reviewed three-path,
169-line diff. The shared source whitelist matched at packaging. The final
build/test peak is 2853.49 MiB and the GPU test peak is 254.57 MiB, under the
original limits and free-memory gate, with no observed service overlap or
memory-limit/OOM events. This change does not own escaped proof/output storage
or establish a throughput gain. No native block or funded slot was consumed.

Metadata/continuation (crate relative):
benchmark-results/gpu-recursive-size-count-20261016/control/current-validation-01.json
benchmark-results/gpu-recursive-size-count-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-recursive-size-count-2026-10-16.json

Preceding checkpoint: recursive session budget/cache reuse (section 9.294)

One existing GPU test on the unchanged combined snapshot produces three fresh
CPU-verified legacy padding proofs at height 2048. Two cold setups, one cache
hit, explicit eviction, five insufficient-budget/configuration rejections and
public/opening mutation rejection pass. All 16 request stages report OpenCL.
The assigned 1 GiB session allowance reserves 1 MiB for retained session storage;
service memory peaks at 238.53 MiB under the original limits. The original result
collector expected an obsolete log marker; an independent audit validates the
successful raw run and actual pinned marker, with no proof rerun. This is not
complete returned-output, cache or enclosing-lifetime ownership qualification.
No native blocks or funded slots are consumed. Source and production images
are unchanged; the full goal remains active.

Metadata/continuation (crate relative):
benchmark-results/gpu-recursive-budget-cache-20261016/control/current-validation-01.json
benchmark-results/gpu-recursive-budget-cache-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-recursive-budget-cache-2026-10-16.json

Preceding combined-source checkpoint: integration checks (section 9.293)

The frozen combined source includes 877 source/support files, incorporating the
concurrent session's capacity and host/pool changes. 135 Rust tests, 205 Python
tests, four all-target checks and 25 GPU tests pass. The GPU tests produce 44
fresh proofs verified on CPU (33 wallet, three registered, eight public recursive
padding requests), plus 18 opening/FRI component cases and two tree operations.
GPU evidence uses default capacity; opt-in capacity 128 has CPU/compilation
coverage only. Two stale Python fixtures were corrected, with explicit capacity
root-selection and 65-transaction preflight boundary checks. Production code
was not changed by this checkpoint.

The audit verifies 877 sources, 40 source archives and 1053 artifacts. The final
snapshot differs from the Rust/GPU test snapshot only in those two Python test
files; their corrected suites pass. The shared source/support whitelist,
including newly added files, matched at packaging. This observation does not
freeze the concurrently edited checkout. Preserved unsuccessful selections and
fixture runs are excluded from accepted coverage.

Original limits remain: 3 GiB worker/build, 1 GiB auditor, four CPUs, zero swap,
150/180-second GPU work/service deadlines and 12288 MiB free GPU memory.
Accepted runs have no observed competing services or memory-limit/OOM events.
No native block or funded slot was consumed. Native Zig/ABI integration, complete
host/cache/output ownership, nonempty recursive requests, production images and
calibration, matched controls, long history, 24 hours AND 150 roots, multi-GPU,
AMD OpenCL and native Apple Metal/local Mac source integration remain open.
The full goal remains active; these checks establish no throughput claim.

Metadata/continuation (crate relative):
benchmark-results/gpu-combined-source-20261016/control/current-validation-01.json
benchmark-results/gpu-combined-source-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-combined-source-integration-2026-10-16.json

Preceding isolated checkpoint: public recursive requests (section 9.292)

Four existing GPU tests on the unchanged, verified section 9.291 source produce
eight fresh recursive padding proofs. The 3-, 5-, 6- and 12-key registries each
prove levels 0 and 5 at height 2048, with one cold setup and one warm preprocessing
hit. All 16 required request stages report completed OpenCL work, including
public-value construction. Each request completes statement, registry,
statement-check, preprocessing and proof slots. Cached preprocessing is explicitly
marked; it does not fabricate fresh device work. CPU verification after GPU
shutdown, CPU public-root comparison and altered expected/embedded public-value
rejection pass for every proof.

The independent audit pins 745 sources, eighteen inherited source archives and
78 new artifacts. No source or production image changes. GPU service peaks span
236.58-254.34 MiB with zero swap, no memory-limit/OOM events and no observed
competing services. Original resource limits and the 12288 MiB free-GPU gate
remain unchanged. No native block or funded slot is consumed.

Metadata/continuation (crate relative):
benchmark-results/gpu-recursive-entrypoint-inventory-20261016/control/current-validation-01.json
benchmark-results/gpu-recursive-entrypoint-inventory-20261016/control/continuation-01.json
Evidence (repository relative):
docs/evidence/gpu-recursive-request-qualification-2026-10-16.json

A bounded source scan collected 2981 textual candidates; selected call chains
were reviewed. This is not an exhaustive command/cfg/raw-arithmetic inventory.
Nonempty wrap/pair, merge and finalization qualification, complete host/cache
ownership, combined-checkout validation, fresh production images/calibration,
matched controls, long history, 24 hours AND 150 roots, multi-GPU, AMD OpenCL and
native Apple Metal/local Mac source integration remain open. The full goal is
active; these correctness samples establish no throughput claim.

Preceding isolated checkpoint: transcript/scalar host ownership (section 9.291)
Each proof session now owns a fixed 1 MiB atomic host quota shared by its clones
and transcript families. Retained states acquire their backing before allocation
and keep the charge through cleanup. Adapters reserve their complete transient
plan before allocation; nested GPU methods exclusively borrow that scope and
check its owner/capacity. Raw APIs reserve their own scopes. Concurrent operations
and future states therefore compose within the same allowance.

126 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
21 GPU test executions pass: nine wallet integrations produce 33 fresh proofs
and two tree operations; four opening/FRI tests cover 18 component cases; seven
transcript/scalar checks and one registered integration add three fresh proofs.
All 36 fresh proofs verify independently on CPU after GPU shutdown. Ownership
checks cover concurrent contention, rejection before GPU work, wrong-session
scopes, error/unwind cleanup and zero live charge after drop. Accepted services
record no observed overlap. An initial interleaved build and eleven tests, plus
the rejected GPU-memory preflight, remain preserved separately.

Known state backing is 424 bytes. Maximum tested scratch is 721952 bytes; two
registered states plus that scratch total 722800 bytes, below 1048576. Allocation
oracles confirm 768 bytes of temporary owners and 1256 bytes of session backing.
The original 3 GiB worker / 1 GiB auditor limits, zero swap, four CPUs and
12288 MiB free-GPU gate remain in force. Accepted build/test services peak at
1627.63 MiB; the registered integration peaks at 270.86 MiB. These are bounded
correctness samples; production images and throughput remain unqualified.

Evidence verifies 745 sources, eighteen current-source archives, one preserved
initial archive and 737 artifacts. The reviewed 946-line diff covers fifteen
paths, including two new modules. The verified section 9.290 snapshot plus this
overlay excludes 74 unrelated changed shared-checkout paths.
Isolated metadata/continuation (crate relative):
benchmark-results/gpu-transcript-host-ownership-20261016/control/current-source-validation-04.json
benchmark-results/gpu-transcript-host-ownership-20261016/control/continuation-04.json
Evidence (repository relative):
docs/evidence/gpu-transcript-host-ownership-2026-10-16.json

Escaped returned vectors, caller input, earlier construction, later output/export,
verifier/foreign allocations and allocator overhead remain separate;
whole_proof=false. Combined-checkout validation, public recursive request/cache
integration and full production/history/multi-GPU/AMD/Metal qualification remain
open. No native block or funded slot is consumed. The full all-GPU goal is active.

Preceding isolated checkpoint: transcript/scalar host storage (section 9.290)

The existing 1 MiB transcript host envelope now bounds observation, sampling,
scalar input/output, next-point conversion, lookup metadata/challenges and domain
splitting. Observation uses a fixed stack batch; other maintained buffers reserve
exact fallible capacity. Lookup IDs retain original encounter-order semantics.
Opening/FRI deducts the envelope alongside retained commitments/runtime storage.
The largest tested transient plan is 721880 bytes. Allocator oracles confirm
696 bytes for temporary owners and 229376 bytes for 4096-entry lookup metadata.

120 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
20 GPU test executions pass: nine wallet integrations produce 33 fresh proofs
and two tree operations; four opening/FRI tests cover 18 component cases; six
transcript/scalar checks and one registered integration add three fresh proofs.
All 36 fresh proofs verify independently on the CPU. Accepted test runs record
no observed service overlap. The initial interleaved build/tests and one
preflight idle-guard rejection are preserved separately.

Evidence verifies 743 sources, seventeen current-source archives, one preserved
initial archive and 704 artifacts. The reviewed 947-line diff covers thirteen
paths, including two new modules. The source is the verified section 9.289
snapshot plus the declared overlay; 73 unrelated changed paths are excluded.
Evidence packaging waited for the other session's benchmark to finish.
Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-transcript-host-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-transcript-host-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-transcript-host-storage-2026-10-16.json

Budget reconstruction links all 33 wallet and three registered proofs. Runtime
charges including scratch span 9471944-76548040 bytes. Build/test services peak
at 1620.61 MiB; wallet GPU services span 143.95-216.22 MiB; opening/FRI components
span 201.70-212.49 MiB. Six transcript/scalar services span 140.48-144.50 MiB;
the registered integration peaks at 1383.13 MiB. The separately retained initial
build peaks at 2847.14 MiB. No recorded service has memory-limit/OOM events.

Combined-checkout validation and full lifetime ownership remain open, including
concurrent calls whose host buffers are allocated outside the execution mutex.
whole_proof=false remains explicit. Original limits and the 12288 MiB free-GPU
gate are unchanged; no production timing approval transfers. This checkpoint
consumes no native block or funded slot. The full all-GPU goal remains active.

Preceding isolated checkpoint: retained runtime storage (section 9.289)

Device-only opening/FRI now charges the existing engine metadata envelope plus
actual mapped staging, shared session storage and current live GPU transcript
states. Commitments and runtime backing reduce the same configured allowance
before opening construction. Host/hybrid behavior, arithmetic, profiles, circuits,
entropy, encoding and verification remain unchanged. Transient transcript/scalar
vectors, future concurrent clones and enclosing lifetimes remain outside this
component; whole_proof=false stays explicit.

108 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Nine wallet integrations produce 33 fresh CPU-verified proofs and two tree-root
operations; all 15 required wallet arithmetic stages report OpenCL. Four focused
GPU tests pass 18 component cases. Six PCS cases verify allocation-free runtime
census, snapshot counting, early exhausted-budget/wrong-session rejection and
explicit CPU-transcript compatibility. Allocator oracles confirm session storage
of 1208 bytes and two live transcript states of 784 bytes on this toolchain.

All 33 proofs link retained preparation, commitments, runtime backing and opening
work to the original request allowance. Observed runtime charges span
8423368-75499464 bytes. These are correctness samples, not throughput qualification.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-runtime-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-opening-runtime-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-opening-runtime-storage-2026-10-16.json

Evidence verifies 741 sources, sixteen current-source archives, one preserved
initial archive and 581 artifacts. The reviewed 374-line diff covers nine paths.
Other-session edits remain preserved; 73 unrelated changed paths are excluded.
Combined-checkout validation is still pending. One successful initial build and
eleven tests overlapped another service and are preserved separately; the tests
were rerun. Accepted runs record no observed service overlap.

Qualified build/test peak is 1565.06 MiB; wallet GPU-service peaks are
144.20-214.19 MiB and component peaks 201.98-212.25 MiB. The initial build peaks at
2846.00 MiB. No recorded service has memory-limit/OOM events. Original limits and
the 12288 MiB free-GPU gate remain unchanged. No production approval transfers.
Next compose transient transcript/scalar buffers and concurrent clone ownership,
earlier construction and later export/verifier/foreign lifetimes. No native block
or funded slot is consumed. The full all-GPU goal remains active.

Preceding isolated checkpoint: retained commitment storage (section 9.288)

Device-only opening admission now charges retained inline prover descriptors,
private/public prefix capacities and allocation wrappers, all salt-store variants,
shared replay-stream/seed wrappers and tree caps. Shared owners and repeated
references are conservatively recounted without a deduplication allocation.
The charge reduces the allowance used by opening construction and the later
opening/FRI partition. Explicit host/hybrid representations keep their existing
path. Engine/session, transcript, device payload, driver, allocator overhead and
enclosing lifetimes remain separate; whole_proof=false stays in the report.

100 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Nine wallet GPU integrations produce 33 fresh proofs (16 quadratic, 17 cubic),
plus two tree-root operations. All 15 required wallet arithmetic stages use
OpenCL; CPU verification after GPU shutdown and altered-public rejection pass.
Four focused tests pass 18 component cases. Six PCS cases independently observe
an allocation-free retained-data census and rejection before GPU work. Actual
Rust wrapper layouts are checked against allocator requests; the replay stream
and its seed wrappers require 312 bytes per conservatively counted occurrence.

All 33 successful proofs link the retained commitment charge to opening
construction, retained output, FRI and serialization under the configured budget.
Observed commitment charges span 19128-29368 bytes. These are correctness samples,
not maximum-size or throughput qualification. Other-session edits remain untouched;
the combined shared checkout still requires validation after concurrent work ends.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-commitment-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-opening-commitment-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-opening-commitment-storage-2026-10-16.json

Evidence checks 738 sources, fifteen current-source archives and 511 artifacts.
The reviewed 415-line diff covers ten paths, including two new partition/test
modules. Host build/test peak is 2861.53 MiB; GPU wallet-service peaks are
141.81-213.45 MiB. No memory-limit/OOM events occur. Original resource limits and
the 12288 MiB free-GPU gate remain unchanged. No production timing approval
transfers. Next compose engine/session and transcript storage, earlier commitment
construction and later output/export lifetimes. No native block or funded slot
is consumed; the full all-GPU goal remains active.

Preceding isolated checkpoint: opening construction storage (section 9.287)

Opening construction now admits retained round capacities, exact nested opened
values, prepared descriptors, FRI output backing and the larger sequential
readback before normal construction allocation or opening arithmetic. Fixed stack
geometry, a height bitset and point/alpha word buffers replace growable metadata.
Output/descriptor vectors use fallible exact reservations. Runtime retained
capacities match the later opening/FRI partition; both proof fields, arithmetic
ordering, profiles and circuit fingerprints remain unchanged in the isolated source.

91 unit/policy tests and CPU/GPU all-target checks pass offline and locked. Nine
qualified wallet GPU integrations produce 33 fresh CPU-verified proofs, plus two
tree-root operations. All 15 required wallet arithmetic stages report OpenCL.
Four focused GPU tests pass 18 component cases, including exact capacity checks,
early insufficient-budget rejection, upstream byte parity and CPU verification
after shutdown. All 33 qualified proofs link construction, retained opening,
FRI and serialization admissions to the same configured operation allowance.

The first compile failure and a later inverted assertion failure are corrected
and preserved. One tree integration passed its proof checks but cleanup detected
another session's validation service; its six additional proofs and two operations
are recorded as superseded. Only that tree test was rerun, successfully. There are
thirteen qualified GPU tests across fourteen GPU attempts. The other session's
source edits remain untouched. Combined shared-checkout validation is still pending.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-construction-storage-20261016/control/current-source-validation-04.json
  benchmark-results/gpu-opening-construction-storage-20261016/control/continuation-04.json
Evidence (repository relative):
  docs/evidence/gpu-opening-construction-storage-2026-10-16.json

Evidence checks 736 sources, fourteen current-source archives, fourteen preserved
initial archives and 701 artifacts. The reviewed 634-line diff covers four paths,
including two new planner/test modules. Build/test host peak is 2753.46 MiB;
qualified wallet GPU-service peaks are 199.96-222.38 MiB. No memory-limit/OOM events
occur. Two Cargo jobs run within the original four-CPU/3 GiB build allowance.
All remaining resource limits and the 12288 MiB free-GPU gate are unchanged.
Engine, transcript, borrowed commitment data, allocator overhead and stack remain
outside this component. Whole-proof ownership and production/throughput gates
remain open. No native block or funded slot is consumed; the all-GPU goal is active.

Preceding isolated checkpoint: opening/FRI host partition (section 9.286)

Opening evaluation now receives the actual configured operation allowance.
An allocation-free census deducts retained opening and round vector capacities,
device-input descriptors, the exact FRI reference array and pending exact hiding
output before FRI. FRI proof assembly, query gathering, salts and final-polynomial
readback receive the remainder, subject to existing local caps. Exact hiding
buffers preserve preprocessing order and encoded bytes.

84 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Nine wallet GPU integrations produce 33 fresh proofs (16 quadratic, 17 cubic)
with all 15 required arithmetic stages on OpenCL and independent CPU verification
after GPU shutdown. Four focused GPU tests pass 18 component cases covering
both fields, early insufficient-allowance rejection, CPU byte parity and CPU
verification after shutdown. These component cases are operation coverage,
separate from the 33 complete wallet proofs. Every successful wallet proof links
its operation allowance, opening partition, FRI storage and serialization record.

The shared checkout is being edited by another session. The initial source guard
rejected unrelated changes before compilation. Validation therefore uses the
verified section 9.285 archive plus only the twelve declared opening/FRI paths,
with separate source, Cargo cache and target directories. No concurrent source
changes are overwritten or qualified. Combined shared-checkout validation remains
pending after that session finishes. The source below is not a production image.

Isolated metadata/continuation (crate relative):
  benchmark-results/gpu-opening-host-partition-20261016/control/current-source-validation-02.json
  benchmark-results/gpu-opening-host-partition-20261016/control/continuation-02.json
Evidence (repository relative):
  docs/evidence/gpu-opening-host-partition-2026-10-16.json

Evidence checks 734 sources, thirteen archives and 460 artifacts; the full
781-line diff covers twelve paths. Host build/test peak is 2957.46 MiB;
wallet GPU-service peaks are 143.83-213.11 MiB. No memory-limit/OOM events occur.
Original resource limits, the 12288 MiB free-GPU gate, proof profiles and circuit
fingerprints remain unchanged in the isolated source. No production timing
approval transfers. This partition excludes borrowed prover data, engine,
transcript, configuration, other caller memory and allocator overhead; it retains
whole_proof=false and host_lifetime_admitted=false. Complete host/cross-stage/
export/recursive lifetimes and production/sustained qualification remain open.
No native block or funded slot is consumed. The all-GPU goal remains active.

Preceding source checkpoint: bounded wallet serialization (section 9.285)

Legacy single/batch and cubic JoinSplit, HTLC and issuance GPU proofs now admit
retained proof/public capacities plus a single final output against their actual
operation allowance. The allocation-free census includes spare capacity at every
nested level. Checked Postcard sizing precedes allocation; cubic envelopes serialize
directly into the final buffer. The existing cubic 2 MiB cap includes its 72-byte
header. CPU encoders/verifiers, proof parameters, circuits and entropy are unchanged.

The preceding preparation/operation partition remains enforced: the 1 GiB request
allowance splits into 203500104-205861128 preparation bytes and 867880696-870241720
operation bytes. Serialization is a late output boundary. Earlier construction,
cross-stage retained storage, caller/configuration/export/verifier/foreign memory,
diagnostics, stack and allocator overhead still need enclosing ownership. Reports
retain whole_proof=false and lattica-wallet-device-phase-v9 with
host_lifetime_admitted=false.

70 unit/policy tests and CPU/GPU all-target checks pass offline and locked.
Seven new output tests independently match retained capacity with allocator
requests, mutate 30 nested capacity locations in each field, cover empty optional
buffers, accept exact limits, reject short limits without allocating, require one
output allocation, reject overflow and preserve Postcard/envelope bytes. The prior
63 tests retain their coverage; all five production fingerprints are unchanged.

Nine GPU integrations produce 33 fresh proofs (16 quadratic, 17 cubic), plus two
tree-root operations. All 15 required proving arithmetic stages use OpenCL. CPU
verification after shutdown, altered-public rejection, capacity/unwind and 21
private-input boundaries pass. Existing 22 resource rejections precede arithmetic.
There are 43 phase-admitted requests: 33 successes and ten later rejections.
69 preparation records and 34 configured operation partitions are checked; the
latter close as 33 successful proofs and one unsuccessful issuance request. All
33 successful proofs have serialization records linked to their actual partitions
and completed requests, independently reconstructed from raw logs. Proof/public/
output totals span 995769-1962352 bytes; encoded output spans 458009-875464 bytes.
These correctness samples do not qualify maximum-size proofs or throughput.

Source metadata/continuation (crate relative):
  benchmark-results/gpu-wallet-serialization-storage-20261016/control/current-source-validation-01.json
  benchmark-results/gpu-wallet-serialization-storage-20261016/control/continuation-01.json
Evidence (repository relative):
  docs/evidence/gpu-wallet-serialization-storage-2026-10-16.json

Independent verification checks 732 sources, ten current-source archives and
317 artifacts. The 715-line diff covers seven changed paths. Build/test host peak
is 2649.92 MiB; GPU-service peaks are 143.61-213.32 MiB. No memory-limit/OOM events
occur. Original 3 GiB worker/build,
1 GiB auditor, four CPUs, zero swap, 150/180-second GPU work/service limits and
12288 MiB free-GPU gate hold. Correctness images use opt-level 1, 64 codegen units
and no LTO; no production timing approval transfers.

Next complete construction and cross-stage retained-output ownership,
caller/export/verifier/foreign lifetimes, public recursive request/cache composition,
fresh production builds/calibration, matched controls and sustained/multi-device
qualification. No native block, funded-slot use or new throughput/speedup is claimed.

Accepted history remains eight blocks at height 17; next native slots 1152-1215,
qualification 9556-9559, unused slots 8288. At least 1312 more unused slots are needed
for a fresh 150-root campaign before controls/failures/qualification. Failed slots
896-959 remain terminal. The original all-GPU goal remains active, including 24 hours
AND 150 roots, multi-GPU, AMD OpenCL and native Apple Metal/local Mac integration.
