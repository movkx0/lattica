# Lattica — audit-readiness status & roadmap

> **Document role:** Current status summary. The audited artifact is the `v3-batch-audit` tag; uncommitted or later changes require separate review.

## Current block-path decision — 2026-10-02

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
Full-size registered-cap checks, recursive proof/root-only replay, matched
end-to-end timing and all production gates remain pending.

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

The [matched cache-workload pilot](evidence/block-v2-cache-bench-pilot-2026-10-02.json)
passes **148 selected native tests, nineteen explicit CPU checks and ten Zig
tests**, then both three-proof arms and fresh CPU replays. For the same
four-transaction subtree, idle-cleared preprocessing took **562.650 seconds**
and retained preprocessing **601.444 seconds** through cleanup: retained was
**6.895% slower in this one ordered pair**, despite one cache hit. The first
retained-arm proof was also a cache miss and substantially slower, so this
does not isolate a causal cache regression. **No speedup is promoted.**
The test-only harness covers five schedules in preflight; only paired-four has
a live comparison. Alternating repeats, mixed schedules, full-block deadlines
and production qualification remain open. The control is not process/OS-cache
cold, and neither arm completes the depth-six block candidate.

The [cache-owning CPU adapter checkpoint](evidence/block-v2-cached-cpu-2026-10-02.json)
now retains one explicitly reserved preprocessing session across synchronous
jobs. **146 selected native tests, eighteen explicit CPU checks and ten Zig
tests pass**, followed by two real full-strength paired-wrapper proofs and a
fresh CPU replay. Setup spans were **45.980 / 0.108 seconds** (one setup, one
cache hit); worker proving spans were **158.441 / 112.056 seconds**. Each
intermediate proof is **1,683,948 bytes**. The proof service took **274.689 seconds**
and peaked at **40.0005 GiB RAM**, with zero swap. Close released all reservations
and live spill mappings.

This is an **inline serial adapter**, not an autonomous warm-worker service or
a completed block. The cache holds only one immutable program type; changing
type replaces it. Fresh randomness and strict owner-side CPU acceptance remain
required. The trial's two different inputs are **not a matched cold/warm control**.
Mixed-workload comparisons, arrival/deadline integration, lifecycle/resource
qualification, full64 and complete post-seal/host/security gates remain open.
The GPU opening backend remains unpromoted after its slower matched pilot.

The [persistent-workspace reservation checkpoint](evidence/block-v2-workspace-reservations-2026-10-02.json)
adds separately journaled cache-lifetime budgets and local-use guards. Idle
workspaces stay charged; cold worker identities cannot alias them, and recovery
requires explicit workspace reconciliation. **144 selected native tests,
sixteen explicit CPU checks and ten Zig tests pass**. The new local `LVDAG004`
envelope embeds the existing snapshot format; cold snapshots retain their
previous encoding. That checkpoint established the reservation foundation;
the cached-adapter continuation above adds real allocation and reuse, without
a matched speedup or production-readiness claim.

The [managed verifier process-loss checkpoint](evidence/block-v2-verifier-crash-2026-10-02.json)
now exercises actual SIGKILL and reaping of a child holding either a guarded
task or a successfully CPU-verified result after its coordinator handle drops.
Recovery stays locked while the child is alive; after reaping, explicit
reconciliation is still required. Old eligibility, stale results and mutated
proofs are rejected. **134 selected native tests, fifteen explicit CPU checks
and ten Zig tests pass**; no new prover is run, and the CPU worker binary is
unchanged. These are task-held and result-held boundaries, not a kill injected
inside cryptographic computation or general external-verifier drain authority.
Warm preprocessing reuse, physical quotas/retention, OOM/timeouts, full64,
complete post-seal finalization and security/host activation remain open.

The [local verifier-guard checkpoint](evidence/block-v2-verifier-guard-2026-10-02.json)
keeps the journal ownership lock alive through a managed CPU verification task
and its pending result. Dropping the coordinator handle cannot allow recovery
to overlap that guarded work, and ordinary completion cannot release its lease
early. **134 selected native tests, fourteen explicit CPU checks, ten Zig tests
and nine live lifecycle/proof/replay stages pass**. The new pair proof is
**1,683,948 bytes**, taking **162.062 s** from dispatch through acceptance/export,
with **40.10 GiB** worker RAM and zero swap. This is a safety check, not a speedup
or complete block-finalization measurement. Historical/external verifiers still
need explicit reconciliation; live crash cases here precede verification.
The separate real-CPU guard test covers in-process owner-handle loss, not an OS
process crash during active verification. Proof/journal encodings and production
defaults remain unchanged.

The earlier [controlled arrival/reuse checkpoint](evidence/block-v2-cpu-arrivals-2026-10-02.json)
passes **15 real CPU proofs**: three single-wallet wrappers, five empty subtrees
and seven merges, producing a **level-six/count-three** root. The third selected
transaction reuses the three completed two-wallet jobs; sealing freezes that
selection, and a later fourth transaction is deferred. A fresh CPU process
verifies the **1,683,948-byte** root using only its registry and proof, rejecting
a wrong expected root and a proof mutation. Debug inner artifacts are retained;
this checkpoint does not claim pruning.

Validation includes **128 selected native tests, thirteen explicit CPU checks
and ten Zig calculator tests**. Separate current-layout SingleWallet registrations
reproduce the keys byte-for-byte; native Zig independently derives the expected
ordered root. Fixture-to-root time is **2,508.284 s (41.805 min)** and
seal-to-root time is **2,004.169 s (33.403 min)**. The latter already exceeds
180 seconds and excludes complete host finalization. Peak worker RAM is
**40.44 GiB**, mapped spill **31.934 GiB**, swap zero. This is a controlled
join-split fixture with a two-hour research deadline, not live networking,
issuance/HTLC, full64, production deadline admission or security approval.
All eight public fixtures are initially loaded; selection admission simulates
arrivals. Production defaults and activation remain unchanged.

The earlier [worker-start recovery checkpoint](evidence/block-v2-cpu-worker-start-2026-10-02.json)
adds an immutable task-bound startup identity, allowing recovery when the
coordinator missed a worker's live process. Live kernel capture takes precedence
over the durable record, including during its temporary hard-link publication
window. **122 native tests, eleven explicit CPU checks and nine live
lifecycle/proof/replay stages pass**, with no compiler warnings. The new
two-transaction proof is **1,683,948 bytes**, taking **164.410 seconds** from
dispatch through acceptance/export; initial admission/publication is excluded.
Worker peak RAM was **39.80 GiB**, mapped spill **31.67 GiB**, swap zero.
The startup record is not a stop receipt: exact process/cgroup termination and
the idle launch gate are still required. Missing or partial identity without a
live observation remains quarantined. Concurrent verifier recovery, physical
quotas/retention, full operation/arrival coverage, full64/complete post-seal gates,
full-tree security and activation remain open. This is recovery qualification,
not a matched speedup or a production-ready block path.

The earlier [CPU process checkpoint](evidence/block-v2-cpu-process-2026-10-02.json)
adds an autonomous CPU worker, executable/configuration-bound launches and
immutable local task/result files. **87 native checks and seven CPU fixture
checks pass**, plus actual-process check/prove runs and fresh raw-node replay.
The new two-transaction proof is **1,683,948 bytes** and took **178.290 seconds**
through dispatch/execution, pinned process/cgroup shutdown checks, owner
verification/acceptance and export; initial admission/task publication is excluded.
Durable OS supervision, physical scratch quotas, full operation/arrival coverage,
full64/complete post-seal gates, full-tree security and activation remain open.
This is an experimental process boundary, not production qualification.

The later [live supervisor checkpoint](evidence/block-v2-cpu-supervisor-live-2026-10-02.json)
passes **105 native tests, nine explicit checks and six live stages**: check,
live cancellation, intentional coordinator exit, fresh-actor recovery, actual
WrapPair proving and independent CPU replay. Recovery confirms the recorded
worker's kernel exit before rebase and does not revive historical eligibility;
this crash occurs before coordinator verification starts. The proof is
1,683,948 bytes and takes **193.623 seconds** from dispatch through
acceptance/export, excluding earlier admission/publication. Worker peak RAM is
42,604,490,752 bytes, spill peak 34,003,439,616 bytes and swap zero. Neither the
64-transaction nor complete post-seal gate is demonstrated. Unseen-launch
liveness, concurrent verifier recovery, global admission/quotas/retention,
full operation coverage and soundness/ZK review remain incomplete.


The [GPU opening-consumer component](evidence/block-v2-gpu-openings-2026-10-01.json)
has passed exact cubic reductions, same-seed proof/challenger equivalence with
preprocessing, pending-event cleanup and small full-strength CPU-verified proofs.
The subsequent [runner/controller checkpoint](evidence/block-v2-gpu-openings-runner-2026-10-02.json)
now binds opening selection, source/executables and separate transfer counters in
the bounded recursive workflow. Validation includes 35 controller tests, 27
selected native library tests, 14 runner/common tests, 24 actual executable
rejection cases, three lifecycle tests and 11 explicit GPU regressions. These
are scoped checks, not a unique-test total or recursive performance qualification.

All three full-size preprocessing keys match independent CPU registration.
The subsequent [opening-enabled recursive trial](evidence/block-v2-gpu-openings-recursive-2026-10-02.json)
now passes the complete count-eight/seven-proof workload, local inner-artifact
pruning and independent CPU-only root audit: **686.046 seconds**, a
**1,683,948-byte** root and **92.427-second** final merge. All seven expected
opening calls were observed. The audit rejects 38 native mutations, four registry
policy mutations and two expected-statement policy mutations without inner proofs.
The shared CPU fixture is retained for controls; no shared-fixture pruning is claimed.

The [fresh same-build retained control](evidence/block-v2-gpu-openings-matched-pilot-2026-10-02.json)
also passes in **607.112 seconds**, with a **71.812-second** final merge and the
same root size. Resident commitments/GPU openings were **13.002% slower** in this
single pair. Promotion is withheld; this does not isolate the opening consumer's
contribution from the resident backend. At least five alternating matched pairs
remain required before an eventual speedup claim. Full64, complete post-seal,
full-tree soundness/ZK, arrival-driven DAG integration and host integration remain open.

The first [local execution contract](evidence/block-v2-local-job-contract-2026-10-02.json)
established bounded public artifacts, semantic job identities and CPU-verified
result tickets. The subsequent [in-memory DAG checkpoint](evidence/block-v2-local-dag-2026-10-02.json)
now implements dependency readiness, candidate sealing/cancellation, frozen
input manifests, attempt fencing, aggregate reservations and bounded pruning.
**21 structural checks** (including 15 DAG checks) and the separate pinned
eight-wallet/root CPU replay pass. A shuffled 127-node graph test uses synthetic
artifacts; it is **not a full64 recursive proof**. The subsequent
[Linux artifact-store checkpoint](evidence/block-v2-artifact-store-2026-10-02.json)
adds private bounded storage, atomic publication, interrupted-write cleanup and
CPU re-verification after reopening. The subsequent
[snapshot-journal checkpoint](evidence/block-v2-journal-2026-10-02.json)
adds durable graph reconstruction, fresh-session fencing, an explicit unresolved
worker/verifier reconciliation boundary and reference-aware garbage collection.
**48 native checks** and three explicit pinned CPU replays passed that checkpoint;
nine abrupt-exit cases run inside two native checks. The subsequent
[CPU-adapter checkpoint](evidence/block-v2-cpu-worker-2026-10-02.json)
passes **52 native checks and four explicit CPU fixture checks**, plus one
separately bounded real paired-wrapper generation and a fresh-process replay.
The new 1,683,948-byte pair proof passed durable acceptance/recovery in a
231.705-second leased execution path. This is two transactions, not a full block.
Historical candidates are not revived as host eligibility. OS worker supervision,
complete operation coverage and arrival-driven integration remain open; this is
not a production proving service.

The subsequent [single-use launch gate](evidence/block-v2-launch-fencing-2026-10-02.json) now
passes **69 execution native checks and four explicit CPU fixture checks**.
It binds exact CPU leases/resources, persists one-use worker admission and
irreversible revocation, and rejects delayed or duplicate starts. Ten new
abrupt-exit cases and an owned live-child lock/reap check pass. This is local
launch fencing, not OS supervision, a new block proof or a performance result.
The supervisor must still confirm exact process/cgroup exit and verifier drain
before releasing reservations; request transport and physical enforcement remain open.

The subsequent [bounded CPU packet checkpoint](evidence/block-v2-worker-packets-2026-10-02.json)
passes **77 execution native checks and six explicit CPU fixture checks**.
One new guarded, packet-driven paired-wrapper proof passed independent owner
verification/durable acceptance and fresh-process raw-node replay: **1,683,948
bytes**, **185.854 seconds** through acceptance/output publication. This covers
two transactions, not a full block or post-seal benchmark. Decoding conveys no
scheduler or proof-validity authority. The later [CPU process checkpoint](evidence/block-v2-cpu-process-2026-10-02.json)
adds the executable and local transport. Durable OS supervision, physical quotas,
complete operation coverage and arrival-driven qualification remain open.

The latest [banded host-readback checkpoint](evidence/block-v2-gpu-readback-2026-10-01.json)
passes selected native/GPU regressions, independent CPU key reproduction, and
one full-strength count-eight recursive proof with local pruning and CPU-only
root audit: **783.952 seconds**, **1,683,948 bytes**, and an **81.324-second** final
merge. Decode includes reorder time. The [fresh retained control](evidence/block-v2-gpu-readback-matched-pilot-2026-10-01.json)
passes in **623.868 seconds**, with a **72.412-second** final merge and the same
root size. Resident mode remains **25.660% slower in this one pair**, and
performance promotion is withheld. Repeat qualification remains open. The initial pressure timing control was excluded
because it used sequential rather than production Rayon scatter; its corrected
Rayon pressure rerun and all seven GPU regressions now pass. Source-archive
comparison proves the subsequent changes are test-only. None of this closes full64, complete post-seal,
full-tree security, host-integration or production-activation gates.

The latest [compact-node-codec checkpoint](evidence/block-v2-fixed-node-codec-2026-10-01.json)
resolves the wide23 envelope blocker at **1,683,948 bytes** under unchanged
2 MiB limits. Default/wallet encoding remains unchanged; the opt-in registry
binds `LBV2RC02`, codec revision two and program manifest six. Default/wide
native and CLI regressions, ABI/Zig checks and six preserved default root replays
pass. Fresh geometry remains 262,144 rows / 29.5 GiB retained-LDE estimate.
The candidate keys now match across two independent registrations, and the
external statement is pinned through native Zig/Rust checks. The first
full-strength eight-transaction candidate run now passes recursive closure and
preserved CPU root-only auditing after local inner-artifact pruning. The
**1,683,948-byte** root took **19.440 minutes** of recursive-command time; the
final merge took **157.817 seconds**. Peak proving-worker memory was **40.000 GiB**,
with zero swap. This is one level-three/count-eight CPU observation, not a
matched speedup or a measurement of complete post-seal finalization.
Padded/depth-six/64-transaction qualification, full-tree security and activation
remain open.

The subsequent [resident hiding-PCS integration](evidence/block-v2-gpu-resident-pcs-2026-10-01.json)
passes CPU-equivalent commitments/openings and small full-strength cubic proof
replay, including active-clone randomness sequencing and explicit research-mode
selection. Seventeen explicit GPU tests and the 248-test broad GPU-feature
library regression pass. These are adapter/component checks, not a recursive
block benchmark or security audit. The subsequent
[bounded GPU grouped workflow](evidence/block-v2-gpu-grouped-workflow-2026-10-01.json)
passes 30 controller tests, 18 executable rejection checks, and three synthetic
service-lifecycle checks. All three full-size resident preprocessing keys now
match the independently registered compact-profile CPU keys. The
[first full-strength resident-GPU count-eight run](evidence/block-v2-gpu-grouped-resident-proof-2026-10-01.json)
now passes local inner-proof pruning and preserved CPU-only root auditing, with
a **1,683,948-byte** root in **14.035 minutes** recursive-command time and an
**84.524-second** final merge. This is one sample, not a matched speedup claim or
complete post-seal measurement. The subsequent
[matched pilot](evidence/block-v2-gpu-grouped-matched-pilot-2026-10-01.json)
passed both CPU audits but measured **10.554 minutes retained / 14.035 minutes
resident**: the resident path was about **33% slower in this one pair**.
Performance promotion is withheld. Repeated comparison, full64/deadline
qualification and complete-tree security review remain open; activation is unchanged.


The latest [bounded-execution checkpoint](bounded-execution-engine.md#current-measurement-and-implementation-checkpoint--2026-10-01)
now includes five completed matched retention-off/on pairs with serial transfers
held fixed. Retention reduced median recursive proving time from **19.627 to
17.642 minutes (10.114%)**, improving total time in all five pairs. Final-merge
median was 170.902 / 167.426 seconds off/on, but the worst observed final merge
increased from **187.451 to 201.993 seconds**. Both variants exceeded three
minutes for the final merge alone in two trials. Retention stays experimental
and opt-in; CPU defaults and security parameters are unchanged.

All ten roots plus the retained pilot passed fresh unchanged CPU verification
after the shared wallet-proof fixtures were pruned. Each rejected 38 native and
four registry-policy mutations, with no inner proofs loaded. The
[complete evidence record](evidence/block-v2-retention-matched-2026-10-01.json)
includes the measurements, source pins, resource limits and bounded replay.
This closes the retention comparison, not full-block feasibility. The grouped-eight
CPU prototype completed four paired wrappers and three merges. Its **1,914,091-byte**
root passed separate fresh CPU replay after pruning all 14 local inner artifacts.
Proving stages took **33.133 minutes**, with a **280.993-second** final merge and
**40.010 GiB** maximum proving-stage cgroup memory, zero swap. Research keys were
separately reproduced and the external expected statement derived with native Zig.
This is one level-three/count-eight sample, not production-profile approval or
a same-eight/backend speed comparison. See the [grouped evidence](evidence/block-v2-grouped-integration-2026-10-01.json).
The later [same-eight CPU pilot](evidence/block-v2-eight-matched-pilot-2026-10-01.json)
completed both constructions using identical wallet-proof bytes: **69.941 minutes
single / 33.552 minutes grouped**, a **52.028%** reduction in this one pair.
The final merge was **264.760 / 287.332 seconds**, so grouping did not improve
that latency in the pilot. Both roots passed recorded CPU audits after local
inner-artifact pruning. Shared wallet fixtures remain retained for the required
five-pair series and final post-shared-pruning replay. Neither repeated nor
production qualification is claimed. The earlier 2026-09-30 measurements below
remain historical evidence.

The [opt-in quotient-fusion candidate](evidence/block-v2-quotient-fusion-2026-10-01.json)
now has component equivalence tests, small full-strength proof replay through the
original CPU PCS, 204 passing CPU library tests and exact full-size reproduction
of all three original grouped preprocessing caps. A separately pinned controller
enforces the full-size compatibility gate, explicit mode/operation telemetry and
the preserved root auditor. The full eight-wallet fused root passed that auditor
after local inner pruning, plus an additional independent CPU replay: **1,913,701
bytes**, **28.983 minutes** total recursive-command time, **252.026 seconds** for
the final merge alone. The completed [same-binary off/on comparison](evidence/block-v2-quotient-fusion-matched-2026-10-01.json)
measured **32.198 / 28.983 minutes**, a **9.983%** reduction in one pair, and
**270.047 / 252.026 seconds** for the final merge. Both roots passed additional
CPU-only replay; retained spill was identical and worker memory essentially
unchanged. Fusion remains opt-in; repeated performance, complete finalization,
depth-six and complete-tree security gates are unmet. No verifier, wire format,
security parameter, C ABI or production default was changed. The separate
[five-pair original single/grouped series](evidence/block-v2-eight-repeated-series-2026-10-01.json)
has started; shared and registration wallet fixtures remain retained until all
consumers finish, followed by the required pruning and fresh root replays.

The approved [incremental recursive block-proving v2 plan](block-proving-v2.md) is
**CANDIDATE / INACTIVE**, outside the frozen audit. The bounded verifier and
wrapper/empty/merge builders now have **real two-level recursive proof evidence**:
four wallets → four wrappers → two sibling merges → final merge. The
1,913,373-byte root verified in a fresh process after all ten inner files were
deleted, and repeat root-only checks passed. The separate artifact checker rejected
38 native mutations and four registry-policy mutations.

The seven serial recursive proving stages took 34.002 minutes, with a peak
proving-service memory measurement of 40.015 GiB and 44.184 GiB peak mapped spill,
zero swap. This is one CPU/disk-backed four-transaction sample, excluding original
wallet proving/registration and failed trials—not the 64-transaction performance
gate. Common-height padding, depth-six proving, full-tree soundness/zero knowledge,
HTLC/issuance, and host integration remain open. Five bounded GPU-hashing trials
also passed: 23.396 minutes median, 24.488 minutes worst, with roots below 2 MiB.
All five roots passed CPU replay and the unchanged artifact checker after shared
wallet-proof pruning. No controlled CPU/GPU speedup or production qualification
is claimed; the final merge alone took 183.645 seconds median.

See the [execution-engine evidence and remaining gates](bounded-execution-engine.md).
The separate artifact checker shares the native verifier; it is not an independent
security audit. New constraints, authenticated cap-path hints, registry/profile
binding, the bounded decoder, and allocator ownership all require delta review.
Historical v1 verification and the default twelve-symbol development ABI remain
unchanged, with no recursion/v2 acceptance symbols.

Earlier A1 diagnostic evidence, predating the verifier/program implementation:

The gated `block-v2` cubic-profile JoinSplit probe and checked resource lower-bound instrumentation
are implemented, with no C ABI. The [reproduction command](block-proving-v2.md#phase-a-diagnostic-reproduction--experimental-not-an-aggregate-benchmark)
proves a candidate leaf and separately inspects legacy q96/F_p² geometry; it completed with exit 2 /
`BLOCKED`, without allocating or creating an aggregate. The binary/all-features compile checks,
targeted candidate tests (13 passed), the Rust library regression (112 passed / 19 intentionally ignored),
the default ABI gate (12 externs, zero recursion/`block_v2` symbols), and Zig/ReleaseSafe FFI tests
passed. These are uncommitted-worktree checks, not independent audit. The legacy trace-commit lower bound is
about 24.44× the 128 GiB scratch budget; this excludes inherited-backend reuse within the budget,
not the possibility of a redesigned fixed-width verifier. Leaf smoke observations and conditional composition accounting
are in the [evidence ledger](block-proving-v2.md#evidence-ledger--implementation-checks-captured-2026-09-29).
A leaf probe, resource estimate, or composition-loss helper is not a passed recursive gate.

The target is wallet-local witnesses, public-only aggregation, and one final proof ≤2 MiB for up to
64 total transactions including issuance, using a new ordered Merkle commitment and a separate
candidate profile. Workstation gates are 48 GiB RAM / 12 GiB VRAM / 128 GiB scratch at the planned
12-minute cadence. Individual-proof containers in blocks and direct witness-based batches are
excluded deployment paths, not fallbacks; hash/FRI recursion must not use a curve/SNARK wrap.

There is **no production-ready block-proving path satisfying these requirements**. Join-splits,
HTLCs, and issuance must all be covered before live activation. The frozen CPU review below remains
evidence for its named artifact only; it does not establish v2 feasibility or live-network readiness.

## Frozen CPU baseline — historical completion

**Status (2026-07-06): COMPLETE — W1–W10 done; artifact frozen at the `v3-batch-audit` tag.** Batch aggregation has a constraint-by-constraint audit (`batch-constraint-audit.md`), C-ABI verifier fuzz (`tests/fuzz_batch.rs`), a four-lens internal adversarial round + remediation (`v3-batch-internal-audit.md` — no critical/high break; F1/F2 fixes), an evidence pass, and a handoff (`v3-batch-audit-handoff.md`). The tagged tip **additionally carries the full external-scope security audit** (`v3-external-audit-report.md` — five adversarial lenses over the join-split + HTLC circuits, the C-ABI/verify boundary, the Zig node, and crypto/ZK: no critical/high) **and its M-EXT-1 (proof malleability) + L-node (mint parity) remediations**, all re-validated (Rust 102 passed / 0 failed, `zig build test` green). The production CPU path is audit-ready; recursion/GPU/streaming stay research/out-of-gate. Entry points: `docs/AUDITORS.md` + `docs/v3-batch-audit-handoff.md` + `docs/v3-external-audit-report.md`; closed findings in `docs/remediation-status.md`.

## 1. Assessment — the three questions

**1.1 Is the CPU prover production-ready? — Yes, within the frozen scope.** There is one production config (`lattica-prover-p3/src/config.rs` — `HidingFriPcs` over the CPU `Radix2DitParallel` DFT + salted `MerkleTreeHidingMmcs`, four random codewords, FRI `log_blowup=4` / `96` queries / `pow_bits=16` / `cap_height=6`), one canonical serializer, and one fail-closed verification core. The four production circuits and the ten-symbol ABI frozen at `v3-batch-audit` funnel through it. The current branch's additional proof-tree container seam is later development and is not automatically audited.

**1.2 Are the GPU / streaming / recursion implementations production-ready? — No.** All three are opt-in and outside the frozen audit. The ABI-symbol gate confirms that no recursion symbol enters the default static library. GPU and streaming remain alternative proving backends under the unchanged verifier. The twelve-symbol development ABI includes a non-recursive proof-tree container, not the feature-gated recursive aggregator.

**1.3 Has the codebase been refactored for simplicity/auditability? — Yes, essentially complete.** The 2026-07-02 A1–I8 whole-crate refactor added a constraint-fingerprint oracle (`src/constraint_fingerprint.rs`) that mechanically pins every production AIR's `(width, periodic, publics, n_constraints, max_degree, fnv)` so any motion/dedup is provably constraint-preserving; single-sourced the FRI config + domain tags (killing 8×/6× literal duplication); deleted a ~150-line duplicated constraint fork (`eval_spend`); collapsed the ABI to one fail-closed core; split the 8,181-line monolith into six files; and quarantined every superseded AIR behind `cfg(test)`. Production code now carries **0 TODO/FIXME, 1 clippy-allow, 2 dead-code allows**. The only deferred item is test-only churn inside the research recursion module — no open production-refactor work.

## 2. Frozen baseline and later development

The original `v3-audit` artifact was followed by a 222-commit production delta containing batch aggregation, a constraint-fingerprint-guarded crate refactor, and exchange deposit mode. That delta completed the W1–W10 review track below and is frozen at `v3-batch-audit`.

The tag, rather than the mutable branch tip or a dirty working tree, is the reproducible audit baseline. Later changes must preserve the frozen ABI and constraint fingerprints or receive explicit delta review. Feature-gated GPU, streaming, and recursion work remains outside the baseline even when its tests pass.

At RC `8be9b17`, the default suite reported **102 passed / 20 ignored**, all 20 ignored audit gates passed when run explicitly, the ABI-symbol gate confirmed ten production externs and zero recursion symbols, and the real Zig/Rust integration passed the individual and batch paths. The subsequent external-scope audit and remediations are included in the tagged artifact.

## 3. Roadmap — the batch-delta audit-readiness track (W1–W10)

| WS | What | Status | Artifact |
|---|---|---|---|
| **W1** | Feature-gate research (recursion/gpu/stream) out of the production staticlib + an ABI-symbol gate | ✅ | `lattica-prover-p3/scripts/check-abi-symbols.sh` (green) |
| **W2** | Batch C-ABI fuzz / adversarial tests | ✅ | `lattica-prover-p3/tests/fuzz_batch.rs` (`772dffb`) |
| **W3** | Batch constraint-by-constraint self-audit | ✅ | `docs/batch-constraint-audit.md` (`b87fe4f`) |
| **W4** | Audit-doc truth pass — stale claims / scope / repro numbers | ✅ | `AUDITORS.md`, `audit-scope-p3.md`, `production-readiness.md` (`d97c1f1`) |
| **W5** | Internal adversarial round on the batch delta (4 lenses) | ✅ | `docs/v3-batch-internal-audit.md` (`8be9b17`) |
| **W6** | Fix wave (F1 verify-cap, F2 overflow, OBS-1 debug-panic, OBS-2 oracle) | ✅ | `8be9b17` (validated green) |
| **W7** | Full gate-run evidence pass at the RC commit | ✅ | RC `8be9b17`: 102/20, `--ignored` 20, ABI gate + real integration green |
| **W8** | New external handoff for the batch tip | ✅ | `docs/v3-batch-audit-handoff.md` |
| **W9** | Final consistency sweep | ✅ | this doc |
| **W10** | Maintainer tags `v3-batch-audit` (freeze the artifact) | ✅ | tagged `v3-batch-audit` (this commit) |

The batch-delta track is **complete (W1–W10)** and the artifact is frozen at the `v3-batch-audit` tag,
which also carries the full external-scope audit + its remediations. Scope was the **production-surface
delta only** — recursion/GPU/streaming research are explicitly out.

## 4. Standing auditor sign-off items

- **~103-bit *proven* soundness** (~127 conjectured) — the Goldilocks `F_p²` ceiling; raising it is a field migration. Machine-checked (`proven_security_meets_production_floor`, asserts ≥100). **The one deliberate parameter needing explicit auditor acceptance** (`docs/soundness-budget.md`).
- **A dedicated Poseidon2 parameter / algebraic-attack review** — requested in `audit-scope-p3.md` §2, deferred to audit time (the RO/CR assumption underpins every hash binding).
- **A4 residuals** — the untagged Merkle `merge` (collision would need a Poseidon2 preimage/collision) and the **`rho`-uniqueness invariant on note creation** (a protocol-level assumption flagged for the auditor).
- **Batch ABI fuzz / adversarial coverage** — completed as W2 in the frozen baseline; new v2 interfaces and recursive constraints require their own coverage and review.

## 5. Scope — out of the lattica audit gate (reaffirmed)

- **Host chain `rubble-node-zig`** — block consensus/PoW/mempool/networking/emission, reorg undo, header-committed roots, and the production release gates in `docs/full-node-security-integration.md` (including the additional v2 gate). `node.zig` here is an in-memory state machine; the lattica-side P-01 enablers (`stateRoot`/`eventRoot`/`positionOf`/`applyHtlc` height-pinning) are built for the host chain to bind.
- **Cross-chain `rubble-xchain-xfer`** — the HTLC engine / swap protocol / Phase-B `await_lock`/timeout cushion.
- **GPU / streaming / recursion** — research and feature-gated (§1.2). Existing alternate proving backends preserve the legacy verifier; v2 is a separate candidate family, not an implicit verifier upgrade.
- **Wallet / prover key management + note discovery.**

## 6. Doc hygiene + batch-delta artifacts + see also

The doc-truth pass (W4) corrected stale claims that would mislead an auditor: the reproduction test counts in `AUDITORS.md` §3, the "coinbase/mint/burn not yet modeled" line and the C-03 checklist row in `audit-scope-p3.md`, an explicit out-of-scope listing for GPU + streaming, a hardened historical banner on `production-readiness.md`, and the crate-relative path to `check-abi-symbols.sh`.

**Batch-delta audit artifacts (W2–W8):** `docs/v3-batch-audit-handoff.md` (the handoff — start here for the delta), `docs/batch-constraint-audit.md` (constraint-by-constraint audit), `docs/v3-batch-internal-audit.md` (the four-lens adversarial round + F1/F2 remediation), `lattica-prover-p3/tests/fuzz_batch.rs` (C-ABI verifier fuzz).

**See also:** `docs/AUDITORS.md` · `docs/audit-scope-p3.md` · `docs/remediation-status.md` · `docs/soundness-budget.md` · `docs/full-node-security-integration.md` · `docs/gpu-acceleration.md` · `docs/recursion-aggregation-status.md`.

**See also:** `docs/AUDITORS.md` (handoff) · `docs/audit-scope-p3.md` (scope/threat model/frozen params) · `docs/remediation-status.md` (closed findings) · `docs/soundness-budget.md` (the proven floor) · `docs/full-node-security-integration.md` (host-chain gates) · `docs/gpu-acceleration.md` · `docs/recursion-aggregation-status.md`.
