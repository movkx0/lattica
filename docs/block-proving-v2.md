# Incremental recursive block proving v2

The [compact opening full-workload continuation](evidence/block-v2-gpu-opening-compact-recursive-2026-10-02.json)
now passes all three independently registered CPU-cap comparisons and one
eight-wallet/seven-proof root-only CPU audit after local inner-proof pruning.
The root is **1,683,948 bytes**; proving commands took **606.828 seconds** and
the complete controller **609.075 seconds**. Peak worker RAM was **32.320 GiB**,
sampled VRAM **6,856 MiB**, and swap zero. All seven expected compact opening
calls were recorded. This is a level-three/count-eight subtree, **not** the
level-six/full64 or complete post-seal gate. Same-build matched controls and
repeat qualification remain open; no performance promotion or activation.

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

The [live CPU supervisor checkpoint](evidence/block-v2-cpu-supervisor-live-2026-10-02.json)
extends the native LVOSR001 journal tests with actual check/cancel, coordinator
exit/recovery, full-strength pair proving and fresh CPU replay. **105 native
checks, nine explicit checks and all six live stages pass**. The supervisor
uses an exec-startup barrier, persists exact process identity and requires
kernel stop evidence independently of helper exit status. Recovery before
verifier startup releases the old lease only after reconciliation and does not
revive host eligibility. The pair proof is 1,683,948 bytes and takes
**193.623 seconds** dispatch-to-acceptance/export: no full-block/post-seal or
speedup claim. Same-boot unseen launches remain quarantined; concurrent verifier
recovery, unique runtime admission, physical quotas and retention remain open.


Latest [opening-enabled recursive checkpoint](evidence/block-v2-gpu-openings-recursive-2026-10-02.json):
the default-off opening consumer is integrated with source/config-bound runner
accounting. Independent full-size keys match CPU registration, and the complete
eight-wallet/seven-proof workload passes local pruning and CPU-only root audit.
The [fresh same-build pilot](evidence/block-v2-gpu-openings-matched-pilot-2026-10-02.json)
measured **686.046 seconds** with resident commitments/GPU openings versus
**607.112 seconds** with retained hashing, both with a **1,683,948-byte** root.
The new backend was **13.002% slower** in this pair and is not promoted. This
does not isolate opening offload from resident commitments; an additional
resident/openings-disabled control would be needed for that attribution.
Host LDE materialization and upstream FRI work remain. Repeat qualification,
arrival-driven DAG integration, full64, complete post-seal, full-tree security and
production activation remain open.

The [local execution contract](evidence/block-v2-local-job-contract-2026-10-02.json),
[in-memory DAG](evidence/block-v2-local-dag-2026-10-02.json) and
[artifact store](evidence/block-v2-artifact-store-2026-10-02.json) are now joined by
a validated [snapshot journal](evidence/block-v2-journal-2026-10-02.json).
**48 native checks and three explicit CPU replays pass.** Recovery reconstructs
the graph, re-verifies stored proofs, fences old sessions and requires explicit
unresolved-worker reconciliation. Candidate eligibility is never automatically
restored. Journaled reference removal precedes artifact garbage collection.
The subsequent [CPU adapter](evidence/block-v2-cpu-worker-2026-10-02.json) passes
52 native checks, four explicit CPU fixture checks, one separately bounded real
paired-wrapper generation and fresh-process replay. Its 1,683,948-byte level-one
proof passed durable acceptance/recovery in a 231.705-second leased execution
path; this is not a block or post-seal measurement. OS worker supervision,
complete operation coverage, host eligibility and arrival-driven qualification
remain open. The synchronous adapter relies on its runtime for resource enforcement.

The subsequent [single-use launch gate](evidence/block-v2-launch-fencing-2026-10-02.json)
passes **69 execution native checks and four explicit CPU fixture checks**, with
ten new abrupt-exit cases and a live-child lock/reap check. Exact lease/resource
binding, durable once-only entry and irreversible revocation fence duplicate and
delayed starts. This remains local metadata: request decoding/transport, exact
OS service/cgroup reconciliation, physical enforcement and arrival integration
are not implemented by the gate. An idle lock is not a termination acknowledgement.
See the [runtime contract](bounded-execution-engine.md#durable-single-use-cpu-launch-gate--2026-10-02).

The subsequent [bounded CPU packets](evidence/block-v2-worker-packets-2026-10-02.json)
pass **77 execution native checks and six explicit CPU fixture checks**, plus one
new guarded paired-wrapper generation, owner CPU verification/durable acceptance
and independent raw-node replay. The 1,683,948-byte proof took 185.854 seconds
through acceptance/output publication, excluding initial fixture/admission/launch
work. This covers two transactions, not a full block or complete post-seal gate.
Packets contain only public artifacts and bounded local metadata; result decoding
grants no proof-validity or scheduler authority. The subsequent
[CPU process checkpoint](evidence/block-v2-cpu-process-2026-10-02.json) adds the
executable and immutable local transport. Durable OS supervision, physical quotas
and arrival-driven qualification remain pending.

The [bounded CPU execution engine](bounded-execution-engine.md) now demonstrates
four real wallet proofs → four wrappers → two sibling merges → one final merge.
The **1,913,373-byte** root verified in a fresh process after deleting all ten
inner artifacts. A separate checker rejected 38 native mutations and four
registry-policy mutations, and repeated root-only checks passed.

> **Authoritative architecture and milestones — CANDIDATE / INACTIVE.**
> The four-transaction/two-level implementation milestone is demonstrated, not
> the full feasibility or release gate. Complete-tree soundness/zero-knowledge
> review, general padding coverage, depth-six/64-transaction performance,
> full transaction coverage, and network integration remain incomplete. Real
> common-height padding of eight transactions to level six is now demonstrated.

All new candidate code is gated behind `block-v2`, with no new C ABI. Common
geometry closes at height 524,288 with a 39 GiB retained-LDE lower bound. After
two unsuccessful memory-workspace trials, the selected CPU/disk-backed run
completed seven serial proving stages in **2,040.123 s** with a peak proving-service
memory measurement of **40.015 GiB**, zero swap, and **44.184 GiB** peak live
mapped spill. Original wallet proving/key registration and failed trials are
excluded from that duration. This is one four-transaction sample, not a passed
64-transaction/ten-minute cold or three-minute finalization benchmark. A later
[bounded GPU-hashing series](bounded-execution-engine.md#gpu-hashing-experiment-2026-09-30)
passed five trials in 23.396 minutes median and 24.488 minutes worst, with all
roots below 2 MiB and CPU-only replay after shared wallet-proof pruning.

The latest [2026-10-01 checkpoint](bounded-execution-engine.md#current-measurement-and-implementation-checkpoint--2026-10-01)
records five matched transfer-mode pairs (only 3.005% median improvement), followed
by five matched retention-off/on pairs with serial transfers held fixed. Retention
reduced median proving time from **19.627 to 17.642 minutes (10.114%)**, but its
worst observed final merge increased from **187.451 to 201.993 seconds**. All ten
retention roots plus the retained pilot passed unchanged CPU verification after
shared-fixture pruning. Retention and overlap remain experimental/opt-in; neither
qualifies 64-transaction performance or production activation. The
[retention evidence and decision](evidence/block-v2-retention-matched-2026-10-01.json)
select continued polynomial/data-movement work and a real eight-wallet grouped
proof prototype. The latter completed seven CPU recursive proofs and fresh
root-only replay after pruning 14 inner artifacts. Its root is **1,914,091 bytes**;
proving stages took **33.133 minutes**, with a **280.993-second** final merge.
This is one level-three/count-eight sample. A later
[same-eight CPU pilot](evidence/block-v2-eight-matched-pilot-2026-10-01.json)
completed in **69.941 minutes single / 33.552 minutes grouped**, a **52.028%**
total-time reduction in one matched pair. Final merge was **264.760 / 287.332
seconds**, respectively. Both roots passed recorded post-local-pruning CPU
audits. Repeated comparison, shared-fixture pruning/replay and all full-block
performance/security gates remain open.

## 1. Architecture and non-negotiable boundaries

Wallets generate hiding transaction proofs locally. Spending keys, private note data, authentication
paths, and other transaction witnesses stay in the wallet. Aggregators receive only completed proofs
and their public inputs/public transaction envelopes; no aggregator API accepts users' witnesses.
The producer's own issuance witness also stays in its wallet component.

The target transaction block contains public transaction data, encrypted outputs, and **one final
recursive aggregate proof**. Individual transaction proofs and intermediate aggregates are temporary
off-chain submission/aggregation artifacts, not retained in the block or required for historical block
verification. Recursion reduces proof overhead; it does not remove transaction data, ciphertexts,
state checks, or the off-chain bandwidth needed to submit proofs.

The following are excluded, including as fallback paths:

- Individual transaction proofs stored in blocks, including the development proof-tree container:
  storage and block-relay requirements grow roughly linearly with proof count.
- Direct witness-based batch proving: a block producer cannot require users' private witnesses in
  this permissionless, non-custodial architecture. Existing batch circuits remain legacy/test assets.
- Curve-, pairing-, or discrete-log-based proof wraps, including a SNARK wrap. Recursive proving
  must remain transparent and post-quantum in its assumptions: hash/FRI only, with no curve wrap.
- Reduced security parameters or multiple aggregate roots as a way to bypass a failed v2 gate.

### Approved acceptance targets, not measured capabilities

| Item | v2 target |
|---|---|
| Block commitment | New domain-separated, ordered binary Merkle tree with 64 leaves and six merge levels |
| Transaction capacity | At most **64 total transactions**, including issuance; this counts transactions, not notes or outputs |
| Transaction-block cadence | **12 minutes**, implemented by the host chain, not by this library |
| Final aggregate proof | At most **2 MiB**; public transaction data and ciphertexts are additional |
| Workstation host RAM | At most **48 GiB** across all proving workers |
| Workstation VRAM | At most **12 GiB** across GPU work |
| Workstation disk scratch | At most **128 GiB** across proving jobs |
| Cold aggregation latency | At most **10 minutes** for 64 already-valid wallet proofs, including wrapping and all merge stages |
| Incremental cycle policy | Reserve the final **3 minutes** for finalization; defer late or insufficiently prepared transactions |
| Block verification | CPU-capable, no GPU, no inner-proof archive, no private witnesses |

The resource limits are provisional acceptance/admission budgets, not a claim that existing recursive
code fits them. A gate failure stops promotion and is reported; it does not authorize relaxing a limit
or changing the architecture. The ten-minute cold workload and the three-minute incremental
finalization window are separate tests. Neither is a current throughput guarantee.

## 2. Candidate profile and bounded recursion

Introduce a separately versioned proof family; **historical v1 parameters, proof bytes, and verification
remain unchanged**. Here, v2 names the new block-proving family, not the repository's older v3 HTLC/audit
milestones. It must not silently replace the default v1 configuration.

| Candidate parameter | Selection |
|---|---|
| Base field / hash | Goldilocks / Poseidon2 |
| Challenge field | Cubic extension of Goldilocks |
| PCS and randomness | Hiding PCS; fresh, full-entropy CSPRNG randomness for every proof |
| FRI arity | Binary |
| FRI queries | `q = 128` |
| Blowup | `log_blowup = 4` (16×) |
| Merkle cap height | `6` |
| Random codewords | `4` |
| Query grinding | `16` bits |

These parameters are **not frozen** until fixed-geometry recursion and the soundness of the complete
maximum-size tree are established. CPU, GPU, and streaming implementations must share the same
registered profile. Deterministic seeds belong only in test interfaces; entropy failures must fail
closed. Backend equivalence is not a zero-knowledge security proof.

The security gate must account for leaf, empty/padding, merge, and root proofs; all relevant proof
instances and composition losses; actual trace geometry and degree; transcript/domain separation;
and profile/verifier-identity binding. Require at least the existing **100-bit proven-soundness
objective for the complete tree** under explicitly recorded assumptions. A per-proof floor, or the
minimum per-level bit count, does not establish that claim. Record the applicable hash and
Fiat-Shamir/quantum assumptions separately; a FRI bit estimate is not an end-to-end post-quantum
security certification.

The current source uses the 32-byte ASCII research label `LATTICA-BLOCK-V2-CANDIDATE-00001`.
It is **not a final cryptographic verifier/program identity or an activation identifier**. A reviewed
profile/program identity must bind the eventual recursive construction before any activation.

### Uniform recursive verifier — two-level proof demonstrated; release gate incomplete

The candidate execution engine replaces the expanding inner-specific monolith with a fixed-width, bounded-degree construction that
schedules verifier operations across rows, with a canonical bounded proof shape and three constrained
modes:

- **Leaf:** verify a registered transaction-proof type and bind its public statement.
- **Empty:** prove a canonical padding statement with zero real transaction count.
- **Merge:** verify two child proofs, bind their registered profiles/verifier identities, and combine
  ordered roots and counts at the correct subtree level.

Do not derive verifier geometry or trust verification keys supplied by an untrusted proof. The target
standalone verifier needs only **aggregate proof + expected public statement + registered profile**.
It must not receive inner proofs or reconstruct aggregation traces from them. The candidate research root verifier now meets this dependency boundary with a
pinned demo registry; the legacy monolith verification API still requires inner
proofs and rebuilds an instance. Neither API is a reviewed production acceptance
ABI. Disk-backed proving does not by itself establish recursion soundness or
deployment readiness.

### New ordered commitment

Leaf commitments bind transaction type, canonical public statement, chain identifier, and proof
profile. Internal commitments bind ordered child roots, subtree level, and counts. Canonical empty
leaves cannot stand in for omitted transactions or increase the real transaction count. Root
verification binds the expected depth, count, profile, and root recomputed from the block body.

Ordinary wallet proofs should not depend on block position or parent hash, allowing reuse as blocks
are assembled. Necessary transaction context remains binding, including HTLC execution height.
Rust and Zig commitment implementations require matching test vectors.

This tree is **not** the legacy `batchRoot` Merkle–Damgård fold. Exact v2 tags, identifiers, public-input
encoding, and proof-byte schema remain subject to implementation and review; this document does not
allocate them. The candidate boundary in [wire-format.md](wire-format.md) does not activate new bytes.

## 3. Incremental lifecycle and host boundary

1. **Submit:** canonicalize a public transaction envelope, run admission checks, verify its wallet
   proof, and cache verified work. Bound queues, workers, and cache storage; apply backpressure.
2. **Prepare:** wrap admitted proofs and merge compatible completed children while new transactions
   arrive. Reuse unaffected subtrees; replacement, eviction, or reordering rebuilds affected branches.
3. **Seal:** recheck state eligibility and freeze the ordered selection. New arrivals queue for a
   later candidate; they do not restart a sealed proof. HTLC height changes, conflicting spends,
   stale anchors, or reorgs may invalidate eligibility even when a cryptographic proof is cached.
4. **Finalize:** complete the six-level padded tree, enforce resource/proof-size/deadline gates, and
   return the single root proof. Failure returns an explicit not-ready/resource/error result, never
   a container, direct batch, lower-security proof, or automatic legacy acceptance.
5. **Verify and apply:** the node canonically decodes, enforces limits, recomputes the ordered root,
   checks anchors/nullifiers/heights/fees/authorized issuance/supply arithmetic, verifies the root
   proof, and applies all state changes atomically.
6. **Recover and prune:** bind cache entries to canonical statements, profiles, proof identities,
   and relevant context. On restart, validate cached artifacts before reuse. Interrupted jobs may
   restart; completed verified work is reusable. Prune off-chain artifacts after a bounded,
   configurable recovery window. Replay must still work after all such artifacts are removed.

Provide versioned wallet-proving, public-only leaf wrapping, pairwise merging, and root-verification
interfaces. Keep witness-bearing wallet APIs separate at type and ABI boundaries. The host-callable
coordinator targets submit/status/seal/cancel operations with bounded concurrency and explicit failures;
these are planned capabilities, not a claim that these APIs exist. A new feature/ABI gate and symbol
tests must keep the candidate family distinct from legacy interfaces.

Delivery covers Lattica's libraries, coordinator, block-application interface, simulation/test harness,
and integration documentation. It does **not** implement another repository's network, durable chain
state, consensus, emission policy, or activation. The host handoff must cover transaction selection,
deadlines, canonical block encoding, persistence, reorg/cache invalidation, activation, monitoring, and
job recovery. Operators need bounded disk usage, protected scratch storage, resource admission,
crash-safe cleanup, queue/deadline metrics, and incident handling before deployment.

### Selected execution DAG and GPU implementation direction

The [execution DAG and GPU implementation plan](dag-gpu-implementation.md)
defines the next implementation path within the existing candidate boundaries.
Use a dependency-driven DAG of approved wrapper/empty/merge jobs and prioritize
GPU transforms feeding commitments through retained device buffers, then
quotient/opening/FRI acceleration. Develop the minimal local DAG harness alongside
the GPU pipeline; a complete remote CPU pool is not a prerequisite.

The plan specifies module boundaries, exact job and device ownership contracts,
transcript barriers, resource admission, recovery and matched acceptance tests.
The [resident LDE/commitment executor](bounded-execution-engine.md#resident-gpu-ldecommitment-executor--component-validation)
now has real GPU component equivalence and failure-path evidence. The explicit
[hiding-PCS adapter](bounded-execution-engine.md#resident-hiding-pcs-adapter--small-proof-validation)
also passes interleaved CPU equivalence and small full-strength cubic proof replay.
The separate [bounded GPU grouped workflow](evidence/block-v2-gpu-grouped-workflow-2026-10-01.json)
passes controller, actual executable-rejection, and synthetic lifecycle checks.
Its three full-size resident preprocessing keys match the independently registered
CPU keys for the compact eight-wallet profile. The
[first complete resident-GPU run](evidence/block-v2-gpu-grouped-resident-proof-2026-10-01.json)
then passed local inner-proof pruning and preserved CPU-only root auditing:
**1,683,948 bytes**, **14.035 minutes** for seven recursive proofs and **84.524
seconds** for the final merge. This is one level-three/count-eight observation,
not a matched speedup or complete post-seal measurement. The subsequent
[one-pair comparison](evidence/block-v2-gpu-grouped-matched-pilot-2026-10-01.json)
passed both roots but observed **10.554 minutes retained / 14.035 minutes
resident**, about a **33% resident regression** in this sample. Do not promote
resident performance on this evidence. Repeated comparisons, the local DAG and
full64/deadline qualification remain open; this does not pass A3.
The ordered block commitment
and host consensus remain in force.
Historical experiments below retain their recorded scope and status.

The [banded host-readback checkpoint](evidence/block-v2-gpu-readback-2026-10-01.json)
now passes one complete count-eight recursive proof and CPU-only root audit after
local pruning: **13.066 minutes**, **1,683,948 bytes**, and an **81.324-second**
final merge. Host decoding is **69.628 seconds**, with reorder time included.
Changed-build keys match the independent CPU registrations. The [same-build
retained control](evidence/block-v2-gpu-readback-matched-pilot-2026-10-01.json)
passes in **10.398 minutes**, with a **72.412-second** final merge and the same
root size. Resident mode remains **25.660% slower in this one pair**; do not
promote it. Repeated comparison and the planned quotient/opening/FRI reuse remain
open. No full64, complete post-seal, security-review or activation gate is closed.

### Proposed distributed execution service

The [distributed proving roadmap](distributed-proving.md) specifies public-only
wrapper/merge jobs, externally pinned result verification, durable scheduling,
per-device GPU admission and recovery across workers. It is not implemented.
An experimental distributed harness does not pass A3 or authorize a production
coordinator. Report fleet resources separately: applying the existing limits
to each worker does not satisfy the aggregate workstation gate.

The unchanged 64-transaction/12-minute profile has a ceiling of 5.333 total
transactions per minute, including issuance. The roadmap's 100/1,000-user-tx/min
experiments require separately reviewed capacity/cadence, encodings, recursive
security and host activation; they do not change this document's targets.

## 4. Milestones and truthful status

| Milestone | Acceptance evidence required | Current status |
|---|---|---|
| A1: profile, security accounting, resource gates | Separate profile, fail-closed gates, parameter fingerprint tests; full-tree accounting distinguished from estimates | **PARTIAL**: candidate profile and resource controls implemented/tested; full-tree soundness and zero-knowledge accounting remain open |
| A2: uniform bounded recursive verifier | Leaf/empty/merge constraints, bounded geometry/degree, registered identities, standalone root verification | **CORE + CONTROLLED ODD-COUNT ARRIVAL ROOT PASSED**: count-eight padding and local-pruning replay, plus a real count-three/level-six SingleWallet arrival/reuse/seal sequence with fresh root-only CPU replay. Debug inner artifacts from the new trial are retained. Production registry approval, other counts, general padding and full-type coverage remain open |
| A3: measured recursive feasibility | Full-strength padded depth-six/64-transaction proofs, cold and incremental latency/resource gates | **OPEN**: compact-codec eight-transaction proving took 19.440 minutes; extending that subtree to a padded level-six root took 14.537 additional minutes. Full-count, repeated cold/incremental deadlines, mixed workloads, and full-block qualification remain open |
| B1: commitment and interfaces | Ordered64 Rust/Zig vectors, versioned public-only interfaces, feature/ABI tests | Native commitment tests and internal public-only wrapper/merge/root functions exist; reviewed wallet/node ABI and block integration remain planned |
| B2: incremental coordinator | Execution DAG, verified dependencies, arrivals, sealing, reuse, cancellation, backpressure, restart and pruning tests | **INLINE CACHE ADAPTER / SELECTED LIVE CPU CASES VALIDATED**: persistent workspace ownership and guarded per-job completion now retain real preprocessing across two full-strength paired proofs; fresh CPU replay passes. This is not an autonomous warm-worker service or matched speedup. Mixed-mode/arrival/deadline qualification, no-identity startup liveness, general external-verifier recovery, physical quotas/retention and full host eligibility coverage remain open; see [cached CPU checkpoint](evidence/block-v2-cached-cpu-2026-10-02.json). |
| B3: full block coverage | Join-splits first, then HTLC redeem/refund and coinbase/issuance; atomic mixed-block application | Planned; **all types required before live activation** |
| C: release qualification | Performance gates, cryptographic review, host integration and explicit activation | **INACTIVE / NOT PRODUCTION-READY** |

Do not build or promote the production coordinator past the mandatory feasibility gate on the strength
of a placeholder verifier, reduced-query proof, resource-plan estimate, or successful early-returning
test. Existing research results remain in [recursion-aggregation-status.md](recursion-aggregation-status.md):
the monolith's self-composition is size/degree-expanding, and recorded full-parameter streaming
preflights require terabytes of scratch. Those results are not v2 measurements.

### Performance engineering while A3 remains open

The matched transfer-overlap and retention investigations are complete. Overlap
improved median total time by 3.005%; retention improved it by 10.114% with serial
transfers held fixed. Both remain experimental and opt-in; their required roots
passed fresh CPU replay after shared-fixture pruning. The
[retention decision](evidence/block-v2-retention-matched-2026-10-01.json) selected
polynomial/data-movement work and a real eight-wallet grouped prototype.
That prototype passed recursive closure and root-only CPU replay. The subsequent
[same-eight CPU pilot](evidence/block-v2-eight-matched-pilot-2026-10-01.json)
measured 69.941 minutes for single wrappers and 33.552 minutes for paired wrappers.
Its grouped final merge was slower (287.332 versus 264.760 seconds).
This single matched pair supports continued grouping investigation, not backend
promotion, a production tail-latency claim, or either block deadline.
The repeated series remains unfinished. The separate opt-in
[quotient-transform fusion implementation](bounded-execution-engine.md#quotient-transform-fusion-experimental-implementation-and-gates)
passed component/native checks, including upstream-equivalent quotient outputs
and small full-strength proofs through the unchanged CPU PCS. A separately pinned
controller now gates full-size proving on exact registered-cap reproduction and
requires observed fused operations plus preserved-auditor root replay. The full
eight-wallet fused run passed these gates with a **1,913,701-byte** root after
local inner pruning: **28.983 minutes** total recursive-command time and a
**252.026-second** final merge. The completed [same-binary matched comparison](evidence/block-v2-quotient-fusion-matched-2026-10-01.json)
measured **32.198 minutes off / 28.983 minutes on**, a **9.983%** total-time
reduction in one pair. Final merge was **270.047 / 252.026 seconds**; retained
spill was identical and worker memory essentially unchanged. Both roots passed
additional CPU-only replay. Fusion remains opt-in: this is not repeated or
production performance qualification. The separate [original five-pair series](evidence/block-v2-eight-repeated-series-2026-10-01.json)
has started without fusion. Shared and registration wallet fixtures must still
be pruned after their consumers finish, followed by fresh root-only replay.
Padding, depth-six and mixed-workload qualification remain conditional on the
feasibility gate.

The [21-lane revision-two experiment](bounded-execution-engine.md#wider-lane-single-table-candidate-native-gate-failed)
is rejected: actual recursive feedback required 266,034 merge rows at the target
262,144-row height. At the resulting 524,288-row height, retained LDE data alone
required 56.625 GiB, exceeding the unchanged 48 GiB budget; the full-height
worst-case envelope also exceeded 2 MiB. No full-size keys or proofs were generated.
Its test-only registration-padding mismatch was corrected and focused session
tests passed in both layouts. The small real proof rejected all 17 mutations.

The default-disabled
[23-lane revision-three construction](bounded-execution-engine.md#23-lane-revision-three-candidate)
retains one AIR, 94 main columns, seven cubic lanes and all security/resource
limits. The [compact-codec continuation](evidence/block-v2-fixed-node-codec-2026-10-01.json)
resolves the earlier 2,849-byte envelope overrun with profile-bound `LBV2RC02`
encoding. The maximum-value template is **1,683,948 bytes**, including its
header. Wallets and default `LBV2RC01` artifacts remain unchanged.

Fresh post-codec common-height/usage checks still fit **262,144 rows**, with
160,893 wrapper, 384 empty and 258,973 merge active rows. The **29.5 GiB**
retained-LDE payload is an estimate, not measured proving memory. Default/wide
native tests, CLI/auditor tests, ABI/Zig validation and six-root default
compatibility replay pass. Candidate keys now match across two independent
registrations, and the external statement is pinned using native Zig plus Rust
registration checks. The first full-strength eight-transaction CPU run now passes
recursive closure and preserved CPU root-only auditing after deleting 14 local
inner artifacts. The root is **1,683,948 bytes**; recursive-command time was
**19.440 minutes**, with a **157.817-second** final merge. Peak proving-worker
memory was **40.000 GiB**, zero swap, with **31.934 GiB** peak mapped spill
(not additional RSS). This is one level-three/count-eight observation, not a
matched speedup or a complete post-seal measurement. Padded/depth-six/64-transaction,
mixed/incremental and full-tree security gates remain open. The legacy oversized
full-height encoding stays rejected; compact encoding cannot waive RAM admission.
No security parameter, production default or activation changed.

The [common-height padding continuation](evidence/block-v2-padding-2026-10-01.json)
now has validated runner, auditor, native Zig commitment and one-shot controller
interfaces. Three real empty proofs and three further merges from the preserved
count-eight root now pass CPU root-only auditing after six local inner artifacts
were pruned. The level-six/count-eight root is **1,683,948 bytes**; the six new
proofs took **872.198 seconds**, with a **122.209-second** final merge. This does
not change the registry/AIR or establish odd-count, full-count or post-seal
qualification. The three-merge command alone took **437.428 seconds**; measuring
only the last merge would hide the remaining serial dependency cost.

The research runner now provides opt-in phase/resource profiling and a single-entry
preprocessing cache; see [controls and security boundaries](bounded-execution-engine.md#profiling-and-single-entry-preprocessing-reuse)
and the [measured reuse experiment](bounded-execution-engine.md#profiled-cache-reuse-experiment-2026-09-30).
These are measurement/reuse tools, not evidence that the cold or incremental
latency targets have been met. The cache holds only immutable preprocessing and
checks full program equality; each proof still uses fresh hiding randomness.

The candidate-only Merkle/Poseidon2 adapter and its bounded launcher are now
implemented, with component compatibility, five full-size trials and post-pruning
CPU replay passed. Managed allocation accounting and a sampled VRAM watchdog are
not an instantaneous physical-driver quota. Later feasibility workloads retain
these mandatory gates:

1. Keep the hashing adapter **candidate-only and prove-side**. Keep verification on the
   standard strict CPU MMCS; do not inherit a GPU verifier that omits dimension
   checks. The v2 configuration still defaults to CPU even with `gpu` compiled;
   the separate adapter requires `LATTICA_V2_GPU_HASH=1` in the research runner.
   DFT and polynomial arithmetic remain CPU work. The older GPU PCS's quadratic challenge type
   is not a drop-in replacement for v2's cubic extension.
2. Enforce one job-wide GPU allocation/concurrency budget before enabling it.
   A device's per-allocation limit and row/column tiling are not a 12 GiB aggregate
   VRAM guarantee; thread-local contexts and retained buffers must be included.
   Measure transfers, staging, RAM, live scratch and GPU allocation peaks as well
   as kernel time. Do not run two current full-size CPU provers concurrently under
   the 48 GiB combined RAM budget.
3. Require same-seed CPU/GPU commitment and opening equivalence in test-only
   fixtures, including salts, matrix order, cap boundaries and tiled remainders.
   Recompute the full-size preprocessing caps and require the existing independent
   pin to match. Real accelerated proofs must verify with the unchanged CPU
   artifact checker, including malformed-proof rejection and root-only replay
   after inner-artifact deletion. No RNG reuse or parameter reduction is allowed.
4. Reprofile after hashing. Quotient evaluation/randomization, polynomial-opening
   reductions and spill traffic remain separate costs; a hash-kernel speedup is
   not a block-proving speedup. Do not sum nested profiler spans into percentages.
5. Run repeated comparable end-to-end trials, then the required common-height
   padding, depth-six/64-transaction and incremental-deadline workloads. Preserve
   the ten-minute cold, three-minute finalization, proof-size and resource gates.

The five RTX 5080 results are recorded in the linked experiment; they are not
full-depth or incremental release qualification. The final merge alone took
183.645 seconds median and 214.290 seconds worst, exceeding the three-minute
target in four of five trials. Transfer overhead and CPU quotient/opening work
remain measured optimization candidates; no reduced-security shortcut is allowed.
This sequence does not authorize activation, witness-bearing aggregation, an
individual-proof block container, or a curve/SNARK wrap.

### Phase A diagnostic reproduction — experimental, not an aggregate benchmark

Sources: [profile/security helpers](../lattica-prover-p3/src/block_v2/profile.rs),
[candidate leaf probe](../lattica-prover-p3/src/block_v2/leaf.rs),
[checked resource accounting](../lattica-prover-p3/src/block_v2/feasibility.rs), and
[feasibility binary](../lattica-prover-p3/src/bin/block_v2_feasibility.rs).

From the repository root, with dependencies already cached for offline Cargo use:

```sh
cd lattica-prover-p3
env RAYON_NUM_THREADS=8 cargo run --offline --release --features block-v2,recursion --bin block-v2-feasibility
```

The `block-v2-feasibility` binary requires both features. It proves/verifies a real candidate
cubic-extension JoinSplit leaf, then uses separate legacy **q96 / quadratic-extension** proofs to
recompute the old monolith's geometry. These are distinct proof families; the latter is diagnostic
input, not a v2 fallback or a candidate recursive proof. No aggregate/root proof is created.

The local leaf probe is context-bound to profile and chain and constrains **`mint = 0`**. Its
experimental 72-byte header contains `LBV2JS01`, the profile identifier, and the chain identifier;
it is not a frozen wallet/network/block wire format or a new public ABI. It does not provide typed
HTLC/issuance coverage or bounded recursive verification.

Resource instrumentation uses checked arithmetic for a **trace-commitment lower bound**. Exceeding
128 GiB rejects that geometry; fitting the lower bound would not establish safe job admission or
peak RAM/VRAM/scratch compliance. Quotient, Merkle, FRI, staging, concurrent-worker, and OS costs
still need full measurement. Composition-loss arithmetic using an assumed proof count is likewise
not complete-tree security without the missing recursive AIR's actual bound.

The captured diagnostic finished with **exit code 2 and `gate=BLOCKED`**, explicitly reporting
bounded cubic recursion not implemented, depth-six proving not run, and no root proof produced.
Earlier errors are failures, not proof-gate success. Do not turn this exit into a green benchmark or
a passed recursive gate. The single smoke sample and calculated geometry are in the ledger below.

The real-input legacy q96/F_p² K=2 planner reports height **2,097,152**, width **5,885**, and this
checked trace-commitment lower bound:

| Calculated allocation component | Bytes |
|---|---:|
| Natural trace | 98,733,916,160 |
| Randomized trace | 197,602,050,048 |
| Committed LDE | 3,161,632,800,768 |
| Trace-commit peak lower bound | **3,359,234,850,816** |
| Approved scratch budget | **137,438,953,472** (128 GiB) |

The lower bound is **about 24.44× the scratch budget**. **No aggregate was allocated or created.**
This rules out reuse of the inherited backend within that budget, not the possibility of a redesigned
fixed-width recursive verifier. It is not a measured v2 peak RSS, VRAM, or disk-use result.

## 5. Validation, evidence, and release

Required correctness/adversarial coverage includes block sizes **1, 2, 3, 4, 8, 16, 32, 63, 64** and
oversize rejection; invalid children; forged empty/count statements; reordered or omitted leaves;
profile/verifier substitution; cross-chain replay; changed ciphertexts/public inputs; malformed or
trailing bytes; corrupted recursive witnesses; and differential checks against native verification.
Validate duplicate-spend, stale-anchor, HTLC-height, and unauthorized-issuance rejection, mixed
transaction blocks, and atomic rollback on validation/allocation failures.

Operational tests must cover steady/bursty arrivals, late submissions, replacements, removals, reorgs,
RNG failure, disk exhaustion, cancellation, crashes, restart recovery, and verification after deleting
all inner/intermediate artifacts. Final validators must run without a GPU or inner-proof archive.

Benchmark CPU and available GPU backends separately at full candidate strength, including leaf
wrapping, every merge/finalization stage, data movement, and peak combined RAM/VRAM/scratch. Supply
valid wallet proofs for the cold aggregation measurement and report wallet proving separately. Use at
least five runs per measured configuration; report median and worst observed latency, proof size,
verification time, hardware/software details, and profile fingerprint. Missing GPU measurements and
resource-preflight exits are **not run / blocked / skipped**, never successful aggregate proofs.

### Two-level milestone evidence — captured 2026-09-30

This uncommitted working-tree demonstration uses the full candidate parameters,
the original pinned demo registry, CPU proving, and disk-backed spill. It is
implementation evidence, not independent security sign-off. Detailed per-node
measurements, hashes, commands, and exclusions are in the
[execution-engine report](bounded-execution-engine.md#completed-two-level-recursive-proof-2026-09-30)
and [machine-readable evidence](evidence/block-v2-two-level-2026-09-30.json).

| Evidence | Result |
|---|---|
| Real recursive chain | Four distinct JoinSplit proofs → four wrappers → two sibling merges → final merge; all native verifications passed |
| Root statement / size | Count 4, level 2, MERGE; 1,913,373 bytes including envelope, under 2 MiB |
| No-inner-artifact verification | Ten inner files deleted; fresh-process root-only verification passed in 65 ms and was repeated successfully |
| Separate artifact checker | 38 native mutation and four registry-policy rejections; zero inner proofs loaded; not an independent cryptographic audit |
| Serial recursive proving stages | 2,040.123 s, excluding original wallet proving/registration, failed trials, and controller overhead |
| Maximum measured per-stage resources | 42,966,003,712 bytes cgroup memory; 47,442,042,880 bytes live mapped spill; zero swap |
| Full-tree review / production registry | Pending; candidate remains inactive |
| Depth six, common-height padding, HTLC/issuance, GPU, coordinator/network | Not demonstrated by this run |

### Evidence ledger — implementation checks captured 2026-09-29

**Implementation checks captured 2026-09-29; uncommitted worktree based on `eda5ee1`, not independent
audit.** These historical results predate the two-level run above. They do not attest a frozen release or complete the recursive feasibility gate.

| Evidence | Recorded result |
|---|---|
| Phase A foundations / identity | Candidate profile, leaf proof, commitment, full verifier compilers, recursive program builders, and execution/registry fingerprint computations implemented behind `block-v2`, with no C ABI. Recursive registry **NOT FROZEN / NOT PROVED**; the ASCII wallet research label is not the aggregate identity |
| Candidate feasibility binary build check | `cargo check --offline --features block-v2,recursion --bin block-v2-feasibility` — passed (from `lattica-prover-p3/`) |
| All-features compile check | `cargo check --offline --features block-v2,recursion,stream,gpu --all-targets` — passed (from `lattica-prover-p3/`). Required writable Cargo cache to unpack offline-cached `bitflags`; compile only, no GPU execution |
| Targeted candidate tests | `cargo test --offline --release --features block-v2 --lib block_v2:: -- --nocapture --test-threads=1` — **13 passed / 0 ignored / 0 failed**, 3.97 s, including commitments, cubic-leaf tampering, and the cubic modulus relation (from `lattica-prover-p3/`). Context encoding delegates to `commitment::Context::to_fields` |
| Full Rust library regression | `env RAYON_NUM_THREADS=8 cargo test --offline --release --features block-v2 --lib -- --test-threads=1` — **113 passed / 19 intentionally ignored / 0 failed**, 77.52 s on the final code (from `lattica-prover-p3/`). Ignored tests are not passed recursive gates |
| Default ABI gate | `bash scripts/check-abi-symbols.sh` — passed, **exactly 12 `lattica_*` externs**, zero recursion and zero `block_v2` symbols (from `lattica-prover-p3/`). No new C ABI is exposed |
| Zig regression tests | `env ZIG_GLOBAL_CACHE_DIR=/tmp/lattica-zig-global-cache zig build test` — exit 0 (repository root) |
| Zig ReleaseSafe FFI tests | `env ZIG_GLOBAL_CACHE_DIR=/tmp/lattica-zig-global-cache zig build test-ffi -Doptimize=ReleaseSafe` — exit 0 (repository root) |
| Formatting checks | Passed: `rustfmt --edition2021 --check src/block_v2/mod.rs src/bin/block_v2_feasibility.rs` (prover crate), `zig fmt --check src/block_v2.zig src/tests.zig` (repository root), and `git diff --check` |
| Candidate leaf test observations | Randomized proof sizes **853,860 and 853,761 bytes**; leaf `AirSecurity`: **82 constraints**, maximum degree **8**, hiding degree bits **13**, proven bits **127**. These are leaf observations, not aggregate size/timing results |
| Security-accounting assumptions | Goldilocks cubic challenge-space floor **191 bits**; conservative hash-collision floor **127 bits**. Assumed maximum **191 proof statements** = 64 wallet + 64 leaf/empty + 63 merge; union-loss **8 bits** gives **119 bits only conditionally if every future AIR achieves at least 127 bits**. This is not an established complete-tree bound |
| Complete-tree soundness review and fixed-geometry proof | Not established |
| Experimental leaf/legacy-geometry diagnostic command above | **Exit 2 / `BLOCKED`**. Candidate leaf **853,965 bytes**, prove **1,337 ms**, verify **38 ms** — **one smoke sample, not a benchmark**. Legacy geometry/lower-bound calculation above; no aggregate allocated, no root proof produced, depth six not run |
| Root-only depth-six proof/verify artifact | Not available; verifier programs exist, but recursive root proving/verification is not demonstrated |
| v2 block CPU/GPU timing, final proof size, RAM, VRAM, scratch, finalization latency | **BLOCK BENCHMARK NOT RUN**; leaf sizes above are not block evidence |
| Candidate backend coverage | CPU leaf and bounded-execution smoke probes; no recursive root proof. **No GPU or streaming v2 proofs attempted**. Compilation alone does not establish either backend's v2 proof compatibility |
| Cryptographic review, host integration, activation authorization | Pending; v2 inactive |

Update this ledger at every milestone with implemented/tested/resource-blocked/unaudited distinctions,
reproducible commands and artifacts, and actual revisions. Passing tests or a resource estimator is
not security sign-off. Require dedicated review of recursion soundness, zero knowledge, profile
binding, and complete-tree composition before value-bearing activation.

Preserve v1 encodings and historical verification for replay. Candidate v2 proofs must remain inactive
until reviewed encodings, full transaction coverage, release gates, and host consensus activation are
explicitly completed. Existing dated audit reports and the `v3-batch-audit` tag do not cover this work.
See [SPEC.md](../SPEC.md), [wire-format.md](wire-format.md),
[current readiness](audit-readiness-status.md), and
[host integration requirements](full-node-security-integration.md).
