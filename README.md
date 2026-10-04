# Lattica

Lattica is a clean-slate, post-quantum shielded-payment protocol and working proof of concept. It combines a Zig wallet and node state machine with Plonky3 zero-knowledge STARK circuits written in Rust. The protocol avoids elliptic curves and discrete-log assumptions throughout its production proof path.

The repository contains an audited CPU proof/verifier baseline, a complete shielded transaction demonstration, production batch circuits, and feature-gated research into GPU proving, out-of-core proving, and recursive aggregation. It is not a complete cryptocurrency node and is not cleared for value-bearing deployment.

## Start here

- [Protocol specification](SPEC.md) defines the transaction model and cryptographic construction.
- [Documentation map](docs/README.md) separates current guidance, normative references, research, and historical audit records.
- [Solving benchmark report](docs/benchmarks/index.html) retains throughput measurements, process telemetry, and P0–P5 development milestones; [usage and portable imports](docs/benchmarks/README.md).
- [Audit handoff](docs/AUDITORS.md) defines the reviewed surface, assumptions, reproduction commands, and exclusions.
- [Current status](docs/audit-readiness-status.md) records the production baseline and active development boundary.
- [Block-proving v2](docs/block-proving-v2.md) defines the approved incremental recursive architecture, inactive candidate profile, and feasibility/release gates.
- [Remediation status](docs/remediation-status.md) maps audit findings to their resolutions.

- [Distributed proving roadmap](docs/distributed-proving.md) specifies proposed public-only CPU/GPU workers, verified job scheduling, and capacity experiments; no distributed service or higher-throughput consensus profile is implemented.
- [Execution DAG and GPU implementation plan](docs/dag-gpu-implementation.md) selects dependency-driven proof execution and a GPU pipeline with retained intermediate data as the immediate acceleration work. Local scheduling and full-block qualification remain pending; resident GPU component and key-reproduction evidence is recorded below.

## What it provides

Lattica replaces the elliptic-curve components normally found in shielded payment systems:

| Function | Lattica construction |
|---|---|
| Zero-knowledge authorization | Transparent Plonky3 FRI-STARK with a hiding PCS |
| Circuit and protocol hash | Poseidon2 over the Goldilocks field |
| Note encryption | ML-KEM-768 and ChaCha20-Poly1305 |
| Key hierarchy | ML-DSA-44 plus hash-derived spending and viewing material |
| Transaction authorization | Join-split proof of spend-key knowledge, bound to a canonical `tx_binding` digest |
| Value conservation | In-circuit balance equations and range checks |

The production circuits cover individual join-splits, shielded HTLCs, and batch forms of both. The Zig node checks anchors, nullifiers, supply transitions, transaction bindings, and proof validity before atomically applying state.

## Repository layout

| Path | Purpose |
|---|---|
| `src/` | Zig protocol, wallet, codecs, state machine, cryptography, and Rust FFI |
| `lattica-prover-p3/` | Production Plonky3 circuits, prover/verifier, C ABI, and research backends |
| `docs/` | Specifications, audit material, operational guidance, and research notes |
| `scripts/` | Cross-language integration and support scripts |
| `framework-spike/`, `plonky2-spike/`, `plonky3-spike/` | Historical framework experiments |
| `lattica-prover/` | Reference-only Winterfell differential oracle |

## Build and verify

Requirements: Zig 0.16, Rust 1.96, and a C toolchain.

```sh
cd lattica-prover-p3
cargo test --release
cd ..

zig build test
scripts/run-real-integration.sh
zig build run -- demo
```

The integration script exercises the real Zig-to-Rust boundary: proof generation, verification, state application, transaction-root agreement, tamper rejection, and double-spend rejection.

## Status and security boundary

The default CPU implementation at `v3-batch-audit` is the frozen ten-symbol audit target and includes the join-split, HTLC, batch join-split, and batch HTLC paths. The current development tree adds two join-split proof-tree container symbols, bringing its default ABI to twelve; that post-tag seam is not covered by the frozen audit. The documented soundness budget for the underlying production proof family is approximately 103 bits proven and 127 bits conjectured.

GPU acceleration, streaming/out-of-core proving, and recursion are opt-in research features. They do not alter the underlying production verifier or leaf-proof format. Recursion remains excluded from the default static library; the development proof-tree container is a non-recursive aggregation seam and must not be mistaken for audited recursive aggregation.

### Approved block-proving direction — candidate / inactive

The [compact opening full-workload continuation](docs/evidence/block-v2-gpu-opening-compact-recursive-2026-10-02.json)
passes full-size CPU/GPU key equivalence and one eight-wallet/seven-proof
recursive run. All seven compact calls were observed; local inner artifacts
were pruned and the independent CPU-only auditor accepted the **1,683,948-byte**
root. Proving commands took **606.828 s**, with **609.075 s** for the complete
controller run. Peak worker RAM was **32.320 GiB**, sampled VRAM **6,856 MiB**,
and swap zero. This is **not** a same-build matched speedup, full64 result or
complete post-seal measurement. Compact remains default-disabled.

The [compact opening consumer](docs/evidence/block-v2-gpu-opening-compact-2026-10-02.json)
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

The [pinned opening-upload investigation](docs/evidence/block-v2-gpu-opening-pinned-2026-10-02.json)
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

The [GPU opening timing diagnostic](docs/evidence/block-v2-gpu-opening-profile-2026-10-02.json)
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

The [matched cache-workload pilot](docs/evidence/block-v2-cache-bench-pilot-2026-10-02.json)
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

The [cache-owning CPU adapter checkpoint](docs/evidence/block-v2-cached-cpu-2026-10-02.json)
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

The [persistent-workspace reservation checkpoint](docs/evidence/block-v2-workspace-reservations-2026-10-02.json)
adds separately journaled cache-lifetime budgets and local-use guards. Idle
workspaces stay charged; cold worker identities cannot alias them, and recovery
requires explicit workspace reconciliation. **144 selected native tests,
sixteen explicit CPU checks and ten Zig tests pass**. The new local `LVDAG004`
envelope embeds the existing snapshot format; cold snapshots retain their
previous encoding. That checkpoint established the reservation foundation;
the cached-adapter continuation above adds real allocation and reuse, without
a matched speedup or production-readiness claim.

The [managed verifier process-loss checkpoint](docs/evidence/block-v2-verifier-crash-2026-10-02.json)
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

The [local verifier-guard checkpoint](docs/evidence/block-v2-verifier-guard-2026-10-02.json)
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

The earlier [controlled arrival/reuse checkpoint](docs/evidence/block-v2-cpu-arrivals-2026-10-02.json)
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

The earlier [worker-start recovery checkpoint](docs/evidence/block-v2-cpu-worker-start-2026-10-02.json)
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

The earlier [CPU process checkpoint](docs/evidence/block-v2-cpu-process-2026-10-02.json)
adds an autonomous CPU worker, executable/configuration-bound launches and
immutable local task/result files. **87 native checks and seven CPU fixture
checks pass**, plus actual-process check/prove runs and fresh raw-node replay.
The new two-transaction proof is **1,683,948 bytes** and took **178.290 seconds**
through dispatch/execution, pinned process/cgroup shutdown checks, owner
verification/acceptance and export; initial admission/task publication is excluded.
Durable OS supervision, physical scratch quotas, full operation/arrival coverage,
full64/complete post-seal gates, full-tree security and activation remain open.
This is an experimental process boundary, not production qualification.

The [live CPU supervisor checkpoint](docs/evidence/block-v2-cpu-supervisor-live-2026-10-02.json)
now exercises actual check-only completion, live cancellation, coordinator
exit/recovery, full-strength pair proving, and fresh CPU replay. **105 native
checks and nine explicit checks pass**, followed by all six live stages. The
pair proof is 1,683,948 bytes; dispatch-to-acceptance/export is **193.623 seconds**,
with 39.68 GiB worker RAM peak and zero swap. This exceeds three minutes and is
not a 64-transaction or complete post-seal result. Unseen-launch recovery,
concurrent verifier drain, full operation coverage, quotas and retention remain
unfinished; production is not enabled.


The candidate GPU opening consumer is now integrated into the bounded recursive
runner. Component tests, independent key reproduction and a complete count-eight
CPU-audited recursive trial pass. The [fresh same-build pilot](docs/evidence/block-v2-gpu-openings-matched-pilot-2026-10-02.json)
measured **686.046 seconds** with resident commitments/GPU openings versus
**607.112 seconds** with retained GPU hashing: the new backend was **13.002%
slower in one pair**, with a slower final merge. It remains default-off and is
not promoted. Host LDE materialization and upstream FRI work remain. Repeated
performance qualification, arrival-driven DAG integration, full64/complete post-seal
deadlines, full-tree security and host activation remain open.

The [bounded CPU execution engine](docs/bounded-execution-engine.md) implements
the fixed-width lookup-backed AIR, full candidate proof-verifier compilers, and
wrapper/empty/merge programs. A real four-transaction, two-level recursive proof
now verifies from the root alone after all inner proofs are deleted. The final
envelope is **1,913,373 bytes**; the seven serial proving stages took **34.002
minutes** with a **40.015 GiB** peak proving-service memory measurement in the
earlier baseline. A later [profiling/cache-reuse run](docs/bounded-execution-engine.md#profiled-cache-reuse-experiment-2026-09-30)
also passed root-only verification but took **36.820 minutes**. It cut repeated
preprocessing setups from seven to two, **without demonstrating an end-to-end
speedup**; both controls remain opt-in.

A later [same-eight CPU pilot](docs/evidence/block-v2-eight-matched-pilot-2026-10-01.json)
measured **69.941 minutes with single wrappers / 33.552 minutes with paired
wrappers**, a **52.028%** reduction in one matched pair. Final merge was
**264.760 / 287.332 seconds**, respectively, and both roots passed recorded CPU
audits after local inner-proof pruning. Repeated comparison, shared-fixture
pruning/replay, and both full-block latency gates remain open.

The separate, default-disabled [quotient-fusion candidate](docs/bounded-execution-engine.md#quotient-transform-fusion-experimental-implementation-and-gates)
passed component tests, exact full-size registered-key reproduction and preserved
CPU verification of a full eight-wallet recursive root after local inner pruning.
The [same-binary matched comparison](docs/evidence/block-v2-quotient-fusion-matched-2026-10-01.json)
measured **32.198 minutes off / 28.983 minutes on**, a **9.983%** reduction in
one pair. Final merge was **270.047 / 252.026 seconds**; memory and retained
geometry were essentially unchanged. Both roots passed additional CPU-only
replay. Fusion remains opt-in: this is not repeated, depth-six or production
qualification. As of 2026-10-01 18:33 UTC, the separate
[original five-pair series](docs/evidence/block-v2-eight-repeated-series-2026-10-01.json)
has four completed trials (two matched pairs), with both controllers exited
successfully. Pair two measured **70.786 minutes single / 32.333 minutes grouped**,
with **286.794 / 263.058-second** final merges and recorded root-only CPU audits.
This is not five-pair qualification. Shared-fixture pruning/replay remains
required after all consumers finish.

[Incremental recursive block proving v2](docs/block-proving-v2.md) targets wallet-local private
witnesses, public-only aggregation, and one final aggregate proof per transaction block. Individual
proofs remain temporary off-chain artifacts. Neither individual-proof containers stored in blocks nor
direct batches requiring users' witnesses are deployment fallbacks. The construction must stay
hash/FRI-based; curve/SNARK wraps are excluded.

The approved targets are a new ordered 64-leaf Merkle commitment, at most 64 total transactions
including issuance, a 12-minute transaction-block cadence, and a final proof no larger than 2 MiB,
within 48 GiB RAM / 12 GiB VRAM / 128 GiB scratch. These are gates, not measured capabilities.
The separate candidate profile does not change historical v1 verification.
**The two-level recursion demonstration is complete; the full feasibility gate is
not.** The four- and eight-transaction measurements do not establish the
64-transaction cold or incremental performance benchmark. Count-eight and controlled count-three trees now
pass real common-height padding to level six. Other counts and arrival schedules,
full-count proving, full-tree soundness/zero-knowledge review, HTLC/issuance, and
network integration remain open. Five
[bounded GPU-hashing trials](docs/bounded-execution-engine.md#gpu-hashing-experiment-2026-09-30)
passed in **23.396 minutes median / 24.488 minutes worst**, with CPU root-only
verification, roots below 2 MiB and unchanged parameters. All roots verified again
after pruning the shared wallet proofs. This is not a controlled CPU/GPU speedup
claim or a passed production performance gate.
The completed five-pair matched GPU retention experiment holds serial transfers
fixed and compares
GPU tree retention off/on: **19.627 / 17.642 minutes median** across five pairs
(a **10.114%** reduction). All ten roots plus the retained pilot passed fresh
CPU-only verification after shared-fixture pruning. The worst observed retained
final merge was **201.993 seconds**, above the three-minute target for the final
merge alone. Retention remains experimental and opt-in. See the
[current checkpoint](docs/bounded-execution-engine.md#current-measurement-and-implementation-checkpoint--2026-10-01)
and [complete evidence](docs/evidence/block-v2-retention-matched-2026-10-01.json).
The grouped-eight CPU prototype completed all seven recursive proofs under its
separately pinned research profile. Its **1,914,091-byte** root passed fresh CPU
replay after all 14 local inner artifacts were pruned. Proving stages took
**33.133 minutes**, including a **280.993-second** final merge. This is one
level-three/count-eight sample, not a same-eight/backend speed comparison or
padded level-six block qualification.

No production-ready block path meeting these requirements exists yet.

The validated [program-usage report](docs/evidence/block-v2-program-usage-2026-10-01.json)
shows that ordinary arithmetic packing is already nearly full. The preserved
[21-lane revision-two experiment](docs/evidence/block-v2-wide-lanes-2026-10-01.json)
passed its real 17-mutation proof test, but recursive feedback pushed its merge to
266,034 rows at the proposed 262,144-row height. Rounding up required 56.625 GiB
of retained LDE data alone, so the unchanged 48 GiB gate rejected it before keys
or proofs. Its full-height worst-case envelope also exceeded 2 MiB.

The default-disabled [23-lane revision-three candidate](docs/evidence/block-v2-wide23-lanes-2026-10-01.json)
retains one 94-column AIR. Its earlier legacy envelope exceeded 2 MiB. The
[compact-codec continuation](docs/evidence/block-v2-fixed-node-codec-2026-10-01.json)
now passes the maximum-value template bound at **1,683,948 bytes**, using the
separately profile-bound `LBV2RC02` research format. Default `LBV2RC01` bytes
and wallet encoding remain unchanged. Fresh geometry still fits 262,144 rows
with a 29.5 GiB retained-LDE estimate, not measured proving RAM or speed.

Current validation passed **223 default / 225 wide native tests** (30 ignored
each), 26 CLI/auditor tests per build, the unchanged 12-export ABI gate, and
111 Debug / 143 ReleaseSafe Zig tests including 32 real FFI tests. Rebuilt
default tools replayed all six original roots and the externally pinned
registry, with all rejection checks and 44 before/after input hashes intact.
The new candidate keys have now been independently reproduced byte-for-byte.
The expected root was derived with the preserved native Zig calculator and both
registries passed positive and altered-statement checks. The first full-strength eight-transaction candidate run now passes recursive
closure and preserved CPU root-only auditing after deleting all 14 local inner
artifacts. Its root is **1,683,948 bytes**, recursive-command time **19.440 minutes**,
and final merge **157.817 seconds**. Peak proving-worker memory was **40.000 GiB**
with zero swap; mapped spill peaked at **31.934 GiB** (not additional RSS).
This is one level-three/count-eight CPU run, not a matched speedup, complete
post-seal timing, padded/depth-six qualification or production approval.

The [padding continuation](docs/evidence/block-v2-padding-2026-10-01.json) adds
validated CPU-only tools to extend that root with real empty-subtree proofs and
ordered merges to level six. Its first full-strength attempt now passes CPU
root-only auditing after local pruning: **1,683,948 bytes**, **14.537 minutes**
for the six new proofs, **122.209 seconds** for the final merge. This is an
eight-transaction padded root, not a full-count block or deadline qualification.

The [resident GPU LDE/commitment prototype](docs/evidence/block-v2-gpu-lde-pipeline-2026-10-01.json)
now passes 17 targeted native tests and all 13 explicit GPU component/regression
tests. It performs accounted column transforms, uninterrupted matrix/salt hashing,
and retained commitments, with explicit host LDE readback. The subsequent
[hiding-PCS adapter](docs/evidence/block-v2-gpu-resident-pcs-2026-10-01.json)
now passes exact CPU commitment/opening comparisons, interleaved randomness and
clone checks, admission-failure checks, and small full-strength cubic proofs
verified through the original CPU PCS. Research selection is explicit and
default-disabled (`LATTICA_V2_GPU_RESIDENT_LDE=1`, requiring GPU hashing and
retained trees); this is distinct from the transfer-overlap switch. The separate
[bounded GPU grouped workflow](docs/evidence/block-v2-gpu-grouped-workflow-2026-10-01.json)
now passes 30 controller tests, 18 actual executable rejection checks, and three
synthetic service-lifecycle checks. All three full-size compact-profile resident
GPU preprocessing keys match the independent CPU registration. The
[first complete resident-GPU eight-wallet run](docs/evidence/block-v2-gpu-grouped-resident-proof-2026-10-01.json)
now passes local inner-proof pruning and preserved CPU-only root auditing:
**1,683,948 bytes**, **14.035 minutes** recursive-command time, **84.524 seconds**
for the final merge. This is one count-eight sample, not a matched speedup claim,
full64 result or complete post-seal measurement. The subsequent
[matched backend pilot](docs/evidence/block-v2-gpu-grouped-matched-pilot-2026-10-01.json)
also passed with retained hashing in **10.554 minutes**: resident LDE was about
**33% slower in this one pair**, with costly host readback/scatter. Resident
performance promotion is withheld; repeated qualification and full-block gates
remain open, and production defaults are unchanged.

The subsequent [banded readback checkpoint](docs/evidence/block-v2-gpu-readback-2026-10-01.json)
passes a complete eight-wallet run and CPU-only audit after local pruning:
**13.066 minutes**, **1,683,948 bytes**, and an **81.324-second** final merge.
Host decode includes reorder work. The [fresh same-build control](docs/evidence/block-v2-gpu-readback-matched-pilot-2026-10-01.json)
passes in **10.398 minutes**, with a **72.412-second** final merge: resident mode
remains **25.660% slower in this single pair**. It is not promoted. Repeated
qualification, the 64-transaction and complete post-seal deadlines remain open.
An initial pressure diagnostic's sequential
timing control was excluded; the corrected Rayon pressure comparison and all
seven GPU regressions now pass. Those layout timings do not establish a recursive
backend speedup. Production defaults remain unchanged.

The [opening-consumer runner checkpoint](docs/evidence/block-v2-gpu-openings-runner-2026-10-02.json)
now binds the explicit opening mode and separate transfer counters to the
preserved source, executable and registration. Controller/native/entrypoint,
lifecycle and GPU component checks pass, and all three full-size preprocessing
keys match the independent CPU reference. The subsequent
[opening-enabled eight-wallet trial](docs/evidence/block-v2-gpu-openings-recursive-2026-10-02.json)
passes local pruning and independent CPU-only root auditing in **686.046 seconds**,
with a **1,683,948-byte** root and **92.427-second** final merge. This is one
correctness-qualified sample, not a full64 or complete post-seal result. The
[fresh matched control](docs/evidence/block-v2-gpu-openings-matched-pilot-2026-10-02.json)
passes in **607.112 seconds**, with a **71.812-second** final merge and the same
root size. Opening-enabled mode was **13.002% slower** in this pair; performance
promotion is withheld and repeat qualification remains open.

The first [local execution contract](docs/evidence/block-v2-local-job-contract-2026-10-02.json)
established bounded public artifacts, semantic job identities and CPU-verified
result tickets. The subsequent [in-memory DAG checkpoint](docs/evidence/block-v2-local-dag-2026-10-02.json)
now implements dependency readiness, candidate sealing/cancellation, frozen
input manifests, attempt fencing, aggregate reservations and bounded pruning.
**21 structural checks** (including 15 DAG checks) and the separate pinned
eight-wallet/root CPU replay pass. A shuffled 127-node graph test uses synthetic
artifacts; it is **not a full64 recursive proof**. The subsequent
[Linux artifact-store checkpoint](docs/evidence/block-v2-artifact-store-2026-10-02.json)
adds private bounded storage, atomic publication, interrupted-write cleanup and
CPU re-verification after reopening. The subsequent
[snapshot-journal checkpoint](docs/evidence/block-v2-journal-2026-10-02.json)
adds durable graph reconstruction, fresh-session fencing, an explicit unresolved
worker/verifier reconciliation boundary and reference-aware garbage collection.
**48 native checks** and three explicit pinned CPU replays passed that checkpoint;
nine abrupt-exit cases run inside two native checks. The subsequent
[CPU-adapter checkpoint](docs/evidence/block-v2-cpu-worker-2026-10-02.json)
passes **52 native checks and four explicit CPU fixture checks**, plus one
separately bounded real paired-wrapper generation and a fresh-process replay.
The new 1,683,948-byte pair proof passed durable acceptance/recovery in a
231.705-second leased execution path. This is two transactions, not a full block.
Historical candidates are not revived as host eligibility. OS worker supervision,
complete operation coverage and arrival-driven integration remain open; this is
not a production proving service.

The subsequent [single-use launch gate](docs/evidence/block-v2-launch-fencing-2026-10-02.json) now
passes **69 execution native checks and four explicit CPU fixture checks**.
It binds exact CPU leases/resources, persists one-use worker admission and
irreversible revocation, and rejects delayed or duplicate starts. Ten new
abrupt-exit cases and an owned live-child lock/reap check pass. This is local
launch fencing, not OS supervision, a new block proof or a performance result.
The supervisor must still confirm exact process/cgroup exit and verifier drain
before releasing reservations; request transport and physical enforcement remain open.

The subsequent [bounded CPU packet checkpoint](docs/evidence/block-v2-worker-packets-2026-10-02.json)
passes **77 execution native checks and six explicit CPU fixture checks**.
One new guarded, packet-driven paired-wrapper proof passed independent owner
verification/durable acceptance and fresh-process raw-node replay: **1,683,948
bytes**, **185.854 seconds** through acceptance/output publication. This covers
two transactions, not a full block or post-seal benchmark. Decoding conveys no
scheduler or proof-validity authority. The later [CPU process checkpoint](docs/evidence/block-v2-cpu-process-2026-10-02.json)
adds the executable and local transport. Durable OS supervision, physical quotas,
complete operation coverage and arrival-driven qualification remain open.

The following remain outside this repository's production claim:

- block consensus, networking, mempool policy, reorg handling, and emissions;
- host-chain release integration and startup attestation;
- operational wallet and prover key management;
- production recursive aggregation;
- final independent sign-off on the documented cryptographic assumptions.

Read [the audit handoff](docs/AUDITORS.md) before treating any component as security-sensitive.
